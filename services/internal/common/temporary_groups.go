//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Temporary MCS groups: formation by a GMOP group regroup creation request, the group regroup check and
// notification of each constituent group, and tear down.
//
// Specifications: TS 24.481 V19.3.0 (Rel-19), TS 24.379 V19.7.0 (Rel-19), TS 24.482 V19.1.0 (Rel-19),
// TS 33.180 V19.4.0 (Rel-19), RFC 4825.
package common

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
)

// Temporary MCS groups (TS 24.481 clause 6.3.14 and clause 6.3.15). A GMC asks its GMS
// to combine groups into a temporary group with a GMOP group regroup creation
// request. The GMS checks whether each constituent group
// may be combined (group regroup check), then marks the group with an
// <on-network-regrouped> element (group regroup notification), and only then
// creates the temporary group's document, which lists the constituent groups in
// <on-network-temporary>. The MCPTT servers learn of both documents from the GMS and apply
// them as a group regroup (TS 24.379 clause 16): the constituent groups are
// regrouped (warning 148) and a call on the temporary group reaches their members.

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.3.4.3: a GMOP document requesting group regroup creation.
type gmopRegroupDocument struct {
	XMLName xml.Name `xml:"urn:3gpp:ns:mcpttGMOP:1.0 document"`
	Request *struct {
		Creation *struct {
			Group groupDocXML `xml:"urn:oma:xml:poc:list-service group"`
		} `xml:"urn:3gpp:ns:mcpttGMOP:1.0 group-regroup-creation"`
	} `xml:"urn:3gpp:ns:mcpttGMOP:1.0 request"`
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.3.4.6: the GMOP document with the group regroup creation response, carrying the entity tag of
// the temporary group document.
func gmopCreationResponse(etag string) []byte {
	var escaped bytes.Buffer
	_ = xml.EscapeText(&escaped, []byte(etag))
	return []byte(xml.Header + `<document xmlns="urn:3gpp:ns:mcpttGMOP:1.0"><response><group-regroup-creation-response>` +
		`<temporary-group-document-ETag>` + escaped.String() + `</temporary-group-document-ETag>` +
		`</group-regroup-creation-response></response></document>`)
}

// ------------------------------------------------------------------------------
// Helper: whether two <on-network-regrouped> marks name the same temporary group, requestor and constituents.
func sameRegroupMark(left, right *TemporaryRegroup) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.TGI == right.TGI && left.Requestor == right.Requestor && slices.Equal(left.Constituents, right.Constituents)
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.14.3.1 step b: whether an identity is authorized to initiate temporary MCS group formation
// (provider policy).
func (svc *service) mayFormTemporaryGroups(identity string) bool {
	user, ok := svc.siteUser("mcptt_id", identity)
	return ok && user.GroupManagement != nil && user.GroupManagement.Temporary
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13.3.3: changeGroup reads a group of this system, lets change decide (an HTTP status; 200 with
// changed true stores the group) and replaces the group's document with a bumped version, so that the servers and
// the subscription front see the change. The read and the write are one step under the store's lock: a change made
// meanwhile (an XCAP PUT of the document) is not overwritten with an older reading.
func (svc *service) changeGroup(id string, change func(group *Group) (status int, changed bool)) int {
	svc.groupDocs.mu.Lock()
	defer svc.groupDocs.mu.Unlock()
	stored := svc.groupDocs.groups[id]
	var group Group
	var found bool
	switch {
	case stored == nil:
		group, found = svc.cfg.groupByID(id)
	case !stored.Deleted:
		parsed, err := parseGroupDocument(stored.XML)
		group, found = parsed, err == nil
	}
	status, changed := change(&group)
	if !found || status != http.StatusOK || !changed {
		return status
	}
	raw, err := groupDocument(group, true)
	if err != nil {
		return http.StatusInternalServerError
	}
	doc := &storedGroupDocument{ID: id, Document: documentName(id), XML: raw, Version: 1}
	if stored != nil {
		doc.Owner, doc.Document, doc.Version = stored.Owner, stored.Document, stored.Version+1
	}
	if err := svc.saveDocumentLocked(doc); err != nil {
		return http.StatusInternalServerError
	}
	svc.groupDocs.groups[id] = doc
	return http.StatusOK
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.14.3.2 and clause 6.3.15.3.2: localRegroupStep is the step at the GMS owning the
// constituent group: kind is "check", "notification" or "delete".
func (svc *service) localRegroupStep(kind, id string, mark *TemporaryRegroup) int {
	svc.temporaryMu.Lock()
	defer svc.temporaryMu.Unlock()
	found := false
	status := svc.changeGroup(id, func(group *Group) (int, bool) {
		if group.ID == "" {
			return http.StatusNotFound, false
		}
		found = true
		switch kind {
		case "delete":
			if group.RegroupedBy == nil || group.RegroupedBy.TGI != mark.TGI {
				return http.StatusNotFound, false
			}
			group.RegroupedBy = nil
		default:
			// Step a.1 and a.2: already regrouped, or itself a temporary group. A group
			// is combined into one temporary group at a time (TS 24.379 clause 16.2.4.1 step 2a).
			if group.RegroupedBy != nil || len(group.TemporaryConstituents) > 0 {
				return http.StatusForbidden, false
			}
			if kind == "check" {
				return http.StatusOK, false
			}
			group.RegroupedBy = mark
		}
		return http.StatusOK, true
	})
	if !found && kind == "delete" {
		return http.StatusForbidden
	}
	return status
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.14.3.1 step d and clause 6.3.15.3.1 step a: regroupStep sends one step to the GMS owning a
// constituent group of this GMS.
func (svc *service) regroupStep(kind, group string, mark *TemporaryRegroup) int {
	return svc.localRegroupStep(kind, group, mark)
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.14.3.1: createTemporaryGroup: the GMS forming a temporary group.
func (svc *service) createTemporaryGroup(writer http.ResponseWriter, request *http.Request) {
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok {
		return
	}
	target, err := svc.usersTarget(request)
	if err != nil {
		writeXCAPError(writer, err)
		return
	}
	result := map[string]any{"requestor": claims.MCPTTID, "document": target.name}
	defer func() { svc.logEvent("temporary_group_formation", result) }()
	fail := func(status int, reason string) {
		result["status"], result["reason"] = status, reason
		writeJSON(writer, status, map[string]string{"error": reason})
	}
	if target.selector != "" || target.doc != nil {
		fail(http.StatusConflict, "document_exists")
		return
	}
	if !strings.EqualFold(mediaType(request.Header.Get("Content-Type")), gmopMIME) {
		fail(http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, 64<<10))
	if err != nil {
		fail(http.StatusRequestEntityTooLarge, "too_large")
		return
	}
	// RFC 4825 section 8.2.5: the GMOP document (TS 24.481 clause 7.3.3) and the group document it carries
	// (TS 24.481 clause 7.2.4) conform to their schemas and to the constraints of TS 24.481 clause 7.2.7.
	if err := gmopDocumentSchema.validate(body); err != nil {
		result["status"], result["reason"] = http.StatusConflict, err.Error()
		writeXCAPError(writer, schemaError(err))
		return
	}
	if root, err := parseXMLTree(body); err == nil {
		if gmopRequest := child(root, gmopNS, "request"); gmopRequest != nil {
			if creation := child(gmopRequest, gmopNS, "group-regroup-creation"); creation != nil {
				if group := child(creation, pocNS, "group"); group != nil {
					if err := groupConstraints(group, target.usersXUI); err != nil {
						result["status"], result["reason"] = http.StatusConflict, err.Error()
						writeXCAPError(writer, err)
						return
					}
				}
			}
		}
	}
	var gmop gmopRegroupDocument
	if xml.Unmarshal(body, &gmop) != nil || gmop.Request == nil || gmop.Request.Creation == nil {
		fail(http.StatusBadRequest, "unsupported_gmop_request")
		return
	}
	raw, err := xml.Marshal(gmop.Request.Creation.Group)
	var group Group
	if err == nil {
		group, err = parseGroupDocument(raw)
	}
	if err != nil || len(group.TemporaryConstituents) == 0 || group.RegroupedBy != nil {
		result["status"], result["reason"] = http.StatusConflict, "constraint-failure"
		writeXCAPError(writer, constraintFailure("a group regroup creation request carries a temporary group with constituent groups"))
		return
	}
	result["temporary_group_id"], result["constituents"] = group.ID, group.TemporaryConstituents
	// Step b: the sender must be authorised to form temporary groups, in its own tree.
	if target.usersXUI != claims.MCPTTID || !svc.mayFormTemporaryGroups(claims.MCPTTID) {
		fail(http.StatusForbidden, "not_authorised")
		return
	}
	seen := map[string]bool{group.ID: true}
	for _, id := range group.TemporaryConstituents {
		if seen[id] || !validSIPIdentity(id) {
			result["status"], result["reason"] = http.StatusConflict, "constraint-failure"
			writeXCAPError(writer, constraintFailure("repeated or invalid constituent MCPTT group ID"))
			return
		}
		seen[id] = true
	}
	// Step c: the temporary MCS group ID must be free and of this provider, and is not being formed by another
	// request (reserved until this one ends).
	_, configured := svc.cfg.groupByID(group.ID)
	_, stored := svc.documentOf(group.ID)
	reserved := false
	if !configured && !stored {
		svc.groupDocs.mu.Lock()
		if !svc.groupDocs.forming[group.ID] {
			svc.groupDocs.forming[group.ID], reserved = true, true
		}
		svc.groupDocs.mu.Unlock()
	}
	if reserved {
		defer func() {
			svc.groupDocs.mu.Lock()
			delete(svc.groupDocs.forming, group.ID)
			svc.groupDocs.mu.Unlock()
		}()
	}
	if !strings.HasSuffix(group.ID, "@"+svc.cfg.Domain) || !validSIPIdentity(group.ID) || !reserved {
		alt := "sip:" + target.name + "-" + mustRandom(6) + "@" + svc.cfg.Domain
		result["status"], result["reason"] = http.StatusConflict, "uniqueness-failure"
		writeXCAPError(writer, &xcapError{Status: http.StatusConflict, Element: "uniqueness-failure", Alt: []string{alt}})
		return
	}
	mark := &TemporaryRegroup{TGI: group.ID, Requestor: claims.MCPTTID, Constituents: group.TemporaryConstituents,
		ProtectMedia: &group.ProtectMedia, ProtectFloor: &group.ProtectFloor}
	// Step d: every constituent group is checked.
	steps := []map[string]any{}
	for _, id := range group.TemporaryConstituents {
		status := svc.regroupStep("check", id, mark)
		steps = append(steps, map[string]any{"group": id, "step": "check", "status": status})
		if status/100 != 2 {
			result["steps"] = steps
			fail(http.StatusForbidden, "constituent_group_refused")
			return
		}
	}
	// Then each marks it; a refusal undoes the marks already placed.
	var placed []string
	for _, id := range group.TemporaryConstituents {
		status := svc.regroupStep("notification", id, mark)
		steps = append(steps, map[string]any{"group": id, "step": "notification", "status": status})
		if status/100 != 2 {
			for _, done := range placed {
				svc.regroupStep("delete", done, mark)
			}
			result["steps"] = steps
			fail(http.StatusForbidden, "constituent_group_refused")
			return
		}
		placed = append(placed, id)
	}
	result["steps"] = steps
	document, err := groupDocument(group, true)
	if err == nil {
		svc.groupDocs.mu.Lock()
		doc := &storedGroupDocument{ID: group.ID, Owner: claims.MCPTTID, Document: target.name, XML: document, Version: 1}
		previous := svc.groupDocs.groups[group.ID]
		if previous != nil {
			doc.Version = previous.Version + 1
		}
		if previous != nil && !previous.Deleted {
			// Stored meanwhile by another way (an XCAP PUT): not overwritten.
			err = errors.New("group document created meanwhile")
		} else if err = svc.saveDocumentLocked(doc); err == nil {
			svc.groupDocs.groups[group.ID] = doc
		}
		svc.groupDocs.mu.Unlock()
	}
	if err != nil {
		for _, done := range placed {
			svc.regroupStep("delete", done, mark)
		}
		fail(http.StatusInternalServerError, "storage_unavailable")
		return
	}
	etag := documentETag(document)
	result["status"] = http.StatusOK
	writer.Header().Set("ETag", etag)
	writer.Header().Set("Content-Type", gmopMIME)
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(gmopCreationResponse(etag))
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.15.3.1: tearDownTemporaryGroup: each constituent group's mark is
// removed, then the temporary group's document.
func (svc *service) tearDownTemporaryGroup(writer http.ResponseWriter, request *http.Request, identity string, group Group) {
	result := map[string]any{"temporary_group_id": group.ID, "by": identity}
	defer func() { svc.logEvent("temporary_group_torn_down", result) }()
	mark := &TemporaryRegroup{TGI: group.ID}
	steps := []map[string]any{}
	for _, id := range group.TemporaryConstituents {
		status := svc.regroupStep("delete", id, mark)
		steps = append(steps, map[string]any{"group": id, "status": status})
	}
	result["steps"] = steps
	svc.groupDocs.mu.Lock()
	doc := &storedGroupDocument{ID: group.ID, Deleted: true, Version: 1}
	if stored := svc.groupDocs.groups[group.ID]; stored != nil {
		doc.Owner, doc.Document, doc.Version = stored.Owner, stored.Document, stored.Version+1
	}
	svc.groupDocs.groups[group.ID] = doc
	err := svc.saveDocumentLocked(doc)
	svc.groupDocs.mu.Unlock()
	if err != nil {
		result["status"] = http.StatusInternalServerError
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "storage unavailable"})
		return
	}
	result["status"] = http.StatusOK
	writer.WriteHeader(http.StatusOK)
}

// ------------------------------------------------------------------------------
// TS 33.180 clause 5.7: keyGroup is a group as the GMS keys it: a temporary group's
// members are those of its constituent groups.
func (svc *service) keyGroup(original Group) Group {
	if len(original.TemporaryConstituents) == 0 {
		return original
	}
	out := original
	out.Members = nil
	for _, id := range original.TemporaryConstituents {
		constituent, ok := svc.group(id)
		if !ok {
			continue
		}
		for _, member := range constituent.Members {
			if !slices.Contains(out.Members, member) {
				out.Members = append(out.Members, member)
			}
		}
	}
	return out
}

// ------------------------------------------------------------------------------
// Helper: getInternalTemporaryGroups gives the MCPTT and MCData servers the temporary
// groups this GMS formed and the groups they combine.
func (svc *service) getInternalTemporaryGroups(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	type temporary struct {
		ID           string   `json:"id"`
		Constituents []string `json:"constituents"`
		Requestor    string   `json:"requestor"`
		Type         string   `json:"type,omitempty"`
	}
	type regrouped struct {
		Group        string   `json:"group"`
		TGI          string   `json:"temporary_group_id"`
		Requestor    string   `json:"requestor"`
		Constituents []string `json:"constituents"`
	}
	out := struct {
		Temporary []temporary `json:"temporary"`
		Regrouped []regrouped `json:"regrouped"`
	}{Temporary: []temporary{}, Regrouped: []regrouped{}}
	svc.groupDocs.mu.Lock()
	docs := make([]storedGroupDocument, 0, len(svc.groupDocs.groups))
	for _, doc := range svc.groupDocs.groups {
		if !doc.Deleted {
			docs = append(docs, *doc)
		}
	}
	svc.groupDocs.mu.Unlock()
	slices.SortFunc(docs, func(left, right storedGroupDocument) int { return strings.Compare(left.ID, right.ID) })
	for _, doc := range docs {
		group, err := parseGroupDocument(doc.XML)
		if err != nil {
			continue
		}
		if len(group.TemporaryConstituents) > 0 {
			out.Temporary = append(out.Temporary, temporary{ID: group.ID, Constituents: group.TemporaryConstituents, Requestor: doc.Owner, Type: group.Type})
		}
		if group.RegroupedBy != nil {
			out.Regrouped = append(out.Regrouped, regrouped{Group: group.ID, TGI: group.RegroupedBy.TGI,
				Requestor: group.RegroupedBy.Requestor, Constituents: group.RegroupedBy.Constituents})
		}
	}
	writeJSON(writer, http.StatusOK, out)
}
