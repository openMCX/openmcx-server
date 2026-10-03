// The group documents of the GMS: their store, their authorization, and the XCAP operations on them in the users
// tree and addressed by group ID (create, retrieve, update, delete, and element and attribute operations).
//
// Specifications: TS 24.481 V19.3.0 (Rel-19), RFC 4825, OMA XDM (Group XDM).
package common

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// The group documents of the GMS, writable with XCAP (TS 24.481 clause 6.3.2 to
// clause 6.3.12, RFC 4825). A document lives in the users tree of the XUI that created it
// (org.openmobilealliance.groups/users/{XUI}/{document}) and is also addressed by its
// group ID (global/byGroupID/{group}, TS 24.481 clause 7.2.10.2). The groups of the site configuration
// are the initial documents; they have no owner and are managed under the MCS service
// provider's policy (TS 24.481 clause 7.2.12.1: "subject to MCS service provider policy"), which here is
// the user profile's group_management "manage" list.
//
// Every change bumps the group's version; the servers and the SIP subscription front
// of the GMS (TS 24.481 clause 6.3.13.3.3, in the MCPTT server) learn changes from it.

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.3: the XCAP root path of the application usage of the group documents.
const groupsAUID = "/xcap-root/org.openmobilealliance.groups"

// ------------------------------------------------------------------------------
// Helper: a stored group document with its users tree, name and version; a deleted one is kept as a tombstone.
type storedGroupDocument struct {
	ID       string `json:"id"`
	Owner    string `json:"owner,omitempty"` // the XUI of the users tree; empty for a provisioned group
	Document string `json:"document"`        // its name in the users tree
	XML      []byte `json:"xml"`
	Version  int64  `json:"version"`
	Deleted  bool   `json:"deleted,omitempty"`
}

// ------------------------------------------------------------------------------
// Helper: the stored group documents by group ID, persisted in the data directory.
type groupStore struct {
	mu     sync.Mutex
	dir    string
	groups map[string]*storedGroupDocument
	// The temporary group IDs being formed (TS 24.481 clause 6.3.14.3.1): taken at step c, so that two
	// formations of one ID cannot both pass it.
	forming map[string]bool
}

// ------------------------------------------------------------------------------
// Helper: loads the stored group documents from the data directory.
func (svc *service) loadGroupStore() error {
	svc.groupDocs = &groupStore{dir: filepath.Join(svc.dataDir, "groups"), groups: map[string]*storedGroupDocument{},
		forming: map[string]bool{}}
	if err := os.MkdirAll(svc.groupDocs.dir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(svc.groupDocs.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(svc.groupDocs.dir, entry.Name()))
		if err != nil {
			return err
		}
		var doc storedGroupDocument
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("decode group document %s: %w", entry.Name(), err)
		}
		svc.groupDocs.groups[doc.ID] = &doc
	}
	return nil
}

// ------------------------------------------------------------------------------
// Helper: group is the effective group: a stored document, else the configured group.
func (svc *service) group(id string) (Group, bool) {
	if svc.groupDocs == nil {
		return svc.cfg.groupByID(id)
	}
	svc.groupDocs.mu.Lock()
	doc := svc.groupDocs.groups[id]
	svc.groupDocs.mu.Unlock()
	if doc == nil {
		return svc.cfg.groupByID(id)
	}
	if doc.Deleted {
		return Group{}, false
	}
	group, err := parseGroupDocument(doc.XML)
	if err != nil {
		return Group{}, false
	}
	return group, true
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.13.3.3: groupVersion is the version of a group's document: 0 for a provisioned group never
// changed.
func (svc *service) groupVersion(id string) int64 {
	if svc.groupDocs == nil {
		return 0
	}
	svc.groupDocs.mu.Lock()
	defer svc.groupDocs.mu.Unlock()
	if doc := svc.groupDocs.groups[id]; doc != nil {
		return doc.Version
	}
	return 0
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.10.2: documentOf returns a group's complete document with its owner and name, the
// configured group rendered on first use.
func (svc *service) documentOf(id string) (*storedGroupDocument, bool) {
	svc.groupDocs.mu.Lock()
	defer svc.groupDocs.mu.Unlock()
	if doc := svc.groupDocs.groups[id]; doc != nil {
		if doc.Deleted {
			return nil, false
		}
		stored := *doc
		return &stored, true
	}
	group, ok := svc.cfg.groupByID(id)
	if !ok {
		return nil, false
	}
	raw, err := groupDocument(group, true)
	if err != nil {
		return nil, false
	}
	return &storedGroupDocument{ID: id, Document: documentName(id), XML: raw}, true
}

// ------------------------------------------------------------------------------
// Helper: the document name of a group in the users tree: the user part of its group ID.
func documentName(id string) string {
	name := strings.TrimPrefix(id, "sip:")
	if at := strings.IndexByte(name, '@'); at >= 0 {
		name = name[:at]
	}
	return name
}

// ------------------------------------------------------------------------------
// Helper: persists one group document atomically; the caller holds groupDocs.mu.
func (svc *service) saveDocumentLocked(doc *storedGroupDocument) error {
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(doc.ID))
	path := filepath.Join(svc.groupDocs.dir, hex.EncodeToString(sum[:16])+".json")
	return writeFileAtomic(path, raw)
}

// ------------------------------------------------------------------------------
// RFC 4825 section 8.5: the entity tag of a document, a digest of its content.
func documentETag(raw []byte) string {
	sum := sha256.Sum256(raw)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// ---- authorization (TS 24.481 clause 7.2.12.1) ----

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.12.1: mayManage: the owner of the users tree, or the provider policy
// (group_management.manage).
func (svc *service) mayManage(identity string, doc *storedGroupDocument) bool {
	if doc.Owner != "" && doc.Owner == identity {
		return true
	}
	user, ok := svc.siteUser("mcptt_id", identity)
	if !ok || user.GroupManagement == nil {
		return false
	}
	return slices.Contains(user.GroupManagement.Manage, "*") || slices.Contains(user.GroupManagement.Manage, doc.ID)
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.2.3 step b: whether an identity is authorized to initiate group creation (provider policy).
func (svc *service) mayCreateGroups(identity string) bool {
	user, ok := svc.siteUser("mcptt_id", identity)
	return ok && user.GroupManagement != nil && user.GroupManagement.Create
}

// ---- XCAP requests ----

// ------------------------------------------------------------------------------
// RFC 4825 section 6: the document and node selector an XCAP request addresses.
type xcapTarget struct {
	doc      *storedGroupDocument // nil when the document does not exist
	selector string               // empty for the whole document
	query    string
	usersXUI string // set for a users-tree URI
	name     string // the document name of a users-tree URI
	groupID  string // set for a byGroupID URI
}

// ------------------------------------------------------------------------------
// RFC 4825 section 6: splitXCAP separates "document/~~/node-selector".
func splitXCAP(rest string) (string, string) {
	if index := strings.Index(rest, "/~~/"); index >= 0 {
		return rest[:index], rest[index+len("/~~/"):]
	}
	return rest, ""
}

// ------------------------------------------------------------------------------
// RFC 4825 section 6.2: the target of a request in the users tree of an XUI.
func (svc *service) usersTarget(request *http.Request) (xcapTarget, error) {
	document, selector := splitXCAP(request.PathValue("rest"))
	if document == "" || strings.Contains(document, "/") {
		return xcapTarget{}, xcapFail(404, "", "no such document")
	}
	target := xcapTarget{selector: selector, query: request.URL.RawQuery, usersXUI: request.PathValue("xui"), name: document}
	svc.groupDocs.mu.Lock()
	for _, doc := range svc.groupDocs.groups {
		if !doc.Deleted && doc.Owner == target.usersXUI && doc.Document == document {
			stored := *doc
			target.doc = &stored
		}
	}
	svc.groupDocs.mu.Unlock()
	return target, nil
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.10.2: the target of a request for a group document addressed by its group ID.
func (svc *service) globalTarget(request *http.Request) (xcapTarget, error) {
	group, selector := splitXCAP(request.PathValue("rest"))
	target := xcapTarget{selector: selector, query: request.URL.RawQuery, groupID: group}
	if doc, ok := svc.documentOf(group); ok {
		target.doc = doc
	}
	return target, nil
}

// ------------------------------------------------------------------------------
// RFC 4825 section 11: sends an XCAP error as a detailed conflict report, or as JSON when it has no error element.
func writeXCAPError(writer http.ResponseWriter, err error) {
	var xcapErr *xcapError
	if !errors.As(err, &xcapErr) {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if xcapErr.Element == "" {
		writeJSON(writer, xcapErr.Status, map[string]string{"error": xcapErr.Detail})
		return
	}
	writer.Header().Set("Content-Type", "application/xcap-error+xml")
	writer.WriteHeader(xcapErr.Status)
	_, _ = writer.Write(xcapErrorBody(xcapErr))
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.3.3, clause 6.3.8.3, clause 6.3.11.3 and clause 6.3.12.3: fetch the document, an element, an
// attribute or the namespace bindings (RFC 4825 section 8.3).
func (svc *service) xcapGet(writer http.ResponseWriter, request *http.Request, target xcapTarget) {
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok {
		return
	}
	if target.doc == nil {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	full := svc.mayManage(claims.MCPTTID, target.doc)
	var raw []byte
	if full {
		raw = target.doc.XML
	} else {
		// Others read what TS 24.481 clause 7.2.12.1 lets them: the members' view.
		group, err := parseGroupDocument(target.doc.XML)
		if err != nil {
			writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		readable, ok := readableGroup(group, claims.MCPTTID, false)
		if !ok {
			writeJSON(writer, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		if raw, err = groupDocument(readable, true); err != nil {
			writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
	}
	if target.selector == "" {
		writeDocument(writer, request, raw, groupDocumentMIME)
		return
	}
	root, sel, err := selectorOn(raw, target)
	if err != nil {
		writeXCAPError(writer, err)
		return
	}
	contentType, body, err := xcapFetch(root, sel)
	if err != nil {
		writeXCAPError(writer, err)
		return
	}
	writer.Header().Set("ETag", documentETag(target.doc.XML))
	writer.Header().Set("Content-Type", contentType)
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body)
}

// ------------------------------------------------------------------------------
// RFC 4825 section 6.3 and section 6.4: the parsed document and the node selector of a request, with the namespace
// bindings of its query.
func selectorOn(raw []byte, target xcapTarget) (*xmlNode, nodeSelector, error) {
	root, err := parseXMLTree(raw)
	if err != nil {
		return nil, nodeSelector{}, err
	}
	bindings, err := parseXMLNSQuery(target.query)
	if err != nil {
		return nil, nodeSelector{}, err
	}
	sel, err := parseNodeSelector(target.selector, bindings, pocNS)
	return root, sel, err
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.2.3 and clause 6.3.4.3 (a whole document), clause 6.3.6.3 and clause 6.3.9.3 (an element or
// an attribute): RFC 4825 section 8.2 "PUT Handling".
func (svc *service) xcapPut(writer http.ResponseWriter, request *http.Request, target xcapTarget) {
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, 64<<10))
	if err != nil {
		writeJSON(writer, http.StatusRequestEntityTooLarge, map[string]string{"error": "too_large"})
		return
	}
	var next []byte
	created := false
	switch {
	case target.doc == nil && target.selector == "" && target.usersXUI != "":
		// TS 24.481 clause 6.3.2.3 step b: creation in the requester's own users tree.
		if target.usersXUI != claims.MCPTTID || !svc.mayCreateGroups(claims.MCPTTID) {
			writeJSON(writer, http.StatusForbidden, map[string]string{"error": "not authorised to create groups"})
			return
		}
		if mediaType(request.Header.Get("Content-Type")) != groupDocumentMIME {
			writeJSON(writer, http.StatusUnsupportedMediaType, map[string]string{"error": "unsupported_media_type"})
			return
		}
		next, created = body, true
	case target.doc == nil:
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	default:
		if !svc.mayManage(claims.MCPTTID, target.doc) {
			writeJSON(writer, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		if match := request.Header.Get("If-Match"); match != "" && match != "*" && match != documentETag(target.doc.XML) {
			writeJSON(writer, http.StatusPreconditionFailed, map[string]string{"error": "etag mismatch"})
			return
		}
		if target.selector == "" {
			if mediaType(request.Header.Get("Content-Type")) != groupDocumentMIME {
				writeJSON(writer, http.StatusUnsupportedMediaType, map[string]string{"error": "unsupported_media_type"})
				return
			}
			next = body
		} else {
			root, sel, err := selectorOn(target.doc.XML, target)
			if err == nil {
				created, err = xcapPut(root, sel, body)
			}
			if err != nil {
				writeXCAPError(writer, err)
				return
			}
			next = root.serialize()
		}
	}
	etag, err := svc.commitDocument(claims.MCPTTID, target, next, created && target.selector == "")
	if err != nil {
		writeXCAPError(writer, err)
		return
	}
	writer.Header().Set("ETag", etag)
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writer.WriteHeader(status)
}

// ------------------------------------------------------------------------------
// RFC 4825 section 8.2.5: commitDocument validates a changed document (the schema of TS 24.481
// clause 7.2.4, then the constraints of TS 24.481 clause 7.2.7) and stores it.
func (svc *service) commitDocument(identity string, target xcapTarget, raw []byte, creation bool) (string, error) {
	owner := target.usersXUI
	if target.doc != nil {
		owner = target.doc.Owner
	}
	if err := validateGroupDocument(raw, owner); err != nil {
		svc.logEvent("group_document_refused", map[string]any{"by": identity, "document": target.name, "group": target.groupID, "error": err.Error()})
		return "", err
	}
	next, err := parseGroupDocument(raw)
	if err != nil {
		return "", constraintFailure(err.Error())
	}
	svc.groupDocs.mu.Lock()
	defer svc.groupDocs.mu.Unlock()
	if creation {
		// TS 24.481 clause 6.3.2.3 step c: the MCS group ID must be free, in this provider's domain.
		alt := "sip:" + target.name + "-" + mustRandom(6) + "@" + svc.cfg.Domain
		if !strings.HasSuffix(next.ID, "@"+svc.cfg.Domain) || !validSIPIdentity(next.ID) {
			return "", &xcapError{Status: 409, Element: "uniqueness-failure", Alt: []string{alt}}
		}
		if existing := svc.groupDocs.groups[next.ID]; (existing != nil && !existing.Deleted) || func() bool {
			_, configured := svc.cfg.groupByID(next.ID)
			return configured && existing == nil
		}() {
			return "", &xcapError{Status: 409, Element: "uniqueness-failure", Alt: []string{alt}}
		}
		// TS 24.481 clause 7.2.12.1: a temporary group is formed by the GMOP request of TS 24.481 clause 6.3.14.3.1 only.
		if len(next.TemporaryConstituents) > 0 || next.RegroupedBy != nil {
			return "", xcapFail(409, "constraint-failure", "a temporary group is formed by a group regroup creation request")
		}
		doc := &storedGroupDocument{ID: next.ID, Owner: identity, Document: target.name, XML: raw, Version: 1}
		if previous := svc.groupDocs.groups[next.ID]; previous != nil {
			doc.Version = previous.Version + 1
		}
		svc.groupDocs.groups[next.ID] = doc
		return documentETag(raw), svc.saveDocumentLocked(doc)
	}
	previous := target.doc
	if next.ID != previous.ID {
		return "", xcapFail(409, "constraint-failure", "the MCS group ID of a document cannot change")
	}
	before, _ := parseGroupDocument(previous.XML)
	// TS 24.481 clause 7.2.12.1: the regrouped state is the regroup procedure's alone, and no one
	// creates, changes or deletes <on-network-temporary> or <on-network-regrouped>.
	if before.Regrouped != next.Regrouped || !slices.Equal(before.TemporaryConstituents, next.TemporaryConstituents) ||
		!sameRegroupMark(before.RegroupedBy, next.RegroupedBy) {
		return "", xcapFail(409, "constraint-failure", "the regrouped state cannot be changed")
	}
	doc := &storedGroupDocument{ID: previous.ID, Owner: previous.Owner, Document: previous.Document, XML: raw, Version: 1}
	if stored := svc.groupDocs.groups[previous.ID]; stored != nil {
		doc.Version = stored.Version + 1
	}
	svc.groupDocs.groups[doc.ID] = doc
	return documentETag(raw), svc.saveDocumentLocked(doc)
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.5.3, clause 6.3.7.3 and clause 6.3.10.3: delete the document, an element or an attribute
// (RFC 4825 section 8.4).
func (svc *service) xcapDelete(writer http.ResponseWriter, request *http.Request, target xcapTarget) {
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok {
		return
	}
	if target.doc == nil {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	if !svc.mayManage(claims.MCPTTID, target.doc) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	if match := request.Header.Get("If-Match"); match != "" && match != "*" && match != documentETag(target.doc.XML) {
		writeJSON(writer, http.StatusPreconditionFailed, map[string]string{"error": "etag mismatch"})
		return
	}
	if target.selector == "" {
		group, err := parseGroupDocument(target.doc.XML)
		if err == nil && (group.Regrouped || group.RegroupedBy != nil) {
			// TS 24.481 clause 7.2.12.1: a regrouped group's document is not deleted.
			writeXCAPError(writer, xcapFail(409, "cannot-delete", "the group is regrouped"))
			return
		}
		if err == nil && len(group.TemporaryConstituents) > 0 {
			// TS 24.481 clause 6.3.15.3.1: the tear down of a temporary group.
			svc.tearDownTemporaryGroup(writer, request, claims.MCPTTID, group)
			return
		}
		svc.groupDocs.mu.Lock()
		doc := &storedGroupDocument{ID: target.doc.ID, Owner: target.doc.Owner, Document: target.doc.Document, Deleted: true, Version: 1}
		if stored := svc.groupDocs.groups[target.doc.ID]; stored != nil {
			doc.Version = stored.Version + 1
		}
		svc.groupDocs.groups[doc.ID] = doc
		err = svc.saveDocumentLocked(doc)
		svc.groupDocs.mu.Unlock()
		if err != nil {
			writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "storage unavailable"})
			return
		}
		writer.WriteHeader(http.StatusOK)
		return
	}
	root, sel, err := selectorOn(target.doc.XML, target)
	if err == nil {
		err = xcapDelete(root, sel)
	}
	if err != nil {
		writeXCAPError(writer, err)
		return
	}
	etag, err := svc.commitDocument(claims.MCPTTID, target, root.serialize(), false)
	if err != nil {
		writeXCAPError(writer, err)
		return
	}
	writer.Header().Set("ETag", etag)
	writer.WriteHeader(http.StatusOK)
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.10: the XCAP routes of the group documents in the users tree and addressed by group ID,
// with the GMOP requests of the temporary group procedures (TS 24.481 clause 6.3.14 and clause 6.3.15).
func (svc *service) routesGroupDocuments(mux *http.ServeMux) {
	users := groupsAUID + "/users/{xui}/{rest...}"
	// TS 24.481 clause 6.3.14.3.1: a GMOP request forming a temporary group in the users tree.
	mux.HandleFunc("POST "+users, svc.createTemporaryGroup)
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		method := method
		handle := func(target xcapTarget, writer http.ResponseWriter, request *http.Request) {
			switch method {
			case "GET":
				svc.xcapGet(writer, request, target)
			case "PUT":
				svc.xcapPut(writer, request, target)
			default:
				svc.xcapDelete(writer, request, target)
			}
		}
		mux.HandleFunc(method+" "+users, func(writer http.ResponseWriter, request *http.Request) {
			target, err := svc.usersTarget(request)
			if err != nil {
				writeXCAPError(writer, err)
				return
			}
			handle(target, writer, request)
		})
		if method == "GET" {
			continue // the global tree's GET is the group document procedure (TS 24.481 clause 6.3.3.3, clause 7.2.12.1)
		}
		mux.HandleFunc(method+" "+groupsAUID+"/global/byGroupID/{rest...}", func(writer http.ResponseWriter, request *http.Request) {
			target, err := svc.globalTarget(request)
			if err != nil {
				writeXCAPError(writer, err)
				return
			}
			handle(target, writer, request)
		})
	}
}
