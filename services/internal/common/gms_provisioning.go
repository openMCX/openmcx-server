//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Group provisioning by MCX Admin through the GMS: an internal interface that stores a group as an XCAP write of
// the whole group document would.
//
// Specifications: TS 24.481 V19.3.0 (Rel-19).
package common

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"sort"
)

// Group provisioning: MCX Admin writes
// the groups it manages through the GMS, with the server client credentials. A group
// comes in the site.json form and is rendered and committed like an XCAP write of
// the whole document (TS 24.481 clause 7.2.4 schema, clause 7.2.7 constraints): the same stored
// document, version and change notification (TS 24.481 clause 6.3.13.3.3 through the MCPTT server's
// subscription front). This is not a 3GPP interface; the XCAP interface is unchanged.

// ------------------------------------------------------------------------------
// Helper: the routes of the internal group provisioning interface (not a 3GPP interface).
func (svc *service) routesGroupProvisioning(mux *http.ServeMux) {
	mux.HandleFunc("GET /internal/groups", svc.listProvisionedGroups)
	mux.HandleFunc("PUT /internal/groups", svc.provisionGroup)
	mux.HandleFunc("DELETE /internal/groups", svc.deprovisionGroup)
}

// ------------------------------------------------------------------------------
// Helper: one group as the provisioning interface lists it.
type provisionedGroup struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
	ETag    string `json:"etag,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
	Group   *Group `json:"group,omitempty"`
}

// ------------------------------------------------------------------------------
// Helper: listProvisionedGroups gives every group with its version, so that MCX Admin sees
// what users changed by XCAP (slice D3). A configured group never changed is version 0.
func (svc *service) listProvisionedGroups(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	svc.groupDocs.mu.Lock()
	out := map[string]provisionedGroup{}
	for id, doc := range svc.groupDocs.groups {
		entry := provisionedGroup{ID: id, Version: doc.Version, Deleted: doc.Deleted}
		if !doc.Deleted {
			if group, err := parseGroupDocument(doc.XML); err == nil {
				entry.Group, entry.ETag = &group, documentETag(doc.XML)
			}
		}
		out[id] = entry
	}
	svc.groupDocs.mu.Unlock()
	for _, group := range svc.cfg.Groups {
		if _, stored := out[group.ID]; stored {
			continue
		}
		if raw, err := groupDocument(group, true); err == nil {
			provisioned := group
			out[group.ID] = provisionedGroup{ID: group.ID, ETag: documentETag(raw), Group: &provisioned}
		}
	}
	list := make([]provisionedGroup, 0, len(out))
	for _, entry := range out {
		list = append(list, entry)
	}
	sort.Slice(list, func(left, right int) bool { return list[left].ID < list[right].ID })
	writeJSON(writer, http.StatusOK, map[string]any{"groups": list})
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.4.3 (as for a group document update): provisionGroup creates or replaces a group, ?id=<group
// ID>. An unchanged group is not a new version, so writing every group again notifies no one.
func (svc *service) provisionGroup(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	id := request.URL.Query().Get("id")
	var group Group
	dec := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&group); err != nil || id == "" || group.ID != id || !validSIPIdentity(id) {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "a group in the site.json form, whose id is the id parameter"})
		return
	}
	raw, err := groupDocument(group, true)
	if err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	svc.groupDocs.mu.Lock()
	defer svc.groupDocs.mu.Unlock()
	previous := svc.groupDocs.groups[id]
	// TS 24.481 clause 7.2.12.1: the regrouped state and a temporary group's constituents are the regroup
	// procedure's; a write may carry them only as the group has them, like an XCAP write.
	var current Group
	if previous != nil && !previous.Deleted {
		current, _ = parseGroupDocument(previous.XML)
	} else if previous == nil {
		current, _ = svc.cfg.groupByID(id)
	}
	if current.Regrouped != group.Regrouped || !slices.Equal(current.TemporaryConstituents, group.TemporaryConstituents) ||
		!sameRegroupMark(current.RegroupedBy, group.RegroupedBy) {
		writeJSON(writer, http.StatusConflict, map[string]string{"error": "the regrouped state and temporary groups are the regroup procedure's"})
		return
	}
	owner, name, version := "", documentName(id), int64(1)
	switch {
	case previous != nil && !previous.Deleted:
		if bytes.Equal(previous.XML, raw) {
			writeJSON(writer, http.StatusOK, map[string]any{"id": id, "version": previous.Version, "etag": documentETag(raw), "changed": false})
			return
		}
		owner, name, version = previous.Owner, previous.Document, previous.Version+1
	case previous != nil:
		version = previous.Version + 1 // created again after a deletion
	default:
		if configured, ok := svc.cfg.groupByID(id); ok {
			if rendered, err := groupDocument(configured, true); err == nil && bytes.Equal(rendered, raw) {
				writeJSON(writer, http.StatusOK, map[string]any{"id": id, "version": 0, "etag": documentETag(raw), "changed": false})
				return
			}
		}
	}
	if err := validateGroupDocument(raw, owner); err != nil {
		svc.logEvent("group_provisioning_refused", map[string]any{"group": id, "error": err.Error()})
		writeXCAPError(writer, err)
		return
	}
	doc := &storedGroupDocument{ID: id, Owner: owner, Document: name, XML: raw, Version: version}
	svc.groupDocs.groups[id] = doc
	if err := svc.saveDocumentLocked(doc); err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "storage unavailable"})
		return
	}
	svc.logEvent("group_provisioned", map[string]any{"group": id, "version": version})
	writeJSON(writer, http.StatusOK, map[string]any{"id": id, "version": version, "etag": documentETag(raw), "changed": true})
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.5.3 (as for a group document deletion): deprovisionGroup deletes a group, ?id=<group ID>;
// deleting a missing group succeeds.
func (svc *service) deprovisionGroup(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	id := request.URL.Query().Get("id")
	svc.groupDocs.mu.Lock()
	defer svc.groupDocs.mu.Unlock()
	previous := svc.groupDocs.groups[id]
	_, configured := svc.cfg.groupByID(id)
	if (previous == nil && !configured) || (previous != nil && previous.Deleted) {
		writeJSON(writer, http.StatusOK, map[string]any{"id": id, "changed": false})
		return
	}
	doc := &storedGroupDocument{ID: id, Document: documentName(id), Deleted: true, Version: 1}
	if previous != nil {
		if before, err := parseGroupDocument(previous.XML); err == nil && (before.Regrouped || before.RegroupedBy != nil || len(before.TemporaryConstituents) > 0) {
			writeJSON(writer, http.StatusConflict, map[string]string{"error": "the group is regrouped or temporary"})
			return
		}
		doc.Owner, doc.Document, doc.Version = previous.Owner, previous.Document, previous.Version+1
	}
	svc.groupDocs.groups[id] = doc
	if err := svc.saveDocumentLocked(doc); err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "storage unavailable"})
		return
	}
	svc.logEvent("group_deprovisioned", map[string]any{"group": id, "version": doc.Version})
	writeJSON(writer, http.StatusOK, map[string]any{"id": id, "version": doc.Version, "changed": true})
}
