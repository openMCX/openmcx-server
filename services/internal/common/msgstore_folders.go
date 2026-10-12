//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCData message store function: creating, retrieving, deleting and searching folders.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 23.282 V19.10.0 (Rel-19),
// OMA RESTful Network API for Message Storage (OMA-TS-REST_NetAPI_NMS-V1_0).

package common

import (
	"net/http"
	"strings"
)

// ---- folders ----

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.8.2 (OMA NMS clause 6.13): create a folder, under the root unless a parent folder is
// given; a duplicate name under the same parent is refused (409).
func (svc *service) nmsCreateFolder(writer http.ResponseWriter, request *http.Request) {
	box, _, ok := svc.boxOf(writer, request)
	if !ok {
		return
	}
	var folder nmsFolder
	if !readJSON(writer, request, "folder", &folder) {
		return
	}
	if folder.Name == "" || len(folder.Name) > 128 || strings.ContainsAny(folder.Name, "/\\") {
		nmsError(writer, http.StatusBadRequest, "SVC0002", "Invalid input value for message part %1", "name")
		return
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	parent := box.Root
	if folder.ParentFolder != "" {
		parent = lastSegment(folder.ParentFolder, "folders")
	}
	if box.Folders[parent] == nil {
		nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "parentFolder")
		return
	}
	for _, existing := range box.Folders {
		if existing.Parent == parent && existing.Name == folder.Name {
			nmsError(writer, http.StatusConflict, "SVC0005", "Duplicate folder name %1", folder.Name)
			return
		}
	}
	created := &storedFolder{ID: mustRandom(12), Name: folder.Name, Parent: parent}
	if folder.Attributes != nil {
		created.Attributes = folder.Attributes.Attribute
	}
	box.ModSeq++
	created.ModSeq = box.ModSeq
	box.Folders[created.ID] = created
	svc.recordLocked(box, "changedFolder", map[string]any{"resourceURL": svc.boxURL(request, box) + "/folders/" + created.ID,
		"parentFolder": svc.boxURL(request, box) + "/folders/" + parent, "lastModSeq": created.ModSeq})
	if svc.commitLocked(writer, box) {
		url := svc.boxURL(request, box) + "/folders/" + created.ID
		writer.Header().Set("Location", url)
		writeJSON(writer, http.StatusCreated, map[string]any{"reference": nmsReference{ResourceURL: url, Path: folderPath(box, created.ID)}})
	}
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.18.2 (OMA NMS clause 6.14): a folder with its subfolders and objects; "root" names
// the root.
func (svc *service) nmsGetFolder(writer http.ResponseWriter, request *http.Request) {
	box, _, ok := svc.boxOf(writer, request)
	if !ok {
		return
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	id := request.PathValue("folder")
	if id == "root" {
		id = box.Root
	}
	folder := box.Folders[id]
	if folder == nil {
		nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "folderId")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"folder": svc.folderView(request, box, folder, true)})
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.7.2 (OMA NMS clause 6.14.6): delete a folder with everything in it. The root and the
// Inbox stay.
func (svc *service) nmsDeleteFolder(writer http.ResponseWriter, request *http.Request) {
	box, _, ok := svc.boxOf(writer, request)
	if !ok {
		return
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	folder := box.Folders[request.PathValue("folder")]
	if folder == nil {
		nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "folderId")
		return
	}
	if folder.ID == box.Root || folder.ID == box.Inbox {
		nmsError(writer, http.StatusForbidden, "POL0002", "The %1 folder cannot be deleted", folder.Name)
		return
	}
	var remove func(id string)
	remove = func(id string) {
		for _, object := range sortedObjects(box) {
			if object.Folder == id {
				svc.deleteObjectLocked(request, box, object)
			}
		}
		for _, child := range sortedFolders(box) {
			if child.Parent == id {
				remove(child.ID)
			}
		}
		delete(box.Folders, id)
		box.ModSeq++
		svc.recordLocked(box, "deletedFolder", map[string]any{"resourceURL": svc.boxURL(request, box) + "/folders/" + id, "lastModSeq": box.ModSeq})
	}
	remove(folder.ID)
	if svc.commitLocked(writer, box) {
		writer.WriteHeader(http.StatusNoContent)
	}
}

// ------------------------------------------------------------------------------
// TS 24.282 clauses 21.2.11.2 and 21.2.23.2 (OMA NMS clause 6.16): folder search. Without search criteria and
// scope limit the answer is the hierarchy below the root or the given folder (FolderReferenceList, list folder
// hierarchy procedure).
func (svc *service) nmsSearchFolders(writer http.ResponseWriter, request *http.Request) {
	box, _, ok := svc.boxOf(writer, request)
	if !ok {
		return
	}
	var sel nmsSelection
	if !readJSON(writer, request, "selectionCriteria", &sel) {
		return
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	scope := box.Root
	if sel.SearchScope != nil && sel.SearchScope.ResourceURL != "" {
		scope = lastSegment(sel.SearchScope.ResourceURL, "folders")
		if box.Folders[scope] == nil {
			nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "searchScope")
			return
		}
	}
	base := svc.boxURL(request, box)
	if sel.SearchCriteria == nil && sel.NonRecursiveScope == nil {
		refs := []nmsReference{}
		for _, folder := range sortedFolders(box) {
			if folder.ID != scope && inScope(box, folder.ID, scope, true) {
				refs = append(refs, nmsReference{ResourceURL: base + "/folders/" + folder.ID, Path: folderPath(box, folder.ID), Name: folder.Name})
			}
		}
		// The root itself is listed first, so a client learns its ID (TS 24.282 clause 21.2.18.1 NOTE).
		root := box.Folders[scope]
		refs = append([]nmsReference{{ResourceURL: base + "/folders/" + root.ID, Path: folderPath(box, root.ID), Name: root.Name}}, refs...)
		writeJSON(writer, http.StatusOK, map[string]any{"folderReferenceList": map[string]any{"folderReference": refs}})
		return
	}
	recursive := sel.NonRecursiveScope == nil || !*sel.NonRecursiveScope
	folders := []nmsFolder{}
	for _, folder := range sortedFolders(box) {
		if folder.ID == scope || !inScope(box, folder.ID, scope, recursive) || (!recursive && folder.Parent != scope) {
			continue
		}
		match := true
		if sel.SearchCriteria != nil {
			for _, criterion := range sel.SearchCriteria.Criterion {
				switch criterion.Type {
				case "Name":
					match = match && strings.EqualFold(folder.Name, criterion.Value)
				case "Attribute":
					found := false
					for _, value := range attributeValues(folder.Attributes, criterion.Name) {
						found = found || strings.EqualFold(value, criterion.Value)
					}
					match = match && found
				}
			}
		}
		if match {
			folders = append(folders, svc.folderView(request, box, folder, false))
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{"folderList": map[string]any{"folder": folders}})
}
