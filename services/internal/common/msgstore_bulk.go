//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCData message store function: bulk operations on objects, copying and moving objects and folders.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 23.282 V19.10.0 (Rel-19),
// OMA RESTful Network API for Message Storage (OMA-TS-REST_NetAPI_NMS-V1_0).

package common

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ---- bulk and folder operations on objects ----

type nmsBulkResponse struct {
	Code    int    `json:"code"`
	Reason  string `json:"reason"`
	Success any    `json:"success,omitempty"`
	Failure any    `json:"failure,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2: dispatch an OMA NMS object operation (objects/operations/{operation}): search
// (clause 21.2.2), bulkUpdate (clause 21.2.3), bulkDelete (clause 21.2.4), bulkCreation (clause 21.2.15),
// copyToFolder (clause 21.2.6) and moveToFolder (clause 21.2.10).
func (svc *service) nmsObjectOperation(writer http.ResponseWriter, request *http.Request) {
	box, _, ok := svc.boxOf(writer, request)
	if !ok {
		return
	}
	switch request.PathValue("action") {
	case "search":
		svc.nmsSearchObjects(writer, request, box)
	case "bulkUpdate":
		svc.nmsBulkUpdate(writer, request, box)
	case "bulkDelete":
		svc.nmsBulkDelete(writer, request, box)
	case "bulkCreation":
		svc.nmsBulkCreation(writer, request, box)
	case "copyToFolder", "moveToFolder":
		svc.nmsCopyMove(writer, request, box, request.PathValue("action") == "moveToFolder")
	default:
		nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "operation")
	}
}

type nmsReferenceList struct {
	ObjectReference []nmsReference `json:"objectReference"`
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.3.2 (OMA NMS clause 6.11): add or remove flags on several objects (bulk update).
func (svc *service) nmsBulkUpdate(writer http.ResponseWriter, request *http.Request, box *storeBox) {
	var update struct {
		Objects   nmsReferenceList `json:"objects"`
		Flags     nmsFlags         `json:"flags"`
		Operation string           `json:"operation"`
	}
	if !readJSON(writer, request, "bulkUpdate", &update) {
		return
	}
	if update.Operation != "AddFlag" && update.Operation != "RemoveFlag" {
		nmsError(writer, http.StatusBadRequest, "SVC0002", "Invalid input value for message part %1", "operation")
		return
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	var responses []nmsBulkResponse
	for _, ref := range update.Objects.ObjectReference {
		object := box.Objects[lastSegment(ref.ResourceURL, "objects")]
		if object == nil {
			responses = append(responses, nmsBulkResponse{Code: 404, Reason: "Not Found", Failure: map[string]any{"resourceURL": ref.ResourceURL}})
			continue
		}
		if update.Operation == "AddFlag" {
			object.Flags = uniqueFlags(append(object.Flags, update.Flags.Flag...))
		} else {
			var kept []string
			for _, flag := range object.Flags {
				remove := false
				for _, removed := range update.Flags.Flag {
					remove = remove || flag == removed
				}
				if !remove {
					kept = append(kept, flag)
				}
			}
			object.Flags = kept
		}
		box.ModSeq++
		object.ModSeq = box.ModSeq
		svc.changedObject(request, box, object)
		responses = append(responses, nmsBulkResponse{Code: 200, Reason: "OK", Success: map[string]any{"resourceURL": ref.ResourceURL}})
	}
	if svc.commitLocked(writer, box) {
		writeJSON(writer, http.StatusOK, map[string]any{"bulkResponseList": map[string]any{"response": responses}})
	}
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.4.2 (OMA NMS clause 6.12): delete several objects (bulk delete).
func (svc *service) nmsBulkDelete(writer http.ResponseWriter, request *http.Request, box *storeBox) {
	var list nmsReferenceList
	if !readJSON(writer, request, "objectReferenceList", &list) {
		return
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	var responses []nmsBulkResponse
	for _, ref := range list.ObjectReference {
		object := box.Objects[lastSegment(ref.ResourceURL, "objects")]
		if object == nil {
			responses = append(responses, nmsBulkResponse{Code: 404, Reason: "Not Found", Failure: map[string]any{"resourceURL": ref.ResourceURL}})
			continue
		}
		svc.deleteObjectLocked(request, box, object)
		responses = append(responses, nmsBulkResponse{Code: 204, Reason: "No Content", Success: map[string]any{"resourceURL": ref.ResourceURL}})
	}
	if svc.commitLocked(writer, box) {
		writeJSON(writer, http.StatusOK, map[string]any{"bulkResponseList": map[string]any{"response": responses}})
	}
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.15.2 (OMA NMS clause 6.10): upload several objects (bulk creation); a payload part
// is kept by reference only, and only an https reference.
func (svc *service) nmsBulkCreation(writer http.ResponseWriter, request *http.Request, box *storeBox) {
	var list struct {
		Object []nmsObject `json:"object"`
	}
	if !readJSON(writer, request, "objectList", &list) {
		return
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	var responses []nmsBulkResponse
	for _, object := range list.Object {
		folder := box.Inbox
		if object.ParentFolder != "" {
			folder = lastSegment(object.ParentFolder, "folders")
		}
		if box.Folders[folder] == nil {
			responses = append(responses, nmsBulkResponse{Code: 404, Reason: "Not Found", Failure: map[string]any{"parentFolder": object.ParentFolder}})
			continue
		}
		stored := &storedObject{ID: mustRandom(20), Folder: folder, CorrelationID: object.CorrelationID}
		if object.Attributes != nil {
			stored.Attributes = object.Attributes.Attribute
		}
		if object.Flags != nil {
			stored.Flags = uniqueFlags(object.Flags.Flag)
		}
		for _, part := range object.PayloadPart {
			if part.Href != "" && !strings.HasPrefix(part.Href, "https://") {
				continue
			}
			stored.Parts = append(stored.Parts, storedPart{ContentType: part.ContentType, Size: part.Size, Href: part.Href})
		}
		box.ModSeq++
		box.Creation++
		stored.ModSeq, stored.Created = box.ModSeq, box.Creation
		box.Objects[stored.ID] = stored
		svc.changedObject(request, box, stored)
		responses = append(responses, nmsBulkResponse{Code: 201, Reason: "Created",
			Success: map[string]any{"resourceURL": svc.boxURL(request, box) + "/objects/" + stored.ID}})
	}
	if svc.commitLocked(writer, box) {
		writeJSON(writer, http.StatusOK, map[string]any{"bulkResponseList": map[string]any{"response": responses}})
	}
}

// ------------------------------------------------------------------------------
// TS 24.282 clauses 21.2.6.2 and 21.2.10.2 (OMA NMS clauses 6.18, 6.19): copy or move objects and folders
// into a folder. A copy gets new IDs and its own copy of each local payload.
func (svc *service) nmsCopyMove(writer http.ResponseWriter, request *http.Request, box *storeBox, move bool) {
	var ref struct {
		TargetFolder  string `json:"targetFolder"`
		SourceObjects *struct {
			ObjectReference []nmsReference `json:"objectReference"`
		} `json:"sourceObjects,omitempty"`
		SourceFolders *struct {
			FolderReference []nmsReference `json:"folderReference"`
		} `json:"sourceFolders,omitempty"`
	}
	if !readJSON(writer, request, "targetSourceRef", &ref) {
		return
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	target := lastSegment(ref.TargetFolder, "folders")
	if box.Folders[target] == nil {
		nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "targetFolder")
		return
	}
	base := svc.boxURL(request, box)
	var responses []nmsBulkResponse
	copyObject := func(object *storedObject, folder string) (*storedObject, error) {
		clone := *object
		clone.ID = mustRandom(20)
		clone.Folder = folder
		clone.Parts = nil
		clone.Flags = append([]string{}, object.Flags...)
		clone.Attributes = append([]nmsAttribute{}, object.Attributes...)
		for _, part := range object.Parts {
			if part.File == "" {
				clone.Parts = append(clone.Parts, part)
				continue
			}
			stored, err := svc.copyPayload(part)
			if err != nil {
				svc.removePayloads(clone.Parts) // the copies made so far; references have no file
				return nil, err
			}
			clone.Parts = append(clone.Parts, stored)
		}
		box.ModSeq++
		box.Creation++
		clone.ModSeq, clone.Created = box.ModSeq, box.Creation
		box.Objects[clone.ID] = &clone
		svc.changedObject(request, box, &clone)
		return &clone, nil
	}
	if ref.SourceObjects != nil {
		for _, source := range ref.SourceObjects.ObjectReference {
			object := box.Objects[lastSegment(source.ResourceURL, "objects")]
			if object == nil {
				responses = append(responses, nmsBulkResponse{Code: 404, Reason: "Not Found", Failure: map[string]any{"resourceURL": source.ResourceURL}})
				continue
			}
			if move {
				object.Folder = target
				box.ModSeq++
				object.ModSeq = box.ModSeq
				svc.changedObject(request, box, object)
				responses = append(responses, nmsBulkResponse{Code: 200, Reason: "OK", Success: map[string]any{"resourceURL": base + "/objects/" + object.ID}})
				continue
			}
			clone, err := copyObject(object, target)
			if err != nil {
				responses = append(responses, nmsBulkResponse{Code: 500, Reason: "Internal Server Error"})
				continue
			}
			responses = append(responses, nmsBulkResponse{Code: 201, Reason: "Created", Success: map[string]any{"resourceURL": base + "/objects/" + clone.ID}})
		}
	}
	if ref.SourceFolders != nil {
		for _, source := range ref.SourceFolders.FolderReference {
			folder := box.Folders[lastSegment(source.ResourceURL, "folders")]
			if folder == nil || folder.ID == box.Root || inScope(box, target, folder.ID, true) {
				// Unknown, the root, or a move/copy into its own subtree.
				responses = append(responses, nmsBulkResponse{Code: 400, Reason: "Bad Request", Failure: map[string]any{"resourceURL": source.ResourceURL}})
				continue
			}
			if move {
				folder.Parent = target
				box.ModSeq++
				folder.ModSeq = box.ModSeq
				svc.recordLocked(box, "changedFolder", map[string]any{"resourceURL": base + "/folders/" + folder.ID,
					"parentFolder": base + "/folders/" + target, "lastModSeq": folder.ModSeq})
				responses = append(responses, nmsBulkResponse{Code: 200, Reason: "OK", Success: map[string]any{"resourceURL": base + "/folders/" + folder.ID}})
				continue
			}
			before := snapshotLocked(box)
			copied, err := svc.copyFolderLocked(request, box, folder, target, copyObject)
			if err != nil {
				// No partial copy is kept.
				svc.rollbackLocked(box, before)
				responses = append(responses, nmsBulkResponse{Code: 500, Reason: "Internal Server Error"})
				continue
			}
			responses = append(responses, nmsBulkResponse{Code: 201, Reason: "Created", Success: map[string]any{"resourceURL": base + "/folders/" + copied}})
		}
	}
	if svc.commitLocked(writer, box) {
		writeJSON(writer, http.StatusOK, map[string]any{"bulkResponseList": map[string]any{"response": responses}})
	}
}

// ------------------------------------------------------------------------------
// Helper: a copy of a stored payload file, for a copied object.
func (svc *service) copyPayload(part storedPart) (storedPart, error) {
	source, err := os.Open(filepath.Join(svc.store.dir, "payload", part.File))
	if err != nil {
		return storedPart{}, err
	}
	defer closeQuietly(source)
	return svc.storePayload(source, part.ContentType)
}

// boxSnapshot is what a box held before a change that may have to be undone.
type boxSnapshot struct {
	folders, objects map[string]bool
	lastEvent        int64 // the index of the box's last event, 0 when none
}

// ------------------------------------------------------------------------------
// Helper: the folders, objects and event count of a box; the caller holds the store lock.
func snapshotLocked(box *storeBox) boxSnapshot {
	snapshot := boxSnapshot{folders: map[string]bool{}, objects: map[string]bool{}}
	if count := len(box.Events); count > 0 {
		snapshot.lastEvent = box.Events[count-1].Index
	}
	for id := range box.Folders {
		snapshot.folders[id] = true
	}
	for id := range box.Objects {
		snapshot.objects[id] = true
	}
	return snapshot
}

// ------------------------------------------------------------------------------
// Helper: removes the folders and objects created since the snapshot, with their payload files and the events
// recorded for them; the caller holds the store lock. Only creations are undone (a copy changes nothing else).
func (svc *service) rollbackLocked(box *storeBox, snapshot boxSnapshot) {
	for id := range box.Folders {
		if !snapshot.folders[id] {
			delete(box.Folders, id)
		}
	}
	for id, object := range box.Objects {
		if !snapshot.objects[id] {
			svc.removePayloads(object.Parts)
			delete(box.Objects, id)
		}
	}
	// Events are appended with rising indexes: those of the copy are at the end.
	for len(box.Events) > 0 && box.Events[len(box.Events)-1].Index > snapshot.lastEvent {
		box.Events = box.Events[:len(box.Events)-1]
	}
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.6.2: copy a folder with its objects and subfolders, recursively, under parent;
// returns the ID of the copy.
func (svc *service) copyFolderLocked(request *http.Request, box *storeBox, folder *storedFolder, parent string,
	copyObject func(*storedObject, string) (*storedObject, error)) (string, error) {
	clone := &storedFolder{ID: mustRandom(12), Name: folder.Name, Parent: parent, Attributes: append([]nmsAttribute{}, folder.Attributes...)}
	box.ModSeq++
	clone.ModSeq = box.ModSeq
	box.Folders[clone.ID] = clone
	svc.recordLocked(box, "changedFolder", map[string]any{"resourceURL": svc.boxURL(request, box) + "/folders/" + clone.ID,
		"parentFolder": svc.boxURL(request, box) + "/folders/" + parent, "lastModSeq": clone.ModSeq})
	for _, object := range sortedObjects(box) {
		if object.Folder == folder.ID {
			if _, err := copyObject(object, clone.ID); err != nil {
				return "", err
			}
		}
	}
	for _, child := range sortedFolders(box) {
		if child.Parent == folder.ID && child.ID != clone.ID {
			if _, err := svc.copyFolderLocked(request, box, child, clone.ID, copyObject); err != nil {
				return "", err
			}
		}
	}
	return clone.ID, nil
}
