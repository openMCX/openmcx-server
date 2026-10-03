// MCData message store: stored objects, their flags and payloads (TS 24.282 clauses 21.2.1, 21.2.3, 21.2.4,
// 21.2.5A, 21.2.15 and 21.2.24; OMA NMS).
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), OMA RESTful Network API for Network Message Storage
// (OMA-TS-REST_NetAPI_NMS-V1_0-20190528-C).

package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ---- objects ----

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.15.2 (upload by the client, OMA NMS clause 6.1.5) and clause 21.2.5A.2 (deposit by the
// MCData server): create an object from an Object as JSON, or from multipart/form-data with the Object in a
// "root-fields" part and its payload in "attachments" parts.
func (svc *service) nmsCreateObject(writer http.ResponseWriter, request *http.Request) {
	box, server, ok := svc.boxOf(writer, request)
	if !ok {
		return
	}
	var object nmsObject
	var attachments []storedPart
	// The payloads stored for the object are removed again unless it is committed.
	committed := false
	defer func() {
		if !committed {
			svc.removePayloads(attachments)
		}
	}()
	mediaType, params, _ := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if strings.HasPrefix(mediaType, "multipart/") {
		reader := multipart.NewReader(io.LimitReader(request.Body, maxStoredPayload+maxStoreRequest), params["boundary"])
		for {
			part, err := reader.NextPart()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				nmsError(writer, http.StatusBadRequest, "SVC0001", "malformed multipart body")
				return
			}
			if part.FormName() == "root-fields" {
				var envelope struct {
					Object nmsObject `json:"object"`
				}
				if json.NewDecoder(io.LimitReader(part, maxStoreRequest)).Decode(&envelope) != nil {
					nmsError(writer, http.StatusBadRequest, "SVC0002", "Invalid input value for message part %1", "root-fields")
					return
				}
				object = envelope.Object
				continue
			}
			stored, err := svc.storePayload(part, part.Header.Get("Content-Type"))
			if err != nil {
				nmsError(writer, http.StatusBadRequest, "SVC0001", err.Error())
				return
			}
			attachments = append(attachments, stored)
		}
	} else if !readJSON(writer, request, "object", &object) {
		return
	}
	retrieve := !strings.EqualFold(request.URL.Query().Get("retrieveFile"), "No")
	svc.store.mu.Lock()
	folder := box.Inbox
	if object.ParentFolder != "" {
		folder = lastSegment(object.ParentFolder, "folders")
		if box.Folders[folder] == nil {
			svc.store.mu.Unlock()
			nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "parentFolder")
			return
		}
	}
	id := mustRandom(20)
	created := &storedObject{ID: id, Folder: folder, CorrelationID: object.CorrelationID}
	if object.Attributes != nil {
		created.Attributes = object.Attributes.Attribute
	}
	if object.Flags != nil {
		created.Flags = uniqueFlags(object.Flags.Flag)
	}
	var remote []int
	for _, payloadPart := range object.PayloadPart {
		if payloadPart.Href != "" {
			if !strings.HasPrefix(payloadPart.Href, "https://") {
				svc.store.mu.Unlock()
				nmsError(writer, http.StatusBadRequest, "SVC0002", "Invalid input value for message part %1", "payloadPart")
				return
			}
			remote = append(remote, len(created.Parts))
		}
		created.Parts = append(created.Parts, storedPart{ContentType: payloadPart.ContentType, Size: payloadPart.Size, Href: payloadPart.Href})
	}
	created.Parts = append(created.Parts, attachments...)
	box.ModSeq++
	box.Creation++
	created.ModSeq, created.Created = box.ModSeq, box.Creation
	box.Objects[id] = created
	svc.changedObject(request, box, created)
	if !svc.commitLocked(writer, box) {
		// Not stored: the object goes again (its event stays, naming an object that is not there).
		delete(box.Objects, id)
		svc.store.mu.Unlock()
		return
	}
	committed = true
	view := svc.objectView(request, box, created)
	svc.store.mu.Unlock()
	// TS 24.282 clause 21.2.5A.2 step 2a i: a deposited file is fetched from the MCData content server and
	// stored in the user's area, unless retrieveFile is "No". A file that cannot be fetched stays a reference
	// (payloadPart href) the client can fetch itself or retrieve later (TS 24.282 clause 21.2.24).
	if server && retrieve {
		for _, index := range remote {
			if err := svc.retrievePart(request, box, id, index); err != nil {
				svc.logEvent("msgstore_retrieve_failed", map[string]any{"object": id, "part": index, "error": err.Error()})
			}
		}
	}
	writer.Header().Set("Location", view.ResourceURL)
	writeJSON(writer, http.StatusCreated, map[string]any{"reference": nmsReference{ResourceURL: view.ResourceURL, Path: view.Path}})
}

// ------------------------------------------------------------------------------
// Helper: the flags without empty, over-long (more than 64 characters) and repeated ones, in their order.
func uniqueFlags(flags []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, flag := range flags {
		if flag != "" && len(flag) <= 64 && !seen[flag] {
			seen[flag] = true
			out = append(out, flag)
		}
	}
	return out
}

// ------------------------------------------------------------------------------
// Helper: removes the payload files of parts that were stored but are not kept.
func (svc *service) removePayloads(parts []storedPart) {
	for _, part := range parts {
		if part.File != "" {
			_ = os.Remove(filepath.Join(svc.store.dir, "payload", part.File)) // best effort: an orphan file only
		}
	}
}

// ------------------------------------------------------------------------------
// Helper: store a payload in a new file of the store's payload directory, at most maxStoredPayload bytes.
func (svc *service) storePayload(body io.Reader, contentType string) (storedPart, error) {
	name := mustRandom(24)
	path := filepath.Join(svc.store.dir, "payload", name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return storedPart{}, err
	}
	written, err := io.Copy(file, io.LimitReader(body, maxStoredPayload+1))
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil || written > maxStoredPayload {
		_ = os.Remove(path) // best effort: the payload is refused either way
		return storedPart{}, errors.New("payload too large or unreadable")
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	return storedPart{ContentType: contentType, Size: written, File: name}, nil
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.24.2 step 2a and clause 21.2.5A.2 step 2a i: fetch a payload part from the MCData content
// server (clause 6.7.2) and keep it locally. The content server is reached with the service credentials.
func (svc *service) retrievePart(request *http.Request, box *storeBox, objectID string, index int) error {
	svc.store.mu.Lock()
	object := box.Objects[objectID]
	if object == nil || index >= len(object.Parts) || object.Parts[index].File != "" {
		svc.store.mu.Unlock()
		return nil
	}
	href := object.Parts[index].Href
	svc.store.mu.Unlock()
	source, err := svc.internalFileURL(href)
	if err != nil {
		return err
	}
	fetch, err := http.NewRequestWithContext(request.Context(), http.MethodGet, source, nil)
	if err != nil {
		return err
	}
	fetch.SetBasicAuth(svc.cfg.ServerClientID, svc.cfg.ServerSecret)
	response, err := svc.httpClient().Do(fetch)
	if err != nil {
		return err
	}
	defer closeQuietly(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("content server answered %d", response.StatusCode)
	}
	stored, err := svc.storePayload(response.Body, response.Header.Get("Content-Type"))
	if err != nil {
		return err
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	object = box.Objects[objectID]
	if object == nil || index >= len(object.Parts) {
		svc.removePayloads([]storedPart{stored})
		return errors.New("object deleted meanwhile")
	}
	stored.Href = ""
	object.Parts[index] = stored
	box.ModSeq++
	object.ModSeq = box.ModSeq
	svc.changedObject(request, box, object)
	return svc.saveBoxLocked(box)
}

// ------------------------------------------------------------------------------
// Helper: a file of this system's content server, as the message store reaches it directly: the clients' URL
// (through the HTTP proxy) with the content server's own origin.
func (svc *service) internalFileURL(href string) (string, error) {
	parsed, err := url.Parse(href)
	if err != nil {
		return "", err
	}
	position := strings.Index(parsed.Path, "/mcdata/files/")
	internal := strings.TrimSuffix(svc.cfg.Endpoints.ContentInternal, "/")
	if position < 0 || internal == "" {
		return "", errors.New("the payload is not a file of this system's content server")
	}
	return internal + parsed.Path[position:], nil
}

// ------------------------------------------------------------------------------
// Helper: the HTTP client for the requests of the message store to other servers (a test's client when set).
func (svc *service) httpClient() *http.Client {
	if svc.serviceClient != nil {
		return svc.serviceClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// ------------------------------------------------------------------------------
// Helper: the box of the request (boxOf) and the object named by its {objectId}; answers SVC0004 when there is
// no such object.
func (svc *service) objectOf(writer http.ResponseWriter, request *http.Request) (*storeBox, *storedObject, bool) {
	box, _, ok := svc.boxOf(writer, request)
	if !ok {
		return nil, nil, false
	}
	svc.store.mu.Lock()
	object := box.Objects[request.PathValue("object")]
	svc.store.mu.Unlock()
	if object == nil {
		nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "objectId")
		return nil, nil, false
	}
	return box, object, true
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.1.2 (OMA NMS clause 6.2.3): return the Object.
func (svc *service) nmsGetObject(writer http.ResponseWriter, request *http.Request) {
	box, object, ok := svc.objectOf(writer, request)
	if !ok {
		return
	}
	svc.store.mu.Lock()
	view := svc.objectView(request, box, object)
	svc.store.mu.Unlock()
	writeJSON(writer, http.StatusOK, map[string]any{"object": view})
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.4.2 step 2: delete an object and its payload files, remember it as vanished and record a
// deletedObject event (clause 21.2.16). The caller holds the store lock.
func (svc *service) deleteObjectLocked(request *http.Request, box *storeBox, object *storedObject) {
	for _, part := range object.Parts {
		if part.File != "" {
			_ = os.Remove(filepath.Join(svc.store.dir, "payload", part.File))
		}
	}
	delete(box.Objects, object.ID)
	box.ModSeq++
	box.Vanished[object.ID] = box.ModSeq
	svc.recordLocked(box, "deletedObject", map[string]any{"resourceURL": svc.boxURL(request, box) + "/objects/" + object.ID,
		"lastModSeq": box.ModSeq, "correlationId": object.CorrelationID})
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.4.2 step 2a (OMA NMS clause 6.2.6): delete one object.
func (svc *service) nmsDeleteObject(writer http.ResponseWriter, request *http.Request) {
	box, object, ok := svc.objectOf(writer, request)
	if !ok {
		return
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	svc.deleteObjectLocked(request, box, object)
	if svc.commitLocked(writer, box) {
		writer.WriteHeader(http.StatusNoContent)
	}
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.1.2 on the flags resource of clause 21.2.3.2 (OMA NMS clauses 6.3, 6.4): the flags of an
// object.
func (svc *service) nmsGetFlags(writer http.ResponseWriter, request *http.Request) {
	box, object, ok := svc.objectOf(writer, request)
	if !ok {
		return
	}
	svc.store.mu.Lock()
	flags := append([]string{}, object.Flags...)
	base := svc.boxURL(request, box)
	svc.store.mu.Unlock()
	writeJSON(writer, http.StatusOK, map[string]any{"flagList": map[string]any{"flag": flags,
		"resourceURL": base + "/objects/" + object.ID + "/flags"}})
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.3.2 step 2a (OMA NMS clauses 6.3.2, 6.4.2): apply a change to the flags of an object,
// record a changedObject event and answer the new flag list.
func (svc *service) setFlags(writer http.ResponseWriter, request *http.Request, change func(object *storedObject)) {
	box, object, ok := svc.objectOf(writer, request)
	if !ok {
		return
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	change(object)
	box.ModSeq++
	object.ModSeq = box.ModSeq
	svc.changedObject(request, box, object)
	if svc.commitLocked(writer, box) {
		writeJSON(writer, http.StatusOK, map[string]any{"flagList": map[string]any{"flag": append([]string{}, object.Flags...),
			"resourceURL": svc.boxURL(request, box) + "/objects/" + object.ID + "/flags"}})
	}
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.3.2 step 2a (OMA NMS clause 6.3.2): replace the flags of an object.
func (svc *service) nmsPutFlags(writer http.ResponseWriter, request *http.Request) {
	var list nmsFlags
	if !readJSON(writer, request, "flagList", &list) {
		return
	}
	svc.setFlags(writer, request, func(object *storedObject) { object.Flags = uniqueFlags(list.Flag) })
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.3.2 step 2a (OMA NMS clause 6.4.2): add one flag to an object.
func (svc *service) nmsAddFlag(writer http.ResponseWriter, request *http.Request) {
	flag := request.PathValue("flag")
	svc.setFlags(writer, request, func(object *storedObject) { object.Flags = uniqueFlags(append(object.Flags, flag)) })
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.3 (OMA NMS clause 6.4): remove one flag from an object.
func (svc *service) nmsRemoveFlag(writer http.ResponseWriter, request *http.Request) {
	flag := request.PathValue("flag")
	svc.setFlags(writer, request, func(object *storedObject) {
		var kept []string
		for _, existing := range object.Flags {
			if existing != flag {
				kept = append(kept, existing)
			}
		}
		object.Flags = kept
	})
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.1.2 (OMA NMS clauses 6.5, 6.6): the payload of an object, one part, or all of them as
// multipart/mixed. A part still held by the content server is answered with a redirect to it.
func (svc *service) nmsPayload(writer http.ResponseWriter, request *http.Request) {
	_, object, ok := svc.objectOf(writer, request)
	if !ok {
		return
	}
	svc.store.mu.Lock()
	parts := append([]storedPart{}, object.Parts...)
	svc.store.mu.Unlock()
	if len(parts) == 0 {
		nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "payload")
		return
	}
	if part := request.PathValue("part"); part != "" {
		number, err := strconv.Atoi(part)
		if err != nil || number < 1 || number > len(parts) {
			nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "part")
			return
		}
		parts = parts[number-1 : number]
	}
	if len(parts) == 1 {
		svc.servePart(writer, parts[0])
		return
	}
	body, boundary, err := svc.mixedPayload(parts)
	if err != nil {
		nmsError(writer, http.StatusInternalServerError, "SVC0001", "storage unavailable")
		return
	}
	writer.Header().Set("Content-Type", "multipart/mixed; boundary="+boundary)
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body) // a failed write is the client's connection
}

// ------------------------------------------------------------------------------
// Helper: the parts of a payload as a multipart/mixed body (OMA NMS clause 6.5); a part still held by the content
// server is a message/external-body reference to it. Returns the body and its boundary.
func (svc *service) mixedPayload(parts []storedPart) ([]byte, string, error) {
	var body bytes.Buffer
	mixed := multipart.NewWriter(&body)
	for _, part := range parts {
		header := map[string][]string{"Content-Type": {part.ContentType}}
		if part.File == "" {
			header["Content-Type"] = []string{"message/external-body; access-type=URL; URL=\"" + part.Href + "\""}
		}
		out, err := mixed.CreatePart(header)
		if err != nil {
			return nil, "", fmt.Errorf("msgstore payload: %w", err)
		}
		if part.File == "" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(svc.store.dir, "payload", part.File))
		if err != nil {
			return nil, "", fmt.Errorf("msgstore payload: %w", err)
		}
		if _, err := out.Write(raw); err != nil {
			return nil, "", fmt.Errorf("msgstore payload: %w", err)
		}
	}
	if err := mixed.Close(); err != nil {
		return nil, "", fmt.Errorf("msgstore payload: %w", err)
	}
	return body.Bytes(), mixed.Boundary(), nil
}

// ------------------------------------------------------------------------------
// Helper: answer one payload part: the stored file, or a redirect to the content server when not stored locally.
func (svc *service) servePart(writer http.ResponseWriter, part storedPart) {
	if part.File == "" {
		writer.Header().Set("Location", part.Href)
		writer.WriteHeader(http.StatusFound)
		return
	}
	file, err := os.Open(filepath.Join(svc.store.dir, "payload", part.File))
	if err != nil {
		nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "payload")
		return
	}
	defer closeQuietly(file)
	writer.Header().Set("Content-Type", part.ContentType)
	writer.Header().Set("Content-Length", strconv.FormatInt(part.Size, 10))
	writer.WriteHeader(http.StatusOK)
	_, _ = io.Copy(writer, file)
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.24.2: retrieve the files of an object from the MCData content server, keep them and answer
// the Object (step 3a).
func (svc *service) nmsRetrieve(writer http.ResponseWriter, request *http.Request) {
	box, object, ok := svc.objectOf(writer, request)
	if !ok {
		return
	}
	svc.store.mu.Lock()
	var remote []int
	for index, part := range object.Parts {
		if part.File == "" && part.Href != "" {
			remote = append(remote, index)
		}
	}
	svc.store.mu.Unlock()
	for _, index := range remote {
		if err := svc.retrievePart(request, box, object.ID, index); err != nil {
			nmsError(writer, http.StatusBadGateway, "SVC0001", "the file could not be retrieved: "+err.Error())
			return
		}
	}
	svc.store.mu.Lock()
	if len(remote) > 0 {
		svc.notifyLocked(box) // TS 24.282 clause 21.2.24.2 step 3b: a changedObject event
	}
	view := svc.objectView(request, box, object)
	svc.store.mu.Unlock()
	writeJSON(writer, http.StatusOK, map[string]any{"object": view})
}
