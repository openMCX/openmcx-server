// MCData message store function: accounts, the NMS resource tree, object and folder views and the change log.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 23.282 V19.10.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19),
// TS 24.482 V19.1.0 (Rel-19), OMA RESTful Network API for Message Storage (OMA-TS-REST_NetAPI_NMS-V1_0).

package common

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// The MCData message store function (TS 24.282 clause 21, TS 23.282 clause 7.13).
//
// MCData-7 (message store client) and MCData-8 (MCData server) follow the RESTful
// Network Message Storage API of OMA-TS-REST_NetAPI_NMS-V1_0, with the resource tree
//
//	/nms/v1/{storeName}/{boxId}/objects[/{objectId}[/flags[/{flag}]|/payload|/payloadParts/{n}|/retrieve]]
//	/nms/v1/{storeName}/{boxId}/objects/operations/{search|bulkUpdate|bulkDelete|bulkCreation|copyToFolder|moveToFolder}
//	/nms/v1/{storeName}/{boxId}/folders[/{folderId}]   and   /folders/operations/search
//	/nms/v1/{storeName}/{boxId}/subscriptions[/{subscriptionId}]
//
// The OMA specification is not supplied: the resources, JSON root elements and
// field names below follow NMS V1.0 as far as TS 24.282 clause 21 names them, and
// the rest is this implementation's reading (see tests/mcdata/MCDATA_MESSAGE_STORE_TEST.md).
//
// A user's access token gives access to the box named by its MCData ID only (TS 23.282
// clause 7.13.2); the MCData server authenticates with the system's service credentials
// (TS 33.180 clause 8.6.1.2, MCData-8). An account, with its root folder and an Inbox, is
// created on first use (TS 23.282 clause 7.13.1, TS 23.282 clause 7.13.3.7).

const storeAPI = "/nms/v1/"

type nmsAttribute struct {
	Name  string   `json:"name"`
	Value []string `json:"value"`
}
type nmsAttributes struct {
	Attribute []nmsAttribute `json:"attribute"`
}
type nmsFlags struct {
	Flag []string `json:"flag"`
}
type nmsPayloadPart struct {
	ContentType string `json:"contentType,omitempty"`
	Size        int64  `json:"size,omitempty"`
	Href        string `json:"href,omitempty"`
	// Stored here (not in OMA JSON): the file holding the part, when it is local.
	file string
}
type nmsObject struct {
	ParentFolder     string           `json:"parentFolder,omitempty"`
	ParentFolderPath string           `json:"parentFolderPath,omitempty"`
	Attributes       *nmsAttributes   `json:"attributes,omitempty"`
	Flags            *nmsFlags        `json:"flags,omitempty"`
	CorrelationID    string           `json:"correlationId,omitempty"`
	PayloadPart      []nmsPayloadPart `json:"payloadPart,omitempty"`
	PayloadURL       string           `json:"payloadURL,omitempty"`
	ResourceURL      string           `json:"resourceURL,omitempty"`
	Path             string           `json:"path,omitempty"`
	LastModSeq       int64            `json:"lastModSeq,omitempty"`
}
type nmsReference struct {
	ResourceURL string `json:"resourceURL"`
	Path        string `json:"path,omitempty"`
	Name        string `json:"name,omitempty"`
}
type nmsFolder struct {
	Name         string         `json:"name"`
	ParentFolder string         `json:"parentFolder,omitempty"`
	Attributes   *nmsAttributes `json:"attributes,omitempty"`
	SubFolders   *struct {
		FolderReference []nmsReference `json:"folderReference"`
	} `json:"subFolders,omitempty"`
	Objects *struct {
		ObjectReference []nmsReference `json:"objectReference"`
	} `json:"objects,omitempty"`
	ResourceURL string `json:"resourceURL,omitempty"`
	Path        string `json:"path,omitempty"`
	LastModSeq  int64  `json:"lastModSeq,omitempty"`
}

// What is kept for each object and folder.
type storedObject struct {
	ID            string         `json:"id"`
	Folder        string         `json:"folder"`
	Attributes    []nmsAttribute `json:"attributes,omitempty"`
	Flags         []string       `json:"flags,omitempty"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	Parts         []storedPart   `json:"parts,omitempty"`
	Created       int64          `json:"created"` // creation cursor
	ModSeq        int64          `json:"mod_seq"`
}
type storedPart struct {
	ContentType string `json:"content_type,omitempty"`
	Size        int64  `json:"size"`
	Href        string `json:"href,omitempty"` // a remote payload (the content server)
	File        string `json:"file,omitempty"` // a local payload
}
type storedFolder struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Parent     string         `json:"parent,omitempty"`
	Attributes []nmsAttribute `json:"attributes,omitempty"`
	ModSeq     int64          `json:"mod_seq"`
}

// One change of a box, as NmsEvent carries it (OMA NMS clause 5.1.5.1).
type storeEvent struct {
	Index int64           `json:"index"`
	Event json.RawMessage `json:"event"`
}
type storeSubscription struct {
	ID           string `json:"id"`
	NotifyURL    string `json:"notify_url"`
	CallbackData string `json:"callback_data,omitempty"`
	Correlator   string `json:"client_correlator,omitempty"`
	Expires      int64  `json:"expires"`
	Index        int64  `json:"index"` // the last event index delivered
}
type storeBox struct {
	ID            string                        `json:"id"` // the MCData ID
	Store         string                        `json:"store"`
	Folders       map[string]*storedFolder      `json:"folders"`
	Objects       map[string]*storedObject      `json:"objects"`
	Root          string                        `json:"root"`
	Inbox         string                        `json:"inbox"`
	ModSeq        int64                         `json:"mod_seq"`
	Creation      int64                         `json:"creation"`
	Vanished      map[string]int64              `json:"vanished"` // object ID -> mod-seq of its deletion
	RestartToken  string                        `json:"restart_token"`
	Events        []storeEvent                  `json:"events"`
	Subscriptions map[string]*storeSubscription `json:"subscriptions"`
}

type messageStore struct {
	mu    sync.Mutex
	dir   string
	boxes map[string]*storeBox
	// Notifications waiting to be sent, one goroutine per box at a time.
	sending map[string]bool
}

const (
	maxStoredPayload    = 32 << 20
	maxStoreRequest     = 4 << 20
	maxBoxEvents        = 1000
	defaultSubLife      = 3600
	maxSubscriptionLife = 86400
)

// ------------------------------------------------------------------------------
// Helper: load the message store boxes (one JSON file per box) from the data directory at start-up.
func (svc *service) loadMessageStore() error {
	svc.store = &messageStore{dir: filepath.Join(svc.dataDir, "msgstore"), boxes: map[string]*storeBox{}, sending: map[string]bool{}}
	if err := os.MkdirAll(filepath.Join(svc.store.dir, "payload"), 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(svc.store.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(svc.store.dir, entry.Name()))
		if err != nil {
			return err
		}
		var box storeBox
		if err := json.Unmarshal(raw, &box); err != nil {
			return fmt.Errorf("decode message store box %s: %w", entry.Name(), err)
		}
		svc.store.boxes[box.Store+"\x00"+box.ID] = &box
	}
	return nil
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2: the routes of the message store function on MCData-7 and MCData-8
// (TS 24.282 clause 21.1), the resource tree of OMA NMS listed at the top of this file.
func (svc *service) routesMsgStore(mux *http.ServeMux) {
	base := "/nms/v1/{store}/{box}"
	mux.HandleFunc("POST "+base+"/objects", svc.nmsCreateObject)
	mux.HandleFunc("GET "+base+"/objects/{object}", svc.nmsGetObject)
	mux.HandleFunc("DELETE "+base+"/objects/{object}", svc.nmsDeleteObject)
	mux.HandleFunc("GET "+base+"/objects/{object}/flags", svc.nmsGetFlags)
	mux.HandleFunc("PUT "+base+"/objects/{object}/flags", svc.nmsPutFlags)
	mux.HandleFunc("PUT "+base+"/objects/{object}/flags/{flag}", svc.nmsAddFlag)
	mux.HandleFunc("DELETE "+base+"/objects/{object}/flags/{flag}", svc.nmsRemoveFlag)
	mux.HandleFunc("GET "+base+"/objects/{object}/payload", svc.nmsPayload)
	mux.HandleFunc("GET "+base+"/objects/{object}/payloadParts/{part}", svc.nmsPayload)
	// "operations/{operation}" (OMA NMS clauses 6.8 to 6.12, 6.18, 6.19) and "{objectId}/retrieve"
	// (TS 24.282 clause 21.2.24).
	mux.HandleFunc("POST "+base+"/objects/{object}/{action}", func(writer http.ResponseWriter, request *http.Request) {
		if request.PathValue("object") == "operations" {
			svc.nmsObjectOperation(writer, request)
			return
		}
		if request.PathValue("action") != "retrieve" {
			nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "operation")
			return
		}
		svc.nmsRetrieve(writer, request)
	})
	mux.HandleFunc("POST "+base+"/folders", svc.nmsCreateFolder)
	mux.HandleFunc("GET "+base+"/folders/{folder}", svc.nmsGetFolder)
	mux.HandleFunc("DELETE "+base+"/folders/{folder}", svc.nmsDeleteFolder)
	mux.HandleFunc("POST "+base+"/folders/operations/search", svc.nmsSearchFolders)
	mux.HandleFunc("POST "+base+"/subscriptions", svc.nmsCreateSubscription)
	mux.HandleFunc("POST "+base+"/subscriptions/{subscription}", svc.nmsUpdateSubscription)
	mux.HandleFunc("DELETE "+base+"/subscriptions/{subscription}", svc.nmsDeleteSubscription)
	mux.HandleFunc("GET /internal/msgstore/boxes", svc.nmsListBoxes)
}

// ------------------------------------------------------------------------------
// Helper: nmsError writes the RequestError of the OMA RESTful Network APIs: a service exception, or a
// policy exception for 403.
func nmsError(writer http.ResponseWriter, status int, id, text string, variables ...string) {
	kind := "serviceException"
	if status == http.StatusForbidden {
		kind = "policyException"
	}
	writeJSON(writer, status, map[string]any{"requestError": map[string]any{kind: map[string]any{
		"messageId": id, "text": text, "variables": variables}}})
}

// ------------------------------------------------------------------------------
// TS 23.282 clause 7.13.2, TS 24.282 clause 21.1: boxOf authenticates the request (the MCData access
// token of a user, or the MCData server's service credentials on MCData-8) and returns the box it names
// (boxId, TS 24.282 clause 21.1 NOTE 1A). A user reaches its own box only; the MCData server any box.
// The account (root folder and Inbox) is created on first use. Deviation from TS 23.282 clause 7.13.3.7.1 (the
// MCData server creates the account before its first deposit, with a create-a-user-account request): TS 24.282
// defines no such request, so the first authorised request creates it, the MCData server's deposit or the user's
// own first access (for a user of this system only); the NOTE there leaves provisioning as the other way.
func (svc *service) boxOf(writer http.ResponseWriter, request *http.Request) (*storeBox, bool, bool) {
	boxID, store := request.PathValue("box"), request.PathValue("store")
	if boxID == "" || store == "" || len(boxID) > 512 || len(store) > 64 || strings.ContainsAny(store, "/\\") {
		nmsError(writer, http.StatusBadRequest, "SVC0002", "Invalid input value for message part %1", "boxId")
		return nil, false, false
	}
	server := svc.internalAuthorized(request)
	if !server {
		claims, ok := svc.authenticateBearer(writer, request)
		if !ok {
			return nil, false, false
		}
		if claims.MCDataID == "" || claims.MCDataID != boxID {
			nmsError(writer, http.StatusForbidden, "POL0001", "Access to another MCData user's storage area is not allowed")
			return nil, false, false
		}
	} else if _, known := svc.siteUser("mcdata_id", boxID); !known {
		nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "boxId")
		return nil, false, false
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	key := store + "\x00" + boxID
	box, ok := svc.store.boxes[key]
	if !ok {
		box = &storeBox{ID: boxID, Store: store, Folders: map[string]*storedFolder{}, Objects: map[string]*storedObject{},
			Vanished: map[string]int64{}, Subscriptions: map[string]*storeSubscription{}}
		box.RestartToken = mustRandom(16)
		box.Root = mustRandom(12)
		box.Folders[box.Root] = &storedFolder{ID: box.Root, Name: ""}
		box.Inbox = mustRandom(12)
		box.Folders[box.Inbox] = &storedFolder{ID: box.Inbox, Name: "Inbox", Parent: box.Root}
		svc.store.boxes[key] = box
		if err := svc.saveBoxLocked(box); err != nil {
			nmsError(writer, http.StatusInternalServerError, "SVC0001", "storage unavailable")
			return nil, false, false
		}
	}
	return box, server, true
}

// ------------------------------------------------------------------------------
// Helper: a random identifier of length characters, letters and digits only.
func mustRandom(length int) string {
	id, err := randomID()
	if err != nil {
		panic(err)
	}
	return strings.NewReplacer("-", "A", "_", "B").Replace(id[:length])
}

// ------------------------------------------------------------------------------
// Helper: write the box atomically to its file (the caller holds the store lock).
func (svc *service) saveBoxLocked(box *storeBox) error {
	raw, err := json.Marshal(box)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(box.Store + "\x00" + box.ID))
	path := filepath.Join(svc.store.dir, hex.EncodeToString(sum[:16])+".json")
	return writeFileAtomic(path, raw)
}

// ------------------------------------------------------------------------------
// OMA NMS clause 5.2, TS 24.282 clause 21.1 NOTE 1A: the resource URL of the box
// ({serverRoot}/nms/v1/{storeName}/{boxId}) as its clients address it.
func (svc *service) boxURL(request *http.Request, box *storeBox) string {
	root := strings.TrimSuffix(svc.cfg.Endpoints.MsgStore, "/")
	if internal := strings.TrimSuffix(svc.cfg.Endpoints.MsgStoreInternal, "/"); internal != "" && (root == "" || svc.internalAuthorized(request)) {
		root = internal
	}
	return root + storeAPI + url.PathEscape(box.Store) + "/" + url.PathEscape(box.ID)
}

// ------------------------------------------------------------------------------
// Helper: the path of a folder, "/" for the root and "/Inbox" for the Inbox.
func folderPath(box *storeBox, id string) string {
	var names []string
	for folder := box.Folders[id]; folder != nil && folder.Parent != ""; folder = box.Folders[folder.Parent] {
		names = append([]string{folder.Name}, names...)
	}
	return "/" + strings.Join(names, "/")
}

// ------------------------------------------------------------------------------
// Helper: the OMA NMS Object of a stored object; a local payload part is addressed by its
// payloadParts resource, a remote one (the content server) by its own URL.
func (svc *service) objectView(request *http.Request, box *storeBox, object *storedObject) nmsObject {
	base := svc.boxURL(request, box)
	view := nmsObject{ParentFolder: base + "/folders/" + object.Folder, ParentFolderPath: folderPath(box, object.Folder),
		CorrelationID: object.CorrelationID, ResourceURL: base + "/objects/" + object.ID, LastModSeq: object.ModSeq}
	view.Path = strings.TrimSuffix(view.ParentFolderPath, "/") + "/" + object.ID
	if len(object.Attributes) > 0 {
		view.Attributes = &nmsAttributes{Attribute: object.Attributes}
	}
	view.Flags = &nmsFlags{Flag: append([]string{}, object.Flags...)}
	if len(object.Parts) > 0 {
		view.PayloadURL = base + "/objects/" + object.ID + "/payload"
	}
	for index, part := range object.Parts {
		href := part.Href
		if part.File != "" {
			href = base + "/objects/" + object.ID + "/payloadParts/" + strconv.Itoa(index+1)
		}
		view.PayloadPart = append(view.PayloadPart, nmsPayloadPart{ContentType: part.ContentType, Size: part.Size, Href: href})
	}
	return view
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.18.2: the OMA NMS Folder of a stored folder; with content, its subfolders and
// objects as references (retrieve content of a given folder).
func (svc *service) folderView(request *http.Request, box *storeBox, folder *storedFolder, content bool) nmsFolder {
	base := svc.boxURL(request, box)
	view := nmsFolder{Name: folder.Name, ResourceURL: base + "/folders/" + folder.ID, Path: folderPath(box, folder.ID), LastModSeq: folder.ModSeq}
	if folder.Parent != "" {
		view.ParentFolder = base + "/folders/" + folder.Parent
	}
	if len(folder.Attributes) > 0 {
		view.Attributes = &nmsAttributes{Attribute: folder.Attributes}
	}
	if content {
		view.SubFolders = &struct {
			FolderReference []nmsReference `json:"folderReference"`
		}{FolderReference: []nmsReference{}}
		view.Objects = &struct {
			ObjectReference []nmsReference `json:"objectReference"`
		}{ObjectReference: []nmsReference{}}
		for _, child := range sortedFolders(box) {
			if child.Parent == folder.ID {
				view.SubFolders.FolderReference = append(view.SubFolders.FolderReference,
					nmsReference{ResourceURL: base + "/folders/" + child.ID, Path: folderPath(box, child.ID), Name: child.Name})
			}
		}
		for _, object := range sortedObjects(box) {
			if object.Folder == folder.ID {
				view.Objects.ObjectReference = append(view.Objects.ObjectReference, nmsReference{ResourceURL: base + "/objects/" + object.ID})
			}
		}
	}
	return view
}

// ------------------------------------------------------------------------------
// Helper: the objects of the box in creation order.
func sortedObjects(box *storeBox) []*storedObject {
	out := make([]*storedObject, 0, len(box.Objects))
	for _, object := range box.Objects {
		out = append(out, object)
	}
	sort.Slice(out, func(first, second int) bool { return out[first].Created < out[second].Created })
	return out
}

// ------------------------------------------------------------------------------
// Helper: the folders of the box by name, then by ID.
func sortedFolders(box *storeBox) []*storedFolder {
	out := make([]*storedFolder, 0, len(box.Folders))
	for _, folder := range box.Folders {
		out = append(out, folder)
	}
	sort.Slice(out, func(first, second int) bool {
		return out[first].Name < out[second].Name || (out[first].Name == out[second].Name && out[first].ID < out[second].ID)
	})
	return out
}

// ------------------------------------------------------------------------------
// Helper: the last path segment of a resource URL of this box, or the value itself.
func lastSegment(value, kind string) string {
	if index := strings.LastIndex(value, "/"+kind+"/"); index >= 0 {
		value = value[index+len(kind)+2:]
	}
	value, _ = url.PathUnescape(value)
	return strings.Trim(value, "/")
}

// ------------------------------------------------------------------------------
// Helper: decode the request body, a JSON object with the single root element named root (OMA NMS),
// into into; on failure answer with an OMA NMS service exception.
func readJSON(writer http.ResponseWriter, request *http.Request, root string, into any) bool {
	var envelope map[string]json.RawMessage
	decoder := json.NewDecoder(io.LimitReader(request.Body, maxStoreRequest))
	if err := decoder.Decode(&envelope); err != nil {
		nmsError(writer, http.StatusBadRequest, "SVC0001", "malformed JSON body")
		return false
	}
	raw, ok := envelope[root]
	if !ok {
		nmsError(writer, http.StatusBadRequest, "SVC0002", "Invalid input value for message part %1", root)
		return false
	}
	if err := json.Unmarshal(raw, into); err != nil {
		nmsError(writer, http.StatusBadRequest, "SVC0002", "Invalid input value for message part %1", root)
		return false
	}
	return true
}

// ------------------------------------------------------------------------------
// OMA NMS clause 5.1.5.1: record the change of an object or folder (an NmsEvent) for the
// subscriptions, to be sent as synchronization notifications (TS 24.282 clause 21.2.16.1).
// At most maxBoxEvents are kept.
func (svc *service) recordLocked(box *storeBox, kind string, value any) {
	raw, err := json.Marshal(map[string]any{kind: value})
	if err != nil {
		// The values are the store's own types: not expected; the event is lost, not the change.
		svc.logEvent("msgstore_event_failed", map[string]any{"kind": kind, "error": err.Error()})
		return
	}
	index := int64(1)
	if count := len(box.Events); count > 0 {
		index = box.Events[count-1].Index + 1
	}
	box.Events = append(box.Events, storeEvent{Index: index, Event: raw})
	if len(box.Events) > maxBoxEvents {
		box.Events = box.Events[len(box.Events)-maxBoxEvents:]
	}
}

// ------------------------------------------------------------------------------
// OMA NMS clause 5.1.5.1: record a changedObject event for a created or changed object.
func (svc *service) changedObject(request *http.Request, box *storeBox, object *storedObject) {
	base := svc.boxURL(request, box)
	svc.recordLocked(box, "changedObject", map[string]any{"parentFolder": base + "/folders/" + object.Folder,
		"flags": nmsFlags{Flag: append([]string{}, object.Flags...)}, "resourceURL": base + "/objects/" + object.ID,
		"lastModSeq": object.ModSeq, "correlationId": object.CorrelationID})
}

// ------------------------------------------------------------------------------
// Helper: save the changed box and start its synchronization notifications (TS 24.282 clause 21.2.16.1);
// on a storage failure answer 500.
func (svc *service) commitLocked(writer http.ResponseWriter, box *storeBox) bool {
	if err := svc.saveBoxLocked(box); err != nil {
		nmsError(writer, http.StatusInternalServerError, "SVC0001", "storage unavailable")
		return false
	}
	svc.notifyLocked(box)
	return true
}
