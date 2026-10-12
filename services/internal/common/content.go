//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The media storage function of the MCData content server: file upload and download over HTTP, transmission
// and reception control, and the stored-file operations the MCData server and message store use.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 23.282 V19.10.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19),
// TS 24.482 V19.1.0 (Rel-19).
package common

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The media storage function of the MCData content server (TS 24.282 clause 10.2.2.2 and
// clause 10.2.3.2, TS 23.282 clause 6.6.3.1.4). Files are uploaded with an HTTP POST carrying a
// multipart/mixed body (an application/vnd.3gpp.mcdata-info+xml part and the file
// as application/octet-stream) and downloaded with an HTTP GET of the URL returned
// in the Location header field of the 201 (Created) response.
//
// TS 24.282 refers to TS 24.482 annex A for the HTTP client and server, which is
// not supplied: the MCData ID is taken from the bearer access token as NOTE 1 of
// TS 24.282 clause 10.2.2.1 and clause 10.2.3.1 describes. The transmission and reception control policies
// come from this service's own configuration, which TS 24.282 leaves as an editor's
// note (how the content server reads them from the MCData server is not specified).

const infoNamespace = "urn:3gpp:ns:mcdataInfo:1.0"

// ------------------------------------------------------------------------------
// TS 24.282 annex D.1: the subset of mcdata-info the media storage function decodes.
type fileUploadInfo struct {
	XMLName     xml.Name `xml:"urn:3gpp:ns:mcdataInfo:1.0 mcdatainfo"`
	RequestType string   `xml:"mcdata-Params>request-type"`
	RequestURI  string   `xml:"mcdata-Params>mcdata-request-uri>mcdataURI"`
	CallingUser string   `xml:"mcdata-Params>mcdata-calling-user-id>mcdataURI"`
}

// ------------------------------------------------------------------------------
// Helper: StoredFile is the metadata kept beside each stored file.
type StoredFile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
	Owner       string `json:"owner"`
	Group       string `json:"group,omitempty"`
	Uploaded    int64  `json:"uploaded"`
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 10.2.2.2 and clause 10.2.3.2: the HTTP routes of the media storage function, with the
// stored-file operations of clause 6.7.
func (svc *service) routesContent(mux *http.ServeMux) {
	mux.HandleFunc("POST /mcdata/files", svc.uploadFile)
	mux.HandleFunc("GET /mcdata/files/{id}/{name}", svc.downloadFile)
	mux.HandleFunc("HEAD /mcdata/files/{id}/{name}", svc.headFile)
	mux.HandleFunc("GET /internal/files", svc.listFiles)
	mux.HandleFunc("DELETE /internal/files/{id}", svc.deleteFile)
}

// ------------------------------------------------------------------------------
// Helper: WithTransferDeadline gives each file upload and download of the media storage function
// [timeout] to complete, in place of the server's short read and write timeouts; other
// requests keep those.
func WithTransferDeadline(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/mcdata/files") || strings.HasPrefix(request.URL.Path, "/mcdata/remote-files") {
			control := http.NewResponseController(writer)
			_ = control.SetReadDeadline(time.Now().Add(timeout))
			_ = control.SetWriteDeadline(time.Now().Add(timeout))
		}
		next.ServeHTTP(writer, request)
	})
}

// ------------------------------------------------------------------------------
// Helper: the directory holding one stored file and its metadata.
func (svc *service) fileDir(id string) string { return filepath.Join(svc.dataDir, "files", id) }

// ------------------------------------------------------------------------------
// Helper: storedFile reads the metadata of one file; the identifier is checked against the
// generated form so that it can never escape the data directory.
func (svc *service) storedFile(id string) (StoredFile, error) {
	// Identifiers are generated here: 32 URL-safe base64 characters, so a request
	// can never walk out of the data directory.
	const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if len(id) != 32 || strings.Trim(id, allowed) != "" {
		return StoredFile{}, errors.New("invalid file identifier")
	}
	raw, err := os.ReadFile(filepath.Join(svc.fileDir(id), "meta.json"))
	if err != nil {
		return StoredFile{}, err
	}
	var file StoredFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return StoredFile{}, err
	}
	return file, nil
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 10.2.2.2: store the file and answer 201 (Created) with its location.
func (svc *service) uploadFile(writer http.ResponseWriter, request *http.Request) {
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok {
		return
	}
	mediaType, params, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") || params["boundary"] == "" {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "expected multipart/mixed"})
		return
	}
	user, ok := svc.siteUser("mcdata_id", claims.MCDataID)
	if !ok || claims.MCDataID == "" {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "unknown MCData user"})
		return
	}
	// Step 1a: transmission control (<allow-transmit-data>, TS 24.282 clause 11.1 step 1).
	if user.MCData == nil || !user.MCData.TransmitData {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "transmission control"})
		return
	}
	var info fileUploadInfo
	var stored *StoredFile
	id, err := randomID()
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "identifier unavailable"})
		return
	}
	id = id[:32]
	directory := svc.fileDir(id)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "storage unavailable"})
		return
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	reader := multipart.NewReader(request.Body, params["boundary"])
	for {
		part, err := reader.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			cleanup()
			writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "malformed multipart body"})
			return
		}
		switch partType(part) {
		case "application/vnd.3gpp.mcdata-info+xml":
			body, err := io.ReadAll(io.LimitReader(part, 64*1024))
			if err != nil || xml.Unmarshal(body, &info) != nil || info.XMLName.Space != infoNamespace {
				cleanup()
				writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "malformed mcdata-info"})
				return
			}
		case "application/octet-stream":
			limit := svc.uploadLimit(info)
			file, err := storeFile(directory, part, limit)
			if err != nil {
				cleanup()
				status := http.StatusInternalServerError
				message := "storage unavailable"
				if errors.Is(err, errTooLarge) {
					status, message = http.StatusRequestEntityTooLarge, "file exceeds the configured maximum"
				}
				writeJSON(writer, status, map[string]string{"error": message})
				return
			}
			stored = file
		case "message/external-body":
			// TS 24.282 clause 10.2.2.2, second list: a file stored in the user's MCData message store,
			// fetched from it with the user's own access token (TS 24.282 clause 6.7.2.1).
			limit := svc.uploadLimit(info)
			file, status, err := svc.fetchNetworkStoredFile(request, claims, part, directory, limit)
			if err != nil {
				cleanup()
				writeJSON(writer, status, map[string]string{"error": err.Error()})
				return
			}
			stored = file
		default:
			cleanup()
			writeJSON(writer, http.StatusUnsupportedMediaType, map[string]string{"error": "unsupported upload body"})
			return
		}
	}
	if stored == nil || info.RequestType == "" {
		cleanup()
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "expected MIME bodies not in the request"})
		return
	}
	// The limit again with the whole mcdata-info: a file part before it was written with the service's limit only
	// (TS 24.282 clause 10.2.2.2 step 1b.b.ii, the group's limit).
	if stored.Size > svc.uploadLimit(info) {
		cleanup()
		writeJSON(writer, http.StatusRequestEntityTooLarge, map[string]string{"error": "file exceeds the configured maximum"})
		return
	}
	if info.CallingUser != "" && info.CallingUser != claims.MCDataID {
		cleanup()
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "calling user does not match the access token"})
		return
	}
	if status, err := svc.checkUploadRequest(info); err != nil {
		cleanup()
		writeJSON(writer, status, map[string]string{"error": err.Error()})
		return
	}
	stored.ID, stored.Owner, stored.Uploaded = id, claims.MCDataID, svc.now().Unix()
	if info.RequestType == "group-fd" {
		stored.Group = info.RequestURI
	}
	raw, err := json.Marshal(stored)
	if err != nil || os.WriteFile(filepath.Join(directory, "meta.json"), raw, 0o600) != nil {
		cleanup()
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "storage unavailable"})
		return
	}
	location := strings.TrimSuffix(svc.cfg.Endpoints.Content, "/") + "/mcdata/files/" + id + "/" + stored.Name
	writer.Header().Set("Location", location)
	writeJSON(writer, http.StatusCreated, map[string]any{"location": location, "size": stored.Size})
}

// ------------------------------------------------------------------------------
// Helper: the error of an upload above the configured maximum size.
var errTooLarge = errors.New("file too large")

// ------------------------------------------------------------------------------
// TS 24.282 clause 10.2.2.2 step 2a: writes one uploaded file, refusing anything above the configured limit.
func storeFile(directory string, part *multipart.Part, limit int64) (*StoredFile, error) {
	return writeStoredFile(directory, part.FileName(), part.Header.Get("Content-Type"), part, limit)
}

// ------------------------------------------------------------------------------
// Helper: writes a file body as the payload of a stored file, refusing anything above the limit, and
// returns its metadata.
func writeStoredFile(directory, fileName, contentType string, body io.Reader, limit int64) (*StoredFile, error) {
	name := filepath.Base(fileName)
	if name == "" || name == "." || name == string(filepath.Separator) {
		name = "file"
	}
	handle, err := os.OpenFile(filepath.Join(directory, "payload"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	written, err := io.Copy(handle, io.LimitReader(body, limit+1))
	if closeErr := handle.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	if written > limit {
		return nil, errTooLarge
	}
	return &StoredFile{Name: name, Size: written, ContentType: contentType}, nil
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 11.1 steps 4 and 6: the maximum file size: <max-data-size-fd-bytes> of the service
// configuration and,
// for a group upload, the group's <mcdata-on-network-max-data-size-for-FD>; both apply,
// so a group cannot raise the service limit. Zero or absent means no such limit; with
// neither, a 64 MiB default bounds the upload.
func (svc *service) uploadLimit(info fileUploadInfo) int64 {
	limit := int64(svc.cfg.MCDataService.MaxDataSizeFDBytes)
	if info.RequestType == "group-fd" {
		if group, ok := svc.currentGroup(info.RequestURI); ok && group.MCData != nil && group.MCData.MaxFDBytes > 0 {
			if groupLimit := int64(group.MCData.MaxFDBytes); limit <= 0 || groupLimit < limit {
				limit = groupLimit
			}
		}
	}
	if limit <= 0 {
		limit = 64 * 1024 * 1024
	}
	return limit
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 10.2.2.2 step 1b: the request type and group checks of the media storage function.
func (svc *service) checkUploadRequest(info fileUploadInfo) (int, error) {
	switch info.RequestType {
	case "one-to-one-fd":
		return 0, nil
	case "group-fd":
		group, ok := svc.currentGroup(info.RequestURI)
		if !ok {
			return http.StatusNotFound, errors.New("unknown group")
		}
		if group.PreconfiguredUseOnly {
			return http.StatusForbidden, errors.New("group is for preconfigured use only")
		}
		if group.MCData == nil || !group.MCData.AllowFD {
			return http.StatusForbidden, errors.New("file distribution not allowed for this group")
		}
		return 0, nil
	default:
		return http.StatusBadRequest, fmt.Errorf("unsupported request type %q", info.RequestType)
	}
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 10.2.3.2: serve the stored file to an authorised MCData user.
func (svc *service) downloadFile(writer http.ResponseWriter, request *http.Request) {
	// The message store fetching a deposited file (TS 24.282 clause 21.2.5A.2 and clause 21.2.24.2 with
	// clause 6.7.2.2) authenticates with the system's service credentials.
	server := svc.internalAuthorized(request)
	var user User
	if !server {
		claims, ok := svc.authenticateBearer(writer, request)
		if !ok {
			return
		}
		user, ok = svc.siteUser("mcdata_id", claims.MCDataID)
		if !ok || claims.MCDataID == "" || user.MCData == nil {
			writeJSON(writer, http.StatusForbidden, map[string]string{"error": "reception control"})
			return
		}
	}
	file, err := svc.storedFile(request.PathValue("id"))
	if err != nil || file.Name != request.PathValue("name") {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	// Step 1: reception control. TS 24.282 leaves the policy as an editor's note, so
	// the media storage function applies the rules that govern the FD request itself:
	// the uploader, the MCData members of the group a group file was uploaded for, and
	// for a one-to-one file the users whose incoming communication list admits the
	// uploader (TS 24.282 clause 10.2.4.3.2 step 5A).
	if !server && !svc.mayDownload(user, file) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "reception control"})
		return
	}
	handle, err := os.Open(filepath.Join(svc.fileDir(file.ID), "payload"))
	if err != nil {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	defer closeQuietly(handle)
	contentType := file.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Cache-Control", "no-store")
	http.ServeContent(writer, request, file.Name, time.Unix(file.Uploaded, 0), handle)
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 6.7.3: the MCData server checks with an HTTP HEAD whether a file URL still
// resolves before it relays an FD request. The MCData server authenticates as
// itself; a client uses its access token.
func (svc *service) headFile(writer http.ResponseWriter, request *http.Request) {
	if !svc.internalAuthorized(request) {
		if _, ok := svc.authenticateBearer(writer, request); !ok {
			return
		}
	}
	file, err := svc.storedFile(request.PathValue("id"))
	if err != nil || file.Name != request.PathValue("name") {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	contentType := file.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Content-Length", fmt.Sprint(file.Size))
	writer.WriteHeader(http.StatusOK)
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 10.2.3.2 step 1: the reception control of a download: the uploader, an MCData member of
// the file's group, or for a one-to-one file a user whose incoming communication list admits the uploader
// (TS 24.282 clause 10.2.4.3.2 step 5A).
func (svc *service) mayDownload(user User, file StoredFile) bool {
	if user.MCDataID == file.Owner {
		return true
	}
	if file.Group != "" {
		group, ok := svc.currentGroup(file.Group)
		if !ok || group.MCData == nil {
			return false
		}
		for _, member := range group.MCData.Members {
			if member == user.MCDataID {
				return true
			}
		}
		return false
	}
	if user.MCData.IncomingAny {
		return true
	}
	for _, allowed := range user.MCData.IncomingFrom {
		if allowed == file.Owner {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 12.4.2.2: the MCData server lists and removes stored files (the file availability
// timer TDC2, and removal once every recipient has reported).
func (svc *service) listFiles(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	entries, err := os.ReadDir(filepath.Join(svc.dataDir, "files"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "storage unavailable"})
		return
	}
	files := []StoredFile{}
	for _, entry := range entries {
		if file, err := svc.storedFile(entry.Name()); err == nil {
			files = append(files, file)
		}
	}
	sort.Slice(files, func(first, second int) bool { return files[first].Uploaded < files[second].Uploaded })
	writeJSON(writer, http.StatusOK, map[string]any{"files": files})
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 12.4.2.2: the MCData server removes a stored file.
func (svc *service) deleteFile(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	file, err := svc.storedFile(request.PathValue("id"))
	if err != nil {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	if err := os.RemoveAll(svc.fileDir(file.ID)); err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "storage unavailable"})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "deleted", "id": file.ID})
}

// ------------------------------------------------------------------------------
// Helper: the media type of one part of a multipart body, empty when it cannot be parsed.
func partType(part *multipart.Part) string {
	value, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
	if err != nil {
		return ""
	}
	return value
}

// ------------------------------------------------------------------------------
// Helper: currentGroup is a group this system owns as its GMS holds it now, with the
// changes written through XCAP (TS 24.481 clauses 6.3.2 to 6.3.12), rather than as
// configured; the configuration answers only when the GMS cannot be reached.
func (svc *service) currentGroup(id string) (Group, bool) {
	if svc.serviceClient != nil && svc.cfg.Endpoints.GMS != "" {
		request, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(svc.cfg.Endpoints.GMS, "/")+"/internal/group?id="+url.QueryEscape(id), nil)
		if err == nil {
			request.SetBasicAuth(svc.cfg.ServerClientID, svc.cfg.ServerSecret)
			if response, err := svc.serviceClient.Do(request); err == nil {
				defer closeQuietly(response.Body)
				var group Group
				switch {
				case response.StatusCode == http.StatusNotFound:
					return Group{}, false
				case response.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&group) == nil:
					return group, true
				}
			}
		}
	}
	return svc.cfg.groupByID(id)
}
