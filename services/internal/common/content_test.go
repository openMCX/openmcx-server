//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ------------------------------------------------------------------------------
// Helper: the configuration of the tests of the media storage function of the MCData content server: upload
// (TS 24.282 clause 10.2.2.2), download (TS 24.282 clause 10.2.3.2), the HEAD existence check (TS 24.282
// clause 6.7.3) and the internal listing and removal used for the file availability timer (TS 24.282
// clause 12.4.2.2).
func contentConfig() Config {
	cfg := testConfig()
	cfg.Endpoints.Content = "https://content-server:8443"
	cfg.MCDataService.MaxDataSizeFDBytes = 64
	cfg.Users[0].MCDataID = "sip:alice.data@mcx.test"
	cfg.Users[0].MCData = &MCDataPolicy{TransmitData: true}
	cfg.Users[1].MCDataID = "sip:bob.data@mcx.test"
	cfg.Users[1].MCData = &MCDataPolicy{}
	cfg.Groups[0].MCData = &GroupMCData{Members: []string{"sip:alice.data@mcx.test"}, AllowFD: true, FDSupported: true, MaxFDBytes: 8}
	return cfg
}

// ------------------------------------------------------------------------------
// Helper: the multipart/mixed body of an upload (TS 24.282 clause 10.2.2.1): the mcdata-info with the request type
// ("group-fd" when a group is given, "one-to-one-fd" otherwise) and the file.
func upload(group, name, contents string) (string, *strings.Reader) {
	return uploadOrdered(group, name, contents, false)
}

// ------------------------------------------------------------------------------
// Helper: upload with the file before the mcdata-info when fileFirst is set (the order of the parts is free).
func uploadOrdered(group, name, contents string, fileFirst bool) (string, *strings.Reader) {
	info := `<?xml version="1.0"?><mcdatainfo xmlns="urn:3gpp:ns:mcdataInfo:1.0"><mcdata-Params><request-type>` +
		map[bool]string{true: "group-fd", false: "one-to-one-fd"}[group != ""] + `</request-type>`
	if group != "" {
		info += `<mcdata-request-uri><mcdataURI>` + group + `</mcdataURI></mcdata-request-uri>`
	}
	info += `<mcdata-calling-user-id><mcdataURI>sip:alice.data@mcx.test</mcdataURI></mcdata-calling-user-id></mcdata-Params></mcdatainfo>`
	boundary := "test-boundary"
	infoPart := "Content-Type: application/vnd.3gpp.mcdata-info+xml\r\n\r\n" + info
	filePart := "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"" + name + "\"\r\n\r\n" + contents
	if fileFirst {
		infoPart, filePart = filePart, infoPart
	}
	body := "--" + boundary + "\r\n" + infoPart + "\r\n--" + boundary + "\r\n" + filePart + "\r\n--" + boundary + "--\r\n"
	return "multipart/mixed; boundary=" + boundary, strings.NewReader(body)
}

// ------------------------------------------------------------------------------
// The media storage function stores an upload and answers 201 with its Location (TS 24.282 clause 10.2.2.2
// step 2), answers HEAD (TS 24.282 clause 6.7.3.2) and serves the file (TS 24.282 clause 10.2.3.2), applies
// reception control (TS 24.282 clause 10.2.3.2 step 1), and lists and removes it for the MCData server
// (TS 24.282 clause 12.4.2.2).
func TestContentServerStoresAndServesFiles(test *testing.T) {
	cfg, key := contentConfig(), testKey(test)
	handler := roleHandler(test, RoleContent, cfg, key, test.TempDir())
	token := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)

	contentType, body := upload("", "report.txt", "hello")
	rr := httptest.NewRecorder()
	request := bearerRequest(http.MethodPost, "/mcdata/files", token, body)
	request.Header.Set("Content-Type", contentType)
	handler.ServeHTTP(rr, request)
	if rr.Code != http.StatusCreated {
		test.Fatalf("upload status=%d body=%s", rr.Code, rr.Body.String())
	}
	location := rr.Header().Get("Location")
	if !strings.HasPrefix(location, cfg.Endpoints.Content+"/mcdata/files/") || !strings.HasSuffix(location, "/report.txt") {
		test.Fatalf("unexpected Location %q", location)
	}
	path := strings.TrimPrefix(location, cfg.Endpoints.Content)

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodHead, path, token, nil))
	if rr.Code != http.StatusOK {
		test.Fatalf("HEAD status=%d", rr.Code)
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodGet, path, token, nil))
	if rr.Code != http.StatusOK || rr.Body.String() != "hello" {
		test.Fatalf("download status=%d body=%q", rr.Code, rr.Body.String())
	}

	// TS 24.282 clause 10.2.3.2 step 1: reception control: a user whose incoming list does not admit the uploader.
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodGet, path, tokenFor(test, cfg, key, "bob", testNow, cfg.ServerClientID), nil))
	if rr.Code != http.StatusForbidden {
		test.Fatalf("reception control status=%d", rr.Code)
	}

	// The MCData server lists and removes the file (TS 24.282 clause 12.4.2.2).
	rr = httptest.NewRecorder()
	listing := httptest.NewRequest(http.MethodGet, "/internal/files", nil)
	listing.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
	handler.ServeHTTP(rr, listing)
	var files struct {
		Files []StoredFile `json:"files"`
	}
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &files) != nil || len(files.Files) != 1 ||
		files.Files[0].Owner != "sip:alice.data@mcx.test" || files.Files[0].Size != 5 {
		test.Fatalf("listing status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	removal := httptest.NewRequest(http.MethodDelete, "/internal/files/"+files.Files[0].ID, nil)
	removal.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
	handler.ServeHTTP(rr, removal)
	if rr.Code != http.StatusOK {
		test.Fatalf("delete status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodHead, path, token, nil))
	if rr.Code != http.StatusNotFound {
		test.Fatalf("HEAD after delete status=%d", rr.Code)
	}
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 10.2.2.2 step 1: the media storage function refuses an upload above the service's
// <max-data-size-fd-bytes> (step 1b.a) or the group's limit (step 1b.b.ii) with 413, of a user without
// transmission rights (step 1a) with 403, to an unknown group (step 1b.b.i) with 404, and a body that is not
// multipart with 400; a download without a token is refused with 401.
func TestContentServerRefusesUnauthorisedUploads(test *testing.T) {
	cfg, key := contentConfig(), testKey(test)
	handler := roleHandler(test, RoleContent, cfg, key, test.TempDir())
	post := func(token, contentType string, body *strings.Reader) int {
		rr := httptest.NewRecorder()
		request := bearerRequest(http.MethodPost, "/mcdata/files", token, body)
		request.Header.Set("Content-Type", contentType)
		handler.ServeHTTP(rr, request)
		return rr.Code
	}
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	bob := tokenFor(test, cfg, key, "bob", testNow, cfg.ServerClientID)

	contentType, body := upload("", "big.bin", strings.Repeat("x", 65))
	if status := post(alice, contentType, body); status != http.StatusRequestEntityTooLarge {
		test.Fatalf("service file size limit: status=%d", status)
	}
	contentType, body = upload(cfg.Groups[0].ID, "big.bin", strings.Repeat("x", 9))
	if status := post(alice, contentType, body); status != http.StatusRequestEntityTooLarge {
		test.Fatalf("group file size limit: status=%d", status)
	}
	// The group's limit applies whatever the order of the parts.
	contentType, body = uploadOrdered(cfg.Groups[0].ID, "big.bin", strings.Repeat("x", 9), true)
	if status := post(alice, contentType, body); status != http.StatusRequestEntityTooLarge {
		test.Fatalf("group file size limit, file before mcdata-info: status=%d", status)
	}
	contentType, body = upload("", "note.txt", "hello")
	if status := post(bob, contentType, body); status != http.StatusForbidden {
		test.Fatalf("transmission control: status=%d", status)
	}
	contentType, body = upload("sip:nowhere@mcx.test", "note.txt", "hello")
	if status := post(alice, contentType, body); status != http.StatusNotFound {
		test.Fatalf("unknown group: status=%d", status)
	}
	if status := post(alice, "text/plain", strings.NewReader("hello")); status != http.StatusBadRequest {
		test.Fatalf("non-multipart upload: status=%d", status)
	}
	// TS 24.482 annex A.2.3 step 1: neither a token nor an asserted identity is 403; an invalid token 401 with a
	// challenge (RFC 6750 section 3.1).
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/mcdata/files/0123456789abcdef0123456789abcdef/x", nil))
	if rr.Code != http.StatusForbidden {
		test.Fatalf("download without a token: status=%d", rr.Code)
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodGet, "/mcdata/files/0123456789abcdef0123456789abcdef/x", "not-a-token", nil))
	if rr.Code != http.StatusUnauthorized || !strings.HasPrefix(rr.Header().Get("WWW-Authenticate"), "Bearer") {
		test.Fatalf("download with an invalid token: status=%d %v", rr.Code, rr.Header())
	}
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 11.1 steps 4 and 6 with clause 10.2.2.2 step 1b: a group limit above the service limit
// does not raise it; below, it applies; with no service limit the group's applies alone.
func TestGroupUploadCannotBypassServiceLimit(test *testing.T) {
	cfg, key := contentConfig(), testKey(test)
	cfg.MCDataService.MaxDataSizeFDBytes = 16
	cfg.Groups[0].MCData.MaxFDBytes = 1000
	handler := roleHandler(test, RoleContent, cfg, key, test.TempDir())
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	post := func(group string, size int) int {
		contentType, body := upload(group, "f.bin", strings.Repeat("x", size))
		rr := httptest.NewRecorder()
		request := bearerRequest(http.MethodPost, "/mcdata/files", alice, body)
		request.Header.Set("Content-Type", contentType)
		handler.ServeHTTP(rr, request)
		return rr.Code
	}
	if status := post(cfg.Groups[0].ID, 17); status != http.StatusRequestEntityTooLarge {
		test.Fatalf("group limit raised the service limit: status=%d", status)
	}
	if status := post(cfg.Groups[0].ID, 16); status != http.StatusCreated {
		test.Fatalf("file at the service limit: status=%d", status)
	}
	cfg.Groups[0].MCData.MaxFDBytes = 4
	handler = roleHandler(test, RoleContent, cfg, key, test.TempDir())
	if status := post(cfg.Groups[0].ID, 5); status != http.StatusRequestEntityTooLarge {
		test.Fatalf("group limit below the service limit: status=%d", status)
	}
	if status := post("", 16); status != http.StatusCreated {
		test.Fatalf("one-to-one file at the service limit: status=%d", status)
	}
	// With no service limit the group's applies alone.
	cfg.MCDataService.MaxDataSizeFDBytes = 0
	handler = roleHandler(test, RoleContent, cfg, key, test.TempDir())
	if status := post(cfg.Groups[0].ID, 5); status != http.StatusRequestEntityTooLarge {
		test.Fatalf("group limit without a service limit: status=%d", status)
	}
}
