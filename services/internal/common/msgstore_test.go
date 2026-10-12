//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The MCData message store function and notification server (TS 24.282 clause 21) and upload by reference at the
// content server (TS 24.282 clause 10.2.2.2).

// The base path of alice's MCData message store account.
const aliceBox = "/nms/v1/mcdata/sip:alice.data@mcx.test"

// ------------------------------------------------------------------------------
// Helper: the configuration of the message store tests (that of the content server tests).
func storeConfig() Config {
	cfg := contentConfig()
	return cfg
}

// ------------------------------------------------------------------------------
// Helper: a message store at the fixed test time, with an optional client for the services it calls.
func storeHandler(test *testing.T, cfg Config, key *rsa.PrivateKey, client *http.Client) http.Handler {
	test.Helper()
	opts := []Option{WithClock(func() time.Time { return testNow })}
	if client != nil {
		opts = append(opts, WithServiceClient(client))
	}
	handler, err := NewHandlerWithKeys(RoleMsgStore, cfg, nil, &key.PublicKey, test.TempDir(), opts...)
	if err != nil {
		test.Fatal(err)
	}
	return handler
}

// ------------------------------------------------------------------------------
// Helper: a request with a JSON body, authenticated with a bearer token or, for "server", the server client
// credentials.
func call(test *testing.T, handler http.Handler, method, target, token string, body any) *httptest.ResponseRecorder {
	test.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	request := httptest.NewRequest(method, target, reader)
	if token == "server" {
		request.SetBasicAuth("mcx-server", "server-secret")
	} else if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)
	return rr
}

// ------------------------------------------------------------------------------
// Helper: decodes a JSON response body, failing the test when it is not JSON.
func decode(test *testing.T, rr *httptest.ResponseRecorder, into any) {
	test.Helper()
	if err := json.Unmarshal(rr.Body.Bytes(), into); err != nil {
		test.Fatalf("decode %q: %v", rr.Body.String(), err)
	}
}

// ------------------------------------------------------------------------------
// Helper: the path of a resource URL as the store itself sees it (the HTTP proxy removes "/msgstore").
func pathOf(resourceURL string) string {
	parsed, _ := url.Parse(resourceURL)
	return strings.TrimPrefix(parsed.Path, "/msgstore")
}

// ------------------------------------------------------------------------------
// Helper: a response carrying an object.
type objectReply struct {
	Object nmsObject `json:"object"`
}

// ------------------------------------------------------------------------------
// Helper: a response carrying a reference to a created resource.
type referenceReply struct {
	Reference nmsReference `json:"reference"`
}

// ------------------------------------------------------------------------------
// The MCData message store function (TS 24.282 clause 21.2): deposit by the MCData server, retrieval, flags,
// search, folders and their hierarchy, move, copy, search-based synchronization, deletion of objects and folders,
// and the bulk update and delete.
func TestMessageStoreObjectsFoldersAndSearch(test *testing.T) {
	cfg, key := storeConfig(), testKey(test)
	cfg.Endpoints.MsgStore = "https://http-proxy:8443/msgstore"
	handler := storeHandler(test, cfg, key, nil)
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	bob := tokenFor(test, cfg, key, "bob", testNow, cfg.ServerClientID)

	// TS 24.282 clause 21.2.5A.2: the MCData server deposits an SDS for alice (service credentials).
	deposit := map[string]any{"object": map[string]any{
		"attributes": map[string]any{"attribute": []map[string]any{
			{"name": "Request-Type", "value": []string{"one-to-one-sds"}},
			{"name": "From", "value": []string{"sip:bob.data@mcx.test"}},
			{"name": "Direction", "value": []string{"In"}}}},
		"flags": map[string]any{"flag": []string{"\\Recent"}}}}
	rr := call(test, handler, http.MethodPost, aliceBox+"/objects?retrieveFile=No", "server", deposit)
	var created referenceReply
	if rr.Code != http.StatusCreated {
		test.Fatalf("deposit status=%d body=%s", rr.Code, rr.Body.String())
	}
	decode(test, rr, &created)
	if !strings.HasPrefix(created.Reference.ResourceURL, "https://") || !strings.HasPrefix(created.Reference.Path, "/Inbox/") {
		test.Fatalf("the object is not in the Inbox: %+v", created.Reference)
	}
	objectPath := pathOf(created.Reference.ResourceURL)

	// TS 24.282 clause 21.2.1: alice reads it through the clients' URL; bob cannot reach alice's box.
	rr = call(test, handler, http.MethodGet, objectPath, alice, nil)
	var object objectReply
	decode(test, rr, &object)
	if rr.Code != http.StatusOK || object.Object.ParentFolderPath != "/Inbox" ||
		!strings.HasPrefix(object.Object.ResourceURL, cfg.Endpoints.MsgStore+"/nms/v1/") {
		test.Fatalf("retrieve status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr = call(test, handler, http.MethodGet, objectPath, bob, nil); rr.Code != http.StatusForbidden {
		test.Fatalf("another user's box status=%d", rr.Code)
	}
	// TS 24.482 annex A.2.3 step 1.
	if rr = call(test, handler, http.MethodGet, objectPath, "", nil); rr.Code != http.StatusForbidden {
		test.Fatalf("no token status=%d", rr.Code)
	}

	// TS 24.282 clause 21.2.3: flags.
	if rr = call(test, handler, http.MethodPut, objectPath+"/flags/%5CSeen", alice, nil); rr.Code != http.StatusOK ||
		!strings.Contains(rr.Body.String(), `\\Seen`) {
		test.Fatalf("add flag status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr = call(test, handler, http.MethodDelete, objectPath+"/flags/%5CRecent", alice, nil); rr.Code != http.StatusOK ||
		strings.Contains(rr.Body.String(), "Recent") {
		test.Fatalf("remove flag status=%d body=%s", rr.Code, rr.Body.String())
	}

	// TS 24.282 clause 21.2.2: search by attribute and by flag.
	search := func(criteria ...nmsCriterion) []nmsObject {
		rr := call(test, handler, http.MethodPost, aliceBox+"/objects/operations/search", alice, map[string]any{"selectionCriteria": map[string]any{
			"searchCriteria": map[string]any{"criterion": criteria}}})
		var list struct {
			ObjectList struct {
				Object []nmsObject `json:"object"`
			} `json:"objectList"`
		}
		if rr.Code != http.StatusOK {
			test.Fatalf("search status=%d body=%s", rr.Code, rr.Body.String())
		}
		decode(test, rr, &list)
		return list.ObjectList.Object
	}
	if count := len(search(nmsCriterion{Type: "Attribute", Name: "From", Value: "sip:bob.data@mcx.test"})); count != 1 {
		test.Fatalf("attribute search found %d", count)
	}
	if count := len(search(nmsCriterion{Type: "Flag", Value: "\\Recent"})); count != 0 {
		test.Fatalf("a removed flag still matches")
	}

	// TS 24.282 clause 21.2.8, clause 21.2.23 and clause 21.2.10: a folder, the hierarchy, and a move into it.
	rr = call(test, handler, http.MethodPost, aliceBox+"/folders", alice, map[string]any{"folder": map[string]any{"name": "Squad1"}})
	var folder referenceReply
	decode(test, rr, &folder)
	if rr.Code != http.StatusCreated || folder.Reference.Path != "/Squad1" {
		test.Fatalf("create folder status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = call(test, handler, http.MethodPost, aliceBox+"/folders", alice, map[string]any{"folder": map[string]any{"name": "Squad1"}})
	if rr.Code != http.StatusConflict {
		test.Fatalf("duplicate folder status=%d", rr.Code)
	}
	rr = call(test, handler, http.MethodPost, aliceBox+"/folders/operations/search", alice, map[string]any{"selectionCriteria": map[string]any{}})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"/Inbox"`) || !strings.Contains(rr.Body.String(), `"/Squad1"`) {
		test.Fatalf("hierarchy status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = call(test, handler, http.MethodPost, aliceBox+"/objects/operations/moveToFolder", alice, map[string]any{"targetSourceRef": map[string]any{
		"targetFolder": folder.Reference.ResourceURL, "sourceObjects": map[string]any{"objectReference": []nmsReference{{ResourceURL: created.Reference.ResourceURL}}}}})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"code":200`) {
		test.Fatalf("move status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = call(test, handler, http.MethodGet, pathOf(folder.Reference.ResourceURL), alice, nil)
	if !strings.Contains(rr.Body.String(), created.Reference.ResourceURL) {
		test.Fatalf("the folder does not list the moved object: %s", rr.Body.String())
	}
	// TS 24.282 clause 21.2.6: a copy of the folder into the Inbox holds a copy of the object.
	rr = call(test, handler, http.MethodPost, aliceBox+"/objects/operations/copyToFolder", alice, map[string]any{"targetSourceRef": map[string]any{
		"targetFolder": "root", "sourceFolders": map[string]any{"folderReference": []nmsReference{{ResourceURL: folder.Reference.ResourceURL}}}}})
	if rr.Code != http.StatusNotFound {
		test.Fatalf("an unknown target folder status=%d", rr.Code)
	}
	inbox := object.Object.ParentFolder
	rr = call(test, handler, http.MethodPost, aliceBox+"/objects/operations/copyToFolder", alice, map[string]any{"targetSourceRef": map[string]any{
		"targetFolder": inbox, "sourceFolders": map[string]any{"folderReference": []nmsReference{{ResourceURL: folder.Reference.ResourceURL}}}}})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"code":201`) {
		test.Fatalf("copy status=%d body=%s", rr.Code, rr.Body.String())
	}
	copies := search(nmsCriterion{Type: "Attribute", Name: "From", Value: "sip:bob.data@mcx.test"})
	if len(copies) != 2 || copies[1].ParentFolderPath != "/Inbox/Squad1" || copies[1].ResourceURL == created.Reference.ResourceURL {
		test.Fatalf("the copy is not in /Inbox/Squad1: %+v", copies)
	}
	// A search value that is not a number is refused (OMA NMS clause 5.1.5.2: cursors and mod-seqs are numbers).
	rr = call(test, handler, http.MethodPost, aliceBox+"/objects/operations/search", alice, map[string]any{"selectionCriteria": map[string]any{
		"searchCriteria": map[string]any{"criterion": []nmsCriterion{{Type: "ModifiedSince", Value: "yesterday"}}}}})
	if rr.Code != http.StatusBadRequest {
		test.Fatalf("a non-numeric mod-seq status=%d", rr.Code)
	}

	// TS 24.282 clause 21.2.17: CreatedObjects gives a creation cursor; VanishedObjects the deletions.
	rr = call(test, handler, http.MethodPost, aliceBox+"/objects/operations/search", alice, map[string]any{"selectionCriteria": map[string]any{
		"searchCriteria": map[string]any{"criterion": []nmsCriterion{{Type: "CreatedObjects", Value: "0"}}}}})
	if !strings.Contains(rr.Body.String(), `"creationCursor":"2"`) {
		test.Fatalf("no creation cursor: %s", rr.Body.String())
	}
	if rr = call(test, handler, http.MethodDelete, objectPath, alice, nil); rr.Code != http.StatusNoContent {
		test.Fatalf("delete status=%d", rr.Code)
	}
	rr = call(test, handler, http.MethodPost, aliceBox+"/objects/operations/search", alice, map[string]any{"selectionCriteria": map[string]any{
		"searchCriteria": map[string]any{"criterion": []nmsCriterion{{Type: "VanishedObjects", Value: "0"}}}}})
	if !strings.Contains(rr.Body.String(), created.Reference.ResourceURL) {
		test.Fatalf("the deletion is not reported: %s", rr.Body.String())
	}
	// TS 24.282 clause 21.2.7: the Inbox cannot be deleted; another folder can.
	rr = call(test, handler, http.MethodGet, aliceBox+"/folders/root", alice, nil)
	var root struct {
		Folder nmsFolder `json:"folder"`
	}
	decode(test, rr, &root)
	for _, sub := range root.Folder.SubFolders.FolderReference {
		want := http.StatusNoContent
		if sub.Name == "Inbox" {
			want = http.StatusForbidden
		}
		if rr = call(test, handler, http.MethodDelete, pathOf(sub.ResourceURL), alice, nil); rr.Code != want {
			test.Fatalf("delete folder %s status=%d", sub.Name, rr.Code)
		}
	}
	// TS 24.282 clause 21.2.3 and clause 21.2.4 in bulk.
	var refs []nmsReference
	for index := 0; index < 3; index++ {
		rr = call(test, handler, http.MethodPost, aliceBox+"/objects", alice, map[string]any{"object": map[string]any{}})
		decode(test, rr, &created)
		refs = append(refs, nmsReference{ResourceURL: created.Reference.ResourceURL})
	}
	rr = call(test, handler, http.MethodPost, aliceBox+"/objects/operations/bulkUpdate", alice, map[string]any{"bulkUpdate": map[string]any{
		"objects": map[string]any{"objectReference": refs}, "flags": map[string]any{"flag": []string{"\\Flagged"}}, "operation": "AddFlag"}})
	if rr.Code != http.StatusOK || strings.Count(rr.Body.String(), `"code":200`) != 3 {
		test.Fatalf("bulk update status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = call(test, handler, http.MethodPost, aliceBox+"/objects/operations/bulkDelete", alice, map[string]any{"objectReferenceList": map[string]any{"objectReference": refs[:2]}})
	if rr.Code != http.StatusOK || strings.Count(rr.Body.String(), `"code":204`) != 2 {
		test.Fatalf("bulk delete status=%d body=%s", rr.Code, rr.Body.String())
	}
	// The copy in /Inbox/Squad1 and the third object remain.
	if count := len(search()); count != 2 {
		test.Fatalf("%d objects remain", count)
	}
}

// ------------------------------------------------------------------------------
// The payloads of the message store: a deposit by reference fetches the file from the content server
// (TS 24.282 clause 21.2.5A.2 step 2a i), a client upload with an attachment (TS 24.282 clause 21.2.15), a file
// left at the content server retrieved on request (TS 24.282 clause 21.2.24.2), and the content server's upload
// by reference of a payload of the user's own account (TS 24.282 clause 10.2.2.2).
func TestMessageStorePayloadUploadAndRetrieveFromContentServer(test *testing.T) {
	cfg, key := storeConfig(), testKey(test)
	// bob may transmit data: his upload by reference below is refused for the account, not for the permission.
	cfg.Users[1].MCData.TransmitData = true
	content := httptest.NewTLSServer(roleHandler(test, RoleContent, cfg, key, test.TempDir()))
	defer content.Close()
	cfg.Endpoints.ContentInternal = content.URL
	handler := storeHandler(test, cfg, key, content.Client())
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)

	// A file uploaded to the content server, then deposited by reference (TS 24.282 clause 21.2.5A.2 step 2a i).
	contentType, body := upload("", "map.bin", "file-bytes")
	request, _ := http.NewRequest(http.MethodPost, content.URL+"/mcdata/files", body)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Authorization", "Bearer "+alice)
	response, err := content.Client().Do(request)
	if err != nil || response.StatusCode != http.StatusCreated {
		test.Fatalf("content upload %v %v", err, response)
	}
	location := response.Header.Get("Location")
	rr := call(test, handler, http.MethodPost, aliceBox+"/objects", "server", map[string]any{"object": map[string]any{
		"payloadPart": []map[string]any{{"contentType": "application/octet-stream", "href": location}}}})
	var created referenceReply
	decode(test, rr, &created)
	rr = call(test, handler, http.MethodGet, pathOf(created.Reference.ResourceURL)+"/payload", alice, nil)
	if rr.Code != http.StatusOK || rr.Body.String() != "file-bytes" {
		test.Fatalf("the deposited file was not fetched: status=%d body=%q", rr.Code, rr.Body.String())
	}

	// TS 24.282 clause 21.2.15: a client upload with root-fields and an attachment.
	var multipartBody bytes.Buffer
	boundary := "store-boundary"
	multipartBody.WriteString("--" + boundary + "\r\nContent-Disposition: form-data; name=\"root-fields\"\r\nContent-Type: application/json\r\n\r\n" +
		`{"object":{"attributes":{"attribute":[{"name":"Subject","value":["note"]}]}}}` + "\r\n--" + boundary +
		"\r\nContent-Disposition: form-data; name=\"attachments\"; filename=\"n.txt\"\r\nContent-Type: text/plain\r\n\r\nremember\r\n--" + boundary + "--\r\n")
	multipartRequest := httptest.NewRequest(http.MethodPost, aliceBox+"/objects", &multipartBody)
	multipartRequest.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	multipartRequest.Header.Set("Authorization", "Bearer "+alice)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, multipartRequest)
	decode(test, rr, &created)
	rr = call(test, handler, http.MethodGet, pathOf(created.Reference.ResourceURL)+"/payloadParts/1", alice, nil)
	if rr.Code != http.StatusOK || rr.Body.String() != "remember" || rr.Header().Get("Content-Type") != "text/plain" {
		test.Fatalf("attachment status=%d body=%q", rr.Code, rr.Body.String())
	}
	// TS 24.282 clause 21.2.24.2: an object whose file is still at the content server is retrieved on request.
	rr = call(test, handler, http.MethodPost, aliceBox+"/objects?retrieveFile=No", "server", map[string]any{"object": map[string]any{
		"payloadPart": []map[string]any{{"href": location}}}})
	decode(test, rr, &created)
	if rr = call(test, handler, http.MethodGet, pathOf(created.Reference.ResourceURL)+"/payload", alice, nil); rr.Code != http.StatusFound {
		test.Fatalf("a remote payload should redirect, status=%d", rr.Code)
	}
	rr = call(test, handler, http.MethodPost, pathOf(created.Reference.ResourceURL)+"/retrieve", alice, map[string]any{"empty": map[string]any{}})
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), location) {
		test.Fatalf("retrieve status=%d body=%s", rr.Code, rr.Body.String())
	}

	// TS 24.282 clause 10.2.2.2: upload by reference of that object's payload to the content server.
	storeServer := httptest.NewTLSServer(handler)
	defer storeServer.Close()
	payloadURL := storeServer.URL + pathOf(created.Reference.ResourceURL) + "/payload"
	cfgContent := cfg
	cfgContent.Endpoints.MsgStoreInternal = storeServer.URL
	byRef := httptest.NewServer(handlerWith(test, RoleContent, cfgContent, key, storeServer.Client()))
	defer byRef.Close()
	info := `<?xml version="1.0"?><mcdatainfo xmlns="urn:3gpp:ns:mcdataInfo:1.0"><mcdata-Params><request-type>one-to-one-fd</request-type>` +
		`<mcdata-calling-user-id><mcdataURI>sip:alice.data@mcx.test</mcdataURI></mcdata-calling-user-id></mcdata-Params></mcdatainfo>`
	uploadByRef := func(target, token string) *http.Response {
		multipartRef := "--b\r\nContent-Type: application/vnd.3gpp.mcdata-info+xml\r\n\r\n" + info +
			"\r\n--b\r\nContent-Type: message/external-body; access-type=URL; URL=\"" + target + "\"\r\n\r\n\r\n--b--\r\n"
		request, _ := http.NewRequest(http.MethodPost, byRef.URL+"/mcdata/files", strings.NewReader(multipartRef))
		request.Header.Set("Content-Type", "multipart/mixed; boundary=b")
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			test.Fatal(err)
		}
		return response
	}
	response = uploadByRef(payloadURL, alice)
	if response.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(response.Body)
		test.Fatalf("upload by reference status=%d body=%s", response.StatusCode, raw)
	}
	stored := response.Header.Get("Location")
	check, _ := http.NewRequest(http.MethodGet, byRef.URL+pathOf(stored), nil)
	check.Header.Set("Authorization", "Bearer "+alice)
	fetched, err := http.DefaultClient.Do(check)
	if err != nil {
		test.Fatal(err)
	}
	raw, _ := io.ReadAll(fetched.Body)
	if fetched.StatusCode != http.StatusOK || string(raw) != "file-bytes" {
		test.Fatalf("the file uploaded by reference: status=%d body=%q", fetched.StatusCode, raw)
	}
	// Another user's account is refused.
	bob := tokenFor(test, cfg, key, "bob", testNow, cfg.ServerClientID)
	if response = uploadByRef(payloadURL, bob); response.StatusCode != http.StatusForbidden {
		test.Fatalf("another account's payload status=%d", response.StatusCode)
	}
}

// ------------------------------------------------------------------------------
// Helper: the handler of a service role at the fixed test time, with an optional client for the services it calls.
func handlerWith(test *testing.T, role Role, cfg Config, key *rsa.PrivateKey, client *http.Client) http.Handler {
	test.Helper()
	opts := []Option{WithClock(func() time.Time { return testNow })}
	if client != nil {
		opts = append(opts, WithServiceClient(client))
	}
	handler, err := NewHandlerWithKeys(role, cfg, nil, &key.PublicKey, test.TempDir(), opts...)
	if err != nil {
		test.Fatal(err)
	}
	return handler
}

// ------------------------------------------------------------------------------
// The notification server and the message store's subscriptions (TS 24.282 clause 21.2): a LongPolling channel
// of the user's own, a subscription naming its callback, a deposit notified and returned by the long poll, a
// restart from index 0 resending the change, the channel's lifetime update and deletion, the subscription's
// deletion, and a callback that requires the service credentials.
func TestNotificationChannelCarriesStoreNotifications(test *testing.T) {
	cfg, key := storeConfig(), testKey(test)
	notifications := httptest.NewTLSServer(handlerWith(test, RoleNotification, cfg, key, nil))
	defer notifications.Close()
	cfg.Endpoints.NotificationInternal = notifications.URL
	cfg.Endpoints.Notification = notifications.URL
	// The notification server's own views name the callback from its configuration.
	notifications.Config.Handler = handlerWith(test, RoleNotification, cfg, key, nil)
	handler := storeHandler(test, cfg, key, notifications.Client())
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	bob := tokenFor(test, cfg, key, "bob", testNow, cfg.ServerClientID)
	client := notifications.Client()
	send := func(method, target, token string, body any) (*http.Response, map[string]any) {
		var reader io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			reader = bytes.NewReader(raw)
		}
		request, _ := http.NewRequest(method, target, reader)
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			test.Fatal(err)
		}
		defer closeQuietly(response.Body)
		var out map[string]any
		_ = json.NewDecoder(response.Body).Decode(&out)
		return response, out
	}
	channels := notifications.URL + "/notificationchannel/v1/" + url.PathEscape("sip:alice.data@mcx.test") + "/channels"
	// TS 24.282 clause 21.2.19: a LongPolling channel.
	response, out := send(http.MethodPost, channels, alice, map[string]any{"notificationChannel": map[string]any{
		"channelType": "LongPolling", "channelData": map[string]any{"maxNotifications": 10}, "channelLifetime": 600}})
	if response.StatusCode != http.StatusCreated {
		test.Fatalf("create channel status=%d %v", response.StatusCode, out)
	}
	channel := out["notificationChannel"].(map[string]any)
	if location := response.Header.Get("Location"); location == "" || location != channel["resourceURL"] {
		test.Fatalf("channel Location %q, resourceURL %v", location, channel["resourceURL"])
	}
	callback := channel["callbackURL"].(string)
	poll := channel["channelData"].(map[string]any)["channelURL"].(string)
	if response, _ = send(http.MethodPost, channels, bob, map[string]any{"notificationChannel": map[string]any{}}); response.StatusCode != http.StatusForbidden {
		test.Fatalf("another user's channels status=%d", response.StatusCode)
	}
	// TS 24.282 clause 21.2.12A: a subscription at the store naming the channel's callback.
	rr := call(test, handler, http.MethodPost, aliceBox+"/subscriptions", alice, map[string]any{"nmsSubscription": map[string]any{
		"callbackReference": map[string]any{"notifyURL": callback, "callbackData": "sync-1"}, "duration": 600}})
	if rr.Code != http.StatusCreated || !strings.Contains(rr.Body.String(), "restartToken") {
		test.Fatalf("subscription status=%d body=%s", rr.Code, rr.Body.String())
	}
	var subscription struct {
		NmsSubscription nmsSubscription `json:"nmsSubscription"`
	}
	decode(test, rr, &subscription)
	// A deposit is notified (TS 24.282 clause 21.2.16) and the long poll returns it (TS 24.282 clause 21.2.22).
	call(test, handler, http.MethodPost, aliceBox+"/objects", "server", map[string]any{"object": map[string]any{
		"attributes": map[string]any{"attribute": []map[string]any{{"name": "Subject", "value": []string{"hello"}}}}}})
	response, out = send(http.MethodPost, poll+"?wait=5", alice, map[string]any{})
	list, _ := out["notificationList"].([]any)
	if response.StatusCode != http.StatusOK || len(list) != 1 {
		test.Fatalf("poll status=%d %v", response.StatusCode, out)
	}
	raw, _ := json.Marshal(list[0])
	if !strings.Contains(string(raw), "changedObject") || !strings.Contains(string(raw), "sync-1") ||
		!strings.Contains(string(raw), subscription.NmsSubscription.RestartToken) {
		test.Fatalf("unexpected notification %s", raw)
	}
	// Nothing more: an empty list when the poll time runs out.
	response, out = send(http.MethodPost, poll+"?wait=1", alice, map[string]any{})
	if list, _ := out["notificationList"].([]any); response.StatusCode != http.StatusOK || len(list) != 0 {
		test.Fatalf("empty poll status=%d %v", response.StatusCode, out)
	}
	// TS 24.282 clause 21.2.14A: restarting from index 0 with the restart token resends the change.
	rr = call(test, handler, http.MethodPost, pathOf(subscription.NmsSubscription.ResourceURL), alice, map[string]any{"nmsSubscriptionUpdate": map[string]any{
		"restartToken": subscription.NmsSubscription.RestartToken, "index": 0, "duration": 600}})
	if rr.Code != http.StatusOK {
		test.Fatalf("update subscription status=%d body=%s", rr.Code, rr.Body.String())
	}
	call(test, handler, http.MethodPost, aliceBox+"/objects", "server", map[string]any{"object": map[string]any{}})
	response, out = send(http.MethodPost, poll+"?wait=5", alice, map[string]any{})
	if response.StatusCode != http.StatusOK {
		test.Fatalf("poll after the restart status=%d", response.StatusCode)
	}
	raw, _ = json.Marshal(out)
	// Event 1 was delivered before; after the restart from index 0 it comes again.
	if !strings.Contains(string(raw), `"lastModSeq":1`) {
		test.Fatalf("the restarted stream did not resend: %s", raw)
	}
	// TS 24.282 clause 21.2.21 and clause 21.2.20.
	resource := channel["resourceURL"].(string)
	if response, out = send(http.MethodPut, resource+"/channelLifetime", alice, map[string]any{"channelLifetime": 120}); response.StatusCode != http.StatusOK ||
		out["channelLifetime"].(float64) != 120 {
		test.Fatalf("lifetime status=%d %v", response.StatusCode, out)
	}
	if response, _ = send(http.MethodDelete, resource, alice, nil); response.StatusCode != http.StatusNoContent {
		test.Fatalf("delete channel status=%d", response.StatusCode)
	}
	if rr = call(test, handler, http.MethodDelete, pathOf(subscription.NmsSubscription.ResourceURL), alice, nil); rr.Code != http.StatusNoContent {
		test.Fatalf("delete subscription status=%d", rr.Code)
	}
	// The callback requires the service credentials.
	request, _ := http.NewRequest(http.MethodPost, callback, strings.NewReader("{}"))
	if response, _ = client.Do(request); response.StatusCode != http.StatusUnauthorized {
		test.Fatalf("an unauthenticated callback status=%d", response.StatusCode)
	}
}

// ------------------------------------------------------------------------------
// Helper: a client upload (TS 24.282 clause 21.2.15) of an object with one attachment, into a folder when one is
// named.
func uploadWithAttachment(test *testing.T, handler http.Handler, token, parentFolder, content string) *httptest.ResponseRecorder {
	test.Helper()
	root, _ := json.Marshal(map[string]any{"object": map[string]any{"parentFolder": parentFolder}})
	boundary := "store-boundary"
	body := "--" + boundary + "\r\nContent-Disposition: form-data; name=\"root-fields\"\r\nContent-Type: application/json\r\n\r\n" +
		string(root) + "\r\n--" + boundary + "\r\nContent-Disposition: form-data; name=\"attachments\"; filename=\"n.txt\"\r\n" +
		"Content-Type: text/plain\r\n\r\n" + content + "\r\n--" + boundary + "--\r\n"
	request := httptest.NewRequest(http.MethodPost, aliceBox+"/objects", strings.NewReader(body))
	request.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	request.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)
	return rr
}

// ------------------------------------------------------------------------------
// Helper: the payload files of a message store's data directory.
func payloadFiles(test *testing.T, dataDir string) []string {
	test.Helper()
	entries, err := os.ReadDir(filepath.Join(dataDir, "msgstore", "payload"))
	if err != nil {
		test.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// ------------------------------------------------------------------------------
// TS 24.282 clauses 21.2.15.2 and 21.2.6.2: an upload that is refused (an unknown parent folder) leaves no payload
// file, and a folder copy that fails part-way (a payload file gone) leaves neither a partial copy nor its files.
func TestClause_21_2_6_2_FailedChangesLeaveNoFiles(test *testing.T) {
	cfg, key := storeConfig(), testKey(test)
	dataDir := test.TempDir()
	handler, err := NewHandlerWithKeys(RoleMsgStore, cfg, nil, &key.PublicKey, dataDir, WithClock(func() time.Time { return testNow }))
	if err != nil {
		test.Fatal(err)
	}
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	if rr := uploadWithAttachment(test, handler, alice, aliceBox+"/folders/unknown", "lost"); rr.Code != http.StatusNotFound {
		test.Fatalf("upload into an unknown folder status=%d body=%s", rr.Code, rr.Body.String())
	}
	if files := payloadFiles(test, dataDir); len(files) != 0 {
		test.Fatalf("a refused upload left payload files %v", files)
	}
	rr := call(test, handler, http.MethodPost, aliceBox+"/folders", alice, map[string]any{"folder": map[string]any{"name": "Squad1"}})
	var folder referenceReply
	decode(test, rr, &folder)
	for _, content := range []string{"first", "second"} {
		if rr := uploadWithAttachment(test, handler, alice, folder.Reference.ResourceURL, content); rr.Code != http.StatusCreated {
			test.Fatalf("upload status=%d body=%s", rr.Code, rr.Body.String())
		}
	}
	// The second object's payload file disappears: its copy fails after the first object was copied.
	files := payloadFiles(test, dataDir)
	for _, name := range files {
		raw, err := os.ReadFile(filepath.Join(dataDir, "msgstore", "payload", name))
		if err == nil && string(raw) == "second" {
			if err := os.Remove(filepath.Join(dataDir, "msgstore", "payload", name)); err != nil {
				test.Fatal(err)
			}
		}
	}
	countAll := func() (int, int) {
		rr := call(test, handler, http.MethodPost, aliceBox+"/folders/operations/search", alice, map[string]any{"selectionCriteria": map[string]any{}})
		folders := strings.Count(rr.Body.String(), `"path"`)
		rr = call(test, handler, http.MethodPost, aliceBox+"/objects/operations/search", alice, map[string]any{"selectionCriteria": map[string]any{}})
		return folders, strings.Count(rr.Body.String(), `"resourceURL"`)
	}
	foldersBefore, objectsBefore := countAll()
	rr = call(test, handler, http.MethodGet, aliceBox+"/folders/root", alice, nil)
	var root struct {
		Folder nmsFolder `json:"folder"`
	}
	decode(test, rr, &root)
	rr = call(test, handler, http.MethodPost, aliceBox+"/objects/operations/copyToFolder", alice, map[string]any{"targetSourceRef": map[string]any{
		"targetFolder": root.Folder.ResourceURL, "sourceFolders": map[string]any{"folderReference": []nmsReference{{ResourceURL: folder.Reference.ResourceURL}}}}})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"code":500`) {
		test.Fatalf("copy status=%d body=%s", rr.Code, rr.Body.String())
	}
	if folders, objects := countAll(); folders != foldersBefore || objects != objectsBefore {
		test.Fatalf("a partial copy remains: %d folders, %d objects (were %d, %d)", folders, objects, foldersBefore, objectsBefore)
	}
	if after := payloadFiles(test, dataDir); len(after) != len(files)-1 {
		test.Fatalf("the partial copy's payload files remain: %v", after)
	}
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.16.1: a notification that cannot even be built as a request (a stored callback URL that does
// not parse) counts as a failed attempt: the delivery ends after its attempts instead of looping.
func TestClause_21_2_16_1_UndeliverableNotificationEnds(test *testing.T) {
	box := &storeBox{ID: "sip:alice.data@mcx.test", Store: "mcdata", Subscriptions: map[string]*storeSubscription{
		"sub": {ID: "sub", NotifyURL: "https://[::1", Expires: testNow.Unix() + 3600}},
		Events: []storeEvent{{Index: 1, Event: json.RawMessage(`{"changedObject":{}}`)}}}
	svc := &service{ctx: test.Context(), now: func() time.Time { return testNow },
		store: &messageStore{dir: test.TempDir(), boxes: map[string]*storeBox{}, sending: map[string]bool{"mcdata\x00" + box.ID: true}}}
	done := make(chan struct{})
	go func() {
		svc.deliverEvents(box)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(deliveryAttempts * deliveryAttempts * deliveryRetryDelay):
		test.Fatal("the delivery of an undeliverable notification does not end")
	}
	if svc.store.sending["mcdata\x00"+box.ID] {
		test.Fatal("the box is still marked as sending")
	}
}
