package common

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ------------------------------------------------------------------------------
// TS 33.180 clause 5.7.2: the GMS provides the GKTP of a protected group's GMK only to an MC service server with
// its credentials, for a member (an MCVideo ID as an MCVideo member); a poll with the current GMK-ID costs no key
// operation; the GMK and RAND have 128 bits with an NTP activation time (TS 33.180 annex E.6.4); the GMK is
// persisted privately and kept at a restart, rotated at expiry and at a membership change with an ordered
// activation time, and unsafe or corrupt key files fail closed.
func TestGroupKeyAccessPersistenceAndRotation(test *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	var kmsRequests atomic.Int32
	kms := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		kmsRequests.Add(1)
		username, password, ok := request.BasicAuth()
		if !ok || username != "gms-key" || password != "gms-secret" || request.Method != "POST" {
			test.Errorf("invalid KMS access")
			writer.WriteHeader(401)
			return
		}
		writer.Header().Set("Content-Type", "application/xml")
		_, _ = writer.Write([]byte("<KmsResponse/>"))
	}))
	defer kms.Close()
	svc := &service{dataDir: test.TempDir(), now: func() time.Time { return now }, cfg: Config{ServerClientID: "server", ServerSecret: "secret", GMSKeyClientID: "gms-key", GMSKeySecret: "gms-secret", Endpoints: Endpoints{KMS: kms.URL, GMS: "https://gms.example.org"}, Users: []User{{MCPTTID: "sip:alice@example.org", MCVideoID: "sip:alice.video@example.org"}, {MCPTTID: "sip:bob@example.org", MCVideoID: "sip:bob.video@example.org"}}, Groups: []Group{{ID: "sip:group@example.org", Members: []string{"sip:alice@example.org"}, ProtectMedia: true, MCVideo: &GroupMCVideo{Members: []string{"sip:alice.video@example.org"}}}}}}
	var operations []map[string]any
	svc.keyTool = func(in map[string]any) (json.RawMessage, error) {
		operations = append(operations, in)
		return json.RawMessage(`{"document":"<group>encrypted-recipient-payload</group>"}`), nil
	}
	handler := newGroupKeyHandler(svc, kms.Client(), time.Hour)
	call := func(handler http.HandlerFunc, user string, auth bool, knownKey ...uint32) *httptest.ResponseRecorder {
		request := httptest.NewRequest("GET", "/internal/gktp?group_id=sip%3Agroup%40example.org&user_id="+user, nil)
		if len(knownKey) > 0 {
			query := request.URL.Query()
			query.Set("known_key_id", strconv.FormatUint(uint64(knownKey[0]), 10))
			request.URL.RawQuery = query.Encode()
		}
		if auth {
			request.SetBasicAuth("server", "secret")
		}
		recorder := httptest.NewRecorder()
		handler(recorder, request)
		return recorder
	}
	if recorder := call(handler, "sip:alice@example.org", false); recorder.Code != 401 {
		test.Fatalf("missing auth = %d", recorder.Code)
	}
	if recorder := call(handler, "sip:bob@example.org", true); recorder.Code != 403 {
		test.Fatalf("nonmember = %d", recorder.Code)
	}
	// An MCVideo ID gets the group's GMK only as one of its MCVideo members.
	if recorder := call(handler, "sip:bob.video@example.org", true); recorder.Code != 403 {
		test.Fatalf("MCVideo nonmember = %d", recorder.Code)
	}
	if len(operations) != 0 {
		test.Fatal("unauthorized native key operation")
	}
	if recorder := call(handler, "sip:alice@example.org", true); recorder.Code != 200 || strings.Contains(recorder.Body.String(), "key_hex") {
		test.Fatalf("key fetch = %d %s", recorder.Code, recorder.Body.String())
	}
	if len(operations) != 1 {
		test.Fatal("missing native encapsulation")
	}
	first := operations[0]
	beforePoll := kmsRequests.Load()
	if recorder := call(handler, "sip:alice@example.org", true, first["csb_id"].(uint32)); recorder.Code != http.StatusNotModified || recorder.Body.Len() != 0 {
		test.Fatalf("unchanged poll = %d %s", recorder.Code, recorder.Body.String())
	}
	if len(operations) != 1 || kmsRequests.Load() != beforePoll {
		test.Fatal("unchanged poll invoked native crypto or KMS")
	}
	if first["valid_from"] != uint64(now.Unix()) || first["ntp_seconds"] != uint64(now.Unix()+2208988800) {
		test.Fatal("validity must be Unix seconds and MIKEY timestamp NTP")
	}
	if len(first["key_hex"].(string)) != 32 || len(first["random_hex"].(string)) != 32 {
		test.Fatal("GMK and RAND must have 128 bits")
	}
	restarted := newGroupKeyHandler(svc, kms.Client(), time.Hour)
	if recorder := call(restarted, "sip:alice@example.org", true); recorder.Code != 200 {
		test.Fatal("restart fetch failed")
	}
	if operations[1]["key_hex"] != first["key_hex"] || operations[1]["csb_id"] != first["csb_id"] {
		test.Fatal("restart replaced live GMK")
	}
	now = now.Add(time.Hour)
	if recorder := call(restarted, "sip:alice@example.org", true); recorder.Code != 200 {
		test.Fatal("rotation fetch failed")
	}
	if operations[2]["key_hex"] == first["key_hex"] || operations[2]["csb_id"] == first["csb_id"] {
		test.Fatal("expired GMK not rotated")
	}
	old := operations[2]["key_hex"]
	svc.cfg.Groups[0].Members = append(svc.cfg.Groups[0].Members, "sip:bob@example.org")
	if recorder := call(restarted, "sip:bob@example.org", true); recorder.Code != 503 {
		test.Fatal("same-second rotation must wait for an ordered activation time")
	}
	now = now.Add(time.Second)
	if recorder := call(restarted, "sip:bob@example.org", true, operations[2]["csb_id"].(uint32)); recorder.Code != 200 {
		test.Fatal("new member key failed")
	}
	if operations[3]["key_hex"] == old {
		test.Fatal("membership change did not rotate GMK")
	}
	files, _ := filepath.Glob(filepath.Join(svc.dataDir, "group-key-*.json"))
	if len(files) != 1 {
		test.Fatal("missing persisted GMK")
	}
	info, _ := os.Stat(files[0])
	if info.Mode().Perm() != 0600 {
		test.Fatal("GMK permissions")
	}
	if err := os.Chmod(files[0], 0644); err != nil {
		test.Fatal(err)
	}
	if recorder := call(restarted, "sip:alice@example.org", true); recorder.Code != 503 || !strings.Contains(recorder.Body.String(), "group_key_permissions_invalid") {
		test.Fatal("unsafe key permissions accepted or error hidden")
	}
	if err := os.Chmod(files[0], 0600); err != nil {
		test.Fatal(err)
	}
	if err := os.WriteFile(files[0], []byte("broken"), 0600); err != nil {
		test.Fatal(err)
	}
	if recorder := call(restarted, "sip:alice@example.org", true); recorder.Code != 503 {
		test.Fatalf("corrupt state must fail closed: %d", recorder.Code)
	}
}

// ------------------------------------------------------------------------------
// TS 24.281 clause 4.7.1 with TS 33.180 clause 5.7.2: an MCVideo server asks for the GMK of its user's MCVideo ID,
// which is delivered to MCVideo members only, and encapsulated for that identity.
func TestGroupKeyForMCVideoMember(test *testing.T) {
	now := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	kms := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/xml")
		_, _ = writer.Write([]byte("<KmsResponse/>"))
	}))
	defer kms.Close()
	svc := &service{dataDir: test.TempDir(), now: func() time.Time { return now }, cfg: Config{ServerClientID: "server", ServerSecret: "secret", GMSKeyClientID: "gms-key", GMSKeySecret: "gms-secret", Endpoints: Endpoints{KMS: kms.URL, GMS: "https://gms.example.org"},
		Users:  []User{{MCPTTID: "sip:alice@example.org", MCVideoID: "sip:alice.video@example.org"}, {MCPTTID: "sip:bob@example.org", MCVideoID: "sip:bob.video@example.org"}},
		Groups: []Group{{ID: "sip:group@example.org", Members: []string{"sip:alice@example.org", "sip:bob@example.org"}, ProtectMedia: true, MCVideo: &GroupMCVideo{Members: []string{"sip:alice.video@example.org"}}}}}}
	var recipients []any
	svc.keyTool = func(in map[string]any) (json.RawMessage, error) {
		recipients = append(recipients, in["recipient"])
		return json.RawMessage(`{"document":"<group>encrypted-recipient-payload</group>"}`), nil
	}
	handler := newGroupKeyHandler(svc, kms.Client(), time.Hour)
	for user, want := range map[string]int{"sip:alice.video@example.org": 200, "sip:bob.video@example.org": 403} {
		request := httptest.NewRequest("GET", "/internal/gktp?group_id=sip%3Agroup%40example.org&user_id="+user, nil)
		request.SetBasicAuth("server", "secret")
		recorder := httptest.NewRecorder()
		handler(recorder, request)
		if recorder.Code != want {
			test.Fatalf("%s = %d want %d", user, recorder.Code, want)
		}
	}
	if len(recipients) != 1 || recipients[0] != "sip:alice.video@example.org" {
		test.Fatalf("one encapsulation for the MCVideo ID expected, got %v", recipients)
	}
}

// ------------------------------------------------------------------------------
// TS 33.180 clause 5.7.2: GKTP requests may come at once; the KMS client made by the first is shared without a
// data race (run with -race).
func TestGroupKeyRequestsShareKMSClient(test *testing.T) {
	now := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	kms := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/xml")
		_, _ = writer.Write([]byte("<KmsResponse/>"))
	}))
	defer kms.Close()
	svc := &service{dataDir: test.TempDir(), now: func() time.Time { return now }, gmsKMSClient: kms.Client(),
		cfg: Config{ServerClientID: "server", ServerSecret: "secret", GMSKeyClientID: "gms-key", GMSKeySecret: "gms-secret",
			Endpoints: Endpoints{KMS: kms.URL, GMS: "https://gms.example.org"}, Users: []User{{MCPTTID: "sip:alice@example.org"}},
			Groups: []Group{{ID: "sip:group@example.org", Members: []string{"sip:alice@example.org"}, ProtectMedia: true}}}}
	svc.keyTool = func(map[string]any) (json.RawMessage, error) {
		return json.RawMessage(`{"document":"<group>encrypted-recipient-payload</group>"}`), nil
	}
	handler := newGroupKeyHandler(svc, nil, time.Hour)
	request := func(group string) int {
		httpRequest := httptest.NewRequest("GET", "/internal/gktp?group_id="+url.QueryEscape(group)+"&user_id=sip%3Aalice%40example.org", nil)
		httpRequest.SetBasicAuth("server", "secret")
		recorder := httptest.NewRecorder()
		handler(recorder, httpRequest)
		return recorder.Code
	}
	var wait sync.WaitGroup
	var local atomic.Int64
	for range 4 {
		wait.Go(func() {
			if request("sip:group@example.org") == http.StatusOK {
				local.Add(1)
			}
		})
	}
	wait.Wait()
	if local.Load() != 4 {
		test.Fatalf("%d of 4 local GKTP requests served", local.Load())
	}
}
