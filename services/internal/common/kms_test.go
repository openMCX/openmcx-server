//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
// TS 33.180 annex D.2.4: the KMS answers a KeyProvision request only for the identity a client may have (the MC
// servers and the GMS: key_clients_test.go): a signed-in user, with the key management scope, for its MCPTT ID, its MCData ID under the MCData
// scope (TS 24.282 clause 6.6) and its MCVideo ID under the MCVideo scope (TS 24.281 clause 4.7). The authority
// never leaks, is persisted privately (TS 33.180 clause 5.3.1.2) and not regenerated at a restart.
func TestKMSAuthorizesIdentityAndPersistsAuthority(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.Users[0].MCDataID = "sip:alice.data@mcx.test"
	cfg.MCDataService.ServiceURI = "sip:mcdata@mcx.test"
	cfg.Users[0].MCVideoID = "sip:alice.mcvideo@mcx.test"
	cfg.MCVideoService.ServiceURI = "sip:mcvideo@mcx.test"
	dir := test.TempDir()
	calls := 0
	backend := func(input map[string]any) (json.RawMessage, error) {
		calls++
		if input["op"] == "authority-generate" {
			return json.RawMessage(`{"private":"test-only"}`), nil
		}
		return json.RawMessage(`{"xml":"<KmsResponse/>"}`), nil
	}
	handler, err := NewHandlerWithKeys(RoleKMS, cfg, nil, &key.PublicKey, dir, WithClock(func() time.Time { return testNow }), WithKeyTool(backend))
	if err != nil {
		test.Fatal(err)
	}
	claims, _ := newClaims(cfg, cfg.Users[0], cfg.ServerClientID, "access", "", testNow)
	claims.Scope = "openid 3gpp:mc:ptt_key_management_service"
	token, _ := signToken(claims, key)
	for _, tc := range []struct {
		path, token string
		status      int
	}{
		{"/keymanagement/identity/v1/init", "", 401},
		{"/keymanagement/identity/v1/keyprov", token, 200},
		{"/keymanagement/identity/v1/keyprov/sip:other@example.test", token, 403},
	} {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, bearerRequest(http.MethodPost, tc.path, tc.token, nil))
		if rr.Code != tc.status {
			test.Fatalf("%s got%d want%d", tc.path, rr.Code, tc.status)
		}
		if strings.Contains(rr.Body.String(), "private") {
			test.Fatal("authority leaked")
		}
	}
	// The MCData ID of the token's user is provisioned only under the MCData KMS scope.
	data := "/keymanagement/identity/v1/keyprov/sip%3Aalice.data%40mcx.test"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodPost, data, token, nil))
	if rr.Code != 403 {
		test.Fatal("MCData identity provisioned without the MCData key management scope")
	}
	claims.Scope = "openid 3gpp:mc:ptt_key_management_service 3gpp:mc:data_key_management_service"
	dataToken, _ := signToken(claims, key)
	for path, want := range map[string]int{data: 200, "/keymanagement/identity/v1/keyprov/sip%3Abob.data%40mcx.test": 403} {
		rr = httptest.NewRecorder()
		handler.ServeHTTP(rr, bearerRequest(http.MethodPost, path, dataToken, nil))
		if rr.Code != want {
			test.Fatalf("%s got%d want%d", path, rr.Code, want)
		}
	}
	// TS 33.180 clause 5.1.3.1: the MCData ID under the MCData KMS scope alone; the MCPTT ID's key material and
	// not without the MCPTT KMS scope.
	claims.Scope = "openid 3gpp:mc:data_key_management_service"
	dataOnly, _ := signToken(claims, key)
	for path, want := range map[string]int{data: 200, "/keymanagement/identity/v1/keyprov": 403, "/keymanagement/identity/v1/init": 200} {
		rr = httptest.NewRecorder()
		handler.ServeHTTP(rr, bearerRequest(http.MethodPost, path, dataOnly, nil))
		if rr.Code != want {
			test.Fatalf("data scope only: %s got%d want%d", path, rr.Code, want)
		}
	}
	// TS 24.281 clause 4.7: the MCVideo ID only under the MCVideo KMS scope, and only the
	// token's own; the MCData scope does not provision it.
	video := "/keymanagement/identity/v1/keyprov/sip%3Aalice.mcvideo%40mcx.test"
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodPost, video, dataToken, nil))
	if rr.Code != 403 {
		test.Fatal("MCVideo identity provisioned without the MCVideo key management scope")
	}
	claims.Scope = "openid 3gpp:mc:ptt_key_management_service 3gpp:mc:video_key_management_service"
	videoToken, _ := signToken(claims, key)
	for path, want := range map[string]int{video: 200, data: 403, "/keymanagement/identity/v1/keyprov/sip%3Abob.mcvideo%40mcx.test": 403} {
		rr = httptest.NewRecorder()
		handler.ServeHTTP(rr, bearerRequest(http.MethodPost, path, videoToken, nil))
		if rr.Code != want {
			test.Fatalf("%s got%d want%d", path, rr.Code, want)
		}
	}
	info, err := os.Stat(filepath.Join(dir, "kms-authority.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		test.Fatal("authority not privately persisted", err)
	}
	claims.Scope = "openid"
	token, _ = signToken(claims, key)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodPost, "/keymanagement/identity/v1/keyprov", token, nil))
	if rr.Code != 403 {
		test.Fatal("missing key management scope accepted")
	}
	before := calls
	_, err = NewHandlerWithKeys(RoleKMS, cfg, nil, &key.PublicKey, dir, WithKeyTool(backend))
	if err != nil || calls != before {
		test.Fatal("restart regenerated authority", err)
	}
}

// ------------------------------------------------------------------------------
// Key provisioning requests run the key tool side by side (it was serialised under the service lock): two
// requests whose key tool runs each wait for the other both complete.
func TestKMSRunsKeyToolConcurrently(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	var inside atomic.Int64
	both := make(chan struct{})
	backend := func(input map[string]any) (json.RawMessage, error) {
		if input["op"] == "authority-generate" {
			return json.RawMessage(`{"private":"test-only"}`), nil
		}
		if inside.Add(1) == 2 {
			close(both)
		}
		select {
		case <-both:
			return json.RawMessage(`{"xml":"<KmsResponse/>"}`), nil
		case <-time.After(5 * time.Second):
			return nil, errors.New("the other request never ran")
		}
	}
	handler, err := NewHandlerWithKeys(RoleKMS, cfg, nil, &key.PublicKey, test.TempDir(), WithClock(func() time.Time { return testNow }),
		WithKeyTool(backend), WithContext(test.Context()))
	if err != nil {
		test.Fatal(err)
	}
	claims, _ := newClaims(cfg, cfg.Users[0], cfg.ServerClientID, "access", "", testNow)
	claims.Scope = scopePTTKeys
	token, _ := signToken(claims, key)
	var wait sync.WaitGroup
	codes := make([]int, 2)
	for index := range codes {
		wait.Go(func() {
			request := bearerRequest(http.MethodPost, "/keymanagement/identity/v1/keyprov", token, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, request)
			codes[index] = rr.Code
		})
	}
	wait.Wait()
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK {
		test.Fatalf("concurrent key provisioning: %v", codes)
	}
}

// ------------------------------------------------------------------------------
// TS 33.180 annex D.2.4 and RFC 5905 section 6: after the NTP era 0 ends (2036-02-07 06:28:16 UTC), the 64-bit
// timestamp of a KeyProvision request carries the era offset only; the KMS takes the era nearest to its clock, so a
// timestamp of the current period is served for its full NTP seconds, and one from the previous era stays refused.
func TestKMSKeyProvisionTimestampAfterEraZero(test *testing.T) {
	now := time.Date(2036, 3, 1, 12, 0, 0, 0, time.UTC)
	nowNTP := uint64(now.Unix()) + ntpUnixOffset
	if nowNTP>>32 != 1 {
		test.Fatal("test clock not in NTP era 1")
	}
	cfg, key := testConfig(), testKey(test)
	var served uint64
	backend := func(input map[string]any) (json.RawMessage, error) {
		if input["op"] == "authority-generate" {
			return json.RawMessage(`{"private":"test-only"}`), nil
		}
		served = input["ntp_seconds"].(uint64)
		return json.RawMessage(`{"xml":"<KmsResponse/>"}`), nil
	}
	handler, err := NewHandlerWithKeys(RoleKMS, cfg, nil, &key.PublicKey, test.TempDir(),
		WithClock(func() time.Time { return now }), WithKeyTool(backend))
	if err != nil {
		test.Fatal(err)
	}
	claims, _ := newClaims(cfg, cfg.Users[0], cfg.ServerClientID, "access", "", now)
	claims.Scope = scopePTTKeys
	token, _ := signToken(claims, key)
	base := "/keymanagement/identity/v1/keyprov/" + strings.ReplaceAll(strings.ReplaceAll(claims.MCPTTID, ":", "%3A"),
		"@", "%40") + "/"
	wanted := nowNTP - 1000
	for _, tc := range []struct {
		seconds uint64
		status  int
	}{{wanted, 200}, {nowNTP - kmsKeyPeriodSeconds - 1, 403}} {
		served = 0
		rr := httptest.NewRecorder()
		path := base + strings.ToUpper(strconv.FormatUint((tc.seconds&0xffffffff)<<32, 16))
		for len(path)-len(base) < 16 {
			path = base + "0" + path[len(base):]
		}
		handler.ServeHTTP(rr, bearerRequest(http.MethodPost, path, token, nil))
		if rr.Code != tc.status {
			test.Fatalf("%s got%d want%d", path, rr.Code, tc.status)
		}
		if tc.status == 200 && served != wanted {
			test.Fatalf("served NTP seconds %d, want %d", served, wanted)
		}
	}
	for _, tc := range []struct{ seconds, now, want uint64 }{
		{0xfffffff0, 1<<32 + 10, 0xfffffff0}, {5, 0xfffffff0, 1<<32 + 5}, {0xd6b43232, 0xd6b43232 + 7, 0xd6b43232},
	} {
		if got := ntpFromWire(uint32(tc.seconds), tc.now); got != tc.want {
			test.Fatalf("ntpFromWire(%x, %x) = %x, want %x", tc.seconds, tc.now, got, tc.want)
		}
	}
}

// ------------------------------------------------------------------------------
// TS 33.180 clause 5.3.2 and annex D.2.2: a signed KMS request body only for a user with transport keys, checked by
// the key tool (refused: 403); the responses of that user carry its keys for signing and wrapping; without
// security.kms_request_window_seconds the configuration is refused.
func TestKMSSignedRequestsForUsersWithTransportKeys(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	alice := cfg.Users[0].MCPTTID
	cfg.Security.TransportKeys = map[string]json.RawMessage{alice: json.RawMessage(`{"trk":{"file":"/keys/alice-trk","id":1}}`)}
	cfg.Security.KMSRequestWindowSeconds = 5
	var verified []map[string]any
	var responses []map[string]any
	accept := true
	backend := func(input map[string]any) (json.RawMessage, error) {
		switch input["op"] {
		case "authority-generate":
			return json.RawMessage(`{"private":"test-only"}`), nil
		case "kms-verify-request":
			verified = append(verified, input)
			if !accept {
				return nil, errors.New("signature")
			}
			return json.RawMessage(`{"user_uri":"` + alice + `"}`), nil
		}
		responses = append(responses, input)
		return json.RawMessage(`{"xml":"<KmsResponse/>"}`), nil
	}
	handler, err := NewHandlerWithKeys(RoleKMS, cfg, nil, &key.PublicKey, test.TempDir(),
		WithClock(func() time.Time { return testNow }), WithKeyTool(backend))
	if err != nil {
		test.Fatal(err)
	}
	claims, _ := newClaims(cfg, cfg.Users[0], cfg.ServerClientID, "access", "", testNow)
	claims.Scope = "openid 3gpp:mc:ptt_key_management_service"
	token, _ := signToken(claims, key)
	post := func(body string) int {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, bearerRequest(http.MethodPost, "/keymanagement/identity/v1/init", token, strings.NewReader(body)))
		return rr.Code
	}
	if code := post("<SignedKmsRequest/>"); code != 200 || len(verified) != 1 {
		test.Fatalf("signed request of a user with keys: %d, %d checks", code, len(verified))
	}
	check := verified[0]
	if check["request_xml"] != "<SignedKmsRequest/>" || check["window_seconds"] != 5 || check["user_uri"] != alice ||
		!strings.HasSuffix(check["request_uri"].(string), "/keymanagement/identity/v1/init") {
		test.Fatalf("verification input %v", check)
	}
	if responses[0]["security"] == nil {
		test.Fatal("response of a user with keys without its keys")
	}
	accept = false
	if code := post("<SignedKmsRequest/>"); code != 403 {
		test.Fatalf("refused signed request answered %d", code)
	}
	accept = true
	// An unsigned request of the same user (the signature is an optional extension): answered, with its keys.
	if code := post(""); code != 200 || responses[len(responses)-1]["security"] == nil {
		test.Fatalf("unsigned request of a user with keys: %d", code)
	}
	// A user without keys: no body.
	cfg.Security.TransportKeys = map[string]json.RawMessage{"sip:other@mcx.test": json.RawMessage(`{}`)}
	handler, err = NewHandlerWithKeys(RoleKMS, cfg, nil, &key.PublicKey, test.TempDir(),
		WithClock(func() time.Time { return testNow }), WithKeyTool(backend))
	if err != nil {
		test.Fatal(err)
	}
	if code := post("<SignedKmsRequest/>"); code != 400 {
		test.Fatalf("body of a user without keys answered %d", code)
	}
	before := len(responses)
	if code := post(""); code != 200 || responses[before]["security"] != nil {
		test.Fatalf("user without keys: %d", code)
	}
	// The window is required with transport keys.
	cfg.Security.KMSRequestWindowSeconds = 0
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "kms_request_window_seconds") {
		test.Fatalf("config without the request window: %v", err)
	}
}
