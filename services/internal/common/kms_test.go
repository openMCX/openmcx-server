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
