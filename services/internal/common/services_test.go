//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
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

// ------------------------------------------------------------------------------
// Helper: a signed access token of a configured user for an audience, issued at the given time.
func tokenFor(test *testing.T, cfg Config, key *rsa.PrivateKey, username string, now time.Time, audience string) string {
	test.Helper()
	user, ok := cfg.userByName(username)
	if !ok {
		test.Fatalf("unknown test user %q", username)
	}
	claims, err := newClaims(cfg, user, audience, "access", "", now)
	if err != nil {
		test.Fatal(err)
	}
	token, err := signToken(claims, key)
	if err != nil {
		test.Fatal(err)
	}
	return token
}

// ------------------------------------------------------------------------------
// Helper: the handler of a service role with the token verification key, at the fixed test time.
func roleHandler(test *testing.T, role Role, cfg Config, key *rsa.PrivateKey, dataDir string) http.Handler {
	test.Helper()
	handler, err := NewHandlerWithKeys(role, cfg, nil, &key.PublicKey, dataDir, WithClock(func() time.Time { return testNow }))
	if err != nil {
		test.Fatal(err)
	}
	return handler
}

// ------------------------------------------------------------------------------
// Helper: a request with a bearer access token.
func bearerRequest(method, target, token string, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, target, body)
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

// ------------------------------------------------------------------------------
// An expired access token and one of another audience are refused.
func TestVerifyTokenRejectsExpiredAndWrongAudience(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	expired := tokenFor(test, cfg, key, "alice", testNow.Add(-10*time.Minute), cfg.ServerClientID)
	if _, err := VerifyToken(expired, &key.PublicKey, cfg.Issuer, cfg.ServerClientID, testNow); err == nil {
		test.Fatal("expired token accepted")
	}
	valid := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	if _, err := VerifyToken(valid, &key.PublicKey, cfg.Issuer, "different-audience", testNow); err == nil {
		test.Fatal("wrong audience accepted")
	}
}

// ------------------------------------------------------------------------------
// The GMS serves a group document (TS 24.481 clause 6.3.3.3) to a member, with an entity tag (If-None-Match gives
// 304) and explicit <protect-media> and <protect-floor-control-signalling> false; a member reads only its own <entry>
// (TS 24.481 clause 7.2.12.1), a non-member nothing; the enhanced status elements of an MCData group (TS 24.481
// clause 7.2.4.2 and clause 7.2.8, for TS 24.282 clause 14.2) are served when set.
func TestGMSRequiresMembershipAndReturnsExplicitClearPolicyWithETag(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.Users = append(cfg.Users, User{Username: "charlie", Password: "charlie-password", MCID: "charlie-mc", MCPTTID: "sip:charlie@mcx.test", SIPURI: "sip:charlie@ims.mcx.test", ClientID: "charlie-device"})
	handler := roleHandler(test, RoleGMS, cfg, key, test.TempDir())
	target := "/xcap-root/org.openmobilealliance.groups/global/byGroupID/" + url.PathEscape("sip:team@mcx.test")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodGet, target, tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID), nil))
	if rr.Code != http.StatusOK {
		test.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/vnd.oma.poc.groups+xml") {
		test.Fatalf("content-type=%q", ct)
	}
	etag := rr.Header().Get("ETag")
	if etag == "" {
		test.Fatal("missing ETag")
	}
	body := rr.Body.String()
	for _, required := range []string{`<list-service uri="sip:team@mcx.test">`, `<entry uri="sip:alice@mcx.test">`,
		`<protect-media xmlns="urn:3gpp:ns:mcpttGroupInfo:1.0">false</protect-media>`,
		`<protect-floor-control-signalling xmlns="urn:3gpp:ns:mcpttGroupInfo:1.0">false</protect-floor-control-signalling>`} {
		if !strings.Contains(body, required) {
			test.Fatalf("group XML missing %q: %s", required, body)
		}
	}
	// TS 24.481 clause 7.2.12.1: a member reads only its own <entry> without the member-list rule.
	if strings.Contains(body, "sip:bob@mcx.test") {
		test.Fatalf("another member's entry exposed: %s", body)
	}
	if strings.Contains(body, "enhanced-status") {
		test.Fatalf("enhanced status without MCData settings: %s", body)
	}

	rr = httptest.NewRecorder()
	req := bearerRequest(http.MethodGet, target, tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID), nil)
	req.Header.Set("If-None-Match", etag)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotModified {
		test.Fatalf("conditional status=%d", rr.Code)
	}

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodGet, target, tokenFor(test, cfg, key, "charlie", testNow, cfg.ServerClientID), nil))
	if rr.Code != http.StatusForbidden {
		test.Fatalf("non-member status=%d body=%s", rr.Code, rr.Body.String())
	}

	// TS 24.481 clause 7.2.4.2 and clause 7.2.8: the enhanced status elements of an MCData group (TS 24.282 clause 14.2).
	for index := range cfg.Users {
		if cfg.Users[index].Username == "alice" {
			cfg.Users[index].MCDataID = "sip:alice.mcdata@mcx.test"
		}
	}
	cfg.Groups[0].MCData = &GroupMCData{Members: []string{"sip:alice.mcdata@mcx.test"}, AllowEnhancedStatus: true,
		EnhancedStatusValues: []EnhancedStatusValue{{ID: "1", Value: "On scene"}, {ID: "2", Value: "En route & ready"}}}
	handler = roleHandler(test, RoleGMS, cfg, key, test.TempDir())
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodGet, target, tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID), nil))
	for _, required := range []string{`<mcdata-allow-enhanced-status xmlns="urn:3gpp:ns:mcpttGroupInfo:1.0">true</mcdata-allow-enhanced-status>`,
		`<id>1</id><shortText><langType>en</langType><langText>On scene</langText></shortText>`,
		`<langText>En route &amp; ready</langText>`} {
		if !strings.Contains(rr.Body.String(), required) {
			test.Fatalf("group XML missing %q: %s", required, rr.Body.String())
		}
	}
}

// ------------------------------------------------------------------------------
// The CMS serves the user profile document only to the user its access token is bound to, with an entity tag and
// without passwords.
func TestCMSProfileIsRestrictedToBoundTokenIdentity(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	handler := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	bobPath := "/xcap-root/org.3gpp.mcptt.user-profile/users/" + url.PathEscape("sip:bob@mcx.test") + "/mcptt-user-profile-1.xml"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodGet, bobPath, tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID), nil))
	if rr.Code != http.StatusForbidden {
		test.Fatalf("cross-user status=%d body=%s", rr.Code, rr.Body.String())
	}

	alicePath := "/xcap-root/org.3gpp.mcptt.user-profile/users/" + url.PathEscape("sip:alice@mcx.test") + "/mcptt-user-profile-1.xml"
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodGet, alicePath, tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID), nil))
	if rr.Code != http.StatusOK {
		test.Fatalf("own status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("ETag") == "" || !strings.Contains(rr.Body.String(), "sip:alice@ims.mcx.test") || !strings.Contains(rr.Body.String(), "alice-device") {
		test.Fatalf("incomplete profile response: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "alice-password") || strings.Contains(rr.Body.String(), "sip-secret") {
		test.Fatal("profile leaked a password")
	}
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 6.3.4.3: an administrator replaces a user profile document, which the CMS then serves (also
// after a restart), with a new entity tag for the SIP front (TS 24.484 clause 6.3.13.3); each refusal names its
// error element.
func TestCMSProfileUpdateByAdministrator(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	for index := range cfg.Users {
		if cfg.Users[index].Username == "alice" {
			cfg.Users[index].ConfigManagement = true
		}
	}
	dir := test.TempDir()
	handler := roleHandler(test, RoleCMS, cfg, key, dir)
	bobPath := "/xcap-root/org.3gpp.mcptt.user-profile/users/" + url.PathEscape("sip:bob@mcx.test") + "/mcptt-user-profile-1.xml"
	alice, bob := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID), tokenFor(test, cfg, key, "bob", testNow, cfg.ServerClientID)
	internal := func() string {
		rr := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/internal/user-profile?mcptt_id="+url.QueryEscape("sip:bob@mcx.test"), nil)
		request.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
		handler.ServeHTTP(rr, request)
		if rr.Code != http.StatusOK {
			test.Fatalf("internal profile status=%d body=%s", rr.Code, rr.Body.String())
		}
		return rr.Body.String()
	}
	before := internal()
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodGet, bobPath, alice, nil))
	if rr.Code != http.StatusOK {
		test.Fatalf("administrator read status=%d", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, userProfileMIME) {
		test.Fatalf("profile served as %q", got)
	}
	if err := userProfileSchema.validate(rr.Body.Bytes()); err != nil {
		test.Fatalf("served profile does not conform: %v", err)
	}
	updated := strings.Replace(rr.Body.String(), "</mcptt-user-profile>", "<Name>Bob</Name></mcptt-user-profile>", 1)
	// RFC 4825 section 8.2.5 and TS 24.484 clause 8.3.2.6: each refusal names its error element.
	for _, tc := range []struct {
		token, body, mime string
		want              int
		element           string
	}{
		{bob, updated, userProfileMIME, http.StatusForbidden, ""},
		{alice, updated, "application/xcap-el+xml", http.StatusUnsupportedMediaType, ""},
		{alice, "<mcptt-user-profile", userProfileMIME, http.StatusConflict, "<not-well-formed"},
		{alice, "<not-a-profile/>", userProfileMIME, http.StatusConflict, "<schema-validation-error"},
		{alice, strings.Replace(updated, "<Status>true</Status>", "<Status>maybe</Status>", 1), userProfileMIME, http.StatusConflict, "<schema-validation-error"},
		{alice, strings.Replace(updated, "<Name>Bob</Name>", "<Colour>blue</Colour>", 1), userProfileMIME, http.StatusConflict, "<schema-validation-error"},
		{alice, strings.Replace(updated, `XUI-URI="sip:bob@mcx.test"`, `XUI-URI="sip:carol@mcx.test"`, 1), userProfileMIME, http.StatusConflict,
			`<constraint-failure phrase="Wrong User Profile URI"`},
		{alice, strings.Replace(updated, "<Name>Bob</Name>", "<Common><MCPTT-group-call><Priority>300</Priority></MCPTT-group-call></Common>", 1),
			userProfileMIME, http.StatusConflict, `<constraint-failure phrase="Priority value out of range"`},
		{alice, updated, userProfileMIME, http.StatusOK, ""},
	} {
		rr = httptest.NewRecorder()
		request := bearerRequest(http.MethodPut, bobPath, tc.token, strings.NewReader(tc.body))
		request.Header.Set("Content-Type", tc.mime)
		handler.ServeHTTP(rr, request)
		if rr.Code != tc.want || !strings.Contains(rr.Body.String(), tc.element) {
			test.Fatalf("PUT status=%d want %d %s body=%s", rr.Code, tc.want, tc.element, rr.Body.String())
		}
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodGet, bobPath, bob, nil))
	if rr.Code != http.StatusOK || rr.Body.String() != updated {
		test.Fatalf("the updated profile is not served: %d %s", rr.Code, rr.Body.String())
	}
	if internal() == before {
		test.Fatal("the entity tag did not change")
	}
	// The update survives a restart of the CMS.
	restarted := roleHandler(test, RoleCMS, cfg, key, dir)
	rr = httptest.NewRecorder()
	restarted.ServeHTTP(rr, bearerRequest(http.MethodGet, bobPath, bob, nil))
	if rr.Body.String() != updated {
		test.Fatal("the updated profile did not persist")
	}
	// An update that cannot be stored is refused, and the stored one is still served.
	unblock := blockWrites(test, dir)
	rr = httptest.NewRecorder()
	request := bearerRequest(http.MethodPut, bobPath, alice, strings.NewReader(strings.Replace(updated, "<Name>Bob</Name>", "<Name>Robert</Name>", 1)))
	request.Header.Set("Content-Type", userProfileMIME)
	restarted.ServeHTTP(rr, request)
	unblock()
	if rr.Code != http.StatusInternalServerError {
		test.Fatalf("an update that could not be stored: %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	restarted.ServeHTTP(rr, bearerRequest(http.MethodGet, bobPath, bob, nil))
	if rr.Body.String() != updated {
		test.Fatal("an update that was not stored is served")
	}
	// A stored file that cannot be read back stops the CMS rather than serving the configured profiles.
	if err := os.WriteFile(filepath.Join(dir, "user-profiles.json"), []byte("{broken"), 0o600); err != nil {
		test.Fatal(err)
	}
	if _, err := NewHandlerWithKeys(RoleCMS, cfg, nil, &key.PublicKey, dir); err == nil {
		test.Fatal("a CMS started with a damaged user profile file")
	}
}

// ------------------------------------------------------------------------------
// The internal group and user lookups of the GMS and CMS need the server client credentials and carry no secrets.
func TestInternalLookupsRequireServerCredentialsAndRedactSecrets(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	for _, tc := range []struct {
		role   Role
		target string
	}{
		{RoleGMS, "/internal/group?id=" + url.QueryEscape("sip:team@mcx.test")},
		{RoleCMS, "/internal/user?mcptt_id=" + url.QueryEscape("sip:alice@mcx.test")},
	} {
		test.Run(string(tc.role), func(test *testing.T) {
			handler := roleHandler(test, tc.role, cfg, key, test.TempDir())
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			req.SetBasicAuth(cfg.ServerClientID, "wrong")
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				test.Fatalf("wrong credentials status=%d", rr.Code)
			}
			rr = httptest.NewRecorder()
			req = httptest.NewRequest(http.MethodGet, tc.target, nil)
			req.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				test.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), "password") || strings.Contains(rr.Body.String(), "sip-secret") {
				test.Fatalf("secret leaked: %s", rr.Body.String())
			}
		})
	}
}

// ------------------------------------------------------------------------------
// The location service stores a user's own location only, and keeps it across a restart.
func TestLMSAllowsOnlySelfLocationAndPersistsAcrossRestart(test *testing.T) {
	cfg, key, dataDir := testConfig(), testKey(test), test.TempDir()
	handler := roleHandler(test, RoleLMS, cfg, key, dataDir)
	token := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	target := "/location/" + url.PathEscape("sip:alice@mcx.test")
	payload := []byte(`{"latitude":48.8566,"longitude":2.3522,"accuracy":8.5}`)
	rr := httptest.NewRecorder()
	req := bearerRequest(http.MethodPut, target, token, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		test.Fatalf("put status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodGet, "/location/"+url.PathEscape("sip:bob@mcx.test"), token, nil))
	if rr.Code != http.StatusForbidden {
		test.Fatalf("cross-user status=%d", rr.Code)
	}

	handler = roleHandler(test, RoleLMS, cfg, key, dataDir)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodGet, target, token, nil))
	if rr.Code != http.StatusOK {
		test.Fatalf("get after restart status=%d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Latitude, Longitude, Accuracy float64
		UpdatedAt                     string `json:"updated_at"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		test.Fatal(err)
	}
	if got.Latitude != 48.8566 || got.Longitude != 2.3522 || got.Accuracy != 8.5 || got.UpdatedAt == "" {
		test.Fatalf("location=%+v", got)
	}
}

// ------------------------------------------------------------------------------
// The location service refuses to start on a corrupt location state.
func TestLMSRefusesCorruptPersistentState(test *testing.T) {
	cfg, key, dataDir := testConfig(), testKey(test), test.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "locations.json"), []byte("{"), 0o600); err != nil {
		test.Fatal(err)
	}
	if _, err := NewHandlerWithKeys(RoleLMS, cfg, nil, &key.PublicKey, dataDir); err == nil {
		test.Fatal("corrupt location state was silently ignored")
	}
}

// ------------------------------------------------------------------------------
// The KMS without its native key tool is alive but not ready, and serves no keys.
func TestKMSFailsClosedWhenNativeBackendUnavailable(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	handler, err := NewHandlerWithKeys(RoleKMS, cfg, nil, &key.PublicKey, test.TempDir(), WithKeyTool(func(map[string]any) (json.RawMessage, error) { return nil, fmt.Errorf("backend unavailable") }))
	if err != nil {
		test.Fatal(err)
	}
	for target, want := range map[string]int{"/healthz": http.StatusOK, "/readyz": http.StatusServiceUnavailable, "/keys": http.StatusNotFound} {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, target, nil))
		if rr.Code != want {
			test.Fatalf("%s status=%d want=%d body=%s", target, rr.Code, want, rr.Body.String())
		}
	}
}

// ------------------------------------------------------------------------------
// The IdMS, GMS, CMS and location service report ready.
func TestImplementedRolesReportReady(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	for _, role := range []Role{RoleIDMS, RoleGMS, RoleCMS, RoleLMS} {
		test.Run(string(role), func(test *testing.T) {
			var handler http.Handler
			if role == RoleIDMS {
				handler = newTestHandler(test, role, cfg, key)
			} else {
				handler = roleHandler(test, role, cfg, key, test.TempDir())
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if rr.Code != http.StatusOK {
				test.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

// ------------------------------------------------------------------------------
// The CMS serves a user's private call policy to the servers (none for a user without one), and the configuration
// refuses an unknown or own private call target.
func TestCMSServesPrivateCallPolicyAndValidatesTargets(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.Users[0].PrivateCall = &PrivateCallPolicy{Allow: true, AutomaticCommencement: true, Targets: []string{"sip:bob@mcx.test"}}
	handler := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	var served publicUser
	for _, id := range []string{"sip:alice@mcx.test", "sip:bob@mcx.test"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/internal/user?mcptt_id="+url.QueryEscape(id), nil)
		req.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			test.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		served = publicUser{}
		if err := json.Unmarshal(rr.Body.Bytes(), &served); err != nil {
			test.Fatal(err)
		}
		if id == "sip:alice@mcx.test" && (served.PrivateCall == nil || !served.PrivateCall.Allow || served.PrivateCall.ManualCommencement ||
			len(served.PrivateCall.Targets) != 1 || served.PrivateCall.Targets[0] != "sip:bob@mcx.test") {
			test.Fatalf("private call policy not served: %s", rr.Body.String())
		}
		if id == "sip:bob@mcx.test" && (served.PrivateCall != nil || strings.Contains(rr.Body.String(), "private_call")) {
			test.Fatalf("absent policy must deny by omission: %s", rr.Body.String())
		}
	}
	for _, target := range []string{"sip:unknown@mcx.test", "sip:alice@mcx.test"} {
		bad := testConfig()
		bad.Users[0].PrivateCall = &PrivateCallPolicy{Allow: true, Targets: []string{target}}
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "invalid private call target") {
			test.Fatalf("target %q accepted: %v", target, err)
		}
	}
}

// ------------------------------------------------------------------------------
// The CMS serves the callee side of the private call policy (callable, incoming_from) only when set, and the
// configuration refuses an unknown or own incoming entry.
func TestCMSServesCalleePrivateCallPolicy(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	callable := false
	cfg.Users[1].PrivateCall = &PrivateCallPolicy{Callable: &callable, IncomingFrom: []string{"sip:alice@mcx.test"}}
	handler := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/internal/user?mcptt_id="+url.QueryEscape("sip:bob@mcx.test"), nil)
	req.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"callable":false`) ||
		!strings.Contains(rr.Body.String(), `"incoming_from":["sip:alice@mcx.test"]`) {
		test.Fatalf("callee policy not served: %d %s", rr.Code, rr.Body.String())
	}
	cfg.Users[0].PrivateCall = &PrivateCallPolicy{Allow: true}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/internal/user?mcptt_id="+url.QueryEscape("sip:alice@mcx.test"), nil)
	req.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
	roleHandler(test, RoleCMS, cfg, key, test.TempDir()).ServeHTTP(rr, req)
	if strings.Contains(rr.Body.String(), "callable") || strings.Contains(rr.Body.String(), "incoming_") {
		test.Fatalf("absent callee fields must be omitted: %s", rr.Body.String())
	}
	for _, caller := range []string{"sip:unknown@mcx.test", "sip:bob@mcx.test"} {
		bad := testConfig()
		bad.Users[1].PrivateCall = &PrivateCallPolicy{IncomingFrom: []string{caller}}
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "invalid incoming private call entry") {
			test.Fatalf("incoming entry %q accepted: %v", caller, err)
		}
	}
}

// ------------------------------------------------------------------------------
// The CMS serves the emergency private call and alert rights with their recipients, and the configuration refuses
// an unknown or own recipient.
func TestCMSServesEmergencyPrivateCallPolicy(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.Users[0].PrivateCall = &PrivateCallPolicy{Allow: true, Emergency: true, EmergencyRecipients: []string{"sip:bob@mcx.test"},
		EmergencyCancel: true, Alert: true, AlertAny: true}
	handler := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/internal/user?mcptt_id="+url.QueryEscape("sip:alice@mcx.test"), nil)
	req.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
	handler.ServeHTTP(rr, req)
	for _, want := range []string{`"emergency":true`, `"emergency_recipients":["sip:bob@mcx.test"]`, `"emergency_cancel":true`,
		`"alert":true`, `"alert_any":true`} {
		if !strings.Contains(rr.Body.String(), want) {
			test.Fatalf("%s not served: %s", want, rr.Body.String())
		}
	}
	for _, recipient := range []string{"sip:unknown@mcx.test", "sip:alice@mcx.test"} {
		for list, policy := range map[string]*PrivateCallPolicy{
			"emergency": {Emergency: true, EmergencyRecipients: []string{recipient}},
			"alert":     {Alert: true, AlertRecipients: []string{recipient}},
		} {
			bad := testConfig()
			bad.Users[0].PrivateCall = policy
			if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "invalid emergency private call recipient") {
				test.Fatalf("%s recipient %q accepted: %v", list, recipient, err)
			}
		}
	}
}

// ------------------------------------------------------------------------------
// The GMS serves a group-broadcast group with its subordinate groups (TS 23.379 clause 10.6.2.5); the configuration
// refuses unknown, own or missing subordinates, and subordinates of a user-broadcast group.
func TestGMSServesBroadcastHierarchyGroups(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.Groups = append(cfg.Groups,
		Group{ID: "sip:all@mcx.test", Type: "group-broadcast", Members: []string{"sip:alice@mcx.test"}, SubordinateGroups: []string{"sip:team@mcx.test"}},
		Group{ID: "sip:ops@mcx.test", Type: "user-broadcast", Members: []string{"sip:alice@mcx.test", "sip:bob@mcx.test"}})
	handler := roleHandler(test, RoleGMS, cfg, key, test.TempDir())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/internal/group?id="+url.QueryEscape("sip:all@mcx.test"), nil)
	req.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"type":"group-broadcast"`) ||
		!strings.Contains(rr.Body.String(), `"subordinate_groups":["sip:team@mcx.test"]`) {
		test.Fatalf("group-broadcast group not served: %d %s", rr.Code, rr.Body.String())
	}
	for name, mutate := range map[string]func(*Config){
		"unknown subordinate": func(config *Config) {
			config.Groups[0].Type, config.Groups[0].SubordinateGroups = "group-broadcast", []string{"sip:nope@mcx.test"}
		},
		"self subordinate": func(config *Config) {
			config.Groups[0].Type, config.Groups[0].SubordinateGroups = "group-broadcast", []string{config.Groups[0].ID}
		},
		"missing subordinates": func(config *Config) { config.Groups[0].Type = "group-broadcast" },
		"subordinates on user-broadcast": func(config *Config) {
			config.Groups = append(config.Groups, Group{ID: "sip:x@mcx.test", Type: "user-broadcast", SubordinateGroups: []string{config.Groups[0].ID}})
		},
	} {
		bad := testConfig()
		mutate(&bad)
		if err := bad.Validate(); err == nil {
			test.Fatalf("%s accepted", name)
		}
	}
}

// ------------------------------------------------------------------------------
// The CMS serves the functional aliases (TS 23.280 clause 8.1.5) and the takeover right; the configuration refuses an
// alias with an unknown user, no activation, or the identity of a user.
func TestCMSServesFunctionalAliases(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.FunctionalAliases = []FunctionalAlias{{ID: "sip:dispatcher@mcx.test", Users: []string{"sip:alice@mcx.test"},
		MaxSimultaneousActivations: 1, AllowTakeover: true}}
	cfg.Users[1].FunctionalAliasTakeover = true
	handler := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	for path, want := range map[string]string{
		"/internal/functional-alias?id=" + url.QueryEscape("sip:dispatcher@mcx.test"): `"max_simultaneous_activations":1`,
		"/internal/user?mcptt_id=" + url.QueryEscape("sip:bob@mcx.test"):              `"functional_alias_takeover":true`,
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), want) {
			test.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
		}
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/internal/functional-alias?id=sip:none@mcx.test", nil)
	req.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		test.Fatalf("unknown alias served: %d", rr.Code)
	}
	for name, fa := range map[string]FunctionalAlias{
		"unknown user":  {ID: "sip:x@mcx.test", Users: []string{"sip:nobody@mcx.test"}, MaxSimultaneousActivations: 1},
		"no activation": {ID: "sip:x@mcx.test", MaxSimultaneousActivations: 0},
		"user id clash": {ID: "sip:alice@mcx.test", MaxSimultaneousActivations: 1},
	} {
		bad := testConfig()
		bad.FunctionalAliases = []FunctionalAlias{fa}
		if err := bad.Validate(); err == nil {
			test.Fatalf("%s accepted", name)
		}
	}
	// In admin mode MCX Admin creates the users later: an alias may name an MCPTT ID the file does not hold yet, but
	// still only an MC service ID.
	admin := testConfig()
	admin.AdminAccounts = &AdminAccountsConfig{URL: "https://mcxadmin:8443", LinkBaseURL: "https://idms:8443"}
	admin.FunctionalAliases = []FunctionalAlias{{ID: "sip:duty-officer.alias@mcx.test",
		Users: []string{"sip:later.mcptt@mcx.test"}, MaxSimultaneousActivations: 1}}
	if err := admin.Validate(); err != nil {
		test.Fatalf("admin mode refused an alias of a user MCX Admin creates later: %v", err)
	}
	admin.FunctionalAliases[0].Users = []string{"later"}
	if err := admin.Validate(); err == nil {
		test.Fatal("admin mode accepted an alias user that is not an MC service ID")
	}
}

// ------------------------------------------------------------------------------
// The user profile document carries the granted MCPTT actions of its ruleset (TS 24.484 clause 8.3.2.1) and none
// other; the group document the user priorities, the preconfigured-use-only flag and the member-list rule
// (TS 24.481 clause 7.2.12.1).
func TestProfileAndGroupDocumentsCarryRulesets(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.Users[0].PrivateCall = &PrivateCallPolicy{Allow: true, AutomaticCommencement: true, Targets: []string{"sip:bob@mcx.test"},
		Emergency: true, EmergencyAny: true, Callback: true, AmbientRemote: true}
	cfg.Users[0].AdhocCall = &AdhocCallPolicy{Allow: true, Modify: true}
	cfg.Users[0].GroupCall = &GroupCallPolicy{RemoteInit: true}
	cfg.Groups[0].UserPriorities = map[string]int{"sip:bob@mcx.test": 7}
	cfg.Groups[0].PreconfiguredUseOnly = true
	// Other members' entries, with their priorities, need the member-list rule (TS 24.481 clause 7.2.12.1).
	cfg.Groups[0].AllowGettingMemberList = true
	token := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	for role, path := range map[Role]string{
		RoleCMS: "/xcap-root/org.3gpp.mcptt.user-profile/users/" + url.PathEscape("sip:alice@mcx.test") + "/mcptt-user-profile-1.xml",
		RoleGMS: "/xcap-root/org.openmobilealliance.groups/global/byGroupID/" + url.PathEscape(cfg.Groups[0].ID),
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		roleHandler(test, role, cfg, key, test.TempDir()).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			test.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		wants := []string{`<allow-private-call xmlns="urn:3gpp:mcptt:user-profile:1.0">true</allow-private-call>`,
			`<allow-automatic-commencement xmlns="urn:3gpp:mcptt:user-profile:1.0">true</allow-automatic-commencement>`,
			`<allow-emergency-private-call xmlns="urn:3gpp:mcptt:user-profile:1.0">true</allow-emergency-private-call>`,
			`<allow-request-private-call-call-back xmlns="urn:3gpp:mcptt:user-profile:1.0">true</allow-request-private-call-call-back>`,
			`<allow-to-modify-adhoc-group-call-participants-info xmlns="urn:3gpp:mcptt:user-profile:1.0">true</allow-to-modify-adhoc-group-call-participants-info>`,
			`<allow-request-remote-initiated-ambient-listening xmlns="urn:3gpp:mcptt:user-profile:1.0">true</allow-request-remote-initiated-ambient-listening>`,
			`<allow-request-remote-init-group-call xmlns="urn:3gpp:mcptt:user-profile:1.0">true</allow-request-remote-init-group-call>`,
			`<PrivateCallList><PrivateCallURI><uri-entry>sip:bob@mcx.test</uri-entry></PrivateCallURI></PrivateCallList>`,
			`<emergency-private-call-recipients entry-info="LocallyDetermined">`}
		if role == RoleGMS {
			wants = []string{`<user-priority xmlns="urn:3gpp:ns:mcpttGroupInfo:1.0">7</user-priority>`,
				`<preconfigured-group-use-only xmlns="urn:3gpp:ns:mcpttGroupInfo:1.0">true</preconfigured-group-use-only>`,
				`<on-network-allow-getting-member-list xmlns="urn:3gpp:ns:mcpttGroupInfo:1.0">true</on-network-allow-getting-member-list>`}
		}
		for _, want := range wants {
			if !strings.Contains(body, want) {
				test.Fatalf("%s lacks %s: %s", path, want, body)
			}
		}
		if role == RoleCMS && (strings.Contains(body, "allow-manual-commencement") ||
			strings.Contains(body, "allow-request-locally-initiated-ambient-listening")) {
			test.Fatalf("ungranted action served: %s", body)
		}
	}
}

// ------------------------------------------------------------------------------
// The GMS serves a chat group's type (none for a prearranged group), and the configuration refuses an unknown type.
func TestGMSServesChatGroupTypeAndRejectsUnknownTypes(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.Groups = append(cfg.Groups, Group{ID: "sip:chat@mcx.test", Type: "chat", Members: []string{"sip:alice@mcx.test", "sip:bob@mcx.test"}})
	handler := roleHandler(test, RoleGMS, cfg, key, test.TempDir())
	for id, want := range map[string]string{"sip:chat@mcx.test": "chat", "sip:team@mcx.test": ""} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/internal/group?id="+url.QueryEscape(id), nil)
		req.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
		handler.ServeHTTP(rr, req)
		var served Group
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &served) != nil || served.Type != want {
			test.Fatalf("group %q: status=%d body=%s", id, rr.Code, rr.Body.String())
		}
	}
	bad := testConfig()
	bad.Groups[0].Type = "broadcast-hierarchy"
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported type") {
		test.Fatalf("unknown group type accepted: %v", err)
	}
}

// ------------------------------------------------------------------------------
// The CMS serves the ad hoc group call right to the user it is granted to only.
func TestCMSServesAdhocCallPolicy(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.Users[0].AdhocCall = &AdhocCallPolicy{Allow: true}
	handler := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	for id, want := range map[string]bool{"sip:alice@mcx.test": true, "sip:bob@mcx.test": false} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/internal/user?mcptt_id="+url.QueryEscape(id), nil)
		req.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
		handler.ServeHTTP(rr, req)
		var served publicUser
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &served) != nil {
			test.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		if got := served.AdhocCall != nil && served.AdhocCall.Allow; got != want {
			test.Fatalf("%s adhoc allow=%v want %v: %s", id, got, want, rr.Body.String())
		}
	}
}

// ------------------------------------------------------------------------------
// The CMS serves a user by MCData ID with the MCData policy, the profile grants the MCData actions
// (TS 24.484 clause 10.3.2.3), the configuration refuses unknown targets, a ruleset without an MCData ID, an unknown
// implicit affiliation group, an MCPTT ID as MCData ID, and the access token carries the MCData ID.
func TestCMSServesMCDataPolicyByMCDataID(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.Users[0].MCDataID = "sip:alice.data@mcx.test"
	cfg.Users[1].MCDataID = "sip:bob.data@mcx.test"
	cfg.Users[0].MCData = &MCDataPolicy{TransmitData: true, Targets: []string{"sip:bob.data@mcx.test"}, MaxData1To1: 100, Adhoc: true}
	if err := cfg.Validate(); err != nil {
		test.Fatal(err)
	}
	handler := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/internal/user?mcdata_id="+url.QueryEscape("sip:alice.data@mcx.test"), nil)
	req.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
	handler.ServeHTTP(rr, req)
	var served publicUser
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &served) != nil {
		test.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if served.MCPTTID != "sip:alice@mcx.test" || served.MCData == nil || !served.MCData.TransmitData ||
		served.MCData.MaxData1To1 != 100 || len(served.MCData.Targets) != 1 {
		test.Fatalf("unexpected MCData user: %s", rr.Body.String())
	}
	if actions := fmt.Sprint(profileRights(cfg.Users[0])); !strings.Contains(actions, "allow-transmit-data") ||
		!strings.Contains(actions, "allow-adhoc-group-data-comn}") || strings.Contains(actions, "allow-adhoc-group-data-comn-participation") {
		test.Fatalf("allow-transmit-data not granted: %v", actions)
	}
	bad := testConfig()
	bad.Users[0].MCDataID = "sip:alice.data@mcx.test"
	bad.Users[0].MCData = &MCDataPolicy{TransmitData: true, Targets: []string{"sip:nobody@mcx.test"}}
	if bad.Validate() == nil {
		test.Fatal("unknown MCData target accepted")
	}
	bad = testConfig()
	bad.Users[0].MCData = &MCDataPolicy{TransmitData: true}
	if bad.Validate() == nil {
		test.Fatal("MCData ruleset without mcdata_id accepted")
	}
	bad = testConfig()
	bad.Users[0].MCDataID = "sip:alice.data@mcx.test"
	bad.Users[0].MCData = &MCDataPolicy{ImplicitAffiliations: []string{"sip:nowhere@mcx.test"}}
	if bad.Validate() == nil {
		test.Fatal("unknown implicit affiliation group accepted")
	}
	implicit := testConfig()
	implicit.Users[0].MCDataID = "sip:alice.data@mcx.test"
	implicit.Users[0].MCData = &MCDataPolicy{ImplicitAffiliations: []string{implicit.Groups[0].ID}}
	if err := implicit.Validate(); err != nil {
		test.Fatal(err)
	}
	withAlias := cfg
	withAlias.FunctionalAliases = []FunctionalAlias{{ID: "sip:desk@mcx.test", MCDataUsers: []string{"sip:bob.data@mcx.test"}, MaxSimultaneousActivations: 1}}
	if err := withAlias.Validate(); err != nil {
		test.Fatal(err)
	}
	withAlias.FunctionalAliases[0].MCDataUsers = []string{"sip:bob@mcx.test"}
	if withAlias.Validate() == nil {
		test.Fatal("functional alias MCData user that is an MCPTT ID accepted")
	}
	bad = testConfig()
	bad.Users[0].MCDataID = bad.Users[1].MCPTTID
	if bad.Validate() == nil {
		test.Fatal("mcdata_id reusing an MCPTT ID accepted")
	}
	claims, err := newClaims(cfg, cfg.Users[0], cfg.ServerClientID, "access", "", testNow)
	if err != nil || claims.MCDataID != "sip:alice.data@mcx.test" {
		test.Fatalf("token lacks mcdata_id: %+v %v", claims, err)
	}
}

// ------------------------------------------------------------------------------
// TS 24.281 clause 4.2 with TS 23.280 clause 8.1.2: an MCVideo ID is a distinct identity the CMS serves the user
// by and the IdMS carries in its tokens; the configuration refuses an MCVideo profile without an MCVideo ID, an
// MCVideo ID that reuses an MCPTT ID, is a duplicate or is not a SIP URI, and functional aliases that confuse them.
func TestMCVideoIDLookupAndClaim(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.Users[0].MCVideoID = "sip:alice.mcvideo@mcx.test"
	if err := cfg.Validate(); err != nil {
		test.Fatal(err)
	}
	handler := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/internal/user?mcvideo_id="+url.QueryEscape("sip:alice.mcvideo@mcx.test"), nil)
	req.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
	handler.ServeHTTP(rr, req)
	var served publicUser
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &served) != nil {
		test.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if served.MCPTTID != "sip:alice@mcx.test" || served.MCVideoID != "sip:alice.mcvideo@mcx.test" {
		test.Fatalf("unexpected MCVideo user: %s", rr.Body.String())
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/internal/user?mcvideo_id="+url.QueryEscape("sip:nobody.mcvideo@mcx.test"), nil)
	req.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		test.Fatalf("unknown MCVideo ID served: %d", rr.Code)
	}
	cfg.Users[0].MCVideo = map[string]any{"private_call": map[string]any{"allow": true}}
	handler = roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/internal/user?mcvideo_id="+url.QueryEscape("sip:alice.mcvideo@mcx.test"), nil)
	req.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &served) != nil ||
		served.MCVideo["private_call"] == nil {
		test.Fatalf("MCVideo profile not served: %s", rr.Body.String())
	}
	orphan := testConfig()
	orphan.Users[1].MCVideo = map[string]any{"private_call": map[string]any{"allow": true}}
	if orphan.Validate() == nil {
		test.Fatal("an MCVideo profile without an MCVideo ID was accepted")
	}
	claims, err := newClaims(cfg, cfg.Users[0], cfg.ServerClientID, "access", "", time.Now())
	if err != nil || claims.MCVideoID != "sip:alice.mcvideo@mcx.test" {
		test.Fatalf("MCVideo ID missing from token claims: %+v %v", claims, err)
	}
	// TS 24.484 clause 9.4.2: <mcvideo-user-list> names MCVideo IDs, and an alias is none of them.
	withAlias := cfg
	withAlias.FunctionalAliases = []FunctionalAlias{{ID: "sip:desk@mcx.test", MCVideoUsers: []string{"sip:alice.mcvideo@mcx.test"}, MaxSimultaneousActivations: 1}}
	if err := withAlias.Validate(); err != nil {
		test.Fatal(err)
	}
	withAlias.FunctionalAliases[0].MCVideoUsers = []string{"sip:alice@mcx.test"}
	if withAlias.Validate() == nil {
		test.Fatal("functional alias MCVideo user that is an MCPTT ID accepted")
	}
	withAlias.FunctionalAliases[0] = FunctionalAlias{ID: "sip:alice.mcvideo@mcx.test", MaxSimultaneousActivations: 1}
	if withAlias.Validate() == nil {
		test.Fatal("functional alias equal to an MCVideo ID accepted")
	}
	for name, ids := range map[string][2]string{
		"reuses an MCPTT ID": {"sip:alice.mcvideo@mcx.test", "sip:alice@mcx.test"},
		"is a duplicate":     {"sip:same.mcvideo@mcx.test", "sip:same.mcvideo@mcx.test"},
		"is not a SIP URI":   {"sip:alice.mcvideo@mcx.test", "bob.mcvideo@mcx.test"},
	} {
		bad := testConfig()
		bad.Users[0].MCVideoID, bad.Users[1].MCVideoID = ids[0], ids[1]
		if bad.Validate() == nil {
			test.Fatalf("an mcvideo_id that %s was accepted", name)
		}
	}
}

// ------------------------------------------------------------------------------
// An MCVideo group lists its members by MCVideo ID, and the GMS serves them to the MCVideo server under "mcvideo"
// (TS 24.281 clause 8.2.2); the configuration refuses an unknown MCVideo member.
func TestGMSServesMCVideoMembers(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.Users[0].MCVideoID = "sip:alice.mcvideo@mcx.test"
	cfg.Groups[0].MCVideo = &GroupMCVideo{Members: []string{"sip:alice.mcvideo@mcx.test"},
		PriorityPolicy: map[string]interface{}{"emergency_users": []interface{}{"sip:alice.mcvideo@mcx.test"}}}
	if err := cfg.Validate(); err != nil {
		test.Fatal(err)
	}
	handler := roleHandler(test, RoleGMS, cfg, key, test.TempDir())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/internal/group?id="+url.QueryEscape(cfg.Groups[0].ID), nil)
	req.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
	handler.ServeHTTP(rr, req)
	var served struct {
		MCVideo *GroupMCVideo `json:"mcvideo"`
	}
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &served) != nil || served.MCVideo == nil ||
		len(served.MCVideo.Members) != 1 || served.MCVideo.Members[0] != "sip:alice.mcvideo@mcx.test" ||
		served.MCVideo.PriorityPolicy["emergency_users"] == nil {
		test.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	bad := testConfig()
	bad.Groups[0].MCVideo = &GroupMCVideo{Members: []string{"sip:nobody.mcvideo@mcx.test"}}
	if bad.Validate() == nil {
		test.Fatal("unknown MCVideo member accepted")
	}
}
