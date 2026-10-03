package common

import (
	"encoding/json"
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
// Helper: the token response of the IdMS (TS 33.180 annex B.5.3), with the error of a refused request.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
}

// ------------------------------------------------------------------------------
// Helper: signIn runs the authorization code grant for a user and returns the token response.
func signIn(test *testing.T, handler http.Handler, user, password string) tokenResponse {
	test.Helper()
	requestID, verifier, redirectURI := beginAuthorization(test, handler, "s")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, formRequest(http.MethodPost, "/login", url.Values{"request_id": {requestID}, "username": {user}, "password": {password}}))
	if rr.Code != http.StatusFound {
		test.Fatalf("login %s: %d", user, rr.Code)
	}
	location, _ := url.Parse(rr.Header().Get("Location"))
	status, raw := redeem(test, handler, location.Query().Get("code"), verifier, redirectURI)
	var out tokenResponse
	_ = json.Unmarshal(raw, &out)
	if status != http.StatusOK || out.RefreshToken == "" {
		test.Fatalf("token: %d %s", status, raw)
	}
	return out
}

// ------------------------------------------------------------------------------
// Helper: a refresh token grant (TS 33.180 annex B.5.2, RFC 6749 section 6) for the client mcx-client, with extra
// form parameters; returns the status and the token response.
func refreshWith(handler http.Handler, token string, extra url.Values) (int, tokenResponse) {
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"mcx-client"}, "refresh_token": {token}}
	for name, values := range extra {
		form[name] = values
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, formRequest(http.MethodPost, "/token", form))
	var out tokenResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

// ------------------------------------------------------------------------------
// TS 33.180 annex B.5 (RFC 6749 section 6): a refresh gives new access, ID and refresh tokens; the ID token names
// the same user and repeats the nonce (OpenID Connect Core 1.0 section 12.2, see refreshGrant); a wider scope, another client or no
// token are refused; rotation retires the used token and its replay revokes the chain (RFC 9700 section 4.14.2).
func TestRefreshTokenGrant(test *testing.T) {
	key := testKey(test)
	handler := newTestHandler(test, RoleIDMS, testConfig(), key)
	first := signIn(test, handler, "alice", "alice-password")

	status, second := refreshWith(handler, first.RefreshToken, nil)
	if status != http.StatusOK || second.AccessToken == "" || second.RefreshToken == "" || second.RefreshToken == first.RefreshToken {
		test.Fatalf("refresh: %d %+v", status, second)
	}
	access, err := VerifyToken(second.AccessToken, &key.PublicKey, "https://idms.mcx.test", "mcx-server", testNow)
	if err != nil || access.MCPTTID != "sip:alice@mcx.test" || access.Type != "access" || access.Scope != "openid" {
		test.Fatalf("refreshed access token: %+v %v", access, err)
	}
	// OpenID Connect Core 1.0 section 12.2: the refreshed ID token names the same user and keeps the acr; it repeats
	// the nonce (a SHOULD NOT there, kept for the openMCX clients, see refreshGrant).
	id, err := VerifyToken(second.IDToken, &key.PublicKey, "https://idms.mcx.test", "mcx-client", testNow)
	if err != nil || id.MCPTTID != "sip:alice@mcx.test" || id.Nonce != "nonce-1" || id.ClientID != "alice-device" ||
		id.ACR != acrPassword {
		test.Fatalf("refreshed ID token: %+v %v", id, err)
	}

	// A wider scope, another client or nothing at all are refused.
	if status, out := refreshWith(handler, second.RefreshToken, url.Values{"scope": {"openid 3gpp:mc:ptt_service"}}); status != http.StatusBadRequest || out.Error != "invalid_grant" {
		test.Fatalf("wider scope: %d %+v", status, out)
	}
	if status, _ := refreshWith(handler, "", nil); status != http.StatusBadRequest {
		test.Fatalf("no token: %d", status)
	}
	// The scope check used (retired) second's token: the chain continues from a fresh sign-in.
	third := signIn(test, handler, "alice", "alice-password")
	if status, _ := refreshWith(handler, third.RefreshToken, url.Values{"client_id": {"other"}}); status != http.StatusBadRequest {
		test.Fatalf("other client: %d", status)
	}

	// RFC 9700 section 4.14.2: rotation: the used token is retired; presenting it again revokes the whole chain.
	fourth := signIn(test, handler, "alice", "alice-password")
	status, fifth := refreshWith(handler, fourth.RefreshToken, nil)
	if status != http.StatusOK {
		test.Fatalf("refresh: %d", status)
	}
	if status, _ := refreshWith(handler, fourth.RefreshToken, nil); status != http.StatusBadRequest {
		test.Fatalf("replayed token: %d", status)
	}
	if status, _ := refreshWith(handler, fifth.RefreshToken, nil); status != http.StatusBadRequest {
		test.Fatalf("the chain's current token after a replay: %d", status)
	}
}

// ------------------------------------------------------------------------------
// A refresh token lapses when unused for longer than its configured lifetime; each use starts the lifetime again.
func TestRefreshTokenLapses(test *testing.T) {
	now := testNow
	cfg := testConfig()
	cfg.RefreshTokenTTLSeconds = 3600
	handler, err := NewHandler(RoleIDMS, cfg, testKey(test), test.TempDir(), WithClock(func() time.Time { return now }))
	if err != nil {
		test.Fatal(err)
	}
	tokens := signIn(test, handler, "alice", "alice-password")
	now = now.Add(59 * time.Minute)
	status, next := refreshWith(handler, tokens.RefreshToken, nil)
	if status != http.StatusOK {
		test.Fatalf("within the lifetime: %d", status)
	}
	// Each use starts the lifetime again; unused for longer, the token lapses.
	now = now.Add(61 * time.Minute)
	if status, _ := refreshWith(handler, next.RefreshToken, nil); status != http.StatusBadRequest {
		test.Fatalf("lapsed: %d", status)
	}
}

// ------------------------------------------------------------------------------
// The refresh token store, saved, is read back after a restart.
func TestRefreshTokensSurviveRestart(test *testing.T) {
	dir := test.TempDir()
	store, err := newRefreshStore(dir)
	if err != nil {
		test.Fatal(err)
	}
	token, err := store.issue(refreshRecord{Login: "alice", ClientID: "mcx-client"}, testNow, time.Hour)
	if err != nil {
		test.Fatal(err)
	}
	if err := store.save(); err != nil {
		test.Fatal(err)
	}
	again, err := newRefreshStore(dir)
	if err != nil {
		test.Fatal(err)
	}
	if record, err := again.use(token, testNow); err != nil || record.Login != "alice" {
		test.Fatalf("after a restart: %+v %v", record, err)
	}
}

// ------------------------------------------------------------------------------
// A failed save is reported, and the store stays changed so that the next save writes it.
func TestRefreshTokensFailedSaveIsRetried(test *testing.T) {
	dir := test.TempDir()
	store, err := newRefreshStore(dir)
	if err != nil {
		test.Fatal(err)
	}
	if _, err := store.issue(refreshRecord{Login: "alice", ClientID: "mcx-client"}, testNow, time.Hour); err != nil {
		test.Fatal(err)
	}
	store.path = filepath.Join(dir, "missing", "idms-refresh-tokens.json")
	if err := store.save(); err == nil {
		test.Fatal("a save into a missing directory succeeded")
	}
	store.path = filepath.Join(dir, "idms-refresh-tokens.json")
	if err := store.save(); err != nil {
		test.Fatal(err)
	}
	if again, err := newRefreshStore(dir); err != nil || len(again.records) != 1 {
		test.Fatalf("retried save holds %d records", len(again.records))
	}
}

// ------------------------------------------------------------------------------
// In admin mode (openMCX's own MCX Admin integration, not a 3GPP procedure) a refresh is refused for a suspended
// account, after Revoke devices from MCX Admin with the server client credentials, and after a new password.
func TestRefreshTokensInAdminMode(test *testing.T) {
	handler, admin, _ := adminModeHandler(test)
	password := "carol-password-12"
	setCarol := func() {
		_, link := issueLink(test, handler, "carol", "mcx-server", "server-secret")
		linkURL, _ := url.Parse(link)
		if status := setPassword(handler, linkURL.Query().Get("token"), password, password); status != http.StatusOK {
			test.Fatalf("set password: %d", status)
		}
	}
	setCarol()

	// Suspension: the refresh is refused, and restoring the account does not revive it.
	tokens := signIn(test, handler, "carol", password)
	if status, _ := refreshWith(handler, tokens.RefreshToken, nil); status != http.StatusOK {
		test.Fatalf("active: %d", status)
	}
	tokens = signIn(test, handler, "carol", password)
	admin.setStatus("carol", "suspended")
	if status, _ := refreshWith(handler, tokens.RefreshToken, nil); status != http.StatusBadRequest {
		test.Fatalf("suspended: %d", status)
	}
	admin.setStatus("carol", "active")

	// Revoke devices, from MCX Admin with the server client credentials.
	tokens = signIn(test, handler, "carol", password)
	revoke := func(user, pw string) int {
		req := httptest.NewRequest(http.MethodPost, "/internal/refresh-tokens/carol/revoke", strings.NewReader(""))
		req.SetBasicAuth(user, pw)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}
	if status := revoke("mcx-server", "wrong"); status != http.StatusUnauthorized {
		test.Fatalf("revoke without the credentials: %d", status)
	}
	if status := revoke("mcx-server", "server-secret"); status != http.StatusOK {
		test.Fatalf("revoke: %d", status)
	}
	if status, _ := refreshWith(handler, tokens.RefreshToken, nil); status != http.StatusBadRequest {
		test.Fatalf("after Revoke devices: %d", status)
	}

	// A new password ends the sessions of the old one.
	tokens = signIn(test, handler, "carol", password)
	password = "carol-password-34"
	setCarol()
	if status, _ := refreshWith(handler, tokens.RefreshToken, nil); status != http.StatusBadRequest {
		test.Fatalf("after a new password: %d", status)
	}
}

// ------------------------------------------------------------------------------
// A refresh token file that cannot be read back is reported, and the store starts empty (the devices sign in again).
func TestRefreshTokensDamagedFileReported(test *testing.T) {
	dir := test.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "idms-refresh-tokens.json"), []byte("{damaged"), 0o600); err != nil {
		test.Fatal(err)
	}
	store, err := newRefreshStore(dir)
	if err == nil || store == nil || len(store.records) != 0 {
		test.Fatalf("a damaged file: %v, %+v", err, store)
	}
}
