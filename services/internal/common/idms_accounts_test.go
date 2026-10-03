package common

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ------------------------------------------------------------------------------
// Helper: fakeAdmin is MCX Admin's account endpoint: accounts by login, checked for the server client credentials.
type fakeAdmin struct {
	mu       sync.Mutex
	accounts map[string]account
}

// ------------------------------------------------------------------------------
// Helper: answers an account lookup by login or MCPTT ID, with the server client credentials only.
func (admin *fakeAdmin) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if user, pw, ok := request.BasicAuth(); !ok || user != "mcx-server" || pw != "server-secret" || request.URL.Path != "/internal/v1/accounts" {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	admin.mu.Lock()
	defer admin.mu.Unlock()
	for _, record := range admin.accounts {
		if record.Login == request.URL.Query().Get("login") || record.MCPTTID == request.URL.Query().Get("mcptt_id") {
			_ = json.NewEncoder(writer).Encode(record)
			return
		}
	}
	writer.WriteHeader(http.StatusNotFound)
}

// ------------------------------------------------------------------------------
// Helper: sets the status of an account (active, suspended), as MCX Admin does.
func (admin *fakeAdmin) setStatus(login, status string) {
	admin.mu.Lock()
	defer admin.mu.Unlock()
	record := admin.accounts[login]
	record.Status = status
	admin.accounts[login] = record
}

// ------------------------------------------------------------------------------
// Helper: an IdMS in admin mode, reading its accounts (carol only) from a fake MCX Admin; returns the IdMS, the fake
// MCX Admin and the IdMS's directory.
func adminModeHandler(test *testing.T) (http.Handler, *fakeAdmin, string) {
	test.Helper()
	admin := &fakeAdmin{accounts: map[string]account{"carol": {Login: "carol", Status: "active", MCID: "sip:carol.mc@mcx.test",
		MCPTTID: "sip:carol.mcptt@mcx.test", SIPURI: "sip:carol@mcx.test", ClientIDs: []string{"carol-device"}}}}
	srv := httptest.NewTLSServer(admin)
	test.Cleanup(srv.Close)
	cfg := testConfig()
	cfg.AdminAccounts = &AdminAccountsConfig{URL: srv.URL, LinkBaseURL: "https://idms.mcx.test"}
	dir := test.TempDir()
	handler, err := NewHandler(RoleIDMS, cfg, testKey(test), dir, WithClock(func() time.Time { return testNow }), WithServiceClient(srv.Client()))
	if err != nil {
		test.Fatal(err)
	}
	return handler, admin, dir
}

// ------------------------------------------------------------------------------
// Helper: asks the IdMS, with the given client credentials, for a link on which an account sets its password;
// returns the status and the link.
func issueLink(test *testing.T, handler http.Handler, login, user, pw string) (int, string) {
	test.Helper()
	req := httptest.NewRequest(http.MethodPost, "/internal/password-links", strings.NewReader(`{"login":"`+login+`","purpose":"set"}`))
	req.SetBasicAuth(user, pw)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	var body struct {
		URL string `json:"url"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, body.URL
}

// ------------------------------------------------------------------------------
// Helper: sets a password on a link's token; returns the status.
func setPassword(handler http.Handler, token, password, confirm string) int {
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, formRequest(http.MethodPost, "/set-password", url.Values{"token": {token}, "password": {password}, "confirm": {confirm}}))
	return rr.Code
}

// ------------------------------------------------------------------------------
// Helper: signs in with a username and password at the start of an authorization code grant; returns the status.
func loginAs(handler http.Handler, test *testing.T, username, password string) int {
	requestID, _, _ := beginAuthorization(test, handler, "state-1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, formRequest(http.MethodPost, "/login", url.Values{"request_id": {requestID}, "username": {username}, "password": {password}}))
	return rr.Code
}

// ------------------------------------------------------------------------------
// The password verifiers: salted PBKDF2-HMAC-SHA256 (RFC 8018) with a random salt, checked; the plain site.json
// passwords of file mode still sign in.
func TestVerifier(test *testing.T) {
	stored, err := newVerifier("a long passphrase")
	if err != nil || !strings.HasPrefix(stored, "$pbkdf2-sha256$600000$") {
		test.Fatalf("verifier %q %v", stored, err)
	}
	if !checkPassword(stored, "a long passphrase") || checkPassword(stored, "a long passphrasE") || checkPassword("", "") {
		test.Fatal("verifier check")
	}
	other, _ := newVerifier("a long passphrase")
	if other == stored {
		test.Fatal("the salt is not random")
	}
	// File mode: the lab's plain site.json passwords still sign in.
	if !checkPassword("alice-password", "alice-password") || checkPassword("alice-password", "x") {
		test.Fatal("plain password")
	}
}

// ------------------------------------------------------------------------------
// MCX Admin accounts (slice B2; openMCX's own MCX Admin integration, not a 3GPP procedure): a link from MCX Admin,
// stored only as a hash, the password set on it once, sign-in, and suspension refusing sign-in and making existing
// tokens inactive at introspection (RFC 7662 section 2).
func TestAdminAccounts(test *testing.T) {
	handler, admin, dir := adminModeHandler(test)
	if code, _ := issueLink(test, handler, "carol", "mcx-server", "wrong"); code != http.StatusUnauthorized {
		test.Fatalf("link without the server credentials: %d", code)
	}
	if code, _ := issueLink(test, handler, "nobody", "mcx-server", "server-secret"); code != http.StatusNotFound {
		test.Fatalf("link for an unknown account: %d", code)
	}
	code, link := issueLink(test, handler, "carol", "mcx-server", "server-secret")
	if code != http.StatusOK || !strings.HasPrefix(link, "https://idms.mcx.test/set-password?token=") {
		test.Fatalf("link %d %q", code, link)
	}
	token := strings.TrimPrefix(link, "https://idms.mcx.test/set-password?token=")
	token, _ = url.QueryUnescape(token)
	// The link is stored only as a hash.
	raw, _ := os.ReadFile(filepath.Join(dir, "idms-credentials.json"))
	if strings.Contains(string(raw), token) {
		test.Fatal("the link token is stored in clear")
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/set-password?token="+url.QueryEscape(token), nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "carol") || rr.Header().Get("Cache-Control") != "no-store" {
		test.Fatalf("form %d", rr.Code)
	}
	if code := setPassword(handler, token, "short", "short"); code != http.StatusBadRequest {
		test.Fatalf("a short password: %d", code)
	}
	if code := setPassword(handler, token, "carol-long-passphrase", "different-passphrase"); code != http.StatusBadRequest {
		test.Fatalf("different passwords: %d", code)
	}
	if code := setPassword(handler, token, "carol-long-passphrase", "carol-long-passphrase"); code != http.StatusOK {
		test.Fatalf("set: %d", code)
	}
	if code := setPassword(handler, token, "another-long-passphrase", "another-long-passphrase"); code != http.StatusNotFound {
		test.Fatalf("a used link: %d", code)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, "idms-credentials.json"))
	if strings.Contains(string(raw), "carol-long-passphrase") {
		test.Fatal("the password is stored in clear")
	}
	if info, _ := os.Stat(filepath.Join(dir, "idms-credentials.json")); info.Mode().Perm() != 0o600 {
		test.Fatalf("credential file mode %v", info.Mode().Perm())
	}
	// Sign-in: the account's own password; the site.json users are not accounts here.
	if code := loginAs(handler, test, "carol", "wrong-passphrase"); code != http.StatusUnauthorized {
		test.Fatalf("wrong password: %d", code)
	}
	if code := loginAs(handler, test, "alice", "alice-password"); code != http.StatusUnauthorized {
		test.Fatalf("a site.json user in admin mode: %d", code)
	}
	requestID, verifier, redirect := beginAuthorization(test, handler, "state-2")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, formRequest(http.MethodPost, "/login", url.Values{"request_id": {requestID}, "username": {"carol"}, "password": {"carol-long-passphrase"}}))
	if rr.Code != http.StatusFound {
		test.Fatalf("carol's sign-in: %d", rr.Code)
	}
	location, _ := url.Parse(rr.Header().Get("Location"))
	status, body := redeem(test, handler, location.Query().Get("code"), verifier, redirect)
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &tokens) != nil {
		test.Fatalf("token %d %s", status, body)
	}
	introspect := func() bool {
		rr := httptest.NewRecorder()
		req := formRequest(http.MethodPost, "/introspect", url.Values{"token": {tokens.AccessToken}})
		req.SetBasicAuth("mcx-server", "server-secret")
		handler.ServeHTTP(rr, req)
		var out struct {
			Active  bool   `json:"active"`
			MCPTTID string `json:"mcptt_id"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return out.Active && out.MCPTTID == "sip:carol.mcptt@mcx.test"
	}
	if !introspect() {
		test.Fatal("carol's token is not active")
	}
	// Suspension in MCX Admin: the token stops being active at once, and sign-in is refused.
	admin.setStatus("carol", "suspended")
	if introspect() {
		test.Fatal("a suspended account's token is still active")
	}
	if code := loginAs(handler, test, "carol", "carol-long-passphrase"); code != http.StatusUnauthorized {
		test.Fatalf("a suspended account signs in: %d", code)
	}
	admin.setStatus("carol", "active")
	if !introspect() {
		test.Fatal("a restored account's token is not active")
	}
}

// ------------------------------------------------------------------------------
// Repeated failures lock the login for a while, even with the right password.
func TestSignInLock(test *testing.T) {
	handler, _, dir := adminModeHandler(test)
	_, link := issueLink(test, handler, "carol", "mcx-server", "server-secret")
	token, _ := url.QueryUnescape(strings.TrimPrefix(link, "https://idms.mcx.test/set-password?token="))
	setPassword(handler, token, "carol-long-passphrase", "carol-long-passphrase")
	for attempt := 0; attempt < maxFailures; attempt++ {
		loginAs(handler, test, "carol", "wrong")
	}
	if code := loginAs(handler, test, "carol", "carol-long-passphrase"); code != http.StatusUnauthorized {
		test.Fatalf("a locked login signs in: %d", code)
	}
	// A new password that cannot be stored does not lift the lock.
	_, link = issueLink(test, handler, "carol", "mcx-server", "server-secret")
	token, _ = url.QueryUnescape(strings.TrimPrefix(link, "https://idms.mcx.test/set-password?token="))
	unblock := blockWrites(test, dir)
	code := setPassword(handler, token, "carol-new-passphrase", "carol-new-passphrase")
	unblock()
	if code != http.StatusInternalServerError {
		test.Fatalf("a password that could not be stored: %d", code)
	}
	if code := loginAs(handler, test, "carol", "carol-long-passphrase"); code != http.StatusUnauthorized {
		test.Fatalf("a failed password change lifted the lock: %d", code)
	}
}
