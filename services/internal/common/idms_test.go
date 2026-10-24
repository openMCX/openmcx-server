//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The fixed time of the tests.
var testNow = time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

// ------------------------------------------------------------------------------
// Helper: the configuration of the tests: domain mcx.test, the IdMS's clients, alice and bob in sip:team@mcx.test.
func testConfig() Config {
	return Config{
		Domain:            "mcx.test",
		ServiceURI:        "https://mcx.test",
		Issuer:            "https://idms.mcx.test",
		OAuthClientID:     "mcx-client",
		OAuthRedirectURIs: []string{"http://127.0.0.1:19000/callback"},
		ServerClientID:    "mcx-server",
		ServerSecret:      "server-secret",
		TokenTTLSeconds:   300,
		Users: []User{{
			Username: "alice", Password: "alice-password", MCID: "alice-mc",
			MCPTTID: "sip:alice@mcx.test", SIPURI: "sip:alice@ims.mcx.test",
			SIPPassword: "sip-secret", ClientID: "alice-device", Groups: []string{"sip:team@mcx.test"},
		}, {
			Username: "bob", Password: "bob-password", MCID: "bob-mc",
			MCPTTID: "sip:bob@mcx.test", SIPURI: "sip:bob@ims.mcx.test",
			SIPPassword: "sip-secret-2", ClientID: "bob-device", Groups: []string{"sip:team@mcx.test"},
		}},
		Groups: []Group{{ID: "sip:team@mcx.test", Members: []string{"sip:alice@mcx.test", "sip:bob@mcx.test"}}},
	}
}

// ------------------------------------------------------------------------------
// Helper: a fresh 2048-bit RSA token signing key.
func testKey(test *testing.T) *rsa.PrivateKey {
	test.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		test.Fatal(err)
	}
	return key
}

// ------------------------------------------------------------------------------
// Helper: the handler of a service role at the fixed test time.
func newTestHandler(test *testing.T, role Role, cfg Config, key *rsa.PrivateKey) http.Handler {
	test.Helper()
	handler, err := NewHandler(role, cfg, key, test.TempDir(), WithClock(func() time.Time { return testNow }))
	if err != nil {
		test.Fatal(err)
	}
	return handler
}

// ------------------------------------------------------------------------------
// Helper: a request with an application/x-www-form-urlencoded body.
func formRequest(method, target string, form url.Values) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

// ------------------------------------------------------------------------------
// Helper: an OIDC Authentication Request (TS 33.180 annex B.4.2.2) with an S256 PKCE challenge (RFC 7636
// section 4.2); returns the request ID of the sign-in, the code verifier and the redirect URI.
func beginAuthorization(test *testing.T, handler http.Handler, state string) (requestID, verifier, redirectURI string) {
	test.Helper()
	verifier = "correct-horse-battery-staple-verifier-1234567890"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	redirectURI = "http://127.0.0.1:19000/callback"
	query := url.Values{
		"response_type": {"code"}, "client_id": {"mcx-client"}, "redirect_uri": {redirectURI},
		"scope": {"openid"}, "state": {state}, "nonce": {"nonce-1"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil))
	if rr.Code != http.StatusOK {
		test.Fatalf("authorize status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		test.Fatal(err)
	}
	if body.RequestID == "" {
		test.Fatal("missing request_id")
	}
	return body.RequestID, verifier, redirectURI
}

// ------------------------------------------------------------------------------
// Helper: alice signs in (TS 33.180 annex B.4.2.3); returns the authorization code, checking the state comes back.
func login(test *testing.T, handler http.Handler, requestID, state string) string {
	test.Helper()
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, formRequest(http.MethodPost, "/login", url.Values{
		"request_id": {requestID}, "username": {"alice"}, "password": {"alice-password"},
	}))
	if rr.Code != http.StatusFound {
		test.Fatalf("login status=%d body=%s", rr.Code, rr.Body.String())
	}
	location, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		test.Fatal(err)
	}
	if got := location.Query().Get("state"); got != state {
		test.Fatalf("state=%q want=%q", got, state)
	}
	code := location.Query().Get("code")
	if code == "" {
		test.Fatal("missing code")
	}
	return code
}

// ------------------------------------------------------------------------------
// Helper: an access token request with the authorization code (TS 33.180 annex B.4.2.4); returns the status and body.
func redeem(test *testing.T, handler http.Handler, code, verifier, redirectURI string) (int, []byte) {
	test.Helper()
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, formRequest(http.MethodPost, "/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"mcx-client"}, "redirect_uri": {redirectURI},
		"code": {code}, "code_verifier": {verifier},
	}))
	return rr.Code, rr.Body.Bytes()
}

// ------------------------------------------------------------------------------
// TS 24.482 clause 6.3.1 with TS 33.180 annex B.4.2: the authorization code grant with PKCE gives a Bearer access
// token bound to the user's identities and an ID token repeating the nonce (TS 33.180 annex B.4.2.5), and the
// state comes back unchanged.
func TestAuthorizationCodePKCEIssuesBoundTokensAndPreservesState(test *testing.T) {
	key := testKey(test)
	handler := newTestHandler(test, RoleIDMS, testConfig(), key)
	requestID, verifier, redirectURI := beginAuthorization(test, handler, "opaque-state")
	code := login(test, handler, requestID, "opaque-state")
	status, raw := redeem(test, handler, code, verifier, redirectURI)
	if status != http.StatusOK {
		test.Fatalf("token status=%d body=%s", status, raw)
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &tokens); err != nil {
		test.Fatal(err)
	}
	if tokens.TokenType != "Bearer" || tokens.ExpiresIn != 300 || tokens.AccessToken == "" || tokens.IDToken == "" {
		test.Fatalf("unexpected token response: %+v", tokens)
	}
	access, err := VerifyToken(tokens.AccessToken, &key.PublicKey, testConfig().Issuer, "mcx-server", testNow)
	if err != nil {
		test.Fatal(err)
	}
	if access.MCPTTID != "sip:alice@mcx.test" || access.SIPURI != "sip:alice@ims.mcx.test" || access.ClientID != "mcx-client" ||
		access.MCClientID != "alice-device" || access.MCID != "alice-mc" {
		test.Fatalf("identity binding missing: %+v", access)
	}
	id, err := VerifyToken(tokens.IDToken, &key.PublicKey, testConfig().Issuer, "mcx-client", testNow)
	if err != nil {
		test.Fatal(err)
	}
	if id.Nonce != "nonce-1" {
		test.Fatalf("nonce=%q", id.Nonce)
	}
}

// ------------------------------------------------------------------------------
// TS 33.180 annex B.4.2.2: an Authentication Request with a redirect URI that is not the loopback one, without a
// PKCE challenge, or with a malformed challenge (RFC 7636 section 4.2) is refused.
func TestAuthorizationRejectsNonLoopbackRedirectAndMissingPKCE(test *testing.T) {
	handler := newTestHandler(test, RoleIDMS, testConfig(), testKey(test))
	for name, query := range map[string]url.Values{
		"non-loopback":        {"response_type": {"code"}, "client_id": {"mcx-client"}, "redirect_uri": {"https://evil.example/cb"}, "scope": {"openid"}, "state": {"s"}, "nonce": {"n"}, "code_challenge": {"x"}, "code_challenge_method": {"S256"}},
		"missing-pkce":        {"response_type": {"code"}, "client_id": {"mcx-client"}, "redirect_uri": {"http://127.0.0.1:19000/callback"}, "scope": {"openid"}, "state": {"s"}, "nonce": {"n"}},
		"malformed-challenge": {"response_type": {"code"}, "client_id": {"mcx-client"}, "redirect_uri": {"http://127.0.0.1:19000/callback"}, "scope": {"openid"}, "state": {"s"}, "nonce": {"n"}, "code_challenge": {"short"}, "code_challenge_method": {"S256"}},
	} {
		test.Run(name, func(test *testing.T) {
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil))
			if rr.Code != http.StatusBadRequest {
				test.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

// ------------------------------------------------------------------------------
// RFC 7636 section 4.1: a code verifier shorter than 43 characters is refused at the token endpoint, even when it
// matches the challenge.
func TestTokenRejectsVerifierOutsidePKCELength(test *testing.T) {
	handler := newTestHandler(test, RoleIDMS, testConfig(), testKey(test))
	verifier := "short"
	digest := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"response_type": {"code"}, "client_id": {"mcx-client"}, "redirect_uri": {"http://127.0.0.1:19000/callback"},
		"scope": {"openid"}, "state": {"state"}, "nonce": {"nonce"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil))
	if rr.Code != http.StatusOK {
		test.Fatalf("authorize status=%d body=%s", rr.Code, rr.Body.String())
	}
	var start struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &start); err != nil {
		test.Fatal(err)
	}
	code := login(test, handler, start.RequestID, "state")
	status, _ := redeem(test, handler, code, verifier, "http://127.0.0.1:19000/callback")
	if status != http.StatusBadRequest {
		test.Fatalf("short verifier status=%d", status)
	}
}

// ------------------------------------------------------------------------------
// TS 33.180 annex B.4.2.3: wrong credentials are refused with 401 and give no authorization code (no redirect).
func TestWrongCredentialsDoNotCreateAuthorizationCode(test *testing.T) {
	handler := newTestHandler(test, RoleIDMS, testConfig(), testKey(test))
	requestID, _, _ := beginAuthorization(test, handler, "state")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, formRequest(http.MethodPost, "/login", url.Values{"request_id": {requestID}, "username": {"alice"}, "password": {"wrong"}}))
	if rr.Code != http.StatusUnauthorized {
		test.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Location") != "" {
		test.Fatal("wrong credentials produced redirect")
	}
}

// ------------------------------------------------------------------------------
// An authorization code is used once: a wrong code verifier consumes it, and the right one then fails too.
func TestAuthorizationCodeIsSingleUseEvenAfterWrongVerifier(test *testing.T) {
	handler := newTestHandler(test, RoleIDMS, testConfig(), testKey(test))
	requestID, verifier, redirectURI := beginAuthorization(test, handler, "state")
	code := login(test, handler, requestID, "state")
	status, _ := redeem(test, handler, code, "wrong-verifier", redirectURI)
	if status != http.StatusBadRequest {
		test.Fatalf("wrong verifier status=%d", status)
	}
	status, _ = redeem(test, handler, code, verifier, redirectURI)
	if status != http.StatusBadRequest {
		test.Fatalf("reused code status=%d", status)
	}
}

// ------------------------------------------------------------------------------
// RFC 7662 section 2: token introspection needs the server client credentials, and reports an access token with a
// changed signature as inactive.
func TestIntrospectionRequiresServerCredentialsAndRejectsMutatedSignature(test *testing.T) {
	key := testKey(test)
	handler := newTestHandler(test, RoleIDMS, testConfig(), key)
	requestID, verifier, redirectURI := beginAuthorization(test, handler, "state")
	code := login(test, handler, requestID, "state")
	_, raw := redeem(test, handler, code, verifier, redirectURI)
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &tokens); err != nil {
		test.Fatal(err)
	}
	parts := strings.Split(tokens.AccessToken, ".")
	if len(parts) != 3 {
		test.Fatal("malformed access token fixture")
	}
	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	mutated := strings.Join(parts, ".")

	for _, tc := range []struct {
		name, password, token string
		wantActive            bool
	}{
		{"wrong-basic", "wrong", tokens.AccessToken, false},
		{"valid", "server-secret", tokens.AccessToken, true},
		{"mutated", "server-secret", mutated, false},
	} {
		test.Run(tc.name, func(test *testing.T) {
			rr := httptest.NewRecorder()
			req := formRequest(http.MethodPost, "/introspect", url.Values{"token": {tc.token}})
			req.SetBasicAuth("mcx-server", tc.password)
			handler.ServeHTTP(rr, req)
			if tc.name == "wrong-basic" {
				if rr.Code != http.StatusUnauthorized {
					test.Fatalf("status=%d", rr.Code)
				}
				return
			}
			if rr.Code != http.StatusOK {
				responseBody, _ := io.ReadAll(rr.Body)
				test.Fatalf("status=%d body=%s", rr.Code, responseBody)
			}
			var body struct {
				Active  bool   `json:"active"`
				MCPTTID string `json:"mcptt_id"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				test.Fatal(err)
			}
			if body.Active != tc.wantActive {
				test.Fatalf("active=%v want=%v", body.Active, tc.wantActive)
			}
			if tc.wantActive && body.MCPTTID != "sip:alice@mcx.test" {
				test.Fatalf("mcptt_id=%q", body.MCPTTID)
			}
		})
	}
}

// ------------------------------------------------------------------------------
// The pending authorization requests are bounded (429 when full), expired ones are reclaimed, and an oversized
// state is refused.
func TestAuthorizationStateBoundedAndExpired(test *testing.T) {
	now := testNow
	svc := &service{cfg: testConfig(), now: func() time.Time { return now }, requests: map[string]authorizationRequest{}, codes: map[string]authorizationCode{}}
	for index := 0; index < 1024; index++ {
		svc.requests[fmt.Sprint(index)] = authorizationRequest{Expires: now.Add(time.Minute)}
	}
	query := url.Values{"response_type": {"code"}, "client_id": {"mcx-client"}, "redirect_uri": {"http://127.0.0.1:19000/callback"}, "scope": {"openid"}, "state": {"state"}, "nonce": {"nonce"}, "code_challenge": {strings.Repeat("A", 43)}, "code_challenge_method": {"S256"}}
	request := func() int {
		recorder := httptest.NewRecorder()
		svc.authorize(recorder, httptest.NewRequest("GET", "/authorize?"+query.Encode(), nil))
		return recorder.Code
	}
	if got := request(); got != http.StatusTooManyRequests {
		test.Fatalf("full pending state returned %d", got)
	}
	now = now.Add(2 * time.Minute)
	if got := request(); got != http.StatusOK || len(svc.requests) != 1 {
		test.Fatalf("expired state not reclaimed: status=%d count=%d", got, len(svc.requests))
	}
	query.Set("state", strings.Repeat("x", 4096))
	if got := request(); got != http.StatusBadRequest {
		test.Fatalf("oversized state returned %d", got)
	}
}

// ------------------------------------------------------------------------------
// Helper: the HTML form of an Authentication Request by GET or POST from a client accepting text/html; returns
// the page.
func signInFormPage(test *testing.T, handler http.Handler, method string, state string) string {
	test.Helper()
	digest := sha256.Sum256([]byte("correct-horse-battery-staple-verifier-1234567890"))
	query := url.Values{
		"response_type": {"code"}, "client_id": {"mcx-client"}, "redirect_uri": {"http://127.0.0.1:19000/callback"},
		"scope": {"openid"}, "state": {state}, "nonce": {"n"}, "acr_values": {"3gpp:acr:password"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	if method == http.MethodPost {
		req = formRequest(http.MethodPost, "/authorize", query)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/html") ||
		rr.Header().Get("X-Frame-Options") != "DENY" {
		test.Fatalf("form %d %s", rr.Code, rr.Body.String())
	}
	return rr.Body.String()
}

// ------------------------------------------------------------------------------
// Helper: the action URI of the page's form.
func formAction(test *testing.T, page string) string {
	test.Helper()
	const marker = `<form action="`
	start := strings.Index(page, marker)
	if start < 0 {
		test.Fatalf("no form: %s", page)
	}
	start += len(marker)
	return html.UnescapeString(page[start : start+strings.Index(page[start:], `"`)])
}

// ------------------------------------------------------------------------------
// TS 24.482 clause 6.2.1 and TS 37.579-1 table 5.3.2.3.1-1 steps 3a1/3b1 to 7: the Authentication Request (by GET
// or POST) is answered with the HTML form of table 5.3.2.3.2-5 (method post, inputs user and password, the IdMS's
// own action); the POST of the form with only those inputs gives the 302 with the code and state, which redeems.
func TestHTMLFormSignIn(test *testing.T) {
	handler := newTestHandler(test, RoleIDMS, testConfig(), testKey(test))
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		page := signInFormPage(test, handler, method, "st-"+method)
		for _, want := range []string{`method="post"`, `type="text" name="user"`, `type="password" name="password"`} {
			if !strings.Contains(page, want) {
				test.Fatalf("%s: form without %s: %s", method, want, page)
			}
		}
		action := formAction(test, page)
		if !strings.HasPrefix(action, userAuthPath+"?") || strings.Contains(page, `type="hidden"`) {
			test.Fatalf("%s: form action %q", method, action)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, formRequest(http.MethodPost, action, url.Values{"user": {"alice"}, "password": {"alice-password"}}))
		location, _ := url.Parse(rr.Header().Get("Location"))
		if rr.Code != http.StatusFound || location.Query().Get("state") != "st-"+method || location.Query().Get("code") == "" ||
			!strings.HasPrefix(location.String(), "http://127.0.0.1:19000/callback?") {
			test.Fatalf("%s: form sign-in %d %s", method, rr.Code, rr.Header().Get("Location"))
		}
		if status, body := redeem(test, handler, location.Query().Get("code"), "correct-horse-battery-staple-verifier-1234567890",
			"http://127.0.0.1:19000/callback"); status != http.StatusOK {
			test.Fatalf("%s: code from the form not redeemed: %d %s", method, status, body)
		}
		// The request is used up: the same form cannot sign in again.
		rr = httptest.NewRecorder()
		handler.ServeHTTP(rr, formRequest(http.MethodPost, action, url.Values{"user": {"alice"}, "password": {"alice-password"}}))
		if rr.Code != http.StatusBadRequest {
			test.Fatalf("%s: replayed form %d", method, rr.Code)
		}
	}
}

// ------------------------------------------------------------------------------
// A failed sign-in by the form goes back to the client with error=access_denied and the state (RFC 6749 section
// 4.1.2.1); the form of an IdMS whose issuer has a path posts below that path.
func TestBrowserSignInForm(test *testing.T) {
	handler := newTestHandler(test, RoleIDMS, testConfig(), testKey(test))
	action := formAction(test, signInFormPage(test, handler, http.MethodGet, "st"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, formRequest(http.MethodPost, action, url.Values{"user": {"alice"}, "password": {"wrong"}}))
	location, _ := url.Parse(rr.Header().Get("Location"))
	if rr.Code != http.StatusFound || location.Query().Get("error") != "access_denied" || location.Query().Get("state") != "st" ||
		location.Query().Get("code") != "" {
		test.Fatalf("failed browser sign-in: %d %s", rr.Code, rr.Header().Get("Location"))
	}
	cfg := testConfig()
	cfg.Issuer = "https://mcx.test/idms"
	prefixed := newTestHandler(test, RoleIDMS, cfg, testKey(test))
	if action := formAction(test, signInFormPage(test, prefixed, http.MethodGet, "st")); !strings.HasPrefix(action, "/idms"+userAuthPath+"?") {
		test.Fatalf("form action below the issuer path: %q", action)
	}
}

// ------------------------------------------------------------------------------
// TS 33.180 table B.4.2.2-1: an Authentication Request with exactly the parameters of the table (acr_values, no
// nonce) is served; the ID token has no nonce (OpenID Connect Core 1.0 section 3.1.2.1: the nonce is optional)
// and names the password-based acr. acr_values is a voluntary claim request: another value still gets a password
// sign-in, and the ID token's acr says so.
func TestTable_B_4_2_2_1_AcrValuesWithoutNonce(test *testing.T) {
	key := testKey(test)
	handler := newTestHandler(test, RoleIDMS, testConfig(), key)
	verifier := "correct-horse-battery-staple-verifier-1234567890"
	digest := sha256.Sum256([]byte(verifier))
	redirectURI := "http://127.0.0.1:19000/callback"
	for _, acr := range []string{"3gpp:acr:password", "urn:example:acr:otp 3gpp:acr:password", "urn:example:acr:otp"} {
		query := url.Values{"response_type": {"code"}, "client_id": {"mcx-client"}, "scope": {"openid 3gpp:mc:ptt_service"},
			"redirect_uri": {redirectURI}, "state": {"abc123"}, "acr_values": {acr},
			"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil))
		if rr.Code != http.StatusOK {
			test.Fatalf("acr_values %q: authorize status=%d body=%s", acr, rr.Code, rr.Body.String())
		}
		var start struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &start); err != nil {
			test.Fatal(err)
		}
		status, raw := redeem(test, handler, login(test, handler, start.RequestID, "abc123"), verifier, redirectURI)
		if status != http.StatusOK {
			test.Fatalf("acr_values %q: token status=%d body=%s", acr, status, raw)
		}
		var tokens struct {
			IDToken string `json:"id_token"`
		}
		if err := json.Unmarshal(raw, &tokens); err != nil {
			test.Fatal(err)
		}
		id, err := VerifyToken(tokens.IDToken, &key.PublicKey, testConfig().Issuer, "mcx-client", testNow)
		if err != nil {
			test.Fatal(err)
		}
		if id.Nonce != "" || id.ACR != acrPassword {
			test.Fatalf("acr_values %q: nonce=%q acr=%q", acr, id.Nonce, id.ACR)
		}
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if !strings.Contains(rr.Body.String(), `"acr_values_supported":["3gpp:acr:password"]`) {
		test.Fatalf("discovery: %s", rr.Body.String())
	}
}
