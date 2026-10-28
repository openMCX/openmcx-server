//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ------------------------------------------------------------------------------
// Helper: the test configuration with the key management clients of the MCPTT, MCData and MCVideo servers and
// the GMS.
func keyClientConfig() Config {
	cfg := testConfig()
	cfg.ServiceURI = "sip:mcptt@mcx.test"
	cfg.MCDataService.ServiceURI = "sip:mcdata@mcx.test"
	cfg.MCVideoService.ServiceURI = "sip:mcvideo@mcx.test"
	cfg.Endpoints.GMS = "https://gms:8443"
	cfg.KeyClients = []KeyClient{
		{ClientID: "mcptt-key", Secret: "mcptt-secret", Identity: cfg.ServiceURI, Scope: scopePTTKeys},
		{ClientID: "mcdata-key", Secret: "mcdata-secret", Identity: cfg.MCDataService.ServiceURI, Scope: scopeDataKeys},
		{ClientID: "mcvideo-key", Secret: "mcvideo-secret", Identity: cfg.MCVideoService.ServiceURI, Scope: scopeVideoKeys},
		{ClientID: "gms-key", Secret: "gms-secret", Identity: cfg.gmsIdentity(), Scope: scopePTTKeys},
	}
	return cfg
}

// ------------------------------------------------------------------------------
// RFC 6749 section 4.4 and TS 33.180 clause 5.3.3: the IdMS issues a key management client's access token for the
// client credentials grant only with its secret (HTTP Basic or the form) and its own scope; the token's subject is
// the client's identity and it names no MC user, so the user-facing services refuse it.
func TestClientCredentialsGrant(test *testing.T) {
	cfg, key := keyClientConfig(), testKey(test)
	handler, err := NewHandlerWithKeys(RoleIDMS, cfg, key, &key.PublicKey, test.TempDir(), WithClock(func() time.Time { return testNow }))
	if err != nil {
		test.Fatal(err)
	}
	grant := func(client, secret, scope string, basic bool) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"client_credentials"}, "scope": {scope}}
		if !basic {
			form.Set("client_id", client)
			form.Set("client_secret", secret)
		}
		request := formRequest(http.MethodPost, "/token", form)
		if basic {
			request.SetBasicAuth(url.QueryEscape(client), url.QueryEscape(secret))
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, request)
		return rr
	}
	for _, tc := range []struct {
		client, secret, scope string
		basic                 bool
		status                int
	}{
		{"mcptt-key", "wrong", scopePTTKeys, true, 401},
		{"unknown", "mcptt-secret", scopePTTKeys, true, 401},
		{"mcptt-key", "mcptt-secret", scopeDataKeys, true, 400},
		{"mcptt-key", "mcptt-secret", "3gpp:mc:ptt_service", true, 400},
		{"mcptt-key", "mcptt-secret", scopePTTKeys, true, 200},
		{"mcdata-key", "mcdata-secret", "", false, 200},
	} {
		if rr := grant(tc.client, tc.secret, tc.scope, tc.basic); rr.Code != tc.status {
			test.Fatalf("%s/%s/%q got %d want %d: %s", tc.client, tc.secret, tc.scope, rr.Code, tc.status, rr.Body)
		}
	}
	rr := grant("mcptt-key", "mcptt-secret", scopePTTKeys, true)
	// RFC 6749 section 5.1: no-store and "Pragma" no-cache on the token response.
	if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Pragma") != "no-cache" {
		test.Fatalf("token response headers %v", rr.Header())
	}
	var answer struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Refresh     string `json:"refresh_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &answer); err != nil || answer.TokenType != "Bearer" || answer.ExpiresIn != cfg.TokenTTLSeconds || answer.Refresh != "" {
		test.Fatalf("token response %s", rr.Body)
	}
	claims, err := VerifyToken(answer.AccessToken, &key.PublicKey, cfg.Issuer, cfg.ServerClientID, testNow)
	if err != nil || claims.Subject != cfg.ServiceURI || claims.MCPTTID != "" || claims.ClientID != "mcptt-key" || claims.Scope != scopePTTKeys {
		test.Fatalf("claims %+v %v", claims, err)
	}
	if _, err := VerifyAccessToken(answer.AccessToken, &key.PublicKey, cfg.Issuer, cfg.ServerClientID, testNow); err == nil {
		test.Fatal("a key management client's token passes as a user's access token")
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if !strings.Contains(rr.Body.String(), `"client_credentials"`) {
		test.Fatal("discovery does not list the client credentials grant")
	}
}

// ------------------------------------------------------------------------------
// TS 33.180 annex D.2.3 and D.2.4: the KMS provisions a key management client of an MC server or the GMS for the
// identity its token names, on the annex D.2 URIs, and for no other; a token naming another client's identity, a
// token without the client's scope and a user's token for a server identity are refused; the internal route is gone.
func TestKMSKeyClients(test *testing.T) {
	cfg, key := keyClientConfig(), testKey(test)
	var provisioned []string
	backend := func(input map[string]any) (json.RawMessage, error) {
		if input["op"] == "authority-generate" {
			return json.RawMessage(`{"private":"test-only"}`), nil
		}
		provisioned = append(provisioned, input["user_uri"].(string))
		return json.RawMessage(`{"xml":"<KmsResponse/>"}`), nil
	}
	handler, err := NewHandlerWithKeys(RoleKMS, cfg, nil, &key.PublicKey, test.TempDir(), WithClock(func() time.Time { return testNow }), WithKeyTool(backend))
	if err != nil {
		test.Fatal(err)
	}
	token := func(client KeyClient, subject, scope string) string {
		claims := TokenClaims{Issuer: cfg.Issuer, Subject: subject, Audience: Audience{cfg.ServerClientID}, Expires: testNow.Add(time.Minute).Unix(),
			IssuedAt: testNow.Unix(), ClientID: client.ClientID, Type: "access", Scope: scope}
		signed, _ := signToken(claims, key)
		return signed
	}
	mcptt, gms := cfg.KeyClients[0], cfg.KeyClients[3]
	own := token(mcptt, mcptt.Identity, scopePTTKeys)
	escaped := func(identity string) string { return "/keymanagement/identity/v1/keyprov/" + url.PathEscape(identity) }
	user, _ := newClaims(cfg, cfg.Users[0], cfg.ServerClientID, "access", "", testNow)
	user.Scope = scopePTTKeys
	userToken, _ := signToken(user, key)
	for _, tc := range []struct {
		path, token, identity string
		status                int
	}{
		{"/keymanagement/identity/v1/init", own, mcptt.Identity, 200},
		{"/keymanagement/identity/v1/certcache", own, mcptt.Identity, 200},
		{"/keymanagement/identity/v1/keyprov", own, mcptt.Identity, 200},
		{escaped(mcptt.Identity), own, mcptt.Identity, 200},
		{escaped(cfg.MCDataService.ServiceURI), own, "", 403},
		{escaped(gms.Identity), token(gms, gms.Identity, scopePTTKeys), gms.Identity, 200},
		// The MCPTT server's client presenting the GMS's identity, and without its key management scope: neither a
		// key management client's token nor a user's (RFC 6750 section 3.1, invalid_token).
		{"/keymanagement/identity/v1/init", token(mcptt, gms.Identity, scopePTTKeys), "", 401},
		{"/keymanagement/identity/v1/keyprov", token(mcptt, mcptt.Identity, "openid"), "", 401},
		// A user's token does not provision a server identity.
		{escaped(mcptt.Identity), userToken, "", 403},
		{"/internal/keymanagement/keyprov?identity=" + url.QueryEscape(mcptt.Identity), own, "", 404},
	} {
		before := len(provisioned)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, bearerRequest(http.MethodPost, tc.path, tc.token, nil))
		if rr.Code != tc.status {
			test.Fatalf("%s got %d want %d: %s", tc.path, rr.Code, tc.status, rr.Body)
		}
		if tc.status == 200 && (len(provisioned) != before+1 || provisioned[before] != tc.identity) {
			test.Fatalf("%s provisioned %v, want %s", tc.path, provisioned[before:], tc.identity)
		}
		// RFC 6750 section 3.1: a token presented and refused is challenged with the error code invalid_token.
		if tc.status == 401 && !strings.Contains(rr.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
			test.Fatalf("%s challenge %q", tc.path, rr.Header().Get("WWW-Authenticate"))
		}
	}
	// RFC 6750 section 2.1 with RFC 7235 section 2.1: the auth-scheme is case-insensitive.
	request := httptest.NewRequest(http.MethodPost, "/keymanagement/identity/v1/init", nil)
	request.Header.Set("Authorization", "bearer "+own)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)
	if rr.Code != http.StatusOK || provisioned[len(provisioned)-1] != mcptt.Identity {
		test.Fatalf("lower-case bearer scheme got %d: %s", rr.Code, rr.Body)
	}
}

// ------------------------------------------------------------------------------
// The key management clients' configuration: an identity of an MC server or the GMS, one client per identity, a
// client ID of its own and a key management scope.
func TestKeyClientValidation(test *testing.T) {
	for name, change := range map[string]func(*Config){
		"unknown identity":   func(cfg *Config) { cfg.KeyClients[0].Identity = "sip:other@mcx.test" },
		"duplicate identity": func(cfg *Config) { cfg.KeyClients[1].Identity = cfg.KeyClients[0].Identity },
		"duplicate client":   func(cfg *Config) { cfg.KeyClients[1].ClientID = cfg.KeyClients[0].ClientID },
		"user client ID":     func(cfg *Config) { cfg.KeyClients[0].ClientID = cfg.OAuthClientID },
		"server client ID":   func(cfg *Config) { cfg.KeyClients[0].ClientID = cfg.ServerClientID },
		"no secret":          func(cfg *Config) { cfg.KeyClients[0].Secret = "" },
		"service scope":      func(cfg *Config) { cfg.KeyClients[0].Scope = "3gpp:mc:ptt_service" },
	} {
		cfg := keyClientConfig()
		change(&cfg)
		if cfg.Validate() == nil {
			test.Fatalf("%s accepted", name)
		}
	}
	if err := keyClientConfig().Validate(); err != nil {
		test.Fatal(err)
	}
}
