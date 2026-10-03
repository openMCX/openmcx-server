// IdMS: the IdM server of TS 24.482 clause 6.3.1, with the OpenID Connect authorization code flow and PKCE of
// TS 33.180 annex B.4.2 (authorization endpoint, sign-in, token endpoint), its discovery document and keys, and
// token introspection for the MC servers.
//
// Specifications: TS 24.482 V19.1.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), RFC 6749, RFC 7636, RFC 7662, RFC 7517,
// OpenID Connect Core 1.0, OpenID Connect Discovery 1.0.
package common

import (
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type authorizationRequest struct {
	ClientID, RedirectURI, State, Nonce, Challenge, Scope string
	Expires                                               time.Time
}
type authorizationCode struct {
	ClientID, RedirectURI, Nonce, Challenge, Scope string
	User                                           User
	Expires                                        time.Time
}

// ------------------------------------------------------------------------------
// TS 24.482 clause 6.3: the IdM server's endpoints: discovery, keys, authorization, sign-in, token and
// introspection, MCX Admin's revocation of a user's refresh tokens and, in admin mode, the password links.
func (svc *service) routesIDMS(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", svc.discovery)
	mux.HandleFunc("GET /jwks", svc.jwks)
	mux.HandleFunc("GET /authorize", svc.authorize)
	mux.HandleFunc("POST /login", svc.login)
	mux.HandleFunc("POST /token", svc.token)
	mux.HandleFunc("POST /introspect", svc.introspect)
	mux.HandleFunc("POST /internal/refresh-tokens/{login}/revoke", svc.revokeRefreshTokens)
	if svc.cfg.AdminAccounts != nil {
		svc.routesAdminAccounts(mux)
	}
}

// ------------------------------------------------------------------------------
// OpenID Connect Discovery 1.0 section 3: the IdM server's provider metadata: its endpoints, the authorization code
// flow with S256 PKCE, the MC scopes (TS 33.180 table B.4.2.2-1) and the grant types it accepts.
func (svc *service) discovery(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{
		"issuer": svc.cfg.Issuer, "authorization_endpoint": svc.cfg.Issuer + "/authorize", "token_endpoint": svc.cfg.Issuer + "/token",
		"jwks_uri": svc.cfg.Issuer + "/jwks", "response_types_supported": []string{"code"},
		"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported": []string{"S256"}, "acr_values_supported": []string{acrPassword},
		"scopes_supported": []string{"openid", "3gpp:mc:ptt_service", "3gpp:mc:data_service", "3gpp:mc:ptt_key_management_service", "3gpp:mc:data_key_management_service",
			"3gpp:mc:video_service", "3gpp:mc:video_key_management_service",
			"3gpp:mc:ptt_config_management_service", "3gpp:mc:ptt_group_management_service"},
		"grant_types_supported": []string{"authorization_code", "refresh_token"},
	})
}

// ------------------------------------------------------------------------------
// RFC 7517 section 5: the JWK Set of the IdMS's token verification key.
func (svc *service) jwks(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"keys": []any{jwk(svc.verificationKey)}})
}

const (
	maxAuthorizationState = 1024
	// The longest state, nonce and acr_values accepted (openMCX limits).
	maxAuthorizationParameter = 1024
	// TS 33.180 table B.4.2.2-1 (acr_values): the password-based ACR value every IdM server supports; the only
	// one this IdMS authenticates with.
	acrPassword = "3gpp:acr:password"
)

// ------------------------------------------------------------------------------
// Helper: drops the lapsed authorization requests and codes. Caller holds svc.mu. Cleanup is bounded by the two
// capped maps.
func (svc *service) sweepAuthorizationState() {
	now := svc.now()
	for id, request := range svc.requests {
		if !request.Expires.After(now) {
			delete(svc.requests, id)
		}
	}
	for id, code := range svc.codes {
		if !code.Expires.After(now) {
			delete(svc.codes, id)
		}
	}
}

// ------------------------------------------------------------------------------
// TS 24.482 clause 6.3.1 and TS 33.180 annex B.4.2.2: validates an OIDC Authentication Request (the parameters of
// table B.4.2.2-1: response_type code, the registered client and redirect URI, the openid scope, state, acr_values
// and an S256 code challenge, RFC 7636 section 4.3) and keeps it for five minutes; a browser gets the sign-in form,
// a native client the request ID.
//
// The nonce is optional (OpenID Connect Core 1.0 section 3.1.2.1, and not in table B.4.2.2-1); when given, the ID
// token repeats it. acr_values is a voluntary claim request (OpenID Connect Core 1.0 section 3.1.2.1): the
// user is authenticated by password whatever it names, and the ID token's acr says so (acrPassword).
// Deviation from TS 33.180 table B.4.2.2-1 (acr_values REQUIRED): a request without acr_values is accepted, as
// from the openMCX clients, which do not send it yet.
func (svc *service) authorize(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	if len(request.URL.RawQuery) > 8192 || len(query.Get("state")) > maxAuthorizationParameter ||
		len(query.Get("nonce")) > maxAuthorizationParameter || len(query.Get("acr_values")) > maxAuthorizationParameter ||
		query.Get("response_type") != "code" || query.Get("client_id") != svc.cfg.OAuthClientID ||
		!svc.cfg.redirectAllowed(query.Get("redirect_uri")) || !containsWord(query.Get("scope"), "openid") ||
		query.Get("state") == "" || query.Get("code_challenge_method") != "S256" || !validS256Challenge(query.Get("code_challenge")) {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	id, err := randomID()
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	svc.mu.Lock()
	svc.sweepAuthorizationState()
	if len(svc.requests) >= maxAuthorizationState {
		svc.mu.Unlock()
		writeJSON(writer, http.StatusTooManyRequests, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	svc.requests[id] = authorizationRequest{ClientID: query.Get("client_id"), RedirectURI: query.Get("redirect_uri"), State: query.Get("state"), Nonce: query.Get("nonce"), Challenge: query.Get("code_challenge"), Scope: query.Get("scope"), Expires: svc.now().Add(5 * time.Minute)}
	svc.mu.Unlock()
	if wantsHTML(request) {
		// A browser (the MCX Admin console): the IdMS's own sign-in form, which posts
		// to /login. Native clients get the request ID as before.
		setPageHeaders(writer)
		_ = signInPage.Execute(writer, map[string]string{"RequestID": id})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"request_id": id})
}

// ------------------------------------------------------------------------------
// Helper: wantsHTML: the request comes from a browser navigation.
func wantsHTML(request *http.Request) bool {
	return strings.Contains(request.Header.Get("Accept"), "text/html")
}

// ------------------------------------------------------------------------------
// Helper: the headers of the IdMS's own HTML pages: never cached, never framed, no script.
func setPageHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Frame-Options", "DENY")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
}

var signInPage = template.Must(template.New("signin").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>openMCX sign-in</title>
<style>body{font-family:system-ui,sans-serif;max-width:24rem;margin:4rem auto;padding:0 1rem;color:#15171c}
.logo{display:inline-block;background:#ffc58a;border-radius:8px;padding:.4rem .7rem;font-weight:700}
input{display:block;width:100%;box-sizing:border-box;margin:.3rem 0 1rem;padding:.55rem;font:inherit}
button{padding:.55rem 1.1rem;font:inherit;background:#c2530f;color:#fff;border:0;border-radius:6px}</style></head>
<body><p><span class="logo">openMCX</span></p><h1>Sign in</h1>
<form method="post" action="login"><input type="hidden" name="request_id" value="{{.RequestID}}"><input type="hidden" name="html" value="1">
<label>User name<input name="username" autocomplete="username" required autofocus></label>
<label>Password<input type="password" name="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button></form></body></html>`))

// ------------------------------------------------------------------------------
// TS 24.482 clause 6.3.1 and TS 33.180 annex B.4.2.3: authenticates the MC service user with username and password
// and answers with an HTTP 302 (Found) to the redirect URI carrying the authorization code (valid for one minute)
// and the state.
func (svc *service) login(writer http.ResponseWriter, request *http.Request) {
	if err := parseForm(writer, request); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	svc.mu.Lock()
	pending, ok := svc.requests[request.Form.Get("request_id")]
	if ok {
		delete(svc.requests, request.Form.Get("request_id"))
	}
	svc.mu.Unlock()
	if !ok || !pending.Expires.After(svc.now()) {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	var user User
	if svc.cfg.AdminAccounts != nil {
		user, ok = svc.adminLogin(request, request.Form.Get("username"), request.Form.Get("password"))
	} else {
		user, ok = svc.cfg.userByName(request.Form.Get("username"))
		ok = ok && checkPassword(user.Password, request.Form.Get("password"))
	}
	if !ok {
		if request.Form.Get("html") == "1" {
			// RFC 6749 section 4.1.2.1: the browser goes back to the client with the error.
			redirect, _ := url.Parse(pending.RedirectURI)
			query := redirect.Query()
			query.Set("error", "access_denied")
			query.Set("state", pending.State)
			redirect.RawQuery = query.Encode()
			http.Redirect(writer, request, redirect.String(), http.StatusFound)
			return
		}
		writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "access_denied"})
		return
	}
	code, err := randomID()
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	svc.mu.Lock()
	svc.sweepAuthorizationState()
	if len(svc.codes) >= maxAuthorizationState {
		svc.mu.Unlock()
		writeJSON(writer, http.StatusTooManyRequests, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	svc.codes[code] = authorizationCode{ClientID: pending.ClientID, RedirectURI: pending.RedirectURI, Nonce: pending.Nonce, Challenge: pending.Challenge, Scope: pending.Scope, User: user, Expires: svc.now().Add(time.Minute)}
	svc.mu.Unlock()
	redirect, _ := url.Parse(pending.RedirectURI)
	query := redirect.Query()
	query.Set("code", code)
	query.Set("state", pending.State)
	redirect.RawQuery = query.Encode()
	http.Redirect(writer, request, redirect.String(), http.StatusFound)
}

// ------------------------------------------------------------------------------
// TS 24.482 clause 6.3.1 and TS 33.180 annex B.4.2.4 and B.4.2.5: the token endpoint. The authorization code grant
// checks the code, client, redirect URI and PKCE verifier (RFC 7636 section 4.6) and answers with the ID, access
// and refresh tokens; the refresh token grant has its own handler.
func (svc *service) token(writer http.ResponseWriter, request *http.Request) {
	if err := parseForm(writer, request); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if request.Form.Get("grant_type") == "refresh_token" {
		svc.refreshGrant(writer, request)
		return
	}
	codeValue := request.Form.Get("code")
	svc.mu.Lock()
	code, ok := svc.codes[codeValue]
	if ok {
		delete(svc.codes, codeValue)
	}
	svc.mu.Unlock()
	digest := sha256.Sum256([]byte(request.Form.Get("code_verifier")))
	actual := base64.RawURLEncoding.EncodeToString(digest[:])
	if !ok || !code.Expires.After(svc.now()) || request.Form.Get("grant_type") != "authorization_code" || request.Form.Get("client_id") != code.ClientID || request.Form.Get("redirect_uri") != code.RedirectURI || !validPKCEVerifier(request.Form.Get("code_verifier")) || !secureEqual(actual, code.Challenge) {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	// TS 33.180 annex B.5: with the ID and access tokens, a refresh token for the native client.
	svc.issueTokens(writer, code.User, code.Scope, code.Nonce, refreshRecord{Login: code.User.Username, ClientID: code.ClientID,
		Scope: code.Scope, Nonce: code.Nonce})
}

// ------------------------------------------------------------------------------
// RFC 7662 section 2: token introspection for the MC servers (server client credentials): an access token of this
// IdMS, of an active account in admin mode, is active, with the identities it binds (TS 33.180 annex B.2.2).
func (svc *service) introspect(writer http.ResponseWriter, request *http.Request) {
	username, password, ok := request.BasicAuth()
	if !ok || !secureEqual(username, svc.cfg.ServerClientID) || !secureEqual(password, svc.cfg.ServerSecret) {
		writer.Header().Set("WWW-Authenticate", `Basic realm="mcx-internal"`)
		writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if err := parseForm(writer, request); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	claims, err := VerifyToken(request.Form.Get("token"), svc.verificationKey, svc.cfg.Issuer, svc.cfg.ServerClientID, svc.now())
	if err != nil || claims.Type != "access" || (svc.cfg.AdminAccounts != nil && !svc.accountActive(request.Context(), claims.MCPTTID)) {
		writeJSON(writer, http.StatusOK, map[string]bool{"active": false})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"active": true, "sub": claims.Subject, "mc_id": claims.MCID, "mcptt_id": claims.MCPTTID, "mcdata_id": claims.MCDataID, "mcvideo_id": claims.MCVideoID, "sip_uri": claims.SIPURI, "client_id": claims.ClientID, "exp": claims.Expires})
}

// ------------------------------------------------------------------------------
// Helper: the space-separated words (a scope) contain the wanted one.
func containsWord(words, wanted string) bool {
	for _, word := range strings.Fields(words) {
		if word == wanted {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------------------
// Helper: parses a form body of at most 64 KiB.
func parseForm(writer http.ResponseWriter, request *http.Request) error {
	request.Body = http.MaxBytesReader(writer, request.Body, 64<<10)
	return request.ParseForm()
}

// ------------------------------------------------------------------------------
// RFC 7636 section 4.2: an S256 code challenge is the base64url encoding (43 characters) of a SHA-256 digest.
func validS256Challenge(value string) bool {
	if len(value) != 43 {
		return false
	}
	for _, symbol := range value {
		if !((symbol >= 'A' && symbol <= 'Z') || (symbol >= 'a' && symbol <= 'z') || (symbol >= '0' && symbol <= '9') || symbol == '-' || symbol == '_') {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------------------------
// RFC 7636 section 4.1: a code verifier has 43 to 128 unreserved characters.
func validPKCEVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, symbol := range value {
		if !((symbol >= 'A' && symbol <= 'Z') || (symbol >= 'a' && symbol <= 'z') || (symbol >= '0' && symbol <= '9') || symbol == '-' || symbol == '.' || symbol == '_' || symbol == '~') {
			return false
		}
	}
	return true
}
