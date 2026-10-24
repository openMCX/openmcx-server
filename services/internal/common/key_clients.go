//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Key management clients of the MC servers and the GMS (TS 33.180 clause 5.3.2): each is a confidential OAuth client
// of the IdMS with its own secret. It obtains an access token with the client credentials grant (RFC 6749 section
// 4.4) whose subject is its identity (the public service identity of its MC server, or the GMS URI) and whose scope
// is its key management scope, and presents it on the KMS request URIs of annex D.2, as the key management client of
// an MC UE does (clause 5.3.3: "The procedure is the same whether the key management client in the MC UE, an MCX
// Server or a Group Management Server is making the request").
//
// Specifications: TS 33.180 V19.4.0 (Rel-19) clauses 5.3.2, 5.3.3 and annex D.2, RFC 6749, RFC 6750.
package common

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// KeyClient is a key management client of an MC server or the GMS, registered with the IdMS.
type KeyClient struct {
	ClientID string `json:"client_id"`
	Secret   string `json:"secret"`
	// The identity the KMS provisions: the public service identity of the MC server, or the GMS URI.
	Identity string `json:"identity"`
	// The key management scope of its MC service (TS 33.180 table B.4.2.2-1).
	Scope string `json:"scope"`
}

// The GMS URI the GMS is keyed as (TS 33.180 clause 5.7: the GMS signs the group keys it distributes).
func (cfg Config) gmsIdentity() string {
	return cfg.Endpoints.GMS + "/xcap-root/org.openmobilealliance.groups"
}

// ------------------------------------------------------------------------------
// Helper: checks the key management clients: each with a client ID of its own (not the users' or the servers'
// OAuth client), a secret, the identity of an MC server or the GMS, at most one client per identity, and a key
// management scope.
func (cfg Config) validateKeyClients() error {
	identities := map[string]bool{cfg.ServiceURI: true, cfg.gmsIdentity(): cfg.Endpoints.GMS != ""}
	if cfg.MCDataService.ServiceURI != "" {
		identities[cfg.MCDataService.ServiceURI] = true
	}
	if cfg.MCVideoService.ServiceURI != "" {
		identities[cfg.MCVideoService.ServiceURI] = true
	}
	clients, keyed := map[string]bool{}, map[string]bool{}
	for _, client := range cfg.KeyClients {
		if client.ClientID == "" || client.Secret == "" || client.ClientID == cfg.OAuthClientID || client.ClientID == cfg.ServerClientID || clients[client.ClientID] {
			return fmt.Errorf("key client %q: a client ID of its own and a secret are required", client.ClientID)
		}
		if !identities[client.Identity] || keyed[client.Identity] {
			return fmt.Errorf("key client %q: identity %q is not an MC server or the GMS, or already has a key client", client.ClientID, client.Identity)
		}
		if client.Scope != scopePTTKeys && client.Scope != scopeDataKeys && client.Scope != scopeVideoKeys {
			return fmt.Errorf("key client %q: scope must be a key management scope", client.ClientID)
		}
		clients[client.ClientID], keyed[client.Identity] = true, true
	}
	return nil
}

// ------------------------------------------------------------------------------
// Helper: the key management client of a client ID.
func (cfg Config) keyClient(clientID string) (KeyClient, bool) {
	for _, client := range cfg.KeyClients {
		if client.ClientID == clientID {
			return client, true
		}
	}
	return KeyClient{}, false
}

// ------------------------------------------------------------------------------
// RFC 6749 section 4.4: the client credentials grant of a key management client. The client authenticates with HTTP
// Basic (section 2.3.1, its client ID and secret form-encoded) or with client_id and client_secret in the body; a
// requested scope must be its key management scope ("openid" aside). The access token (section 4.4.3, no refresh
// token) has its identity as subject, the MC servers' audience and its scope, and no MC user's claims.
func (svc *service) clientCredentialsGrant(writer http.ResponseWriter, request *http.Request) {
	id, secret, basic := request.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = request.Form.Get("client_id"), request.Form.Get("client_secret")
	}
	client, ok := svc.cfg.keyClient(id)
	if !ok || !secureEqual(secret, client.Secret) {
		if basic {
			writer.Header().Set("WWW-Authenticate", `Basic realm="mcx-idms"`)
		}
		writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	for _, scope := range strings.Fields(request.Form.Get("scope")) {
		if scope != client.Scope && scope != "openid" {
			writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_scope"})
			return
		}
	}
	tokenID, err := randomID()
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	now := svc.now()
	claims := TokenClaims{Issuer: svc.cfg.Issuer, Subject: client.Identity, Audience: Audience{svc.cfg.ServerClientID},
		Expires: now.Add(time.Duration(svc.cfg.TokenTTLSeconds) * time.Second).Unix(), IssuedAt: now.Unix(),
		TokenID: tokenID, ClientID: client.ClientID, Type: "access", Scope: client.Scope}
	token, err := signToken(claims, svc.signingKey)
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	svc.logEvent("key_client_token_issued", map[string]any{"client_id": client.ClientID, "identity": client.Identity})
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer",
		"expires_in": svc.cfg.TokenTTLSeconds, "scope": client.Scope})
}

// ------------------------------------------------------------------------------
// TS 33.180 clause 5.3.3 step 1 and annex D.2: the identity of a key management client of an MC server or the GMS
// from its Bearer access token: a token of the IdMS (issuer, audience, signature, lifetime) without an MC user (no
// mcptt_id), issued to a configured key management client, whose subject is that client's identity and whose scope
// holds its key management scope. ok is false for any other token (a user's token goes the user's way).
func (svc *service) keyClientIdentity(request *http.Request) (identity string, ok bool) {
	value := request.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return "", false
	}
	claims, err := VerifyToken(strings.TrimPrefix(value, "Bearer "), svc.verificationKey, svc.cfg.Issuer, svc.cfg.ServerClientID, svc.now())
	if err != nil || claims.MCPTTID != "" || (claims.Type != "" && claims.Type != "access") {
		return "", false
	}
	client, known := svc.cfg.keyClient(claims.ClientID)
	if !known || claims.Subject != client.Identity || !containsWord(claims.Scope, client.Scope) {
		return "", false
	}
	return client.Identity, true
}

// ------------------------------------------------------------------------------
// The access token of a key management client, obtained from the IdMS's token endpoint (its discovery document,
// OpenID Connect Discovery 1.0 section 3) and kept until shortly before it expires.
type keyClientToken struct {
	mu      sync.Mutex
	token   string
	expires time.Time
}

// ------------------------------------------------------------------------------
// Helper: a current access token of the key management client, from the cache or a new client credentials grant.
func (svc *service) keyClientAccessToken(ctx context.Context, client *http.Client, key KeyClient) (string, error) {
	cache := &svc.gmsKeyToken
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.token != "" && svc.now().Add(30*time.Second).Before(cache.expires) {
		return cache.token, nil
	}
	discovery, err := getJSON(ctx, client, strings.TrimRight(svc.cfg.Issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return "", err
	}
	endpoint, _ := discovery["token_endpoint"].(string)
	if issuer, _ := discovery["issuer"].(string); issuer != svc.cfg.Issuer || !strings.HasPrefix(endpoint, "https://") {
		return "", errors.New("invalid IdMS discovery document")
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {key.Scope}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(key.ClientID), url.QueryEscape(key.Secret))
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("IdMS unavailable")
	}
	defer resp.Body.Close()
	var answer struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&answer) != nil || answer.AccessToken == "" || answer.ExpiresIn <= 0 {
		return "", errors.New("client credentials grant refused")
	}
	cache.token, cache.expires = answer.AccessToken, svc.now().Add(time.Duration(answer.ExpiresIn)*time.Second)
	return cache.token, nil
}

// ------------------------------------------------------------------------------
// Helper: a JSON object fetched with GET.
func getJSON(ctx context.Context, client *http.Client, target string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("IdMS unavailable")
	}
	defer resp.Body.Close()
	var out map[string]any
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out) != nil {
		return nil, errors.New("invalid IdMS discovery document")
	}
	return out, nil
}
