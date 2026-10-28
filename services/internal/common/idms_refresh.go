//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// IdMS refresh tokens: the refresh token grant of TS 33.180 annex B.5 with rotation and replay detection, and the
// token response it shares with the authorization code grant.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.482 V19.1.0 (Rel-19), RFC 6749, RFC 9700,
// OpenID Connect Core 1.0.
package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Refresh tokens (TS 33.180 annex B.5, RFC 6749 section 6): the token response of
// the authorization code grant carries a refresh token, and a native MC client
// obtains new access tokens with grant_type=refresh_token instead of signing the
// user in again, so it need not keep the password (TS 33.180 clause 5.1.2).
//
// A refresh token is an opaque random value; IdMS keeps only its SHA-256. Each use
// returns a new refresh token and retires the one used (rotation, RFC 9700 section 4.14.2,
// for these public clients); presenting a retired token again revokes its whole
// chain, since one of the two holders is not the device it was issued to. A token
// is refused once the user's account is no longer active (admin mode: suspended or
// retired in MCX Admin; file mode: gone from site.json), and all of a user's tokens
// are revoked when the password is set again or MCX Admin revokes the devices.

const (
	defaultRefreshTTL = 7 * 24 * time.Hour // unused for this long, a refresh token lapses
	maxRefreshTokens  = 200000
	refreshSaveEvery  = 5 * time.Second
)

// refreshRecord is one refresh token chain's current token, by its hash.
type refreshRecord struct {
	Chain    string `json:"chain"` // all tokens of one sign-in share it
	Login    string `json:"login"`
	User     User   `json:"user"` // the identities at sign-in (file mode); admin mode reads them again
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
	// Of the authentication; refreshed ID tokens repeat it (see issueTokens).
	Nonce   string    `json:"nonce"`
	Expires time.Time `json:"expires"`
	Retired bool      `json:"retired,omitempty"`
}

type refreshStore struct {
	mu      sync.Mutex
	path    string
	records map[string]refreshRecord // by SHA-256 of the token
	dirty   bool
}

// ------------------------------------------------------------------------------
// Helper: the IdMS's refresh token store, read back from its data directory. A file that cannot be read back is
// reported and the store starts empty: the devices sign in again (the IdMS still starts).
func newRefreshStore(dataDir string) (*refreshStore, error) {
	store := &refreshStore{path: filepath.Join(dataDir, "idms-refresh-tokens.json"), records: map[string]refreshRecord{}}
	raw, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err == nil {
		err = json.Unmarshal(raw, &store.records)
	}
	if err != nil {
		store.records = map[string]refreshRecord{}
		return store, fmt.Errorf("refresh tokens: %w", err)
	}
	return store, nil
}

// ------------------------------------------------------------------------------
// Helper: persistRefreshTokens (every refreshSaveEvery) drops lapsed records and writes the store when it changed:
// a restart loses at most the last few rotations, whose devices then sign in again.
func (svc *service) persistRefreshTokens(time.Time) {
	svc.refresh.mu.Lock()
	svc.refresh.sweep(svc.now())
	svc.refresh.mu.Unlock()
	svc.saveRefreshTokens()
}

// ------------------------------------------------------------------------------
// Helper: saves the refresh token store and logs a failure (the next save tries again).
func (svc *service) saveRefreshTokens() {
	if err := svc.refresh.save(); err != nil {
		svc.logEvent("refresh_tokens_save_failed", map[string]any{"error": err.Error()})
	}
}

// ------------------------------------------------------------------------------
// Helper: writes the records to the data directory when they changed (atomically, by rename); after a failed write
// the next save tries again.
func (store *refreshStore) save() error {
	store.mu.Lock()
	if !store.dirty {
		store.mu.Unlock()
		return nil
	}
	raw, err := json.Marshal(store.records)
	store.dirty = false
	store.mu.Unlock()
	if err == nil {
		err = writeFileAtomic(store.path, raw)
	}
	if err != nil {
		store.mu.Lock()
		store.dirty = true
		store.mu.Unlock()
		return fmt.Errorf("refresh tokens: %w", err)
	}
	return nil
}

// ------------------------------------------------------------------------------
// Helper: sweep drops lapsed records; the caller holds store.mu.
func (store *refreshStore) sweep(now time.Time) {
	for hash, record := range store.records {
		if !record.Expires.After(now) {
			delete(store.records, hash)
			store.dirty = true
		}
	}
}

// ------------------------------------------------------------------------------
// RFC 9700 section 4.14.2: issue starts or continues a chain and returns the new token.
func (store *refreshStore) issue(record refreshRecord, now time.Time, ttl time.Duration) (string, error) {
	token, err := randomID()
	if err != nil {
		return "", err
	}
	if record.Chain == "" {
		if record.Chain, err = randomID(); err != nil {
			return "", err
		}
	}
	record.Expires, record.Retired = now.Add(ttl), false
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.records) >= maxRefreshTokens {
		store.sweep(now)
		if len(store.records) >= maxRefreshTokens {
			return "", errors.New("refresh token store full")
		}
	}
	store.records[tokenHash(token)] = record
	store.dirty = true
	return token, nil
}

var errRefreshReplayed = errors.New("refresh token replayed")

// ------------------------------------------------------------------------------
// RFC 9700 section 4.14.2: use retires a token and returns its record; a retired token revokes its chain.
func (store *refreshStore) use(token string, now time.Time) (refreshRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	hash := tokenHash(token)
	record, ok := store.records[hash]
	if !ok || !record.Expires.After(now) {
		return refreshRecord{}, errors.New("unknown or lapsed refresh token")
	}
	if record.Retired {
		store.revokeLocked(func(other refreshRecord) bool { return other.Chain == record.Chain })
		return record, errRefreshReplayed
	}
	record.Retired = true
	// A retired token is kept until the chain's next token would lapse, to recognise a replay.
	store.records[hash] = record
	store.dirty = true
	return record, nil
}

// ------------------------------------------------------------------------------
// Helper: removes the records that match and returns how many; the caller holds store.mu.
func (store *refreshStore) revokeLocked(match func(refreshRecord) bool) int {
	count := 0
	for hash, record := range store.records {
		if match(record) {
			delete(store.records, hash)
			count++
		}
	}
	if count > 0 {
		store.dirty = true
	}
	return count
}

// ------------------------------------------------------------------------------
// Helper: revokeLogin revokes every refresh token of a login.
func (store *refreshStore) revokeLogin(login string) int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.revokeLocked(func(record refreshRecord) bool { return record.Login == login })
}

// ------------------------------------------------------------------------------
// Helper: how long an unused refresh token lasts (refresh_token_ttl_seconds, 7 days by default).
func (svc *service) refreshTTL() time.Duration {
	if svc.cfg.RefreshTokenTTLSeconds > 0 {
		return time.Duration(svc.cfg.RefreshTokenTTLSeconds) * time.Second
	}
	return defaultRefreshTTL
}

// ------------------------------------------------------------------------------
// TS 33.180 annex B.5.2 and B.5.3 (RFC 6749 section 6): refreshGrant is grant_type=refresh_token: new access and ID
// tokens, and the chain's next refresh token.
func (svc *service) refreshGrant(writer http.ResponseWriter, request *http.Request) {
	invalid := func() { writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_grant"}) }
	token := request.Form.Get("refresh_token")
	// RFC 6749 sections 5.2 and 6: the refresh_token parameter is REQUIRED ("invalid_request" without it).
	if token == "" {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if request.Form.Get("client_id") != svc.cfg.OAuthClientID {
		invalid()
		return
	}
	record, err := svc.refresh.use(token, svc.now())
	if errors.Is(err, errRefreshReplayed) {
		svc.logEvent("refresh_token_replayed", map[string]any{"user": record.Login})
	}
	if err != nil || record.ClientID != request.Form.Get("client_id") {
		invalid()
		return
	}
	// RFC 6749 section 6 and TS 33.180 table B.5.2-1: a narrower scope may be asked for, never a wider one (RFC 6749
	// section 5.2: "invalid_scope", the scope "exceeds the scope granted by the resource owner").
	scope := record.Scope
	if asked := request.Form.Get("scope"); asked != "" {
		for _, word := range strings.Fields(asked) {
			if !containsWord(record.Scope, word) {
				writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_scope"})
				return
			}
		}
		scope = asked
	}
	user, active, err := svc.currentUser(request, record)
	if err != nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	if !active {
		// Suspended, retired or removed: this sign-in is over for good.
		svc.refresh.revokeLogin(record.Login)
		svc.logEvent("refresh_refused", map[string]any{"user": record.Login, "reason": "account not active"})
		invalid()
		return
	}
	// Deviation from OpenID Connect Core 1.0 (errata set 2) section 12.2, a SHOULD NOT: the refreshed ID token
	// carries the nonce of the original authentication (the section allows it, the value then MUST be the
	// original one) because the OpenMCX clients check the nonce of every ID token they receive, refreshed ones
	// included (src/security/http.cpp oidc_refresh).
	svc.issueTokens(writer, user, scope, record.Nonce, refreshRecord{Chain: record.Chain, Login: record.Login, User: record.User,
		ClientID: record.ClientID, Scope: record.Scope, Nonce: record.Nonce})
}

// ------------------------------------------------------------------------------
// TS 33.180 annex B.5.3: currentUser is the refresh token's user as the accounts say now (the IdM server confirms
// that the account is still valid).
func (svc *service) currentUser(request *http.Request, record refreshRecord) (User, bool, error) {
	if svc.cfg.AdminAccounts != nil {
		managed, err := svc.lookupAccount(request.Context(), "login", record.Login)
		if errors.Is(err, errNoAccount) {
			return User{}, false, nil
		}
		if err != nil {
			return User{}, false, err
		}
		user := managed.user()
		// The MC client the tokens were issued for stays theirs while the account lists it.
		for _, id := range managed.ClientIDs {
			if id == record.User.ClientID {
				user.ClientID = id
			}
		}
		return user, managed.Status == "active" && user.MCPTTID == record.User.MCPTTID, nil
	}
	user, ok := svc.cfg.userByName(record.Login)
	return user, ok && user.MCPTTID == record.User.MCPTTID, nil
}

// ------------------------------------------------------------------------------
// TS 33.180 annex B.4.2.5 and B.5.3: issueTokens writes a token response: access and ID tokens and, for a chain,
// its next refresh token.
func (svc *service) issueTokens(writer http.ResponseWriter, user User, scope, nonce string, chain refreshRecord) {
	fail := func() { writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"}) }
	accessClaims, err := newClaims(svc.cfg, user, svc.cfg.ServerClientID, "access", "", svc.now())
	if err != nil {
		fail()
		return
	}
	accessClaims.Scope = scope
	idClaims, err := newClaims(svc.cfg, user, svc.cfg.OAuthClientID, "id", nonce, svc.now())
	if err != nil {
		fail()
		return
	}
	// The user signed in with a password (TS 33.180 table B.4.2.2-1); a refresh keeps the original acr.
	idClaims.ACR = acrPassword
	access, err := signToken(accessClaims, svc.signingKey)
	if err != nil {
		fail()
		return
	}
	id, err := signToken(idClaims, svc.signingKey)
	if err != nil {
		fail()
		return
	}
	chain.User = user
	refresh, err := svc.refresh.issue(chain, svc.now(), svc.refreshTTL())
	if err != nil {
		fail()
		return
	}
	// RFC 6749 section 5.1: "Cache-Control" no-store (writeJSON) and "Pragma" no-cache.
	writer.Header().Set("Pragma", "no-cache")
	writeJSON(writer, http.StatusOK, map[string]any{"access_token": access, "id_token": id, "refresh_token": refresh,
		"token_type": "Bearer", "expires_in": svc.cfg.TokenTTLSeconds})
}

// ------------------------------------------------------------------------------
// Not 3GPP (MCX Admin integration): revokeRefreshTokens is MCX Admin's Revoke devices at IdMS: the user's devices
// must sign in again (with the server client credentials).
func (svc *service) revokeRefreshTokens(writer http.ResponseWriter, request *http.Request) {
	username, password, ok := request.BasicAuth()
	if !ok || !secureEqual(username, svc.cfg.ServerClientID) || !secureEqual(password, svc.cfg.ServerSecret) {
		writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	login := request.PathValue("login")
	count := svc.refresh.revokeLogin(login)
	svc.saveRefreshTokens()
	svc.logEvent("refresh_tokens_revoked", map[string]any{"user": login, "count": count})
	writeJSON(writer, http.StatusOK, map[string]int{"revoked": count})
}
