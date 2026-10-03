// IdMS accounts managed by MCX Admin: the account lookup, the password verifiers and the one-time links on which a
// user sets a password (openMCX's own MCX Admin integration, not a 3GPP procedure; the OIDC flow of TS 24.482 is
// unchanged).
//
// Specifications: TS 24.482 V19.1.0 (Rel-19), RFC 8018, NIST SP 800-63B.
package common

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Accounts managed by MCX Admin. With
// admin_accounts configured, IdMS takes an account's status and identities from MCX
// Admin, keeps the account's password itself as a salted PBKDF2 verifier, and issues
// the one-time links on which a user sets or resets it. MCX Admin never sees a
// password. Without admin_accounts, IdMS works from site.json as before (file mode);
// either way the OIDC flow and its tokens are unchanged (TS 24.482).

// AdminAccountsConfig points IdMS at MCX Admin. IdMS and MCX Admin authenticate to
// each other with the server client credentials they share (server_client_id,
// server_secret); no other secret is involved.
type AdminAccountsConfig struct {
	URL         string `json:"url"`           // MCX Admin, e.g. https://mcxadmin:8443
	LinkBaseURL string `json:"link_base_url"` // this IdMS as users reach it, for the set-password links
	LinkTTL     int    `json:"link_ttl_seconds,omitempty"`
}

// account is what MCX Admin says about an account.
type account struct {
	Login     string   `json:"login"`
	Status    string   `json:"status"`
	MCID      string   `json:"mc_id"`
	MCPTTID   string   `json:"mcptt_id"`
	SIPURI    string   `json:"sip_uri"`
	ClientIDs []string `json:"client_ids"`
	MCDataID  string   `json:"mcdata_id"`
	MCVideoID string   `json:"mcvideo_id"`
}

// ------------------------------------------------------------------------------
// Helper: the user record of an account, with its first MC client ID.
func (managed account) user() User {
	user := User{Username: managed.Login, MCID: managed.MCID, MCPTTID: managed.MCPTTID, SIPURI: managed.SIPURI, MCDataID: managed.MCDataID, MCVideoID: managed.MCVideoID}
	if len(managed.ClientIDs) > 0 {
		user.ClientID = managed.ClientIDs[0]
	}
	return user
}

var errNoAccount = errors.New("no such account")

// ------------------------------------------------------------------------------
// Not 3GPP (MCX Admin integration): lookupAccount asks MCX Admin for an account by login or MCPTT ID.
func (svc *service) lookupAccount(ctx context.Context, key, value string) (account, error) {
	target := strings.TrimSuffix(svc.cfg.AdminAccounts.URL, "/") + "/internal/v1/accounts?" + url.Values{key: {value}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return account{}, err
	}
	req.SetBasicAuth(svc.cfg.ServerClientID, svc.cfg.ServerSecret)
	resp, err := svc.serviceClient.Do(req)
	if err != nil {
		return account{}, err
	}
	defer closeQuietly(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return account{}, errNoAccount
	}
	if resp.StatusCode != http.StatusOK {
		return account{}, fmt.Errorf("MCX Admin: status %d", resp.StatusCode)
	}
	var managed account
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&managed); err != nil {
		return account{}, err
	}
	return managed, nil
}

// --- Password verifiers (NIST SP 800-63B: salted, adaptive; PBKDF2-HMAC-SHA256) ---

const pbkdf2Iterations = 600000

// ------------------------------------------------------------------------------
// Helper: a salted PBKDF2-HMAC-SHA256 (RFC 8018) verifier of a password, as
// $pbkdf2-sha256$<iterations>$<salt>$<key>.
func newVerifier(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations, base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// ------------------------------------------------------------------------------
// Helper: checkPassword checks a password against a verifier, or, for the lab's site.json in file mode, against a
// stored plain password.
func checkPassword(stored, password string) bool {
	if !strings.HasPrefix(stored, "$pbkdf2-sha256$") {
		return stored != "" && secureEqual(stored, password)
	}
	parts := strings.Split(stored, "$")
	if len(parts) != 5 {
		return false
	}
	iterations, err := strconv.Atoi(parts[2])
	if err != nil || iterations < 1 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[3])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[4])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// --- IdMS's own credential file: verifiers and pending links, in its data directory ---

type credentialLink struct {
	Login   string    `json:"login"`
	Purpose string    `json:"purpose"`
	Expires time.Time `json:"expires"`
}

type credentialFile struct {
	Verifiers map[string]string         `json:"verifiers"` // by login
	Links     map[string]credentialLink `json:"links"`     // by SHA-256 of the link token
}

type credentials struct {
	mu   sync.Mutex
	path string
	// Failed sign-ins by login, and until when a login is locked after too many.
	failures map[string]int
	locked   map[string]time.Time
}

// ------------------------------------------------------------------------------
// Helper: IdMS's credentials, kept in its data directory.
func newCredentials(dataDir string) *credentials {
	return &credentials{path: filepath.Join(dataDir, "idms-credentials.json"), failures: map[string]int{}, locked: map[string]time.Time{}}
}

// ------------------------------------------------------------------------------
// Helper: reads IdMS's credential file (verifiers and pending links); a missing file is an empty one.
func (store *credentials) load() (credentialFile, error) {
	file := credentialFile{Verifiers: map[string]string{}, Links: map[string]credentialLink{}}
	raw, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return file, nil
	}
	if err != nil {
		return file, err
	}
	err = json.Unmarshal(raw, &file)
	if file.Verifiers == nil {
		file.Verifiers = map[string]string{}
	}
	if file.Links == nil {
		file.Links = map[string]credentialLink{}
	}
	return file, err
}

// ------------------------------------------------------------------------------
// Helper: writes IdMS's credential file atomically (by rename).
func (store *credentials) save(file credentialFile) error {
	raw, err := json.Marshal(file)
	if err != nil {
		return err
	}
	return writeFileAtomic(store.path, raw)
}

const (
	maxFailures  = 10
	lockDuration = 15 * time.Minute
)

// ------------------------------------------------------------------------------
// Helper: verify checks a login's password, with a lock after repeated failures.
func (store *credentials) verify(login, password string, now time.Time) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	if until, ok := store.locked[login]; ok && now.Before(until) {
		return false
	}
	file, err := store.load()
	if err != nil {
		return false
	}
	if checkPassword(file.Verifiers[login], password) {
		delete(store.failures, login)
		return true
	}
	store.failures[login]++
	if store.failures[login] >= maxFailures {
		store.locked[login] = now.Add(lockDuration)
		store.failures[login] = 0
	}
	return false
}

// ------------------------------------------------------------------------------
// Helper: the SHA-256 (hex) under which a link token or refresh token is stored.
func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// --- Endpoints ---

// ------------------------------------------------------------------------------
// Not 3GPP (MCX Admin integration): the routes of the password links in admin mode.
func (svc *service) routesAdminAccounts(mux *http.ServeMux) {
	mux.HandleFunc("POST /internal/password-links", svc.passwordLink)
	mux.HandleFunc("GET /set-password", svc.setPasswordForm)
	mux.HandleFunc("POST /set-password", svc.setPassword)
}

// ------------------------------------------------------------------------------
// Not 3GPP (MCX Admin integration): passwordLink issues a one-time link on which the user of an account sets its
// password (purpose "set") or resets it ("reset"). Only MCX Admin, with the server client credentials, may ask; the
// link is returned once and stored only as a hash.
func (svc *service) passwordLink(writer http.ResponseWriter, request *http.Request) {
	username, password, ok := request.BasicAuth()
	if !ok || !secureEqual(username, svc.cfg.ServerClientID) || !secureEqual(password, svc.cfg.ServerSecret) {
		writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req struct {
		Login   string `json:"login"`
		Purpose string `json:"purpose"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 4096)).Decode(&req); err != nil || (req.Purpose != "set" && req.Purpose != "reset") {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	managed, err := svc.lookupAccount(request.Context(), "login", req.Login)
	if errors.Is(err, errNoAccount) || (err == nil && managed.Status == "retired") {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "no_such_account"})
		return
	}
	if err != nil {
		writeJSON(writer, http.StatusBadGateway, map[string]string{"error": "accounts_unavailable"})
		return
	}
	token, err := randomID()
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	ttl := time.Duration(svc.cfg.AdminAccounts.LinkTTL) * time.Second
	if ttl <= 0 {
		ttl = 72 * time.Hour
	}
	expires := svc.now().Add(ttl)
	svc.credentials.mu.Lock()
	file, err := svc.credentials.load()
	if err == nil {
		for hash, link := range file.Links { // one pending link per account; expired ones go too
			if link.Login == managed.Login || !link.Expires.After(svc.now()) {
				delete(file.Links, hash)
			}
		}
		file.Links[tokenHash(token)] = credentialLink{Login: managed.Login, Purpose: req.Purpose, Expires: expires}
		err = svc.credentials.save(file)
	}
	svc.credentials.mu.Unlock()
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	link := strings.TrimSuffix(svc.cfg.AdminAccounts.LinkBaseURL, "/") + "/set-password?token=" + url.QueryEscape(token)
	svc.logEvent("password_link_issued", map[string]any{"user": managed.Login, "purpose": req.Purpose, "expires": expires.Unix()})
	writeJSON(writer, http.StatusOK, map[string]any{"url": link, "expires": expires.Unix()})
}

var setPasswordPage = template.Must(template.New("p").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>openMCX: set your password</title>
<style>body{font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem}
input{display:block;width:100%;margin:.4rem 0 1rem;padding:.5rem}button{padding:.5rem 1rem}</style></head>
<body><h1>openMCX</h1>{{if .Message}}<p>{{.Message}}</p>{{end}}{{if .Token}}
<form method="post" action="set-password"><input type="hidden" name="token" value="{{.Token}}">
<p>Account <strong>{{.Login}}</strong>. At least 12 characters.</p>
<label>New password<input type="password" name="password" autocomplete="new-password" minlength="12" required></label>
<label>Repeat it<input type="password" name="confirm" autocomplete="new-password" minlength="12" required></label>
<button type="submit">Set password</button></form>{{end}}</body></html>`))

// ------------------------------------------------------------------------------
// Helper: the pending, unexpired link of a link token.
func (svc *service) pendingLink(token string) (credentialLink, bool) {
	svc.credentials.mu.Lock()
	defer svc.credentials.mu.Unlock()
	file, err := svc.credentials.load()
	if err != nil {
		return credentialLink{}, false
	}
	link, ok := file.Links[tokenHash(token)]
	return link, ok && link.Expires.After(svc.now())
}

// ------------------------------------------------------------------------------
// Not 3GPP (MCX Admin integration): the set-password form of a pending link.
func (svc *service) setPasswordForm(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	token := request.URL.Query().Get("token")
	link, ok := svc.pendingLink(token)
	if !ok {
		writer.WriteHeader(http.StatusNotFound)
		_ = setPasswordPage.Execute(writer, map[string]string{"Message": "This link is not valid: it was used or has expired. Ask your administrator for a new one."})
		return
	}
	_ = setPasswordPage.Execute(writer, map[string]string{"Token": token, "Login": link.Login})
}

// ------------------------------------------------------------------------------
// Not 3GPP (MCX Admin integration): sets the password of a pending link's account: stores its verifier and uses the
// link up in one write, lifts the sign-in lock and revokes the account's refresh tokens.
func (svc *service) setPassword(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if err := parseForm(writer, request); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	token, password := request.Form.Get("token"), request.Form.Get("password")
	link, ok := svc.pendingLink(token)
	page := map[string]string{"Token": token, "Login": link.Login}
	switch {
	case !ok:
		writer.WriteHeader(http.StatusNotFound)
		_ = setPasswordPage.Execute(writer, map[string]string{"Message": "This link is not valid: it was used or has expired."})
		return
	case len(password) < 12 || len(password) > 256:
		page["Message"] = "The password must have 12 to 256 characters."
	case password != request.Form.Get("confirm"):
		page["Message"] = "The two passwords differ."
	}
	if page["Message"] != "" {
		writer.WriteHeader(http.StatusBadRequest)
		_ = setPasswordPage.Execute(writer, page)
		return
	}
	verifier, err := newVerifier(password)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	svc.credentials.mu.Lock()
	file, err := svc.credentials.load()
	used := false
	if err == nil {
		// The link is used once: removed with the same write that stores the verifier.
		if current, still := file.Links[tokenHash(token)]; !still || current.Login != link.Login {
			used = true
		} else {
			delete(file.Links, tokenHash(token))
			file.Verifiers[link.Login] = verifier
			err = svc.credentials.save(file)
		}
	}
	if err == nil && !used {
		// Only a password that was stored lifts the sign-in lock.
		delete(svc.credentials.failures, link.Login)
		delete(svc.credentials.locked, link.Login)
	}
	svc.credentials.mu.Unlock()
	if used {
		writer.WriteHeader(http.StatusConflict)
		_ = setPasswordPage.Execute(writer, map[string]string{"Message": "This link is not valid any more."})
		return
	}
	if err != nil {
		svc.logEvent("password_set_failed", map[string]any{"user": link.Login, "error": err.Error()})
		writer.WriteHeader(http.StatusInternalServerError)
		_ = setPasswordPage.Execute(writer, map[string]string{"Message": "The password could not be stored. Try again later."})
		return
	}
	// A new password ends the sessions the old one started (their refresh tokens).
	svc.refresh.revokeLogin(link.Login)
	svc.saveRefreshTokens()
	svc.logEvent("password_set", map[string]any{"user": link.Login, "purpose": link.Purpose})
	_ = setPasswordPage.Execute(writer, map[string]string{"Message": "Your password is set. You can sign in now."})
}

// ------------------------------------------------------------------------------
// TS 24.482 clause 6.3.1: adminLogin is the login check in admin mode: an active account with its password.
func (svc *service) adminLogin(request *http.Request, login, password string) (User, bool) {
	managed, err := svc.lookupAccount(request.Context(), "login", login)
	if err != nil || managed.Status != "active" {
		// The password is still checked, so that a refusal takes as long either way.
		svc.credentials.verify(login, password, svc.now())
		return User{}, false
	}
	if !svc.credentials.verify(managed.Login, password, svc.now()) {
		return User{}, false
	}
	return managed.user(), true
}

// ------------------------------------------------------------------------------
// Not 3GPP (MCX Admin integration): accountActive says whether the account of an MCPTT ID is active in MCX Admin: a
// suspended account's tokens stop being active at once.
func (svc *service) accountActive(ctx context.Context, mcpttID string) bool {
	managed, err := svc.lookupAccount(ctx, "mcptt_id", mcpttID)
	return err == nil && managed.Status == "active"
}
