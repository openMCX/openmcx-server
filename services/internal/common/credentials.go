//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The Credential Service of the accounts managed by MCX Admin: SIP digest credentials issued to signed-in clients,
// and suspended, resumed or retired on MCX Admin's request (OpenMCX's own MCX Admin integration, not a 3GPP
// procedure).
//
// Specifications: TS 29.228 V19.2.0, TS 33.180 V19.4.0 (Rel-19); RFC 2617, RFC 6750.
package common

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// The Credential Service: it owns the
// SIP digest credentials of managed accounts. A client signed in at IdMS obtains its
// SIP credential here, once per request, and the service writes it into the SIP
// core's subscriber table as digest hashes only (HA1 = MD5(user:realm:password) and
// HA1b with user@domain, RFC 2617 section 3.2.2.2): the password is in the answer alone. MCX Admin never sees one: after each revision it only
// tells this service which accounts to suspend, resume or retire. A suspended
// account's row is moved to subscriber_suspended, so the SIP core refuses its
// REGISTER (the standard 401), and moved back on resume.

// CredentialsConfig configures the credentials role.
type CredentialsConfig struct {
	// A file holding the DSN of a database user limited to the subscriber tables.
	MySQLDSNFile string `json:"mysql_dsn_file"`
	// Device certificates (slice F2): the issuing CA's certificate and key (PEM), and
	// how long a certificate lasts (certificate_days, 30 when absent: default pending
	// maintainer choice (no spec value)); without them no certificate is issued.
	IssuerCertFile  string `json:"issuer_cert_file,omitempty"`
	IssuerKeyFile   string `json:"issuer_key_file,omitempty"`
	CertificateDays int    `json:"certificate_days,omitempty"`
	// OpenMCX's own CA, whose validity and issue periods are local policy (RFC 5280 section 3.3: CRLs are issued
	// periodically, at an interval the CA chooses; section 5.1.2.5: nextUpdate is the issuer's), with defaults pending
	// maintainer choice (no spec value): certificate_backdate_s, how far an issued certificate's notBefore lies
	// before its issue (300 s when absent); crl_validity_days, the time from a CRL's issue to its nextUpdate (30
	// days); crl_refresh_hours, how often the CRL is issued again (24 hours); crl_clock_skew_s, how far its
	// thisUpdate lies before its issue (300 s). The backdate and skew allow for verifiers whose clock is behind.
	CertificateBackdateS *int `json:"certificate_backdate_s,omitempty"`
	CRLValidityDays      int  `json:"crl_validity_days,omitempty"`
	CRLRefreshHours      int  `json:"crl_refresh_hours,omitempty"`
	CRLClockSkewS        *int `json:"crl_clock_skew_s,omitempty"`
	// The revocation list the SIP core reads (crl in its tls.cfg), rewritten on a
	// revocation, and the SIP core's operator RPC that reloads it (tls.reload), called
	// with this service's certificate (client_cert_file, client_key_file, ca_file).
	CRLFile        string `json:"crl_file,omitempty"`
	SIPCoreRPC     string `json:"sip_core_rpc,omitempty"`
	ClientCertFile string `json:"client_cert_file,omitempty"`
	ClientKeyFile  string `json:"client_key_file,omitempty"`
	CAFile         string `json:"ca_file,omitempty"`
}

type credentialStore struct {
	db     *sql.DB
	issuer *deviceIssuer
	cfg    *CredentialsConfig
	rpc    *http.Client
}

// ------------------------------------------------------------------------------
// Helper: opens the SIP core's subscriber database (its DSN read from a file) and, when configured, the device
// certificate issuer and the client for the SIP core's operator RPC.
func openCredentialStore(cfg *CredentialsConfig) (*credentialStore, error) {
	if cfg == nil || cfg.MySQLDSNFile == "" {
		return nil, errors.New("the credentials role needs credentials.mysql_dsn_file")
	}
	raw, err := os.ReadFile(cfg.MySQLDSNFile)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("mysql", strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, err
	}
	db.SetConnMaxLifetime(5 * time.Minute)
	store := &credentialStore{db: db, cfg: cfg}
	if cfg.IssuerCertFile != "" || cfg.IssuerKeyFile != "" {
		if store.issuer, err = loadDeviceIssuer(cfg); err != nil {
			return nil, err
		}
	}
	if cfg.SIPCoreRPC != "" {
		if store.rpc, err = rpcClient(cfg); err != nil {
			return nil, err
		}
	}
	return store, nil
}

const subscriberColumns = "username, domain, password, ha1, ha1b"

// ------------------------------------------------------------------------------
// Not 3GPP (MCX Admin integration): the Credential Service's routes: SIP credentials and device certificates for
// signed-in clients, and MCX Admin's internal requests.
func (svc *service) routesCredentials(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/sip-credential", svc.issueSIPCredential)
	mux.HandleFunc("POST /internal/sip-credentials/{login}/{action}", svc.changeSIPCredential)
	mux.HandleFunc("POST /v1/client-certificate", svc.issueClientCertificate)
	mux.HandleFunc("POST /internal/client-certificates/{login}/revoke", svc.revokeDevices)
}

// ------------------------------------------------------------------------------
// Not 3GPP (MCX Admin integration): issueSIPCredential gives the signed-in user (RFC 6750 bearer access token) a
// new SIP password for its SIP identity, replacing any previous one. The password is in this answer only.
func (svc *service) issueSIPCredential(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok {
		return
	}
	if svc.cfg.AdminAccounts != nil && !svc.accountActive(request.Context(), claims.MCPTTID) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "account_not_active"})
		return
	}
	username, domain, ok := strings.Cut(strings.TrimPrefix(claims.SIPURI, "sip:"), "@")
	if !ok || username == "" || domain != svc.cfg.Domain || !strings.HasPrefix(claims.SIPURI, "sip:") {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "no_sip_identity"})
		return
	}
	// TS 33.180 clause 6.2.1 and TS 29.228 clause 6.3.1 step 4: an identity provisioned for IMS AKA authenticates
	// with IMS AKA only; a digest credential issued for it would let a holder of the access token fall back to SIP
	// digest.
	aka, err := svc.creds.akaIdentity(request.Context(), claims.SIPURI, username+"@"+domain)
	if err != nil {
		svc.logEvent("sip_credential_failed", map[string]any{"user": username, "error": err.Error()})
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "store_unavailable"})
		return
	}
	if aka {
		svc.logEvent("sip_credential_refused", map[string]any{"user": username, "reason": "aka_identity"})
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "aka_identity"})
		return
	}
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	password := hex.EncodeToString(secret)
	if err := svc.creds.set(request.Context(), username, domain, password); err != nil {
		svc.logEvent("sip_credential_failed", map[string]any{"user": username, "error": err.Error()})
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "store_unavailable"})
		return
	}
	svc.logEvent("sip_credential_issued", map[string]any{"user": username})
	writeJSON(writer, http.StatusOK, map[string]string{"username": username, "domain": domain, "identity": claims.SIPURI, "password": password})
}

// ------------------------------------------------------------------------------
// TS 29.228 clause 6.3.1 step 4: whether the SIP database holds an IMS AKA subscription for the public user
// identity or the private user identity (the SIP core's ims_subscription table, tools/provision.py). A database
// without that table, or one that does not let this service read it, holds no AKA subscription for it: the SIP
// core refuses digest for an AKA identity itself as well.
func (store *credentialStore) akaIdentity(ctx context.Context, impu, impi string) (bool, error) {
	var rows int
	err := store.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM ims_subscription WHERE auth_scheme = 'aka' AND (impu = ? OR impi = ?)`, impu, impi).Scan(&rows)
	if noSubscriptionTable(err) {
		return false, nil
	}
	return rows > 0, err
}

// ------------------------------------------------------------------------------
// Helper: whether a MySQL error says that the ims_subscription table does not exist (1146) or is not granted to
// this service's database user (1142), as in a deployment without IMS AKA subscriptions.
func noSubscriptionTable(err error) bool {
	var mysqlErr *mysql.MySQLError
	return errors.As(err, &mysqlErr) && (mysqlErr.Number == 1146 || mysqlErr.Number == 1142)
}

// ------------------------------------------------------------------------------
// RFC 2617 section 3.2.2.2: stores a SIP credential as its digest hashes HA1 and HA1b only, and ends any suspension
// of the account.
func (store *credentialStore) set(ctx context.Context, username, domain, password string) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // after a Commit, Rollback does nothing
	if _, err := tx.ExecContext(ctx, `DELETE FROM subscriber_suspended WHERE username = ? AND domain = ?`, username, domain); err != nil {
		return err
	}
	ha1, ha1b := digestHA1(username, domain, password), digestHA1(username+"@"+domain, domain, password)
	if _, err := tx.ExecContext(ctx, `INSERT INTO subscriber (username, domain, password, ha1, ha1b) VALUES (?, ?, '', ?, ?)
		ON DUPLICATE KEY UPDATE password = '', ha1 = VALUES(ha1), ha1b = VALUES(ha1b)`, username, domain, ha1, ha1b); err != nil {
		return err
	}
	return tx.Commit()
}

// ------------------------------------------------------------------------------
// Not 3GPP (MCX Admin integration): changeSIPCredential suspends, resumes or retires an account's SIP credential.
// Only MCX Admin, with the server client credentials, may ask; the answer carries no credential. Each action is
// idempotent.
func (svc *service) changeSIPCredential(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	login, action := request.PathValue("login"), request.PathValue("action")
	var moves []string
	switch action {
	case "suspend":
		moves = []string{
			`INSERT IGNORE INTO subscriber_suspended (` + subscriberColumns + `) SELECT ` + subscriberColumns + ` FROM subscriber WHERE username = ? AND domain = ?`,
			`DELETE FROM subscriber WHERE username = ? AND domain = ?`}
	case "resume":
		moves = []string{
			`INSERT IGNORE INTO subscriber (` + subscriberColumns + `) SELECT ` + subscriberColumns + ` FROM subscriber_suspended WHERE username = ? AND domain = ?`,
			`DELETE FROM subscriber_suspended WHERE username = ? AND domain = ?`}
	case "retire":
		moves = []string{`DELETE FROM subscriber WHERE username = ? AND domain = ?`,
			`DELETE FROM subscriber_suspended WHERE username = ? AND domain = ?`}
	default:
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "unknown_action"})
		return
	}
	tx, err := svc.creds.db.BeginTx(request.Context(), nil)
	if err == nil {
		defer func() { _ = tx.Rollback() }() // after a Commit, Rollback does nothing
		for _, stmt := range moves {
			if _, err = tx.ExecContext(request.Context(), stmt, login, svc.cfg.Domain); err != nil {
				break
			}
		}
		if err == nil {
			err = tx.Commit()
		}
	}
	if err != nil {
		svc.logEvent("sip_credential_change_failed", map[string]any{"user": login, "action": action, "error": err.Error()})
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "store_unavailable"})
		return
	}
	svc.logEvent("sip_credential_"+action, map[string]any{"user": login})
	writeJSON(writer, http.StatusOK, map[string]string{"user": login, "action": action})
}

// ------------------------------------------------------------------------------
// RFC 2617 section 3.2.2.2: digestHA1 is the stored digest secret, the realm being the SIP core's domain.
func digestHA1(user, realm, password string) string {
	sum := md5.Sum([]byte(user + ":" + realm + ":" + password))
	return hex.EncodeToString(sum[:])
}
