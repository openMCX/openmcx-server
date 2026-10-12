//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Device certificates: the TLS client certificates the SIP core requires, issued for a PKCS#10 request of a
// signed-in client and revoked with a CRL (OpenMCX's own MCX Admin integration, not a 3GPP procedure).
//
// Specifications: RFC 5280, RFC 2986, RFC 6750.
package common

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Device certificates: a client that
// activates gets the TLS client certificate the SIP core requires (require_certificate,
// the system CA in ca_list) for a key it made itself. Only the public key of its
// request is used: the certificate names "mcx-device <MC client ID>", never a server's
// name (which the SIP core and the services recognise servers by), with the client ID
// and the SIP URI as URI subject alternative names (the client ID only when it is a URI) and no DNS name. The issuing key is the
// system CA's, mounted by this service alone (production: an issuing CA in an HSM).

type deviceIssuer struct {
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer
	days    int
}

// ------------------------------------------------------------------------------
// Helper: loads the issuing CA's certificate and key (PKCS#8, PKCS#1 or EC) and the lifetime of the certificates it
// issues (30 days by default).
func loadDeviceIssuer(cfg *CredentialsConfig) (*deviceIssuer, error) {
	certPEM, err := os.ReadFile(cfg.IssuerCertFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("credentials.issuer_cert_file: no PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(cfg.IssuerKeyFile)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("credentials.issuer_key_file: no PEM key")
	}
	var key any
	if key, err = x509.ParsePKCS8PrivateKey(kb.Bytes); err != nil {
		if key, err = x509.ParsePKCS1PrivateKey(kb.Bytes); err != nil {
			if key, err = x509.ParseECPrivateKey(kb.Bytes); err != nil {
				return nil, errors.New("credentials.issuer_key_file: not a PKCS#8, PKCS#1 or EC key")
			}
		}
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("credentials.issuer_key_file: not a signing key")
	}
	days := cfg.CertificateDays
	if days <= 0 {
		days = 30
	}
	return &deviceIssuer{cert: cert, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}), key: signer, days: days}, nil
}

// ------------------------------------------------------------------------------
// Helper: acceptableDeviceKey: EC P-256 or P-384, or RSA of at least 2048 bits.
func acceptableDeviceKey(key any) bool {
	switch publicKey := key.(type) {
	case *ecdsa.PublicKey:
		return publicKey.Curve == elliptic.P256() || publicKey.Curve == elliptic.P384()
	case *rsa.PublicKey:
		return publicKey.N.BitLen() >= 2048
	}
	return false
}

// ------------------------------------------------------------------------------
// Not 3GPP (MCX Admin integration): issueClientCertificate answers a signed-in user's (RFC 6750 bearer access
// token) PKCS#10 request (RFC 2986; PEM, or DER as application/pkcs10) with a certificate (RFC 5280) for its key,
// the issuer's certificate and the expiry. The account must be active; the request's subject is not used.
func (svc *service) issueClientCertificate(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok {
		return
	}
	if svc.creds.issuer == nil {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "certificates_not_issued_here"})
		return
	}
	if svc.cfg.AdminAccounts != nil && !svc.accountActive(request.Context(), claims.MCPTTID) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "account_not_active"})
		return
	}
	username, domain, ok := strings.Cut(strings.TrimPrefix(claims.SIPURI, "sip:"), "@")
	if !ok || username == "" || domain != svc.cfg.Domain || claims.ClientID == "" {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "no_client_identity"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, 16<<10))
	if err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}
	csr, err := x509.ParseCertificateRequest(raw)
	if err != nil || csr.CheckSignature() != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_certificate_request"})
		return
	}
	if !acceptableDeviceKey(csr.PublicKey) {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "unsupported_key"})
		return
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	now := svc.now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "mcx-device " + claims.ClientID},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(time.Duration(svc.creds.issuer.days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// Client authentication, and server authentication for a listening client the
		// SIP core connects to (its TLS client checks the purpose); no DNS name, so it
		// cannot stand for a server's host.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if _, isRSA := csr.PublicKey.(*rsa.PublicKey); isRSA {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	for _, id := range []string{claims.ClientID, claims.SIPURI} {
		if uri, err := url.Parse(id); err == nil && uri.Scheme != "" {
			template.URIs = append(template.URIs, uri)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, svc.creds.issuer.cert, csr.PublicKey, svc.creds.issuer.key)
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	serialHex := hex.EncodeToString(serial.Bytes())
	if _, err := svc.creds.db.ExecContext(request.Context(), `INSERT INTO client_certificates (serial, username, domain, client_id, not_after, issued_at)
		VALUES (?, ?, ?, ?, ?, ?)`, serialHex, username, domain, claims.ClientID, template.NotAfter.UTC(), now.UTC()); err != nil {
		svc.logEvent("client_certificate_failed", map[string]any{"user": username, "error": err.Error()})
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "store_unavailable"})
		return
	}
	svc.logEvent("client_certificate_issued", map[string]any{"user": username, "client_id": claims.ClientID, "serial": serialHex,
		"not_after": template.NotAfter.Unix()})
	writeJSON(writer, http.StatusOK, map[string]any{
		"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"issuer":      string(svc.creds.issuer.certPEM),
		"not_after":   template.NotAfter.Unix(),
		"serial":      serialHex,
	})
}

// ------------------------------------------------------------------------------
// Not 3GPP (MCX Admin integration): revokeDevices is Revoke devices, for a lost or stolen device (MCX Admin, with
// the server client credentials): the account's certificates are recorded revoked and its SIP credential removed,
// so no device of it registers until one activates again: the new revocation list is published and the SIP core
// asked to reload it (publishCRL), and the SIP credential's removal stops a device whose TLS connection is open.
func (svc *service) revokeDevices(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	login := request.PathValue("login")
	tx, err := svc.creds.db.BeginTx(request.Context(), nil)
	var revoked int64
	if err == nil {
		defer func() { _ = tx.Rollback() }() // after a Commit, Rollback does nothing
		var res interface{ RowsAffected() (int64, error) }
		res, err = tx.ExecContext(request.Context(), `UPDATE client_certificates SET revoked_at = ? WHERE username = ? AND domain = ? AND revoked_at IS NULL`,
			svc.now().UTC(), login, svc.cfg.Domain)
		if err == nil {
			revoked, err = res.RowsAffected()
		}
		if err == nil {
			for _, table := range []string{"subscriber", "subscriber_suspended"} {
				if _, err = tx.ExecContext(request.Context(), `DELETE FROM `+table+` WHERE username = ? AND domain = ?`, login, svc.cfg.Domain); err != nil {
					break
				}
			}
		}
		if err == nil {
			err = tx.Commit()
		}
	}
	if err != nil {
		svc.logEvent("devices_revoke_failed", map[string]any{"user": login, "error": err.Error()})
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "store_unavailable"})
		return
	}
	svc.logEvent("devices_revoked", map[string]any{"user": login, "certificates": revoked})
	if revoked > 0 {
		if err := svc.publishCRL(request.Context()); err != nil {
			svc.logEvent("crl_failed", map[string]any{"error": err.Error()})
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{"user": login, "certificates_revoked": revoked, "sip_credential": "removed"})
}

// ---- the revocation list (slice F2) ----

// ------------------------------------------------------------------------------
// Helper: the HTTPS client (system CA, this service's client certificate) for the SIP core's operator RPC.
func rpcClient(cfg *CredentialsConfig) (*http.Client, error) {
	pool := x509.NewCertPool()
	if cfg.CAFile != "" {
		raw, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(raw) {
			return nil, errors.New("credentials.ca_file: no PEM certificate")
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	if cfg.ClientCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: transport}, nil
}

// OpenMCX: the revocation list is valid for crlValidity (RFC 5280 section 5.1.2.5 nextUpdate), refreshed every
// crlRefresh, and dated crlClockSkew back for verifiers whose clock is behind.
const (
	crlValidity  = 30 * 24 * time.Hour
	crlRefresh   = 24 * time.Hour
	crlClockSkew = 5 * time.Minute
)

// ------------------------------------------------------------------------------
// RFC 5280 section 5.1.2.6: the revoked device certificates that have not expired. A serial number that does not
// parse (a damaged row) is logged and left out: the list of the others is still published.
func (svc *service) revokedCertificates(ctx context.Context, now time.Time) ([]x509.RevocationListEntry, error) {
	// Times as Unix seconds: the DSN need not ask the driver to parse DATETIME.
	rows, err := svc.creds.db.QueryContext(ctx, `SELECT serial, UNIX_TIMESTAMP(revoked_at) FROM client_certificates WHERE revoked_at IS NOT NULL AND not_after > ?`, now)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }() // rows.Err below reports what matters
	var entries []x509.RevocationListEntry
	for rows.Next() {
		var serial string
		var seconds float64
		if err := rows.Scan(&serial, &seconds); err != nil {
			return nil, err
		}
		serialNumber, ok := new(big.Int).SetString(serial, 16)
		if !ok {
			svc.logEvent("crl_bad_serial", map[string]any{"serial": serial})
			continue
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: serialNumber, RevocationTime: time.Unix(int64(seconds), 0).UTC()})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// ------------------------------------------------------------------------------
// RFC 5280 section 5: publishCRL writes the revocation list of the device certificates revoked and not yet expired,
// signed with the issuing CA's key, and has the SIP core reload it.
func (svc *service) publishCRL(ctx context.Context) error {
	store := svc.creds
	if store.issuer == nil || store.cfg.CRLFile == "" {
		return nil
	}
	now := svc.now().UTC()
	entries, err := svc.revokedCertificates(ctx, now)
	if err != nil {
		return err
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(now.UnixNano()), ThisUpdate: now.Add(-crlClockSkew), NextUpdate: now.Add(crlValidity),
		RevokedCertificateEntries: entries}, store.issuer.cert, store.issuer.key)
	if err != nil {
		return err
	}
	// The CRL is public: the SIP core reads it.
	if err := writeFileAtomicMode(store.cfg.CRLFile, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o644); err != nil {
		return err
	}
	svc.logEvent("crl_published", map[string]any{"revoked": len(entries)})
	if store.rpc == nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, store.cfg.SIPCoreRPC, strings.NewReader(`{"jsonrpc":"2.0","method":"tls.reload","id":1}`))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := store.rpc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() // read already: closing loses nothing
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("tls.reload: %w", err)
	}
	if resp.StatusCode != http.StatusOK || strings.Contains(string(body), `"error"`) {
		return errors.New("tls.reload: " + resp.Status + " " + strings.TrimSpace(string(body)))
	}
	return nil
}

// ------------------------------------------------------------------------------
// RFC 5280 section 5: refreshCRL keeps the list current: at start, and daily, before its next update.
func (svc *service) refreshCRL(ctx context.Context) {
	for {
		if err := svc.publishCRL(ctx); err != nil {
			svc.logEvent("crl_failed", map[string]any{"error": err.Error()})
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(crlRefresh):
		}
	}
}
