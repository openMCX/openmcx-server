package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ------------------------------------------------------------------------------
// The Credential Service (OpenMCX's own MCX Admin integration, not a 3GPP procedure) against a MySQL
// (MCX_TEST_MYSQL: a DSN without a database, e.g. root:pw@tcp(mysql:3306)/), with the SIP core's subscriber table:
// SIP digest credentials issued to a signed-in client (RFC 6750) and stored as their digest hash only (RFC 2617
// section 3.2.2.2), replaced, suspended, resumed and retired on MCX Admin's request; then device certificates
// (slice F2) issued for a PKCS#10 request (RFC 2986) and revoked with a CRL (RFC 5280).
func TestCredentialService(test *testing.T) {
	dsn := os.Getenv("MCX_TEST_MYSQL")
	if dsn == "" {
		test.Skip("MCX_TEST_MYSQL not set")
	}
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	name := "t_" + hex.EncodeToString(suffix)
	root, err := sql.Open("mysql", dsn)
	if err != nil {
		test.Fatal(err)
	}
	for _, stmt := range []string{"CREATE DATABASE " + name,
		"CREATE TABLE " + name + ".subscriber (id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, username VARCHAR(64) NOT NULL, domain VARCHAR(64) NOT NULL, password VARCHAR(64) NOT NULL, ha1 VARCHAR(128) NOT NULL DEFAULT '', ha1b VARCHAR(128) NOT NULL DEFAULT '', UNIQUE(username,domain))",
		"CREATE TABLE " + name + ".subscriber_suspended LIKE " + name + ".subscriber",
		"CREATE TABLE " + name + ".client_certificates (serial VARCHAR(64) PRIMARY KEY, username VARCHAR(64) NOT NULL, domain VARCHAR(64) NOT NULL, " +
			"client_id VARCHAR(255) NOT NULL, not_after DATETIME NOT NULL, issued_at DATETIME NOT NULL, revoked_at DATETIME NULL)"} {
		if _, err := root.Exec(stmt); err != nil {
			test.Fatal(err)
		}
	}
	test.Cleanup(func() { _, _ = root.Exec("DROP DATABASE " + name); closeQuietly(root) })
	dsnFile := filepath.Join(test.TempDir(), "dsn")
	_ = os.WriteFile(dsnFile, []byte(strings.Replace(dsn, ")/", ")/"+name, 1)), 0o600)
	cfg := testConfig()
	cfg.Users[0].SIPURI = "sip:alice@mcx.test" // the lab's form: the SIP core's domain
	cfg.Credentials = &CredentialsConfig{MySQLDSNFile: dsnFile}
	key := testKey(test)
	handler, err := NewHandler(RoleCredentials, cfg, key, test.TempDir(), WithClock(func() time.Time { return testNow }), WithContext(test.Context()))
	if err != nil {
		test.Fatal(err)
	}
	issue := func(token string) (int, map[string]string) {
		req := httptest.NewRequest(http.MethodPost, "/v1/sip-credential", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		var out map[string]string
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}
	if code, _ := issue(""); code != http.StatusForbidden {
		test.Fatalf("without a token: %d", code)
	}
	code, cred := issue(tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID))
	if code != http.StatusOK || cred["username"] != "alice" || cred["domain"] != "mcx.test" || len(cred["password"]) != 40 {
		test.Fatalf("issue %d %v", code, cred)
	}
	db, _ := sql.Open("mysql", strings.Replace(dsn, ")/", ")/"+name, 1))
	defer closeQuietly(db)
	// Only the digest hash is stored, never the password (RFC 2617 section 3.2.2.2).
	count := func(table string) (rows int) {
		_ = db.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE username = 'alice' AND password = '' AND ha1 = ?",
			digestHA1("alice", "mcx.test", cred["password"])).Scan(&rows)
		return
	}
	if count("subscriber") != 1 {
		test.Fatal("the credential is not in the subscriber table")
	}
	// A second issue replaces the first.
	_, again := issue(tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID))
	if again["password"] == cred["password"] || count("subscriber") != 0 {
		test.Fatal("a new credential did not replace the old")
	}
	cred = again
	change := func(action, user, pw string) int {
		req := httptest.NewRequest(http.MethodPost, "/internal/sip-credentials/alice/"+action, nil)
		req.SetBasicAuth(user, pw)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}
	if change("suspend", "mcx-server", "wrong") != http.StatusUnauthorized {
		test.Fatal("a change without the server credentials")
	}
	if change("suspend", "mcx-server", "server-secret") != http.StatusOK || count("subscriber") != 0 || count("subscriber_suspended") != 1 {
		test.Fatal("suspend did not move the row aside")
	}
	if change("suspend", "mcx-server", "server-secret") != http.StatusOK || count("subscriber_suspended") != 1 {
		test.Fatal("suspend is not idempotent")
	}
	if change("resume", "mcx-server", "server-secret") != http.StatusOK || count("subscriber") != 1 || count("subscriber_suspended") != 0 {
		test.Fatal("resume did not bring the row back")
	}
	if change("retire", "mcx-server", "server-secret") != http.StatusOK || count("subscriber")+count("subscriber_suspended") != 0 {
		test.Fatal("retire did not remove the credential")
	}

	// Device certificates (slice F2), from a service with an issuing CA.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(24 * time.Hour)}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	dir := test.TempDir()
	keyDER, _ := x509.MarshalPKCS8PrivateKey(caKey)
	_ = os.WriteFile(filepath.Join(dir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "ca.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	cfg.Credentials.IssuerCertFile, cfg.Credentials.IssuerKeyFile = filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	// The revocation list, and a SIP core that is asked to reload it.
	var reloads atomic.Int64
	core := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, rpcRequest *http.Request) {
		body, _ := io.ReadAll(rpcRequest.Body)
		if strings.Contains(string(body), `"tls.reload"`) {
			reloads.Add(1)
		}
		_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","result":"ok","id":1}`))
	}))
	defer core.Close()
	cfg.Credentials.CRLFile, cfg.Credentials.SIPCoreRPC = filepath.Join(dir, "devices.crl"), core.URL
	handler, err = NewHandler(RoleCredentials, cfg, key, test.TempDir(), WithClock(func() time.Time { return testNow }), WithContext(test.Context()))
	if err != nil {
		test.Fatal(err)
	}
	request := func(key any, subject string) []byte {
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: subject},
			DNSNames: []string{"mcx-server"}}, key)
		if err != nil {
			test.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	}
	certify := func(body []byte, token string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, "/v1/client-certificate", strings.NewReader(string(body)))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	token := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	if code, _ := certify(request(deviceKey, "x"), ""); code != http.StatusForbidden {
		test.Fatalf("without a token: %d", code)
	}
	// A request naming a server gets the device's name, and no DNS name, all the same.
	code, issued := certify(request(deviceKey, "mcx-server"), token)
	if code != http.StatusOK {
		test.Fatalf("issue %d %v", code, issued)
	}
	block, _ := pem.Decode([]byte(issued["certificate"].(string)))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		test.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: testNow, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		test.Fatalf("the certificate does not chain to the CA for client authentication: %v", err)
	}
	var uris []string
	for _, uri := range cert.URIs {
		uris = append(uris, uri.String())
	}
	// The client ID "alice-device" is not a URI: it is named in the CN only; the SIP URI is the URI SAN.
	if cert.Subject.CommonName != "mcx-device alice-device" || len(cert.DNSNames) != 0 || !cert.PublicKey.(*ecdsa.PublicKey).Equal(&deviceKey.PublicKey) ||
		!slices.Equal(uris, []string{"sip:alice@mcx.test"}) {
		test.Fatalf("certificate: CN %q, DNS %v, URIs %v", cert.Subject.CommonName, cert.DNSNames, uris)
	}
	if cert.NotAfter.Sub(testNow) > 31*24*time.Hour {
		test.Fatalf("valid until %v", cert.NotAfter)
	}
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	if code, _ := certify(request(weak, "x"), token); code != http.StatusBadRequest {
		test.Fatalf("a 1024-bit RSA key: %d", code)
	}
	tampered := request(deviceKey, "x")
	tampered[len(tampered)/2] ^= 0x10
	if code, _ := certify(tampered, token); code != http.StatusBadRequest {
		test.Fatalf("a damaged request: %d", code)
	}
	// Revoke devices: the certificate is recorded revoked and the SIP credential goes.
	if code, cred = issue(token); code != http.StatusOK || count("subscriber") != 1 {
		test.Fatal("no SIP credential before revoking")
	}
	req := httptest.NewRequest(http.MethodPost, "/internal/client-certificates/alice/revoke", nil)
	req.SetBasicAuth("mcx-server", "server-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	var revoked int
	_ = db.QueryRow("SELECT COUNT(*) FROM client_certificates WHERE username = 'alice' AND revoked_at IS NOT NULL").Scan(&revoked)
	if rr.Code != http.StatusOK || revoked != 1 || count("subscriber") != 0 {
		test.Fatalf("revoke: %d, %d revoked, %d SIP credentials", rr.Code, revoked, count("subscriber"))
	}
	raw, err := os.ReadFile(cfg.Credentials.CRLFile)
	if err != nil {
		test.Fatalf("no revocation list: %v", err)
	}
	crlBlock, _ := pem.Decode(raw)
	crl, err := x509.ParseRevocationList(crlBlock.Bytes)
	if err != nil || crl.CheckSignatureFrom(caCert) != nil {
		test.Fatalf("the revocation list is not the CA's: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		test.Fatalf("the revocation list names %v, not %v", crl.RevokedCertificateEntries, cert.SerialNumber)
	}
	// Once at the service's start (in the background), and after the revocation.
	for deadline := time.Now().Add(5 * time.Second); reloads.Load() < 2 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if count := reloads.Load(); count < 2 {
		test.Fatalf("the SIP core was asked to reload %d times", count)
	}
}

// ------------------------------------------------------------------------------
// The SIP core's RPC client refuses a CA file that holds no certificate (it trusted nothing before, silently).
func TestRPCClientRefusesCAFileWithoutCertificate(test *testing.T) {
	caFile := filepath.Join(test.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, []byte("not a certificate\n"), 0o600); err != nil {
		test.Fatal(err)
	}
	if _, err := rpcClient(&CredentialsConfig{CAFile: caFile}); err == nil {
		test.Fatal("a CA file without a certificate was accepted")
	}
}
