//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ------------------------------------------------------------------------------
// Helper: issuerFiles: a self-signed CA certificate and its PKCS#8 key in PEM files, for loadDeviceIssuer.
func issuerFiles(test *testing.T) (string, string) {
	test.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		test.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		test.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		test.Fatal(err)
	}
	dir := test.TempDir()
	certFile, keyFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		test.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		test.Fatal(err)
	}
	return certFile, keyFile
}

// ------------------------------------------------------------------------------
// RFC 5280 sections 3.3 and 5.1.2.5: the CA's certificate backdate and CRL validity, refresh and clock skew are local
// policy: configurable, with today's values (300 s, 30 days, 24 hours, 300 s) when absent.
func TestDeviceIssuerTiming(test *testing.T) {
	certFile, keyFile := issuerFiles(test)
	issuer, err := loadDeviceIssuer(&CredentialsConfig{IssuerCertFile: certFile, IssuerKeyFile: keyFile})
	if err != nil {
		test.Fatal(err)
	}
	if issuer.days != 30 || issuer.backdate != 5*time.Minute || issuer.crlValidity != 30*24*time.Hour ||
		issuer.crlRefresh != 24*time.Hour || issuer.crlClockSkew != 5*time.Minute {
		test.Fatalf("defaults: %d days, backdate %v, validity %v, refresh %v, skew %v", issuer.days, issuer.backdate,
			issuer.crlValidity, issuer.crlRefresh, issuer.crlClockSkew)
	}
	backdate, skew := 0, 60
	issuer, err = loadDeviceIssuer(&CredentialsConfig{IssuerCertFile: certFile, IssuerKeyFile: keyFile,
		CertificateDays: 7, CertificateBackdateS: &backdate, CRLValidityDays: 3, CRLRefreshHours: 6, CRLClockSkewS: &skew})
	if err != nil {
		test.Fatal(err)
	}
	if issuer.days != 7 || issuer.backdate != 0 || issuer.crlValidity != 3*24*time.Hour ||
		issuer.crlRefresh != 6*time.Hour || issuer.crlClockSkew != time.Minute {
		test.Fatalf("configured: %d days, backdate %v, validity %v, refresh %v, skew %v", issuer.days, issuer.backdate,
			issuer.crlValidity, issuer.crlRefresh, issuer.crlClockSkew)
	}
	negative := -1
	for name, cfg := range map[string]*CredentialsConfig{
		"certificate_backdate_s": {IssuerCertFile: certFile, IssuerKeyFile: keyFile, CertificateBackdateS: &negative},
		"crl_clock_skew_s":       {IssuerCertFile: certFile, IssuerKeyFile: keyFile, CRLClockSkewS: &negative},
	} {
		if _, err := loadDeviceIssuer(cfg); err == nil {
			test.Errorf("a negative %s was accepted", name)
		}
	}
	// RFC 5280 section 5.1.2.5: the next CRL is issued no later than nextUpdate: a refresh longer than the validity
	// is refused, one equal to it is accepted.
	if _, err := loadDeviceIssuer(&CredentialsConfig{IssuerCertFile: certFile, IssuerKeyFile: keyFile,
		CRLValidityDays: 1, CRLRefreshHours: 48}); err == nil {
		test.Error("a CRL refresh of 48 hours with a validity of 1 day was accepted")
	}
	if _, err := loadDeviceIssuer(&CredentialsConfig{IssuerCertFile: certFile, IssuerKeyFile: keyFile,
		CRLValidityDays: 1, CRLRefreshHours: 24}); err != nil {
		test.Errorf("a CRL refresh equal to its validity was refused: %v", err)
	}
}
