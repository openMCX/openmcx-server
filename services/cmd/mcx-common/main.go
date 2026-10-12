//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// mcx-common runs one common service role (IdMS, GMS, CMS, LMS, KMS, MCData content server, message store or
// notification server or Credential Service): its keys, its TLS client towards the services of this system, and its
// HTTPS server.
//
// Specifications: TS 24.482 V19.1.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19),
// TS 23.280 V19.10.1 (Rel-19).
package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/open-mcx/open-mcx/services/internal/common"
)

// ------------------------------------------------------------------------------
// Helper: runs the service; a failure is logged and exits with status 1.
func main() {
	if err := run(); err != nil {
		log.Printf("mcx-common: %v", err)
		os.Exit(1)
	}
}

// ------------------------------------------------------------------------------
// Helper: reads the flags and the configuration, loads the keys of the role, builds the TLS clients it needs
// (the system's services) and serves HTTPS (TS 24.482 annex A.2.3).
func run() error {
	var roleValue, configPath, listen, certPath, keyPath, signingPath, verificationPath, dataDir, caPath string
	flag.StringVar(&roleValue, "role", "", "service role: idms, gms, cms, lms, kms, content, msgstore, notification or credentials")
	flag.StringVar(&configPath, "config", "", "common JSON configuration")
	flag.StringVar(&listen, "listen", ":8443", "HTTPS listen address")
	flag.StringVar(&certPath, "tls-cert", "", "TLS certificate PEM")
	flag.StringVar(&keyPath, "tls-key", "", "TLS private key PEM")
	flag.StringVar(&signingPath, "signing-key", "", "IdMS RSA private signing key PEM")
	flag.StringVar(&verificationPath, "verification-key", "", "GMS/CMS/LMS RSA public verification key PEM")
	flag.StringVar(&dataDir, "data-dir", "", "role-owned persistent data directory")
	flag.StringVar(&caPath, "ca-file", "", "CA certificate PEM for the TLS client towards the services of this system")
	var transferTimeoutMs int
	flag.IntVar(&transferTimeoutMs, "file-transfer-timeout-ms", 0,
		"content role: read and write deadline of one MCData file upload or download; 0 keeps the server timeouts")
	flag.Parse()
	if transferTimeoutMs < 0 {
		return fmt.Errorf("--file-transfer-timeout-ms must not be negative")
	}
	if roleValue == "" || configPath == "" || certPath == "" || keyPath == "" || dataDir == "" {
		return fmt.Errorf("--role, --config, --tls-cert, --tls-key and --data-dir are required")
	}
	role := common.Role(roleValue)
	common.PrintBanner(fmt.Sprintf("mcx-common (%s)", roleValue))
	cfg, err := common.LoadConfig(configPath)
	if err != nil {
		return err
	}
	var signing *rsa.PrivateKey
	var verification *rsa.PublicKey
	if role == common.RoleIDMS {
		if signingPath == "" {
			return fmt.Errorf("--signing-key is required for idms")
		}
		signing, err = common.LoadRSAPrivateKey(signingPath)
		if err != nil {
			return err
		}
		verification = &signing.PublicKey
	} else if role == common.RoleGMS || role == common.RoleCMS || role == common.RoleLMS || role == common.RoleKMS || role == common.RoleContent ||
		role == common.RoleMsgStore || role == common.RoleNotification || role == common.RoleCredentials {
		if verificationPath == "" {
			return fmt.Errorf("--verification-key is required for %s", role)
		}
		verification, err = common.LoadRSAPublicKey(verificationPath)
		if err != nil {
			return err
		}
	}
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS12}
	var opts []common.Option
	if (role == common.RoleMsgStore || role == common.RoleContent || role == common.RoleKMS || role == common.RoleGMS ||
		((role == common.RoleIDMS || role == common.RoleCMS || role == common.RoleCredentials || role == common.RoleLMS) && cfg.AdminAccounts != nil)) && caPath != "" {
		// The message store fetches deposited files from the content server and posts
		// to the notification server; the content server fetches network-stored files;
		// an IdMS or a CMS in admin mode asks MCX Admin for accounts and user records.
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("CA file contains no certificate")
		}
		opts = append(opts, common.WithServiceClient(&http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, TLSHandshakeTimeout: 5 * time.Second,
		}}))
	}
	handler, err := common.NewHandlerWithKeys(role, cfg, signing, verification, dataDir, opts...)
	if err != nil {
		return err
	}
	if role == common.RoleContent && transferTimeoutMs > 0 {
		handler = common.WithTransferDeadline(handler, time.Duration(transferTimeoutMs)*time.Millisecond)
	}
	if debug, err := common.DebugLogging(cfg.LogLevel); err != nil {
		return err
	} else if debug {
		handler = common.WithRequestLog(handler, roleValue)
	}
	server := &http.Server{
		Addr: listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10,
		TLSConfig: serverTLS,
	}
	log.Printf("starting %s HTTPS service on %s", role, listen)
	return server.ListenAndServeTLS(certPath, keyPath)
}
