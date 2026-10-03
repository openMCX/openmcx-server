// RSA keys of the IdMS tokens (TS 33.180 annex B.2): the signing key and the verification keys, read from PEM files
// or from PEM text in the configuration.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), RFC 7468, RFC 8017, RFC 5958, RFC 5280.
package common

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// ------------------------------------------------------------------------------
// Helper: reads the IdMS's RSA token signing key from a PEM file, as PKCS#1 (RFC 8017) or PKCS#8 (RFC 5958).
func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	block, err := readPEM(path)
	if err != nil {
		return nil, err
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse RSA private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not RSA")
	}
	return rsaKey, nil
}

// ------------------------------------------------------------------------------
// Helper: reads an RSA token verification key from a PEM file.
func LoadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	block, err := readPEM(path)
	if err != nil {
		return nil, err
	}
	return rsaPublicKey(block)
}

// ------------------------------------------------------------------------------
// Helper: the RSA public key of a PEM block, as a SubjectPublicKeyInfo (RFC 5280 section 4.1.2.7) or a PKCS#1
// RSAPublicKey (RFC 8017 appendix A.1.1).
func rsaPublicKey(block *pem.Block) (*rsa.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("verification key is not RSA")
		}
		return rsaKey, nil
	}
	if rsaKey, parseErr := x509.ParsePKCS1PublicKey(block.Bytes); parseErr == nil {
		return rsaKey, nil
	}
	return nil, errors.New("verification key must contain an RSA public key")
}

// ------------------------------------------------------------------------------
// Helper: the one PEM block (RFC 7468) of a key file.
func readPEM(path string) (*pem.Block, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 {
		return nil, errors.New("key file must contain exactly one PEM block")
	}
	return block, nil
}
