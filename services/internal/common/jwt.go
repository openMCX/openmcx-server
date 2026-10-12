//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// IdMS tokens: the claims of the ID and access tokens of TS 33.180 annex B.2, their RS256 signature and
// verification, and the JWK of the verification key.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), RFC 7519, RFC 7515, RFC 7518, RFC 7517,
// OpenID Connect Core 1.0.
package common

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type TokenClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Expires  int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
	TokenID  string `json:"jti"`
	Nonce    string `json:"nonce,omitempty"`
	// ID token: the authentication context class (OpenID Connect Core 1.0 section 2).
	ACR      string `json:"acr,omitempty"`
	MCID     string `json:"mc_id"`
	MCPTTID  string `json:"mcptt_id"`
	MCDataID string `json:"mcdata_id,omitempty"`
	// The MCVideo ID the MCVideo server binds at service authorisation (TS 24.281 clause 7.3).
	MCVideoID string `json:"mcvideo_id,omitempty"`
	SIPURI    string `json:"sip_uri"`
	ClientID  string `json:"client_id"`
	Type      string `json:"token_type"`
	Scope     string `json:"scope,omitempty"`
}

// ------------------------------------------------------------------------------
// Helper: a random identifier (32 random bytes, base64url): token IDs ("jti", RFC 7519 section 4.1.7),
// authorization request IDs and codes, refresh tokens and link tokens.
func randomID() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// ------------------------------------------------------------------------------
// Helper: the "kid" of a verification key (RFC 7515 section 4.1.4): base64url of the first 12 bytes of the SHA-256
// of its modulus.
func keyID(pub *rsa.PublicKey) string {
	digest := sha256.Sum256(pub.N.Bytes())
	return base64.RawURLEncoding.EncodeToString(digest[:12])
}

// ------------------------------------------------------------------------------
// TS 33.180 annex B.2: signs the claims of an ID token or access token (RS256).
func signToken(claims TokenClaims, key *rsa.PrivateKey) (string, error) {
	return signClaims(claims, key)
}

// ------------------------------------------------------------------------------
// RFC 7515 section 5.2: verifiedPayload checks an RS256 signature (RFC 7518 section 3.3) and returns the claims
// part.
func verifiedPayload(token string, key *rsa.PublicKey) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("malformed header")
	}
	var header struct {
		Algorithm string `json:"alg"`
	}
	if json.Unmarshal(headerRaw, &header) != nil || header.Algorithm != "RS256" {
		return nil, errors.New("unsupported token algorithm")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("malformed signature")
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sig); err != nil {
		return nil, errors.New("invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed claims")
	}
	return payload, nil
}

// ------------------------------------------------------------------------------
// Helper: unverifiedIssuer reads the "iss" claim before the key to verify it is chosen.
func unverifiedIssuer(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Issuer
}

// ------------------------------------------------------------------------------
// RFC 7515 section 5.1: signs claims as a JWT (RFC 7519) with RS256 (RFC 7518 section 3.3), naming the key by its
// "kid".
func signClaims(claims any, key *rsa.PrivateKey) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": keyID(&key.PublicKey)})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	hash := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// OpenMCX: how far in the future a token's iat may lie (the issuer's clock ahead of this server's), RFC 7519
// section 4.1.6.
const issuedAtLeeway = time.Minute

// ------------------------------------------------------------------------------
// TS 33.180 annex B.11.2: validates an access token (RFC 7519): its RS256 signature, issuer and audience, "exp"
// (annex B.12) and "iat" (at most one minute ahead), and the identity binding claims (annex B.2.2.3, with OpenMCX's
// mc_id, sip_uri and client_id).
func VerifyToken(token string, key *rsa.PublicKey, issuer, audience string, now time.Time) (TokenClaims, error) {
	payload, err := verifiedPayload(token, key)
	if err != nil {
		return TokenClaims{}, err
	}
	var claims TokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return TokenClaims{}, errors.New("malformed claims")
	}
	if claims.Issuer != issuer || claims.Audience != audience {
		return TokenClaims{}, errors.New("invalid issuer or audience")
	}
	if claims.Expires <= now.Unix() || claims.IssuedAt > now.Add(issuedAtLeeway).Unix() {
		return TokenClaims{}, errors.New("token expired or not yet valid")
	}
	if claims.Subject == "" || claims.MCPTTID == "" || claims.MCID == "" || claims.SIPURI == "" || claims.ClientID == "" {
		return TokenClaims{}, errors.New("missing identity binding")
	}
	return claims, nil
}

// ------------------------------------------------------------------------------
// Helper: compares two secrets in constant time.
func secureEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

// ------------------------------------------------------------------------------
// RFC 7517 section 4 and RFC 7518 section 6.3.1: the public JWK of an RSA verification key, published in the IdMS's
// JWK Set.
func jwk(pub *rsa.PublicKey) map[string]string {
	exponent := []byte{byte(pub.E >> 16), byte(pub.E >> 8), byte(pub.E)}
	for len(exponent) > 1 && exponent[0] == 0 {
		exponent = exponent[1:]
	}
	return map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": keyID(pub), "n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(exponent)}
}

// ------------------------------------------------------------------------------
// TS 33.180 annex B.2.1 and B.2.2: the claims of an ID token (audience the MC client, with the authentication's
// nonce) or an access token (audience the MC servers) for a user: iss, sub, aud, exp, iat, jti and the user's MC ID
// and MC service IDs.
func newClaims(cfg Config, user User, audience, tokenType, nonce string, now time.Time) (TokenClaims, error) {
	id, err := randomID()
	if err != nil {
		return TokenClaims{}, err
	}
	return TokenClaims{Issuer: cfg.Issuer, Subject: user.MCPTTID, Audience: audience, Expires: now.Add(time.Duration(cfg.TokenTTLSeconds) * time.Second).Unix(), IssuedAt: now.Unix(), TokenID: id, Nonce: nonce, MCID: user.MCID, MCPTTID: user.MCPTTID, MCDataID: user.MCDataID, MCVideoID: user.MCVideoID, SIPURI: user.SIPURI, ClientID: user.ClientID, Type: tokenType}, nil
}
