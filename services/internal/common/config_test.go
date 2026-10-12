//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ------------------------------------------------------------------------------
// The configuration must state protect_floor for each group (the <protect-floor-control-signalling> of TS 24.481
// clause 7.2.8), and a group asking for media protection without the supported protected profile is refused.
func TestLoadConfigRequiresExplicitFalseSecurityPolicy(test *testing.T) {
	cfg := testConfig()
	raw, err := json.Marshal(cfg)
	if err != nil {
		test.Fatal(err)
	}
	withoutFloor := strings.Replace(string(raw), `,"protect_floor":false`, "", 1)
	path := filepath.Join(test.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(withoutFloor), 0o600); err != nil {
		test.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "protect_floor must be explicit") {
		test.Fatalf("error=%v", err)
	}

	cfg.Groups[0].ProtectMedia = true
	raw, err = json.Marshal(cfg)
	if err != nil {
		test.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		test.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "unsupported protected profile") {
		test.Fatalf("error=%v", err)
	}
}

// ------------------------------------------------------------------------------
// The signing key and the verification key load from their PEM files; the verification loader refuses private
// key material.
func TestKeyLoadersSeparateSigningAndVerificationMaterial(test *testing.T) {
	key := testKey(test)
	dir := test.TempDir()
	privatePath := filepath.Join(dir, "signing.pem")
	publicPath := filepath.Join(dir, "verification.pem")
	privateDER := x509.MarshalPKCS1PrivateKey(key)
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		test.Fatal(err)
	}
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		test.Fatal(err)
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o600); err != nil {
		test.Fatal(err)
	}

	loadedPrivate, err := LoadRSAPrivateKey(privatePath)
	if err != nil {
		test.Fatal(err)
	}
	loadedPublic, err := LoadRSAPublicKey(publicPath)
	if err != nil {
		test.Fatal(err)
	}
	if loadedPrivate.N.Cmp(key.N) != 0 || loadedPublic.N.Cmp(key.N) != 0 {
		test.Fatal("loaded key differs")
	}
	if _, err := LoadRSAPublicKey(privatePath); err == nil {
		test.Fatal("verification loader accepted private key material")
	}
}

// ------------------------------------------------------------------------------
// A group's call policy (with an explicit empty initiate list and the minimum of affiliated members) and floor
// priority caps survive the configuration and the internal JSON the servers read.
func TestGroupPolicySurvivesConfigurationAndInternalJSON(test *testing.T) {
	const input = `{"id":"sip:group@example.test","members":["sip:a@example.test"],"protect_media":false,"protect_floor":false,"call_policy":{"initiate_members":[],"join_members":["sip:a@example.test"],"minimum_affiliated_members":2,"required_affiliated_members":["sip:a@example.test"]},"floor_priority_caps":{"sip:a@example.test":7}}`
	var group Group
	if err := json.Unmarshal([]byte(input), &group); err != nil {
		test.Fatal(err)
	}
	wire, err := json.Marshal(group)
	if err != nil {
		test.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(wire, &got); err != nil {
		test.Fatal(err)
	}
	if _, ok := got["call_policy"]; !ok {
		test.Fatal("trusted per-group call policy was dropped from internal response")
	}
	var policy map[string]json.RawMessage
	if err := json.Unmarshal(got["call_policy"], &policy); err != nil {
		test.Fatal(err)
	}
	if string(policy["initiate_members"]) != "[]" {
		test.Fatal("explicit empty initiate allowlist must survive serialization")
	}
	if string(policy["minimum_affiliated_members"]) != "2" {
		test.Fatal("minimum affiliated member policy lost")
	}
	var caps map[string]uint8
	if err := json.Unmarshal(got["floor_priority_caps"], &caps); err != nil || caps["sip:a@example.test"] != 7 {
		test.Fatalf("priority caps lost: %v, error %v", caps, err)
	}
}

// ------------------------------------------------------------------------------
// A floor priority cap above 255 is refused when a group is read.
func TestGroupRejectsOutOfRangePriorityCap(test *testing.T) {
	var group Group
	if err := json.Unmarshal([]byte(`{"floor_priority_caps":{"sip:a@example.test":256}}`), &group); err == nil {
		test.Fatal("invalid floor priority cap accepted")
	}
}

// ------------------------------------------------------------------------------
// The limit of simultaneous group affiliations (the <MaxAffiliationsN2> of TS 24.484 clause 8.3.2.7) may not be
// negative, and is served to the server in the internal user and to the client in the user profile document.
func TestAffiliationLimitIsServedToTheServerAndInTheProfile(test *testing.T) {
	cfg := testConfig()
	cfg.Users[0].MaxAffiliations = -1
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "negative affiliation limit") {
		test.Fatalf("negative limit accepted: %v", err)
	}
	cfg.Users[0].MaxAffiliations = 2
	if err := cfg.Validate(); err != nil {
		test.Fatal(err)
	}
	raw, err := json.Marshal(publicUser{MaxAffiliations: cfg.Users[0].MaxAffiliations})
	if err != nil || !strings.Contains(string(raw), `"max_affiliations":2`) {
		test.Fatalf("limit missing from internal user: %s %v", raw, err)
	}
	doc, err := xml.Marshal(userProfileXML(cfg.Users[0]))
	if err != nil || !strings.Contains(string(doc), "<MaxAffiliationsN2>2</MaxAffiliationsN2>") {
		test.Fatalf("limit missing from profile document: %s %v", doc, err)
	}
}
