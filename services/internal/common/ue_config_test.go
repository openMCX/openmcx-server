//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testUE = "urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66"

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.2.1A: an MCPTT client reads the MCPTT UE configuration document of its UE at
// org.3gpp.mcptt.ue-config/users/sip:MCPTTID/MCSUEID: generated from the master document with the UE's ID, valid
// against the schema of clause 8.2.2.3; also under the TS 37.579-1 document name; another user's or a name that is no
// instance ID is refused.
func TestCMSServesMCPTTUEConfiguration(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.Users[0].UEs = []string{testUE}
	cfg.UEConfig = &MCPTTUEConfig{MaxGroupCallsN4: 4, PrioritizedGroups: []UEGroupPriority{{Group: "sip:team@mcx.test", Priority: 6}}}
	handler := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	base := "/xcap-root/org.3gpp.mcptt.ue-config/users/" + url.PathEscape("sip:alice@mcx.test") + "/"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, bearerRequest(http.MethodGet, base+url.PathEscape(testUE), alice, nil))
	body := rr.Body.String()
	if rr.Code != http.StatusOK || !strings.HasPrefix(rr.Header().Get("Content-Type"), mcpttUEConfigMIME) || rr.Header().Get("ETag") == "" {
		test.Fatalf("UE configuration %d %q %s", rr.Code, rr.Header().Get("Content-Type"), body)
	}
	for _, want := range []string{`domain="mcx.test"`, "<Instance-ID-URN>" + testUE + "</Instance-ID-URN>", "<Max-Simul-Call-N10>2</Max-Simul-Call-N10>",
		"<Max-Simul-Call-N4>4</Max-Simul-Call-N4>", "<Max-Simul-Trans-N5>5</Max-Simul-Trans-N5>",
		"<MCPTT-Group-ID>sip:team@mcx.test</MCPTT-Group-ID><group-priority-hierarchy>6</group-priority-hierarchy>",
		"<Relay-Service>false</Relay-Service>"} {
		if !strings.Contains(body, want) {
			test.Fatalf("UE configuration without %s: %s", want, body)
		}
	}
	if err := schemaError(mcpttUEConfigSchema.validate([]byte(body))); err != nil {
		test.Fatalf("UE configuration not valid: %v", err)
	}
	for _, tc := range []struct {
		path, token string
		status      int
	}{
		// A UE without a document of its own: generated from the master document.
		{base + url.PathEscape("urn:gsma:imei:35209900-176148-1"), alice, http.StatusOK},
		{base + mcpttUEConfigTestName, alice, http.StatusOK},
		{base + "ue.xml", alice, http.StatusNotFound},
		{base + url.PathEscape(testUE), tokenFor(test, cfg, key, "bob", testNow, cfg.ServerClientID), http.StatusForbidden},
		{base + url.PathEscape(testUE), scopedToken(test, cfg, key, "alice", "openid "+scopeDataConfig), http.StatusForbidden},
	} {
		rr = httptest.NewRecorder()
		handler.ServeHTTP(rr, bearerRequest(http.MethodGet, tc.path, tc.token, nil))
		if rr.Code != tc.status {
			test.Fatalf("%s: %d want %d %s", tc.path, rr.Code, tc.status, rr.Body.String())
		}
	}
}

// ------------------------------------------------------------------------------
// The defaults of the master document (TS 37.579-1 table 5.5.8.2-1) with the user's groups prioritised, and a
// master document out of range (TS 24.484 clause 8.2.2.6) or a malformed UE instance ID is refused at start.
func TestMCPTTUEConfigurationDefaultsAndValidation(test *testing.T) {
	cfg := testConfig()
	cfg.Users[0].Groups = []string{"sip:team@mcx.test", "sip:other@mcx.test"}
	svc := &service{cfg: cfg}
	raw, ok, err := svc.mcpttUEConfigDocument(cfg.Users[0], "")
	if err != nil || !ok || strings.Contains(string(raw), "mcptt-UE-id") ||
		!strings.Contains(string(raw), "<MCPTT-Group-ID>sip:other@mcx.test</MCPTT-Group-ID><group-priority-hierarchy>6</group-priority-hierarchy>") {
		test.Fatalf("default UE configuration %v %v %s", ok, err, raw)
	}
	if err := schemaError(mcpttUEConfigSchema.validate(raw)); err != nil {
		test.Fatal(err)
	}
	bad := testConfig()
	bad.UEConfig = &MCPTTUEConfig{MaxPrivateCallsN10: 5}
	if bad.Validate() == nil {
		test.Fatal("N10 of 5 accepted")
	}
	bad = testConfig()
	bad.Users[0].UEs = []string{"imei-1"}
	if bad.Validate() == nil {
		test.Fatal("malformed UE instance ID accepted")
	}
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 6.3.13.3.2.2 step e: the subscription function reads the entity tag of each subscribed document:
// the UE configuration, the user profile (under its current name) and the service configuration, the same entity tag
// as the document's GET; only with the server credentials.
func TestInternalConfigurationDocument(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	handler := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	for _, tc := range []struct {
		auid, xui, document, name, path string
	}{
		{mcpttUEConfigAUID, "sip:alice@mcx.test", testUE, testUE,
			"/xcap-root/org.3gpp.mcptt.ue-config/users/sip:alice@mcx.test/" + url.PathEscape(testUE)},
		{"org.3gpp.mcptt.user-profile", "sip:alice@mcx.test", "mcptt-user-profile-9.xml", "mcptt-user-profile-1.xml",
			"/xcap-root/org.3gpp.mcptt.user-profile/users/sip:alice@mcx.test/mcptt-user-profile-1.xml"},
		{"org.3gpp.mcptt.service-config", "", "service-config.xml", "service-config.xml",
			"/xcap-root/org.3gpp.mcptt.service-config/global/service-config.xml"},
	} {
		request := httptest.NewRequest(http.MethodGet, "/internal/configuration-document?"+url.Values{"auid": {tc.auid}, "xui": {tc.xui}, "document": {tc.document}}.Encode(), nil)
		request.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, request)
		var answer map[string]string
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &answer) != nil || answer["document"] != tc.name {
			test.Fatalf("%s: %d %s", tc.auid, rr.Code, rr.Body.String())
		}
		rr = httptest.NewRecorder()
		handler.ServeHTTP(rr, bearerRequest(http.MethodGet, tc.path, alice, nil))
		if rr.Code != http.StatusOK || rr.Header().Get("ETag") != answer["document_etag"] {
			test.Fatalf("%s: entity tag %q, GET %d %q", tc.auid, answer["document_etag"], rr.Code, rr.Header().Get("ETag"))
		}
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/internal/configuration-document?auid=org.3gpp.mcptt.service-config&document=service-config.xml", nil))
	if rr.Code != http.StatusUnauthorized {
		test.Fatalf("internal document without credentials: %d", rr.Code)
	}
}
