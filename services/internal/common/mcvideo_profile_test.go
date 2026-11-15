//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ------------------------------------------------------------------------------
// Helper: the XCAP URI path of an MCVideo user profile document of a user (TS 24.484 clause 9.3.1A).
func mcvideoProfilePath(id string, index int) string {
	return "/xcap-root/org.3gpp.mcvideo.user-profile/users/" + url.PathEscape(id) + "/" + mcvideoProfileDocumentName(index)
}

// ------------------------------------------------------------------------------
// Helper: mcvideoConfig gives alice and bob MCVideo IDs and alice an MCVideo record with rights from every part of
// the MCVideo user profile document (TS 24.484 clause 9.3.2.1); bob may not be called.
func mcvideoConfig(cfg Config) Config {
	no := false
	cfg.Endpoints.KMS = "https://kms.mcx.test"
	cfg.Users[0].MCVideoID = "sip:alice.mcvideo@mcx.test"
	cfg.Users[1].MCVideoID = "sip:bob.mcvideo@mcx.test"
	cfg.Users[0].MCVideo = map[string]any{
		"private_call": map[string]any{"allow": true, "automatic_commencement": true, "targets": []any{"sip:bob.mcvideo@mcx.test"},
			"incoming_from": []any{"sip:bob.mcvideo@mcx.test"}, "emergency": true, "emergency_any": true, "ambient_remote": true},
		"adhoc_call": map[string]any{"allow": true, "modify": true}, "regroup": true, "allow_revoke_transmit": true,
		"allow_video_push_to_server": true, "remote_group_selection": []any{"sip:bob.mcvideo@mcx.test"}, "max_affiliations": 2,
		"location": map[string]any{"request": true}}
	cfg.Users[1].MCVideo = map[string]any{"private_call": PrivateCallPolicy{Allow: true, Callable: &no}}
	cfg.Groups[0].MCVideo = &GroupMCVideo{Members: []string{"sip:alice.mcvideo@mcx.test", "sip:bob.mcvideo@mcx.test"}}
	return cfg
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3: the CMS serves each MCVideo user's profile at the XCAP URI of TS 24.484 clause 9.3.1A,
// valid against the schema of TS 24.484 clause 9.3.2.3, and its rights read back to the record they came from;
// another user's profile, another index and a document name of MCPTT are refused.
func TestMCVideoProfileDocument(test *testing.T) {
	key := testKey(test)
	cfg := mcvideoConfig(testConfig())
	cms := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	get := func(path, token string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		cms.ServeHTTP(rr, bearerRequest("GET", path, token, nil))
		return rr
	}
	rr := get(mcvideoProfilePath("sip:alice.mcvideo@mcx.test", 1), alice)
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != mcvideoProfileMIME+"; charset=utf-8" {
		test.Fatalf("profile status=%d type=%q body=%s", rr.Code, rr.Header().Get("Content-Type"), rr.Body.String())
	}
	body := rr.Body.Bytes()
	if err := mcvideoProfileSchema.validate(body); err != nil {
		test.Fatalf("the served profile fails the schema of 9.3.2.3: %v\n%s", err, body)
	}
	for _, want := range []string{`XUI-URI="sip:alice.mcvideo@mcx.test"`, `user-profile-index="1"`,
		"<ProfileName>mcvideo-user-profile-1.xml</ProfileName>",
		"<MCVideoUserID><uri-entry>sip:alice.mcvideo@mcx.test</uri-entry></MCVideoUserID>",
		"<PrivateCallOnNetwork><PrivateCallURI><uri-entry>sip:bob.mcvideo@mcx.test</uri-entry></PrivateCallURI><PrivateCallKMSURI><PrivateCallKMSURI><uri-entry>https://kms.mcx.test</uri-entry></PrivateCallKMSURI></PrivateCallKMSURI></PrivateCallOnNetwork>",
		"<MCVideoGroupInfo><MCVideo-Group-ID><uri-entry>sip:team@mcx.test</uri-entry></MCVideo-Group-ID></MCVideoGroupInfo>",
		"<MaxAffiliationsN2>2</MaxAffiliationsN2>",
		`<allow-private-call xmlns="urn:3gpp:ns:mcvideo:user-profile:1.0">true</allow-private-call>`,
		`<allow-request-remote-initiated-ambient-viewing xmlns="urn:3gpp:ns:mcvideo:user-profile:1.0">true</allow-request-remote-initiated-ambient-viewing>`,
		`<allow-video-push-to-server xmlns="urn:openmcx:ns:userProfile:1.0">true</allow-video-push-to-server>`} {
		if !strings.Contains(string(body), want) {
			test.Fatalf("profile lacks %s:\n%s", want, body)
		}
	}
	var doc mcvideoProfileXML
	if err := xml.Unmarshal(body, &doc); err != nil {
		test.Fatal(err)
	}
	got, _ := json.Marshal(doc.rights())
	want, _ := mcvideoRightsOf(cfg.Users[0])
	wantRaw, _ := json.Marshal(want)
	if string(got) != string(wantRaw) {
		test.Fatalf("rights read back\n got %s\nwant %s", got, wantRaw)
	}
	// Bob cannot be called: the implementation's extension says so.
	bob := tokenFor(test, cfg, key, "bob", testNow, cfg.ServerClientID)
	if rr = get(mcvideoProfilePath("sip:bob.mcvideo@mcx.test", 1), bob); rr.Code != http.StatusOK ||
		!strings.Contains(rr.Body.String(), "<not-callable>true</not-callable>") {
		test.Fatalf("bob's profile status=%d body=%s", rr.Code, rr.Body.String())
	}
	// Another user's profile, another index, and a document name of MCPTT are refused.
	for _, testCase := range []struct {
		name, path, token string
		want              int
	}{
		{"another user's profile", mcvideoProfilePath("sip:alice.mcvideo@mcx.test", 1), bob, http.StatusForbidden},
		{"another index", mcvideoProfilePath("sip:alice.mcvideo@mcx.test", 2), alice, http.StatusNotFound},
		{"an MCPTT document name", strings.Replace(mcvideoProfilePath("sip:alice.mcvideo@mcx.test", 1), "mcvideo-user-profile-1.xml", "index", 1),
			alice, http.StatusNotFound},
	} {
		if rr = get(testCase.path, testCase.token); rr.Code != testCase.want {
			test.Fatalf("%s: %s status=%d want %d", testCase.name, testCase.path, rr.Code, testCase.want)
		}
	}
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.6: the validation constraints the schema does not express (the XUI-URI, the document
// name of the profile index, the priority range); the schema itself refuses a non-boolean <Status> and an MCPTT
// user profile.
func TestMCVideoProfileConstraints(test *testing.T) {
	doc := `<mcvideo-user-profile xmlns="urn:3gpp:ns:mcvideo:user-profile:1.0" XUI-URI="sip:a@x" user-profile-index="2"><Status>true</Status>` +
		`<OnNetwork index="0"><MCVideoGroupInfo><MCVideo-Group-ID><uri-entry>sip:g@x</uri-entry></MCVideo-Group-ID>` +
		`<RelativePresentationPriority>%s</RelativePresentationPriority></MCVideoGroupInfo></OnNetwork></mcvideo-user-profile>`
	for _, testCase := range []struct {
		priority, xui, name, phrase string
	}{{"7", "sip:a@x", "mcvideo-user-profile-2.xml", ""},
		{"7", "sip:b@x", "mcvideo-user-profile-2.xml", "Wrong User Profile URI"},
		{"7", "sip:a@x", "mcvideo-user-profile-1.xml", "does not comply"},
		{"256", "sip:a@x", "mcvideo-user-profile-2.xml", "Priority value out of range"}} {
		err := mcvideoProfileConstraints([]byte(strings.Replace(doc, "%s", testCase.priority, 1)), testCase.xui, testCase.name)
		if (testCase.phrase == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), testCase.phrase)) {
			test.Fatalf("%+v: %v", testCase, err)
		}
	}
	valid := strings.Replace(doc, "%s", "7", 1)
	if err := mcvideoProfileSchema.validate([]byte(valid)); err != nil {
		test.Fatalf("a valid profile: %v", err)
	}
	if err := mcvideoProfileSchema.validate([]byte(strings.Replace(valid, "<Status>true", "<Status>maybe", 1))); err == nil {
		test.Fatal("a non-boolean <Status> passed the schema")
	}
	// A document of the MCPTT schema is not an MCVideo user profile.
	if err := mcvideoProfileSchema.validate([]byte(`<mcptt-user-profile xmlns="urn:3gpp:mcptt:user-profile:1.0" XUI-URI="sip:a@x" user-profile-index="1"/>`)); err == nil {
		test.Fatal("an MCPTT profile passed the MCVideo schema")
	}
}

// ------------------------------------------------------------------------------
// TS 24.484 clauses 8.3.2.1, 9.3.2.1 and 10.3.2.1 with TS 24.379, TS 24.281 and TS 24.282 clause 7.3.3 steps 3a and
// 3b: a user profile of any MC service may set <user-max-simultaneous-authorizations> to 1, not more (one binding per
// MC service ID in the present edition).
func TestAuthorizationLimitConstraint(test *testing.T) {
	for _, testCase := range []struct {
		check         func(raw []byte, xui, name string) error
		root, ns, doc string
	}{{profileConstraints, "mcptt-user-profile", "urn:3gpp:mcptt:user-profile:1.0", "mcptt-user-profile-1.xml"},
		{mcvideoProfileConstraints, "mcvideo-user-profile", "urn:3gpp:ns:mcvideo:user-profile:1.0", "mcvideo-user-profile-1.xml"},
		{mcdataProfileConstraints, "mcdata-user-profile", "urn:3gpp:ns:mcdata:user-profile:1.0", "mcdata-user-profile-1.xml"}} {
		for value, refused := range map[string]bool{"1": false, "2": true} {
			raw := `<` + testCase.root + ` xmlns="` + testCase.ns + `" XUI-URI="sip:a@x" user-profile-index="1"><OnNetwork index="0">` +
				`<anyExt><user-max-simultaneous-authorizations>` + value + `</user-max-simultaneous-authorizations></anyExt>` +
				`</OnNetwork></` + testCase.root + `>`
			err := testCase.check([]byte(raw), "sip:a@x", testCase.doc)
			if refused != (err != nil) || (err != nil && !strings.Contains(err.Error(), "At most 1 simultaneous service authorization")) {
				test.Fatalf("%s with %s: %v", testCase.root, value, err)
			}
		}
	}
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1 item 9 f: a user allowed emergency alerts to users has the <PrivateEmergencyAlert> of
// <OnNetwork> (the target condition of TS 24.281 clause 6.2.8.3.1.3 2)): "LocallyDetermined" for any user, or
// "UsePreConfigured" with the single configured recipient; the document stays valid against the schema.
func TestMCVideoPrivateEmergencyAlert(test *testing.T) {
	key := testKey(test)
	for _, testCase := range []struct {
		policy map[string]any
		want   string
	}{
		{map[string]any{"allow": true, "alert": true, "alert_any": true},
			`<PrivateEmergencyAlert><entry entry-info="LocallyDetermined"><uri-entry></uri-entry></entry></PrivateEmergencyAlert>`},
		{map[string]any{"allow": true, "alert": true, "alert_recipients": []any{"sip:bob.mcvideo@mcx.test"}},
			`<PrivateEmergencyAlert><entry entry-info="UsePreConfigured"><uri-entry>sip:bob.mcvideo@mcx.test</uri-entry></entry></PrivateEmergencyAlert>`},
	} {
		cfg := mcvideoConfig(testConfig())
		cfg.Users[0].MCVideo["private_call"] = testCase.policy
		cms := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
		rr := httptest.NewRecorder()
		cms.ServeHTTP(rr, bearerRequest("GET", mcvideoProfilePath("sip:alice.mcvideo@mcx.test", 1),
			tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID), nil))
		body := rr.Body.Bytes()
		if rr.Code != http.StatusOK || !strings.Contains(string(body), testCase.want) {
			test.Fatalf("status=%d, want %s in\n%s", rr.Code, testCase.want, body)
		}
		if err := mcvideoProfileSchema.validate(body); err != nil {
			test.Fatalf("the served profile fails the schema of 9.3.2.3: %v\n%s", err, body)
		}
	}
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1 item 8 d) with TS 24.281 clause 6.2.8.3.9: a target's <PrivateCallKMSURI> is the KMS URI
// the record gives it (target_kms), else the KMS of the endpoints; "" gives an empty entry.
func TestMCVideoProfilePrivateCallKMS(test *testing.T) {
	key := testKey(test)
	cfg := mcvideoConfig(testConfig())
	private := cfg.Users[0].MCVideo["private_call"].(map[string]any)
	private["targets"] = []any{"sip:bob.mcvideo@mcx.test", "sip:carol.mcvideo@mcx.test"}
	private["target_kms"] = map[string]any{"sip:bob.mcvideo@mcx.test": "https://kms2.mcx.test"}
	cms := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	rr := httptest.NewRecorder()
	cms.ServeHTTP(rr, bearerRequest("GET", mcvideoProfilePath("sip:alice.mcvideo@mcx.test", 1), alice, nil))
	body := rr.Body.String()
	if rr.Code != http.StatusOK {
		test.Fatalf("profile status=%d body=%s", rr.Code, body)
	}
	if err := mcvideoProfileSchema.validate(rr.Body.Bytes()); err != nil {
		test.Fatalf("the served profile fails the schema of 9.3.2.3: %v\n%s", err, body)
	}
	for _, want := range []string{
		"<PrivateCallURI><uri-entry>sip:bob.mcvideo@mcx.test</uri-entry></PrivateCallURI><PrivateCallKMSURI><PrivateCallKMSURI><uri-entry>https://kms2.mcx.test</uri-entry>",
		"<PrivateCallURI><uri-entry>sip:carol.mcvideo@mcx.test</uri-entry></PrivateCallURI><PrivateCallKMSURI><PrivateCallKMSURI><uri-entry>https://kms.mcx.test</uri-entry>"} {
		if !strings.Contains(body, want) {
			test.Fatalf("profile lacks %s:\n%s", want, body)
		}
	}
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 9.3.2.1 item 8 e) v): the <Priority> of <MCVideo-group-call> is the record's group_call priority
// (TS 24.581 clauses 14.2.3 and 14.2.6: the client's configured priority), 0 by default; out of range is refused.
func TestMCVideoProfilePriority(test *testing.T) {
	key := testKey(test)
	for _, testCase := range []struct {
		policy map[string]any
		want   string
		status int
	}{
		{nil, "<Priority>0</Priority>", http.StatusOK},
		{map[string]any{"priority": 5}, "<Priority>5</Priority>", http.StatusOK},
		{map[string]any{"priority": 255}, "<Priority>255</Priority>", http.StatusOK},
	} {
		cfg := mcvideoConfig(testConfig())
		if testCase.policy != nil {
			cfg.Users[0].MCVideo["group_call"] = testCase.policy
		}
		cms := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
		rr := httptest.NewRecorder()
		cms.ServeHTTP(rr, bearerRequest("GET", mcvideoProfilePath("sip:alice.mcvideo@mcx.test", 1),
			tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID), nil))
		body := rr.Body.Bytes()
		if rr.Code != testCase.status || !strings.Contains(string(body), testCase.want) {
			test.Fatalf("status=%d, want %s in\n%s", rr.Code, testCase.want, body)
		}
		if err := mcvideoProfileSchema.validate(body); err != nil {
			test.Fatalf("the served profile fails the schema of 9.3.2.3: %v\n%s", err, body)
		}
	}
	cfg := mcvideoConfig(testConfig())
	cfg.Users[0].MCVideo["group_call"] = map[string]any{"priority": 256}
	svc := &service{cfg: cfg}
	if _, err := svc.mcvideoProfileXML(cfg.Users[0]); err == nil {
		test.Fatal("a priority above 255 accepted")
	}
}
