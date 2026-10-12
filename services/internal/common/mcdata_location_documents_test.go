//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ------------------------------------------------------------------------------
// Helper: mcdataLocationConfig gives alice an MCData record with rights from every part of the MCData user profile
// document (TS 24.484 clause 10.3.2.1) and location rights; bob shares his location with alice only.
func mcdataLocationConfig(cfg Config) Config {
	cfg.Endpoints.KMS = "https://kms.mcx.test"
	cfg.Endpoints.Content = "https://content.mcx.test/mcdata"
	cfg.Endpoints.MsgStore = "https://msgstore.mcx.test:8443"
	cfg.Users[0].MCDataID = "sip:alice.mcdata@mcx.test"
	cfg.Users[1].MCDataID = "sip:bob.mcdata@mcx.test"
	cfg.Users[0].MCData = &MCDataPolicy{TransmitData: true, Targets: []string{"sip:bob.mcdata@mcx.test"},
		IncomingFrom: []string{"sip:bob.mcdata@mcx.test"}, MaxData1To1: 2048, EmergencyAlert: true, Adhoc: true,
		StoreComms: true, StoreGroupComms: []string{cfg.Groups[0].ID}, ImplicitAffiliations: []string{cfg.Groups[0].ID},
		Organization: "fire"}
	cfg.Groups[0].MCData = &GroupMCData{Members: []string{"sip:alice.mcdata@mcx.test", "sip:bob.mcdata@mcx.test"}}
	cfg.Users[0].Location = &LocationPolicy{Request: true, Configure: true}
	no := false
	cfg.Users[1].Location = &LocationPolicy{ShareWith: []string{cfg.Users[0].MCPTTID}, Report: &no}
	return cfg
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 10.3 and clause 7.4: the CMS serves each MCData user's profile and each user's location user
// configuration data document at their XCAP URIs, valid against their schemas; the MCPTT profile names the location
// document and is served under the AUID of clause 8.3.2.2 as well; another user's documents are refused.
func TestMCDataProfileAndLocationDocuments(test *testing.T) {
	key := testKey(test)
	cfg := mcdataLocationConfig(testConfig())
	cms := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	get := func(path, token string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		cms.ServeHTTP(rr, bearerRequest("GET", path, token, nil))
		return rr
	}
	profile := "/xcap-root/org.3gpp.mcdata.user-profile/users/" + url.PathEscape("sip:alice.mcdata@mcx.test") + "/mcdata-user-profile-1.xml"
	rr := get(profile, alice)
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != mcdataProfileMIME+"; charset=utf-8" {
		test.Fatalf("MCData profile status=%d type=%q body=%s", rr.Code, rr.Header().Get("Content-Type"), rr.Body.String())
	}
	body := rr.Body.String()
	if err := mcdataProfileSchema.validate(rr.Body.Bytes()); err != nil {
		test.Fatalf("the MCData profile fails the schema of 10.3.2.3: %v\n%s", err, body)
	}
	for _, want := range []string{`XUI-URI="sip:alice.mcdata@mcx.test"`,
		"<MCDataUserID><uri-entry>sip:alice.mcdata@mcx.test</uri-entry></MCDataUserID>",
		"<MissionCriticalOrganization>fire</MissionCriticalOrganization>",
		"<TxRxControl><MaxData1To1>2048</MaxData1To1><MaxTime1To1>P1D</MaxTime1To1>",
		"<One-to-One-CommunicationListEntry><MCData-ID><uri-entry>sip:bob.mcdata@mcx.test</uri-entry></MCData-ID><MCData-ID-KMSURI><uri-entry>https://kms.mcx.test</uri-entry></MCData-ID-KMSURI>",
		"<MCData-Group-ID><uri-entry>" + cfg.Groups[0].ID + "</uri-entry></MCData-Group-ID>",
		"<allow-store-group-comm-in-msgstore>true</allow-store-group-comm-in-msgstore>",
		"<MCDataContentServerURI>https://content.mcx.test/mcdata</MCDataContentServerURI>",
		"<MessageStoreHostname>msgstore.mcx.test</MessageStoreHostname>",
		"<IncomingOne-to-OneCommunicationList>",
		`<allow-transmit-data xmlns="urn:3gpp:ns:mcdata:user-profile:1.0">true</allow-transmit-data>`,
		`<allow-adhoc-group-data-comn xmlns="urn:3gpp:ns:mcdata:user-profile:1.0">true</allow-adhoc-group-data-comn>`,
		"/xcap-root/org.3gpp.mcs.location-user-config/users/sip:alice.mcdata@mcx.test/location-user-config-1.xml"} {
		if !strings.Contains(body, want) {
			test.Fatalf("MCData profile lacks %s:\n%s", want, body)
		}
	}
	// The location document, by any of alice's MC service IDs.
	location := func(id string) string {
		return "/xcap-root/org.3gpp.mcs.location-user-config/users/" + url.PathEscape(id) + "/location-user-config-1.xml"
	}
	for _, id := range []string{cfg.Users[0].MCPTTID, "sip:alice.mcdata@mcx.test"} {
		rr = get(location(id), alice)
		if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != locationConfigMIME+"; charset=utf-8" {
			test.Fatalf("location document %s status=%d body=%s", id, rr.Code, rr.Body.String())
		}
	}
	body = rr.Body.String()
	if err := locationConfigSchema.validate(rr.Body.Bytes()); err != nil {
		test.Fatalf("the location document fails the schema of 7.4.2.3: %v\n%s", err, body)
	}
	for _, want := range []string{`domain="` + cfg.Domain + `"`, "<mc-service-id>" + cfg.Users[0].MCPTTID + "</mc-service-id>",
		"<mc-service-id>sip:alice.mcdata@mcx.test</mc-service-id>",
		">true</allow-request-location-of-users>", ">true</allow-request-location-of-groups>",
		">true</allow-change-location-configuration-of-users>", ">true</allow-to-share-location-information>"} {
		if !strings.Contains(body, want) {
			test.Fatalf("location document lacks %s:\n%s", want, body)
		}
	}
	// Bob shares with alice only, and does not report.
	bob := tokenFor(test, cfg, key, "bob", testNow, cfg.ServerClientID)
	rr = get(location(cfg.Users[1].MCPTTID), bob)
	if body = rr.Body.String(); rr.Code != http.StatusOK || !strings.Contains(body, `<identity><one id="`+cfg.Users[0].MCPTTID+`"></one></identity>`) ||
		!strings.Contains(body, "location-reporting-disabled") || strings.Contains(body, "allow-request-location-of-users") {
		test.Fatalf("bob's location document status=%d body=%s", rr.Code, body)
	}
	if err := locationConfigSchema.validate(rr.Body.Bytes()); err != nil {
		test.Fatalf("bob's location document fails the schema: %v\n%s", err, body)
	}
	// The MCPTT profile under the AUID of TS 24.484 clause 8.3.2.2, naming the location document.
	rr = get("/xcap-root/org.3gpp.mcptt.user-profile/users/"+url.PathEscape(cfg.Users[0].MCPTTID)+"/mcptt-user-profile-1.xml", alice)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "<LocationUserProfileURI>") {
		test.Fatalf("MCPTT profile status=%d body=%s", rr.Code, rr.Body.String())
	}
	// Another user's documents are refused.
	if rr = get(location(cfg.Users[1].MCPTTID), alice); rr.Code != http.StatusForbidden {
		test.Fatalf("bob's location document for alice: %d", rr.Code)
	}
	bobProfile := "/xcap-root/org.3gpp.mcdata.user-profile/users/" + url.PathEscape("sip:bob.mcdata@mcx.test") + "/mcdata-user-profile-1.xml"
	if rr = get(bobProfile, alice); rr.Code != http.StatusForbidden {
		test.Fatalf("bob's MCData profile for alice: %d", rr.Code)
	}
}
