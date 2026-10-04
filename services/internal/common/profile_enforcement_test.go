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
// TS 24.484 clause 8.3.2.1: an MCPTT user profile document read back gives the rights it was rendered from: rendering
// the read-back user gives the same document.
func TestApplyProfileRoundTrip(test *testing.T) {
	no := false
	user := User{MCPTTID: "sip:a@mcx.test", MCID: "sip:a.mc@mcx.test", SIPURI: "sip:a@mcx.test", ClientID: "urn:uuid:1",
		Groups: []string{"sip:ops@mcx.test", "sip:fire@mcx.test"}, MaxAffiliations: 3,
		FunctionalAliasTakeover: true, MCDataID: "sip:a.data@mcx.test",
		PrivateCall: &PrivateCallPolicy{Allow: true, AutomaticCommencement: true, Targets: []string{"sip:b@mcx.test"},
			IncomingFrom: []string{"sip:c@mcx.test"}, Emergency: true, EmergencyRecipients: []string{"sip:b@mcx.test", "sip:c@mcx.test"},
			EmergencyCancel: true, Alert: true, AlertAny: true, Transfer: true, ForwardImmediate: "sip:d@mcx.test", Callable: &no},
		AdhocCall: &AdhocCallPolicy{Allow: true, Participation: true, Modify: true},
		GroupCall: &GroupCallPolicy{Emergency: true, EmergencyGroup: "sip:ops@mcx.test", Imminent: true, ImminentCancel: true,
			Alert: true, AlertCancel: true},
		MCData: &MCDataPolicy{TransmitData: true, Targets: []string{"sip:b.data@mcx.test"}, EmergencyAlert: true, EmergencyGroupCancel: true}}
	rendered, _ := xml.Marshal(userProfileXML(user))
	var doc profileXML
	if err := xml.Unmarshal(rendered, &doc); err != nil {
		test.Fatal(err)
	}
	again, _ := xml.Marshal(userProfileXML(applyProfile(User{MCPTTID: user.MCPTTID, MCID: user.MCID, SIPURI: user.SIPURI,
		ClientID: user.ClientID, MCDataID: user.MCDataID}, doc)))
	if string(again) != string(rendered) {
		test.Fatalf("read back differs\n got %s\nwant %s", again, rendered)
	}
	// The configured parts the document cannot express stay.
	if back := applyProfile(user, doc); back.PrivateCall.ForwardImmediate != "sip:d@mcx.test" ||
		len(back.MCData.Targets) != 1 {
		test.Fatalf("configured parts lost: %+v %+v", back.PrivateCall, back.MCData)
	}
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 6.3.4.3 and clause 8.3.1A: an administrator uploads a user's profile at
// mcptt-user-profile-<index>.xml and the servers enforce it (the internal user lookup gives its rights); another
// document name is not the user's document, a name that does not match the index is a constraint failure; a later
// change of the user's configuration supersedes the uploaded document.
func TestCMSUploadedProfileEnforced(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	for index := range cfg.Users {
		switch cfg.Users[index].Username {
		case "alice":
			cfg.Users[index].ConfigManagement = true
		case "bob":
			cfg.Users[index].PrivateCall = &PrivateCallPolicy{Allow: true}
			cfg.Users[index].GroupCall = &GroupCallPolicy{Emergency: true}
		}
	}
	dir := test.TempDir()
	handler := roleHandler(test, RoleCMS, cfg, key, dir)
	bobID := "sip:bob@mcx.test"
	bobPath := "/xcap-root/org.3gpp.mcptt.user-profile/users/" + url.PathEscape(bobID) + "/mcptt-user-profile-1.xml"
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	send := func(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		request := bearerRequest(method, path, alice, strings.NewReader(body))
		request.Header.Set("Content-Type", userProfileMIME)
		h.ServeHTTP(rr, request)
		return rr
	}
	internalUser := func(h http.Handler) publicUser {
		rr := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/internal/user?mcptt_id="+url.QueryEscape(bobID), nil)
		request.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
		h.ServeHTTP(rr, request)
		var user publicUser
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &user) != nil {
			test.Fatalf("internal user status=%d body=%s", rr.Code, rr.Body.String())
		}
		return user
	}
	if user := internalUser(handler); !user.PrivateCall.Allow || !user.GroupCall.Emergency {
		test.Fatalf("configured rights: %+v %+v", user.PrivateCall, user.GroupCall)
	}
	rr := send(handler, http.MethodGet, bobPath, "")
	if rr.Code != http.StatusOK {
		test.Fatalf("profile at its 3GPP document name: %d", rr.Code)
	}
	// Only the AUID and document name of TS 24.484 clauses 8.3.2.2 and 8.3.1A.
	for _, other := range []string{strings.Replace(bobPath, "mcptt-user-profile-1.xml", "index", 1),
		strings.Replace(bobPath, "org.3gpp.mcptt.user-profile", "3gpp.mcptt.user-profile", 1)} {
		if got := send(handler, http.MethodGet, other, ""); got.Code != http.StatusNotFound {
			test.Fatalf("%s: %d", other, got.Code)
		}
	}
	// Bob's emergency group call and private call rights withdrawn.
	updated := strings.NewReplacer(
		`<allow-emergency-group-call xmlns="urn:3gpp:mcptt:user-profile:1.0">true</allow-emergency-group-call>`, "",
		`<allow-private-call xmlns="urn:3gpp:mcptt:user-profile:1.0">true</allow-private-call>`, "").Replace(rr.Body.String())
	if updated == rr.Body.String() {
		test.Fatalf("the rights to withdraw are not in the profile: %s", updated)
	}
	if rr = send(handler, http.MethodPut, strings.Replace(bobPath, "-1.xml", "-2.xml", 1), updated); rr.Code != http.StatusNotFound {
		test.Fatalf("another document name: %d", rr.Code)
	}
	if rr = send(handler, http.MethodPut, bobPath, strings.Replace(updated, `user-profile-index="1"`, `user-profile-index="2"`, 1)); rr.Code != http.StatusConflict ||
		!strings.Contains(rr.Body.String(), "mcptt-user-profile-&lt;profile-index&gt;.xml") {
		test.Fatalf("a document name that does not match its index: %d %s", rr.Code, rr.Body.String())
	}
	if rr = send(handler, http.MethodPut, bobPath, updated); rr.Code != http.StatusOK {
		test.Fatalf("upload: %d %s", rr.Code, rr.Body.String())
	}
	if user := internalUser(handler); user.PrivateCall.Allow || user.GroupCall.Emergency {
		test.Fatalf("the uploaded profile is not enforced: %+v %+v", user.PrivateCall, user.GroupCall)
	}
	// After a restart with the same configuration the uploaded profile still applies.
	restarted := roleHandler(test, RoleCMS, cfg, key, dir)
	if user := internalUser(restarted); user.PrivateCall.Allow {
		test.Fatal("the uploaded profile did not persist")
	}
	// A later change of bob's configuration is the latest change of his profile: it supersedes the uploaded one.
	for index := range cfg.Users {
		if cfg.Users[index].Username == "bob" {
			cfg.Users[index].MaxAffiliations = 5
		}
	}
	changed := roleHandler(test, RoleCMS, cfg, key, dir)
	if user := internalUser(changed); !user.PrivateCall.Allow || !user.GroupCall.Emergency || user.MaxAffiliations != 5 {
		test.Fatalf("the configuration change did not supersede the upload: %+v", user)
	}
	if rr = send(changed, http.MethodGet, bobPath, ""); !strings.Contains(rr.Body.String(), "<MaxAffiliationsN2>5</MaxAffiliationsN2>") {
		test.Fatalf("served profile after the configuration change: %s", rr.Body.String())
	}
}
