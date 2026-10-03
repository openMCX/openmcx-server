package common

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.2 and clause 7.2.4.2: a group document carries everything a server enforces (with the MCData
// and MCVideo members) and reads back into the same group; without members (TS 24.481
// clause 6.3.16.3) it has no <list>; a document without the uri attribute is refused.
func TestGroupDocumentRoundTrip(test *testing.T) {
	group := Group{ID: "sip:ops@mcx.test", Type: "chat", Members: []string{"sip:alice@mcx.test", "sip:erin@other.test"},
		UserPriorities: map[string]int{"sip:erin@other.test": 3}, ProtectMedia: false, ProtectFloor: true,
		PreconfiguredUseOnly: true, AllowGettingMemberList: true, SubordinateGroups: []string{"sip:sub@mcx.test"},
		CallPolicy:        map[string]interface{}{"max_participants": float64(5), "setup_timeout_ms": float64(4000)},
		PriorityPolicy:    map[string]interface{}{"emergency_users": []interface{}{"sip:alice@mcx.test"}},
		FloorPriorityCaps: map[string]uint8{"sip:alice@mcx.test": 7},
		MCData: &GroupMCData{Members: []string{"sip:alice.data@mcx.test"}, SDSSupported: true, AllowSDS: true,
			AllowEnhancedStatus: true, EnhancedStatusValues: []EnhancedStatusValue{{ID: "1", Value: "On scene"}}},
		// The MCVideo server reads the MCVideo members with the group.
		MCVideo: &GroupMCVideo{Members: []string{"sip:alice.mcvideo@mcx.test", "sip:erin.mcvideo@other.test"},
			UserPriorities: map[string]int{"sip:erin.mcvideo@other.test": 2}}}
	raw, err := groupDocument(group, true)
	if err != nil {
		test.Fatal(err)
	}
	back, err := parseGroupDocument(raw)
	if err != nil {
		test.Fatal(err)
	}
	if !reflect.DeepEqual(back, group) {
		test.Fatalf("round trip changed the group:\n%#v\n%#v\n%s", group, back, raw)
	}
	for _, want := range []string{`<group xmlns="urn:oma:xml:poc:list-service">`, `<list-service uri="sip:ops@mcx.test">`,
		`<entry uri="sip:erin@other.test">`, `enabler="urn:urn-7:3gpp-service.ims.icsi.mcptt"`,
		`enabler="urn:urn-7:3gpp-service.ims.icsi.mcdata"`, `enabler="urn:urn-7:3gpp-service.ims.icsi.mcvideo"`, `<on-network-max-participant-count xmlns="urn:3gpp:ns:mcpttGroupInfo:1.0">5<`} {
		if !strings.Contains(string(raw), want) {
			test.Fatalf("document lacks %s: %s", want, raw)
		}
	}
	// TS 24.481 clause 6.3.16.3: without <list>.
	bare, err := groupDocument(group, false)
	if err != nil || strings.Contains(string(bare), "<list>") || strings.Contains(string(bare), "<entry") {
		test.Fatalf("document excluding members still lists them: %v %s", err, bare)
	}
	if _, err := parseGroupDocument([]byte(`<group xmlns="urn:oma:xml:poc:list-service"><list-service/></group>`)); err == nil {
		test.Fatal("document without uri accepted")
	}
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.12.1: what each identity may read: nothing for a non-member, its own entry for a member, all
// for an authorized MCS server, and all for a member when <on-network-allow-getting-member-list> allows it.
func TestReadableGroup(test *testing.T) {
	group := Group{ID: "sip:ops@mcx.test", Members: []string{"sip:a@mcx.test", "sip:b@mcx.test"},
		UserPriorities: map[string]int{"sip:a@mcx.test": 1, "sip:b@mcx.test": 2}}
	if _, ok := readableGroup(group, "sip:c@mcx.test", false); ok {
		test.Fatal("non-member reads the group")
	}
	own, ok := readableGroup(group, "sip:a@mcx.test", false)
	if !ok || !reflect.DeepEqual(own.Members, []string{"sip:a@mcx.test"}) || len(own.UserPriorities) != 1 {
		test.Fatalf("member view: %#v", own)
	}
	if all, _ := readableGroup(group, "", true); len(all.Members) != 2 {
		test.Fatal("server view reduced")
	}
	group.AllowGettingMemberList = true
	if all, _ := readableGroup(group, "sip:a@mcx.test", false); len(all.Members) != 2 {
		test.Fatal("member-list rule ignored")
	}
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.16.3: an HTTP POST with a GMOP document requesting the group document excluding the members
// (TS 24.481 clause 7.3.4.2) returns the group without <list>; another MIME type gets 415, an empty request 400.
func TestGMSGroupDocumentExcludingMembers(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	cfg.Groups[0].AllowGettingMemberList = true
	handler := roleHandler(test, RoleGMS, cfg, key, test.TempDir())
	target := "/xcap-root/org.openmobilealliance.groups/global/byGroupID/" + url.PathEscape("sip:team@mcx.test")
	token := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	gmop := `<document xmlns="urn:3gpp:ns:mcpttGMOP:1.0"><request><get-excluding-memberlist/></request></document>`
	for _, testCase := range []struct {
		contentType, body string
		status            int
	}{{gmopMIME, gmop, http.StatusOK}, {"application/xml", gmop, http.StatusUnsupportedMediaType},
		{gmopMIME, `<document xmlns="urn:3gpp:ns:mcpttGMOP:1.0"><request/></document>`, http.StatusBadRequest}} {
		rr := httptest.NewRecorder()
		req := bearerRequest(http.MethodPost, target, token, strings.NewReader(testCase.body))
		req.Header.Set("Content-Type", testCase.contentType)
		handler.ServeHTTP(rr, req)
		if rr.Code != testCase.status {
			test.Fatalf("%s: status=%d body=%s", testCase.contentType, rr.Code, rr.Body.String())
		}
		if testCase.status == http.StatusOK && (strings.Contains(rr.Body.String(), "<entry") || !strings.Contains(rr.Body.String(), "list-service")) {
			test.Fatalf("members not excluded: %s", rr.Body.String())
		}
	}
}
