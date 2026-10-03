package common

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.14.3 and clause 6.3.15.3: alice's GMS combines two groups into a temporary group (the authorization of step b and the <uniqueness-failure> of step c of
// clause 6.3.14.3.1, the regroup check and notification), refuses changes of the marks by others, then tears the
// temporary group down.
func TestTemporaryGroup(test *testing.T) {
	cfgA := testConfig()
	cfgA.Groups = append(cfgA.Groups, Group{ID: "sip:ops@mcx.test", Members: []string{"sip:bob@mcx.test"}})
	cfgA.Users[0].GroupManagement = &GroupManagementPolicy{Temporary: true}
	key := testKey(test)
	ownGMS, err := NewHandlerWithKeys(RoleGMS, cfgA, nil, &key.PublicKey, test.TempDir(), WithClock(func() time.Time { return testNow }))
	if err != nil {
		test.Fatal(err)
	}
	alice := tokenFor(test, cfgA, key, "alice", testNow, cfgA.ServerClientID)
	bob := tokenFor(test, cfgA, key, "bob", testNow, cfgA.ServerClientID)
	form := func(token, tgi string, constituents ...string) *httptest.ResponseRecorder {
		ids := ""
		for _, id := range constituents {
			ids += `<mcpttgi:constituent-MCPTT-group-ID>` + id + `</mcpttgi:constituent-MCPTT-group-ID>`
		}
		body := `<?xml version="1.0"?><document xmlns="urn:3gpp:ns:mcpttGMOP:1.0"><request><group-regroup-creation>` +
			`<group xmlns="urn:oma:xml:poc:list-service" xmlns:mcpttgi="urn:3gpp:ns:mcpttGroupInfo:1.0"><list-service uri="` + tgi + `">` +
			`<mcpttgi:protect-media>true</mcpttgi:protect-media>` +
			`<mcpttgi:on-network-temporary><mcpttgi:constituent-MCPTT-group-IDs>` + ids +
			`</mcpttgi:constituent-MCPTT-group-IDs></mcpttgi:on-network-temporary></list-service></group>` +
			`</group-regroup-creation></request></document>`
		name := strings.TrimSuffix(strings.TrimPrefix(tgi, "sip:"), "@mcx.test")
		request := bearerRequest(http.MethodPost, groupsAUID+"/users/"+url.PathEscape("sip:alice@mcx.test")+"/"+name, token, strings.NewReader(body))
		request.Header.Set("Content-Type", gmopMIME)
		rr := httptest.NewRecorder()
		ownGMS.ServeHTTP(rr, request)
		return rr
	}
	internal := func(gms http.Handler, id string) Group {
		request := httptest.NewRequest(http.MethodGet, "/internal/group?id="+url.QueryEscape(id), nil)
		request.SetBasicAuth(cfgA.ServerClientID, cfgA.ServerSecret)
		rr := httptest.NewRecorder()
		gms.ServeHTTP(rr, request)
		var group Group
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &group) != nil {
			test.Fatalf("internal group %s: %d %s", id, rr.Code, rr.Body.String())
		}
		return group
	}
	// TS 24.481 clause 6.3.14.3.1 step b: bob may not form temporary groups.
	if rr := form(bob, "sip:temp-1@mcx.test", "sip:team@mcx.test", "sip:ops@mcx.test"); rr.Code != http.StatusForbidden {
		test.Fatalf("an unauthorised formation: %d %s", rr.Code, rr.Body.String())
	}
	// TS 24.481 clause 6.3.14.3.1 step c: an identity of another provider is refused with an alternative.
	if rr := form(alice, "sip:temp-1@other.test", "sip:team@mcx.test"); rr.Code != http.StatusConflict ||
		!strings.Contains(rr.Body.String(), "uniqueness-failure") || !strings.Contains(rr.Body.String(), "@mcx.test") {
		test.Fatalf("a foreign identity: %d %s", rr.Code, rr.Body.String())
	}
	rr := form(alice, "sip:temp-1@mcx.test", "sip:team@mcx.test", "sip:ops@mcx.test")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "<temporary-group-document-ETag>") || rr.Header().Get("ETag") == "" {
		test.Fatalf("formation: %d %s", rr.Code, rr.Body.String())
	}
	temporary := internal(ownGMS, "sip:temp-1@mcx.test")
	if strings.Join(temporary.TemporaryConstituents, ",") != "sip:team@mcx.test,sip:ops@mcx.test" || !temporary.ProtectMedia {
		test.Fatalf("temporary group %#v", temporary)
	}
	if mark := internal(ownGMS, "sip:team@mcx.test").RegroupedBy; mark == nil || mark.TGI != "sip:temp-1@mcx.test" ||
		mark.Requestor != "sip:alice@mcx.test" {
		test.Fatalf("own constituent mark %#v", mark)
	}
	if mark := internal(ownGMS, "sip:ops@mcx.test").RegroupedBy; mark == nil || mark.TGI != "sip:temp-1@mcx.test" {
		test.Fatalf("second constituent mark %#v", mark)
	}
	// A group is combined into one temporary group at a time.
	if rr := form(alice, "sip:temp-2@mcx.test", "sip:team@mcx.test"); rr.Code != http.StatusForbidden {
		test.Fatalf("a regrouped constituent: %d %s", rr.Code, rr.Body.String())
	}
	// TS 24.481 clause 7.2.12.1: nobody changes the marks by XCAP, nor deletes a regrouped group's document.
	rr = httptest.NewRecorder()
	ownGMS.ServeHTTP(rr, bearerRequest(http.MethodDelete, groupPath("sip:team@mcx.test"), alice, nil))
	if rr.Code == http.StatusOK {
		test.Fatal("a regrouped group's document was deleted")
	}
	// TS 24.481 clause 6.3.15.3.1: tear down by the requester.
	rr = httptest.NewRecorder()
	ownGMS.ServeHTTP(rr, bearerRequest(http.MethodDelete, groupsAUID+"/users/"+url.PathEscape("sip:alice@mcx.test")+"/temp-1", alice, nil))
	if rr.Code != http.StatusOK {
		test.Fatalf("tear down: %d %s", rr.Code, rr.Body.String())
	}
	if internal(ownGMS, "sip:team@mcx.test").RegroupedBy != nil || internal(ownGMS, "sip:ops@mcx.test").RegroupedBy != nil {
		test.Fatal("a mark outlived the temporary group")
	}
	request := httptest.NewRequest(http.MethodGet, "/internal/group?id="+url.QueryEscape("sip:temp-1@mcx.test"), nil)
	request.SetBasicAuth(cfgA.ServerClientID, cfgA.ServerSecret)
	rr = httptest.NewRecorder()
	ownGMS.ServeHTTP(rr, request)
	if rr.Code != http.StatusNotFound {
		test.Fatalf("the torn down group remains: %d", rr.Code)
	}
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.14.3.1 step c: formations of one temporary group ID at the same time, of different
// constituent groups, cannot all pass the uniqueness check: exactly one is formed, and only its constituent is
// marked.
func TestClause_6_3_14_3_1_ConcurrentFormationsOfOneID(test *testing.T) {
	cfg := testConfig()
	cfg.Users[0].GroupManagement = &GroupManagementPolicy{Temporary: true}
	cfg.Groups = append(cfg.Groups, Group{ID: "sip:squad@mcx.test", Members: []string{"sip:alice@mcx.test"}})
	key := testKey(test)
	gms := roleHandler(test, RoleGMS, cfg, key, test.TempDir())
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	form := func(constituent string) int {
		body := `<?xml version="1.0"?><document xmlns="urn:3gpp:ns:mcpttGMOP:1.0"><request><group-regroup-creation>` +
			`<group xmlns="urn:oma:xml:poc:list-service" xmlns:mcpttgi="urn:3gpp:ns:mcpttGroupInfo:1.0"><list-service uri="sip:temp-9@mcx.test">` +
			`<mcpttgi:on-network-temporary><mcpttgi:constituent-MCPTT-group-IDs><mcpttgi:constituent-MCPTT-group-ID>` + constituent +
			`</mcpttgi:constituent-MCPTT-group-ID></mcpttgi:constituent-MCPTT-group-IDs></mcpttgi:on-network-temporary></list-service></group>` +
			`</group-regroup-creation></request></document>`
		request := bearerRequest(http.MethodPost, groupsAUID+"/users/"+url.PathEscape("sip:alice@mcx.test")+"/temp-9", alice, strings.NewReader(body))
		request.Header.Set("Content-Type", gmopMIME)
		rr := httptest.NewRecorder()
		gms.ServeHTTP(rr, request)
		return rr.Code
	}
	var wait sync.WaitGroup
	var formed atomic.Int64
	for index := range 8 {
		constituent := []string{"sip:team@mcx.test", "sip:squad@mcx.test"}[index%2]
		wait.Go(func() {
			if form(constituent) == http.StatusOK {
				formed.Add(1)
			}
		})
	}
	wait.Wait()
	if formed.Load() != 1 {
		test.Fatalf("%d formations of one temporary group ID succeeded", formed.Load())
	}
	marked := 0
	for _, id := range []string{"sip:team@mcx.test", "sip:squad@mcx.test"} {
		request := httptest.NewRequest(http.MethodGet, "/internal/group?id="+url.QueryEscape(id), nil)
		request.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
		rr := httptest.NewRecorder()
		gms.ServeHTTP(rr, request)
		var group Group
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &group) != nil {
			test.Fatalf("internal group %s: %d", id, rr.Code)
		}
		if group.RegroupedBy != nil {
			marked++
		}
	}
	if marked != 1 {
		test.Fatalf("%d constituent groups marked", marked)
	}
}

// ------------------------------------------------------------------------------
// Helper: the XCAP URI path of a group document addressed by a group ID (TS 24.481 clause 7.2.10.2).
func groupPath(id string) string {
	return "/xcap-root/org.openmobilealliance.groups/global/byGroupID/" + url.PathEscape(id)
}
