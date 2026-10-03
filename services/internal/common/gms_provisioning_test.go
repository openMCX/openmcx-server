package common

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ------------------------------------------------------------------------------
// MCX Admin (slice D1) writes groups through the GMS's internal interface, as a group document update
// (TS 24.481 clause 6.3.4.3) and deletion (TS 24.481 clause 6.3.5.3): server credentials required, an unchanged
// group keeps its version, the regrouped state is not provisioned (TS 24.481 clause 7.2.12.1), the XCAP view
// follows, and the store survives a restart.
func TestGroupProvisioning(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	dir := test.TempDir()
	handler := roleHandler(test, RoleGMS, cfg, key, dir)
	internal := func(handler http.Handler, method, id, body, secret string) (int, map[string]any) {
		req := httptest.NewRequest(method, "/internal/groups?id="+url.QueryEscape(id), strings.NewReader(body))
		req.SetBasicAuth("mcx-server", secret)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}
	xcapGet := func(handler http.Handler, group, user string) int {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, bearerRequest(http.MethodGet, "/xcap-root/org.openmobilealliance.groups/global/byGroupID/"+url.PathEscape(group),
			tokenFor(test, cfg, key, user, testNow, cfg.ServerClientID), nil))
		return rr.Code
	}
	versions := func(handler http.Handler) map[string]float64 {
		code, out := internal(handler, http.MethodGet, "", "", "server-secret")
		if code != 200 {
			test.Fatalf("list %d", code)
		}
		byGroup := map[string]float64{}
		for _, entry := range out["groups"].([]any) {
			fields := entry.(map[string]any)
			version, _ := fields["version"].(float64)
			if fields["deleted"] == true {
				version = -version
			}
			byGroup[fields["id"].(string)] = version
		}
		return byGroup
	}
	team := `{"id":"sip:team@mcx.test","members":["sip:alice@mcx.test","sip:bob@mcx.test"],"protect_media":false,"protect_floor":false}`
	if code, _ := internal(handler, http.MethodPut, "sip:team@mcx.test", team, "wrong"); code != 401 {
		test.Fatalf("without the server credentials: %d", code)
	}
	if code, out := internal(handler, http.MethodPut, "sip:team@mcx.test", team, "server-secret"); code != 200 || out["changed"] != false {
		test.Fatalf("the configured group again: %d %v", code, out)
	}
	if byGroup := versions(handler); byGroup["sip:team@mcx.test"] != 0 {
		test.Fatalf("versions %v", byGroup)
	}
	if code, _ := internal(handler, http.MethodPut, "sip:other@mcx.test", team, "server-secret"); code != 400 {
		test.Fatalf("an id that differs from the parameter: %d", code)
	}
	regrouped := strings.Replace(team, `"protect_media"`, `"regrouped":true,"protect_media"`, 1)
	if code, _ := internal(handler, http.MethodPut, "sip:team@mcx.test", regrouped, "server-secret"); code != 409 {
		test.Fatalf("the regrouped state provisioned: %d", code)
	}
	// TS 24.481 clause 7.2.12.1: a group configured regrouped is written as it is: no change to its state.
	cfgRegrouped := cfg
	cfgRegrouped.Groups = append(append([]Group(nil), cfg.Groups...), Group{ID: "sip:marked@mcx.test", Regrouped: true,
		Members: []string{"sip:alice@mcx.test"}})
	marked := roleHandler(test, RoleGMS, cfgRegrouped, key, test.TempDir())
	if code, out := internal(marked, http.MethodPut, "sip:marked@mcx.test",
		`{"id":"sip:marked@mcx.test","regrouped":true,"members":["sip:alice@mcx.test"],"protect_media":false,"protect_floor":false}`, "server-secret"); code != 200 || out["changed"] != false {
		test.Fatalf("an unchanged regrouped group: %d %v", code, out)
	}
	if code, _ := internal(marked, http.MethodPut, "sip:marked@mcx.test",
		`{"id":"sip:marked@mcx.test","members":["sip:alice@mcx.test"],"protect_media":false,"protect_floor":false}`, "server-secret"); code != 409 {
		test.Fatalf("the regrouped state removed: %d", code)
	}
	// Bob leaves the team: his XCAP read is refused, alice's is not.
	alone := `{"id":"sip:team@mcx.test","members":["sip:alice@mcx.test"],"protect_media":false,"protect_floor":false}`
	if code, out := internal(handler, http.MethodPut, "sip:team@mcx.test", alone, "server-secret"); code != 200 || out["changed"] != true || out["version"] != float64(1) {
		test.Fatalf("change: %d %v", code, out)
	}
	if xcapGet(handler, "sip:team@mcx.test", "bob") != 403 || xcapGet(handler, "sip:team@mcx.test", "alice") != 200 {
		test.Fatal("the XCAP view does not follow the provisioned members")
	}
	// A new group, deleted, then created again.
	fresh := `{"id":"sip:night@mcx.test","members":["sip:bob@mcx.test"],"protect_media":false,"protect_floor":false}`
	if code, out := internal(handler, http.MethodPut, "sip:night@mcx.test", fresh, "server-secret"); code != 200 || out["version"] != float64(1) {
		test.Fatalf("create: %d %v", code, out)
	}
	if xcapGet(handler, "sip:night@mcx.test", "bob") != 200 {
		test.Fatal("bob does not read the new group")
	}
	if code, out := internal(handler, http.MethodDelete, "sip:night@mcx.test", "", "server-secret"); code != 200 || out["version"] != float64(2) {
		test.Fatalf("delete: %d %v", code, out)
	}
	if xcapGet(handler, "sip:night@mcx.test", "bob") != 404 {
		test.Fatal("a deleted group is still served")
	}
	if code, out := internal(handler, http.MethodDelete, "sip:night@mcx.test", "", "server-secret"); code != 200 || out["changed"] != false {
		test.Fatalf("delete again: %d %v", code, out)
	}
	if code, out := internal(handler, http.MethodPut, "sip:night@mcx.test", fresh, "server-secret"); code != 200 || out["version"] != float64(3) {
		test.Fatalf("create again: %d %v", code, out)
	}
	// The store survives a restart.
	again := roleHandler(test, RoleGMS, cfg, key, dir)
	if byGroup := versions(again); byGroup["sip:team@mcx.test"] != 1 || byGroup["sip:night@mcx.test"] != 3 {
		test.Fatalf("after a restart %v", byGroup)
	}
	if xcapGet(again, "sip:team@mcx.test", "bob") != 403 {
		test.Fatal("a restart went back to the configured members")
	}
}

// ------------------------------------------------------------------------------
// In admin mode the GMS's group-management check (TS 24.481 clause 7.2.12.1, "subject to MCS service provider
// policy") reads the user from MCX Admin: a user who is only there, with manage rights, changes a group by XCAP
// (TS 24.481 clause 6.3.6.3).
func TestGroupManagementAdminMode(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	admin := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("mcptt_id") != "sip:carol@mcx.test" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(writer, http.StatusOK, User{Username: "carol", MCPTTID: "sip:carol@mcx.test", ClientID: "carol-device",
			GroupManagement: &GroupManagementPolicy{Manage: []string{"sip:team@mcx.test"}}})
	}))
	defer admin.Close()
	cfg.AdminAccounts = &AdminAccountsConfig{URL: admin.URL, LinkBaseURL: "https://idms.mcx.test"}
	handler, err := NewHandlerWithKeys(RoleGMS, cfg, nil, &key.PublicKey, test.TempDir(), WithClock(func() time.Time { return testNow }), WithServiceClient(admin.Client()))
	if err != nil {
		test.Fatal(err)
	}
	carol := cfg
	carol.Users = append(carol.Users, User{Username: "carol", Password: "p", MCID: "carol-mc", MCPTTID: "sip:carol@mcx.test",
		SIPURI: "sip:carol@ims.mcx.test", ClientID: "carol-device"})
	put := func(user string) int {
		body := `<entry xmlns="urn:oma:xml:poc:list-service" uri="sip:carol@mcx.test"/>`
		req := bearerRequest(http.MethodPut, groupsAUID+"/global/byGroupID/"+url.PathEscape("sip:team@mcx.test")+"/~~/"+
			url.PathEscape(`group/list-service/list/entry[@uri="sip:carol@mcx.test"]`), tokenFor(test, carol, key, user, testNow, cfg.ServerClientID), strings.NewReader(body))
		req.Header.Set("Content-Type", "application/xcap-el+xml")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}
	if code := put("bob"); code != http.StatusForbidden {
		test.Fatalf("bob, not a manager in MCX Admin: %d", code)
	}
	if code := put("carol"); code != http.StatusCreated {
		test.Fatalf("carol, a manager only in MCX Admin: %d", code)
	}
}

// ------------------------------------------------------------------------------
// MCX Admin (slice D4): in admin mode the groups of the MCVideo user profile document (TS 24.484 clause 9.3.2.1)
// are the ones MCX Admin names for the user; in file mode they come from the configured groups.
func TestMCVideoProfileGroupsAdminMode(test *testing.T) {
	cfg := testConfig()
	cfg.Groups[0].MCVideo = &GroupMCVideo{Members: []string{"sip:alice.video@mcx.test"}}
	user := User{MCPTTID: "sip:alice@mcx.test", MCVideoID: "sip:alice.video@mcx.test", MCVideoGroups: []string{"sip:night@mcx.test"}}
	groups := func(svc *service) []string {
		doc, err := svc.mcvideoProfileXML(user)
		if err != nil {
			test.Fatal(err)
		}
		var out []string
		if doc.OnNetwork != nil {
			for _, groupInfo := range doc.OnNetwork.GroupInfo {
				out = append(out, groupInfo.GroupID.URI)
			}
		}
		return out
	}
	if got := groups(&service{cfg: cfg}); strings.Join(got, " ") != "sip:team@mcx.test" {
		test.Fatalf("file mode %v", got)
	}
	cfg.AdminAccounts = &AdminAccountsConfig{URL: "https://mcxadmin", LinkBaseURL: "https://idms"}
	if got := groups(&service{cfg: cfg}); strings.Join(got, " ") != "sip:night@mcx.test" {
		test.Fatalf("admin mode %v", got)
	}
}
