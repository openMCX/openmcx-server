package common

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ------------------------------------------------------------------------------
// The SEAL location management server (TS 24.545): the MCPTT server subscribes to alice's location
// (TS 24.545 clause 6.2.6.2.2), the clients read their configuration (TS 24.545 clause 6.2.2.3.1) and report (TS 24.545 clause 6.2.2.3.2), the server is notified
// (TS 24.545 clause 6.2.7.2), asks on demand (TS 24.545 clause 6.2.8.2), receives a history location result
// report (TS 24.545 clause 6.2.20.3), and unsubscribes.
func TestSealLocationManagement(test *testing.T) {
	cfgA := testConfig()
	cfgA.SealLM = &SealLMConfig{Identity: "sip:lms@mcx.test", VALServers: []string{"sip:mcptt@mcx.test"}, PeriodicSeconds: 5}
	key := testKey(test)
	// The notification interval (TLM-2) needs a clock that moves.
	start := time.Now()
	build := func(cfg Config) http.Handler {
		handler, err := NewHandlerWithKeys(RoleLMS, cfg, nil, &key.PublicKey, test.TempDir(),
			WithClock(func() time.Time { return testNow.Add(time.Since(start)) }))
		if err != nil {
			test.Fatal(err)
		}
		return handler
	}
	ownLMS := build(cfgA)
	alice := tokenFor(test, cfgA, key, "alice", testNow, cfgA.ServerClientID)
	point := func(lat, lon uint32) string {
		return fmt.Sprintf(`<current-location><current-geographical-coordinate><longitude><threebytes>%d</threebytes></longitude>`+
			`<latitude><threebytes>%d</threebytes></latitude></current-geographical-coordinate></current-location>`, lon, lat)
	}
	doc := func(inner string) string {
		return `<?xml version="1.0"?><location-info xmlns="urn:3gpp:ns:sealLocationInfo:1.0">` + inner + `</location-info>`
	}
	send := func(handler http.Handler, method, path, token, body string, internal *Config) *httptest.ResponseRecorder {
		httpRequest := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			httpRequest.Header.Set("Authorization", "Bearer "+token)
		}
		if internal != nil {
			httpRequest.SetBasicAuth(internal.ServerClientID, internal.ServerSecret)
		}
		if body != "" {
			httpRequest.Header.Set("Content-Type", sealLocationMIME)
			httpRequest.Header.Set("Accept", sealLocationMIME)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httpRequest)
		return rr
	}
	user := func(id string) string { return sealBase + "/users/" + url.PathEscape(id) }
	// TS 24.545 clause 6.2.2.3.1: a client reads its own configuration only.
	rr := send(ownLMS, "GET", user("sip:alice@mcx.test")+"/configuration", alice, "", nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `<periodic-report trigger-id="periodic">5</periodic-report>`) ||
		!strings.Contains(rr.Body.String(), "/reports</report-uri>") {
		test.Fatalf("configuration: %d %s", rr.Code, rr.Body.String())
	}
	if rr := send(ownLMS, "GET", user("sip:bob@mcx.test")+"/configuration", alice, "", nil); rr.Code != http.StatusForbidden {
		test.Fatalf("another user's configuration: %d", rr.Code)
	}
	// TS 24.545 clause 6.2.6.2.2: only the MC service servers of this system subscribe.
	subscription := doc(`<identity><VAL-user-id><sealURI>%s</sealURI></VAL-user-id></identity><subscription><identities-list>` +
		`<VAL-user-id><sealURI>sip:alice@mcx.test</sealURI></VAL-user-id>` +
		`</identities-list><time-interval-length>1</time-interval-length><expiry-time>-60</expiry-time></subscription>`)
	if rr := send(ownLMS, "POST", sealBase+"/subscriptions", "", fmt.Sprintf(subscription, "sip:mcptt@other.test"), &cfgA); rr.Code != http.StatusForbidden {
		test.Fatalf("a foreign VAL server subscribed: %d", rr.Code)
	}
	rr = send(ownLMS, "POST", sealBase+"/subscriptions", "", fmt.Sprintf(subscription, "sip:mcptt@mcx.test"), &cfgA)
	var answer sealLocationInfo
	if rr.Code != 200 || xml.Unmarshal(rr.Body.Bytes(), &answer) != nil || answer.SubscriptionIdentifier == "" ||
		answer.ExpiryTime == nil || *answer.ExpiryTime != 60 || answer.IdentitiesList != nil {
		test.Fatalf("subscription: %d %s", rr.Code, rr.Body.String())
	}
	status := func(handler http.Handler, cfg *Config) map[string]any {
		var out map[string]any
		_ = json.Unmarshal(send(handler, "GET", sealBase+"/status", "", "", cfg).Body.Bytes(), &out)
		return out
	}
	// TS 24.545 clause 6.2.2.3.2.
	if rr := send(ownLMS, "POST", user("sip:alice@mcx.test")+"/reports", alice, doc(`<report><trigger-id>periodic</trigger-id>`+
		point(4473924, 93206)+`</report>`), nil); rr.Code != 200 {
		test.Fatalf("alice's report: %d %s", rr.Code, rr.Body.String())
	}
	if rr := send(ownLMS, "POST", user("sip:bob@mcx.test")+"/reports", alice, doc(`<report>`+point(1, 1)+`</report>`), nil); rr.Code != http.StatusForbidden {
		test.Fatalf("a report for another user: %d", rr.Code)
	}
	// TS 24.545 clause 6.2.7.2 on the server's channel: alice's position.
	seen := map[string]bool{}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !seen["alice"] {
		rr := send(ownLMS, "POST", sealBase+"/notifications?val="+url.QueryEscape("sip:mcptt@mcx.test")+"&wait=2", "", "", &cfgA)
		var out struct{ Notifications []string }
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		for _, notification := range out.Notifications {
			if strings.Contains(notification, "sip:alice@mcx.test") && strings.Contains(notification, "<threebytes>4473924</threebytes>") {
				seen["alice"] = true
			}
			if !strings.Contains(notification, "<subscription-identifier>"+answer.SubscriptionIdentifier+"</subscription-identifier>") {
				seen["alice"] = false
			}
		}
	}
	if !seen["alice"] {
		test.Fatalf("notifications seen %v", seen)
	}
	// TS 24.545 clause 6.2.8.2: on demand.
	request := doc(`<identity><VAL-user-id><sealURI>sip:mcptt@mcx.test</sealURI></VAL-user-id></identity><identities-list>` +
		`<VAL-user-id><sealURI>sip:alice@mcx.test</sealURI></VAL-user-id>` +
		`</identities-list>`)
	rr = send(ownLMS, "POST", sealBase+"/location-requests", "", request, &cfgA)
	var reports sealLocationInfo
	if rr.Code != 200 || xml.Unmarshal(rr.Body.Bytes(), &reports) != nil || reports.Reports == nil || len(reports.Reports.Reports) != 1 {
		test.Fatalf("on-demand request: %d %s", rr.Code, rr.Body.String())
	}
	// TS 24.545 clause 6.2.20.3: alice's history reaches the subscriber, marked as history.
	history := doc(`<anyExt><history-loc-result-report><subscription-identifier>history</subscription-identifier>` +
		`<reports>` + point(4470000, 93000) + `<anyExt><timestamp>2026-09-19T23:50:00Z</timestamp></anyExt></reports>` +
		`<reports>` + point(4471000, 93100) + `<anyExt><timestamp>2026-09-19T23:55:00Z</timestamp></anyExt></reports>` +
		`</history-loc-result-report></anyExt>`)
	if rr := send(ownLMS, "POST", user("sip:alice@mcx.test")+"/history", alice, history, nil); rr.Code != 200 {
		test.Fatalf("history: %d %s", rr.Code, rr.Body.String())
	}
	found := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && !found; {
		rr := send(ownLMS, "POST", sealBase+"/notifications?val="+url.QueryEscape("sip:mcptt@mcx.test")+"&wait=2", "", "", &cfgA)
		found = strings.Contains(rr.Body.String(), `trigger-id=\"history\"`) && strings.Contains(rr.Body.String(), "4470000")
	}
	if !found {
		test.Fatal("no history notification")
	}
	// The latest position is still the reported one.
	users := status(ownLMS, &cfgA)["users"].(map[string]any)
	if latest := users["sip:alice@mcx.test"].(map[string]any)["latest"].(map[string]any); latest["latitude"] != float64(4473924) {
		test.Fatalf("latest %v", latest)
	}
	// TS 24.545 clause 6.2.6.2.2: deletion ends the subscription.
	deletion := doc(`<identity><VAL-user-id><sealURI>sip:mcptt@mcx.test</sealURI></VAL-user-id></identity>` +
		`<subscription-identifier>` + answer.SubscriptionIdentifier + `</subscription-identifier><expiry-time>0</expiry-time>`)
	if rr := send(ownLMS, "POST", sealBase+"/subscriptions", "", deletion, &cfgA); rr.Code != 200 {
		test.Fatalf("deletion: %d %s", rr.Code, rr.Body.String())
	}
	if subs := status(ownLMS, &cfgA)["subscriptions"].(map[string]any); len(subs) != 0 {
		test.Fatalf("the subscription remains: %v", subs)
	}
}
