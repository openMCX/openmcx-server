//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ------------------------------------------------------------------------------
// TS 24.484 clauses 8.4, 9.4 and 10.4: every signed-in user reads the three service configuration documents at
// CMSXCAPROOTURI/<AUID>/global/service-config.xml, valid against their schemas, with the RFC 8101 resource priorities
// of the site (or the defaults); the servers get the same values on the internal interface.
func TestServiceConfigurationDocuments(test *testing.T) {
	key := testKey(test)
	cfg := testConfig()
	cfg.ServiceConfig = ServiceConfiguration{
		MCPTT:  &MCPTTServiceConfiguration{ResourcePriority: ResourcePriorities{Emergency: "mcpttq.14", Imminent: "mcpttq.9", Normal: "mcpttq.1"}, FloorQueue: true, FloorTimers: map[string]int{"t1": 5500}},
		MCData: &MCDataServiceConfiguration{DefaultFileAvailabilityS: 600}}
	cms := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	alice := tokenFor(test, cfg, key, "alice", testNow, cfg.ServerClientID)
	for _, tc := range []struct {
		auid, mime string
		schema     *documentSchema
		want       []string
	}{
		{"org.3gpp.mcptt.service-config", "application/vnd.3gpp.mcptt-service-config+xml", mcpttServiceConfigSchema,
			[]string{`<service-configuration-params domain="` + cfg.Domain + `">`, "<T1-end-of-rtp-media>PT5.5S</T1-end-of-rtp-media>",
				"<C7-floor-idle>10</C7-floor-idle>", "<floor-control-queue><depth>1</depth></floor-control-queue>",
				"<emergency-resource-priority><resource-priority-namespace>mcpttq</resource-priority-namespace><resource-priority-priority>14</resource-priority-priority>",
				"<normal-resource-priority><resource-priority-namespace>mcpttq</resource-priority-namespace><resource-priority-priority>1</resource-priority-priority>",
				"<anyExt><max-simultaneous-authorizations>1</max-simultaneous-authorizations></anyExt></on-network>"}},
		{"org.3gpp.mcvideo.service-config", "application/vnd.3gpp.mcvideo-service-config+xml", mcvideoServiceConfigSchema,
			[]string{"<imminent-peril-resource-priority><resource-priority-namespace>mcpttp</resource-priority-namespace><resource-priority-priority>10</resource-priority-priority>",
				"<anyExt><max-simultaneous-authorizations>1</max-simultaneous-authorizations></anyExt></on-network>"}},
		{"org.3gpp.mcdata.service-config", "application/vnd.3gpp.mcdata-service-config+xml", mcdataServiceConfigSchema,
			[]string{"<default-file-availability>600</default-file-availability>",
				"<anyExt><emergency-resource-priority><resource-priority-namespace>mcpttp</resource-priority-namespace><resource-priority-priority>15</resource-priority-priority>",
				"</normal-resource-priority><max-simultaneous-authorizations>1</max-simultaneous-authorizations></anyExt>"}},
	} {
		rr := httptest.NewRecorder()
		cms.ServeHTTP(rr, bearerRequest("GET", "/xcap-root/"+tc.auid+"/global/service-config.xml", alice, nil))
		if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != tc.mime+"; charset=utf-8" {
			test.Fatalf("%s: status=%d type=%q body=%s", tc.auid, rr.Code, rr.Header().Get("Content-Type"), rr.Body.String())
		}
		if err := tc.schema.validate(rr.Body.Bytes()); err != nil {
			test.Fatalf("%s fails its schema: %v\n%s", tc.auid, err, rr.Body.String())
		}
		for _, want := range tc.want {
			if !strings.Contains(rr.Body.String(), want) {
				test.Fatalf("%s lacks %s:\n%s", tc.auid, want, rr.Body.String())
			}
		}
		// Without an access token: refused.
		rr = httptest.NewRecorder()
		cms.ServeHTTP(rr, httptest.NewRequest("GET", "/xcap-root/"+tc.auid+"/global/service-config.xml", nil))
		if rr.Code != http.StatusForbidden {
			test.Fatalf("%s without a token: %d", tc.auid, rr.Code)
		}
	}
	// The servers' view.
	rr := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/internal/service-config?service=mcptt", nil)
	request.SetBasicAuth(cfg.ServerClientID, cfg.ServerSecret)
	cms.ServeHTTP(rr, request)
	var internal struct {
		ResourcePriority map[string]string `json:"resource_priority"`
		Timers           map[string]int    `json:"fc_timers_counters"`
		QueueDepth       int               `json:"floor_queue_depth"`
		Organization     string            `json:"organization"`
	}
	// <floor-control-queue>/<depth> as published (at least 1), and the organisation (the domain when not set).
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &internal) != nil ||
		internal.ResourcePriority["emergency"] != "mcpttq.14" || internal.Timers["t1"] != 5500 || internal.Timers["t8"] != 1000 ||
		internal.QueueDepth < 1 || internal.Organization != cfg.organization() || internal.Organization == "" {
		test.Fatalf("internal service configuration %d %s", rr.Code, rr.Body.String())
	}
}

// ------------------------------------------------------------------------------
// RFC 8101 and TS 24.484 clause 8.4.2.7: a namespace other than mcpttp or mcpttq, a level outside 0 to 15, or an
// emergency level below the imminent peril one is refused.
func TestServiceConfigurationValidation(test *testing.T) {
	for _, rp := range []ResourcePriorities{
		{Emergency: "mcptt.15"}, {Emergency: "mcpttp.16"}, {Emergency: "mcpttp.07"},
		{Emergency: "mcpttp.5", Imminent: "mcpttp.10"}, {Normal: "mcpttp.12"}, {Imminent: "dsn.flash"},
	} {
		if err := (ServiceConfiguration{MCPTT: &MCPTTServiceConfiguration{ResourcePriority: rp}}).Validate(); err == nil {
			test.Fatalf("accepted %+v", rp)
		}
	}
	if err := (ServiceConfiguration{MCData: &MCDataServiceConfiguration{ResourcePriority: ResourcePriorities{Emergency: "mcpttq.15", Imminent: "mcpttq.10", Normal: "mcpttq.0"}}}).Validate(); err != nil {
		test.Fatal(err)
	}
	if err := (ServiceConfiguration{MCPTT: &MCPTTServiceConfiguration{FloorTimers: map[string]int{"t99": 1}}}).Validate(); err == nil {
		test.Fatal("an unknown timer was accepted")
	}
}
