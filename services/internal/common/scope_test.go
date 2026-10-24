//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

package common

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ------------------------------------------------------------------------------
// Helper: a signed access token of a configured user with the given scope.
func scopedToken(test *testing.T, cfg Config, key *rsa.PrivateKey, username, scope string) string {
	test.Helper()
	user, ok := cfg.userByName(username)
	if !ok {
		test.Fatalf("unknown test user %q", username)
	}
	claims, err := newClaims(cfg, user, cfg.ServerClientID, "access", "", testNow)
	if err != nil {
		test.Fatal(err)
	}
	claims.Scope = scope
	token, err := signToken(claims, key)
	if err != nil {
		test.Fatal(err)
	}
	return token
}

// ------------------------------------------------------------------------------
// TS 33.180 clause 5.1.3.1 and RFC 6750 section 3.1: a valid token without the scope of the role it is presented to
// is answered 403 insufficient_scope with the Bearer challenge; with that scope it passes the check.
func TestRolesRequireTheirScope(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	alice := url.PathEscape("sip:alice@mcx.test")
	for _, tc := range []struct {
		role         Role
		method, path string
		scope        string
	}{
		{RoleCMS, http.MethodGet, "/xcap-root/" + locationConfigAUID + "/users/" + alice + "/location-user-config-1.xml", scopeDataConfig},
		{RoleGMS, http.MethodGet, "/xcap-root/org.openmobilealliance.groups/global/byGroupID/" + url.PathEscape("sip:team@mcx.test"), "3gpp:mc:video_group_management_service"},
		{RoleLMS, http.MethodGet, "/location/" + alice, scopeLocation},
		{RoleMsgStore, http.MethodGet, "/nms/v1/msgstore/" + alice + "/objects/x", scopeDataService},
		{RoleNotification, http.MethodGet, "/notificationchannel/v1/" + alice + "/channels/x", scopeDataService},
		{RoleContent, http.MethodGet, "/mcdata/files/x/y", scopeDataService},
	} {
		handler := roleHandler(test, tc.role, cfg, key, test.TempDir())
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, bearerRequest(tc.method, tc.path, scopedToken(test, cfg, key, "alice", "openid 3gpp:mc:ptt_service"), nil))
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "insufficient_scope") ||
			!strings.Contains(rr.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`) {
			test.Fatalf("%s %s without scope: %d %q %s", tc.role, tc.path, rr.Code, rr.Header().Get("WWW-Authenticate"), rr.Body.String())
		}
		rr = httptest.NewRecorder()
		handler.ServeHTTP(rr, bearerRequest(tc.method, tc.path, scopedToken(test, cfg, key, "alice", "openid "+tc.scope), nil))
		if strings.Contains(rr.Body.String(), "insufficient_scope") {
			test.Fatalf("%s %s refused under %s: %d %s", tc.role, tc.path, tc.scope, rr.Code, rr.Body.String())
		}
	}
}

// ------------------------------------------------------------------------------
// TS 33.180 clause 5.1.3.1: a configuration management document of one MC service is served under that service's
// configuration management scope only: the MCPTT user profile and service configuration under the MCPTT one.
func TestCMSDocumentsRequireTheirServiceScope(test *testing.T) {
	cfg, key := testConfig(), testKey(test)
	handler := roleHandler(test, RoleCMS, cfg, key, test.TempDir())
	profile := "/xcap-root/org.3gpp.mcptt.user-profile/users/" + url.PathEscape("sip:alice@mcx.test") + "/mcptt-user-profile-1.xml"
	for _, tc := range []struct {
		path, scope string
		status      int
	}{
		{profile, scopeVideoConfig, http.StatusForbidden},
		{profile, scopePTTConfig, http.StatusOK},
		{"/xcap-root/org.3gpp.mcptt.service-config/global/service-config.xml", scopeDataConfig, http.StatusForbidden},
		{"/xcap-root/org.3gpp.mcptt.service-config/global/service-config.xml", scopePTTConfig, http.StatusOK},
		{"/xcap-root/org.3gpp.mcdata.service-config/global/service-config.xml", scopeDataConfig, http.StatusOK},
	} {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, bearerRequest(http.MethodGet, tc.path, scopedToken(test, cfg, key, "alice", "openid "+tc.scope), nil))
		if rr.Code != tc.status {
			test.Fatalf("%s under %s: %d want %d %s", tc.path, tc.scope, rr.Code, tc.status, rr.Body.String())
		}
		if tc.status == http.StatusForbidden && !strings.Contains(rr.Header().Get("WWW-Authenticate"), `scope="3gpp:mc:ptt_config_management_service"`) {
			test.Fatalf("challenge does not name the scope: %q", rr.Header().Get("WWW-Authenticate"))
		}
	}
}
