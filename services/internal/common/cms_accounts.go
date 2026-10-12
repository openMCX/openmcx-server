// CMS user records: the user record the CMS serves its profile documents from, taken from site.json or, in admin
// mode, from MCX Admin (OpenMCX's own MCX Admin integration, not a 3GPP procedure).
//
// Specifications: TS 24.484 V19.6.0 (Rel-19).
package common

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ------------------------------------------------------------------------------
// Not 3GPP (MCX Admin integration): siteUser is the user record the CMS serves from (profile documents, TS 24.484,
// and the servers' /internal/user view), by MCPTT, MCData or MCVideo ID. With admin_accounts it comes from MCX
// Admin: the user's identities and effective profile, active accounts only, no secret.
// Otherwise it is the site.json record, as before.
func (svc *service) siteUser(key, value string) (User, bool) {
	if svc.cfg.AdminAccounts == nil {
		switch key {
		case "mcdata_id":
			return svc.cfg.userByMCDataID(value)
		case "mcvideo_id":
			return svc.cfg.userByMCVideoID(value)
		}
		return svc.cfg.userByMCPTTID(value)
	}
	if svc.serviceClient == nil {
		// Started without --ca-file: MCX Admin cannot be reached, so no user is known.
		svc.logEvent("admin_accounts_unavailable", map[string]any{"error": "no service client (--ca-file)"})
		return User{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	target := strings.TrimSuffix(svc.cfg.AdminAccounts.URL, "/") + "/internal/v1/site-users?" + url.Values{key: {value}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return User{}, false
	}
	req.SetBasicAuth(svc.cfg.ServerClientID, svc.cfg.ServerSecret)
	resp, err := svc.serviceClient.Do(req)
	if err != nil {
		svc.logEvent("admin_accounts_unavailable", map[string]any{"error": err.Error()})
		return User{}, false
	}
	defer closeQuietly(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return User{}, false
	}
	var user User
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&user); err != nil || user.Password != "" || user.SIPPassword != "" {
		return User{}, false
	}
	return user, true
}
