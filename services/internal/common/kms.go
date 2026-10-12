//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// KMS: the key management server of TS 33.180 clause 5.3, answering the KMS requests of annex D.2 (Initialize,
// KeyProvision and CertCache, over direct TLS) with the KMS responses of annex D.3, computed by the native
// ECCSI/SAKKE key tool.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19), RFC 6507,
// RFC 6508, RFC 5905.
package common

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// TS 33.180 clause 5.3.1.2: the key period of the identity keys, 30 days (in seconds).
	kmsKeyPeriodSeconds = 30 * 24 * 60 * 60
	// RFC 5905 section 6: the seconds from the NTP epoch (1900) to the Unix epoch (1970).
	ntpUnixOffset = 2208988800
	// The largest request body read: anything at all is refused (no TrK/InK, annex D.2.2), one byte more than
	// 64 KiB tells a large body from a small one.
	kmsMaxRequestBody = 64<<10 + 1
	// OpenMCX: key tool runs at a time (each one a process); further requests wait for a slot.
	maxConcurrentKeyTool = 4
)

// KeyTool is the native, standard ECCSI/SAKKE backend. Inputs and outputs can
// contain private key material: never include either in logs or HTTP errors.
type KeyTool func(map[string]any) (json.RawMessage, error)

// ------------------------------------------------------------------------------
// Helper: an option that replaces the ECCSI/SAKKE key tool.
func WithKeyTool(fn KeyTool) Option { return func(svc *service) { svc.keyTool = fn } }

// ------------------------------------------------------------------------------
// Helper: runs mcx-keytool, the native ECCSI (RFC 6507) and SAKKE (RFC 6508) backend, with one JSON request on its
// standard input, and returns its JSON answer.
func nativeKeyTool(input map[string]any) (json.RawMessage, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "mcx-keytool")
	cmd.Stdin = bytes.NewReader(raw)
	var output, failure bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &failure
	if err = cmd.Run(); err != nil {
		// The IS proxy's reason names no key material (see mcx-keytool).
		if reason := strings.TrimSpace(failure.String()); strings.HasPrefix(reason, "is-proxy: ") && len(reason) < 200 {
			return nil, errors.New(reason)
		}
		return nil, errors.New("native key operation unavailable")
	}
	if output.Len() > 1<<20 || !json.Valid(output.Bytes()) {
		return nil, errors.New("invalid native key response")
	}
	return json.RawMessage(output.Bytes()), nil
}

// ------------------------------------------------------------------------------
// Helper: runs the key tool for a request, at most maxConcurrentKeyTool at a time; the requests do not wait for
// one another otherwise (the key tool keeps no state between runs).
func (svc *service) runKeyTool(input map[string]any) (json.RawMessage, error) {
	svc.keyToolSlots <- struct{}{}
	defer func() { <-svc.keyToolSlots }()
	return svc.keyTool(input)
}

// ------------------------------------------------------------------------------
// TS 33.180 clause 5.3.1.2: loads the Home KMS's authority (its secrets and the public parameters of its KMS
// certificate, annex D.3.2) from the data directory, or has the key tool generate it (key period 30 days) and
// persists it privately; without the key tool the KMS stays unavailable.
func (svc *service) initializeKMS() error {
	path := filepath.Join(svc.dataDir, "kms-authority.json")
	raw, err := os.ReadFile(path)
	if err == nil {
		if !json.Valid(raw) {
			return errors.New("invalid persisted KMS authority")
		}
		info, statErr := os.Stat(path)
		if statErr != nil || info.Mode().Perm()&0077 != 0 {
			return errors.New("KMS authority permissions must be private")
		}
		svc.kmsAuthority = raw
		return nil
	}
	if !os.IsNotExist(err) {
		return errors.New("cannot read KMS authority")
	}
	raw, err = svc.keyTool(map[string]any{"op": "authority-generate", "kms_uri": svc.cfg.Endpoints.KMS, "key_period": kmsKeyPeriodSeconds, "key_offset": 0})
	if err != nil {
		svc.kmsError = err
		return nil
	}
	if !json.Valid(raw) {
		return errors.New("invalid generated KMS authority")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create KMS authority")
	}
	_, err = file.Write(raw)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errors.New("cannot persist KMS authority")
	}
	svc.kmsAuthority = raw
	return nil
}

// ------------------------------------------------------------------------------
// TS 33.180 annex D.2: the KMS request URIs (init, keyprov and certcache) and the internal requests of the MC servers and the GMS.
func (svc *service) routesKMS(mux *http.ServeMux) {
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, _ *http.Request) {
		if svc.kmsError != nil || len(svc.kmsAuthority) == 0 {
			writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "reason": "native KMS backend unavailable"})
			return
		}
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("POST /keymanagement/identity/v1/{operation}", svc.kmsProvision)
	// TS 33.180 annex D.2.5: a client naming the version of the cache it holds gets the current one.
	mux.HandleFunc("POST /keymanagement/identity/v1/certcache/{version}", svc.kmsProvision)
	mux.HandleFunc("POST /keymanagement/identity/v1/keyprov/{identity}", svc.kmsProvision)
	mux.HandleFunc("POST /keymanagement/identity/v1/keyprov/{identity}/{timestamp}", svc.kmsProvision)
	mux.HandleFunc("POST /internal/keymanagement/{operation}", svc.kmsProvision)
}

// ------------------------------------------------------------------------------
// TS 33.180 annex D.2.3, D.2.4 and D.2.5: answers a KMS Initialize, KeyProvision or CertCache request with its KMS
// response XML (annex D.3): for a signed-in user with the key management scope (annex B.4.2.2), its MCPTT, MCData
// or MCVideo ID; for an MC server, its public service identity; for the GMS, its identity. A KeyProvision request
// may name the key period by its NTP timestamp (RFC 5905).
func (svc *service) kmsProvision(writer http.ResponseWriter, request *http.Request) {
	user := ""
	operation := request.PathValue("operation")
	if request.PathValue("version") != "" {
		operation = "certcache"
	}
	if operation == "" {
		operation = "keyprov"
	}
	if operation != "init" && operation != "keyprov" && operation != "certcache" {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	if strings.HasPrefix(request.URL.Path, "/internal/") {
		client, secret, basic := request.BasicAuth()
		gms := basic && svc.cfg.GMSKeyClientID != "" && svc.cfg.GMSKeySecret != "" &&
			client == svc.cfg.GMSKeyClientID && subtle.ConstantTimeCompare([]byte(secret), []byte(svc.cfg.GMSKeySecret)) == 1
		as := svc.internalAuthorized(request)
		if !as && !gms {
			writer.Header().Set("WWW-Authenticate", `Basic realm="mcx-kms"`)
			writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		user = request.URL.Query().Get("identity")
		server := user == svc.cfg.ServiceURI || (svc.cfg.MCDataService.ServiceURI != "" && user == svc.cfg.MCDataService.ServiceURI) ||
			(svc.cfg.MCVideoService.ServiceURI != "" && user == svc.cfg.MCVideoService.ServiceURI)
		if !(as && server) && !(gms && user == svc.cfg.Endpoints.GMS+"/xcap-root/org.openmobilealliance.groups") {
			writeJSON(writer, http.StatusForbidden, map[string]string{"error": "forbidden_identity"})
			return
		}
	} else {
		claims, ok := svc.authenticateBearer(writer, request)
		if !ok {
			return
		}
		if !containsWord(claims.Scope, "3gpp:mc:ptt_key_management_service") {
			writeJSON(writer, http.StatusForbidden, map[string]string{"error": "insufficient_scope"})
			return
		}
		current, exists := svc.siteUser("mcptt_id", claims.MCPTTID)
		if !exists || current.ClientID != claims.ClientID {
			writeJSON(writer, http.StatusForbidden, map[string]string{"error": "forbidden_identity"})
			return
		}
		user = claims.MCPTTID
		if id := request.PathValue("identity"); id != "" && id != user {
			// TS 33.180 clause 5.3 and TS 24.282 clause 6.6: key material for the user's MCData ID,
			// which signs and receives MCData PCKs, under the MCData KMS scope; and
			// (TS 24.281 clause 4.7) for its MCVideo ID under the MCVideo KMS scope.
			data := claims.MCDataID != "" && id == claims.MCDataID && current.MCDataID == claims.MCDataID &&
				containsWord(claims.Scope, "3gpp:mc:data_key_management_service")
			video := claims.MCVideoID != "" && id == claims.MCVideoID && current.MCVideoID == claims.MCVideoID &&
				containsWord(claims.Scope, "3gpp:mc:video_key_management_service")
			if !data && !video {
				writeJSON(writer, http.StatusForbidden, map[string]string{"error": "forbidden_identity"})
				return
			}
			user = id
		}
	}
	// This direct-TLS profile does not implement the optional TrK/InK extension (TS 33.180 annex D.2.2);
	// reject submitted protected request bodies instead of pretending to verify them.
	body, err := io.ReadAll(io.LimitReader(request.Body, kmsMaxRequestBody))
	if err != nil || len(body) > 0 {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "unsupported_request_body"})
		return
	}
	now := uint64(svc.now().Unix() + ntpUnixOffset)
	if requested := request.PathValue("timestamp"); requested != "" {
		value, parseErr := strconv.ParseUint(requested, 16, 64)
		if parseErr != nil || len(requested) != 16 {
			writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_timestamp"})
			return
		}
		// A client cannot request future identity keys or arbitrary historical periods.
		selected := value >> 32
		if selected > now || now-selected > kmsKeyPeriodSeconds {
			writeJSON(writer, http.StatusForbidden, map[string]string{"error": "unavailable_key_period"})
			return
		}
		now = selected
	}
	if svc.kmsError != nil || len(svc.kmsAuthority) == 0 {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "kms_unavailable"})
		return
	}
	input := map[string]any{"op": "kms-" + operation, "authority": svc.kmsAuthority, "user_uri": user, "ntp_seconds": now, "request_uri": svc.cfg.Endpoints.KMS + request.URL.RequestURI()}
	raw, err := svc.runKeyTool(input)
	var result struct {
		XML string `json:"xml"`
	}
	if err != nil || json.Unmarshal(raw, &result) != nil || result.XML == "" {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "key_provision_failed"})
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/xml")
	writer.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(writer, result.XML)
}
