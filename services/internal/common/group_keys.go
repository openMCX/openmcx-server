//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Group keys: the GMK epochs the GMS generates, persists and rotates on a membership change, and the Group Key
// Transport Payload it provides to the MC service servers for a member of a protected group.
//
// Specifications: TS 33.180 V19.4.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19), TS 24.281 V19.6.0 (Rel-19).
package common

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ------------------------------------------------------------------------------
// Helper: these records are private GMS state, never an HTTP response. The public
// identifier changes with every key epoch, including membership changes.
var errGroupKeyPermissions = errors.New("group key permissions invalid")

// ------------------------------------------------------------------------------
// TS 33.180 clause 5.7.2: one GMK epoch of a group: the GMK, its random value, the GMK-ID and the activation and
// expiry times (TS 33.180 annex E.6.4 and annex E.6.10), with the membership it was generated for.
type groupKeyRecord struct {
	GroupID    string `json:"group_id"`
	Membership string `json:"membership"`
	Key        string `json:"key"`
	Random     string `json:"random"`
	ID         uint32 `json:"id"`
	ValidFrom  uint64 `json:"valid_from"`
	ValidTo    uint64 `json:"valid_to"`
}

// ------------------------------------------------------------------------------
// Helper: a digest of the group ID and its sorted members; a change of it starts a new GMK epoch.
func groupMembership(group Group) string {
	members := append([]string(nil), group.Members...)
	sort.Strings(members)
	raw, _ := json.Marshal(struct { // strings only: cannot fail
		ID      string
		Members []string
	}{group.ID, members})
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

// ------------------------------------------------------------------------------
// Helper: the file of a group's GMK epoch in the data directory, named by a digest of the group ID.
func groupKeyPath(dir, group string) string {
	hash := sha256.Sum256([]byte(group))
	return filepath.Join(dir, "group-key-"+hex.EncodeToString(hash[:])+".json")
}

// ------------------------------------------------------------------------------
// TS 33.180 clause 5.7.2: the current GMK epoch of a group, read from its file, or generated anew when there is none,
// it has expired or the membership changed: a random 128-bit GMK and random value, and a GMK-ID with purpose tag 0
// (TS 33.180 annex G, table G-1), different from the previous one. The file is written atomically, readable only by
// the GMS.
func groupKeyEpoch(dir string, group Group, now uint64, lifetime time.Duration) (groupKeyRecord, error) {
	path := groupKeyPath(dir, group.ID)
	var record groupKeyRecord
	raw, err := os.ReadFile(path)
	if err == nil {
		info, checkErr := os.Lstat(path)
		if checkErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return record, errGroupKeyPermissions
		}
		if json.Unmarshal(raw, &record) != nil || record.GroupID != group.ID || record.ID>>28 != 0 || record.ID == 0 || record.ValidTo <= record.ValidFrom {
			return record, errors.New("invalid persisted group key")
		}
		key, checkErr := hex.DecodeString(record.Key)
		random, re := hex.DecodeString(record.Random)
		if checkErr != nil || re != nil || len(key) != 16 || len(random) != 16 {
			return record, errors.New("invalid persisted key material")
		}
		if record.ValidFrom > now {
			return record, errors.New("group key clock moved backwards")
		}
		if record.ValidTo > now && record.Membership == groupMembership(group) {
			return record, nil
		}
	} else if !os.IsNotExist(err) {
		return record, errors.New("group key state unreadable")
	}
	previous := record.ID
	// Clients reject non-advancing activation times to prevent signed old-key
	// rollback. Retry a same-second membership rotation on the next poll.
	if previous != 0 && now <= record.ValidFrom {
		return record, errors.New("group key activation has not advanced")
	}
	var material [36]byte
	if _, err = rand.Read(material[:]); err != nil {
		return record, errors.New("group key entropy unavailable")
	}
	id := binary.BigEndian.Uint32(material[32:]) & 0x0fffffff
	for id == 0 || id == previous {
		if _, err = rand.Read(material[32:]); err != nil {
			return record, err
		}
		id = binary.BigEndian.Uint32(material[32:]) & 0x0fffffff
	}
	record = groupKeyRecord{GroupID: group.ID, Membership: groupMembership(group), Key: hex.EncodeToString(material[:16]), Random: hex.EncodeToString(material[16:32]), ID: id, ValidFrom: now, ValidTo: now + uint64(lifetime/time.Second)}
	raw, err = json.Marshal(record)
	if err != nil {
		return record, err
	}
	file, err := os.CreateTemp(dir, ".group-key-*")
	if err != nil {
		return record, err
	}
	temp := file.Name()
	defer func() { _ = os.Remove(temp) }() // gone after the rename: nothing to remove
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return record, err
	}
	if closeErr != nil {
		return record, closeErr
	}
	if err = os.Rename(temp, path); err != nil {
		return record, err
	}
	dirFile, err := os.Open(dir)
	if err != nil {
		return record, err
	}
	err = dirFile.Sync()
	_ = dirFile.Close()
	return record, err
}

// ------------------------------------------------------------------------------
// Helper: the HTTPS client of the GMS for its KMS, trusting only the configured CA and following no redirect.
func groupKMSClient() (*http.Client, error) {
	roots := x509.NewCertPool()
	pem, err := os.ReadFile("/config/tls/ca.crt")
	if err != nil || !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("KMS trust anchor unavailable")
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: TLSProfile(&tls.Config{RootCAs: roots})}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("KMS redirect forbidden") }}, nil
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.7.3 and clause 7.7.10: the routes of the group keys: the internal GKTP request of the MC service
// servers.
func (svc *service) routesGroupKeys(mux *http.ServeMux) {
	mux.HandleFunc("GET /internal/gktp", newGroupKeyHandler(svc, nil, 24*time.Hour))
}

// ------------------------------------------------------------------------------
// TS 33.180 clause 5.7.2: the GMS provides the Group Key Transport Payload (TS 24.481 clause 7.4.2) of the current
// GMK epoch for a member of a protected group, encrypted to the member under the KMS and signed by the GMS.
func newGroupKeyHandler(svc *service, client *http.Client, lifetime time.Duration) http.HandlerFunc {
	mu := &svc.groupKeyMu
	// The KMS client, made at first use and kept (its connections are reused).
	var kmsMu sync.Mutex
	var kmsClient *http.Client
	kmsClientOnce := func() (*http.Client, error) {
		kmsMu.Lock()
		defer kmsMu.Unlock()
		if kmsClient == nil {
			made, err := svc.keyClient(client)
			if err != nil {
				return nil, err
			}
			kmsClient = made
		}
		return kmsClient, nil
	}
	return func(writer http.ResponseWriter, request *http.Request) {
		if !svc.requireInternal(writer, request) {
			return
		}
		group, exists := svc.group(request.URL.Query().Get("group_id"))
		if !exists {
			writeJSON(writer, 404, map[string]string{"error": "group_not_found"})
			return
		}
		// A temporary group's members are those of its constituent groups.
		group = svc.keyGroup(group)
		user := request.URL.Query().Get("user_id")
		// An MCVideo server asks for its user's MCVideo ID, a member of the group's
		// MCVideo members (TS 24.281 clause 4.7.1; TS 33.180 clause 5.7).
		_, known := svc.siteUser("mcptt_id", user)
		members := group.Members
		if !known {
			if _, video := svc.siteUser("mcvideo_id", user); video && group.MCVideo != nil {
				known, members = true, group.MCVideo.Members
			}
		}
		member := false
		for _, id := range members {
			if id == user {
				member = true
			}
		}
		if !known || !member {
			writeJSON(writer, 403, map[string]string{"error": "group_membership_required"})
			return
		}
		if !group.ProtectMedia {
			writeJSON(writer, 409, map[string]string{"error": "group_media_not_protected"})
			return
		}
		if lifetime < time.Second || lifetime > 30*24*time.Hour {
			writeJSON(writer, 503, map[string]string{"error": "invalid_group_key_lifetime"})
			return
		}
		mu.Lock()
		defer mu.Unlock()
		now := uint64(svc.now().Unix())
		gmsURI := strings.TrimRight(svc.cfg.Endpoints.GMS, "/") + "/xcap-root/org.openmobilealliance.groups"
		epoch, err := groupKeyEpoch(svc.dataDir, group, now, lifetime)
		if err != nil {
			code := "group_key_state_unavailable"
			if errors.Is(err, errGroupKeyPermissions) {
				code = "group_key_permissions_invalid"
			}
			writeJSON(writer, 503, map[string]string{"error": code})
			return
		}
		// Authorize membership and refresh the epoch before comparing the public
		// identifier. An unchanged subscription needs no KMS or private operation.
		if known := request.URL.Query().Get("known_key_id"); known != "" {
			id, parseErr := strconv.ParseUint(known, 10, 32)
			if parseErr != nil {
				writeJSON(writer, 400, map[string]string{"error": "invalid_known_key_id"})
				return
			}
			if uint32(id) == epoch.ID {
				writer.Header().Set("Cache-Control", "no-store")
				writer.WriteHeader(http.StatusNotModified)
				return
			}
		}
		kms, err := kmsClientOnce()
		if err != nil {
			writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "kms_trust_unavailable"})
			return
		}
		parsed, err := url.Parse(svc.cfg.Endpoints.KMS)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			writeJSON(writer, 503, map[string]string{"error": "invalid_kms_endpoint"})
			return
		}
		input := map[string]any{"op": "gktp", "kms_uri": svc.cfg.Endpoints.KMS, "gms_uri": gmsURI, "recipient": user, "group_id": group.ID, "key_hex": epoch.Key, "random_hex": epoch.Random, "csb_id": epoch.ID, "ntp_seconds": now + ntpUnixOffset, "valid_from": epoch.ValidFrom, "valid_to": epoch.ValidTo, "key_parameter_profile": svc.cfg.Security.KeyParameterProfile}
		if code := svc.gmsKeyDocuments(request.Context(), kms, input); code != "" {
			writeJSON(writer, 503, map[string]string{"error": code})
			return
		}
		raw, err := svc.keyTool(input)
		var result struct {
			Document string `json:"document"`
		}
		if err != nil || json.Unmarshal(raw, &result) != nil || result.Document == "" {
			writeJSON(writer, 503, map[string]string{"error": "group_key_encapsulation_failed"})
			return
		}
		writeJSON(writer, 200, map[string]any{"document": result.Document, "key_id": epoch.ID, "expires": epoch.ValidTo})
	}
}

// ------------------------------------------------------------------------------
// TS 33.180 clause 5.3.3 and annex D.2.3 and D.2.4: gmsKeyDocuments adds this GMS's KMS documents to a key tool
// input: the init and key provisioning responses, requested on the KMS request URIs with the access token of its key
// management client (key_clients.go).
func (svc *service) gmsKeyDocuments(ctx context.Context, client *http.Client, input map[string]any) string {
	gmsURI, _ := input["gms_uri"].(string)
	parsed, err := url.Parse(svc.cfg.Endpoints.KMS)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "invalid_kms_endpoint"
	}
	var key KeyClient
	for _, candidate := range svc.cfg.KeyClients {
		if candidate.Identity == gmsURI {
			key = candidate
		}
	}
	if key.ClientID == "" {
		return "no_key_client"
	}
	token, err := svc.keyClientAccessToken(ctx, client, key)
	if err != nil {
		return "key_client_token_unavailable"
	}
	base := strings.TrimRight(svc.cfg.Endpoints.KMS, "/") + "/keymanagement/identity/v1/"
	for _, op := range []string{"init", "keyprov"} {
		target := base + op
		if op == "keyprov" {
			// TS 33.180 annex D.2.4: the key provisioning request names the identity.
			target += "/" + url.PathEscape(gmsURI)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, nil)
		if err != nil {
			return "kms_request_failed"
		}
		req.Header.Set("Authorization", "Bearer "+token)
		// Disable redirects even on an injected client so credentials cannot leave
		// the configured KMS authority.
		requestClient := *client
		requestClient.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("KMS redirect forbidden") }
		resp, err := requestClient.Do(req)
		if err != nil {
			return "kms_provision_unavailable"
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || len(body) > 1<<20 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/xml") {
			return "kms_provision_failed"
		}
		input["kms_"+op+"_xml"] = string(body)
		input[op+"_request_uri"] = target
	}
	return ""
}

// ------------------------------------------------------------------------------
// Helper: the HTTPS client for the KMS: the given one, the configured one, or one trusting the configured CA.
func (svc *service) keyClient(client *http.Client) (*http.Client, error) {
	if client != nil {
		return client, nil
	}
	if svc.gmsKMSClient != nil {
		return svc.gmsKMSClient, nil
	}
	return groupKMSClient()
}
