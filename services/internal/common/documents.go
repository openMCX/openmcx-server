//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// HTTP routes of the GMS and the CMS: group documents addressed by group ID, user profile documents, the bearer
// access token check and the internal interface the MCPTT, MCData and MCVideo servers read.
//
// Specifications: TS 24.481 V19.3.0 (Rel-19), TS 24.484 V19.6.0 (Rel-19), TS 24.482 V19.1.0 (Rel-19),
// TS 24.379 V19.7.0 (Rel-19), TS 23.280 V19.10.1 (Rel-19), RFC 4825, RFC 6750.
package common

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ------------------------------------------------------------------------------
// Helper: the user record the internal interface serves to the MC service servers.
type publicUser struct {
	// The profile index (TS 24.484 clause 8.3.2.1).
	ProfileIndex int                `json:"profile_index"`
	MCID         string             `json:"mc_id"`
	MCPTTID      string             `json:"mcptt_id"`
	SIPURI       string             `json:"sip_uri"`
	ClientID     string             `json:"client_id"`
	Groups       []string           `json:"groups"`
	PrivateCall  *PrivateCallPolicy `json:"private_call,omitempty"`
	AdhocCall    *AdhocCallPolicy   `json:"adhoc_call,omitempty"`
	GroupCall    *GroupCallPolicy   `json:"group_call,omitempty"`
	// <allow-takeover-functional-alias-other-user>.
	FunctionalAliasTakeover bool `json:"functional_alias_takeover,omitempty"`
	FunctionalAliasBinding  bool `json:"functional_alias_binding,omitempty"`
	MaxAffiliations         int  `json:"max_affiliations,omitempty"`
	// <allow-regroup> (TS 24.379 clause 16.2.2.2 step 3).
	Regroup   bool            `json:"regroup,omitempty"`
	MCDataID  string          `json:"mcdata_id,omitempty"`
	MCData    *MCDataPolicy   `json:"mcdata,omitempty"`
	MCVideoID string          `json:"mcvideo_id,omitempty"`
	MCVideo   map[string]any  `json:"mcvideo,omitempty"`
	Location  *LocationPolicy `json:"location,omitempty"`
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 7.2.10.2: the GMS routes of the group documents addressed by a group ID (retrieval, TS 24.481
// clause 6.3.3.3; retrieval excluding members, clause 6.3.16.3; element, attribute and namespace fetch, clause
// 6.3.8.3, clause 6.3.11.3 and clause 6.3.12.3), the group key routes and the internal group routes.
func (svc *service) routesGMS(mux *http.ServeMux) {
	svc.routesGroupKeys(mux)
	mux.HandleFunc("GET /xcap-root/org.openmobilealliance.groups/global/byGroupID/{group}", svc.getGroupDocument)
	mux.HandleFunc("POST /xcap-root/org.openmobilealliance.groups/global/byGroupID/{group}", svc.postGroupDocument)
	// An element, attribute or namespace fetch of a group document (TS 24.481 clause 6.3.8.3, clause 6.3.11.3, clause
	// 6.3.12.3).
	mux.HandleFunc("GET /xcap-root/org.openmobilealliance.groups/global/byGroupID/{group}/~~/{selector...}", func(writer http.ResponseWriter, request *http.Request) {
		target := xcapTarget{selector: request.PathValue("selector"), query: request.URL.RawQuery, groupID: request.PathValue("group")}
		if doc, ok := svc.documentOf(target.groupID); ok {
			target.doc = doc
		}
		svc.xcapGet(writer, request, target)
	})
	mux.HandleFunc("GET /internal/group", svc.getInternalGroup)
	mux.HandleFunc("GET /internal/temporary-groups", svc.getInternalTemporaryGroups)
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 7.4.2.2, clause 8.2.2.2, clause 8.3.2.2, clause 9.3.2.2 and clause 10.3.2.2: the CMS routes of
// the location user configuration data documents, the MCPTT UE configuration documents and the MCPTT, MCVideo and
// MCData user profile documents (application unique IDs) and the internal user routes.
func (svc *service) routesCMS(mux *http.ServeMux) {
	// The AUID "org.3gpp.mcptt.user-profile" (TS 24.484 clause 8.3.2.2) and the document
	// mcptt-user-profile-<index>.xml (clause 8.3.1A).
	mux.HandleFunc("GET /xcap-root/org.3gpp.mcptt.user-profile/users/{mcpttID}/{document}", svc.getUserProfile)
	mux.HandleFunc("PUT /xcap-root/org.3gpp.mcptt.user-profile/users/{mcpttID}/{document}", svc.putUserProfile)
	mux.HandleFunc("GET /internal/user-profile", svc.getInternalUserProfile)
	mux.HandleFunc("GET /internal/user", svc.getInternalUser)
	mux.HandleFunc("GET /internal/functional-alias", svc.getInternalFunctionalAlias)
	mux.HandleFunc("GET /xcap-root/org.3gpp.mcvideo.user-profile/users/{mcvideoID}/{document}", svc.getMCVideoProfile)
	mux.HandleFunc("GET /xcap-root/org.3gpp.mcdata.user-profile/users/{mcdataID}/{document}", svc.getMCDataProfile)
	// TS 24.484 clauses 8.4.2.8, 9.4.2.8 and 10.4.2.8: the global service configuration documents.
	mux.HandleFunc("GET /xcap-root/{auid}/global/{document}", svc.getServiceConfig)
	mux.HandleFunc("GET /internal/service-config", svc.getInternalServiceConfig)
	mux.HandleFunc("GET /xcap-root/"+locationConfigAUID+"/users/{serviceID}/{document}", svc.getLocationConfig)
	// TS 24.484 clause 8.2.1A: the MCPTT UE configuration document of a user's UE.
	mux.HandleFunc("GET /xcap-root/"+mcpttUEConfigAUID+"/users/{mcpttID}/{document}", svc.getMCPTTUEConfig)
	// TS 24.484 clause 6.3.13.3.2.2 step e: the entity tags of the documents of a configuration subscription.
	mux.HandleFunc("GET /internal/configuration-document", svc.getInternalConfigurationDocument)
}

// ------------------------------------------------------------------------------
// TS 24.482 annex A.2.3 step 2: the HTTP server of the GMS and the CMS (TS 24.484 clause 6.2.4.1) validates the bearer access token (RFC 6750) and takes the MC service ID of the token as the
// identity of the sender of the request.
func (svc *service) authenticateBearer(writer http.ResponseWriter, request *http.Request) (TokenClaims, bool) {
	const prefix = "Bearer "
	value := request.Header.Get("Authorization")
	if value == "" {
		// TS 24.482 annex A.2.3 step 1: no bearer access token.
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "no_identity"})
		return TokenClaims{}, false
	}
	if len(value) <= len(prefix) || value[:len(prefix)] != prefix {
		bearerDenied(writer)
		return TokenClaims{}, false
	}
	claims, err := VerifyAccessToken(value[len(prefix):], svc.verificationKey, svc.cfg.Issuer, svc.cfg.ServerClientID, svc.now())
	if err != nil {
		bearerDenied(writer)
		return TokenClaims{}, false
	}
	// TS 33.180 clause 5.1.3.1: the access token is scoped for the service it is presented to.
	if scopes := roleScopes(svc.role); len(scopes) > 0 && !hasScope(claims, scopes...) {
		insufficientScope(writer, scopes...)
		return TokenClaims{}, false
	}
	return claims, true
}

// Scope values of TS 33.180 table B.4.2.2-1.
const (
	scopePTTConfig   = "3gpp:mc:ptt_config_management_service"
	scopeVideoConfig = "3gpp:mc:video_config_management_service"
	scopeDataConfig  = "3gpp:mc:data_config_management_service"
	scopeLocation    = "3gpp:mc:location_management_service"
	scopeDataService = "3gpp:mc:data_service"
	scopePTTKeys     = "3gpp:mc:ptt_key_management_service"
	scopeDataKeys    = "3gpp:mc:data_key_management_service"
	scopeVideoKeys   = "3gpp:mc:video_key_management_service"
)

// ------------------------------------------------------------------------------
// TS 33.180 clause 5.1.3.1 and table B.4.2.2-1: the scopes of which an access token presented to a role carries at
// least one: the CMS a configuration management scope and the GMS a group management scope, of any MC service (the
// documents of each MC service are checked further where they are served, requireScope); the location management
// server the location management scope; the KMS a key management scope (kmsProvision checks the one of each MC
// service ID); and the MCData content server, message store (TS 33.180 clause 8.6.0, "appropriately scoped access
// token for MCData") and notification server the MCData service scope. The Credential Service (not 3GPP) needs none.
func roleScopes(role Role) []string {
	switch role {
	case RoleCMS:
		return []string{scopePTTConfig, scopeVideoConfig, scopeDataConfig}
	case RoleGMS:
		return []string{"3gpp:mc:ptt_group_management_service", "3gpp:mc:video_group_management_service",
			"3gpp:mc:data_group_management_service"}
	case RoleLMS:
		return []string{scopeLocation}
	case RoleKMS:
		return []string{scopePTTKeys, scopeDataKeys, scopeVideoKeys}
	case RoleContent, RoleMsgStore, RoleNotification:
		return []string{scopeDataService}
	}
	return nil
}

// ------------------------------------------------------------------------------
// Helper: the access token's scope contains one of the scopes.
func hasScope(claims TokenClaims, scopes ...string) bool {
	for _, scope := range scopes {
		if containsWord(claims.Scope, scope) {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------------------
// TS 33.180 clause 5.1.3.1: requireScope: a document of one MC service is served under that service's scope only
// (TS 33.180 clause 5.1.3.1: "This configuration management authorisation may be repeated for each CM service");
// otherwise answers as insufficientScope.
func requireScope(writer http.ResponseWriter, claims TokenClaims, scope string) bool {
	if containsWord(claims.Scope, scope) {
		return true
	}
	insufficientScope(writer, scope)
	return false
}

// ------------------------------------------------------------------------------
// RFC 6750 sections 3 and 3.1: a valid access token without the scope the resource requires is answered 403 with the
// error code insufficient_scope in the WWW-Authenticate challenge, with the scope attribute when one scope is required
// (the attribute lists scopes all required, not alternatives).
func insufficientScope(writer http.ResponseWriter, scopes ...string) {
	challenge := `Bearer realm="mcx-common", error="insufficient_scope"`
	if len(scopes) == 1 {
		challenge += `, scope="` + scopes[0] + `"`
	}
	writer.Header().Set("WWW-Authenticate", challenge)
	writeJSON(writer, http.StatusForbidden, map[string]string{"error": "insufficient_scope"})
}

// ------------------------------------------------------------------------------
// RFC 6750 section 3.1: a request with an invalid or expired bearer access token, or another authentication scheme,
// is answered 401 with a WWW-Authenticate challenge (invalid_token: a client signs in again or refreshes its token).
// A request without a token gets 403 (TS 24.482 annex A.2.3 step 1, authenticateBearer).
func bearerDenied(writer http.ResponseWriter) {
	writer.Header().Set("WWW-Authenticate", `Bearer realm="mcx-common"`)
	writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.3.3: the GMS answers a retrieval of a group document addressed by its group ID (TS 24.481
// clause 7.2.10.2), reduced to what the authenticated identity may read (TS 24.481 clause 7.2.12.1).
func (svc *service) getGroupDocument(writer http.ResponseWriter, request *http.Request) {
	svc.serveGroupDocument(writer, request, true)
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.16.3: an HTTP POST with a GMOP document (TS 24.481 clause 7.3.4.2, MIME type of clause
// 7.3.2) asks for the group document without the <list> of its members.
func (svc *service) postGroupDocument(writer http.ResponseWriter, request *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, 64<<10))
	if err != nil {
		writeJSON(writer, http.StatusRequestEntityTooLarge, map[string]string{"error": "too_large"})
		return
	}
	if !strings.EqualFold(mediaType(request.Header.Get("Content-Type")), gmopMIME) {
		writeJSON(writer, http.StatusUnsupportedMediaType, map[string]string{"error": "unsupported_media_type"})
		return
	}
	exclude, err := gmopGetExcludingMemberList(raw)
	if err != nil || !exclude {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "unsupported_gmop_request"})
		return
	}
	svc.serveGroupDocument(writer, request, false)
}

// ------------------------------------------------------------------------------
// TS 24.481 clause 6.3.3.3 and clause 6.3.16.3: the GMS serves a group document, with or without its member list,
// reduced by the authorization policy of TS 24.481 clause 7.2.12.1.
func (svc *service) serveGroupDocument(writer http.ResponseWriter, request *http.Request, withList bool) {
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok {
		return
	}
	group, ok := svc.group(request.PathValue("group"))
	if !ok {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	// The owner and the managers of a document read all of it (TS 24.481 clause 7.2.12.1).
	if doc, stored := svc.documentOf(group.ID); stored && svc.mayManage(claims.MCPTTID, doc) && withList {
		writeDocument(writer, request, doc.XML, groupDocumentMIME)
		return
	}
	readable, ok := readableGroup(group, claims.MCPTTID, false)
	// A temporary group lists no members: those of its constituent groups read it.
	if len(group.TemporaryConstituents) > 0 {
		readable, ok = group, slices.Contains(svc.keyGroup(group).Members, claims.MCPTTID)
	}
	if !ok {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	raw, err := groupDocument(readable, withList)
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeDocument(writer, request, raw, groupDocumentMIME)
}

// ------------------------------------------------------------------------------
// Helper: the media type of a Content-Type header field value, without parameters, in lower case.
func mediaType(value string) string {
	if index := strings.IndexByte(value, ';'); index >= 0 {
		value = value[:index]
	}
	return strings.ToLower(strings.TrimSpace(value))
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 6.3.3.3: the CMS answers a retrieval of an MCPTT user profile document; the user of the profile
// and a configuration manager may read it (access permissions of TS 24.484 clause 8.3.2.11).
func (svc *service) getUserProfile(writer http.ResponseWriter, request *http.Request) {
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok || !requireScope(writer, claims, scopePTTConfig) {
		return
	}
	id := request.PathValue("mcpttID")
	if id != claims.MCPTTID && !svc.configManager(claims.MCPTTID) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	if user, known := svc.siteUser("mcptt_id", id); known && !profileDocumentAddressed(request.PathValue("document"), user) {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": http.StatusText(http.StatusNotFound)})
		return
	}
	raw, status := svc.userProfileDocument(id)
	if status != http.StatusOK {
		writeJSON(writer, status, map[string]string{"error": http.StatusText(status)})
		return
	}
	writeDocument(writer, request, raw, userProfileMIME)
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 8.3.1A and clause 8.3.2.8: whether a request names the user's MCPTT user profile document,
// mcptt-user-profile-<index>.xml.
func profileDocumentAddressed(document string, user User) bool {
	return document == profileDocumentName(user.profileIndex())
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 6.3.3.3: the user profile document the CMS serves: one updated by an administrator (TS 24.484
// clause 6.3.4.3), else the one built from the configuration.
func (svc *service) userProfileDocument(id string) ([]byte, int) {
	user, ok := svc.siteUser("mcptt_id", id)
	if !ok {
		return nil, http.StatusNotFound
	}
	if stored, updated := svc.uploadedProfile(user); updated {
		return stored, http.StatusOK
	}
	raw, err := xml.Marshal(svc.servedProfileXML(user))
	if err != nil {
		return nil, http.StatusInternalServerError
	}
	return append([]byte(xml.Header), raw...), http.StatusOK
}

// ------------------------------------------------------------------------------
// Helper: whether the user with this MCPTT ID may manage the configuration of other users (project policy).
func (svc *service) configManager(id string) bool {
	user, ok := svc.siteUser("mcptt_id", id)
	return ok && user.ConfigManagement
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 6.3.4.3: an authorized CMC replaces a user profile document. The document must be a user profile
// for the same MCPTT ID, at its document name; the servers then enforce the rights it grants (effectiveUser).
func (svc *service) putUserProfile(writer http.ResponseWriter, request *http.Request) {
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok || !requireScope(writer, claims, scopePTTConfig) {
		return
	}
	id := request.PathValue("mcpttID")
	if !svc.configManager(claims.MCPTTID) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	user, known := svc.siteUser("mcptt_id", id)
	if known && !profileDocumentAddressed(request.PathValue("document"), user) {
		// One MCPTT user profile document per user, at its index (TS 24.484 clause 8.3.2.8).
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": http.StatusText(http.StatusNotFound)})
		return
	}
	current, status := svc.userProfileDocument(id)
	if status != http.StatusOK {
		writeJSON(writer, status, map[string]string{"error": http.StatusText(status)})
		return
	}
	if match := request.Header.Get("If-Match"); match != "" && match != "*" && match != documentETag(current) {
		writeJSON(writer, http.StatusPreconditionFailed, map[string]string{"error": "precondition_failed"})
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, 64<<10))
	if err != nil {
		writeJSON(writer, http.StatusRequestEntityTooLarge, map[string]string{"error": "too_large"})
		return
	}
	// RFC 4825 section 8.2.2: the body is a user profile document (TS 24.484 clause 8.3.2.5).
	if mediaType(request.Header.Get("Content-Type")) != userProfileMIME {
		writeJSON(writer, http.StatusUnsupportedMediaType, map[string]string{"error": "unsupported_media_type"})
		return
	}
	// RFC 4825 section 8.2.5: the document conforms to the schema of TS 24.484 clause 8.3.2.3, then to the
	// constraints of TS 24.484 clause 8.3.2.6.
	err = schemaError(userProfileSchema.validate(raw))
	if err == nil {
		err = profileConstraints(raw, id, profileDocumentName(user.profileIndex()))
	}
	if err != nil {
		svc.logEvent("user_profile_refused", map[string]any{"user_id": id, "by": claims.MCPTTID, "error": err.Error()})
		writeXCAPError(writer, err)
		return
	}
	generated, err := xml.Marshal(svc.servedProfileXML(user))
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	svc.mu.Lock()
	if svc.profileDocs == nil {
		svc.profileDocs = map[string][]byte{}
	}
	if svc.profileBases == nil {
		svc.profileBases = map[string]string{}
	}
	previous, had := svc.profileDocs[id]
	previousBase, hadBase := svc.profileBases[id]
	svc.profileDocs[id] = raw
	svc.profileBases[id] = documentETag(append([]byte(xml.Header), generated...))
	if err := svc.saveProfileDocumentsLocked(); err != nil {
		// Not stored: the document served stays the previous one.
		if had {
			svc.profileDocs[id] = previous
		} else {
			delete(svc.profileDocs, id)
		}
		if hadBase {
			svc.profileBases[id] = previousBase
		} else {
			delete(svc.profileBases, id)
		}
		svc.mu.Unlock()
		svc.logEvent("user_profile_save_failed", map[string]any{"user_id": id, "error": err.Error()})
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "storage_unavailable"})
		return
	}
	svc.mu.Unlock()
	svc.logEvent("user_profile_updated", map[string]any{"user_id": id, "by": claims.MCPTTID})
	writer.Header().Set("ETag", documentETag(raw))
	writer.WriteHeader(http.StatusOK)
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 6.3.13.3: getInternalUserProfile gives the SIP front of the CMS the entity tag of a user
// profile document, whose changes it notifies.
func (svc *service) getInternalUserProfile(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	raw, status := svc.userProfileDocument(request.URL.Query().Get("mcptt_id"))
	if status != http.StatusOK {
		writeJSON(writer, status, map[string]string{"error": http.StatusText(status)})
		return
	}
	user, _ := svc.siteUser("mcptt_id", request.URL.Query().Get("mcptt_id"))
	writeJSON(writer, http.StatusOK, map[string]string{"document_etag": documentETag(raw),
		"document": profileDocumentName(user.profileIndex())})
}

// ------------------------------------------------------------------------------
// Helper: the updated profile documents persist in the CMS's data directory (atomically); the caller holds svc.mu.
func (svc *service) saveProfileDocumentsLocked() error {
	if svc.dataDir == "" {
		return nil
	}
	raw, err := json.Marshal(svc.profileDocs)
	if err != nil {
		return fmt.Errorf("user profiles: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(svc.dataDir, "user-profiles.json"), raw); err != nil {
		return err
	}
	if raw, err = json.Marshal(svc.profileBases); err != nil {
		return fmt.Errorf("user profiles: %w", err)
	}
	return writeFileAtomic(filepath.Join(svc.dataDir, "user-profile-bases.json"), raw)
}

// ------------------------------------------------------------------------------
// Helper: loads the updated profile documents from the CMS's data directory; none stored is not an error, a file
// that cannot be read or decoded is (the CMS would otherwise serve the configured profiles as if never changed).
func (svc *service) loadProfileDocuments() error {
	if svc.dataDir == "" {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(svc.dataDir, "user-profiles.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("user profiles: %w", err)
	}
	var docs map[string][]byte
	if err := json.Unmarshal(raw, &docs); err != nil {
		return fmt.Errorf("user profiles: %w", err)
	}
	svc.profileDocs = docs
	// The configured profile each was uploaded over; none for documents stored by earlier versions, which stay until
	// the next upload.
	raw, err = os.ReadFile(filepath.Join(svc.dataDir, "user-profile-bases.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil {
		err = json.Unmarshal(raw, &svc.profileBases)
	}
	if err != nil {
		return fmt.Errorf("user profile bases: %w", err)
	}
	return nil
}

// ------------------------------------------------------------------------------
// RFC 4825 section 8.3: an element fetched from a document is sent as application/xcap-el+xml.
func writeXML(writer http.ResponseWriter, request *http.Request, raw []byte) {
	writeDocument(writer, request, append([]byte(xml.Header), raw...), "application/xcap-el+xml")
}

// ------------------------------------------------------------------------------
// RFC 4825 section 8.5: writeDocument sends a complete XML document with an entity tag, and 304 when the
// If-None-Match entity tag is current.
func writeDocument(writer http.ResponseWriter, request *http.Request, raw []byte, contentType string) {
	sum := sha256.Sum256(raw)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	writer.Header().Set("ETag", etag)
	writer.Header().Set("Cache-Control", "private, no-cache")
	if request.Header.Get("If-None-Match") == etag {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	writer.Header().Set("Content-Type", contentType+"; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(raw)
}

// ------------------------------------------------------------------------------
// Helper: whether a request of the internal interface carries the server client credentials (HTTP Basic).
func (svc *service) internalAuthorized(request *http.Request) bool {
	username, password, ok := request.BasicAuth()
	if !ok || len(username) != len(svc.cfg.ServerClientID) || len(password) != len(svc.cfg.ServerSecret) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(username), []byte(svc.cfg.ServerClientID)) == 1 && subtle.ConstantTimeCompare([]byte(password), []byte(svc.cfg.ServerSecret)) == 1
}

// ------------------------------------------------------------------------------
// Helper: answers 401 to a request of the internal interface without the server client credentials.
func (svc *service) requireInternal(writer http.ResponseWriter, request *http.Request) bool {
	if svc.internalAuthorized(request) {
		return true
	}
	writer.Header().Set("WWW-Authenticate", `Basic realm="mcx-internal"`)
	writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	return false
}

// ------------------------------------------------------------------------------
// Helper: the internal interface serves a group with its document version and entity tag to the MC service servers.
func (svc *service) getInternalGroup(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	id := request.URL.Query().Get("id")
	group, ok := svc.group(id)
	if !ok {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	// The document version lets the servers and the subscription front notice changes.
	raw, err := json.Marshal(group)
	var out map[string]any
	if err == nil {
		err = json.Unmarshal(raw, &out)
	}
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out["document_version"] = svc.groupVersion(id)
	// The entity tag of the complete document (RFC 4825 section 8.5), as xcap-diff carries it (TS 24.481 clause
	// 6.3.13.3.3).
	if svc.groupDocs != nil {
		if doc, ok := svc.documentOf(id); ok {
			out["document_etag"] = documentETag(doc.XML)
		}
	}
	writeJSON(writer, http.StatusOK, out)
}

// ------------------------------------------------------------------------------
// Helper: the internal interface serves a user by MCPTT ID, MCData ID or MCVideo ID.
func (svc *service) getInternalUser(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	user, ok := svc.siteUser("mcptt_id", request.URL.Query().Get("mcptt_id"))
	if id := request.URL.Query().Get("mcdata_id"); id != "" {
		user, ok = svc.siteUser("mcdata_id", id)
	}
	if id := request.URL.Query().Get("mcvideo_id"); id != "" {
		user, ok = svc.siteUser("mcvideo_id", id)
	}
	if !ok {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	// The rights of an uploaded MCPTT user profile document (TS 24.484 clause 6.3.4.3).
	user = svc.effectiveUser(user)
	writeJSON(writer, http.StatusOK, publicUser{ProfileIndex: user.profileIndex(), MCID: user.MCID, MCPTTID: user.MCPTTID, SIPURI: user.SIPURI, ClientID: user.ClientID, Groups: user.Groups, PrivateCall: user.PrivateCall, AdhocCall: user.AdhocCall, GroupCall: user.GroupCall,
		FunctionalAliasTakeover: user.FunctionalAliasTakeover, FunctionalAliasBinding: user.FunctionalAliasBinding, MaxAffiliations: user.MaxAffiliations,
		Regroup: user.Regroup, MCDataID: user.MCDataID, MCData: user.MCData, MCVideoID: user.MCVideoID, MCVideo: user.MCVideo, Location: user.Location})
}

// ------------------------------------------------------------------------------
// Helper: getInternalFunctionalAlias serves one functional alias definition to the MCPTT, MCData and MCVideo servers.
func (svc *service) getInternalFunctionalAlias(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	fa, ok := svc.cfg.functionalAliasByID(request.URL.Query().Get("id"))
	if !ok {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	writeJSON(writer, http.StatusOK, fa)
}
