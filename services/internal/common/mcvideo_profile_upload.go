//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCVideo user profile documents replaced by an authorised configuration management client (TS 24.484 clause 6.3.4.3
// for the MCVideo user profile of clause 9.3), as putUserProfile does for the MCPTT user profile.
//
// Specifications: TS 24.484 V19.6.0 (Rel-19), RFC 4825.

package common

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// ------------------------------------------------------------------------------
// Helper: the MCVideo user profile document generated from the configuration, with its profile index.
func (svc *service) generatedMCVideoProfile(user User) ([]byte, int, error) {
	doc, err := svc.mcvideoProfileXML(user)
	if err != nil {
		return nil, 0, err
	}
	raw, err := xml.Marshal(doc)
	if err != nil {
		return nil, 0, err
	}
	return append([]byte(xml.Header), raw...), doc.ProfileIndex, nil
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 6.3.4.3: uploadedMCVideoProfile is the MCVideo user profile document an authorised CMC stored for
// the user, while it is the latest change of the user's profile: a later change of the configuration supersedes it
// (as uploadedProfile for the MCPTT user profile).
func (svc *service) uploadedMCVideoProfile(user User, generated []byte) ([]byte, bool) {
	current := documentETag(generated)
	svc.mu.Lock()
	defer svc.mu.Unlock()
	stored, ok := svc.mcvideoProfileDocs[user.MCVideoID]
	if !ok {
		return nil, false
	}
	if base, known := svc.mcvideoProfileBases[user.MCVideoID]; known && base != current {
		delete(svc.mcvideoProfileDocs, user.MCVideoID)
		delete(svc.mcvideoProfileBases, user.MCVideoID)
		if err := svc.saveMCVideoProfileDocumentsLocked(); err != nil {
			svc.logEvent("mcvideo_user_profile_save_failed", map[string]any{"user_id": user.MCVideoID, "error": err.Error()})
		}
		svc.logEvent("mcvideo_user_profile_superseded", map[string]any{"user_id": user.MCVideoID})
		return nil, false
	}
	return stored, true
}

// ------------------------------------------------------------------------------
// TS 24.484 clause 6.3.4.3: an authorised CMC replaces an MCVideo user profile document. The document must be the
// MCVideo user profile of the same MCVideo ID at its document name (TS 24.484 clauses 9.3.1A, 9.3.2.3 and 9.3.2.6).
func (svc *service) putMCVideoProfile(writer http.ResponseWriter, request *http.Request) {
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok || !requireScope(writer, claims, scopeVideoConfig) {
		return
	}
	if !svc.configManager(claims.MCPTTID) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	id := request.PathValue("mcvideoID")
	current, index, status := svc.mcvideoProfileDocument(id)
	if status == http.StatusOK && request.PathValue("document") != mcvideoProfileDocumentName(index) {
		status = http.StatusNotFound // one MCVideo user profile document per user, at its index
	}
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
	// RFC 4825 section 8.2.2: the body is an MCVideo user profile document (TS 24.484 clause 9.3.2.5).
	if mediaType(request.Header.Get("Content-Type")) != mcvideoProfileMIME {
		writeJSON(writer, http.StatusUnsupportedMediaType, map[string]string{"error": "unsupported_media_type"})
		return
	}
	// RFC 4825 section 8.2.5: the schema of TS 24.484 clause 9.3.2.3, then the constraints of clause 9.3.2.6.
	err = schemaError(mcvideoProfileSchema.validate(raw))
	if err == nil {
		err = mcvideoProfileConstraints(raw, id, mcvideoProfileDocumentName(index))
	}
	if err != nil {
		svc.logEvent("mcvideo_user_profile_refused", map[string]any{"user_id": id, "by": claims.MCPTTID, "error": err.Error()})
		writeXCAPError(writer, err)
		return
	}
	user, _ := svc.siteUser("mcvideo_id", id)
	generated, _, err := svc.generatedMCVideoProfile(user)
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	svc.mu.Lock()
	if svc.mcvideoProfileDocs == nil {
		svc.mcvideoProfileDocs = map[string][]byte{}
	}
	if svc.mcvideoProfileBases == nil {
		svc.mcvideoProfileBases = map[string]string{}
	}
	previous, had := svc.mcvideoProfileDocs[id]
	previousBase, hadBase := svc.mcvideoProfileBases[id]
	svc.mcvideoProfileDocs[id] = raw
	svc.mcvideoProfileBases[id] = documentETag(generated)
	if err := svc.saveMCVideoProfileDocumentsLocked(); err != nil {
		// Not stored: the document served stays the previous one.
		if had {
			svc.mcvideoProfileDocs[id] = previous
		} else {
			delete(svc.mcvideoProfileDocs, id)
		}
		if hadBase {
			svc.mcvideoProfileBases[id] = previousBase
		} else {
			delete(svc.mcvideoProfileBases, id)
		}
		svc.mu.Unlock()
		svc.logEvent("mcvideo_user_profile_save_failed", map[string]any{"user_id": id, "error": err.Error()})
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "storage_unavailable"})
		return
	}
	svc.mu.Unlock()
	svc.logEvent("mcvideo_user_profile_updated", map[string]any{"user_id": id, "by": claims.MCPTTID})
	writer.Header().Set("ETag", documentETag(raw))
	writer.WriteHeader(http.StatusOK)
}

// ------------------------------------------------------------------------------
// Helper: the replaced MCVideo user profile documents persist in the CMS's data directory (atomically); the caller
// holds svc.mu.
func (svc *service) saveMCVideoProfileDocumentsLocked() error {
	if svc.dataDir == "" {
		return nil
	}
	raw, err := json.Marshal(svc.mcvideoProfileDocs)
	if err != nil {
		return fmt.Errorf("MCVideo user profiles: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(svc.dataDir, "mcvideo-user-profiles.json"), raw); err != nil {
		return err
	}
	if raw, err = json.Marshal(svc.mcvideoProfileBases); err != nil {
		return fmt.Errorf("MCVideo user profiles: %w", err)
	}
	return writeFileAtomic(filepath.Join(svc.dataDir, "mcvideo-user-profile-bases.json"), raw)
}

// ------------------------------------------------------------------------------
// Helper: loads the replaced MCVideo user profile documents from the CMS's data directory; none stored is not an
// error, a file that cannot be read or decoded is.
func (svc *service) loadMCVideoProfileDocuments() error {
	if svc.dataDir == "" {
		return nil
	}
	for _, file := range []struct {
		name string
		into any
	}{{"mcvideo-user-profiles.json", &svc.mcvideoProfileDocs}, {"mcvideo-user-profile-bases.json", &svc.mcvideoProfileBases}} {
		raw, err := os.ReadFile(filepath.Join(svc.dataDir, file.name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err == nil {
			err = json.Unmarshal(raw, file.into)
		}
		if err != nil {
			return fmt.Errorf("MCVideo user profiles: %w", err)
		}
	}
	return nil
}
