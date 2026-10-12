//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The LMS's simple location store: each user reads and writes only its own last location over HTTP.
//
// Specifications: TS 24.482 V19.1.0 (Rel-19) (the access token only); the location API itself is this
// implementation's, outside the 3GPP procedures (the SEAL location management server is in seal_location.go).
package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Location struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Accuracy  float64 `json:"accuracy"`
	UpdatedAt string  `json:"updated_at"`
}

// ------------------------------------------------------------------------------
// Helper: registers the routes of the simple location store.
func (svc *service) routesLMS(mux *http.ServeMux) {
	mux.HandleFunc("GET /location/{mcpttID}", svc.getLocation)
	mux.HandleFunc("PUT /location/{mcpttID}", svc.putLocation)
}

// ------------------------------------------------------------------------------
// Helper: authenticates the bearer access token (TS 24.482) and returns the MCPTT ID of the path,
// which must be the token's own; otherwise answers 403.
func (svc *service) ownLocation(writer http.ResponseWriter, request *http.Request) (string, bool) {
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok {
		return "", false
	}
	id := request.PathValue("mcpttID")
	if id != claims.MCPTTID {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return "", false
	}
	return id, true
}

// ------------------------------------------------------------------------------
// Helper: GET /location/{mcpttID}: the user's last stored location, or 404.
func (svc *service) getLocation(writer http.ResponseWriter, request *http.Request) {
	id, ok := svc.ownLocation(writer, request)
	if !ok {
		return
	}
	svc.mu.Lock()
	location, exists := svc.locations[id]
	svc.mu.Unlock()
	if !exists {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	writeJSON(writer, http.StatusOK, location)
}

// ------------------------------------------------------------------------------
// Helper: PUT /location/{mcpttID}: validates and stores the user's location with the time of the update,
// and persists all locations.
func (svc *service) putLocation(writer http.ResponseWriter, request *http.Request) {
	id, ok := svc.ownLocation(writer, request)
	if !ok {
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 16<<10)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var location Location
	if err := decoder.Decode(&location); err != nil || location.Latitude < -90 || location.Latitude > 90 || location.Longitude < -180 || location.Longitude > 180 || location.Accuracy < 0 {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_location"})
		return
	}
	location.UpdatedAt = svc.now().UTC().Format(time.RFC3339Nano)
	svc.mu.Lock()
	svc.locations[id] = location
	err := svc.saveLocationsLocked()
	svc.mu.Unlock()
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "persistence_failed"})
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

// ------------------------------------------------------------------------------
// Helper: the file the locations are persisted in.
func (svc *service) locationPath() string { return filepath.Join(svc.dataDir, "locations.json") }

// ------------------------------------------------------------------------------
// Helper: loads the persisted locations at start; a missing file is no error.
func (svc *service) loadLocations() error {
	raw, err := os.ReadFile(svc.locationPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var values map[string]Location
	if err := json.Unmarshal(raw, &values); err != nil {
		return fmt.Errorf("decode locations: %w", err)
	}
	svc.locations = values
	return nil
}

// ------------------------------------------------------------------------------
// Helper: persists the locations through a temporary file and a rename; the caller holds svc.mu.
func (svc *service) saveLocationsLocked() error {
	raw, err := json.Marshal(svc.locations)
	if err != nil {
		return err
	}
	return writeFileAtomic(svc.locationPath(), raw)
}
