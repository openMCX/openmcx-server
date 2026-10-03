// The common services' HTTP handler: one role per process (IdMS, GMS, CMS, LMS, KMS, the MCData content server,
// message store and notification server, the IS proxy or the Credential Service), its state and its routes.
//
// Specifications: TS 24.482 V19.1.0 (Rel-19), TS 33.180 V19.4.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19),
// TS 24.484 V19.6.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19), TS 23.280 V19.10.1 (Rel-19).
package common

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type Option func(*service)

// ------------------------------------------------------------------------------
// Helper: an option that replaces the service's clock.
func WithClock(clock func() time.Time) Option { return func(svc *service) { svc.now = clock } }

// ------------------------------------------------------------------------------
// Helper: WithServiceClient gives the message store and the content server (and the KMS, GMS, and in admin mode the
// IdMS, CMS, LMS and Credential Service) the HTTP client for the other services of this system (TLS with the system
// CA).
func WithServiceClient(client *http.Client) Option {
	return func(svc *service) { svc.serviceClient = client }
}

// ------------------------------------------------------------------------------
// Helper: WithContext bounds the service's background work (the SLM-S timers, the IdMS refresh token saves, the
// CRL refresh): it stops when ctx ends. Without it the work runs for the life of the process.
func WithContext(ctx context.Context) Option { return func(svc *service) { svc.ctx = ctx } }

type service struct {
	// Ends the background work (WithContext).
	ctx             context.Context
	role            Role
	cfg             Config
	signingKey      *rsa.PrivateKey
	verificationKey *rsa.PublicKey
	dataDir         string
	refresh         *refreshStore // IdMS: refresh tokens (TS 33.180 annex B.5)
	now             func() time.Time
	mu              sync.Mutex
	requests        map[string]authorizationRequest
	codes           map[string]authorizationCode
	locations       map[string]Location
	keyTool         KeyTool
	keyToolSlots    chan struct{} // runKeyTool
	kmsAuthority    json.RawMessage
	kmsError        error
	// MCData message store and notification server (TS 24.282 clause 21).
	store *messageStore
	// The writable group documents of the GMS (TS 24.481 clauses 6.3.2 to 6.3.12).
	groupDocs *groupStore
	// User profile documents updated through the CMS (TS 24.484 clause 6.3.4), by MCPTT ID.
	profileDocs   map[string][]byte
	notifications *notificationServer
	// Requests to other services of this system (the content server, the
	// notification server); replaced in tests.
	serviceClient *http.Client
	// Serialises the changes of <on-network-regrouped> elements (TS 24.481 clause 6.3.14).
	temporaryMu sync.Mutex
	// Serialises the group key epochs of the GMS.
	groupKeyMu sync.Mutex
	// The GMS's client towards its KMS; replaced in tests.
	gmsKMSClient *http.Client
	// The SEAL location management server's positions, subscriptions and channels.
	sealLM *sealState
	// IdMS's password verifiers and set-password links, for accounts managed by MCX Admin.
	credentials *credentials
	// The Credential Service's SIP credential tables.
	creds *credentialStore
}

// ------------------------------------------------------------------------------
// Helper: the handler of a role: checks the configuration and the keys the role needs, prepares the data directory,
// the state and the options, and registers /healthz and the role's routes.
func NewHandlerWithKeys(role Role, cfg Config, signingKey *rsa.PrivateKey, verificationKey *rsa.PublicKey, dataDir string, opts ...Option) (http.Handler, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if role == RoleIDMS && signingKey == nil {
		return nil, errors.New("IdMS requires a private signing key")
	}
	if (role == RoleGMS || role == RoleCMS || role == RoleLMS || role == RoleKMS || role == RoleContent ||
		role == RoleMsgStore || role == RoleNotification || role == RoleCredentials) && verificationKey == nil {
		return nil, errors.New("verification key is required")
	}
	if role != RoleIDMS && role != RoleGMS && role != RoleCMS && role != RoleLMS && role != RoleKMS && role != RoleContent &&
		role != RoleMsgStore && role != RoleNotification && role != RoleCredentials {
		return nil, errors.New("unknown service role")
	}
	if dataDir == "" {
		return nil, errors.New("data directory is required")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	svc := &service{ctx: context.Background(), role: role, cfg: cfg, signingKey: signingKey, verificationKey: verificationKey, dataDir: dataDir, now: time.Now, requests: map[string]authorizationRequest{}, codes: map[string]authorizationCode{}, locations: map[string]Location{}}
	svc.credentials = newCredentials(dataDir)
	svc.keyTool = nativeKeyTool
	svc.keyToolSlots = make(chan struct{}, maxConcurrentKeyTool)
	for _, opt := range opts {
		opt(svc)
	}
	if role == RoleIDMS {
		var err error
		if svc.refresh, err = newRefreshStore(dataDir); err != nil {
			svc.logEvent("refresh_tokens_load_failed", map[string]any{"error": err.Error()})
		}
		svc.every(refreshSaveEvery, svc.persistRefreshTokens)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "alive", "role": string(role)})
	})
	if err := svc.routes(mux); err != nil {
		return nil, err
	}
	return mux, nil
}

// ------------------------------------------------------------------------------
// Helper: logs one event of the service as a JSON line.
func (svc *service) logEvent(event string, fields map[string]any) {
	fields["event"] = event
	fields["role"] = string(svc.role)
	raw, _ := json.Marshal(fields) // the services' own values (strings, numbers, lists): not expected to fail
	log.Print(string(raw))
}

// ------------------------------------------------------------------------------
// Helper: registers /readyz and the routes of the service's role, after loading and checking its stored state.
func (svc *service) routes(mux *http.ServeMux) error {
	if svc.role != RoleKMS {
		mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, _ *http.Request) {
			writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
		})
	}
	switch svc.role {
	case RoleIDMS:
		svc.routesIDMS(mux)
	case RoleGMS:
		if err := svc.loadGroupStore(); err != nil {
			return err
		}
		if err := svc.checkGroupDocuments(); err != nil {
			return err
		}
		svc.routesGMS(mux)
		svc.routesGroupDocuments(mux)
		svc.routesGroupProvisioning(mux)
	case RoleCMS:
		if err := svc.loadProfileDocuments(); err != nil {
			return err
		}
		if err := svc.checkProfileDocuments(); err != nil {
			return err
		}
		if err := svc.checkMCVideoProfileDocuments(); err != nil {
			return err
		}
		svc.routesCMS(mux)
	case RoleLMS:
		if err := svc.loadLocations(); err != nil {
			return err
		}
		if err := svc.loadSealLocations(); err != nil {
			return err
		}
		svc.routesLMS(mux)
		svc.routesSealLM(mux)
	case RoleKMS:
		if err := svc.initializeKMS(); err != nil {
			return err
		}
		svc.routesKMS(mux)
	case RoleContent:
		svc.routesContent(mux)
	case RoleMsgStore:
		if err := svc.loadMessageStore(); err != nil {
			return err
		}
		svc.routesMsgStore(mux)
	case RoleNotification:
		svc.notifications = newNotificationServer()
		svc.routesNotification(mux)
	case RoleCredentials:
		store, err := openCredentialStore(svc.cfg.Credentials)
		if err != nil {
			return err
		}
		svc.creds = store
		svc.routesCredentials(mux)
		if store.issuer != nil && store.cfg.CRLFile != "" {
			go svc.refreshCRL(svc.ctx)
		}
	}
	return nil
}

// ------------------------------------------------------------------------------
// Helper: every runs work at each interval until the service's context ends.
func (svc *service) every(interval time.Duration, work func(now time.Time)) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-svc.ctx.Done():
				return
			case now := <-ticker.C:
				work(now)
			}
		}
	}()
}

// ------------------------------------------------------------------------------
// Helper: writeFileAtomic replaces a file through a temporary file and a rename, owner-only; the temporary file is
// removed when the write or the rename fails.
func writeFileAtomic(path string, raw []byte) error {
	return writeFileAtomicMode(path, raw, 0o600)
}

// ------------------------------------------------------------------------------
// Helper: writeFileAtomic with the file's permissions.
func writeFileAtomicMode(path string, raw []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	err := os.WriteFile(tmp, raw, mode)
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp) // best effort: the error that matters is the write's
		return err
	}
	return nil
}

// ------------------------------------------------------------------------------
// Helper: closeQuietly closes what was only read (a response body, a file opened for reading, a database handle at
// the end): a failed close loses nothing, so its error is not reported.
func closeQuietly(closer io.Closer) { _ = closer.Close() }

// ------------------------------------------------------------------------------
// Helper: writes a JSON answer, never cached.
func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
