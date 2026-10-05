// SEAL location management server (SLM-S) in the LMS role: client reports and history, subscriptions,
// notifications and on-demand requests of MC service servers.
//
// Specifications: TS 23.280 V19.10.1 (Rel-19), TS 24.545, TS 23.434, TS 23.032.
package common

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The SEAL location management server (SLM-S) of TS 24.545 (V19.4.0 when written), over HTTP, in the LMS role
// (TS 23.280 clause 10.9, TS 23.434 clause 9.3). The location management clients of this system's users fetch
// their reporting configuration and report to it (TS 24.545 clause 6.2.2); after a loss of connectivity they
// report what they stored in a history location result report (TS 24.545 clause 6.2.20). The MC service servers
// subscribe to the location of users (TS 24.545 clause 6.2.6.2.2), are notified of it (TS 24.545 clause 6.2.7.2)
// and ask for it on demand (TS 24.545 clause 6.2.8.2).
//
// TS 24.545 leaves the Request-URIs to the vertical application's usage; here they are under /seal-lm/v1. An MC
// service server has no HTTP listener, so the notifications of TS 24.545 clause 6.2.7.2 c) reach it on a
// long-poll channel it opens at this server; each carries the same location-info document.

const (
	sealLocationMIME = "application/vnd.3gpp.seal-location-info+xml"
	sealLocationNS   = "urn:3gpp:ns:sealLocationInfo:1.0"
	sealExtensionNS  = "urn:openmcx:ns:sealLocation:1.0"
	sealBase         = "/seal-lm/v1"
	// openMCX: how often the subscriptions' timers (TLM-1, TLM-2) are checked.
	sealTickInterval = 500 * time.Millisecond
)

// SealLMConfig configures the SLM-S.
type SealLMConfig struct {
	// The identity of this SLM-S.
	Identity string `json:"identity"`
	// The <periodic-report> and <minimum-interval-length> given to the clients, in seconds.
	PeriodicSeconds int `json:"periodic_seconds,omitempty"`
	MinimumInterval int `json:"minimum_interval,omitempty"`
	// Positions kept per user, reported ones and history ones together.
	HistoryLimit int `json:"history_limit,omitempty"`
	// The longest subscription accepted, in seconds (TS 24.545 clause 6.2.6.2.2 step b).
	MaxExpiry int `json:"max_expiry,omitempty"`
	// The MC service servers of this system, implicitly trusted (TS 23.280 clause 10.9.3.5 NOTE 2).
	VALServers []string `json:"val_servers"`
}

// ------------------------------------------------------------------------------
// Helper: checks the SLM-S configuration: an identity of this domain and SIP identities for this system's MC
// service servers.
func (config *SealLMConfig) validate(cfg Config) error {
	if config == nil {
		return nil
	}
	if !validSIPIdentity(config.Identity) || uriDomain(config.Identity) != strings.ToLower(cfg.Domain) {
		return errors.New("seal_lm requires an identity of this domain")
	}
	for _, id := range config.VALServers {
		if !validSIPIdentity(id) {
			return fmt.Errorf("seal_lm VAL server %q is not a SIP identity", id)
		}
	}
	return nil
}

// ---- location-info documents (TS 24.545 clauses 7.3 and 7.4) ----

type sealContent struct {
	URI    string `xml:"sealURI,omitempty"`
	String string `xml:"sealString,omitempty"`
}

// ------------------------------------------------------------------------------
// Helper: the value of a <sealURI> or <sealString> element, empty when absent.
func (content *sealContent) value() string {
	if content == nil {
		return ""
	}
	if content.URI != "" {
		return content.URI
	}
	return content.String
}

// ------------------------------------------------------------------------------
// Helper: a <sealURI> element holding an identity.
func sealURI(id string) *sealContent { return &sealContent{URI: id} }

type sealIdentity struct {
	VALUserID *sealContent `xml:"VAL-user-id"`
}

type sealIDList struct {
	IDs []sealContent `xml:"VAL-user-id"`
}

// ------------------------------------------------------------------------------
// Helper: the distinct identities of a list of <VAL-user-id> elements.
func (list *sealIDList) values() []string {
	if list == nil {
		return nil
	}
	var out []string
	for index := range list.IDs {
		if value := list.IDs[index].value(); value != "" && !slices.Contains(out, value) {
			out = append(out, value)
		}
	}
	return out
}

// ------------------------------------------------------------------------------
// Helper: a list of <VAL-user-id> elements, one <sealURI> per identity.
func sealIDs(ids []string) *sealIDList {
	list := &sealIDList{}
	for _, id := range ids {
		list.IDs = append(list.IDs, sealContent{URI: id})
	}
	return list
}

type sealThreeBytes struct {
	Value uint32 `xml:"threebytes"`
}

// tPointCoordinate: longitude and latitude coded as in TS 23.032 clause 6.1.
type sealPoint struct {
	Longitude sealThreeBytes `xml:"longitude"`
	Latitude  sealThreeBytes `xml:"latitude"`
}

type sealAnyExt struct {
	Timestamp     string             `xml:"urn:3gpp:ns:sealLocationInfo:1.0 timestamp,omitempty"`
	History       *struct{}          `xml:"urn:openmcx:ns:sealLocation:1.0 history"`
	ReportURI     string             `xml:"urn:openmcx:ns:sealLocation:1.0 report-uri,omitempty"`
	HistoryURI    string             `xml:"urn:openmcx:ns:sealLocation:1.0 history-uri,omitempty"`
	HistoryResult *sealHistoryResult `xml:"urn:3gpp:ns:sealLocationInfo:1.0 history-loc-result-report"`
}

type sealCurrentLocation struct {
	Coordinate *sealPoint `xml:"current-geographical-coordinate"`
}

type sealReport struct {
	ReportID string              `xml:"report-id,attr,omitempty"`
	Triggers []string            `xml:"trigger-id"`
	Current  sealCurrentLocation `xml:"current-location"`
	AnyExt   *sealAnyExt         `xml:"anyExt"`
}

type sealLatestLocation struct {
	Coordinate *sealPoint `xml:"latest-coordinate"`
}

type sealLocInfoReport struct {
	VALUserID *sealContent       `xml:"VAL-user-id"`
	Latest    sealLatestLocation `xml:"latest-location"`
	AnyExt    *sealAnyExt        `xml:"anyExt"`
}

type sealReports struct {
	Reports []sealLocInfoReport `xml:"loc-info-report"`
}

type sealNotification struct {
	TriggerID      string      `xml:"trigger-id,attr"`
	IdentitiesList *sealIDList `xml:"identities-list"`
	Reports        sealReports `xml:"reports"`
	// TS 24.545 clause 6.2.7.2 a) 2) iv).
	SubscriptionIdentifier string `xml:"subscription-identifier,omitempty"`
}

type sealSubscription struct {
	IdentitiesList         *sealIDList `xml:"identities-list"`
	TimeInterval           int         `xml:"time-interval-length,omitempty"`
	SubscriptionIdentifier string      `xml:"subscription-identifier,omitempty"`
	ExpiryTime             *int        `xml:"expiry-time"`
}

type sealTrigger struct {
	TriggerID string `xml:"trigger-id,attr"`
	Value     int    `xml:",chardata"`
}

type sealTriggering struct {
	Periodic *sealTrigger `xml:"periodic-report"`
}

type sealRequestedLocation struct {
	Coordinate *struct{} `xml:"current-geographical-coordinate"`
}

type sealConfiguration struct {
	LocationInformation *sealRequestedLocation `xml:"location-information"`
	Triggering          *sealTriggering        `xml:"triggering-criteria"`
	MinimumInterval     int                    `xml:"minimum-interval-length,omitempty"`
}

type sealHistoryResult struct {
	SubscriptionIdentifier string       `xml:"subscription-identifier"`
	Reports                []sealReport `xml:"reports"`
}

type sealLocationInfo struct {
	XMLName       xml.Name           `xml:"urn:3gpp:ns:sealLocationInfo:1.0 location-info"`
	Identity      *sealIdentity      `xml:"identity"`
	Configuration *sealConfiguration `xml:"configuration"`
	Report        *sealReport        `xml:"report"`
	Notification  *sealNotification  `xml:"notification"`
	Subscription  *sealSubscription  `xml:"subscription"`
	// The on-demand request and answer (TS 24.545 clause 6.2.8), and the answer and
	// deletion of a subscription (TS 24.545 clause 6.2.6.2.2), carry these directly in <location-info>.
	IdentitiesList         *sealIDList        `xml:"identities-list"`
	Reports                *sealReports       `xml:"reports"`
	SubscriptionIdentifier string             `xml:"subscription-identifier,omitempty"`
	ExpiryTime             *int               `xml:"expiry-time"`
	HistoryResult          *sealHistoryResult `xml:"history-loc-result-report"`
	AnyExt                 *sealAnyExt        `xml:"anyExt"`
}

// ------------------------------------------------------------------------------
// Helper: the <VAL-user-id> in the <identity> of a location-info document, the sender of a
// request.
func (info *sealLocationInfo) sender() string {
	if info.Identity == nil {
		return ""
	}
	return info.Identity.VALUserID.value()
}

// ------------------------------------------------------------------------------
// Helper: the <history-loc-result-report> of a location-info document (TS 24.545 clause 6.2.20), directly in
// <location-info> or in its <anyExt>.
func (info *sealLocationInfo) history() *sealHistoryResult {
	if info.HistoryResult != nil {
		return info.HistoryResult
	}
	if info.AnyExt != nil {
		return info.AnyExt.HistoryResult
	}
	return nil
}

// ------------------------------------------------------------------------------
// Helper: encodes a location-info document with the XML declaration.
func marshalSeal(document sealLocationInfo) ([]byte, error) {
	raw, err := xml.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("seal location-info: %w", err)
	}
	return append([]byte(xml.Header), raw...), nil
}

// ------------------------------------------------------------------------------
// Helper: answers with a location-info document (application/vnd.3gpp.seal-location-info+xml), not
// cached.
func writeSeal(writer http.ResponseWriter, status int, document sealLocationInfo) {
	raw, err := marshalSeal(document)
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writer.Header().Set("Content-Type", sealLocationMIME)
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_, _ = writer.Write(raw) // a failed write is the client's connection
}

// ------------------------------------------------------------------------------
// Helper: reads the location-info document of a request: only its MIME type, at most
// 64 KiB and without a DOCTYPE.
func readSeal(writer http.ResponseWriter, request *http.Request) (sealLocationInfo, bool) {
	var document sealLocationInfo
	if !strings.EqualFold(mediaType(request.Header.Get("Content-Type")), sealLocationMIME) {
		writeJSON(writer, http.StatusUnsupportedMediaType, map[string]string{"error": "unsupported_media_type"})
		return document, false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, 64<<10))
	if err != nil || bytes.Contains(bytes.ToUpper(raw), []byte("<!DOCTYPE")) || xml.Unmarshal(raw, &document) != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_location_info"})
		return document, false
	}
	return document, true
}

// ---- state ----

// sealFix is one position of a user, as its client reported it.
type sealFix struct {
	Latitude  uint32   `json:"latitude"`  // TS 23.032 coded
	Longitude uint32   `json:"longitude"` // TS 23.032 coded
	Timestamp string   `json:"timestamp"`
	Received  string   `json:"received"`
	Triggers  []string `json:"triggers,omitempty"`
	History   bool     `json:"history,omitempty"` // reported in a history location result report
}

type sealUserState struct {
	Latest  *sealFix  `json:"latest,omitempty"`
	History []sealFix `json:"history"`
}

type sealSubscriptionState struct {
	ID       string
	VAL      string // the subscriber: an MC service server
	Users    []string
	Interval time.Duration
	Expires  time.Time
	last     time.Time
	pending  map[string][]sealFix
}

type sealState struct {
	mu            sync.Mutex
	users         map[string]*sealUserState
	subscriptions map[string]*sealSubscriptionState
	queues        map[string][][]byte      // notifications waiting for a VAL server's channel
	wake          map[string]chan struct{} // closed when a VAL server's queue grows
	next          int
	ticker        sync.Once
}

// ------------------------------------------------------------------------------
// Helper: the state of the SLM-S, created on first use.
func (svc *service) seal() *sealState {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if svc.sealLM == nil {
		svc.sealLM = &sealState{users: map[string]*sealUserState{}, subscriptions: map[string]*sealSubscriptionState{},
			queues: map[string][][]byte{}, wake: map[string]chan struct{}{}}
	}
	return svc.sealLM
}

// ------------------------------------------------------------------------------
// Helper: the file in which the users' positions are kept.
func (svc *service) sealPath() string { return filepath.Join(svc.dataDir, "seal-locations.json") }

// ------------------------------------------------------------------------------
// Helper: loads the users' stored positions; none stored is not an error.
func (svc *service) loadSealLocations() error {
	st := svc.seal()
	raw, err := os.ReadFile(svc.sealPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, &st.users)
}

// ------------------------------------------------------------------------------
// Helper: stores the users' positions, through a temporary file. Caller holds st.mu.
func (svc *service) saveSealLocationsLocked(st *sealState) {
	raw, err := json.Marshal(st.users)
	if err == nil {
		err = writeFileAtomic(svc.sealPath(), raw)
	}
	if err != nil {
		// The positions stay in memory; the next report tries again.
		svc.logEvent("seal_locations_save_failed", map[string]any{"error": err.Error()})
	}
}

// ------------------------------------------------------------------------------
// Helper: the positions kept per user, 100 when not configured.
func (config *SealLMConfig) historyLimit() int {
	if config.HistoryLimit > 0 {
		return config.HistoryLimit
	}
	return 100
}

// ---- routes ----

// ------------------------------------------------------------------------------
// TS 23.280 clause 10.9 (TS 24.545): registers the SLM-S routes, those of the clients and of the MC service
// servers, and starts the ticker of the subscriptions' timers.
func (svc *service) routesSealLM(mux *http.ServeMux) {
	if svc.cfg.SealLM == nil {
		return
	}
	mux.HandleFunc("GET "+sealBase+"/users/{user}/configuration", svc.sealConfiguration)
	mux.HandleFunc("POST "+sealBase+"/users/{user}/reports", svc.sealReport)
	mux.HandleFunc("POST "+sealBase+"/users/{user}/history", svc.sealHistory)
	mux.HandleFunc("POST "+sealBase+"/subscriptions", svc.sealSubscribe)
	mux.HandleFunc("POST "+sealBase+"/location-requests", svc.sealLocationRequest)
	mux.HandleFunc("POST "+sealBase+"/notifications", svc.sealNotificationChannel)
	mux.HandleFunc("GET "+sealBase+"/status", svc.sealStatus)
	st := svc.seal()
	st.ticker.Do(func() { svc.every(sealTickInterval, func(time.Time) { svc.sealTick() }) })
}

// ------------------------------------------------------------------------------
// TS 24.545 clause 6.2.1.1: the identity of a client's request is its access token, for its own location only.
func (svc *service) sealOwnUser(writer http.ResponseWriter, request *http.Request) (string, bool) {
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok {
		return "", false
	}
	if request.PathValue("user") != claims.MCPTTID {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return "", false
	}
	return claims.MCPTTID, true
}

// ------------------------------------------------------------------------------
// TS 24.545 clause 6.2.2.3.1: the location reporting configuration of a client.
func (svc *service) sealConfiguration(writer http.ResponseWriter, request *http.Request) {
	user, ok := svc.sealOwnUser(writer, request)
	if !ok {
		return
	}
	cfg := svc.cfg.SealLM
	periodic, minimum := cfg.PeriodicSeconds, cfg.MinimumInterval
	if periodic <= 0 {
		periodic = 5
	}
	if minimum <= 0 {
		minimum = 1
	}
	// The client reaches this server as it reached it for the configuration:
	// directly, or through this system's HTTP proxy, which names its host and prefix.
	origin := "https://" + request.Host
	if host := request.Header.Get("X-Forwarded-Host"); host != "" {
		origin = "https://" + host + request.Header.Get("X-Forwarded-Prefix")
	}
	base := origin + sealBase + "/users/" + url.PathEscape(user)
	writeSeal(writer, http.StatusOK, sealLocationInfo{Identity: &sealIdentity{VALUserID: sealURI(user)},
		Configuration: &sealConfiguration{LocationInformation: &sealRequestedLocation{Coordinate: &struct{}{}},
			Triggering:      &sealTriggering{Periodic: &sealTrigger{TriggerID: "periodic", Value: periodic}},
			MinimumInterval: minimum},
		// Where the reports and the history location result reports go (TS 24.545 clauses 6.2.2.2.2 a) and 6.2.20.2 a)).
		AnyExt: &sealAnyExt{ReportURI: base + "/reports", HistoryURI: base + "/history"}})
}

// ------------------------------------------------------------------------------
// Helper: the position of a <report> (TS 24.545 clause 6.2.2.3.2), a TS 23.032 coded coordinate; its time is
// the reported <timestamp>, or the time of receipt.
func sealFixFrom(report sealReport, history bool, now time.Time) (sealFix, error) {
	point := report.Current.Coordinate
	if point == nil {
		return sealFix{}, errors.New("a report without a coordinate")
	}
	if point.Latitude.Value > 0xffffff || point.Longitude.Value > 0xffffff {
		return sealFix{}, errors.New("a coordinate out of range")
	}
	fix := sealFix{Latitude: point.Latitude.Value, Longitude: point.Longitude.Value, Triggers: report.Triggers,
		Received: now.UTC().Format(time.RFC3339), History: history}
	if report.AnyExt != nil && report.AnyExt.Timestamp != "" {
		if _, err := time.Parse(time.RFC3339, report.AnyExt.Timestamp); err != nil {
			return sealFix{}, errors.New("an invalid timestamp")
		}
		fix.Timestamp = report.AnyExt.Timestamp
	}
	if fix.Timestamp == "" {
		fix.Timestamp = fix.Received
	}
	return fix, nil
}

// ------------------------------------------------------------------------------
// TS 24.545 clause 6.2.2.3.2: a client's location report.
func (svc *service) sealReport(writer http.ResponseWriter, request *http.Request) {
	user, ok := svc.sealOwnUser(writer, request)
	if !ok {
		return
	}
	document, ok := readSeal(writer, request)
	if !ok {
		return
	}
	if document.Report == nil || (document.sender() != "" && document.sender() != user) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "report_of_another_user"})
		return
	}
	fix, err := sealFixFrom(*document.Report, false, svc.now())
	if err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	svc.sealStore(user, []sealFix{fix})
	svc.logEvent("seal_location_report", map[string]any{"user": user, "triggers": fix.Triggers})
	writer.WriteHeader(http.StatusOK)
}

// ------------------------------------------------------------------------------
// TS 24.545 clause 6.2.20.3: the positions a client stored while it could not report (TS 23.280 clause
// 10.9.3.9.1).
func (svc *service) sealHistory(writer http.ResponseWriter, request *http.Request) {
	user, ok := svc.sealOwnUser(writer, request)
	if !ok {
		return
	}
	document, ok := readSeal(writer, request)
	if !ok {
		return
	}
	result := document.history()
	if result == nil || len(result.Reports) == 0 {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "no_history_location_result_report"})
		return
	}
	var fixes []sealFix
	for _, report := range result.Reports {
		fix, err := sealFixFrom(report, true, svc.now())
		if err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		fixes = append(fixes, fix)
	}
	// The stored positions are older than the latest reported one, if any.
	slices.SortFunc(fixes, func(first, second sealFix) int { return strings.Compare(first.Timestamp, second.Timestamp) })
	svc.sealStore(user, fixes)
	svc.logEvent("seal_location_history", map[string]any{"user": user, "reports": len(fixes)})
	writer.WriteHeader(http.StatusOK)
}

// ------------------------------------------------------------------------------
// Helper: sealStore keeps positions of a user and marks them for its subscriptions.
func (svc *service) sealStore(user string, fixes []sealFix) {
	st := svc.seal()
	st.mu.Lock()
	defer st.mu.Unlock()
	state := st.users[user]
	if state == nil {
		state = &sealUserState{History: []sealFix{}}
		st.users[user] = state
	}
	for _, fix := range fixes {
		state.History = append(state.History, fix)
		if !fix.History && (state.Latest == nil || fix.Timestamp >= state.Latest.Timestamp) {
			latest := fix
			state.Latest = &latest
		}
	}
	if limit := svc.cfg.SealLM.historyLimit(); len(state.History) > limit {
		state.History = state.History[len(state.History)-limit:]
	}
	svc.saveSealLocationsLocked(st)
	for _, sub := range st.subscriptions {
		if slices.Contains(sub.Users, user) {
			if sub.pending == nil {
				sub.pending = map[string][]sealFix{}
			}
			sub.pending[user] = append(sub.pending[user], fixes...)
		}
	}
}

// ------------------------------------------------------------------------------
// TS 24.545 clauses 6.2.6.2.1.3 and 6.2.6.2.1.4: sealTick is TLM-1 and TLM-2 of every subscription.
func (svc *service) sealTick() {
	st := svc.seal()
	now := svc.now()
	type send struct {
		sub   sealSubscriptionState
		fixes map[string][]sealFix
		ended bool
	}
	var sends []send
	st.mu.Lock()
	for id, sub := range st.subscriptions {
		if !now.Before(sub.Expires) {
			delete(st.subscriptions, id)
			sends = append(sends, send{sub: *sub, ended: true})
			continue
		}
		if len(sub.pending) > 0 && now.Sub(sub.last) >= sub.Interval {
			sends = append(sends, send{sub: *sub, fixes: sub.pending})
			sub.pending, sub.last = nil, now
		}
	}
	st.mu.Unlock()
	for _, item := range sends {
		if item.ended {
			// TLM-1: the subscriber is told the subscription ended.
			zero := 0
			svc.sealDeliver(item.sub, sealLocationInfo{Identity: &sealIdentity{VALUserID: sealURI(item.sub.VAL)},
				SubscriptionIdentifier: item.sub.ID, ExpiryTime: &zero})
			svc.logEvent("seal_subscription_expired", map[string]any{"subscription": item.sub.ID, "subscriber": item.sub.VAL})
			continue
		}
		svc.sealNotify(item.sub, item.fixes)
	}
}

// ------------------------------------------------------------------------------
// TS 24.545 clause 6.2.7.2: sealNotify sends one notification with the users whose positions are pending,
// each position a <loc-info-report>.
func (svc *service) sealNotify(sub sealSubscriptionState, fixes map[string][]sealFix) {
	var users []string
	for user := range fixes {
		users = append(users, user)
	}
	slices.Sort(users)
	notification := &sealNotification{TriggerID: "periodic", IdentitiesList: sealIDs(users), SubscriptionIdentifier: sub.ID}
	history := false
	for _, user := range users {
		for _, fix := range fixes[user] {
			ext := &sealAnyExt{Timestamp: fix.Timestamp}
			if fix.History {
				ext.History, history = &struct{}{}, true
			}
			notification.Reports.Reports = append(notification.Reports.Reports, sealLocInfoReport{VALUserID: sealURI(user),
				Latest: sealLatestLocation{Coordinate: &sealPoint{Longitude: sealThreeBytes{fix.Longitude}, Latitude: sealThreeBytes{fix.Latitude}}},
				AnyExt: ext})
		}
	}
	if history {
		notification.TriggerID = "history"
	}
	svc.sealDeliver(sub, sealLocationInfo{Identity: &sealIdentity{VALUserID: sealURI(sub.VAL)}, Notification: notification})
	svc.logEvent("seal_location_notified", map[string]any{"subscription": sub.ID, "subscriber": sub.VAL, "users": users,
		"reports": len(notification.Reports.Reports), "history": history})
}

// ------------------------------------------------------------------------------
// TS 24.545 clause 6.2.7.2: sealDeliver sends to the channel of a VAL server of this system.
func (svc *service) sealDeliver(sub sealSubscriptionState, document sealLocationInfo) {
	raw, err := marshalSeal(document)
	if err != nil {
		svc.logEvent("seal_notification_failed", map[string]any{"subscription": sub.ID, "error": err.Error()})
		return
	}
	svc.sealQueue(sub.VAL, raw)
}

// ------------------------------------------------------------------------------
// Helper: queues a notification for a VAL server's channel (at most 256) and wakes its long poll.
func (svc *service) sealQueue(val string, doc []byte) {
	st := svc.seal()
	st.mu.Lock()
	defer st.mu.Unlock()
	queue := append(st.queues[val], doc)
	if len(queue) > 256 {
		queue = queue[len(queue)-256:]
	}
	st.queues[val] = queue
	if ch, ok := st.wake[val]; ok {
		close(ch)
		delete(st.wake, val)
	}
}

// ---- MC service servers ----

// ------------------------------------------------------------------------------
// TS 23.280 clause 10.9.3.5 NOTE 2: sealVAL is the MC service server of a request: this system's servers only,
// with the server credentials, naming themselves in <identity>.
func (svc *service) sealVAL(writer http.ResponseWriter, request *http.Request, named string) (string, bool) {
	if !svc.requireInternal(writer, request) {
		return "", false
	}
	if !slices.Contains(svc.cfg.SealLM.VALServers, named) {
		writeJSON(writer, http.StatusForbidden, map[string]string{"error": "not_a_val_server"})
		return "", false
	}
	return named, true
}

// ------------------------------------------------------------------------------
// TS 24.545 clause 6.2.6.2.2: an MC service server subscribes to, or unsubscribes from, users' location.
func (svc *service) sealSubscribe(writer http.ResponseWriter, request *http.Request) {
	document, ok := readSeal(writer, request)
	if !ok {
		return
	}
	val, ok := svc.sealVAL(writer, request, document.sender())
	if !ok {
		return
	}
	// Deletion: <subscription-identifier> with <expiry-time> zero.
	if id, expiry := sealDeletion(document); id != "" && expiry == 0 {
		svc.sealUnsubscribe(writer, val, id)
		return
	}
	if document.Subscription == nil || document.Subscription.ExpiryTime == nil || document.Subscription.TimeInterval <= 0 {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid_subscription"})
		return
	}
	requested := document.Subscription.IdentitiesList.values()
	sub, accepted := svc.sealCreate(val, requested, document.Subscription)
	expiry := int((sub.Expires.Sub(svc.now()) + time.Second/2) / time.Second)
	svc.logEvent("seal_subscription", map[string]any{"subscription": sub.ID, "subscriber": val, "users": accepted,
		"requested": requested, "interval": int(sub.Interval / time.Second), "expiry": expiry})
	// TS 24.545 clause 6.2.6.2.2 step m: the identifier, the accepted expiry and, when reduced, the users kept.
	answer := sealLocationInfo{SubscriptionIdentifier: sub.ID, ExpiryTime: &expiry}
	if len(accepted) != len(requested) {
		answer.IdentitiesList = sealIDs(accepted)
	}
	writeSeal(writer, http.StatusOK, answer)
}

// ------------------------------------------------------------------------------
// TS 24.545 clause 6.2.6.2.2: the <subscription-identifier> and <expiry-time> of a request, in <location-info>
// or in its <subscription>; a deletion has <expiry-time> zero. The expiry is -1 when absent.
func sealDeletion(document sealLocationInfo) (string, int) {
	id, expiry := document.SubscriptionIdentifier, -1
	if document.ExpiryTime != nil {
		expiry = *document.ExpiryTime
	}
	if document.Subscription != nil && document.Subscription.SubscriptionIdentifier != "" {
		id = document.Subscription.SubscriptionIdentifier
		if document.Subscription.ExpiryTime != nil {
			expiry = *document.Subscription.ExpiryTime
		}
	}
	return id, expiry
}

// ------------------------------------------------------------------------------
// TS 24.545 clause 6.2.6.2.2: sealCreate stores a subscription for the users this system serves and may share
// (step l), and answers which were kept.
func (svc *service) sealCreate(val string, requested []string, request *sealSubscription) (*sealSubscriptionState, []string) {
	cfg := svc.cfg.SealLM
	var kept []string
	for _, user := range requested {
		if _, known := svc.siteUser("mcptt_id", user); known {
			kept = append(kept, user)
		}
	}
	// TS 24.545 clause 6.2.6.2.2 step b: the expiry is at most the configured limit. <expiry-time> is positive
	// seconds (clause 7.5); a negative value is accepted, as its magnitude, only to tolerate peers that follow the
	// schema's xs:nonPositiveInteger type.
	seconds := *request.ExpiryTime
	if seconds < 0 {
		seconds = -seconds
	}
	limit := cfg.MaxExpiry
	if limit <= 0 {
		limit = 3600
	}
	if seconds == 0 || seconds > limit {
		seconds = limit
	}
	st := svc.seal()
	st.mu.Lock()
	defer st.mu.Unlock()
	st.next++
	sub := &sealSubscriptionState{ID: strconv.Itoa(st.next), VAL: val, Users: kept,
		Interval: time.Duration(max(request.TimeInterval, 1)) * time.Second, Expires: svc.now().Add(time.Duration(seconds) * time.Second)}
	st.subscriptions[sub.ID] = sub
	// The current status (TS 24.545 clause 6.2.6.1.1.1 iii): the latest known positions are pending at once.
	for _, user := range kept {
		if state := st.users[user]; state != nil && state.Latest != nil {
			if sub.pending == nil {
				sub.pending = map[string][]sealFix{}
			}
			sub.pending[user] = []sealFix{*state.Latest}
		}
	}
	snapshot := *sub
	return &snapshot, kept
}

// ------------------------------------------------------------------------------
// TS 23.280 clause 10.9.3.7: ends a subscription of its subscriber.
func (svc *service) sealUnsubscribe(writer http.ResponseWriter, val, id string) {
	st := svc.seal()
	st.mu.Lock()
	sub := st.subscriptions[id]
	if sub == nil || sub.VAL != val {
		st.mu.Unlock()
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": "no_such_subscription"})
		return
	}
	delete(st.subscriptions, id)
	st.mu.Unlock()
	svc.logEvent("seal_unsubscribed", map[string]any{"subscription": id, "subscriber": val})
	writeSeal(writer, http.StatusOK, sealLocationInfo{Subscription: &sealSubscription{SubscriptionIdentifier: id}})
}

// ------------------------------------------------------------------------------
// Helper: the long-poll channel on which an MC service server receives its notifications (TS 24.545 clause
// 6.2.7.2 c)); it has no HTTP listener.
func (svc *service) sealNotificationChannel(writer http.ResponseWriter, request *http.Request) {
	val, ok := svc.sealVAL(writer, request, request.URL.Query().Get("val"))
	if !ok {
		return
	}
	wait, _ := strconv.Atoi(request.URL.Query().Get("wait"))
	wait = min(max(wait, 0), 10)
	st := svc.seal()
	deadline := time.After(time.Duration(wait) * time.Second)
	for {
		st.mu.Lock()
		queue := st.queues[val]
		if len(queue) > 0 || wait == 0 {
			delete(st.queues, val)
			st.mu.Unlock()
			out := make([]string, 0, len(queue))
			for _, doc := range queue {
				out = append(out, string(doc))
			}
			writeJSON(writer, http.StatusOK, map[string]any{"notifications": out})
			return
		}
		ch, ok := st.wake[val]
		if !ok {
			ch = make(chan struct{})
			st.wake[val] = ch
		}
		st.mu.Unlock()
		select {
		case <-ch:
		case <-deadline:
			wait = 0
		case <-request.Context().Done():
			return
		}
	}
}

// ------------------------------------------------------------------------------
// TS 24.545 clause 6.2.8.2: an MC service server asks for users' latest location. With the project's
// <history/> in <anyExt>, the stored history comes too (TS 23.280 clause 10.9.3.9.2.2).
func (svc *service) sealLocationRequest(writer http.ResponseWriter, request *http.Request) {
	document, ok := readSeal(writer, request)
	if !ok {
		return
	}
	val, ok := svc.sealVAL(writer, request, document.sender())
	if !ok {
		return
	}
	requested := document.IdentitiesList.values()
	history := document.AnyExt != nil && document.AnyExt.History != nil
	reports := svc.sealReportsFor(requested, history)
	svc.logEvent("seal_location_request", map[string]any{"requester": val, "users": requested, "reports": len(reports), "history": history})
	writeSeal(writer, http.StatusOK, sealLocationInfo{Identity: &sealIdentity{VALUserID: sealURI(val)}, IdentitiesList: sealIDs(requested),
		Reports: &sealReports{Reports: reports}})
}

// ------------------------------------------------------------------------------
// TS 24.545 clause 6.2.8.2: sealReportsFor: the latest position of each user this system serves, and with history the stored positions before it.
func (svc *service) sealReportsFor(users []string, history bool) []sealLocInfoReport {
	st := svc.seal()
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []sealLocInfoReport
	add := func(user string, fix sealFix) {
		ext := &sealAnyExt{Timestamp: fix.Timestamp}
		if fix.History {
			ext.History = &struct{}{}
		}
		out = append(out, sealLocInfoReport{VALUserID: sealURI(user),
			Latest: sealLatestLocation{Coordinate: &sealPoint{Longitude: sealThreeBytes{fix.Longitude}, Latitude: sealThreeBytes{fix.Latitude}}},
			AnyExt: ext})
	}
	for _, user := range users {
		_, known := svc.siteUser("mcptt_id", user)
		state := st.users[user]
		if !known || state == nil {
			continue
		}
		if history {
			for _, fix := range state.History {
				add(user, fix)
			}
		} else if state.Latest != nil {
			add(user, *state.Latest)
		}
	}
	return out
}

// ------------------------------------------------------------------------------
// Helper: the stored positions and subscriptions, for this system's servers.
func (svc *service) sealStatus(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	st := svc.seal()
	st.mu.Lock()
	defer st.mu.Unlock()
	subs := map[string]any{}
	for id, sub := range st.subscriptions {
		subs[id] = map[string]any{"subscriber": sub.VAL, "users": sub.Users, "interval": int(sub.Interval / time.Second)}
	}
	writeJSON(writer, http.StatusOK, map[string]any{"users": st.users, "subscriptions": subs})
}
