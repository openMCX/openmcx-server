//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// MCData message store: subscriptions and notifications (TS 24.282 clauses 21.2.12A to 21.2.14A and 21.2.16;
// OMA NMS).
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 23.282 V19.10.0 (Rel-19), OMA RESTful Network API for Network
// Message Storage (OMA-TS-REST_NetAPI_NMS-V1_0-20190528-C).

package common

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ---- subscriptions and notifications (TS 24.282 clauses 21.2.12A to 21.2.14A, 21.2.16) ----

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.12A.2 (OMA NMS clause 6.20.5): the NmsSubscription of a request and a response.
type nmsSubscription struct {
	CallbackReference struct {
		NotifyURL    string `json:"notifyURL"`
		CallbackData string `json:"callbackData,omitempty"`
	} `json:"callbackReference"`
	Duration         int64  `json:"duration,omitempty"`
	ClientCorrelator string `json:"clientCorrelator,omitempty"`
	RestartToken     string `json:"restartToken,omitempty"`
	Index            *int64 `json:"index,omitempty"`
	ResourceURL      string `json:"resourceURL,omitempty"`
}

// ------------------------------------------------------------------------------
// Helper: the NmsSubscription view of a stored subscription, with its remaining duration and the box's
// restart token.
func (svc *service) subscriptionView(request *http.Request, box *storeBox, sub *storeSubscription) nmsSubscription {
	var view nmsSubscription
	view.CallbackReference.NotifyURL, view.CallbackReference.CallbackData = sub.NotifyURL, sub.CallbackData
	view.Duration = sub.Expires - svc.now().Unix()
	view.ClientCorrelator, view.RestartToken = sub.Correlator, box.RestartToken
	index := sub.Index
	view.Index = &index
	view.ResourceURL = svc.boxURL(request, box) + "/subscriptions/" + sub.ID
	return view
}

// ------------------------------------------------------------------------------
// Helper: the granted lifetime of a subscription in seconds: the requested duration, defaultSubLife when none,
// at most maxSubscriptionLife.
func lifetime(requested int64) int64 {
	if requested <= 0 {
		return defaultSubLife
	}
	if requested > maxSubscriptionLife {
		return maxSubscriptionLife
	}
	return requested
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.12A.2 (OMA NMS clause 6.20.5): subscribe to the changes of the box. Events already
// recorded are sent from the given index when the restart token matches, otherwise from now on.
func (svc *service) nmsCreateSubscription(writer http.ResponseWriter, request *http.Request) {
	box, _, ok := svc.boxOf(writer, request)
	if !ok {
		return
	}
	var subscription nmsSubscription
	if !readJSON(writer, request, "nmsSubscription", &subscription) {
		return
	}
	notify, err := url.Parse(subscription.CallbackReference.NotifyURL)
	if err != nil || notify.Scheme != "https" || notify.Host == "" {
		nmsError(writer, http.StatusBadRequest, "SVC0002", "Invalid input value for message part %1", "notifyURL")
		return
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	if len(box.Subscriptions) >= 16 {
		nmsError(writer, http.StatusForbidden, "POL0003", "Too many subscriptions")
		return
	}
	sub := &storeSubscription{ID: mustRandom(16), NotifyURL: notify.String(), CallbackData: subscription.CallbackReference.CallbackData,
		Correlator: subscription.ClientCorrelator, Expires: svc.now().Unix() + lifetime(subscription.Duration), Index: lastIndex(box)}
	if subscription.RestartToken == box.RestartToken && subscription.Index != nil && *subscription.Index <= sub.Index {
		sub.Index = *subscription.Index
	}
	box.Subscriptions[sub.ID] = sub
	if !svc.commitLocked(writer, box) {
		return
	}
	view := svc.subscriptionView(request, box, sub)
	writer.Header().Set("Location", view.ResourceURL)
	writeJSON(writer, http.StatusCreated, map[string]any{"nmsSubscription": view})
}

// ------------------------------------------------------------------------------
// Helper: the index of the last event recorded for the box, 0 when none.
func lastIndex(box *storeBox) int64 {
	if count := len(box.Events); count > 0 {
		return box.Events[count-1].Index
	}
	return 0
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.14A.2 (OMA NMS clause 6.21.5): extend a subscription, and optionally restart its stream
// from an index.
func (svc *service) nmsUpdateSubscription(writer http.ResponseWriter, request *http.Request) {
	box, _, ok := svc.boxOf(writer, request)
	if !ok {
		return
	}
	var update nmsSubscription
	if !readJSON(writer, request, "nmsSubscriptionUpdate", &update) {
		return
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	sub := box.Subscriptions[request.PathValue("subscription")]
	if sub == nil {
		nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "subscriptionId")
		return
	}
	sub.Expires = svc.now().Unix() + lifetime(update.Duration)
	if update.RestartToken == box.RestartToken && update.Index != nil && *update.Index <= lastIndex(box) {
		sub.Index = *update.Index
	}
	if svc.commitLocked(writer, box) {
		writeJSON(writer, http.StatusOK, map[string]any{"nmsSubscription": svc.subscriptionView(request, box, sub)})
	}
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.13A.2 (OMA NMS clause 6.21.6): delete a subscription.
func (svc *service) nmsDeleteSubscription(writer http.ResponseWriter, request *http.Request) {
	box, _, ok := svc.boxOf(writer, request)
	if !ok {
		return
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	if box.Subscriptions[request.PathValue("subscription")] == nil {
		nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "subscriptionId")
		return
	}
	delete(box.Subscriptions, request.PathValue("subscription"))
	if svc.commitLocked(writer, box) {
		writer.WriteHeader(http.StatusNoContent)
	}
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.16.1 (OMA NMS clause 6.22): drop the expired subscriptions and, when a subscription has
// events after its index, start their delivery (deliverEvents) unless it runs already. The caller holds the store
// lock.
func (svc *service) notifyLocked(box *storeBox) {
	key := box.Store + "\x00" + box.ID
	if svc.store.sending[key] {
		return
	}
	pending := false
	now := svc.now().Unix()
	for id, sub := range box.Subscriptions {
		if sub.Expires <= now {
			delete(box.Subscriptions, id)
			continue
		}
		pending = pending || sub.Index < lastIndex(box)
	}
	if !pending {
		return
	}
	svc.store.sending[key] = true
	go svc.deliverEvents(box)
}

// OpenMCX: a notification is tried deliveryAttempts times, waiting one, two, ... deliveryRetryDelay in between.
const (
	deliveryAttempts   = 5
	deliveryRetryDelay = 500 * time.Millisecond
)

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.16.1 step 1 (OMA NMS clause 6.22.5): the events after each subscription's index are
// POSTed to its callback URL as an NmsEventList, retried up to 5 times with a growing delay. The notification
// server of this system is reached with the service credentials (MCData-11, TS 23.282 clause 6.4.4.1.10, secured
// as per TS 24.282 clause 21.1); any other callback without them.
func (svc *service) deliverEvents(box *storeBox) {
	key := box.Store + "\x00" + box.ID
	for attempt := 0; attempt < deliveryAttempts; attempt++ {
		svc.store.mu.Lock()
		type batch struct {
			sub  storeSubscription
			body []byte
			last int64
		}
		var batches []batch
		for _, sub := range box.Subscriptions {
			var events []json.RawMessage
			last := sub.Index
			for _, event := range box.Events {
				if event.Index > sub.Index {
					events = append(events, event.Event)
					last = event.Index
				}
			}
			if len(events) == 0 {
				continue
			}
			body, err := json.Marshal(map[string]any{"nmsEventList": map[string]any{"nmsEvent": events,
				"callbackData": sub.CallbackData, "index": last, "restartToken": box.RestartToken}})
			if err != nil {
				svc.logEvent("msgstore_notification_failed", map[string]any{"subscription": sub.ID, "error": err.Error()})
				continue
			}
			batches = append(batches, batch{*sub, body, last})
		}
		svc.store.mu.Unlock()
		if len(batches) == 0 {
			break
		}
		failed := false
		for _, pending := range batches {
			request, err := http.NewRequestWithContext(svc.ctx, http.MethodPost, pending.sub.NotifyURL, bytes.NewReader(pending.body))
			if err != nil {
				// Not deliverable now: counted as a failed attempt, so that the retries end.
				failed = true
				continue
			}
			request.Header.Set("Content-Type", "application/json")
			if svc.trustedCallback(pending.sub.NotifyURL) {
				request.SetBasicAuth(svc.cfg.ServerClientID, svc.cfg.ServerSecret)
			}
			response, err := svc.httpClient().Do(request)
			if err == nil {
				// The answer's body is not used: drained for the connection's reuse, errors do not matter.
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
				_ = response.Body.Close()
			}
			if err != nil || response.StatusCode >= 300 {
				failed = true
				continue
			}
			svc.store.mu.Lock()
			if sub := box.Subscriptions[pending.sub.ID]; sub != nil && pending.last > sub.Index {
				sub.Index = pending.last
				if err := svc.saveBoxLocked(box); err != nil {
					// Kept in memory; after a restart the events are sent again.
					svc.logEvent("msgstore_save_failed", map[string]any{"box": box.ID, "error": err.Error()})
				}
			}
			svc.store.mu.Unlock()
		}
		if !failed {
			attempt = -1 // new events may have arrived meanwhile: look again
		} else {
			time.Sleep(time.Duration(attempt+1) * deliveryRetryDelay)
		}
	}
	svc.store.mu.Lock()
	delete(svc.store.sending, key)
	svc.store.mu.Unlock()
}

// ------------------------------------------------------------------------------
// Helper: whether a callback URL belongs to this system's notification server (MCData-11).
func (svc *service) trustedCallback(callback string) bool {
	for _, root := range []string{svc.cfg.Endpoints.NotificationInternal, svc.cfg.Endpoints.Notification} {
		if root != "" && strings.HasPrefix(callback, strings.TrimSuffix(root, "/")+"/") {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------------------
// Helper (not in TS 24.282): for the servers and tests, the boxes and their object counts.
func (svc *service) nmsListBoxes(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	svc.store.mu.Lock()
	defer svc.store.mu.Unlock()
	out := map[string]any{}
	for _, box := range svc.store.boxes {
		out[box.ID] = map[string]any{"store": box.Store, "objects": len(box.Objects), "folders": len(box.Folders),
			"subscriptions": len(box.Subscriptions), "mod_seq": box.ModSeq, "events": lastIndex(box)}
	}
	writeJSON(writer, http.StatusOK, out)
}
