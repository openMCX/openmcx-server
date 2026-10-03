// The MCData notification server: LongPolling notification channels on MCData-10 and the callback of MCData-11.
//
// Specifications: TS 24.282 V19.7.0 (Rel-19), TS 23.282 V19.10.0 (Rel-19), TS 24.482 V19.1.0 (Rel-19),
// OMA RESTful Network API for Notification Channel (OMA-TS-REST_NetAPI_NotificationChannel-V1_0).
package common

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The MCData notification server (TS 24.282 clause 21.2.16.3, clauses 21.2.19 to 21.2.22; TS 23.282
// clause 7.13.3.17.3, reference points MCData-10 and MCData-11 in TS 23.282 clauses 6.4.4.1.9 and 6.4.4.1.10).
// MCData-10 follows OMA-TS-REST_NetAPI_NotificationChannel-V1_0:
//
//	POST   /notificationchannel/v1/{userId}/channels                    create a channel
//	GET    /notificationchannel/v1/{userId}/channels[/{channelId}]      read
//	DELETE /notificationchannel/v1/{userId}/channels/{channelId}        delete
//	PUT    /notificationchannel/v1/{userId}/channels/{channelId}/channelLifetime
//	POST   /notificationchannel/v1/{userId}/channels/{channelId}/poll   the channelURL (LongPolling)
//
// MCData-11: the message store POSTs its NmsEventList to the channel's callbackURL,
//
//	POST   /notificationchannel/callbacks/{channelId}
//
// with the system's service credentials. Only LongPolling channels are offered: a
// WebSocket or native (push) channel needs a transport the lab does not have.

type notificationChannel struct {
	ID         string
	User       string
	Tag        string
	Correlator string
	Max        int
	Expires    time.Time
	queue      []json.RawMessage
	wake       chan struct{}
	received   int
	delivered  int
}

type notificationServer struct {
	mu       sync.Mutex
	channels map[string]*notificationChannel
}

const (
	defaultChannelLifetime = 3600
	maxChannelLifetime     = 86400
	maxQueuedNotifications = 200
	// openMCX limits (OMA-TS-REST_NetAPI_NotificationChannel-V1_0 leaves them to the server): channels per user,
	// and the default and largest maxNotifications per poll.
	maxChannelsPerUser      = 8
	defaultMaxNotifications = 20
	maxMaxNotifications     = 100
)

// ------------------------------------------------------------------------------
// Helper: an empty notification server.
func newNotificationServer() *notificationServer {
	return &notificationServer{channels: map[string]*notificationChannel{}}
}

// ------------------------------------------------------------------------------
// TS 23.282 clauses 6.4.4.1.9 and 6.4.4.1.10: registers the routes of MCData-10 (the channel resources of
// OMA-TS-REST_NetAPI_NotificationChannel-V1_0) and MCData-11 (the callback), and the internal channel listing.
func (svc *service) routesNotification(mux *http.ServeMux) {
	base := "/notificationchannel/v1/{user}/channels"
	mux.HandleFunc("POST "+base, svc.createChannel)
	mux.HandleFunc("GET "+base, svc.listChannels)
	mux.HandleFunc("GET "+base+"/{channel}", svc.getChannel)
	mux.HandleFunc("DELETE "+base+"/{channel}", svc.deleteChannel)
	mux.HandleFunc("PUT "+base+"/{channel}/channelLifetime", svc.updateChannelLifetime)
	mux.HandleFunc("POST "+base+"/{channel}/poll", svc.pollChannel)
	mux.HandleFunc("POST /notificationchannel/callbacks/{channel}", svc.channelCallback)
	mux.HandleFunc("GET /internal/notification/channels", svc.internalChannels)
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.1 NOTE 1: authenticates the access token (TS 24.482); the user of the path must be
// the MCData ID of the token.
func (svc *service) channelUser(writer http.ResponseWriter, request *http.Request) (string, bool) {
	claims, ok := svc.authenticateBearer(writer, request)
	if !ok {
		return "", false
	}
	if claims.MCDataID == "" || claims.MCDataID != request.PathValue("user") {
		nmsError(writer, http.StatusForbidden, "POL0001", "Access to another MCData user's channels is not allowed")
		return "", false
	}
	return claims.MCDataID, true
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.1 NOTE 1: the channel named in the path, which must belong to the MCData ID of the
// access token; otherwise answers 404 with SVC0004. Expired channels are removed first.
func (svc *service) channelOf(writer http.ResponseWriter, request *http.Request) (*notificationChannel, bool) {
	user, ok := svc.channelUser(writer, request)
	if !ok {
		return nil, false
	}
	svc.notifications.mu.Lock()
	defer svc.notifications.mu.Unlock()
	svc.expireChannelsLocked()
	channel := svc.notifications.channels[request.PathValue("channel")]
	if channel == nil || channel.User != user {
		nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "channelId")
		return nil, false
	}
	return channel, true
}

// ------------------------------------------------------------------------------
// Helper: removes the channels whose lifetime has run out and wakes their polls; the caller holds
// svc.notifications.mu.
func (svc *service) expireChannelsLocked() {
	now := svc.now()
	for id, channel := range svc.notifications.channels {
		if !now.Before(channel.Expires) {
			close(channel.wake)
			delete(svc.notifications.channels, id)
		}
	}
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.19.2 NOTE 1: the channel resource as returned to the client, with its channelURL
// (LongPolling) and its callbackURL, which the message store reaches directly over MCData-11.
func (svc *service) channelView(channel *notificationChannel) map[string]any {
	root := strings.TrimSuffix(svc.cfg.Endpoints.Notification, "/")
	internal := strings.TrimSuffix(svc.cfg.Endpoints.NotificationInternal, "/")
	if internal == "" {
		internal = root
	}
	base := svc.channelResourceURL(channel)
	return map[string]any{
		"clientCorrelator": channel.Correlator, "applicationTag": channel.Tag, "channelType": "LongPolling",
		"channelData": map[string]any{"channelURL": base + "/poll", "maxNotifications": channel.Max},
		// The message store reaches the callback directly (MCData-11).
		"callbackURL":     internal + "/notificationchannel/callbacks/" + channel.ID,
		"resourceURL":     base,
		"channelLifetime": int64(channel.Expires.Sub(svc.now()).Seconds()),
	}
}

// ------------------------------------------------------------------------------
// Helper: the channel's resourceURL, also its Location when created.
func (svc *service) channelResourceURL(channel *notificationChannel) string {
	root := strings.TrimSuffix(svc.cfg.Endpoints.Notification, "/")
	return root + "/notificationchannel/v1/" + url.PathEscape(channel.User) + "/channels/" + channel.ID
}

// ------------------------------------------------------------------------------
// Helper: the granted channel lifetime in seconds: the default when none is requested, at most the maximum.
func channelLifetime(requested int64) int64 {
	if requested <= 0 {
		return defaultChannelLifetime
	}
	if requested > maxChannelLifetime {
		return maxChannelLifetime
	}
	return requested
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.19.2: creates a LongPolling channel (OMA-TS-REST_NetAPI_NotificationChannel-V1_0
// clause 6.1.5); at most 8 channels per user.
func (svc *service) createChannel(writer http.ResponseWriter, request *http.Request) {
	user, ok := svc.channelUser(writer, request)
	if !ok {
		return
	}
	var channelRequest struct {
		ClientCorrelator string `json:"clientCorrelator"`
		ApplicationTag   string `json:"applicationTag"`
		ChannelType      string `json:"channelType"`
		ChannelData      struct {
			MaxNotifications int `json:"maxNotifications"`
		} `json:"channelData"`
		ChannelLifetime int64 `json:"channelLifetime"`
	}
	if !readJSON(writer, request, "notificationChannel", &channelRequest) {
		return
	}
	if channelRequest.ChannelType != "" && channelRequest.ChannelType != "LongPolling" {
		nmsError(writer, http.StatusBadRequest, "SVC0003", "Invalid input value for message part %1, valid values are %2",
			"channelType", "LongPolling")
		return
	}
	svc.notifications.mu.Lock()
	defer svc.notifications.mu.Unlock()
	svc.expireChannelsLocked()
	count := 0
	for _, channel := range svc.notifications.channels {
		if channel.User == user {
			count++
		}
	}
	if count >= maxChannelsPerUser {
		nmsError(writer, http.StatusForbidden, "POL0003", "Too many channels")
		return
	}
	maxNotifications := channelRequest.ChannelData.MaxNotifications
	if maxNotifications <= 0 || maxNotifications > maxMaxNotifications {
		maxNotifications = defaultMaxNotifications
	}
	channel := &notificationChannel{ID: mustRandom(16), User: user, Tag: channelRequest.ApplicationTag, Correlator: channelRequest.ClientCorrelator,
		Max: maxNotifications, Expires: svc.now().Add(time.Duration(channelLifetime(channelRequest.ChannelLifetime)) * time.Second), wake: make(chan struct{})}
	svc.notifications.channels[channel.ID] = channel
	writer.Header().Set("Location", svc.channelResourceURL(channel))
	writeJSON(writer, http.StatusCreated, map[string]any{"notificationChannel": svc.channelView(channel)})
}

// ------------------------------------------------------------------------------
// OMA-TS-REST_NetAPI_NotificationChannel-V1_0: the list of the user's channels.
func (svc *service) listChannels(writer http.ResponseWriter, request *http.Request) {
	user, ok := svc.channelUser(writer, request)
	if !ok {
		return
	}
	svc.notifications.mu.Lock()
	defer svc.notifications.mu.Unlock()
	svc.expireChannelsLocked()
	list := []map[string]any{}
	for _, channel := range svc.notifications.channels {
		if channel.User == user {
			list = append(list, svc.channelView(channel))
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{"notificationChannelList": map[string]any{"channel": list}})
}

// ------------------------------------------------------------------------------
// OMA-TS-REST_NetAPI_NotificationChannel-V1_0: one of the user's channels.
func (svc *service) getChannel(writer http.ResponseWriter, request *http.Request) {
	channel, ok := svc.channelOf(writer, request)
	if !ok {
		return
	}
	svc.notifications.mu.Lock()
	view := svc.channelView(channel)
	svc.notifications.mu.Unlock()
	writeJSON(writer, http.StatusOK, map[string]any{"notificationChannel": view})
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.20.2: deletes the channel and wakes its polls
// (OMA-TS-REST_NetAPI_NotificationChannel-V1_0 clause 6.2.6).
func (svc *service) deleteChannel(writer http.ResponseWriter, request *http.Request) {
	channel, ok := svc.channelOf(writer, request)
	if !ok {
		return
	}
	svc.notifications.mu.Lock()
	if _, open := svc.notifications.channels[channel.ID]; open {
		close(channel.wake)
		delete(svc.notifications.channels, channel.ID)
	}
	svc.notifications.mu.Unlock()
	writer.WriteHeader(http.StatusNoContent)
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.21.2: updates the channel lifetime, a new lifetime from now
// (OMA-TS-REST_NetAPI_NotificationChannel-V1_0 clause 6.4.4).
func (svc *service) updateChannelLifetime(writer http.ResponseWriter, request *http.Request) {
	channel, ok := svc.channelOf(writer, request)
	if !ok {
		return
	}
	var lifetime int64
	if !readJSON(writer, request, "channelLifetime", &lifetime) {
		return
	}
	svc.notifications.mu.Lock()
	channel.Expires = svc.now().Add(time.Duration(channelLifetime(lifetime)) * time.Second)
	remaining := int64(channel.Expires.Sub(svc.now()).Seconds())
	svc.notifications.mu.Unlock()
	writeJSON(writer, http.StatusOK, map[string]any{"channelLifetime": remaining})
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.22.2: the long poll (OMA-TS-REST_NetAPI_NotificationChannel-V1_0 clause 6.3.5). Notifications waiting are answered at once; otherwise
// the request is held until one arrives or the poll time ("wait" seconds, at most 9,
// default 8) runs out, and an empty list is returned. The bound keeps the poll inside
// the HTTP proxy's 10 s wait for a response header.
func (svc *service) pollChannel(writer http.ResponseWriter, request *http.Request) {
	channel, ok := svc.channelOf(writer, request)
	if !ok {
		return
	}
	wait := 8 * time.Second
	if value := request.URL.Query().Get("wait"); value != "" {
		if duration, err := time.ParseDuration(value + "s"); err == nil && duration >= 0 && duration <= 9*time.Second {
			wait = duration
		}
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		svc.notifications.mu.Lock()
		if len(channel.queue) > 0 {
			count := len(channel.queue)
			if count > channel.Max {
				count = channel.Max
			}
			batch := append([]json.RawMessage{}, channel.queue[:count]...)
			channel.queue = channel.queue[count:]
			channel.delivered += count
			svc.notifications.mu.Unlock()
			writeJSON(writer, http.StatusOK, map[string]any{"notificationList": batch})
			return
		}
		wake := channel.wake
		svc.notifications.mu.Unlock()
		select {
		case <-wake:
			svc.notifications.mu.Lock()
			_, open := svc.notifications.channels[channel.ID]
			svc.notifications.mu.Unlock()
			if !open {
				nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "channelId")
				return
			}
		case <-deadline.C:
			writeJSON(writer, http.StatusOK, map[string]any{"notificationList": []json.RawMessage{}})
			return
		case <-request.Context().Done():
			return
		}
	}
}

// ------------------------------------------------------------------------------
// TS 24.282 clause 21.2.16.3: a notification from the message store over MCData-11 (TS 23.282 clause
// 7.13.3.17.3), queued for the channel's client (at most maxQueuedNotifications, the oldest dropped).
func (svc *service) channelCallback(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
	if err != nil || !json.Valid(raw) {
		nmsError(writer, http.StatusBadRequest, "SVC0001", "malformed notification")
		return
	}
	svc.notifications.mu.Lock()
	defer svc.notifications.mu.Unlock()
	svc.expireChannelsLocked()
	channel := svc.notifications.channels[request.PathValue("channel")]
	if channel == nil {
		nmsError(writer, http.StatusNotFound, "SVC0004", "No valid addresses provided in message part %1", "channelId")
		return
	}
	channel.queue = append(channel.queue, json.RawMessage(raw))
	if len(channel.queue) > maxQueuedNotifications {
		channel.queue = channel.queue[len(channel.queue)-maxQueuedNotifications:]
	}
	channel.received++
	// Wake every poll waiting on the channel.
	close(channel.wake)
	channel.wake = make(chan struct{})
	writer.WriteHeader(http.StatusNoContent)
}

// ------------------------------------------------------------------------------
// Helper: the internal list of all channels with their queue counters, for the lab's tests.
func (svc *service) internalChannels(writer http.ResponseWriter, request *http.Request) {
	if !svc.requireInternal(writer, request) {
		return
	}
	svc.notifications.mu.Lock()
	defer svc.notifications.mu.Unlock()
	out := []map[string]any{}
	for _, channel := range svc.notifications.channels {
		out = append(out, map[string]any{"id": channel.ID, "user": channel.User, "queued": len(channel.queue), "received": channel.received, "delivered": channel.delivered})
	}
	writeJSON(writer, http.StatusOK, out)
}
