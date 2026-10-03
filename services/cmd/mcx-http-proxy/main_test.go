package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ------------------------------------------------------------------------------
// TS 24.482 annex A.2.2.2: the public proxy forwards a client's request by path prefix with its bearer credential
// and without the proxy headers a client could forge, passes the upstream decision and entity tag back
// unchanged, and exposes no internal route.
func TestPublicRoutingAndAuthorizationPreservation(test *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, forwarded *http.Request) {
		if forwarded.URL.Path != "/xcap-root/org.openmobilealliance.groups/global/byGroupID/test" {
			test.Errorf("wrong forwarded path: %s", forwarded.URL.Path)
		}
		if forwarded.Header.Get("Authorization") != "Bearer test-only" {
			test.Error("bearer credential not forwarded")
		}
		if forwarded.Header.Get("Forwarded") != "" || forwarded.Header.Get("X-Forwarded-User") != "" {
			test.Error("untrusted proxy identity forwarded")
		}
		writer.Header().Set("ETag", "\"profile-version\"")
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte("upstream authorization decision"))
	}))
	defer upstream.Close()
	endpoints := map[string]string{}
	for _, role := range []string{"gms", "cms", "lms", "kms"} {
		endpoints[role] = upstream.URL
	}
	handler, err := proxyHandler(endpoints, upstream.Client().Transport)
	if err != nil {
		test.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/gms/xcap-root/org.openmobilealliance.groups/global/byGroupID/test", nil)
	request.Header.Set("Authorization", "Bearer test-only")
	request.Header.Set("Forwarded", "for=attacker")
	request.Header.Set("X-Forwarded-User", "privileged")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 401 || response.Header().Get("ETag") != "\"profile-version\"" {
		test.Fatalf("upstream decision not preserved: %d", response.Code)
	}
	for _, target := range []string{"/gms/internal/group", "/cms/internal/user", "/internal/group", "/idms/token", "/gms/xcap-root/../../internal/group", "/kms/internal/user"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest("GET", target, nil))
		if recorder.Code != 400 && recorder.Code != 404 {
			test.Errorf("private route %s exposed: %d", target, recorder.Code)
		}
	}
}

// ------------------------------------------------------------------------------
// The proxy refuses an upstream whose TLS certificate it does not trust (502), a body above 1 MiB (413), and a
// plaintext upstream in its configuration.
func TestRejectUntrustedUpstreamAndLargeBody(test *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { test.Error("untrusted upstream reached") }))
	defer upstream.Close()
	endpoints := map[string]string{}
	for _, role := range []string{"gms", "cms", "lms", "kms"} {
		endpoints[role] = upstream.URL
	}
	handler, err := proxyHandler(endpoints, http.DefaultTransport)
	if err != nil {
		test.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/cms/xcap-root/test", nil))
	if recorder.Code != 502 {
		test.Fatalf("untrusted TLS should fail: %d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("PUT", "/lms/location/test", strings.NewReader(strings.Repeat("x", (1<<20)+1))))
	if recorder.Code != 413 {
		test.Fatalf("large body accepted: %d", recorder.Code)
	}
	endpoints["cms"] = "http://plaintext.invalid"
	if _, err := proxyHandler(endpoints, http.DefaultTransport); err == nil {
		test.Fatal("plaintext upstream accepted")
	}
}

// ------------------------------------------------------------------------------
// TS 24.482 annex A.2.2.2 for TS 24.282 clause 21.2: the message store (MCData-7) and notification server
// (MCData-10) are reached through the proxy; a backslash passes only as a flag name; their callbacks and internals
// are not reached.
func TestMessageStoreRouting(test *testing.T) {
	var seen []string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seen = append(seen, request.URL.Path)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	endpoints := map[string]string{}
	for _, role := range []string{"gms", "cms", "lms", "kms", "msgstore", "notification"} {
		endpoints[role] = upstream.URL
	}
	handler, err := proxyHandler(endpoints, upstream.Client().Transport)
	if err != nil {
		test.Fatal(err)
	}
	for _, target := range []string{"/msgstore/nms/v1/mcdata/sip:alice@mcx.test/objects", "/notification/notificationchannel/v1/sip:alice@mcx.test/channels"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest("POST", target, nil))
		if recorder.Code != http.StatusNoContent {
			test.Errorf("%s not forwarded: %d", target, recorder.Code)
		}
	}
	if len(seen) != 2 || seen[0] != "/nms/v1/mcdata/sip:alice@mcx.test/objects" || seen[1] != "/notificationchannel/v1/sip:alice@mcx.test/channels" {
		test.Fatalf("forwarded paths %v", seen)
	}
	// A flag name such as \Seen passes, as the last segment of a flags path only.
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("PUT", "/msgstore/nms/v1/mcdata/a/objects/o/flags/%5CSeen", nil))
	if recorder.Code != http.StatusNoContent {
		test.Errorf("a flag name was refused: %d", recorder.Code)
	}
	for _, target := range []string{"/msgstore/nms/v1/mcdata/a%5Cb/objects", "/msgstore/nms/v1/mcdata/a/objects/o/flags/%5C/x"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest("PUT", target, nil))
		if recorder.Code != http.StatusBadRequest {
			test.Errorf("backslash in %s accepted: %d", target, recorder.Code)
		}
	}
	for _, target := range []string{"/msgstore/internal/msgstore/boxes", "/notification/notificationchannel/callbacks/x", "/notification/internal/notification/channels"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest("POST", target, nil))
		if recorder.Code != http.StatusNotFound {
			test.Errorf("private route %s exposed: %d", target, recorder.Code)
		}
	}
}

// ------------------------------------------------------------------------------
// TS 24.545: a client reaches its own SEAL location resources, told the prefix this proxy removed; the servers'
// subscriptions and channels stay internal.
func TestSealLocationRouting(test *testing.T) {
	var prefix, path string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		prefix, path = request.Header.Get("X-Forwarded-Prefix"), request.URL.Path
		writer.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	endpoints := map[string]string{}
	for _, role := range []string{"gms", "cms", "lms", "kms"} {
		endpoints[role] = upstream.URL
	}
	handler, err := proxyHandler(endpoints, upstream.Client().Transport)
	if err != nil {
		test.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest("GET", "/lms/seal-lm/v1/users/sip:bob@mcx.test/configuration", nil))
	if rr.Code != http.StatusOK || prefix != "/lms" || path != "/seal-lm/v1/users/sip:bob@mcx.test/configuration" {
		test.Fatalf("client configuration: %d prefix %q path %q", rr.Code, prefix, path)
	}
	for _, internal := range []string{"/lms/seal-lm/v1/subscriptions", "/lms/seal-lm/v1/notifications"} {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest("POST", internal, strings.NewReader("<x/>")))
		if rr.Code != http.StatusNotFound {
			test.Fatalf("%s reachable from clients: %d", internal, rr.Code)
		}
	}
}

// ------------------------------------------------------------------------------
// Helper: a body of [size] bytes produced on demand.
func bodyOf(size int64) io.Reader { return io.LimitReader(zeroes{}, size) }

// ------------------------------------------------------------------------------
// Helper: an endless reader of zero bytes.
type zeroes struct{}

// ------------------------------------------------------------------------------
// Helper: fills the buffer with zeroes.
func (zeroes) Read(buffer []byte) (int, error) { clear(buffer); return len(buffer), nil }

// ------------------------------------------------------------------------------
// Helper: a proxy with the given content options in front of an upstream that counts the bytes it receives;
// returns the proxy and the upstream.
func contentProxy(test *testing.T, received *int64, options contentOptions) (http.Handler, *httptest.Server) {
	test.Helper()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		copied, _ := io.Copy(io.Discard, request.Body)
		*received = copied
		writer.WriteHeader(http.StatusCreated)
	}))
	endpoints := map[string]string{"content": upstream.URL, "msgstore": upstream.URL}
	for _, role := range []string{"gms", "cms", "lms", "kms"} {
		endpoints[role] = upstream.URL
	}
	handler, err := proxyHandlerWith(endpoints, upstream.Client().Transport, options)
	if err != nil {
		test.Fatal(err)
	}
	return handler, upstream
}

// ------------------------------------------------------------------------------
// A configured content limit above the default lets a large upload stream through to the media storage function;
// the message store keeps the default bound.
func TestConfiguredContentLimitAllowsLargeStreamingUpload(test *testing.T) {
	var received int64
	size := int64(contentLimit + 4<<20)
	handler, upstream := contentProxy(test, &received, contentOptions{limit: size})
	defer upstream.Close()
	request := httptest.NewRequest("POST", "/content/mcdata/files", bodyOf(size))
	request.ContentLength = size
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || received != size {
		test.Fatalf("large upload: status=%d received=%d", response.Code, received)
	}
	// The message store keeps the default bound.
	request = httptest.NewRequest("PUT", "/msgstore/nms/v1/x", bodyOf(size))
	request.ContentLength = size
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		test.Fatalf("message store bound changed: status=%d", response.Code)
	}
}

// ------------------------------------------------------------------------------
// The content limit refuses an upload above it with 413, with or without a known length, and passes one at it.
func TestContentRequestLimitRejectsKnownAndUnknownLength(test *testing.T) {
	var received int64
	handler, upstream := contentProxy(test, &received, contentOptions{limit: 1000})
	defer upstream.Close()
	for _, known := range []bool{true, false} {
		request := httptest.NewRequest("POST", "/content/mcdata/files", bodyOf(1001))
		request.ContentLength = map[bool]int64{true: 1001, false: -1}[known]
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusRequestEntityTooLarge {
			test.Fatalf("over the limit (known length %v): status=%d", known, response.Code)
		}
	}
	request := httptest.NewRequest("POST", "/content/mcdata/files", bodyOf(1000))
	request.ContentLength = -1
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || received != 1000 {
		test.Fatalf("at the limit: status=%d received=%d", response.Code, received)
	}
}

// ------------------------------------------------------------------------------
// A slow upload outlives the server's read timeout only with the configured deadline.
func TestSlowFileTransferUsesConfiguredTimeout(test *testing.T) {
	for _, timeout := range []time.Duration{0, 5 * time.Second} {
		var received int64
		handler, upstream := contentProxy(test, &received, contentOptions{limit: 1 << 20, timeout: timeout})
		proxy := httptest.NewUnstartedServer(handler)
		proxy.Config.ReadTimeout = 300 * time.Millisecond
		proxy.StartTLS()
		reader, writer := io.Pipe()
		go func() {
			for chunk := 0; chunk < 8; chunk++ {
				time.Sleep(100 * time.Millisecond)
				_, _ = writer.Write(make([]byte, 1024))
			}
			_ = writer.Close()
		}()
		request, _ := http.NewRequest("POST", proxy.URL+"/content/mcdata/files", reader)
		response, err := proxy.Client().Do(request)
		ok := err == nil && response.StatusCode == http.StatusCreated && received == 8*1024
		if response != nil {
			_ = response.Body.Close()
		}
		if ok != (timeout > 0) {
			test.Errorf("timeout %v: completed=%v (err=%v)", timeout, ok, err)
		}
		proxy.Close()
		upstream.Close()
	}
}

// ------------------------------------------------------------------------------
// Helper: the public handler with the default content limit (the tests' proxy).
func proxyHandler(endpoints map[string]string, transport http.RoundTripper) (http.Handler, error) {
	return proxyHandlerWith(endpoints, transport, contentOptions{limit: contentLimit})
}
