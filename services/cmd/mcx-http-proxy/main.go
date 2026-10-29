//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// mcx-http-proxy exposes only the public common-service reference points: the HTTP proxy of TS 24.482 clause 5.4
// and annex A.2.2 in front of the GMS, CMS, LMS, KMS and the MCData content server, message store and notification
// server.
//
// Specifications: TS 24.482 V19.1.0 (Rel-19), TS 24.481 V19.3.0 (Rel-19), TS 24.282 V19.7.0 (Rel-19),
// TS 23.280 V19.10.1 (Rel-19), TS 24.545.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/open-mcx/open-mcx/services/internal/common"
)

// ------------------------------------------------------------------------------
// Helper: runs the proxy; a failure is logged and exits with status 1.
func main() {
	if err := run(); err != nil {
		log.Printf("mcx-http-proxy: %v", err)
		os.Exit(1)
	}
}

// ------------------------------------------------------------------------------
// Helper: reads the flags and the site configuration, builds the upstream transport (presenting the proxy's
// certificate) and the public listener.
func run() error {
	var config, listen, cert, key, ca string
	var contentRequestLimit int64
	var transferTimeoutMs int
	flag.StringVar(&config, "config", "", "site JSON configuration")
	flag.StringVar(&listen, "listen", ":8443", "HTTPS listen address")
	flag.StringVar(&cert, "tls-cert", "", "server certificate PEM")
	flag.StringVar(&key, "tls-key", "", "server private key PEM")
	flag.StringVar(&ca, "ca-file", "", "upstream CA certificate PEM")
	flag.Int64Var(&contentRequestLimit, "content-request-limit-bytes", contentLimit,
		"largest request body passed to the MCData content server (file plus its multipart framing)")
	flag.IntVar(&transferTimeoutMs, "file-transfer-timeout-ms", 0,
		"read and write deadline of one MCData file upload or download; 0 keeps the server timeouts")
	flag.Parse()
	if config == "" || cert == "" || key == "" || ca == "" {
		return errors.New("--config, --tls-cert, --tls-key and --ca-file are required")
	}
	if contentRequestLimit <= 0 || transferTimeoutMs < 0 {
		return errors.New("--content-request-limit-bytes must be positive and --file-transfer-timeout-ms not negative")
	}
	common.PrintBanner("mcx-http-proxy")
	raw, err := os.ReadFile(config)
	if err != nil {
		return err
	}
	var cfg struct {
		Endpoints map[string]string `json:"endpoints"`
		Forward   map[string]string `json:"forward"`
		LogLevel  string            `json:"log_level"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	pem, err := os.ReadFile(ca)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return errors.New("CA file contains no certificate")
	}
	own, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return err
	}
	// The proxy presents its own certificate upstream.
	transport := &http.Transport{
		TLSClientConfig:     common.TLSProfile(&tls.Config{RootCAs: pool, Certificates: []tls.Certificate{own}}),
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout: 30 * time.Second, MaxIdleConns: 32, MaxIdleConnsPerHost: 8,
	}
	handler, err := proxyHandlerWith(cfg.Endpoints, transport,
		contentOptions{limit: contentRequestLimit, timeout: time.Duration(transferTimeoutMs) * time.Millisecond,
			forward: cfg.Forward})
	if err != nil {
		return err
	}
	if debug, err := common.DebugLogging(cfg.LogLevel); err != nil {
		return err
	} else if debug {
		handler = common.WithRequestLog(handler, "http-proxy")
	}
	serverTLS := common.TLSProfile(&tls.Config{})
	server := &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 64 << 10, TLSConfig: serverTLS}
	log.Printf("HTTPS public common-service proxy listening on %s", listen)
	return server.ListenAndServeTLS(cert, key)
}

// The largest request body this proxy passes to the MCData content server and the
// message store, unless configured otherwise for the content server.
const contentLimit = 32 << 20

// contentOptions bound MCData file transfers through the proxy: the largest upload body,
// and a per-request deadline that replaces the short server timeouts for a large file.
type contentOptions struct {
	limit   int64
	timeout time.Duration
	// forward: the authorities of the own MC service provider's servers ("host[:port]" of their URIs) -> the role whose
	// upstream serves them, for requests in absolute-form (TS 24.482 annex A.2.2.2 step 3).
	forward map[string]string
}

// The context key of a request this proxy received in absolute-form (its target authority).
type forwardedKey struct{}

// ------------------------------------------------------------------------------
// Helper: RFC 3986 section 6.2.3: an authority with its host in lower case and the scheme's default port (RFC 9110
// section 4.2.2) left out, so "cms.test:443" of an https URI and "cms.test" name the same server.
func normalAuthority(scheme, authority string) string {
	authority = strings.ToLower(authority)
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return authority
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return authority
}

// ------------------------------------------------------------------------------
// TS 24.482 annex A.2.2.2: the public proxy: forwards the HTTP requests of MC clients by path prefix to the public
// resources of the GMS, CMS, LMS, KMS and the MCData content server, message store and notification server, removes
// caller-supplied proxy assertions, bounds the request bodies, and never logs a body or a credential.
func proxyHandlerWith(endpoints map[string]string, transport http.RoundTripper, content contentOptions) (http.Handler, error) {
	proxies := map[string]*httputil.ReverseProxy{}
	// The forward map, normalised for both schemes a UE may send through the TLS tunnel (TS 24.482 annex A.2.1.2).
	forward := map[string]string{}
	for authority, role := range content.forward {
		switch role {
		case "gms", "cms", "lms", "kms", "content", "msgstore", "notification":
		default:
			return nil, fmt.Errorf("forward %s: unknown role %q", authority, role)
		}
		if authority == "" || strings.ContainsAny(authority, "/@?# ") {
			return nil, fmt.Errorf("forward: %q is not a host[:port]", authority)
		}
		forward[normalAuthority("https", authority)] = role
	}
	for _, role := range []string{"gms", "cms", "lms", "kms", "content", "msgstore", "notification"} {
		// The MCData content server, message store and notification server are
		// configured only where they are deployed.
		if (role == "content" || role == "msgstore" || role == "notification") && endpoints[role] == "" {
			continue
		}
		target, err := url.Parse(endpoints[role])
		if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil || target.RawQuery != "" || target.Fragment != "" || (target.Path != "" && target.Path != "/") {
			return nil, fmt.Errorf("%s requires an HTTPS origin URL", role)
		}
		prefix := "/" + role
		proxies[role] = &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(proxyRequest *httputil.ProxyRequest) {
				proxyRequest.SetURL(target)
				proxyRequest.Out.URL.Path = strings.TrimPrefix(proxyRequest.In.URL.Path, prefix)
				proxyRequest.Out.URL.RawPath = ""
				// No caller-supplied proxy assertions are trusted by the upstream.
				proxyRequest.Out.Header.Del("Forwarded")
				proxyRequest.Out.Header.Del("X-Forwarded-User")
				proxyRequest.SetXForwarded()
				if authority, ok := proxyRequest.In.Context().Value(forwardedKey{}).(string); ok {
					// Absolute-form: the client named the server itself, so the service's own URIs stay as they are.
					proxyRequest.Out.Header.Set("X-Forwarded-Host", authority)
					return
				}
				// The path prefix this proxy removed, for a service that returns its own URIs.
				proxyRequest.Out.Header.Set("X-Forwarded-Prefix", prefix)
			},
			ErrorHandler: func(writer http.ResponseWriter, request *http.Request, err error) {
				// A body of unknown length that overran the limit is refused as too large,
				// not reported as an upstream failure.
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					http.Error(writer, "request body too large", http.StatusRequestEntityTooLarge)
					return
				}
				// Never include upstream response bodies or bearer credentials in logs.
				http.Error(writer, "upstream unavailable", http.StatusBadGateway)
			},
		}
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && (request.URL.Path == "/healthz" || request.URL.Path == "/readyz") {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte("{\"ready\":true}\n"))
			return
		}
		// TS 24.482 annex A.2.2.2 step 1: "if the HTTP request method contains an X-3GPP-Asserted-Identity header field
		// ..., the HTTP proxy shall reject the HTTP request method with an HTTP 403 (Forbidden) response".
		if _, asserted := request.Header[http.CanonicalHeaderKey("X-3GPP-Asserted-Identity")]; asserted {
			http.Error(writer, "X-3GPP-Asserted-Identity not accepted from a client", http.StatusForbidden)
			return
		}
		// TS 24.482 annex A.2.2.1 (the proxy role of RFC 9112, section 3.2.2: a server "MUST accept the absolute-form")
		// and A.2.2.2 step 3: a request for a server of the own MC service provider is passed to it as a reverse
		// proxy, under the same public-path rules as the path prefixes; the provider has no partner (step 2), so an
		// authority this proxy does not serve is refused.
		// Over HTTP/2 the target's authority comes in :authority (RFC 9113 section 8.3.1, A.2.2.2 "server role of
		// ... IETF RFC 9113"): a request naming a served server there is forwarded the same way.
		h2Forward := !request.URL.IsAbs() && request.ProtoMajor == 2 && forward[normalAuthority("https", request.Host)] != ""
		if h2Forward {
			request.URL.Scheme, request.URL.Host = "https", request.Host
		}
		if request.URL.IsAbs() {
			authority := normalAuthority(request.URL.Scheme, request.URL.Host)
			role, served := forward[authority]
			if !served || request.URL.User != nil {
				http.Error(writer, "no server of this MC service provider", http.StatusForbidden)
				return
			}
			request = request.WithContext(context.WithValue(request.Context(), forwardedKey{}, request.URL.Host))
			target := request.URL
			request.URL = &url.URL{Path: "/" + role + target.Path, RawQuery: target.RawQuery}
			if target.RawPath != "" {
				request.URL.RawPath = "/" + role + target.RawPath
			}
			if request.URL.Path == "/"+role {
				request.URL.Path += "/"
			}
		}
		// The one backslash allowed is in a message store flag name (\Seen, \Flagged: the
		// flags resource of OMA NMS clause 6.3), as the last segment of a flags path.
		checked := request.URL.Path
		if index := strings.LastIndex(checked, "/flags/"); strings.HasPrefix(checked, "/msgstore/nms/v1/") && index >= 0 &&
			!strings.Contains(checked[index+len("/flags/"):], "/") {
			checked = checked[:index+len("/flags/")] + strings.ReplaceAll(checked[index+len("/flags/"):], "\\", "")
		}
		if path.Clean(request.URL.Path) != request.URL.Path || strings.ContainsRune(checked, '\\') {
			http.Error(writer, "invalid public path", http.StatusBadRequest)
			return
		}
		role := ""
		for _, name := range []string{"gms", "cms"} {
			if strings.HasPrefix(request.URL.Path, "/"+name+"/xcap-root/") {
				role = name
			}
		}
		// The SEAL location management server (TS 24.545): a client's own configuration,
		// reports and history only, never the servers' subscriptions and channels.
		if strings.HasPrefix(request.URL.Path, "/lms/location/") || strings.HasPrefix(request.URL.Path, "/lms/seal-lm/v1/users/") {
			role = "lms"
		}
		if strings.HasPrefix(request.URL.Path, "/kms/") && !strings.HasPrefix(request.URL.Path, "/kms/internal") {
			role = "kms"
		}
		// The MCData content server: file upload and download only (TS 24.282 clauses 10.2.2 and 10.2.3).
		if strings.HasPrefix(request.URL.Path, "/content/mcdata/files") && proxies["content"] != nil {
			role = "content"
		}
		// The MCData message store (MCData-7) and notification server (MCData-10), TS 24.282
		// clause 21: their public resources only, never the servers' callbacks or internals.
		if strings.HasPrefix(request.URL.Path, "/msgstore/nms/v1/") && proxies["msgstore"] != nil {
			role = "msgstore"
		}
		if strings.HasPrefix(request.URL.Path, "/notification/notificationchannel/v1/") && proxies["notification"] != nil {
			role = "notification"
		}
		if role == "" {
			http.NotFound(writer, request)
			return
		}
		// Uploaded files are streamed; every other request is small and buffered.
		if role == "content" || role == "msgstore" {
			limit := int64(contentLimit)
			if role == "content" {
				limit = content.limit
				if content.timeout > 0 {
					// Unsupported only on test recorders, where there is no deadline to extend.
					control := http.NewResponseController(writer)
					_ = control.SetReadDeadline(time.Now().Add(content.timeout))
					_ = control.SetWriteDeadline(time.Now().Add(content.timeout))
				}
			}
			if request.ContentLength > limit {
				http.Error(writer, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			request.Body = http.MaxBytesReader(writer, request.Body, limit)
			proxies[role].ServeHTTP(writer, request)
			return
		}
		if request.ContentLength > 1<<20 {
			http.Error(writer, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, 1<<20))
		if err != nil {
			http.Error(writer, "invalid or oversized request body", http.StatusRequestEntityTooLarge)
			return
		}
		_ = request.Body.Close()
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.ContentLength = int64(len(body))
		proxies[role].ServeHTTP(writer, request)
	}), nil
}
