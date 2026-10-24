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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
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
		contentOptions{limit: contentRequestLimit, timeout: time.Duration(transferTimeoutMs) * time.Millisecond})
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
}

// ------------------------------------------------------------------------------
// TS 24.482 annex A.2.2.2: the public proxy: forwards the HTTP requests of MC clients by path prefix to the public
// resources of the GMS, CMS, LMS, KMS and the MCData content server, message store and notification server, removes
// caller-supplied proxy assertions, bounds the request bodies, and never logs a body or a credential.
func proxyHandlerWith(endpoints map[string]string, transport http.RoundTripper, content contentOptions) (http.Handler, error) {
	proxies := map[string]*httputil.ReverseProxy{}
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
