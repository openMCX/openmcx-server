//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// The HTTP request log of the common services and the HTTP proxy (OpenMCX, no 3GPP specification): at log level
// "debug" (the configuration's "log_level", or the environment variable MCX_LOG, which overrides it), one
// human-readable line per request on stderr, "YYYY/MM/DD HH:MM:SS OpenMCX DEBUG [<program>] HTTP <method> <path> |
// <status> | <n> ms | <remote>" in local time; stdout keeps the JSON events. Never the query string, the headers or the body:
// they carry access tokens, passwords and keys.
package common

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// ------------------------------------------------------------------------------
// DebugLogging tells whether the log level is "debug": MCX_LOG if set, else the configured level ("info" when
// empty). Any other value is an error.
func DebugLogging(configured string) (bool, error) {
	level := configured
	if env := os.Getenv("MCX_LOG"); env != "" {
		level = env
	}
	switch level {
	case "", "info":
		return false, nil
	case "debug":
		return true, nil
	}
	return false, fmt.Errorf("invalid log level %q (info or debug)", level)
}

// ------------------------------------------------------------------------------
// debugLog writes the debug lines on stderr, without the standard logger's flags: each line carries its own time.
var debugLog = log.New(os.Stderr, "", 0)

// ------------------------------------------------------------------------------
// WithRequestLog wraps handler so that each request is logged under program ("cms", "idms", "http-proxy").
func WithRequestLog(handler http.Handler, program string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: writer, status: http.StatusOK}
		handler.ServeHTTP(recorder, request)
		debugLog.Printf("%s OpenMCX DEBUG [%s] HTTP %s %s | %d | %d ms | %s", start.Format("2006/01/02 15:04:05"),
			program, request.Method, request.URL.Path, recorder.status, time.Since(start).Milliseconds(), request.RemoteAddr)
	})
}

// ------------------------------------------------------------------------------
// Helper: a ResponseWriter that remembers the status; Flush and Unwrap keep streaming responses (long polling, file
// transfers) working.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (recorder *statusRecorder) WriteHeader(status int) {
	recorder.status = status
	recorder.ResponseWriter.WriteHeader(status)
}

func (recorder *statusRecorder) Flush() {
	if flusher, ok := recorder.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (recorder *statusRecorder) Unwrap() http.ResponseWriter { return recorder.ResponseWriter }
