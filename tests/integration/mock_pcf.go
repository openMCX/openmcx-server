// A mock PCF for the N5 lab: Npcf_PolicyAuthorization (TS 29.514) over HTTP/2
// cleartext with prior knowledge and over HTTP/1.1, recording every request.
//
//	POST   /npcf-policyauthorization/v1/app-sessions              201 + Location
//	PATCH  /npcf-policyauthorization/v1/app-sessions/{id}         200
//	POST   /npcf-policyauthorization/v1/app-sessions/{id}/delete  204
//
// Test control (not part of N5):
//
//	GET  /mock/requests              the recorded requests
//	POST /mock/config {"fail_create": true}
//	POST /mock/notify {"id": "...", "kind": "notify"|"terminate", "body": {...}}
//	     sends the notification to the AF's notifUri of that app session
//	GET  /healthz
//
// Run with "go run mock_pcf.go [-listen :8080] [-record /artifacts/mock-pcf/requests.jsonl]".
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const base = "/npcf-policyauthorization/v1/app-sessions"

type record struct {
	Time        string          `json:"time"`
	Method      string          `json:"method"`
	Path        string          `json:"path"`
	Proto       string          `json:"proto"`
	ContentType string          `json:"content_type"`
	Body        json.RawMessage `json:"body,omitempty"`
	Status      int             `json:"status"`
	ID          string          `json:"id,omitempty"`
}

type pcf struct {
	mu         sync.Mutex
	next       int
	sessions   map[string]json.RawMessage // id -> AppSessionContext
	records    []record
	failCreate bool
	file       *os.File
}

func (p *pcf) save(r record) {
	p.records = append(p.records, r)
	if p.file != nil {
		line, _ := json.Marshal(r)
		p.file.Write(append(line, '\n'))
	}
}

func problem(w http.ResponseWriter, status int, cause string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"status": status, "cause": cause})
}

func (p *pcf) serveN5(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	rec := record{Time: time.Now().UTC().Format(time.RFC3339Nano), Method: r.Method, Path: r.URL.Path, Proto: r.Proto,
		ContentType: r.Header.Get("Content-Type")}
	if json.Valid(body) {
		rec.Body = body
	}
	p.mu.Lock()
	defer func() { p.save(rec); p.mu.Unlock() }()
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, base), "/")
	parts := strings.Split(rest, "/")
	switch {
	case r.Method == http.MethodPost && rest == "":
		var ctx struct {
			AscReqData map[string]any `json:"ascReqData"`
		}
		if rec.ContentType != "application/json" || json.Unmarshal(body, &ctx) != nil || ctx.AscReqData == nil {
			rec.Status = 400
			problem(w, 400, "INVALID_MSG_FORMAT")
			return
		}
		if p.failCreate {
			rec.Status = 503
			problem(w, 503, "NF_CONGESTION")
			return
		}
		p.next++
		id := fmt.Sprintf("app-%d", p.next)
		p.sessions[id] = body
		rec.Status, rec.ID = 201, id
		w.Header().Set("Location", "http://"+r.Host+base+"/"+id)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write(body)
	case r.Method == http.MethodPatch && len(parts) == 1:
		rec.ID = parts[0]
		if _, ok := p.sessions[parts[0]]; !ok {
			rec.Status = 404
			problem(w, 404, "APPLICATION_SESSION_CONTEXT_NOT_FOUND")
			return
		}
		if rec.ContentType != "application/merge-patch+json" || !json.Valid(body) {
			rec.Status = 400
			problem(w, 400, "INVALID_MSG_FORMAT")
			return
		}
		rec.Status = 200
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(p.sessions[parts[0]])
	case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "delete":
		rec.ID = parts[0]
		if _, ok := p.sessions[parts[0]]; !ok {
			rec.Status = 404
			problem(w, 404, "APPLICATION_SESSION_CONTEXT_NOT_FOUND")
			return
		}
		delete(p.sessions, parts[0])
		rec.Status = 204
		w.WriteHeader(204)
	default:
		rec.Status = 404
		problem(w, 404, "RESOURCE_URI_STRUCTURE_NOT_FOUND")
	}
}

func (p *pcf) serveMock(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/mock/requests":
		p.mu.Lock()
		defer p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(p.records)
	case "/mock/config":
		var c struct {
			FailCreate bool `json:"fail_create"`
		}
		json.NewDecoder(r.Body).Decode(&c)
		p.mu.Lock()
		p.failCreate = c.FailCreate
		p.mu.Unlock()
		w.WriteHeader(204)
	case "/mock/notify":
		var n struct {
			ID   string          `json:"id"`
			Kind string          `json:"kind"`
			Body json.RawMessage `json:"body"`
		}
		json.NewDecoder(r.Body).Decode(&n)
		p.mu.Lock()
		ctx, ok := p.sessions[n.ID]
		p.mu.Unlock()
		if !ok {
			http.Error(w, "unknown app session", 404)
			return
		}
		var c struct {
			AscReqData struct {
				NotifURI string `json:"notifUri"`
			} `json:"ascReqData"`
		}
		json.Unmarshal(ctx, &c)
		// The AF's receiver is HTTP/1.1 (TS 29.500 requires HTTP/2; see the AF docs).
		client := http.Client{Timeout: 3 * time.Second}
		resp, err := client.Post(c.AscReqData.NotifURI+"/"+n.Kind, "application/json", bytes.NewReader(n.Body))
		status := 0
		if err == nil {
			status = resp.StatusCode
			resp.Body.Close()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": status, "uri": c.AscReqData.NotifURI + "/" + n.Kind,
			"error": fmt.Sprint(err)})
	default:
		http.NotFound(w, r)
	}
}

func main() {
	listen := flag.String("listen", ":8080", "listen address")
	recordPath := flag.String("record", "", "append each request as a JSON line to this file")
	flag.Parse()
	p := &pcf{sessions: map[string]json.RawMessage{}}
	if *recordPath != "" {
		os.MkdirAll(filepath.Dir(*recordPath), 0o755)
		f, err := os.OpenFile(*recordPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatal(err)
		}
		p.file = f
	}
	mux := http.NewServeMux()
	mux.HandleFunc(base, p.serveN5)
	mux.HandleFunc(base+"/", p.serveN5)
	mux.HandleFunc("/mock/", p.serveMock)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	server := &http.Server{Addr: *listen, Handler: mux, Protocols: new(http.Protocols)}
	server.Protocols.SetHTTP1(true)
	server.Protocols.SetUnencryptedHTTP2(true)
	log.Printf("mock PCF on %s (HTTP/1.1 and h2c prior knowledge)", *listen)
	log.Fatal(server.ListenAndServe())
}
