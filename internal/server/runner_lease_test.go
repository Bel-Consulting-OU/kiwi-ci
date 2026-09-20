package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// pkiLeaseRequest issues one runner-tier request with the runner bearer,
// the lease identity headers and an optional TLS peer certificate.
func pkiLeaseRequest(t *testing.T, h http.Handler, method, path string, body []byte, bearer, runnerID, token string, generation int64, peer *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("X-Kiwi-Runner-ID", runnerID)
	req.Header.Set("X-Kiwi-Lease-Token", token)
	req.Header.Set("X-Kiwi-Lease-Generation", fmt.Sprintf("%d", generation))
	if peer != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// runnerLeaseTableServer builds an mTLS-enforced persistent server with a
// leased job held by runner-a under certA.
func runnerLeaseTableServer(t *testing.T) (*Server, http.Handler, Task, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewPersistent("runner-tok", "runner-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.RunnerCA = ca
	s.RequireRunnerClientCerts = true
	h := s.Handler()
	_, certA := pkiSignRunner(t, ca, "runner-a")
	_, certB := pkiSignRunner(t, ca, "runner-b")
	reg := map[string]any{"id": "runner-a", "name": "ra", "capacity": 2, "protocol_min": 3, "protocol_max": 3, "labels": []string{"container"}}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register", reg, "runner-tok", certA); w.Code != http.StatusOK {
		t.Fatalf("register runner-a: %d %s", w.Code, w.Body.String())
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: smokePipeline, Trusted: true,
	}); err != nil {
		t.Fatal(err)
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/runner-a/next", map[string]any{}, "runner-tok", certA); w.Code != http.StatusOK {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	} else {
		var task Task
		if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
			t.Fatal(err)
		}
		return s, h, task, certA, certB
	}
	return s, h, Task{}, certA, certB
}

// TestAuthorizeRunnerLeaseAdoptionTable verifies that every runner endpoint
// authorized through authorizeRunnerLease rejects a certificate identity
// mismatch with the SAME 403 and a stale lease with the SAME 409.
func TestAuthorizeRunnerLeaseAdoptionTable(t *testing.T) {
	s, h, task, certA, certB := runnerLeaseTableServer(t)
	jobID := task.Job.ID
	rid := "runner-a"
	tok := task.LeaseToken
	gen := task.LeaseGeneration
	cacheKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	jsonBody := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	leaseBody := func(tok string, gen int64, extra map[string]any) []byte {
		m := map[string]any{"runner_id": rid, "lease_token": tok, "lease_generation": gen}
		for k, v := range extra {
			m[k] = v
		}
		return jsonBody(m)
	}
	ephemeral := base64.StdEncoding.EncodeToString(make([]byte, 32))

	endpoints := []struct {
		name        string
		method      string
		path        string
		headersOnly bool
		body        func(tok string, gen int64) []byte
	}{
		{"heartbeat", http.MethodPost, "/api/v1/jobs/" + jobID + "/heartbeat", false, func(tok string, gen int64) []byte { return leaseBody(tok, gen, nil) }},
		{"log", http.MethodPost, "/api/v1/jobs/" + jobID + "/log", false, func(tok string, gen int64) []byte { return leaseBody(tok, gen, map[string]any{"line": "hello"}) }},
		{"complete", http.MethodPost, "/api/v1/jobs/" + jobID + "/complete", false, func(tok string, gen int64) []byte { return leaseBody(tok, gen, map[string]any{"status": "success"}) }},
		{"secrets", http.MethodPost, "/api/v1/jobs/" + jobID + "/secrets", false, func(tok string, gen int64) []byte {
			return leaseBody(tok, gen, map[string]any{"name": "x", "ephemeral_public": ephemeral})
		}},
		{"tests", http.MethodPost, "/api/v1/jobs/" + jobID + "/tests", false, func(tok string, gen int64) []byte {
			return leaseBody(tok, gen, map[string]any{"report": map[string]any{}})
		}},
		{"snapshots", http.MethodPost, "/api/v1/jobs/" + jobID + "/snapshots", true, func(tok string, gen int64) []byte { return nil }},
		{"generated", http.MethodPost, "/api/v1/jobs/" + jobID + "/generated", true, func(tok string, gen int64) []byte { return []byte(`{}`) }},
		{"test-shards", http.MethodGet, "/api/v1/jobs/" + jobID + "/test-shards", true, func(tok string, gen int64) []byte { return nil }},
		{"artifact upload", http.MethodPut, "/api/v1/jobs/" + jobID + "/artifacts/bin", true, func(tok string, gen int64) []byte { return nil }},
		{"dependency download", http.MethodGet, "/api/v1/jobs/" + jobID + "/dependencies/build/bin", true, func(tok string, gen int64) []byte { return nil }},
		{"cache get", http.MethodGet, "/api/v1/jobs/" + jobID + "/cache/" + cacheKey, true, func(tok string, gen int64) []byte { return nil }},
		{"cache put", http.MethodPut, "/api/v1/jobs/" + jobID + "/cache/" + cacheKey, true, func(tok string, gen int64) []byte { return nil }},
	}

	for _, tc := range endpoints {
		t.Run(tc.name+"/cert-mismatch", func(t *testing.T) {
			w := pkiLeaseRequest(t, h, tc.method, tc.path, tc.body(tok, gen), "runner-tok", rid, tok, gen, certB)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s with wrong certificate: got %d, want 403 (%s)", tc.name, w.Code, w.Body.String())
			}
		})
		t.Run(tc.name+"/stale-lease", func(t *testing.T) {
			w := pkiLeaseRequest(t, h, tc.method, tc.path, tc.body("wrong-token", gen), "runner-tok", rid, "wrong-token", gen, certA)
			if w.Code != http.StatusConflict {
				t.Fatalf("%s with stale lease: got %d, want 409 (%s)", tc.name, w.Code, w.Body.String())
			}
		})
		t.Run(tc.name+"/generation-mismatch", func(t *testing.T) {
			w := pkiLeaseRequest(t, h, tc.method, tc.path, tc.body(tok, gen+7), "runner-tok", rid, tok, gen+7, certA)
			if w.Code != http.StatusConflict {
				t.Fatalf("%s with wrong generation: got %d, want 409 (%s)", tc.name, w.Code, w.Body.String())
			}
		})
	}

	// The authorized identity still works: the heartbeat succeeds with the
	// matching certificate, token and generation.
	if w := pkiLeaseRequest(t, h, http.MethodPost, "/api/v1/jobs/"+jobID+"/heartbeat", leaseBody(tok, gen, nil), "runner-tok", rid, tok, gen, certA); w.Code != http.StatusOK {
		t.Fatalf("authorized heartbeat: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	_ = s
}
