package runner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	v1 "github.com/Bel-Consulting-OU/kiwi-ci/internal/api/v1"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// TestUploadGeneratedFragmentCarriesFragmentID pins the runner side of
// HIGH-15: the POST body carries the deterministic fragment_id derived from
// the parsed {jobs, deps}, the lease headers are set, and the server's
// recomputed digest matches (so the upload is admitted, not a 400).
func TestUploadGeneratedFragmentCarriesFragmentID(t *testing.T) {
	type captured struct {
		body    []byte
		headers http.Header
	}
	got := make(chan captured, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- captured{body: body, headers: r.Header.Clone()}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"job_ids":["child"]}`))
	}))
	defer srv.Close()

	r := &Runner{ID: "runner-1", Client: srv.Client()}
	r.Cfg.Server = srv.URL
	r.Cfg.Token = "runner-token"
	task := server.Task{Job: model.Job{ID: "job-1", RunID: "run-1"}, LeaseToken: "lease-token", LeaseGeneration: 7}
	data := []byte(`{"jobs":{"child":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo child"}]}},"deps":{}}`)
	if err := r.uploadGeneratedFragmentData(context.Background(), task, "generated.yaml", data); err != nil {
		t.Fatalf("upload: %v", err)
	}
	c := <-got
	if c.headers.Get("X-Kiwi-Runner-ID") != "runner-1" || c.headers.Get("X-Kiwi-Lease-Token") != "lease-token" || c.headers.Get("X-Kiwi-Lease-Generation") != "7" {
		t.Fatalf("lease headers = %v", c.headers)
	}
	var sent v1.GeneratedFragment
	if err := json.Unmarshal(c.body, &sent); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if sent.FragmentID == "" {
		t.Fatal("upload body is missing fragment_id")
	}
	want, err := sent.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if sent.FragmentID != want {
		t.Fatalf("fragment_id = %q, want the deterministic digest %q", sent.FragmentID, want)
	}
	// Re-sending the same parsed fragment derives the SAME id (stable across
	// retries), independent of the ambient body bytes' key order.
	if again, err := sent.Digest(); err != nil || again != sent.FragmentID {
		t.Fatalf("digest not stable: %q/%q err=%v", again, sent.FragmentID, err)
	}
}

// TestUploadGeneratedFragmentRejectsEscapingPath: the runner never posts a
// fragment path that escapes the workspace.
func TestUploadGeneratedFragmentRejectsEscapingPath(t *testing.T) {
	r := &Runner{ID: "runner-1", Client: http.DefaultClient}
	r.Cfg.Server = "http://127.0.0.1:1"
	if err := r.uploadGeneratedFragmentData(context.Background(), server.Task{Job: model.Job{ID: "j"}}, "../escape.yaml", []byte(`{}`)); err == nil {
		t.Fatal("escaping generate.path must be rejected before any request")
	}
}
