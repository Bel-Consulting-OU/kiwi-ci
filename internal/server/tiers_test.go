package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// runnerTokenServer builds a persistent server with distinct runner and
// admin tokens (legacy token mode: no store principals).
func runnerTokenServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRunnerTokenBlockedFromGeneralArtifactReads(t *testing.T) {
	s := runnerTokenServer(t)
	// Seed a run with an artifact record via the admin token.
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "admin-tok", `{"repo_url":"https://github.com/kiwi/repo.git","ref":"main","pipeline":`+jsonString(testPipeline)+`}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	var run modelRunID
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.artifacts["art1"] = model.ArtifactRecord{ID: "art1", RunID: run.ID, Name: "bin", SHA256: "a", Path: "", CreatedAt: time.Now().UTC()}
	s.mu.Unlock()

	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/runs/" + run.ID + "/artifacts"},
		{http.MethodGet, "/api/v1/artifacts/art1"},
		{http.MethodGet, "/api/v1/artifacts/art1/provenance"},
		{http.MethodGet, "/api/v1/runs/" + run.ID},
		{http.MethodGet, "/api/v1/runs/" + run.ID + "/jobs"},
	} {
		// The runner bearer token must not read general artifact/run data.
		if w := doJSON(t, s, tc.method, tc.path, "runner-tok", ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("runner token on %s %s: want 401 got %d: %s", tc.method, tc.path, w.Code, w.Body.String())
		}
		// The admin token keeps working (artifact byte paths may 404 when
		// the record has no backing bytes, but never 401/403).
		if w := doJSON(t, s, tc.method, tc.path, "admin-tok", ""); w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
			t.Fatalf("admin token on %s %s: got %d: %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
}

func TestRunnerTokenOnDependencyDownloadWithLease(t *testing.T) {
	s := runnerTokenServer(t)
	// Full producer/consumer flow with the runner-tier routes carrying the
	// runner token and the control-plane routes carrying the admin token.
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "admin-tok", `{"repo_url":"https://github.com/kiwi/repo.git","ref":"main","pipeline":`+jsonString(producerPipeline)+`}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	if w = doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "runner-tok", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2}`); w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var reg struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil {
		t.Fatal(err)
	}
	runnerID := reg.ID
	// Lease the producer (build) with the runner token.
	if w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "runner-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("build lease: %d %s", w.Code, w.Body.String())
	}
	buildID, buildHdrs := seedRunningJob(t, s, "build", runnerID, "build-token")
	if w = doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+buildID+"/artifacts/bin", "runner-tok", "the-binary", buildHdrs); w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	complete := `{"runner_id":` + jsonString(runnerID) + `,"lease_token":` + jsonString("build-token") + `,"lease_generation":1,"status":"success"}`
	if w = doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+buildID+"/complete", "runner-tok", complete); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	// Lease the consumer with the runner token and download the dependency.
	if w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "runner-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("consumer lease: %d %s", w.Code, w.Body.String())
	}
	var consumerTask Task
	if err := json.Unmarshal(w.Body.Bytes(), &consumerTask); err != nil {
		t.Fatal(err)
	}
	if consumerTask.Job.Key != "consume" {
		t.Fatalf("leased %q, want consume", consumerTask.Job.Key)
	}
	chdrs := leaseHeaders(consumerTask, runnerID)
	dl := "/api/v1/jobs/" + consumerTask.Job.ID + "/dependencies/build/bin"
	if w = doJSONHeaders(t, s, http.MethodGet, dl, "runner-tok", "", chdrs); w.Code != http.StatusOK {
		t.Fatalf("dependency download with runner token + lease: want 200 got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "the-binary" {
		t.Fatalf("downloaded bytes = %q", w.Body.String())
	}
	// The same route without the runner bearer is rejected by the tier.
	if w = doJSONHeaders(t, s, http.MethodGet, dl, "", "", chdrs); w.Code != http.StatusUnauthorized {
		t.Fatalf("dependency download without runner token: want 401 got %d", w.Code)
	}
	// Without a valid lease the handler rejects even with the runner token.
	bad := map[string]string{"X-Kiwi-Runner-ID": runnerID, "X-Kiwi-Lease-Token": "wrong", "X-Kiwi-Lease-Generation": fmt.Sprint(consumerTask.LeaseGeneration)}
	if w = doJSONHeaders(t, s, http.MethodGet, dl, "runner-tok", "", bad); w.Code != http.StatusConflict {
		t.Fatalf("dependency download with bad lease: want 409 got %d", w.Code)
	}
}
