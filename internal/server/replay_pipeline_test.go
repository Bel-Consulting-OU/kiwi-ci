package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// replayUploadMemory uploads one archive under a memory-mode lease.
func replayUploadMemory(t *testing.T, s *Server, c *testClient, jobID, runnerID, token string, gen int64) model.SnapshotRecord {
	t.Helper()
	body := fcSnapshotArchive(t)
	headers := map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      token,
		"X-Kiwi-Lease-Generation": strconv.FormatInt(gen, 10),
		"Content-Type":            "application/gzip",
	}
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", body, headers)
	if w.Code != http.StatusCreated {
		t.Fatalf("snapshot upload = %d: %s", w.Code, w.Body.String())
	}
	var rec model.SnapshotRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// TestSnapshotUploadStampsAttemptIdentityMemory: the snapshot record carries
// the lease generation it was uploaded under and the job's attempt counter,
// so a retried job has addressable per-attempt snapshots.
func TestSnapshotUploadStampsAttemptIdentityMemory(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "secret")
	runID, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)
	s.mu.Lock()
	j := s.jobs[jobID]
	j.Attempts = 3
	s.jobs[jobID] = j
	s.mu.Unlock()

	rec := replayUploadMemory(t, s, c, jobID, runnerID, token, gen)
	if rec.LeaseGeneration != gen {
		t.Fatalf("record lease generation = %d, want %d", rec.LeaseGeneration, gen)
	}
	if rec.Attempts != 3 {
		t.Fatalf("record attempts = %d, want 3", rec.Attempts)
	}
	w := c.do(http.MethodGet, "/api/v1/runs/"+runID+"/snapshots", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list snapshots = %d: %s", w.Code, w.Body.String())
	}
	var listed []model.SnapshotRecord
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].LeaseGeneration != gen || listed[0].Attempts != 3 {
		t.Fatalf("listed records = %+v", listed)
	}
}

// TestSnapshotUploadStampsAttemptIdentityDB is the DB/CAS counterpart: the
// record persisted through SnapshotStore/InsertSnapshotForLease carries the
// same attempt identity.
func TestSnapshotUploadStampsAttemptIdentityDB(t *testing.T) {
	f := newDBFakeStore()
	_, runnerID, jobID, task, c := snapshotCASServer(t, f, t.TempDir())
	runID := task.Job.RunID
	f.mu.Lock()
	j := f.jobs[jobID]
	j.Attempts = 2
	f.jobs[jobID] = j
	f.mu.Unlock()

	w := uploadSnapshotCAS(t, c, jobID, runnerID, task, fcSnapshotArchive(t))
	if w.Code != http.StatusCreated {
		t.Fatalf("snapshot upload = %d: %s", w.Code, w.Body.String())
	}
	var rec model.SnapshotRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.LeaseGeneration != task.LeaseGeneration || rec.Attempts != 2 {
		t.Fatalf("uploaded record = generation %d attempts %d, want %d/2", rec.LeaseGeneration, rec.Attempts, task.LeaseGeneration)
	}
	stored, found, err := f.GetSnapshot(t.Context(), runID, rec.ID)
	if err != nil || !found {
		t.Fatalf("stored record = found %t err %v", found, err)
	}
	if stored.LeaseGeneration != task.LeaseGeneration || stored.Attempts != 2 {
		t.Fatalf("stored record = generation %d attempts %d, want %d/2", stored.LeaseGeneration, stored.Attempts, task.LeaseGeneration)
	}
}

// assertExportedPipeline checks the export body against the persisted job and
// proves the exported text/payload pair re-verifies with the shared verifier
// (the endpoint hands out exactly what the runner executed).
func assertExportedPipeline(t *testing.T, w *httptest.ResponseRecorder, j model.Job) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("pipeline export = %d: %s", w.Code, w.Body.String())
	}
	var got runJobPipeline
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.RunID != j.RunID || got.JobID != j.ID || got.Key != j.Key {
		t.Fatalf("export identity = run %q job %q key %q, want run %q job %q key %q", got.RunID, got.JobID, got.Key, j.RunID, j.ID, j.Key)
	}
	if got.Pipeline != j.Pipeline || got.Pipeline == "" {
		t.Fatalf("export pipeline = %q, want the persisted %q", got.Pipeline, j.Pipeline)
	}
	if got.LeaseGeneration != j.LeaseGeneration || got.Attempts != j.Attempts {
		t.Fatalf("export attempt identity = gen %d attempts %d, want %d/%d", got.LeaseGeneration, got.Attempts, j.LeaseGeneration, j.Attempts)
	}
	// The persisted execution state the replay materializer consumes must be
	// exported exactly; without it exact replay cannot derive the effective
	// network/sandbox/resource restrictions.
	wantPersisted := persistedJobForExport(j)
	if !reflect.DeepEqual(got.PersistedJob, wantPersisted) {
		t.Fatalf("export persisted job = %+v, want %+v", got.PersistedJob, wantPersisted)
	}
	if j.CompiledJobPayload != nil {
		if got.CompiledJobPayload == nil || got.CompiledJobPayload.PipelineDigest != j.CompiledJobPayload.PipelineDigest {
			t.Fatalf("export payload = %+v, want the persisted payload", got.CompiledJobPayload)
		}
		spec, err := pipeline.Parse([]byte(got.Pipeline))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pipeline.VerifyCompiledJobBinding(spec, j.Key, got.CompiledJobPayload); err != nil {
			t.Fatalf("exported pair does not re-verify: %v", err)
		}
	}
}

// TestExportRunJobPipelineRequiresAdminMemory pins the export endpoint's tier
// in memory mode: non-admins are rejected, the admin token gets the persisted
// pipeline text and payload, and a key (not just a job ID) addresses the job.
func TestExportRunJobPipelineRequiresAdminMemory(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "secret")
	runID, jobID, _, _, _ := leaseNativeJob(t, c, testPipeline)
	s.mu.Lock()
	j := s.jobs[jobID]
	s.mu.Unlock()

	snapAdminAuthzToken(t, s, "pipe-reader", auth.Principal{
		Subject: "reader",
		Roles:   []auth.Role{auth.RoleRead},
	})
	path := "/api/v1/runs/" + runID + "/jobs/" + jobID + "/pipeline"
	// The route is admin tier: a non-admin principal is rejected before (or
	// by) the handler's requireRunAdmin.
	if w := doJSON(t, s, http.MethodGet, path, "pipe-reader", ""); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("reader export = %d, want 401/403: %s", w.Code, w.Body.String())
	}
	assertExportedPipeline(t, doJSON(t, s, http.MethodGet, path, "secret", ""), j)
	assertExportedPipeline(t, doJSON(t, s, http.MethodGet, "/api/v1/runs/"+runID+"/jobs/"+j.Key+"/pipeline", "secret", ""), j)
	// Unknown job and cross-run references are 404, never another run's data.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/"+runID+"/jobs/nope/pipeline", "secret", ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown job = %d, want 404", w.Code)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/other-run/jobs/"+jobID+"/pipeline", "secret", ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown run = %d, want 404", w.Code)
	}
}

// TestExportRunJobPipelineDB is the DB-mode counterpart: the persisted text
// and payload are served from the store, the payload re-verifies, and a
// non-admin principal is rejected.
func TestExportRunJobPipelineDB(t *testing.T) {
	f := newDBFakeStore()
	s, _, jobID, task, _ := snapshotCASServer(t, f, t.TempDir())
	runID := task.Job.RunID
	j := task.Job

	snapAdminAuthzToken(t, s, "pipe-reader-db", auth.Principal{
		Subject: "reader",
		Roles:   []auth.Role{auth.RoleRead},
	})
	path := "/api/v1/runs/" + runID + "/jobs/" + jobID + "/pipeline"
	if w := doJSON(t, s, http.MethodGet, path, "pipe-reader-db", ""); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("reader export = %d, want 401/403: %s", w.Code, w.Body.String())
	}
	assertExportedPipeline(t, doJSON(t, s, http.MethodGet, path, "token", ""), j)
	// DB key fallback: the job's declared key resolves through the run's job
	// list when GetJob misses.
	assertExportedPipeline(t, doJSON(t, s, http.MethodGet, "/api/v1/runs/"+runID+"/jobs/"+j.Key+"/pipeline", "token", ""), j)
}
