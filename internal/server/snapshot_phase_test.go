package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// uploadSnapshotPhaseMemory uploads one archive under a memory-mode lease
// with an explicit (or empty) phase header.
func uploadSnapshotPhaseMemory(t *testing.T, s *Server, c *testClient, jobID, runnerID, token string, gen int64, phase string) model.SnapshotRecord {
	t.Helper()
	headers := map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      token,
		"X-Kiwi-Lease-Generation": strconv.FormatInt(gen, 10),
		"Content-Type":            "application/gzip",
	}
	if phase != "" {
		headers["X-Kiwi-Snapshot-Phase"] = phase
	}
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", fcSnapshotArchive(t), headers)
	if w.Code != http.StatusCreated {
		t.Fatalf("snapshot upload = %d: %s", w.Code, w.Body.String())
	}
	var rec model.SnapshotRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// TestSnapshotUploadPhaseRoundTripMemory: a missing phase defaults to
// post_job (older runners), an explicit pre_job is stamped in the record and
// the listing, and an invalid phase is a 400 that commits nothing.
func TestSnapshotUploadPhaseRoundTripMemory(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "secret")
	runID, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)

	if rec := uploadSnapshotPhaseMemory(t, s, c, jobID, runnerID, token, gen, ""); rec.Phase != model.SnapshotPhasePostJob {
		t.Fatalf("default phase = %q, want post_job", rec.Phase)
	}
	if rec := uploadSnapshotPhaseMemory(t, s, c, jobID, runnerID, token, gen, model.SnapshotPhasePreJob); rec.Phase != model.SnapshotPhasePreJob {
		t.Fatalf("pre_job phase = %q", rec.Phase)
	}

	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", fcSnapshotArchive(t), map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      token,
		"X-Kiwi-Lease-Generation": strconv.FormatInt(gen, 10),
		"Content-Type":            "application/gzip",
		"X-Kiwi-Snapshot-Phase":   "sideways",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid phase = %d, want 400: %s", w.Code, w.Body.String())
	}
	if len(s.snapshots) != 2 {
		t.Fatalf("snapshot records = %d, want 2 (the invalid upload committed nothing)", len(s.snapshots))
	}

	list := c.do(http.MethodGet, "/api/v1/runs/"+runID+"/snapshots", nil, nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", list.Code, list.Body.String())
	}
	var listed []model.SnapshotRecord
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	phases := map[string]int{}
	for _, rec := range listed {
		phases[rec.Phase]++
	}
	if phases[model.SnapshotPhasePreJob] != 1 || phases[model.SnapshotPhasePostJob] != 1 {
		t.Fatalf("listed phases = %v, want one pre_job and one post_job", phases)
	}
}

// TestSnapshotUploadPhaseRoundTripDB is the DB/CAS counterpart: the phase is
// stamped on the record persisted through InsertSnapshotForLease, and an
// invalid phase is refused before anything is staged.
func TestSnapshotUploadPhaseRoundTripDB(t *testing.T) {
	f := newDBFakeStore()
	_, runnerID, jobID, task, c := snapshotCASServer(t, f, t.TempDir())
	runID := task.Job.RunID

	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", fcSnapshotArchive(t), map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      task.LeaseToken,
		"X-Kiwi-Lease-Generation": strconv.FormatInt(task.LeaseGeneration, 10),
		"Content-Type":            "application/gzip",
		"X-Kiwi-Snapshot-Phase":   model.SnapshotPhasePreJob,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("pre_job upload = %d: %s", w.Code, w.Body.String())
	}
	var rec model.SnapshotRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Phase != model.SnapshotPhasePreJob {
		t.Fatalf("response phase = %q, want pre_job", rec.Phase)
	}
	stored, found, err := f.GetSnapshot(t.Context(), runID, rec.ID)
	if err != nil || !found {
		t.Fatalf("stored record = found %t err %v", found, err)
	}
	if stored.Phase != model.SnapshotPhasePreJob {
		t.Fatalf("stored phase = %q, want pre_job", stored.Phase)
	}

	w = c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", fcSnapshotArchive(t), map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      task.LeaseToken,
		"X-Kiwi-Lease-Generation": strconv.FormatInt(task.LeaseGeneration, 10),
		"Content-Type":            "application/gzip",
		"X-Kiwi-Snapshot-Phase":   "nope",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid phase = %d, want 400: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	records := len(f.snapshots)
	f.mu.Unlock()
	if records != 1 {
		t.Fatalf("stored records = %d, want 1 (the invalid upload committed nothing)", records)
	}
}

// TestParseSnapshotPhase pins the accepted values and default.
func TestParseSnapshotPhase(t *testing.T) {
	for raw, want := range map[string]string{
		"":            model.SnapshotPhasePostJob,
		"post_job":    model.SnapshotPhasePostJob,
		"pre_job":     model.SnapshotPhasePreJob,
		"  pre_job\t": model.SnapshotPhasePreJob,
	} {
		got, err := parseSnapshotPhase(raw)
		if err != nil || got != want {
			t.Fatalf("parseSnapshotPhase(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	if _, err := parseSnapshotPhase("post"); err == nil {
		t.Fatal("invalid phase accepted")
	}
}
