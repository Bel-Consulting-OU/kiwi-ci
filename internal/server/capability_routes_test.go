package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// capabilityRepoKey renders the explicit ACL spelling of a repository grant,
// the form operators write in a token file.
func capabilityRepoKey(t *testing.T, legacy string) string {
	t.Helper()
	grant, err := auth.ParseRepoGrant(legacy)
	if err != nil {
		t.Fatal(err)
	}
	return grant.Serialized()
}

// capabilityServer builds a persistent server with controller principals in
// its AuthStore and one queued run per repository (repo-a, repo-b).
func capabilityServer(t *testing.T) (*Server, model.Run, model.Run) {
	t.Helper()
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]auth.Principal{
		"events-a": {Subject: "faktor", RepositoryCapabilities: map[string][]auth.Capability{
			capabilityRepoKey(t, "github.com/acme/repo-a"): {auth.CapExecutionEventsRead},
		}},
		"events-b": {Subject: "faktor-b", RepositoryCapabilities: map[string][]auth.Capability{
			capabilityRepoKey(t, "github.com/acme/repo-b"): {auth.CapExecutionEventsRead},
		}},
		"global-events":   {Subject: "feed", Capabilities: []auth.Capability{auth.CapExecutionEventsRead}},
		"global-evidence": {Subject: "auditor", Capabilities: []auth.Capability{auth.CapEvidenceRead}},
		"repo-evidence": {Subject: "auditor-a", RepositoryCapabilities: map[string][]auth.Capability{
			capabilityRepoKey(t, "github.com/acme/repo-a"): {auth.CapEvidenceRead},
		}},
		"checkpoints-a": {Subject: "replayer", RepositoryCapabilities: map[string][]auth.Capability{
			capabilityRepoKey(t, "github.com/acme/repo-a"): {auth.CapCheckpointsRead},
		}},
		"canceller-a": {Subject: "canceller", RepositoryCapabilities: map[string][]auth.Capability{
			capabilityRepoKey(t, "github.com/acme/repo-a"): {auth.CapRunsCancel},
		}},
		"canceller-b": {Subject: "canceller-b", RepositoryCapabilities: map[string][]auth.Capability{
			capabilityRepoKey(t, "github.com/acme/repo-b"): {auth.CapRunsCancel},
		}},
		"graph-only": {Subject: "graph", Capabilities: []auth.Capability{auth.CapGraphMutationsWrite}},
		"reader-a": {Subject: "reader", Repositories: map[string]auth.RepositoryPermission{
			capabilityRepoKey(t, "github.com/acme/repo-a"): {Read: true},
		}},
		"read-role": {Subject: "global-reader", Roles: []auth.Role{auth.RoleRead}},
	}
	for raw, p := range keys {
		if err := s.AuthStore.AddToken(raw, p); err != nil {
			t.Fatalf("AddToken(%s): %v", raw, err)
		}
	}
	ctx := context.Background()
	runA, err := s.enqueue(ctx, SubmitRun{
		RepoURL: "https://github.com/acme/repo-a.git", RepoFullName: "acme/repo-a",
		Ref: "refs/heads/main", Event: "push", Pipeline: testPipeline,
	})
	if err != nil {
		t.Fatal(err)
	}
	runB, err := s.enqueue(ctx, SubmitRun{
		RepoURL: "https://github.com/acme/repo-b.git", RepoFullName: "acme/repo-b",
		Ref: "refs/heads/main", Event: "push", Pipeline: testPipeline,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := repoIDForRun(runA); got != "github.com/acme/repo-a" {
		t.Fatalf("run-a canonical repo = %q", got)
	}
	if got := repoIDForRun(runB); got != "github.com/acme/repo-b" {
		t.Fatalf("run-b canonical repo = %q", got)
	}
	return s, runA, runB
}

// seedSnapshot stages one snapshot record plus its archive bytes for the run,
// so the download handler can serve a verified stream.
func seedSnapshot(t *testing.T, s *Server, run model.Run) (sid string, archivePath string) {
	t.Helper()
	body := []byte("snapshot-bytes")
	path := filepath.Join(t.TempDir(), "snap.gz")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	sid = "snap-" + run.ID
	s.mu.Lock()
	s.snapshots[sid] = model.SnapshotRecord{
		ID: sid, RunID: run.ID, Path: path, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:]),
	}
	s.mu.Unlock()
	return sid, path
}

// jobIDForRun returns one job ID of the run from the in-memory state.
func jobIDForRun(t *testing.T, s *Server, runID string) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, j := range s.jobs {
		if j.RunID == runID {
			return id
		}
	}
	t.Fatalf("no job for run %s", runID)
	return ""
}

// TestControllerCapabilityEventScope pins the execution.events:read scope on
// the cursor-pull list: a repository-scoped controller reads runs in its
// repository, is denied another repository and the unscoped cursor; a global
// grant reads unscoped; a plain repository reader may read its own run's
// history but not the unscoped cursor; the runner bearer is refused.
func TestControllerCapabilityEventScope(t *testing.T) {
	s, runA, runB := capabilityServer(t)
	cases := []struct {
		name, token, path string
		want              int
	}{
		{"repo-scoped capability reads its run", "events-a", "/api/v1/events?run_id=" + runA.ID, http.StatusOK},
		{"repo-scoped capability denied another repo", "events-a", "/api/v1/events?run_id=" + runB.ID, http.StatusForbidden},
		{"repo-scoped capability denied unscoped", "events-a", "/api/v1/events", http.StatusForbidden},
		{"global capability reads unscoped", "global-events", "/api/v1/events", http.StatusOK},
		{"global capability reads any run", "global-events", "/api/v1/events?run_id=" + runB.ID, http.StatusOK},
		{"repo reader reads its own run history", "reader-a", "/api/v1/events?run_id=" + runA.ID, http.StatusOK},
		{"repo reader denied another repo", "reader-a", "/api/v1/events?run_id=" + runB.ID, http.StatusForbidden},
		{"repo reader denied unscoped", "reader-a", "/api/v1/events", http.StatusForbidden},
		{"global read role denied unscoped without capability", "read-role", "/api/v1/events", http.StatusForbidden},
		{"unrelated capability denied", "graph-only", "/api/v1/events", http.StatusForbidden},
		{"unknown run denied without global capability", "events-a", "/api/v1/events?run_id=missing", http.StatusForbidden},
		{"unknown run allowed with global capability", "global-events", "/api/v1/events?run_id=missing", http.StatusOK},
		{"admin token unchanged", "admin-tok", "/api/v1/events", http.StatusOK},
		{"runner bearer refused", "runner-tok", "/api/v1/events", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		if w := doJSON(t, s, http.MethodGet, tc.path, tc.token, ""); w.Code != tc.want {
			t.Errorf("%s: GET %s with %s = %d, want %d: %s", tc.name, tc.path, tc.token, w.Code, tc.want, w.Body.String())
		}
	}
	// The scoped read returns only the addressed run's events.
	w := doJSON(t, s, http.MethodGet, "/api/v1/events?run_id="+runA.ID+"&limit=1000", "events-a", "")
	if w.Code != http.StatusOK {
		t.Fatalf("scoped events = %d: %s", w.Code, w.Body.String())
	}
	for _, e := range decodeEventsResponse(t, w.Body.Bytes()).Events {
		if e.RunID != runA.ID {
			t.Fatalf("scoped read leaked run %q: %+v", e.RunID, e)
		}
	}
}

// TestControllerCapabilityAuditScope pins evidence:read on the audit trail:
// the trail spans every repository, so only a GLOBAL evidence:read (or
// admin) passes; a repository-scoped grant reaches the handler and is
// answered 403.
func TestControllerCapabilityAuditScope(t *testing.T) {
	s, _, _ := capabilityServer(t)
	cases := []struct {
		name, token string
		want        int
	}{
		{"global evidence reads the trail", "global-evidence", http.StatusOK},
		{"repo-scoped evidence denied (global scope required)", "repo-evidence", http.StatusForbidden},
		{"events capability denied", "events-a", http.StatusForbidden},
		{"reserved graph capability denied", "graph-only", http.StatusForbidden},
		{"admin token unchanged", "admin-tok", http.StatusOK},
		{"runner bearer refused", "runner-tok", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		if w := doJSON(t, s, http.MethodGet, "/api/v1/audit", tc.token, ""); w.Code != tc.want {
			t.Errorf("%s: audit with %s = %d, want %d: %s", tc.name, tc.token, w.Code, tc.want, w.Body.String())
		}
	}
}

// TestControllerCapabilitySnapshotAndPipelineScope pins checkpoints:read on
// the snapshot surface and evidence:read on the exact-replay pipeline export,
// both run-scoped: a capability held for repo-a covers run-a's routes and is
// denied on run-b's; a plain reader and a different capability class are
// denied.
func TestControllerCapabilitySnapshotAndPipelineScope(t *testing.T) {
	s, runA, runB := capabilityServer(t)
	sidA, _ := seedSnapshot(t, s, runA)
	sidB, _ := seedSnapshot(t, s, runB)
	jobA := jobIDForRun(t, s, runA.ID)
	jobB := jobIDForRun(t, s, runB.ID)

	cases := []struct {
		name, token, path string
		want              int
	}{
		{"checkpoints reads its run listing", "checkpoints-a", "/api/v1/runs/" + runA.ID + "/snapshots", http.StatusOK},
		{"checkpoints denied another run listing", "checkpoints-a", "/api/v1/runs/" + runB.ID + "/snapshots", http.StatusForbidden},
		{"checkpoints downloads its run archive", "checkpoints-a", "/api/v1/runs/" + runA.ID + "/snapshots/" + sidA, http.StatusOK},
		{"checkpoints downloads another run archive", "checkpoints-a", "/api/v1/runs/" + runB.ID + "/snapshots/" + sidB, http.StatusForbidden},
		{"repo reader denied snapshots", "reader-a", "/api/v1/runs/" + runA.ID + "/snapshots", http.StatusForbidden},
		{"evidence capability denied snapshots", "repo-evidence", "/api/v1/runs/" + runA.ID + "/snapshots", http.StatusForbidden},
		{"repo-scoped evidence exports its run pipeline", "repo-evidence", "/api/v1/runs/" + runA.ID + "/jobs/" + jobA + "/pipeline", http.StatusOK},
		{"repo-scoped evidence denied another run pipeline", "repo-evidence", "/api/v1/runs/" + runB.ID + "/jobs/" + jobB + "/pipeline", http.StatusForbidden},
		{"checkpoints capability denied pipeline export", "checkpoints-a", "/api/v1/runs/" + runA.ID + "/jobs/" + jobA + "/pipeline", http.StatusForbidden},
		{"repo reader denied pipeline export", "reader-a", "/api/v1/runs/" + runA.ID + "/jobs/" + jobA + "/pipeline", http.StatusForbidden},
		{"admin token unchanged list", "admin-tok", "/api/v1/runs/" + runA.ID + "/snapshots", http.StatusOK},
		{"admin token unchanged pipeline", "admin-tok", "/api/v1/runs/" + runA.ID + "/jobs/" + jobA + "/pipeline", http.StatusOK},
		{"runner bearer refused snapshots", "runner-tok", "/api/v1/runs/" + runA.ID + "/snapshots", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		if w := doJSON(t, s, http.MethodGet, tc.path, tc.token, ""); w.Code != tc.want {
			t.Errorf("%s: GET %s with %s = %d, want %d: %s", tc.name, tc.path, tc.token, w.Code, tc.want, w.Body.String())
		}
	}
}

// TestControllerCapabilityCancelScope pins runs:cancel: the capability
// cancels a run in its own repository and is denied another repository's run,
// while the existing ActionCancel role path is untouched and the runner
// bearer never reaches the handler.
func TestControllerCapabilityCancelScope(t *testing.T) {
	s, runA, runB := capabilityServer(t)
	cases := []struct {
		name, token, run string
		want             int
	}{
		{"capability denied another repo's run", "canceller-a", runB.ID, http.StatusForbidden},
		{"capability cancels its own run", "canceller-a", runA.ID, http.StatusOK},
		{"capability cancels its own run on the other repo", "canceller-b", runB.ID, http.StatusOK},
		{"runner bearer refused", "runner-tok", runA.ID, http.StatusUnauthorized},
		{"repo reader denied cancel", "reader-a", runB.ID, http.StatusForbidden},
		{"events capability denied cancel", "events-a", runB.ID, http.StatusForbidden},
	}
	for _, tc := range cases {
		if w := doJSON(t, s, http.MethodPost, "/api/v1/runs/"+tc.run+"/cancel", tc.token, ""); w.Code != tc.want {
			t.Errorf("%s: cancel %s with %s = %d, want %d: %s", tc.name, tc.run, tc.token, w.Code, tc.want, w.Body.String())
		}
	}
	s.mu.Lock()
	statusA := s.runs[runA.ID].Status
	statusB := s.runs[runB.ID].Status
	s.mu.Unlock()
	if statusA != model.StatusCancelled || statusB != model.StatusCancelled {
		t.Fatalf("cancelled run statuses = %q/%q, want both cancelled", statusA, statusB)
	}
}

// TestControllerCapabilityStreamScope pins the SSE wrapper to the same scope
// as the cursor-pull list: a repository-scoped controller streams its own
// run's events and is denied another repository and the unscoped stream
// before any byte of the stream is committed.
func TestControllerCapabilityStreamScope(t *testing.T) {
	s, runA, runB := capabilityServer(t)
	// Denials are answered before streaming begins and can be observed with
	// a recorder.
	for _, tc := range []struct {
		name, token, path string
		want              int
	}{
		{"scoped controller denied another repo stream", "events-a", "/api/v1/events/stream?run_id=" + runB.ID, http.StatusForbidden},
		{"scoped controller denied unscoped stream", "events-a", "/api/v1/events/stream", http.StatusForbidden},
		{"repo reader denied another repo stream", "reader-a", "/api/v1/events/stream?run_id=" + runB.ID, http.StatusForbidden},
		{"runner bearer refused", "runner-tok", "/api/v1/events/stream", http.StatusUnauthorized},
	} {
		if w := doJSON(t, s, http.MethodGet, tc.path, tc.token, ""); w.Code != tc.want {
			t.Errorf("%s: GET %s with %s = %d, want %d", tc.name, tc.path, tc.token, w.Code, tc.want)
		}
	}

	// The allowed stream really streams: run-a's queued events arrive.
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	frames := startStream(t, ctx, srv.URL+"/api/v1/events/stream?run_id="+runA.ID, "events-a")
	expectEventFrame(t, frames, 1)
	cancel()

	// An admin token streams unscoped (unchanged behavior).
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	adminFrames := startStream(t, ctx2, srv.URL+"/api/v1/events/stream", "admin-tok")
	expectEventFrame(t, adminFrames, 1)
	cancel2()
}
