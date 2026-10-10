package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// existenceMaskedBody is the exact wire bytes of the single masking response:
// every "no such run" and every hidden-run answer on the run-scoped endpoints
// must be byte-identical to this.
const existenceMaskedBody = "{\"error\":\"not found\"}\n"

// existenceLeakServer extends capabilityServer with the principals and
// records the masking matrix needs: a run in repo-a and a run in repo-b, one
// job each (capabilityServer enqueues them), one snapshot archive and one
// artifact each, plus repository-scoped capability variants on BOTH halves.
func existenceLeakServer(t *testing.T) (*Server, model.Run, model.Run) {
	t.Helper()
	s, runA, runB := capabilityServer(t)
	now := time.Now().UTC()
	for raw, p := range map[string]auth.Principal{
		"checkpoints-b": {Subject: "replayer-b", RepositoryCapabilities: map[string][]auth.Capability{
			capabilityRepoKey(t, "github.com/acme/repo-b"): {auth.CapCheckpointsRead},
		}},
		"evidence-b": {Subject: "auditor-b", RepositoryCapabilities: map[string][]auth.Capability{
			capabilityRepoKey(t, "github.com/acme/repo-b"): {auth.CapEvidenceRead},
		}},
		"artifact-a": {Subject: "artifact-a", Repositories: map[string]auth.RepositoryPermission{
			capabilityRepoKey(t, "github.com/acme/repo-a"): {Read: true, ArtifactRead: true},
		}},
		"reader-b": {Subject: "reader-b", Repositories: map[string]auth.RepositoryPermission{
			capabilityRepoKey(t, "github.com/acme/repo-b"): {Read: true},
		}},
	} {
		if err := s.AuthStore.AddToken(raw, p); err != nil {
			t.Fatalf("AddToken(%s): %v", raw, err)
		}
	}
	// One real artifact per run: the authorized download must stream, the
	// masked download must never touch these bytes.
	seedExistenceArtifact := func(id, runID, jobID, body string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), id+".tar.gz")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(body))
		s.mu.Lock()
		s.artifacts[id] = model.ArtifactRecord{
			ID: id, RunID: runID, JobID: jobID, Name: "bin", Path: path,
			Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:]), CreatedAt: now,
		}
		s.mu.Unlock()
	}
	seedExistenceArtifact("art-a", runA.ID, jobIDForRun(t, s, runA.ID), "artifact-bytes-a")
	seedExistenceArtifact("art-b", runB.ID, jobIDForRun(t, s, runB.ID), "artifact-bytes-b")
	seedSnapshot(t, s, runA)
	seedSnapshot(t, s, runB)
	// The log stream success control must not block for the default idle
	// window.
	s.LogStreamIdleTimeout = 5 * time.Millisecond
	return s, runA, runB
}

// existenceOutcome is one captured response with the per-request correlation
// id removed (it is minted per request by design and is not part of the
// existence surface).
type existenceOutcome struct {
	status int
	body   string
	header http.Header
}

func existenceCapture(t *testing.T, s *Server, method, path, token, body string) existenceOutcome {
	t.Helper()
	w := doJSON(t, s, method, path, token, body)
	h := w.Header().Clone()
	h.Del("X-Kiwi-Request-Id")
	return existenceOutcome{status: w.Code, body: w.Body.String(), header: h}
}

// existenceAssertIndistinguishable issues the foreign-addressed and the
// genuinely-missing request with the SAME method/token/logical address shape
// and fails unless status, body bytes and every response header (except the
// per-request correlation id) are identical.
func existenceAssertIndistinguishable(t *testing.T, s *Server, method, token, body, foreignPath, missingPath string) existenceOutcome {
	t.Helper()
	foreign := existenceCapture(t, s, method, foreignPath, token, body)
	missing := existenceCapture(t, s, method, missingPath, token, body)
	if foreign.status != missing.status || foreign.body != missing.body || !reflect.DeepEqual(foreign.header, missing.header) {
		t.Fatalf("existence leak: %s %s\n foreign(%s): %d %q %v\n missing(%s): %d %q %v",
			method, foreignPath, token, foreign.status, foreign.body, foreign.header,
			token, missing.status, missing.body, missing.header)
	}
	return foreign
}

// existenceAssertMasked additionally pins the shared answer to the masked 404
// and proves the body carries no run/job/artifact/snapshot metadata.
func existenceAssertMasked(t *testing.T, s *Server, method, token, body, foreignPath, missingPath string, secrets ...string) {
	t.Helper()
	got := existenceAssertIndistinguishable(t, s, method, token, body, foreignPath, missingPath)
	if got.status != http.StatusNotFound || got.body != existenceMaskedBody {
		t.Fatalf("%s %s with %s: want masked 404 %q, got %d %q", method, foreignPath, token, existenceMaskedBody, got.status, got.body)
	}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if strings.Contains(got.body, secret) {
			t.Fatalf("%s %s masked body leaked %q: %q", method, foreignPath, secret, got.body)
		}
	}
}

// TestExistenceMaskingReaderCannotDistinguish pins the core finding: a
// principal with read access to repo-a only must receive byte-identical
// answers for repo-b's run and an unknown run id on EVERY run-scoped
// endpoint, and must still be served (or refused per capability rules) on its
// own repository.
func TestExistenceMaskingReaderCannotDistinguish(t *testing.T) {
	s, runA, runB := existenceLeakServer(t)
	jobB := jobIDForRun(t, s, runB.ID)
	jobA := jobIDForRun(t, s, runA.ID)
	sidB := "snap-" + runB.ID
	sidA := "snap-" + runA.ID
	const missingRun = "run-existence-missing"
	secrets := []string{runB.ID, runA.ID, runB.RepoFullName, jobB, "art-b", sidB, "artifact-bytes", "snapshot-bytes"}

	// Each entry: the foreign address and the same logical address on an
	// unknown run id, both requested with the repo-a reader.
	type exposure struct {
		name        string
		method      string
		foreignPath string
		missingPath string
	}
	for _, tc := range []exposure{
		{"run get", http.MethodGet, "/api/v1/runs/" + runB.ID, "/api/v1/runs/" + missingRun},
		{"run jobs", http.MethodGet, "/api/v1/runs/" + runB.ID + "/jobs", "/api/v1/runs/" + missingRun + "/jobs"},
		{"run logs", http.MethodGet, "/api/v1/runs/" + runB.ID + "/logs", "/api/v1/runs/" + missingRun + "/logs"},
		{"run logs stream", http.MethodGet, "/api/v1/runs/" + runB.ID + "/logs/stream", "/api/v1/runs/" + missingRun + "/logs/stream"},
		{"run deployments", http.MethodGet, "/api/v1/runs/" + runB.ID + "/deployments", "/api/v1/runs/" + missingRun + "/deployments"},
		{"run tests", http.MethodGet, "/api/v1/runs/" + runB.ID + "/tests", "/api/v1/runs/" + missingRun + "/tests"},
		{"cancel", http.MethodPost, "/api/v1/runs/" + runB.ID + "/cancel", "/api/v1/runs/" + missingRun + "/cancel"},
		{"rerun", http.MethodPost, "/api/v1/runs/" + runB.ID + "/rerun", "/api/v1/runs/" + missingRun + "/rerun"},
		{"events run scope", http.MethodGet, "/api/v1/events?run_id=" + runB.ID, "/api/v1/events?run_id=" + missingRun},
	} {
		t.Run(tc.name, func(t *testing.T) {
			existenceAssertMasked(t, s, tc.method, "reader-a", "", tc.foreignPath, tc.missingPath, secrets...)
		})
	}

	// The handler-masked run-addressed subresources that require a positive
	// action/capability the reader lacks at the tier gate are still
	// indistinguishable (uniform 403 at the gate for both ids): the key is
	// equality, and the capability variants below pin the handler masking.
	for _, tc := range []exposure{
		{"run artifacts list", http.MethodGet, "/api/v1/runs/" + runB.ID + "/artifacts", "/api/v1/runs/" + missingRun + "/artifacts"},
		{"run snapshots list", http.MethodGet, "/api/v1/runs/" + runB.ID + "/snapshots", "/api/v1/runs/" + missingRun + "/snapshots"},
		{"snapshot download", http.MethodGet, "/api/v1/runs/" + runB.ID + "/snapshots/" + sidB, "/api/v1/runs/" + missingRun + "/snapshots/" + sidB},
		{"pipeline export", http.MethodGet, "/api/v1/runs/" + runB.ID + "/jobs/" + jobB + "/pipeline", "/api/v1/runs/" + missingRun + "/jobs/" + jobB + "/pipeline"},
		{"job attestation", http.MethodGet, "/api/v1/jobs/" + jobB + "/attestation", "/api/v1/jobs/job-existence-missing/attestation"},
		{"artifact download", http.MethodGet, "/api/v1/artifacts/art-b", "/api/v1/artifacts/art-existence-missing"},
		{"artifact provenance", http.MethodGet, "/api/v1/artifacts/art-b/provenance", "/api/v1/artifacts/art-existence-missing/provenance"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			existenceAssertIndistinguishable(t, s, tc.method, "reader-a", "", tc.foreignPath, tc.missingPath)
		})
	}

	// Own-repo controls: the reader is a live principal and its own
	// repository is still served (or refused only by the narrower
	// capability/action rule, which is not an existence leak).
	for _, tc := range []struct {
		name, method, path string
		want               int
	}{
		{"own run get", http.MethodGet, "/api/v1/runs/" + runA.ID, http.StatusOK},
		{"own run jobs", http.MethodGet, "/api/v1/runs/" + runA.ID + "/jobs", http.StatusOK},
		{"own run logs", http.MethodGet, "/api/v1/runs/" + runA.ID + "/logs", http.StatusOK},
		{"own run logs stream", http.MethodGet, "/api/v1/runs/" + runA.ID + "/logs/stream", http.StatusOK},
		{"own run deployments", http.MethodGet, "/api/v1/runs/" + runA.ID + "/deployments", http.StatusOK},
		{"own run tests", http.MethodGet, "/api/v1/runs/" + runA.ID + "/tests", http.StatusOK},
		{"own events run scope", http.MethodGet, "/api/v1/events?run_id=" + runA.ID, http.StatusOK},
		{"own artifacts list denied without artifact_read", http.MethodGet, "/api/v1/runs/" + runA.ID + "/artifacts", http.StatusForbidden},
		{"own artifact download denied without artifact_read", http.MethodGet, "/api/v1/artifacts/art-a", http.StatusForbidden},
		{"own snapshots denied without checkpoints:read", http.MethodGet, "/api/v1/runs/" + runA.ID + "/snapshots", http.StatusForbidden},
		{"own snapshot download denied without checkpoints:read", http.MethodGet, "/api/v1/runs/" + runA.ID + "/snapshots/" + sidA, http.StatusForbidden},
		{"own pipeline denied without evidence:read", http.MethodGet, "/api/v1/runs/" + runA.ID + "/jobs/" + jobA + "/pipeline", http.StatusForbidden},
		{"own cancel denied without cancel action", http.MethodPost, "/api/v1/runs/" + runA.ID + "/cancel", http.StatusForbidden},
		{"own rerun denied without rerun action", http.MethodPost, "/api/v1/runs/" + runA.ID + "/rerun", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if w := doJSON(t, s, tc.method, tc.path, "reader-a", ""); w.Code != tc.want {
				t.Fatalf("%s %s with reader-a = %d, want %d: %s", tc.method, tc.path, w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// TestExistenceMaskingCapabilityVariants pins the capability rules on both
// halves: a repository-scoped capability holder reaches the run its grant
// covers and is masked (never 403) on the other repository and on unknown
// ids; a plain reader of the covered repository keeps the existing 403 when
// the narrower capability is missing.
func TestExistenceMaskingCapabilityVariants(t *testing.T) {
	s, runA, runB := existenceLeakServer(t)
	jobA := jobIDForRun(t, s, runA.ID)
	jobB := jobIDForRun(t, s, runB.ID)
	sidA := "snap-" + runA.ID
	sidB := "snap-" + runB.ID
	const missingRun = "run-existence-missing"
	secrets := []string{runB.ID, runA.ID, runB.RepoFullName, jobB, "art-b", sidB, "artifact-bytes", "snapshot-bytes"}

	// checkpoints:read on repo-a and repo-b.
	existenceAssertMasked(t, s, http.MethodGet, "checkpoints-a", "", "/api/v1/runs/"+runB.ID+"/snapshots", "/api/v1/runs/"+missingRun+"/snapshots", secrets...)
	existenceAssertMasked(t, s, http.MethodGet, "checkpoints-a", "", "/api/v1/runs/"+runB.ID+"/snapshots/"+sidB, "/api/v1/runs/"+missingRun+"/snapshots/"+sidB, secrets...)
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/"+runA.ID+"/snapshots", "checkpoints-a", ""); w.Code != http.StatusOK {
		t.Fatalf("checkpoints-a own listing = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/"+runA.ID+"/snapshots/"+sidA, "checkpoints-a", ""); w.Code != http.StatusOK {
		t.Fatalf("checkpoints-a own download = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/"+runB.ID+"/snapshots", "checkpoints-b", ""); w.Code != http.StatusOK {
		t.Fatalf("checkpoints-b own listing = %d: %s", w.Code, w.Body.String())
	}
	existenceAssertMasked(t, s, http.MethodGet, "checkpoints-b", "", "/api/v1/runs/"+runA.ID+"/snapshots", "/api/v1/runs/"+missingRun+"/snapshots", secrets...)

	// evidence:read on repo-a and repo-b, on the pipeline export and the
	// attestation route (a visible run with no attestation record is a plain
	// 404, which is what the covered principal gets).
	existenceAssertMasked(t, s, http.MethodGet, "repo-evidence", "", "/api/v1/runs/"+runB.ID+"/jobs/"+jobB+"/pipeline", "/api/v1/runs/"+missingRun+"/jobs/"+jobB+"/pipeline", secrets...)
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/"+runA.ID+"/jobs/"+jobA+"/pipeline", "repo-evidence", ""); w.Code != http.StatusOK {
		t.Fatalf("repo-evidence own pipeline = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/jobs/"+jobA+"/attestation", "repo-evidence", ""); w.Code != http.StatusNotFound {
		t.Fatalf("repo-evidence own attestation (absent record) = %d, want plain 404", w.Code)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/"+runB.ID+"/jobs/"+jobB+"/pipeline", "evidence-b", ""); w.Code != http.StatusOK {
		t.Fatalf("evidence-b own pipeline = %d: %s", w.Code, w.Body.String())
	}
	existenceAssertMasked(t, s, http.MethodGet, "evidence-b", "", "/api/v1/runs/"+runA.ID+"/jobs/"+jobA+"/pipeline", "/api/v1/runs/"+missingRun+"/jobs/"+jobA+"/pipeline", secrets...)
	existenceAssertMasked(t, s, http.MethodGet, "evidence-b", "", "/api/v1/jobs/"+jobA+"/attestation", "/api/v1/jobs/job-existence-missing/attestation", secrets...)

	// execution.events:read on repo-a and repo-b.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/events?run_id="+runB.ID, "events-b", ""); w.Code != http.StatusOK {
		t.Fatalf("events-b own run scope = %d: %s", w.Code, w.Body.String())
	}
	existenceAssertMasked(t, s, http.MethodGet, "events-b", "", "/api/v1/events?run_id="+runA.ID, "/api/v1/events?run_id="+missingRun, secrets...)

	// runs:cancel on repo-b: its run cancels, the other repository and the
	// unknown id are masked before any mutation.
	existenceAssertMasked(t, s, http.MethodPost, "canceller-b", "", "/api/v1/runs/"+runA.ID+"/cancel", "/api/v1/runs/"+missingRun+"/cancel", secrets...)
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs/"+runB.ID+"/cancel", "canceller-b", ""); w.Code != http.StatusOK {
		t.Fatalf("canceller-b own cancel = %d: %s", w.Code, w.Body.String())
	}
	// The masked cancel above must not have touched run-a state.
	s.mu.Lock()
	statusA := s.runs[runA.ID].Status
	s.mu.Unlock()
	if statusA.Terminal() {
		t.Fatalf("masked cancel mutated the foreign run: status %q", statusA)
	}

	// A reader of the covered repository keeps the 403 for the narrower
	// missing capability (read visibility passed, capability denial follows).
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/"+runB.ID+"/snapshots", "reader-b", ""); w.Code != http.StatusForbidden {
		t.Fatalf("reader-b snapshot listing = %d, want 403: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/"+runB.ID+"/jobs/"+jobB+"/pipeline", "reader-b", ""); w.Code != http.StatusForbidden {
		t.Fatalf("reader-b pipeline = %d, want 403: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/"+runB.ID, "reader-b", ""); w.Code != http.StatusOK {
		t.Fatalf("reader-b own run = %d: %s", w.Code, w.Body.String())
	}

	// artifact_read on repo-a: the artifact surface is served on its own
	// repository and masked on the other / unknown ones.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/"+runA.ID+"/artifacts", "artifact-a", ""); w.Code != http.StatusOK {
		t.Fatalf("artifact-a own list = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/artifacts/art-a", "artifact-a", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "artifact-bytes-a") {
		t.Fatalf("artifact-a own download = %d: %s", w.Code, w.Body.String())
	}
	existenceAssertMasked(t, s, http.MethodGet, "artifact-a", "", "/api/v1/runs/"+runB.ID+"/artifacts", "/api/v1/runs/"+missingRun+"/artifacts", secrets...)
	existenceAssertMasked(t, s, http.MethodGet, "artifact-a", "", "/api/v1/artifacts/art-b", "/api/v1/artifacts/art-existence-missing", secrets...)
}

// TestExistenceMaskingAdminAlwaysAllowed proves the masking never turns into
// a denial for the admin: every repo-b surface answers its normal success and
// the unknown id its normal not-found.
func TestExistenceMaskingAdminAlwaysAllowed(t *testing.T) {
	s, _, runB := existenceLeakServer(t)
	jobB := jobIDForRun(t, s, runB.ID)
	sidB := "snap-" + runB.ID
	for _, tc := range []struct {
		name, method, path string
		want               int
	}{
		{"admin run get", http.MethodGet, "/api/v1/runs/" + runB.ID, http.StatusOK},
		{"admin run jobs", http.MethodGet, "/api/v1/runs/" + runB.ID + "/jobs", http.StatusOK},
		{"admin run logs", http.MethodGet, "/api/v1/runs/" + runB.ID + "/logs", http.StatusOK},
		{"admin snapshots", http.MethodGet, "/api/v1/runs/" + runB.ID + "/snapshots", http.StatusOK},
		{"admin snapshot download", http.MethodGet, "/api/v1/runs/" + runB.ID + "/snapshots/" + sidB, http.StatusOK},
		{"admin pipeline", http.MethodGet, "/api/v1/runs/" + runB.ID + "/jobs/" + jobB + "/pipeline", http.StatusOK},
		{"admin events run scope", http.MethodGet, "/api/v1/events?run_id=" + runB.ID, http.StatusOK},
		{"admin unknown run", http.MethodGet, "/api/v1/runs/run-existence-missing", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if w := doJSON(t, s, tc.method, tc.path, "admin-tok", ""); w.Code != tc.want {
				t.Fatalf("%s %s with admin-tok = %d, want %d: %s", tc.method, tc.path, w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// TestExistenceMaskingDBMode repeats the masking core over the DB store
// branches: the primitive resolves through GetRun in every run-scoped
// handler, so the two-repo evidence must hold with the store-backed server
// too (authorized controls included; the event store contract is exercised in
// the memory/fs matrix above).
func TestExistenceMaskingDBMode(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	now := time.Now().UTC()
	f.mu.Lock()
	f.runs["run-a-db"] = model.Run{ID: "run-a-db", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusRunning, CreatedAt: now}
	f.runs["run-b-db"] = model.Run{ID: "run-b-db", Repo: "https://github.com/o/repo-b.git", RepoFullName: "o/repo-b", Status: model.StatusRunning, CreatedAt: now}
	f.jobs["job-a-db"] = model.Job{ID: "job-a-db", RunID: "run-a-db", Key: "build", RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusQueued, Pipeline: testPipeline, CreatedAt: now}
	f.jobs["job-b-db"] = model.Job{ID: "job-b-db", RunID: "run-b-db", Key: "build", RepoURL: "https://github.com/o/repo-b.git", RepoFullName: "o/repo-b", Status: model.StatusQueued, Pipeline: testPipeline, CreatedAt: now}
	f.artifacts = append(f.artifacts, model.ArtifactRecord{ID: "art-b-db", RunID: "run-b-db", JobID: "job-b-db", Name: "bin", SHA256: "aaaaaaaa", CreatedAt: now})
	f.mu.Unlock()
	for raw, p := range map[string]auth.Principal{
		"reader-a-db": {Subject: "reader", Repositories: map[string]auth.RepositoryPermission{
			capabilityRepoKey(t, "github.com/o/repo-a"): {Read: true},
		}},
		"checkpoints-a-db": {Subject: "replayer", RepositoryCapabilities: map[string][]auth.Capability{
			capabilityRepoKey(t, "github.com/o/repo-a"): {auth.CapCheckpointsRead},
		}},
		"evidence-a-db": {Subject: "auditor", RepositoryCapabilities: map[string][]auth.Capability{
			capabilityRepoKey(t, "github.com/o/repo-a"): {auth.CapEvidenceRead},
		}},
		"artifact-a-db": {Subject: "artifact-a", Repositories: map[string]auth.RepositoryPermission{
			capabilityRepoKey(t, "github.com/o/repo-a"): {Read: true, ArtifactRead: true},
		}},
	} {
		if err := s.AuthStore.AddToken(raw, p); err != nil {
			t.Fatal(err)
		}
	}
	const missing = "run-existence-missing-db"
	for _, tc := range []struct {
		name, method, token, foreignPath, missingPath string
	}{
		{"run get", http.MethodGet, "reader-a-db", "/api/v1/runs/run-b-db", "/api/v1/runs/" + missing},
		{"run jobs", http.MethodGet, "reader-a-db", "/api/v1/runs/run-b-db/jobs", "/api/v1/runs/" + missing + "/jobs"},
		{"run artifacts", http.MethodGet, "reader-a-db", "/api/v1/runs/run-b-db/artifacts", "/api/v1/runs/" + missing + "/artifacts"},
		{"run logs", http.MethodGet, "reader-a-db", "/api/v1/runs/run-b-db/logs", "/api/v1/runs/" + missing + "/logs"},
		{"cancel", http.MethodPost, "reader-a-db", "/api/v1/runs/run-b-db/cancel", "/api/v1/runs/" + missing + "/cancel"},
		{"rerun", http.MethodPost, "reader-a-db", "/api/v1/runs/run-b-db/rerun", "/api/v1/runs/" + missing + "/rerun"},
		{"events run scope", http.MethodGet, "reader-a-db", "/api/v1/events?run_id=run-b-db", "/api/v1/events?run_id=" + missing},
		{"snapshots list", http.MethodGet, "checkpoints-a-db", "/api/v1/runs/run-b-db/snapshots", "/api/v1/runs/" + missing + "/snapshots"},
		{"snapshot download", http.MethodGet, "checkpoints-a-db", "/api/v1/runs/run-b-db/snapshots/sid-b", "/api/v1/runs/" + missing + "/snapshots/sid-b"},
		{"pipeline export", http.MethodGet, "evidence-a-db", "/api/v1/runs/run-b-db/jobs/job-b-db/pipeline", "/api/v1/runs/" + missing + "/jobs/job-b-db/pipeline"},
		{"job attestation", http.MethodGet, "evidence-a-db", "/api/v1/jobs/job-b-db/attestation", "/api/v1/jobs/job-missing-db/attestation"},
		{"artifact download", http.MethodGet, "reader-a-db", "/api/v1/artifacts/art-b-db", "/api/v1/artifacts/art-missing-db"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			existenceAssertMasked(t, s, tc.method, tc.token, "", tc.foreignPath, tc.missingPath, "run-b-db", "repo-b", "job-b-db", "art-b-db")
		})
	}
	// Authorized controls: the repo-a halves are served normally in DB mode.
	for _, tc := range []struct {
		name, method, path, token string
		want                      int
	}{
		{"own run get", http.MethodGet, "/api/v1/runs/run-a-db", "reader-a-db", http.StatusOK},
		{"own run jobs", http.MethodGet, "/api/v1/runs/run-a-db/jobs", "reader-a-db", http.StatusOK},
		{"own run artifacts without artifact_read", http.MethodGet, "/api/v1/runs/run-a-db/artifacts", "reader-a-db", http.StatusForbidden},
		{"own run artifacts", http.MethodGet, "/api/v1/runs/run-a-db/artifacts", "artifact-a-db", http.StatusOK},
		{"own run logs", http.MethodGet, "/api/v1/runs/run-a-db/logs", "reader-a-db", http.StatusOK},
		{"own snapshots", http.MethodGet, "/api/v1/runs/run-a-db/snapshots", "checkpoints-a-db", http.StatusOK},
		{"own pipeline", http.MethodGet, "/api/v1/runs/run-a-db/jobs/job-a-db/pipeline", "evidence-a-db", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if w := doJSON(t, s, tc.method, tc.path, tc.token, ""); w.Code != tc.want {
				t.Fatalf("%s %s with %s = %d, want %d: %s", tc.method, tc.path, tc.token, w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// TestExistenceMaskingNoAuditSideChannel proves a masked cancel/rerun writes
// no audit row and no state change: the failures never reach the mutation
// funnel, so the audit trail cannot become an externally observable
// "someone probed a run" signal. The metrics funnel labels every masked
// answer with the same bounded {code=404, method, path_class} series as a
// genuinely missing run (raw ids never enter metric labels), so it records no
// distinct forbidden outcome either; the metric registry is not wired on the
// test server, which is the documented skip for the counter-level assertion.
func TestExistenceMaskingNoAuditSideChannel(t *testing.T) {
	s, runA, runB := existenceLeakServer(t)
	// Masked probes: foreign and unknown ids on both mutating endpoints.
	for _, path := range []string{
		"/api/v1/runs/" + runB.ID + "/cancel",
		"/api/v1/runs/" + runB.ID + "/rerun",
		"/api/v1/runs/run-existence-missing/cancel",
		"/api/v1/runs/run-existence-missing/rerun",
	} {
		if w := doJSON(t, s, http.MethodPost, path, "reader-a", ""); w.Code != http.StatusNotFound {
			t.Fatalf("masked %s = %d, want 404", path, w.Code)
		}
	}
	// The audit trail is readable by the admin; no cancel/rerun evidence may
	// exist for the masked probes.
	w := doJSON(t, s, http.MethodGet, "/api/v1/audit", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("audit read = %d: %s", w.Code, w.Body.String())
	}
	for _, action := range []string{"run.cancelled", "run.rerun"} {
		if strings.Contains(w.Body.String(), action) {
			t.Fatalf("masked probe recorded %q audit evidence: %s", action, w.Body.String())
		}
	}
	// Neither run changed state.
	s.mu.Lock()
	statusA, statusB := s.runs[runA.ID].Status, s.runs[runB.ID].Status
	s.mu.Unlock()
	if statusA.Terminal() || statusB.Terminal() {
		t.Fatalf("masked probes mutated state: %q/%q", statusA, statusB)
	}
}
