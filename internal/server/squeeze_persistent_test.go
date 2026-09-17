package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestSqueezeNewPersistentLoaderErrors drives every data-dir loader failure
// return inside NewPersistentWithCluster with a corrupt fixture file.
func TestSqueezeNewPersistentLoaderErrors(t *testing.T) {
	cases := []struct {
		name  string
		write func(t *testing.T, dir string)
	}{
		{"lease key hex", func(t *testing.T, dir string) {
			writeTestFile(t, filepath.Join(dir, "lease.key"), []byte("zz"))
		}},
		{"lease key size", func(t *testing.T, dir string) {
			writeTestFile(t, filepath.Join(dir, "lease.key"), []byte("abcd"))
		}},
		{"lease key read error", func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "lease.key"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"runner ca invalid", func(t *testing.T, dir string) {
			writeTestFile(t, filepath.Join(dir, "ca.crt"), []byte("junk"))
			writeTestFile(t, filepath.Join(dir, "ca.key"), []byte("junk"))
		}},
		{"runner ca cert read error", func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "ca.crt"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"provenance key invalid", func(t *testing.T, dir string) {
			writeTestFile(t, filepath.Join(dir, "provenance.key"), []byte("junk"))
		}},
		{"provenance key read error", func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "provenance.key"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"cache signing key invalid", func(t *testing.T, dir string) {
			writeTestFile(t, filepath.Join(dir, cacheSigningKeyFile), []byte("junk"))
			writeTestFile(t, filepath.Join(dir, cacheSigningPubFile), []byte("junk"))
		}},
		{"web session secret invalid", func(t *testing.T, dir string) {
			writeTestFile(t, filepath.Join(dir, webSessionKeyFile), []byte("zz"))
		}},
		{"web session secret size", func(t *testing.T, dir string) {
			writeTestFile(t, filepath.Join(dir, webSessionKeyFile), []byte("abcd"))
		}},
		{"web session secret read error", func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, webSessionKeyFile), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"test history invalid", func(t *testing.T, dir string) {
			writeTestFile(t, filepath.Join(dir, testHistoryFile), []byte("{"))
		}},
		{"schedules invalid", func(t *testing.T, dir string) {
			writeTestFile(t, filepath.Join(dir, schedulesFile), []byte("{"))
		}},
		{"state invalid", func(t *testing.T, dir string) {
			writeTestFile(t, filepath.Join(dir, "state.json"), []byte("{"))
		}},
		{"state read error", func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "state.json"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"drain flag invalid", func(t *testing.T, dir string) {
			writeTestFile(t, filepath.Join(dir, drainFlagFile), []byte("{"))
		}},
		{"drain flag read error", func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, drainFlagFile), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"logs invalid", func(t *testing.T, dir string) {
			writeTestFile(t, filepath.Join(dir, "logs.jsonl"), []byte("{not json\n"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.write(t, dir)
			if _, err := NewPersistentWithCluster("t", "t", dir, nil); err == nil {
				t.Fatalf("NewPersistentWithCluster(%s) = nil error", tc.name)
			}
		})
	}
}

// TestSqueezeNewPersistentSymlinkedDataDir forces MkdirAll failures through a
// dangling symlink: every read looks like a missing file but the directory
// cannot be materialized.
func TestSqueezeNewPersistentSymlinkedDataDir(t *testing.T) {
	root := t.TempDir()
	dangling := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(root, "missing-target"), dangling); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := NewPersistentWithCluster("t", "t", dangling, nil); err == nil {
		t.Fatal("dangling symlink data dir = nil error")
	}
}

// TestSqueezeNewPersistentPersistFailure makes the final snapshot write fail
// after every loader succeeded.
func TestSqueezeNewPersistentPersistFailure(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewPersistentWithCluster("t", "t", dir, nil); err != nil {
		t.Fatal(err)
	}
	// Verify the persisted snapshot is rewritten on the next start; make the
	// directory unwritable so that write fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := NewPersistentWithCluster("t", "t", dir, nil); err == nil {
		t.Fatal("read-only data dir = nil error, want persist failure")
	}
}

// TestSqueezeNewPersistentRestoreFixture reopens a snapshot carrying a
// delivery-bearing run, an artifact with provenance, and a capacity-less
// runner so the restore branches run.
func TestSqueezeNewPersistentRestoreFixture(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	expiry := now.Add(time.Hour)
	st := storage.New(dir)
	snap := storage.Snapshot{
		Version: 1,
		Runs: map[string]model.Run{
			"run-1": {ID: "run-1", RepoFullName: "acme/backend", SHA: "sha", Status: model.StatusRunning, Metadata: map[string]string{"gitlab_delivery": "del-1", "github_delivery": "  ", "forgejo_delivery": "del-2"}},
		},
		Jobs: map[string]model.Job{
			"job-1": {ID: "job-1", RunID: "run-1", Status: model.StatusRunning, LeaseRunnerID: "runner-1", LeaseExpiresAt: &expiry},
		},
		Runners: map[string]model.Runner{
			"runner-1": {ID: "runner-1", Capacity: 0},
		},
		Artifacts: map[string]model.ArtifactRecord{
			"art-1": {ID: "art-1", RunID: "run-1", JobID: "job-1", Name: "pkg", SHA256: "sum"},
			"art-2": {ID: "art-2", RunID: "run-1", JobID: "job-1", Name: "prov", SHA256: "sum", ProvenanceSHA256: "provsum"},
		},
	}
	if err := st.Save(snap); err != nil {
		t.Fatal(err)
	}
	s, err := NewPersistentWithCluster("t", "t", dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.deliveries["del-1"] != "run-1" || s.deliveries["del-2"] != "run-1" {
		t.Fatalf("deliveries restored = %v", s.deliveries)
	}
	if _, ok := s.deliveries["  "]; ok {
		t.Fatalf("blank delivery restored: %v", s.deliveries)
	}
	if a := s.artifacts["art-1"]; a.Path != filepath.Join(dir, "artifacts", "run-1", "job-1", "art-1.tar.gz") {
		t.Fatalf("artifact path = %q", a.Path)
	}
	if a := s.artifacts["art-2"]; a.ProvenancePath != a.Path+".intoto.json" {
		t.Fatalf("provenance path = %q", a.ProvenancePath)
	}
	r := s.runners["runner-1"]
	if r.Capacity != 1 {
		t.Fatalf("capacity-less runner not defaulted: %+v", r)
	}
	if len(r.ActiveJobs) != 1 || r.ActiveJobs[0] != "job-1" || r.CurrentJob != "job-1" || !r.Busy {
		t.Fatalf("active job restore = %+v", r)
	}
}

// TestSqueezeNewPersistentClusterLoaderErrors drives the cluster-store
// loader error returns for every signing root.
func TestSqueezeNewPersistentClusterLoaderErrors(t *testing.T) {
	cases := []struct {
		name  string
		store ClusterKeyStore
	}{
		{"lease load error", fixedClusterStore{}},
		{"lease wrong size", fixedClusterStore{b: []byte("short")}},
		{"oidc ring invalid", fixedClusterStore{b: []byte("{")}},
		{"runner ca blob invalid", fixedClusterStore{b: []byte("junk")}},
		{"provenance pem invalid", fixedClusterStore{b: []byte("junk")}},
		{"cache pem invalid", fixedClusterStore{b: []byte("junk")}},
		{"web session wrong size", fixedClusterStore{b: []byte("short")}},
	}
	for _, tc := range cases {
		if tc.name == "web session wrong size" {
			tc.store = staticKindStore{kind: clusterKindWebSession, b: []byte("short")}
		}
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewPersistentWithCluster("t", "t", t.TempDir(), tc.store); err == nil {
				t.Fatalf("%s = nil error", tc.name)
			}
		})
	}
}

// staticKindStore returns per-kind material from a map.
type staticKindStore struct {
	kind string
	b    []byte
	err  error
}

func (s staticKindStore) LoadOrCreate(kind string) ([]byte, error) {
	if kind == s.kind {
		return s.b, s.err
	}
	return nil, errStaticKindMissing
}

var errStaticKindMissing = errClusterKindMissing{}

type errClusterKindMissing struct{}

func (errClusterKindMissing) Error() string { return "cluster key kind missing" }

// TestSqueezeSwitchToDBInitError: a store whose schema check fails refuses
// the switch before any wiring happens.
func TestSqueezeSwitchToDBInitError(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	f.leaderErr = errStaticKindMissing
	if err := s.SwitchToDB(f); err == nil {
		t.Fatal("SwitchToDB with failing leadership claim = nil error")
	}
}

// TestSqueezeSwitchToDBOPAError: a policy installed before the switch that
// cannot compile fails the switch closed.
func TestSqueezeSwitchToDBOPAError(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{OPAFile: filepath.Join(t.TempDir(), "missing.rego")}
	if err := s.SwitchToDB(newDBFakeStore()); err == nil {
		t.Fatal("SwitchToDB with broken policy = nil error")
	}
}

// TestSqueezeLoadDrainFlagEdges covers the loader's empty-dir and error
// returns directly.
func TestSqueezeLoadDrainFlagEdges(t *testing.T) {
	s := New("t")
	if err := s.loadDrainFlag(""); err != nil {
		t.Fatalf("empty data dir: %v", err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, drainFlagFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.loadDrainFlag(dir); err == nil {
		t.Fatal("read error = nil")
	}
	dir2 := t.TempDir()
	writeTestFile(t, filepath.Join(dir2, drainFlagFile), []byte("{"))
	if err := s.loadDrainFlag(dir2); err == nil {
		t.Fatal("unmarshal error = nil")
	}
}

// TestSqueezeDrainActiveJobsDB covers the DB-mode drain accounting with a
// fake store, including the fallback when listing runs fails.
func TestSqueezeDrainActiveJobsDB(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.InsertRun(ctx, model.Run{ID: "run-1", Status: model.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	if err := f.InsertRun(ctx, model.Run{ID: "run-2", Status: model.StatusSuccess}); err != nil {
		t.Fatal(err)
	}
	if err := f.InsertJob(ctx, model.Job{ID: "job-1", RunID: "run-1", Status: model.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	if err := f.InsertJob(ctx, model.Job{ID: "job-2", RunID: "run-1", Status: model.StatusQueued}); err != nil {
		t.Fatal(err)
	}
	if err := f.InsertJob(ctx, model.Job{ID: "job-3", RunID: "run-2", Status: model.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	if got := s.ActiveJobs(); got != 1 {
		t.Fatalf("ActiveJobs = %d, want 1 (only non-terminal runs count)", got)
	}
	// A failing store falls back to the in-memory count.
	f.listRunsErr = errStaticKindMissing
	s.mu.Lock()
	s.jobs["mem-1"] = model.Job{ID: "mem-1", Status: model.StatusRunning}
	s.mu.Unlock()
	if got := s.ActiveJobs(); got != 1 {
		t.Fatalf("ActiveJobs fallback = %d, want 1", got)
	}
}

func TestSqueezeContextTimeout(t *testing.T) {
	ctx, cancel := contextTimeout(time.Second)
	defer cancel()
	if ctx == nil {
		t.Fatal("nil context")
	}
	select {
	case <-ctx.Done():
		t.Fatal("context already done")
	default:
	}
}

func TestSqueezeDrainServerDecodeError(t *testing.T) {
	s := New("t")
	c := newTestClient(t, s.Handler(), "t")
	w := c.do(http.MethodPost, "/api/v1/drain", []byte("{"), map[string]string{"Content-Type": "application/json"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("decode error = %d, want 400", w.Code)
	}
}

// TestSqueezeDeploymentMemoryNotFound covers the 404 edges of the memory-mode
// deployment endpoints and finishDeploymentDB's no-op returns.
func TestSqueezeDeploymentMemoryNotFound(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	if w := c.do(http.MethodPost, "/api/v1/jobs/missing/deployments", nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("record missing job = %d, want 404", w.Code)
	}
	if w := c.do(http.MethodGet, "/api/v1/runs/missing/deployments", nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("list missing run = %d, want 404", w.Code)
	}
}

func TestSqueezeFinishDeploymentDBNoOps(t *testing.T) {
	s := New("t")
	now := time.Now().UTC()
	// No environment: nothing to finish.
	s.finishDeploymentDB(context.Background(), model.Job{ID: "j", Environment: ""}, model.StatusSuccess, now)
	// Environment job with no record anywhere: nothing to finish.
	s.finishDeploymentDB(context.Background(), model.Job{ID: "j", RunID: "r", Environment: "prod"}, model.StatusSuccess, now)
	// Already-finished record is the idempotency marker.
	s.mu.Lock()
	s.deployments["j2"] = model.Deployment{ID: "d2", JobID: "j2", RunID: "r", Environment: "prod", FinishedAt: &now}
	s.mu.Unlock()
	s.finishDeploymentDB(context.Background(), model.Job{ID: "j2", RunID: "r", Environment: "prod"}, model.StatusFailure, now)
	s.mu.Lock()
	d := s.deployments["j2"]
	s.mu.Unlock()
	if d.Status == model.StatusFailure {
		t.Fatalf("finished deployment was overwritten: %+v", d)
	}
}

// TestSqueezeFinishDeploymentDBStoreLookup covers the DB-mode fallback that
// resolves the record by run when the memory mirror is empty.
func TestSqueezeFinishDeploymentDBStoreLookup(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if err := f.InsertDeployment(context.Background(), model.Deployment{ID: "d1", JobID: "job-1", RunID: "run-1", Environment: "prod"}); err != nil {
		t.Fatal(err)
	}
	s.finishDeploymentDB(context.Background(), model.Job{ID: "job-1", RunID: "run-1", Environment: "prod"}, model.StatusSuccess, time.Now().UTC())
	f.mu.Lock()
	d := f.deployments["d1"]
	f.mu.Unlock()
	if d.Status != model.StatusSuccess || d.FinishedAt == nil {
		t.Fatalf("deployment not finished from store lookup: %+v", d)
	}
}

// TestSqueezeRecordDeploymentDBPaths covers the DB-mode record endpoint,
// including not-found, store failure and the insert error log.
func TestSqueezeRecordDeploymentDBPaths(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	f.getJobErr = errStaticKindMissing
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "token")
	if w := c.do(http.MethodPost, "/api/v1/jobs/missing/deployments", nil, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("store error = %d, want 500", w.Code)
	}
	f.getJobErr = storage.ErrNotFound
	if w := c.do(http.MethodPost, "/api/v1/jobs/missing/deployments", nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("missing job = %d, want 404", w.Code)
	}
	f.getJobErr = nil
	if err := f.InsertJob(context.Background(), model.Job{ID: "job-1", RunID: "run-1"}); err != nil {
		t.Fatal(err)
	}
	if w := c.do(http.MethodPost, "/api/v1/jobs/job-1/deployments", nil, nil); w.Code != http.StatusConflict {
		t.Fatalf("no environment = %d, want 409", w.Code)
	}
	if err := f.InsertJob(context.Background(), model.Job{ID: "job-2", RunID: "run-1", Environment: "prod"}); err != nil {
		t.Fatal(err)
	}
	f.deploymentInsertErr = errStaticKindMissing
	if w := c.do(http.MethodPost, "/api/v1/jobs/job-2/deployments", nil, nil); w.Code != http.StatusCreated {
		t.Fatalf("record with failing insert = %d, want 201", w.Code)
	}
}

// TestSqueezeListDeploymentsDBPaths covers the DB-mode list endpoint.
func TestSqueezeListDeploymentsDBPaths(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "token")
	f.getRunErr = errStaticKindMissing
	if w := c.do(http.MethodGet, "/api/v1/runs/run-1/deployments", nil, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("store error = %d, want 500", w.Code)
	}
	f.getRunErr = storage.ErrNotFound
	if w := c.do(http.MethodGet, "/api/v1/runs/run-1/deployments", nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("missing run = %d, want 404", w.Code)
	}
	f.getRunErr = nil
	if err := f.InsertRun(context.Background(), model.Run{ID: "run-1", Status: model.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	if err := f.InsertDeployment(context.Background(), model.Deployment{ID: "d1", JobID: "job-1", RunID: "run-1", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	// A memory-mirror record not present in the store is appended.
	s.mu.Lock()
	s.deployments["mirror"] = model.Deployment{ID: "d2", JobID: "job-2", RunID: "run-1", CreatedAt: time.Now().UTC().Add(time.Second)}
	s.mu.Unlock()
	w := c.do(http.MethodGet, "/api/v1/runs/run-1/deployments", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", w.Code, w.Body.String())
	}
	var out []model.Deployment
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("deployments = %+v, want store record plus mirror", out)
	}
	f.listDeploymentsErr = errStaticKindMissing
	if w := c.do(http.MethodGet, "/api/v1/runs/run-1/deployments", nil, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("list store error = %d, want 500", w.Code)
	}
}

// TestSqueezeRepoIdentityEdges covers the host/fallback derivations.
func TestSqueezeRepoIdentityEdges(t *testing.T) {
	if got := repoHost("https://user:pass@github.com/o/r.git"); got != "github.com" {
		t.Fatalf("repoHost(userinfo) = %q", got)
	}
	if got := repoHost("ssh://git@github.com:2222/o/r.git"); got != "github.com:2222" {
		t.Fatalf("repoHost(port) = %q", got)
	}
	if got := repoHost("git@github.com:o/r.git"); got != "github.com" {
		t.Fatalf("repoHost(scp) = %q", got)
	}
	if got := repoHost("github.com/o/r"); got != "github.com" {
		t.Fatalf("repoHost(bare slash) = %q", got)
	}
	if got := repoHost("weirdhost"); got != "weirdhost" {
		t.Fatalf("repoHost(bare) = %q", got)
	}
	if got := repoFullNameFromCloneURL("  acme/backend  "); got != "acme/backend" {
		t.Fatalf("repoFullNameFromCloneURL(bare) = %q", got)
	}
	if got := repoFullNameFromCloneURL("https://github.com/acme/backend.git"); got != "acme/backend" {
		t.Fatalf("repoFullNameFromCloneURL(url) = %q", got)
	}

	s := New("t")
	if got := s.configuredForgeHost("github"); got != "" {
		t.Fatalf("unconfigured host = %q", got)
	}
	s.SetForgeBaseURL("github", "https://github.enterprise.example/api/v3")
	if got := s.configuredForgeHost("github"); got != "github.enterprise.example" {
		t.Fatalf("configured host = %q", got)
	}
	if got := s.forgeInstanceHost("github", ""); got != "github.enterprise.example" {
		t.Fatalf("configured fallback host = %q", got)
	}
	s2 := New("t")
	s2.SetForgeBaseURL("github", "https://api.github.com")
	if got := s2.configuredForgeHost("github"); got != "github.com" {
		t.Fatalf("api.github.com normalization = %q", got)
	}
	if got := publicForgeHost("gitlab"); got != "gitlab.com" {
		t.Fatalf("publicForgeHost(gitlab) = %q", got)
	}
	if got := publicForgeHost("forgejo"); got != "codeberg.org" {
		t.Fatalf("publicForgeHost(forgejo) = %q", got)
	}
	if got := publicForgeHost("github"); got != "github.com" {
		t.Fatalf("publicForgeHost(github) = %q", got)
	}
	if got := New("t").forgeInstanceHost("gitlab", ""); got != "gitlab.com" {
		t.Fatalf("default instance host = %q", got)
	}
	// The head repository's clone URL is the fallback when the base omits one.
	ec := forge.EventContext{
		Repository:     forge.Repository{FullName: "acme/backend"},
		HeadRepository: forge.Repository{FullName: "fork/backend", CloneURL: "https://github.com/fork/r.git"},
	}
	if got := webhookRepoCoordinate(ec).CloneURL; got != "https://github.com/fork/r.git" {
		t.Fatalf("webhookRepoCoordinate fallback = %q", got)
	}
}
