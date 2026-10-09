package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/execution"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

// recordedExport builds the control plane's exact-replay export body for one
// job of text with coherent digests; mutate, when non-nil, tampers the
// payload after the digests are computed (simulating a corrupt record).
func recordedExport(t *testing.T, text, key string, mutate func(*model.CompiledJobPayload)) string {
	t.Helper()
	return recordedExportWithPersisted(t, text, key, mutate, map[string]any{"trusted": true})
}

// recordedExportWithPersisted is recordedExport with an explicit persisted
// job state (trust, resource requests, legacy network) so tests can exercise
// the shared materializer's trust/resource overlays.
func recordedExportWithPersisted(t *testing.T, text, key string, mutate func(*model.CompiledJobPayload), persisted map[string]any) string {
	t.Helper()
	spec, err := pipeline.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	pd, err := pipeline.PipelineDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	cj, ok := g.Jobs[key]
	if !ok {
		t.Fatalf("no compiled job %q", key)
	}
	cjJSON, err := json.Marshal(cj)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cjJSON)
	payload := &model.CompiledJobPayload{
		SchemaVersion:   1,
		CompilerVersion: "test",
		PipelineDigest:  pd,
		JobDigest:       hex.EncodeToString(sum[:]),
		EffectiveJob:    json.RawMessage(cjJSON),
	}
	if mutate != nil {
		mutate(payload)
	}
	body, err := json.Marshal(map[string]any{
		"run_id":               "run1",
		"id":                   "job1",
		"key":                  key,
		"pipeline":             text,
		"compiled_job_payload": payload,
		"persisted_job":        persisted,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// exactReplayEnv serves the recorded-pipeline export, a paginated snapshot
// listing and snapshot downloads, recording what the CLI requested.
type exactReplayEnv struct {
	srv          *httptest.Server
	export       string
	pages        [][]model.SnapshotRecord
	next         []string
	pageByCursor map[string]int
	archives     map[string][]byte
	downloads    []string
	cursors      []string
}

func newExactReplayEnv(t *testing.T, export string, pages [][]model.SnapshotRecord, next []string, archives map[string][]byte) *exactReplayEnv {
	t.Helper()
	env := &exactReplayEnv{export: export, pages: pages, next: next, archives: archives, pageByCursor: map[string]int{}}
	cursor := ""
	for i := range pages {
		env.pageByCursor[cursor] = i
		if i < len(next) {
			cursor = next[i]
		}
	}
	env.srv = scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/pipeline"):
			_, _ = w.Write([]byte(env.export))
		case r.URL.Path == "/api/v1/runs/run1/snapshots":
			got := r.URL.Query().Get("cursor")
			env.cursors = append(env.cursors, got)
			i, ok := env.pageByCursor[got]
			if !ok {
				_, _ = w.Write([]byte("[]"))
				return
			}
			if i < len(env.next) && env.next[i] != "" {
				w.Header().Set("X-Kiwi-Next-Cursor", env.next[i])
			}
			_ = json.NewEncoder(w).Encode(env.pages[i])
		case strings.HasPrefix(r.URL.Path, "/api/v1/runs/run1/snapshots/"):
			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			env.downloads = append(env.downloads, id)
			archive, ok := env.archives[id]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	})
	return env
}

func exactPage(recs ...model.SnapshotRecord) []model.SnapshotRecord { return recs }

// TestReplayExactIgnoresLocalPipelineFile proves the default mode executes
// the recorded pipeline: a divergent (and even missing) local --pipeline file
// is never read, and the historical job runs.
func TestReplayExactIgnoresLocalPipelineFile(t *testing.T) {
	historical := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo historical\n"
	env := newExactReplayEnv(t,
		recordedExport(t, historical, "build", nil),
		[][]model.SnapshotRecord{exactPage(model.SnapshotRecord{ID: "snap1", JobKey: "build", LeaseGeneration: 1, Phase: model.SnapshotPhasePreJob, CreatedAt: time.Now().UTC()})},
		nil,
		map[string][]byte{"snap1": snapshotArchive(t)},
	)
	divergent := writePipeline(t, t.TempDir(), "version: 1\njobs:\n  build:\n    steps:\n      - run: exit 3\n")
	if err := Replay(context.Background(), []string{"--server", env.srv.URL, "--pipeline", divergent, "run1", "build"}); err != nil {
		t.Fatalf("exact replay used the divergent local pipeline: %v", err)
	}
	if err := Replay(context.Background(), []string{"--server", env.srv.URL, "--pipeline", filepath.Join(t.TempDir(), "missing.yaml"), "run1", "build"}); err != nil {
		t.Fatalf("exact replay read the local pipeline file: %v", err)
	}
	if len(env.downloads) != 2 {
		t.Fatalf("downloads = %v", env.downloads)
	}
}

// TestReplayExactRefusesMismatchedPayload: a record whose payload does not
// re-bind to the recorded pipeline is refused with the actionable pointer to
// --debug-rerun, and nothing is restored or executed.
func TestReplayExactRefusesMismatchedPayload(t *testing.T) {
	historical := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo historical\n"
	env := newExactReplayEnv(t,
		recordedExport(t, historical, "build", func(p *model.CompiledJobPayload) {
			p.PipelineDigest = strings.Repeat("0", 64)
		}),
		[][]model.SnapshotRecord{exactPage(model.SnapshotRecord{ID: "snap1", JobKey: "build", LeaseGeneration: 1, Phase: model.SnapshotPhasePreJob, CreatedAt: time.Now().UTC()})},
		nil,
		map[string][]byte{"snap1": snapshotArchive(t)},
	)
	err := Replay(context.Background(), []string{"--server", env.srv.URL, "run1", "build"})
	if err == nil || !strings.Contains(err.Error(), "recorded pipeline/payload mismatch") || !strings.Contains(err.Error(), "--debug-rerun") {
		t.Fatalf("mismatch = %v", err)
	}
	if len(env.downloads) != 0 {
		t.Fatalf("downloaded %v despite the refusal", env.downloads)
	}
}

// TestReplayExactSelectsRequestedAttempt: with several snapshots for the same
// job key, --attempt selects exactly that lease generation and the default
// selects the newest generation (not the oldest record).
func TestReplayExactSelectsRequestedAttempt(t *testing.T) {
	historical := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo historical\n"
	now := time.Now().UTC()
	env := newExactReplayEnv(t,
		recordedExport(t, historical, "build", nil),
		[][]model.SnapshotRecord{exactPage(
			model.SnapshotRecord{ID: "snap-old", JobKey: "build", LeaseGeneration: 1, Phase: model.SnapshotPhasePreJob, CreatedAt: now.Add(-time.Hour)},
			model.SnapshotRecord{ID: "snap-new", JobKey: "build", LeaseGeneration: 2, Phase: model.SnapshotPhasePreJob, CreatedAt: now},
		)},
		nil,
		map[string][]byte{"snap-old": snapshotArchive(t), "snap-new": snapshotArchive(t)},
	)
	if err := Replay(context.Background(), []string{"--server", env.srv.URL, "--attempt", "1", "run1", "build"}); err != nil {
		t.Fatalf("attempt 1 replay: %v", err)
	}
	if len(env.downloads) != 1 || env.downloads[0] != "snap-old" {
		t.Fatalf("attempt 1 downloaded %v, want [snap-old]", env.downloads)
	}
	if err := Replay(context.Background(), []string{"--server", env.srv.URL, "run1", "build"}); err != nil {
		t.Fatalf("default replay: %v", err)
	}
	if len(env.downloads) != 2 || env.downloads[1] != "snap-new" {
		t.Fatalf("default downloaded %v, want snap-new", env.downloads)
	}
}

// TestReplayExactRefusesMissingAttempt: a requested generation with no
// snapshot is refused, never silently replaced by another attempt's
// workspace.
func TestReplayExactRefusesMissingAttempt(t *testing.T) {
	historical := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo historical\n"
	env := newExactReplayEnv(t,
		recordedExport(t, historical, "build", nil),
		[][]model.SnapshotRecord{exactPage(model.SnapshotRecord{ID: "snap1", JobKey: "build", LeaseGeneration: 1, Phase: model.SnapshotPhasePreJob, CreatedAt: time.Now().UTC()})},
		nil,
		map[string][]byte{"snap1": snapshotArchive(t)},
	)
	err := Replay(context.Background(), []string{"--server", env.srv.URL, "--attempt", "7", "run1", "build"})
	if err == nil || !strings.Contains(err.Error(), "lease generation 7") {
		t.Fatalf("missing attempt = %v", err)
	}
	if len(env.downloads) != 0 {
		t.Fatalf("downloaded %v despite the missing attempt", env.downloads)
	}
}

// TestReplayExactPaginatesSnapshotList: selection walks X-Kiwi-Next-Cursor
// pages instead of assuming one page; a generation only present on the second
// page is still found.
func TestReplayExactPaginatesSnapshotList(t *testing.T) {
	historical := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo historical\n"
	now := time.Now().UTC()
	env := newExactReplayEnv(t,
		recordedExport(t, historical, "build", nil),
		[][]model.SnapshotRecord{
			exactPage(model.SnapshotRecord{ID: "snap1", JobKey: "build", LeaseGeneration: 1, Phase: model.SnapshotPhasePreJob, CreatedAt: now.Add(-time.Hour)}),
			exactPage(model.SnapshotRecord{ID: "snap2", JobKey: "build", LeaseGeneration: 2, Phase: model.SnapshotPhasePreJob, CreatedAt: now}),
		},
		[]string{"cur1"},
		map[string][]byte{"snap1": snapshotArchive(t), "snap2": snapshotArchive(t)},
	)
	if err := Replay(context.Background(), []string{"--server", env.srv.URL, "run1", "build"}); err != nil {
		t.Fatalf("paginated replay: %v", err)
	}
	if len(env.downloads) != 1 || env.downloads[0] != "snap2" {
		t.Fatalf("downloaded %v, want [snap2]", env.downloads)
	}
	if len(env.cursors) != 2 || env.cursors[0] != "" || env.cursors[1] != "cur1" {
		t.Fatalf("cursors = %q, want the second page requested with cur1", env.cursors)
	}
	if err := Replay(context.Background(), []string{"--server", env.srv.URL, "--attempt", "1", "run1", "build"}); err != nil {
		t.Fatalf("paginated replay with attempt: %v", err)
	}
	if len(env.downloads) != 2 || env.downloads[1] != "snap1" {
		t.Fatalf("downloaded %v, want snap1 on the first page", env.downloads)
	}
}

// TestReplayDebugRerunUsesLocalPipelineAndWarns: --debug-rerun preserves the
// old behavior (the local file is authoritative) and warns loudly that the
// execution semantics may differ from the recorded run.
func TestReplayDebugRerunUsesLocalPipelineAndWarns(t *testing.T) {
	historical := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo recorded\n"
	env := newExactReplayEnv(t,
		recordedExport(t, historical, "build", nil),
		[][]model.SnapshotRecord{exactPage(model.SnapshotRecord{ID: "snap1", JobKey: "build", LeaseGeneration: 1, Phase: model.SnapshotPhasePreJob, CreatedAt: time.Now().UTC()})},
		nil,
		map[string][]byte{"snap1": snapshotArchive(t)},
	)
	local := writePipeline(t, t.TempDir(), "version: 1\njobs:\n  build:\n    steps:\n      - run: exit 3\n")
	origStderr := os.Stderr
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = pipeW
	replayErr := Replay(context.Background(), []string{"--server", env.srv.URL, "--pipeline", local, "--debug-rerun", "run1", "build"})
	_ = pipeW.Close()
	os.Stderr = origStderr
	warned, _ := io.ReadAll(pipeR)
	if replayErr == nil || !strings.Contains(replayErr.Error(), "failures") {
		t.Fatalf("debug rerun did not execute the failing local pipeline: %v", replayErr)
	}
	if !strings.Contains(string(warned), "CURRENT pipeline file") || !strings.Contains(string(warned), "may differ") {
		t.Fatalf("missing debug-rerun warning: %q", string(warned))
	}
}

// captureReplayOptions installs the replay options seam for one test and
// returns an accessor for the last derived executor options.
func captureReplayOptions(t *testing.T) func() (executor.Options, bool) {
	t.Helper()
	orig := replayOptionsSeam
	var got executor.Options
	var seen bool
	replayOptionsSeam = func(o executor.Options) {
		got, seen = o, true
	}
	t.Cleanup(func() { replayOptionsSeam = orig })
	return func() (executor.Options, bool) { return got, seen }
}

// stubReplayQuota replaces the OS-level quota probe exact replay uses for
// untrusted records and returns a counter of how many times it was invoked.
func stubReplayQuota(t *testing.T, status executor.DiskQuotaStatus, cleanup func() error) *int {
	t.Helper()
	orig := replayWorkspaceDiskQuotaSetup
	calls := 0
	replayWorkspaceDiskQuotaSetup = func(string, int64) (executor.DiskQuotaStatus, func() error) {
		calls++
		return status, cleanup
	}
	t.Cleanup(func() { replayWorkspaceDiskQuotaSetup = orig })
	return &calls
}

// untrustedRecord builds the export for an untrusted job with the untrusted
// policy floor (the same shape TestReplayExactEnforcesUntrustedFloor uses).
func untrustedRecord(t *testing.T, historical, key string) string {
	t.Helper()
	return recordedExportWithPersisted(t, historical, key,
		func(p *model.CompiledJobPayload) {
			b, merr := json.Marshal(policy.DefaultUntrustedCapabilities())
			if merr != nil {
				t.Fatal(merr)
			}
			p.EffectivePolicy = json.RawMessage(b)
		},
		map[string]any{"trusted": false, "network": "internet"})
}

// TestReplayExactUntrustedRefusesWithoutQuotaOrFlag: an untrusted recorded
// job must not run when the host cannot establish the same OS-level hard
// workspace quota the distributed runner installs; replay refuses with an
// actionable pointer to --allow-unbounded-workspace and downloads nothing.
func TestReplayExactUntrustedRefusesWithoutQuotaOrFlag(t *testing.T) {
	historical := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo historical\n"
	env := newExactReplayEnv(t,
		untrustedRecord(t, historical, "build"),
		[][]model.SnapshotRecord{exactPage(model.SnapshotRecord{ID: "snap-pre", JobKey: "build", LeaseGeneration: 1, Phase: model.SnapshotPhasePreJob, CreatedAt: time.Now().UTC()})},
		nil,
		map[string][]byte{"snap-pre": snapshotArchive(t)},
	)
	probes := stubReplayQuota(t, executor.DiskQuotaStatus{Detail: "no XFS prjquota on this host"}, nil)
	gotOptions := captureReplayOptions(t)
	err := Replay(context.Background(), []string{"--server", env.srv.URL, "run1", "build"})
	if err == nil || !strings.Contains(err.Error(), "allow-unbounded-workspace") || !strings.Contains(err.Error(), "refusing to replay untrusted job") {
		t.Fatalf("untrusted replay without quota = %v, want the actionable refusal", err)
	}
	if *probes != 1 {
		t.Fatalf("quota probe calls = %d, want 1", *probes)
	}
	if len(env.downloads) != 0 {
		t.Fatalf("downloaded %v despite the refusal", env.downloads)
	}
	if _, seen := gotOptions(); seen {
		t.Fatal("options seam fired: execution started despite the refusal")
	}
}

// TestReplayExactUntrustedAllowUnboundedWarnsAndProceeds: the explicit
// operator escape hatch prints a loud warning, skips the probe, and runs the
// recorded job without requiring a hard quota.
func TestReplayExactUntrustedAllowUnboundedWarnsAndProceeds(t *testing.T) {
	historical := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo historical\n"
	env := newExactReplayEnv(t,
		untrustedRecord(t, historical, "build"),
		[][]model.SnapshotRecord{exactPage(model.SnapshotRecord{ID: "snap-pre", JobKey: "build", LeaseGeneration: 1, Phase: model.SnapshotPhasePreJob, CreatedAt: time.Now().UTC()})},
		nil,
		map[string][]byte{"snap-pre": snapshotArchive(t)},
	)
	probes := stubReplayQuota(t, executor.DiskQuotaStatus{Detail: "unsupported"}, nil)
	gotOptions := captureReplayOptions(t)

	origStderr := os.Stderr
	pipeR, pipeW, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	os.Stderr = pipeW
	replayErr := Replay(context.Background(), []string{"--server", env.srv.URL, "--allow-unbounded-workspace", "run1", "build"})
	_ = pipeW.Close()
	os.Stderr = origStderr
	warned, _ := io.ReadAll(pipeR)
	// The untrusted native floor still fails closed on the non-root sandbox
	// requirement: reaching "failures" proves execution started.
	if replayErr == nil || !strings.Contains(replayErr.Error(), "failures") {
		t.Fatalf("escape-hatch replay = %v, want the sandbox-floor failure", replayErr)
	}
	if *probes != 0 {
		t.Fatalf("quota probe calls = %d, want 0 under the escape hatch", *probes)
	}
	if len(env.downloads) != 1 {
		t.Fatalf("downloads = %v, want the snapshot restored", env.downloads)
	}
	opts, ok := gotOptions()
	if !ok {
		t.Fatal("replay options seam never fired")
	}
	if opts.RequireUntrustedDiskQuota || opts.WorkspaceQuota != nil {
		t.Fatalf("escape-hatch options = quota-required %t status %v, want unbounded", opts.RequireUntrustedDiskQuota, opts.WorkspaceQuota)
	}
	if !strings.Contains(string(warned), "--allow-unbounded-workspace") || !strings.Contains(string(warned), "UNTRUSTED") {
		t.Fatalf("missing loud unbounded-workspace warning: %q", string(warned))
	}
}

// TestReplayExactUntrustedQuotaEnforcedWhenSupported: when the host supports
// the hard quota, it is installed BEFORE the snapshot is restored, passed
// through to the executor, and cleaned up after the replay.
func TestReplayExactUntrustedQuotaEnforcedWhenSupported(t *testing.T) {
	historical := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo historical\n"
	env := newExactReplayEnv(t,
		untrustedRecord(t, historical, "build"),
		[][]model.SnapshotRecord{exactPage(model.SnapshotRecord{ID: "snap-pre", JobKey: "build", LeaseGeneration: 1, Phase: model.SnapshotPhasePreJob, CreatedAt: time.Now().UTC()})},
		nil,
		map[string][]byte{"snap-pre": snapshotArchive(t)},
	)
	cleaned := 0
	probes := stubReplayQuota(t, executor.DiskQuotaStatus{Hard: true, Limit: 123, Detail: "fake XFS project quota"}, func() error {
		cleaned++
		return nil
	})
	gotOptions := captureReplayOptions(t)
	replayErr := Replay(context.Background(), []string{"--server", env.srv.URL, "run1", "build"})
	if replayErr == nil || !strings.Contains(replayErr.Error(), "failures") {
		t.Fatalf("quota-supported untrusted replay = %v, want the sandbox-floor failure", replayErr)
	}
	if *probes != 1 {
		t.Fatalf("quota probe calls = %d, want 1", *probes)
	}
	opts, ok := gotOptions()
	if !ok {
		t.Fatal("replay options seam never fired")
	}
	if !opts.RequireUntrustedDiskQuota {
		t.Fatal("hard quota installed but RequireUntrustedDiskQuota not set")
	}
	if opts.WorkspaceQuota == nil || !opts.WorkspaceQuota.Hard || opts.WorkspaceQuota.Limit != 123 {
		t.Fatalf("WorkspaceQuota = %+v, want the installed hard quota", opts.WorkspaceQuota)
	}
	if cleaned != 1 {
		t.Fatalf("quota cleanup calls = %d, want 1", cleaned)
	}
}

// TestReplayExactTrustedDoesNotProbeQuota: trusted jobs keep today's
// behavior; the untrusted quota probe must never run for them.
func TestReplayExactTrustedDoesNotProbeQuota(t *testing.T) {
	historical := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo historical\n"
	env := newExactReplayEnv(t,
		recordedExport(t, historical, "build", nil),
		[][]model.SnapshotRecord{exactPage(model.SnapshotRecord{ID: "snap-pre", JobKey: "build", LeaseGeneration: 1, Phase: model.SnapshotPhasePreJob, CreatedAt: time.Now().UTC()})},
		nil,
		map[string][]byte{"snap-pre": snapshotArchive(t)},
	)
	probes := stubReplayQuota(t, executor.DiskQuotaStatus{Detail: "must not be consulted"}, nil)
	if err := Replay(context.Background(), []string{"--server", env.srv.URL, "run1", "build"}); err != nil {
		t.Fatalf("trusted replay: %v", err)
	}
	if *probes != 0 {
		t.Fatalf("quota probe calls for a trusted job = %d, want 0", *probes)
	}
}

// TestReplayExactEnforcesUntrustedFloor: an untrusted recorded job must be
// replayed under the untrusted network/sandbox/resource floor even when the
// persisted fields pretend otherwise (network=internet). The recorded
// effective policy is the authority; the persisted network field is ignored
// whenever a verified payload policy exists, and the untrusted floor toggles
// the immutable-image requirement and the mandatory workspace bound.
func TestReplayExactEnforcesUntrustedFloor(t *testing.T) {
	historical := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo historical\n"
	untrusted := untrustedRecord(t, historical, "build")
	env := newExactReplayEnv(t,
		untrusted,
		[][]model.SnapshotRecord{exactPage(
			model.SnapshotRecord{ID: "snap-pre", JobKey: "build", LeaseGeneration: 1, Phase: model.SnapshotPhasePreJob, CreatedAt: time.Now().UTC()},
		)},
		nil,
		map[string][]byte{"snap-pre": snapshotArchive(t)},
	)
	gotOptions := captureReplayOptions(t)
	// The recorded effective execution demands the hard workspace quota; the
	// probe reports a supported host so the replay reaches the sandbox floor.
	stubReplayQuota(t, executor.DiskQuotaStatus{Hard: true, Limit: 10 << 30, Detail: "fake XFS project quota"}, nil)
	// The untrusted floor demands non-root, which the native runtime cannot
	// enforce: the replay must finish with failures instead of silently
	// running the job under weaker conditions.
	replayErr := Replay(context.Background(), []string{"--server", env.srv.URL, "run1", "build"})
	if replayErr == nil || !strings.Contains(replayErr.Error(), "failures") {
		t.Fatalf("untrusted replay = %v, want the sandbox-floor refusal", replayErr)
	}
	opts, ok := gotOptions()
	if !ok {
		t.Fatal("replay options seam never fired")
	}
	if !opts.Untrusted || !opts.RequireImmutableImages {
		t.Fatalf("replay options = untrusted %t immutable %t, want the untrusted floor", opts.Untrusted, opts.RequireImmutableImages)
	}
	if opts.WorkspaceMaxBytes != execution.DefaultUntrustedWorkspaceMaxBytes {
		t.Fatalf("WorkspaceMaxBytes = %d, want the untrusted default %d", opts.WorkspaceMaxBytes, execution.DefaultUntrustedWorkspaceMaxBytes)
	}
}

// TestReplayExactPrefersPreJobSnapshot: when an attempt has BOTH a pre_job
// checkpoint and a post_job outcome snapshot, exact replay must select the
// pre_job record (the only state that predates the attempt's mutations).
func TestReplayExactPrefersPreJobSnapshot(t *testing.T) {
	historical := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo historical\n"
	now := time.Now().UTC()
	env := newExactReplayEnv(t,
		recordedExport(t, historical, "build", nil),
		[][]model.SnapshotRecord{exactPage(
			model.SnapshotRecord{ID: "snap-pre", JobKey: "build", LeaseGeneration: 1, Phase: model.SnapshotPhasePreJob, CreatedAt: now},
			model.SnapshotRecord{ID: "snap-post", JobKey: "build", LeaseGeneration: 1, Phase: model.SnapshotPhasePostJob, CreatedAt: now.Add(time.Second)},
		)},
		nil,
		map[string][]byte{"snap-pre": snapshotArchive(t), "snap-post": snapshotArchive(t)},
	)
	if err := Replay(context.Background(), []string{"--server", env.srv.URL, "run1", "build"}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(env.downloads) != 1 || env.downloads[0] != "snap-pre" {
		t.Fatalf("downloaded %v, want the pre_job snapshot", env.downloads)
	}
	if err := Replay(context.Background(), []string{"--server", env.srv.URL, "--attempt", "1", "run1", "build"}); err != nil {
		t.Fatalf("replay attempt 1: %v", err)
	}
	if len(env.downloads) != 2 || env.downloads[1] != "snap-pre" {
		t.Fatalf("downloaded %v, want snap-pre for the requested attempt", env.downloads)
	}
}

// TestReplayExactRefusesPostJobOnlyAndEscapeHatch: an attempt whose only
// snapshot is the post-execution outcome must be REFUSED with an actionable
// error naming the problem, and --allow-post-job-snapshot must select it with
// a printed warning that execution starts from post-execution state.
func TestReplayExactRefusesPostJobOnlyAndEscapeHatch(t *testing.T) {
	historical := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo historical\n"
	env := newExactReplayEnv(t,
		recordedExport(t, historical, "build", nil),
		[][]model.SnapshotRecord{exactPage(
			model.SnapshotRecord{ID: "snap-post", JobKey: "build", LeaseGeneration: 1, Phase: model.SnapshotPhasePostJob, CreatedAt: time.Now().UTC()},
		)},
		nil,
		map[string][]byte{"snap-post": snapshotArchive(t)},
	)
	err := Replay(context.Background(), []string{"--server", env.srv.URL, "run1", "build"})
	if err == nil || !strings.Contains(err.Error(), "pre_job") || !strings.Contains(err.Error(), "--allow-post-job-snapshot") {
		t.Fatalf("post-job-only refusal = %v, want the actionable pre_job/escape-hatch error", err)
	}
	if len(env.downloads) != 0 {
		t.Fatalf("downloaded %v despite the refusal", env.downloads)
	}

	origStderr := os.Stderr
	pipeR, pipeW, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	os.Stderr = pipeW
	replayErr := Replay(context.Background(), []string{"--server", env.srv.URL, "--allow-post-job-snapshot", "run1", "build"})
	_ = pipeW.Close()
	os.Stderr = origStderr
	warned, _ := io.ReadAll(pipeR)
	if replayErr != nil {
		t.Fatalf("escape-hatch replay: %v", replayErr)
	}
	if len(env.downloads) != 1 || env.downloads[0] != "snap-post" {
		t.Fatalf("downloaded %v, want snap-post under the escape hatch", env.downloads)
	}
	if !strings.Contains(string(warned), "POST-execution") {
		t.Fatalf("missing post-execution warning: %q", string(warned))
	}
}
