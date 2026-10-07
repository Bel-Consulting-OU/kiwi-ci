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

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// recordedExport builds the control plane's exact-replay export body for one
// job of text with coherent digests; mutate, when non-nil, tampers the
// payload after the digests are computed (simulating a corrupt record).
func recordedExport(t *testing.T, text, key string, mutate func(*model.CompiledJobPayload)) string {
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
		[][]model.SnapshotRecord{exactPage(model.SnapshotRecord{ID: "snap1", JobKey: "build", LeaseGeneration: 1, CreatedAt: time.Now().UTC()})},
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
		[][]model.SnapshotRecord{exactPage(model.SnapshotRecord{ID: "snap1", JobKey: "build", LeaseGeneration: 1, CreatedAt: time.Now().UTC()})},
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
			model.SnapshotRecord{ID: "snap-old", JobKey: "build", LeaseGeneration: 1, CreatedAt: now.Add(-time.Hour)},
			model.SnapshotRecord{ID: "snap-new", JobKey: "build", LeaseGeneration: 2, CreatedAt: now},
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
		[][]model.SnapshotRecord{exactPage(model.SnapshotRecord{ID: "snap1", JobKey: "build", LeaseGeneration: 1, CreatedAt: time.Now().UTC()})},
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
			exactPage(model.SnapshotRecord{ID: "snap1", JobKey: "build", LeaseGeneration: 1, CreatedAt: now.Add(-time.Hour)}),
			exactPage(model.SnapshotRecord{ID: "snap2", JobKey: "build", LeaseGeneration: 2, CreatedAt: now}),
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
		[][]model.SnapshotRecord{exactPage(model.SnapshotRecord{ID: "snap1", JobKey: "build", LeaseGeneration: 1, CreatedAt: time.Now().UTC()})},
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
