package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func fsTestRepo(t *testing.T) *Repository {
	t.Helper()
	return New(filepath.Join(t.TempDir(), "state"))
}

func TestFSRepositorySaveLoadRoundTrip(t *testing.T) {
	repo := fsTestRepo(t)
	now := time.Now().UTC().Truncate(time.Second)
	in := Snapshot{
		Version: 99,
		Runs: map[string]model.Run{
			"run-1": {ID: "run-1", Repo: "https://github.com/acme/api.git", Status: model.StatusQueued, CreatedAt: now},
		},
		Jobs: map[string]model.Job{
			"job-1": {ID: "job-1", RunID: "run-1", Key: "build", Status: model.StatusQueued, CreatedAt: now},
		},
		Runners: map[string]model.Runner{
			"runner-1": {ID: "runner-1", Name: "r1", Capacity: 2, LastSeen: now},
		},
		Artifacts: map[string]model.ArtifactRecord{
			"art-1": {ID: "art-1", RunID: "run-1", Name: "bin", SHA256: "abc"},
		},
		Reports: map[string]model.TestReport{
			"rep-1": {ID: "rep-1", RunID: "run-1", Tests: 3},
		},
		DownstreamLinks: map[string]DownstreamLink{
			"link-1": {ParentJobID: "job-1", TargetRepo: "acme/other", TargetRef: "main"},
		},
		Profiles: map[string]model.RunnerProfile{
			"prof-1": {ID: "prof-1", MaxCapacity: 4},
		},
		CertProfileLinks: map[string]string{"serial-1": "prof-1"},
	}
	if err := repo.Save(in); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := repo.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if out.Version != 1 {
		t.Fatalf("Save must stamp Version 1, got %d", out.Version)
	}
	if len(out.Runs) != 1 || out.Runs["run-1"].Repo != in.Runs["run-1"].Repo {
		t.Fatalf("runs not round-tripped: %+v", out.Runs)
	}
	if len(out.Jobs) != 1 || out.Jobs["job-1"].Key != "build" {
		t.Fatalf("jobs not round-tripped: %+v", out.Jobs)
	}
	if len(out.Runners) != 1 || out.Runners["runner-1"].Capacity != 2 {
		t.Fatalf("runners not round-tripped: %+v", out.Runners)
	}
	if len(out.Artifacts) != 1 || out.Artifacts["art-1"].SHA256 != "abc" {
		t.Fatalf("artifacts not round-tripped: %+v", out.Artifacts)
	}
	if len(out.Reports) != 1 || out.Reports["rep-1"].Tests != 3 {
		t.Fatalf("reports not round-tripped: %+v", out.Reports)
	}
	if out.DownstreamLinks["link-1"].TargetRef != "main" {
		t.Fatalf("downstream links not round-tripped: %+v", out.DownstreamLinks)
	}
	if out.Profiles["prof-1"].MaxCapacity != 4 {
		t.Fatalf("profiles not round-tripped: %+v", out.Profiles)
	}
	if out.CertProfileLinks["serial-1"] != "prof-1" {
		t.Fatalf("cert profile links not round-tripped: %+v", out.CertProfileLinks)
	}
}

func TestFSLoadMissingFileReturnsDefaults(t *testing.T) {
	repo := fsTestRepo(t)
	out, err := repo.Load()
	if err != nil {
		t.Fatalf("load on missing root: %v", err)
	}
	if out.Version != 1 {
		t.Fatalf("default version = %d, want 1", out.Version)
	}
	for name, nonNil := range map[string]bool{
		"runs":      out.Runs != nil,
		"jobs":      out.Jobs != nil,
		"runners":   out.Runners != nil,
		"artifacts": out.Artifacts != nil,
		"reports":   out.Reports != nil,
	} {
		if !nonNil {
			t.Errorf("%s: expected non-nil default map", name)
		}
	}
	// The additive maps stay nil on the missing-file path: their absence is
	// the documented signal that the snapshot predates the feature.
	if out.DownstreamLinks != nil || out.Profiles != nil || out.CertProfileLinks != nil {
		t.Fatalf("additive maps must stay nil on a missing snapshot: %+v", out)
	}
}

func TestFSLoadNilPayloadMapsAreFilled(t *testing.T) {
	dir := t.TempDir()
	repo := New(dir)
	payload := `{"version":1,"runs":null,"jobs":null,"runners":null,"artifacts":null,"reports":null}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(payload), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	out, err := repo.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if out.Runs == nil || out.Jobs == nil || out.Runners == nil || out.Artifacts == nil ||
		out.Reports == nil || out.DownstreamLinks == nil || out.Profiles == nil || out.CertProfileLinks == nil {
		t.Fatalf("nil maps must be filled on load: %+v", out)
	}
}

func TestFSLoadCorruptStateFails(t *testing.T) {
	dir := t.TempDir()
	repo := New(dir)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	_, err := repo.Load()
	if err == nil {
		t.Fatal("expected decode error")
	}
	if !strings.Contains(err.Error(), "decode state:") {
		t.Fatalf("error = %v, want decode state prefix", err)
	}
}

func TestFSLoadReadErrorIsNotNotExist(t *testing.T) {
	dir := t.TempDir()
	// Root is a regular file: joining "state.json" under it makes ReadFile
	// fail with ENOTDIR rather than ErrNotExist.
	root := filepath.Join(dir, "rootfile")
	if err := os.WriteFile(root, []byte("x"), 0o600); err != nil {
		t.Fatalf("write root file: %v", err)
	}
	repo := New(root)
	_, err := repo.Load()
	if err == nil {
		t.Fatal("expected read error when root is a file")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error = %v, expected a non-not-exist read error", err)
	}
}

func TestFSSaveMkdirError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	repo := New(filepath.Join(blocker, "nested"))
	if err := repo.Save(Snapshot{}); err == nil {
		t.Fatal("expected MkdirAll error when root parent is a file")
	}
}

func TestFSSaveMarshalError(t *testing.T) {
	repo := fsTestRepo(t)
	err := repo.Save(Snapshot{Profiles: map[string]model.RunnerProfile{"p": {ID: "p", CostPerHour: math.Inf(1)}}})
	if err == nil {
		t.Fatal("expected marshal error for non-finite float")
	}
}

func TestFSSaveWriteError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-based failure is not enforceable as root")
	}
	dir := t.TempDir()
	inner := filepath.Join(dir, "ro")
	if err := os.Mkdir(inner, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(inner, 0o700) })
	repo := New(inner)
	if err := repo.Save(Snapshot{}); err == nil {
		t.Fatal("expected write error in read-only root")
	}
}

func TestFSAppendAndReadLogsAndAudit(t *testing.T) {
	repo := fsTestRepo(t)
	now := time.Now().UTC()
	for i := int64(1); i <= 5; i++ {
		if err := repo.AppendLog(model.LogEntry{Seq: i, RunID: "run-1", Line: "line"}); err != nil {
			t.Fatalf("append log %d: %v", i, err)
		}
	}
	if err := repo.AppendLog(model.LogEntry{Seq: 6, RunID: "run-2", Line: "other"}); err != nil {
		t.Fatalf("append other log: %v", err)
	}
	if err := repo.AppendAudit(model.AuditEvent{ID: "a1", Action: "run.created", CreatedAt: now}); err != nil {
		t.Fatalf("append audit: %v", err)
	}
	if err := repo.AppendAudit(model.AuditEvent{ID: "a2", Action: "run.finished", CreatedAt: now}); err != nil {
		t.Fatalf("append audit: %v", err)
	}

	got, err := repo.ReadLogs("run-1", 2, 0)
	if err != nil {
		t.Fatalf("read logs: %v", err)
	}
	if len(got) != 3 || got[0].Seq != 3 || got[2].Seq != 5 {
		t.Fatalf("read logs = %+v, want seq 3..5", got)
	}
	got, err = repo.ReadLogs("run-1", 20, 10)
	if err != nil {
		t.Fatalf("read logs after: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("after=20 must yield nothing, got %+v", got)
	}
	got, err = repo.ReadLogs("run-1", 0, 10001)
	if err != nil {
		t.Fatalf("read logs limit overflow: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("limit>10000 defaults to 2000, got %d entries", len(got))
	}
	got, err = repo.ReadLogs("run-1", 0, 2)
	if err != nil {
		t.Fatalf("read logs limited: %v", err)
	}
	if len(got) != 2 || got[0].Seq != 4 {
		t.Fatalf("limit keeps the last entries, got %+v", got)
	}

	audit, err := repo.ReadAudit(0)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if len(audit) != 2 || audit[0].ID != "a1" {
		t.Fatalf("read audit = %+v", audit)
	}
	audit, err = repo.ReadAudit(10001)
	if err != nil {
		t.Fatalf("read audit limit overflow: %v", err)
	}
	if len(audit) != 2 {
		t.Fatalf("read audit = %+v", audit)
	}
}

func TestFSReadLogsMissingFileIsEmpty(t *testing.T) {
	repo := fsTestRepo(t)
	got, err := repo.ReadLogs("run-1", 0, 10)
	if err != nil || len(got) != 0 {
		t.Fatalf("missing logs = %+v, %v", got, err)
	}
	audit, err := repo.ReadAudit(10)
	if err != nil || len(audit) != 0 {
		t.Fatalf("missing audit = %+v, %v", audit, err)
	}
}

func TestFSReadJSONLErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "corrupt.jsonl"), []byte("not-json\n"), 0o600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	if _, err := readJSONL[model.LogEntry](filepath.Join(dir, "corrupt.jsonl"), 10, func(model.LogEntry) bool { return true }); err == nil {
		t.Fatal("expected decode error for corrupt jsonl")
	}
	if err := os.Mkdir(filepath.Join(dir, "adir.jsonl"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := readJSONL[model.LogEntry](filepath.Join(dir, "adir.jsonl"), 10, func(model.LogEntry) bool { return true }); err == nil {
		t.Fatal("expected read error for directory path")
	}
	if _, err := readJSONL[model.LogEntry](filepath.Join(dir, "missing.jsonl"), 10, func(model.LogEntry) bool { return true }); err != nil {
		t.Fatalf("missing file must be empty, got %v", err)
	}
	if os.Geteuid() == 0 {
		return
	}
	secret := filepath.Join(dir, "secret.jsonl")
	if err := os.WriteFile(secret, []byte("{}\n"), 0o000); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o600) })
	if _, err := readJSONL[model.LogEntry](secret, 10, func(model.LogEntry) bool { return true }); err == nil {
		t.Fatal("expected open error for unreadable file")
	}
}

func TestFSReadJSONLTrimsToLimitAndSkipsFiltered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "many.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	enc := json.NewEncoder(f)
	for i := int64(1); i <= 5; i++ {
		if err := enc.Encode(model.LogEntry{Seq: i, RunID: "run", Line: "l"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	out, err := readJSONL[model.LogEntry](path, 2, func(model.LogEntry) bool { return true })
	if err != nil {
		t.Fatalf("readJSONL: %v", err)
	}
	if len(out) != 2 || out[0].Seq != 4 || out[1].Seq != 5 {
		t.Fatalf("trim to limit failed: %+v", out)
	}
	out, err = readJSONL[model.LogEntry](path, 10, func(e model.LogEntry) bool { return e.Seq <= 2 })
	if err != nil {
		t.Fatalf("readJSONL filtered: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("filter ignored: %+v", out)
	}
}

func TestFSAppendJSONLErrors(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	repo := New(filepath.Join(blocker, "nested"))
	if err := repo.AppendLog(model.LogEntry{RunID: "run"}); err == nil {
		t.Fatal("expected MkdirAll error")
	}
	if err := repo.AppendAudit(model.AuditEvent{ID: "a"}); err == nil {
		t.Fatal("expected MkdirAll error")
	}

	if os.Geteuid() == 0 {
		t.Skip("permission-based failure is not enforceable as root")
	}
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatalf("mkdir ro: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
	roRepo := New(ro)
	if err := roRepo.AppendLog(model.LogEntry{RunID: "run"}); err == nil {
		t.Fatal("expected OpenFile error in read-only root")
	}

	encRepo := fsTestRepo(t)
	if err := encRepo.appendJSONL("funcs.jsonl", func() {}); err == nil {
		t.Fatal("expected encode error for unsupported value")
	}
}

func TestFSMaxLogSeq(t *testing.T) {
	repo := fsTestRepo(t)
	got, err := repo.MaxLogSeq()
	if err != nil || got != 0 {
		t.Fatalf("missing logs max seq = %d, %v", got, err)
	}
	for _, seq := range []int64{4, 11, 7} {
		if err := repo.AppendLog(model.LogEntry{Seq: seq, RunID: "run"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	got, err = repo.MaxLogSeq()
	if err != nil {
		t.Fatalf("max seq: %v", err)
	}
	if got != 11 {
		t.Fatalf("max seq = %d, want 11", got)
	}

	dir := t.TempDir()
	corrupt := New(dir)
	if err := os.WriteFile(filepath.Join(dir, "logs.jsonl"), []byte("nope\n"), 0o600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	if _, err := corrupt.MaxLogSeq(); err == nil {
		t.Fatal("expected decode error on corrupt log")
	}

	rootFile := filepath.Join(dir, "rootfile")
	if err := os.WriteFile(rootFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write root file: %v", err)
	}
	if _, err := New(rootFile).MaxLogSeq(); err == nil {
		t.Fatal("expected open error when root is a regular file")
	}
}

func TestFSJSONLStreamFinished(t *testing.T) {
	if jsonlStreamFinished(nil) {
		t.Fatal("nil error must not finish a stream")
	}
	if jsonlStreamFinished(errors.New("boom")) {
		t.Fatal("unexpected error must not finish a stream")
	}
	if !jsonlStreamFinished(io.EOF) {
		t.Fatal("io.EOF must finish a stream")
	}
	if !jsonlStreamFinished(os.ErrClosed) {
		t.Fatal("os.ErrClosed must finish a stream")
	}
	if !jsonlStreamFinished(fmt.Errorf("read: %w", io.EOF)) {
		t.Fatal("wrapped io.EOF must finish a stream")
	}
}
