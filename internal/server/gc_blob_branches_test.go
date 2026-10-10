package server

// Run-retention cascade and blob-verification branches: the fs-mode
// pruneRunsLocked sweep over every derived index, the delivery/job-lock
// pruners, the temp-file sweeper age gates, and the direct verifyStoredBlob
// read-back failures. All state is in-memory or on a temp dir; no forge API
// or database is involved.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func TestPruneRunsLockedCascadeAndBounds(t *testing.T) {
	s := New("secret")
	s.RunRetention = time.Hour
	s.MaxRetainedRuns = 1
	now := time.Now().UTC()
	old := now.Add(-2 * time.Hour)
	recent := now.Add(-time.Minute)

	newRun := func(id string, status model.Status, at time.Time) model.Run {
		fin := at
		return model.Run{ID: id, Status: status, CreatedAt: at, FinishedAt: &fin}
	}
	s.runs["old-run"] = newRun("old-run", model.StatusSuccess, old)
	s.runs["new-run"] = newRun("new-run", model.StatusSuccess, recent)
	s.runs["live-run"] = model.Run{ID: "live-run", Status: model.StatusRunning, CreatedAt: old}
	s.jobs["old-job"] = model.Job{ID: "old-job", RunID: "old-run"}
	s.jobs["live-job"] = model.Job{ID: "live-job", RunID: "live-run"}
	s.reports["old-report"] = model.TestReport{ID: "old-report", RunID: "old-run"}
	s.snapshots["old-snap"] = model.SnapshotRecord{ID: "old-snap", RunID: "old-run"}
	s.deployments["old-deploy"] = model.Deployment{ID: "old-deploy", RunID: "old-run", JobID: "old-job"}
	s.completions["old-key"] = model.CompletionReceipt{JobID: "old-job", Generation: 1}
	s.completionReceiptAt["old-key"] = old
	s.deliveries["delivery-1"] = "old-run"
	s.downstreamLinks["link-1"] = storage.DownstreamLink{ParentJobID: "old-job", TargetRepo: "acme/child"}
	s.occurrences["sched-1"] = map[int64]string{1: "old-run", 2: "live-run"}
	s.orphanOccurrences["sched-1\x001\x00old-run"] = true

	ids := s.pruneRunsLocked(now)
	if len(ids) != 2 || ids[0] != "new-run" || ids[1] != "old-run" {
		t.Fatalf("pruned ids = %v, want [new-run old-run] (retention + max-bound)", ids)
	}
	if _, ok := s.runs["old-run"]; ok {
		t.Fatal("old run survived")
	}
	// The live run occupies the single retained slot, so the newest terminal
	// run is also pruned by the max-retained bound.
	if _, ok := s.runs["new-run"]; ok {
		t.Fatal("max-retention bound did not prune the terminal run")
	}
	if _, ok := s.runs["live-run"]; !ok {
		t.Fatal("non-terminal run pruned")
	}
	if _, ok := s.jobs["old-job"]; ok {
		t.Fatal("job of pruned run survived")
	}
	if _, ok := s.jobs["live-job"]; !ok {
		t.Fatal("live job pruned")
	}
	if _, ok := s.reports["old-report"]; ok {
		t.Fatal("report survived")
	}
	if _, ok := s.snapshots["old-snap"]; ok {
		t.Fatal("snapshot survived")
	}
	if _, ok := s.deployments["old-deploy"]; ok {
		t.Fatal("deployment survived")
	}
	if _, ok := s.completions["old-key"]; ok {
		t.Fatal("completion receipt survived")
	}
	if _, ok := s.completionReceiptAt["old-key"]; ok {
		t.Fatal("completion receipt timestamp survived")
	}
	if _, ok := s.deliveries["delivery-1"]; ok {
		t.Fatal("delivery receipt survived")
	}
	if _, ok := s.downstreamLinks["link-1"]; ok {
		t.Fatal("downstream link survived")
	}
	if occ := s.occurrences["sched-1"]; len(occ) != 1 || occ[2] != "live-run" {
		t.Fatalf("occurrences = %v, want the live claim kept", occ)
	}
	if _, ok := s.orphanOccurrences["sched-1\x001\x00old-run"]; ok {
		t.Fatal("orphan occurrence claim survived")
	}

	// Disabled retention and DB mode are no-ops.
	s.RunRetention = 0
	s.MaxRetainedRuns = 0
	if ids := s.pruneRunsLocked(now); ids != nil {
		t.Fatalf("disabled retention pruned %v", ids)
	}
	s.RunRetention = time.Hour
	s.DB = newDBFakeStore()
	if ids := s.pruneRunsLocked(now); ids != nil {
		t.Fatalf("DB mode pruned %v", ids)
	}
	s.DB = nil

	// No candidates is a no-op.
	empty := New("secret")
	empty.RunRetention = time.Hour
	if ids := empty.pruneRunsLocked(now); ids != nil {
		t.Fatalf("empty server pruned %v", ids)
	}
}

func TestPruneDeliveriesAndJobLocks(t *testing.T) {
	s := New("secret")
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	recent := now.Add(-time.Minute)
	s.runs["old-run"] = model.Run{ID: "old-run", CreatedAt: old}
	s.runs["new-run"] = model.Run{ID: "new-run", CreatedAt: recent}
	s.deliveries["dangling"] = "missing-run"
	s.deliveries["old"] = "old-run"
	s.deliveries["new"] = "new-run"
	s.pruneDeliveriesLocked(now)
	if _, ok := s.deliveries["dangling"]; ok {
		t.Fatal("delivery for a missing run survived")
	}
	if _, ok := s.deliveries["old"]; ok {
		t.Fatal("aged delivery survived")
	}
	if _, ok := s.deliveries["new"]; !ok {
		t.Fatal("recent delivery pruned")
	}

	s.jobs["live-job"] = model.Job{ID: "live-job"}
	s.jobLocks["live-job"] = nil
	s.jobLocks["stale-job"] = nil
	s.pruneJobLocksLocked()
	if _, ok := s.jobLocks["stale-job"]; ok {
		t.Fatal("stale job lock survived")
	}
	if _, ok := s.jobLocks["live-job"]; !ok {
		t.Fatal("live job lock pruned")
	}
}

func TestSweepTempFilesAgeGates(t *testing.T) {
	if n := sweepTempFiles("", time.Now()); n != 0 {
		t.Fatalf("empty root swept %d", n)
	}
	root := t.TempDir()
	if n := sweepTempFiles(root, time.Now()); n != 0 {
		t.Fatalf("missing dirs swept %d", n)
	}
	oldStamp := time.Now().Add(-2 * tempFileMaxAge)
	for _, sub := range []string{"artifacts", "cache"} {
		dir := filepath.Join(root, sub)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		oldTmp := filepath.Join(dir, "old.tmp")
		if err := os.WriteFile(oldTmp, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(oldTmp, oldStamp, oldStamp); err != nil {
			t.Fatal(err)
		}
		freshTmp := filepath.Join(dir, "fresh.tmp")
		if err := os.WriteFile(freshTmp, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "keep.bin"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if n := sweepTempFiles(root, time.Now()); n != 2 {
		t.Fatalf("swept %d files, want 2 aged temp files", n)
	}
	for _, sub := range []string{"artifacts", "cache"} {
		for _, name := range []string{"old.tmp"} {
			if _, err := os.Stat(filepath.Join(root, sub, name)); !os.IsNotExist(err) {
				t.Fatalf("%s/%s not removed: %v", sub, name, err)
			}
		}
		for _, name := range []string{"fresh.tmp", "keep.bin"} {
			if _, err := os.Stat(filepath.Join(root, sub, name)); err != nil {
				t.Fatalf("%s/%s removed: %v", sub, name, err)
			}
		}
	}
}

func TestVerifyStoredBlobReadBack(t *testing.T) {
	ctx := context.Background()
	c := cas.New(newMemBlob())
	payload := "verified-payload"
	obj, err := c.Put(ctx, strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyStoredBlob(ctx, c, obj.SHA256, obj.Size); err != nil {
		t.Fatalf("matching read-back = %v, want nil", err)
	}
	if err := verifyStoredBlob(ctx, c, obj.SHA256, obj.Size+1); err == nil {
		t.Fatal("read-back with a wrong expected size succeeded")
	}
	if err := verifyStoredBlob(ctx, c, "0000000000000000000000000000000000000000000000000000000000000000", 1); err == nil {
		t.Fatal("read-back of a missing digest succeeded")
	}
}

func TestEffectivePolicyDigestBranches(t *testing.T) {
	if got := effectivePolicyDigest(nil); got != "" {
		t.Fatalf("nil payload digest = %q", got)
	}
	if got := effectivePolicyDigest(&model.CompiledJobPayload{}); got != "" {
		t.Fatalf("nil policy digest = %q", got)
	}
	p := &model.CompiledJobPayload{EffectivePolicy: map[string]any{"network": "deny"}}
	first := effectivePolicyDigest(p)
	if first == "" {
		t.Fatal("policy digest omitted for a decoded policy")
	}
	if second := effectivePolicyDigest(p); second != first {
		t.Fatalf("digest not canonical: %q vs %q", first, second)
	}
}

func TestExecutionCapsuleDigestOmissionBranches(t *testing.T) {
	if got := executionCapsuleDigestForJob(model.Job{}); got != "" {
		t.Fatalf("bare job digest = %q, want omitted", got)
	}
	if got := executionCapsuleDigestForJob(model.Job{Pipeline: "version: 1\njobs: {}\n"}); got != "" {
		t.Fatalf("job without a compiled payload digest = %q, want omitted", got)
	}
	if got := executionCapsuleDigestForJob(model.Job{Pipeline: "not: [valid", CompiledJobPayload: &model.CompiledJobPayload{}}); got != "" {
		t.Fatalf("unparseable pipeline digest = %q, want omitted", got)
	}
	validPipeline := "version: 1\njobs:\n  j:\n    runtime: container\n    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    steps:\n      - run: echo hi\n"
	if got := executionCapsuleDigestForJob(model.Job{Key: "j", Pipeline: validPipeline, CompiledJobPayload: &model.CompiledJobPayload{}}); got != "" {
		t.Fatalf("unbound compiled payload digest = %q, want omitted", got)
	}
}
