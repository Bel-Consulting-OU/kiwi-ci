package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestCompletionResultDigestCanonicalAndVersioned pins the v2 canonical
// encoding: determinism under map order, every field bound, nil runtime
// distinct from an empty one, and the legacy v1 computation preserved byte
// for byte for the compatibility path.
func TestCompletionResultDigestCanonicalAndVersioned(t *testing.T) {
	runtimeA := &model.ObservedRuntime{OS: "linux", Arch: "amd64", ServiceImages: map[string]string{"b": "2", "a": "1"}}
	runtimeAReordered := &model.ObservedRuntime{OS: "linux", Arch: "amd64", ServiceImages: map[string]string{"a": "1", "b": "2"}}
	outs := map[string]string{"x": "1", "y": "2"}
	outsReordered := map[string]string{"y": "2", "x": "1"}

	base := CompletionResultDigestV2(model.StatusSuccess, "boom", outs, runtimeA)
	if len(base) != 64 {
		t.Fatalf("v2 digest = %q, want 64 hex chars", base)
	}
	if again := CompletionResultDigestV2(model.StatusSuccess, "boom", outsReordered, runtimeAReordered); again != base {
		t.Fatalf("v2 digest not canonical: %q != %q", again, base)
	}
	diffs := map[string]string{
		"status":   CompletionResultDigestV2(model.StatusFailure, "boom", outs, runtimeA),
		"error":    CompletionResultDigestV2(model.StatusSuccess, "other", outs, runtimeA),
		"outputs":  CompletionResultDigestV2(model.StatusSuccess, "boom", map[string]string{"x": "1", "y": "3"}, runtimeA),
		"runtime":  CompletionResultDigestV2(model.StatusSuccess, "boom", outs, &model.ObservedRuntime{OS: "linux", Arch: "arm64"}),
		"nil run":  CompletionResultDigestV2(model.StatusSuccess, "boom", outs, nil),
		"empty rt": CompletionResultDigestV2(model.StatusSuccess, "boom", outs, &model.ObservedRuntime{}),
	}
	for name, got := range diffs {
		if got == base {
			t.Fatalf("v2 digest did not change with %s", name)
		}
	}
	// nil and empty runtimes are distinct evidence.
	if diffs["nil run"] == diffs["empty rt"] {
		t.Fatal("nil runtime encoded identically to an empty runtime")
	}

	// V1 is the historical computation, unchanged.
	wantV1 := referenceCompletionResultHashV1(model.StatusSuccess, "boom", outs)
	if got := CompletionResultDigestV1(model.StatusSuccess, "boom", outs); got != wantV1 {
		t.Fatalf("v1 digest = %q, want the historical computation %q", got, wantV1)
	}
	// V1 ignores runtime by construction; V2 must not equal it.
	if base == wantV1 {
		t.Fatal("v2 digest equals the v1 digest")
	}
}

// referenceCompletionResultHashV1 re-implements the pre-versioning server
// computation independently, so the compatibility digest cannot silently
// drift from what already-shipped receipts contain.
func referenceCompletionResultHashV1(status model.Status, errMsg string, outputs map[string]string) string {
	outJSON, _ := json.Marshal(outputs)
	h := sha256.New()
	_, _ = io.WriteString(h, string(status))
	_, _ = h.Write([]byte{0})
	_, _ = io.WriteString(h, errMsg)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(outJSON)
	return hex.EncodeToString(h.Sum(nil))
}

// TestCompletionReceiptReplayMatchesVersionMatrix pins the replay resolution
// contract: v2 compares digests, v1 additionally requires nil-or-equal runtime
// evidence, and a v2-evidence-bearing retry never masquerades as the legacy
// identity.
func TestCompletionReceiptReplayMatchesVersionMatrix(t *testing.T) {
	status, errMsg := model.StatusSuccess, ""
	outs := map[string]string{"o": "1"}
	runtimeA := &model.ObservedRuntime{OS: "linux", Arch: "amd64"}
	runtimeB := &model.ObservedRuntime{OS: "linux", Arch: "arm64"}

	v2A := CompletionResultDigestV2(status, errMsg, outs, runtimeA)
	v2B := CompletionResultDigestV2(status, errMsg, outs, runtimeB)
	v2Nil := CompletionResultDigestV2(status, errMsg, outs, nil)
	v1 := CompletionResultDigestV1(status, errMsg, outs)

	storedV2 := model.CompletionReceipt{ResultHash: v2A, ResultHashVersion: CompletionResultHashVersionV2}
	storedV1 := model.CompletionReceipt{ResultHash: v1, ResultHashVersion: CompletionResultHashVersionLegacy}
	storedLegacyZero := model.CompletionReceipt{ResultHash: v1} // pre-field record

	cases := []struct {
		name            string
		stored          model.CompletionReceipt
		requestHash     string
		requestVersion  int
		requestObserved *model.ObservedRuntime
		storedObserved  *model.ObservedRuntime
		want            bool
	}{
		{"v2 identical", storedV2, v2A, 0, runtimeA, nil, true},
		{"v2 changed runtime", storedV2, v2B, 0, runtimeB, nil, false},
		{"v2 changed outputs", storedV2, CompletionResultDigestV2(status, errMsg, map[string]string{"o": "2"}, runtimeA), 0, runtimeA, nil, false},
		{"v2 changed error", storedV2, CompletionResultDigestV2(status, "boom", outs, runtimeA), 0, runtimeA, nil, false},
		{"v1 request matches v1 receipt", storedV1, v1, CompletionResultHashVersionLegacy, nil, nil, true},
		{"v2 request without evidence matches v1 receipt", storedV1, v2Nil, 0, nil, nil, true},
		{"v2 request with new evidence conflicts with v1 receipt", storedV1, v2A, 0, runtimeA, nil, false},
		{"v2 request with equal stored evidence matches v1 receipt", storedV1, v2A, 0, runtimeA, runtimeA, true},
		{"v2 request with differing stored evidence conflicts", storedV1, v2A, 0, runtimeA, runtimeB, false},
		{"version-less stored receipt is legacy", storedLegacyZero, v2Nil, 0, nil, nil, true},
		{"version-less stored receipt rejects new evidence", storedLegacyZero, v2A, 0, runtimeA, nil, false},
		{"v2 stored receipt rejects a v1-labelled request", storedV2, v1, CompletionResultHashVersionLegacy, nil, nil, false},
	}
	for _, tc := range cases {
		got := CompletionReceiptReplayMatches(tc.stored, tc.requestHash, tc.requestVersion, status, errMsg, outs, tc.requestObserved, tc.storedObserved)
		if got != tc.want {
			t.Errorf("%s: match = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestMemCompletionV2BindsObservedRuntime proves the in-memory completion
// receipt is the v2 identity: a retried completion with changed runtime
// evidence, outputs, status or error conflicts instead of replaying, the
// identical replay is accepted, and the receipt is written exactly once.
func TestMemCompletionV2BindsObservedRuntime(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	const (
		jobID    = "job-v2"
		runID    = "run-v2"
		runnerID = "runner-v2"
	)
	wave1RunningJob(m, jobID, runID, runnerID)
	outs := map[string]string{"o": "1"}
	runtimeA := &model.ObservedRuntime{OS: "linux", Arch: "amd64", MainImage: "alpine:3.20"}
	receipt := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: CompletionResultDigestV2(model.StatusSuccess, "", outs, runtimeA)}
	if err := m.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", outs, receipt, runtimeA); err != nil {
		t.Fatalf("first completion: %v", err)
	}
	// Identical replay (same runtime evidence) is idempotent.
	if err := m.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", outs, receipt, runtimeA); err != nil {
		t.Fatalf("identical replay = %v, want nil", err)
	}
	// Contradictory runtime evidence for the same identity conflicts.
	runtimeB := &model.ObservedRuntime{OS: "linux", Arch: "arm64"}
	changedRuntime := receipt
	changedRuntime.ResultHash = CompletionResultDigestV2(model.StatusSuccess, "", outs, runtimeB)
	if err := m.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", outs, changedRuntime, runtimeB); !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("changed-runtime replay = %v, want ErrCompletionConflict", err)
	}
	// Changed outputs/status/error conflict under the v2 digest.
	changedOutputs := receipt
	changedOutputs.ResultHash = CompletionResultDigestV2(model.StatusSuccess, "", map[string]string{"o": "2"}, runtimeA)
	if err := m.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", map[string]string{"o": "2"}, changedOutputs, runtimeA); !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("changed-outputs replay = %v, want ErrCompletionConflict", err)
	}
	changedStatus := receipt
	changedStatus.ResultHash = CompletionResultDigestV2(model.StatusFailure, "", outs, runtimeA)
	if err := m.CompleteJob(ctx, jobID, 1, runnerID, model.StatusFailure, "", outs, changedStatus, runtimeA); !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("changed-status replay = %v, want ErrCompletionConflict", err)
	}
	changedError := receipt
	changedError.ResultHash = CompletionResultDigestV2(model.StatusFailure, "boom", outs, runtimeA)
	if err := m.CompleteJob(ctx, jobID, 1, runnerID, model.StatusFailure, "boom", outs, changedError, runtimeA); !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("changed-error replay = %v, want ErrCompletionConflict", err)
	}
	// Exactly one receipt, the first v2 identity, and the job evidence is the
	// first completion's.
	m.mu.Lock()
	stored := m.receipts[m.receiptKey(jobID, 1, runnerID)]
	receipts := len(m.receipts)
	j := m.jobs[jobID]
	m.mu.Unlock()
	if receipts != 1 {
		t.Fatalf("receipt rows = %d, want exactly 1", receipts)
	}
	if stored.ResultHash != receipt.ResultHash || stored.ResultHashVersion != CompletionResultHashVersionV2 {
		t.Fatalf("stored receipt = %+v, want the first v2 identity", stored)
	}
	if j.ObservedRuntime == nil || j.ObservedRuntime.Arch != runtimeA.Arch {
		t.Fatalf("contradictory attempts rewrote job runtime evidence: %+v", j.ObservedRuntime)
	}
}

// TestMemLegacyV1ReceiptRuntimeGate proves the compatibility rule for
// receipts written before the versioned digest: a v1-identical retry without
// runtime evidence replays, an evidence-bearing v2 retry conflicts unless the
// stored attempt evidence is equal, and the receipt stays v1.
func TestMemLegacyV1ReceiptRuntimeGate(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	const (
		jobID    = "job-v1"
		runID    = "run-v1"
		runnerID = "runner-v1"
	)
	wave1RunningJob(m, jobID, runID, runnerID)
	outs := map[string]string{"o": "1"}
	legacy := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: CompletionResultDigestV1(model.StatusSuccess, "", outs), ResultHashVersion: CompletionResultHashVersionLegacy}
	if err := m.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", outs, legacy, nil); err != nil {
		t.Fatalf("legacy completion: %v", err)
	}
	// A v1-labelled identical retry replays.
	if err := m.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", outs, legacy, nil); err != nil {
		t.Fatalf("legacy-identical replay = %v, want nil", err)
	}
	// A v2 retry without runtime evidence still resolves the legacy identity.
	v2NoRuntime := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: CompletionResultDigestV2(model.StatusSuccess, "", outs, nil)}
	if err := m.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", outs, v2NoRuntime, nil); err != nil {
		t.Fatalf("v2 replay without evidence = %v, want nil", err)
	}
	// A v2-evidence-bearing retry conflicts: the legacy receipt never bound
	// the runtime, and the stored attempt has none to compare.
	runtimeA := &model.ObservedRuntime{OS: "linux", Arch: "amd64"}
	v2WithRuntime := v2NoRuntime
	v2WithRuntime.ResultHash = CompletionResultDigestV2(model.StatusSuccess, "", outs, runtimeA)
	if err := m.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", outs, v2WithRuntime, runtimeA); !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("evidence-bearing retry against legacy receipt = %v, want ErrCompletionConflict", err)
	}
	m.mu.Lock()
	stored := m.receipts[m.receiptKey(jobID, 1, runnerID)]
	m.mu.Unlock()
	if stored.ResultHashVersion != CompletionResultHashVersionLegacy || stored.ResultHash != legacy.ResultHash {
		t.Fatalf("legacy receipt was rewritten: %+v", stored)
	}

	// A legacy completion that DID persist runtime evidence accepts a v2
	// retry carrying the same evidence (nil-or-equal) and rejects a different
	// capture.
	const job2 = "job-v1b"
	wave1RunningJob(m, job2, runID, runnerID)
	legacy2 := model.CompletionReceipt{JobID: job2, Generation: 1, RunnerID: runnerID, ResultHash: CompletionResultDigestV1(model.StatusSuccess, "", outs), ResultHashVersion: CompletionResultHashVersionLegacy}
	if err := m.CompleteJob(ctx, job2, 1, runnerID, model.StatusSuccess, "", outs, legacy2, runtimeA); err != nil {
		t.Fatalf("legacy completion with evidence: %v", err)
	}
	v2Equal := legacy2
	v2Equal.ResultHashVersion = 0
	v2Equal.ResultHash = CompletionResultDigestV2(model.StatusSuccess, "", outs, runtimeA)
	if err := m.CompleteJob(ctx, job2, 1, runnerID, model.StatusSuccess, "", outs, v2Equal, runtimeA); err != nil {
		t.Fatalf("v2 retry with equal stored evidence = %v, want nil", err)
	}
	runtimeB := &model.ObservedRuntime{OS: "linux", Arch: "arm64"}
	v2Different := v2Equal
	v2Different.ResultHash = CompletionResultDigestV2(model.StatusSuccess, "", outs, runtimeB)
	if err := m.CompleteJob(ctx, job2, 1, runnerID, model.StatusSuccess, "", outs, v2Different, runtimeB); !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("v2 retry with different stored evidence = %v, want ErrCompletionConflict", err)
	}
}

// TestMemAttemptScopedEvidenceQueries proves the in-memory attempt-scoped
// reads return exactly the requested attempt's records even with other jobs
// and generations present.
func TestMemAttemptScopedEvidenceQueries(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	m.artifacts = append(m.artifacts,
		model.ArtifactRecord{ID: "a1", RunID: "run", JobID: "job-a", Name: "bin", LeaseGeneration: 1},
		model.ArtifactRecord{ID: "a2", RunID: "run", JobID: "job-a", Name: "bin", LeaseGeneration: 2},
		model.ArtifactRecord{ID: "a3", RunID: "run", JobID: "job-b", Name: "bin", LeaseGeneration: 1},
	)
	m.reports = append(m.reports,
		model.TestReport{ID: "r1", RunID: "run", JobID: "job-a", LeaseGeneration: 1},
		model.TestReport{ID: "r2", RunID: "run", JobID: "job-a", LeaseGeneration: 2},
		model.TestReport{ID: "r3", RunID: "run", JobID: "job-b", LeaseGeneration: 1},
	)
	m.snapshots = append(m.snapshots,
		model.SnapshotRecord{ID: "s1", RunID: "run", JobID: "job-a", LeaseGeneration: 1},
		model.SnapshotRecord{ID: "s2", RunID: "run", JobID: "job-a", LeaseGeneration: 2},
		model.SnapshotRecord{ID: "s3", RunID: "run", JobID: "job-b", LeaseGeneration: 1},
	)

	arts, err := m.ListArtifactsByJobGeneration(ctx, "job-a", 1)
	if err != nil || len(arts) != 1 || arts[0].ID != "a1" {
		t.Fatalf("scoped artifacts = %+v err=%v, want exactly a1", arts, err)
	}
	reports, err := m.ListTestReportsByJobGeneration(ctx, "job-a", 1)
	if err != nil || len(reports) != 1 || reports[0].ID != "r1" {
		t.Fatalf("scoped reports = %+v err=%v, want exactly r1", reports, err)
	}
	snaps, err := m.ListSnapshotsByJobGeneration(ctx, "job-a", 1)
	if err != nil || len(snaps) != 1 || snaps[0].ID != "s1" {
		t.Fatalf("scoped snapshots = %+v err=%v, want exactly s1", snaps, err)
	}
	if none, err := m.ListArtifactsByJobGeneration(ctx, "job-a", 9); err != nil || len(none) != 0 {
		t.Fatalf("missing generation artifacts = %+v err=%v, want empty", none, err)
	}
}
