package system_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood/system"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestSysDFDr001 proves DF-DR-001 — backup → destroy → restore:
//
//  1. NewPersistent on DataDir1, submit+complete trusted-native work via
//     the signed GitHub webhook ingress.
//  2. Backup: copy the entire data directory (the documented FS-mode
//     backup method — a consistent directory copy after Close).
//  3. Destroy the original (remove the directory).
//  4. Restore into DataDir2 from the backup copy.
//  5. NewPersistent on the restored directory: the historical run is still
//     queryable and the evidence envelope still verifies (FetchEvidence +
//     VerifyEvidence through the public API).
//
// The backup is a plain directory copy taken after the system is closed
// (no writers), which is the supported FS-store backup procedure. Nothing
// in the store is mutated outside the public API.
//
// Evidence after restore: the FS-mode EnvelopeRef records an absolute file
// path under the original DataDir1. Restoring to a different path leaves
// that pointer stale, so FetchEvidence is attempted on the restored system
// and reported ("if possible" per the scenario contract). Restoring to the
// same path — the common DR drill — is proven in the same test via a
// second cycle that preserves absolute refs.
func TestSysDFDr001(t *testing.T) {
	trusted := useTrustedNative(t)
	if !trusted {
		t.Setenv("KIWI_ALLOW_UNQUOTAED_UNTRUSTED_DISK", "1")
	}

	// --- Phase 1: live system on DataDir1, complete trusted work. ---
	root := t.TempDir()
	dataDir1 := filepath.Join(root, "state")
	if err := os.MkdirAll(dataDir1, 0o700); err != nil {
		t.Fatal(err)
	}
	sys1, err := system.Launch(system.SystemConfig{
		RunnerToken: "sys-dr-runner",
		AdminToken:  "sys-dr-admin",
		DataDir:     dataDir1,
	})
	if err != nil {
		t.Fatalf("launch DataDir1: %v", err)
	}
	if trusted {
		if err := sys1.EnableTrustedWebhook(system.TrustedWebhookConfig{PipelineYAML: nativeEchoPipeline}); err != nil {
			t.Fatalf("enable trusted webhook: %v", err)
		}
	}
	var labels []string
	if !trusted {
		labels = []string{"container"}
	}
	if err := sys1.StartRunner("dr-runner", labels); err != nil {
		t.Fatalf("start runner: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var runID string
	if trusted {
		runID, err = sys1.SubmitTrustedNative(ctx, nativeEchoPipeline)
	} else {
		runID, err = sys1.SubmitPipeline(ctx, containerEchoPipeline, system.SubmitOpts{})
	}
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	status, err := sys1.WaitJobTerminal(ctx, runID, "build")
	if err != nil {
		t.Fatalf("wait job: %v", err)
	}
	if status != model.StatusSuccess {
		j, _ := sys1.JobByKey(ctx, runID, "build")
		t.Fatalf("job status = %s error=%q, want success", status, j.Error)
	}
	job1, err := sys1.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	// Capture the evidence envelope from the live system BEFORE backup.
	evCtx, evCancel := context.WithTimeout(ctx, 25*time.Second)
	defer evCancel()
	envBefore, err := sys1.FetchEvidence(evCtx, job1.ID, job1.LeaseGeneration)
	if err != nil {
		t.Fatalf("fetch evidence before backup: %v", err)
	}
	if len(envBefore) == 0 {
		t.Fatal("empty attestation envelope before backup")
	}
	// Verify the pre-backup envelope too, so the DR proof starts from a
	// known-good attestation.
	if _, err := sys1.VerifyEvidence(ctx, envBefore); err != nil {
		t.Fatalf("verify evidence before backup: %v", err)
	}

	// --- Phase 2: backup — copy the state directory after Close. ---
	if err := sys1.Close(); err != nil {
		t.Fatalf("close DataDir1 system: %v", err)
	}
	backupDir := filepath.Join(root, "backup")
	if err := copyDir(dataDir1, backupDir); err != nil {
		t.Fatalf("backup copy: %v", err)
	}

	// --- Phase 3: destroy the original. ---
	if err := os.RemoveAll(dataDir1); err != nil {
		t.Fatalf("destroy original: %v", err)
	}
	if _, err := os.Stat(dataDir1); !os.IsNotExist(err) {
		t.Fatalf("original data dir still exists after destroy (stat err=%v)", err)
	}

	// --- Phase 4a: restore into a DIFFERENT directory (DataDir2). ---
	dataDir2 := filepath.Join(root, "restored")
	if err := copyDir(backupDir, dataDir2); err != nil {
		t.Fatalf("restore copy to DataDir2: %v", err)
	}

	// --- Phase 5a: NewPersistent on the restored dir; history must survive. ---
	sys2, err := system.Launch(system.SystemConfig{
		RunnerToken: "sys-dr-runner",
		AdminToken:  "sys-dr-admin",
		DataDir:     dataDir2,
	})
	if err != nil {
		t.Fatalf("launch restored DataDir2: %v", err)
	}
	run2, err := sys2.QueryRun(ctx, runID)
	if err != nil {
		t.Fatalf("query run after restore (DataDir2): %v", err)
	}
	if run2.ID != runID || run2.Status != model.StatusSuccess {
		t.Fatalf("after restore (DataDir2) run = %+v, want %s success", run2, runID)
	}
	jobs2, err := sys2.QueryJobs(ctx, runID)
	if err != nil {
		t.Fatalf("query jobs after restore (DataDir2): %v", err)
	}
	found := false
	for _, j := range jobs2 {
		if j.Key == "build" && j.Status == model.StatusSuccess {
			found = true
		}
	}
	if !found {
		t.Fatalf("after restore (DataDir2) jobs = %+v, want terminal success build", jobs2)
	}
	job2, err := sys2.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("job after restore (DataDir2): %v", err)
	}
	if job2.ID != job1.ID {
		t.Fatalf("job id changed across restore: %q → %q", job1.ID, job2.ID)
	}
	// FetchEvidence on the cross-directory restore: the FS-mode
	// EnvelopeRef is an absolute path under DataDir1 (destroyed), so the
	// envelope file is not reachable. The scenario contract says "if
	// possible"; we observe and log rather than fail.
	crossCtx, crossCancel := context.WithTimeout(context.Background(), 3*time.Second)
	envCross, err := sys2.FetchEvidence(crossCtx, job2.ID, job2.LeaseGeneration)
	crossCancel()
	if err != nil {
		t.Logf("FetchEvidence after cross-directory restore (expected for FS-mode absolute EnvelopeRef): %v", err)
	} else {
		t.Logf("FetchEvidence after cross-directory restore succeeded (%d bytes)", len(envCross))
	}
	if err := sys2.Close(); err != nil {
		t.Fatalf("close restored DataDir2: %v", err)
	}

	// --- Phase 4b: restore into the SAME path (the common DR drill). ---
	// This preserves absolute EnvelopeRef pointers and proves the full
	// evidence chain survives backup → destroy → restore.
	if err := copyDir(backupDir, dataDir1); err != nil {
		t.Fatalf("restore copy to original path: %v", err)
	}

	// --- Phase 5b: NewPersistent on the same-path restore; full evidence. ---
	sys3, err := system.Launch(system.SystemConfig{
		RunnerToken: "sys-dr-runner",
		AdminToken:  "sys-dr-admin",
		DataDir:     dataDir1,
	})
	if err != nil {
		t.Fatalf("launch restored DataDir1: %v", err)
	}
	defer func() { _ = sys3.Close() }()

	run3, err := sys3.QueryRun(ctx, runID)
	if err != nil {
		t.Fatalf("query run after same-path restore: %v", err)
	}
	if run3.ID != runID || run3.Status != model.StatusSuccess {
		t.Fatalf("after same-path restore run = %+v, want %s success", run3, runID)
	}
	job3, err := sys3.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("job after same-path restore: %v", err)
	}
	if job3.ID != job1.ID {
		t.Fatalf("job id changed across same-path restore: %q → %q", job1.ID, job3.ID)
	}
	sameCtx, sameCancel := context.WithTimeout(context.Background(), 25*time.Second)
	envAfter, err := sys3.FetchEvidence(sameCtx, job3.ID, job3.LeaseGeneration)
	sameCancel()
	if err != nil {
		t.Fatalf("fetch evidence after same-path restore: %v", err)
	}
	if len(envAfter) == 0 {
		t.Fatal("empty attestation envelope after same-path restore")
	}
	st, err := sys3.VerifyEvidence(context.Background(), envAfter)
	if err != nil {
		t.Fatalf("verify evidence after same-path restore: %v", err)
	}
	if st.Attestation == nil {
		t.Fatal("verified statement after restore carries no execution attestation")
	}
	if st.Attestation.JobID != job3.ID {
		t.Fatalf("attestation job id after restore = %q, want %q", st.Attestation.JobID, job3.ID)
	}
	// Byte-level continuity: the restored envelope is the same one the
	// original system produced.
	if string(envBefore) != string(envAfter) {
		t.Fatal("attestation envelope changed across backup/restore")
	}
}

// copyDir recursively copies src into dst (creating dst). It is the
// documented FS-mode backup procedure: a consistent directory copy taken
// after the system is closed (no writers).
func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		return copyFile(path, target)
	})
}

// copyFile copies one file, preserving the mode bits.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, st.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
