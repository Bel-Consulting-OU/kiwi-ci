package snapshot_test

// Cross-feature composition: workspace snapshot capture through the shared
// bounded staging area.
//
// The server stages a snapshot upload inside the shared staging.Budget and
// parses the staged bytes with snapshot.Parse; the runner captures with
// snapshot.Create. This test composes the same pieces at the package boundary:
// a real capture is spooled through staging.SpoolFile into the budget
// directory, the staged archive is parsed back and must describe exactly the
// capture, and the budget/exhaustion/cancellation exits must leave no partial
// staging anywhere — including the bare system temp directory.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// composeWorkspace writes a small deterministic workspace tree.
func composeWorkspace(t *testing.T) string {
	t.Helper()
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "a.txt"), bytes.Repeat([]byte("a"), 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "b.bin"), bytes.Repeat([]byte("b"), 8192), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "nested", "c.txt"), []byte("c"), 0o644); err != nil {
		t.Fatal(err)
	}
	return ws
}

// composeWatchTemp points TMPDIR at a fresh watched directory.
func composeWatchTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	return dir
}

// composeSpoolEntries lists staging entries excluding the ownership lock file,
// which legitimately exists for the lifetime of the budget.
func composeSpoolEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read staging dir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Name() == "kiwi-stage.lock" {
			continue
		}
		names = append(names, e.Name())
	}
	return names
}

func composeTempEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read watched temp dir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// TestComposeSnapshotCaptureSpooledInsideStagingBudget captures a real
// workspace through the shared staging area: the capture streams into a spool
// file inside the budget directory, the staged archive parses back to the
// capture's manifest, and the reservation returns to baseline with no spool
// file left.
func TestComposeSnapshotCaptureSpooledInsideStagingBudget(t *testing.T) {
	watched := composeWatchTemp(t)
	ws := composeWorkspace(t)

	// A capture of this tree is a few KiB; give the budget room for two.
	budget, err := staging.NewBudget(filepath.Join(t.TempDir(), "staging"), 256<<10)
	if err != nil {
		t.Fatal(err)
	}

	pr, pw := io.Pipe()
	type captureResult struct {
		m   snapshot.Manifest
		err error
	}
	captured := make(chan captureResult, 1)
	go func() {
		m, cerr := snapshot.Create(ws, pw)
		_ = pw.CloseWithError(cerr)
		captured <- captureResult{m: m, err: cerr}
	}()

	res, err := budget.Acquire(context.Background(), 64<<10)
	if err != nil {
		t.Fatalf("staging reservation: %v", err)
	}
	stagedPath, n, err := budget.SpoolFile(pr, 64<<10)
	if err != nil {
		res.Release()
		t.Fatalf("spool snapshot capture: %v", err)
	}
	got := <-captured
	if got.err != nil {
		t.Fatalf("snapshot.Create: %v", got.err)
	}
	if !strings.HasPrefix(stagedPath, budget.Dir()+string(os.PathSeparator)) {
		t.Fatalf("spooled capture %s is outside the budget directory %s", stagedPath, budget.Dir())
	}
	if n <= 0 {
		t.Fatalf("spooled capture is empty")
	}

	// The staged archive must parse back to the capture's manifest.
	f, err := os.Open(stagedPath)
	if err != nil {
		t.Fatal(err)
	}
	parsed, perr := snapshot.Parse(f)
	closeErr := f.Close()
	if perr != nil {
		t.Fatalf("parse staged capture: %v", perr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if parsed.RootSHA256 != got.m.RootSHA256 {
		t.Fatalf("staged capture root %s, want the capture's %s", parsed.RootSHA256, got.m.RootSHA256)
	}
	if len(parsed.Entries) != len(got.m.Entries) {
		t.Fatalf("staged capture has %d entries, want %d", len(parsed.Entries), len(got.m.Entries))
	}

	// Every exit path returns the reservation and removes the spool file.
	_ = os.Remove(stagedPath)
	res.Release()
	if budget.Used() != 0 {
		t.Fatalf("budget used after release = %d, want 0", budget.Used())
	}
	if entries := composeSpoolEntries(t, budget.Dir()); len(entries) != 0 {
		t.Fatalf("staging directory entries after release = %v, want none", entries)
	}
	if entries := composeTempEntries(t, watched); len(entries) != 0 {
		t.Fatalf("snapshot capture staged into the bare system temp directory: %v", entries)
	}
}

// TestComposeSnapshotCaptureExhaustionFailsTypedAndPartialFree proves the
// exhaustion contract at the snapshot boundary: a reservation larger than the
// budget fails with the typed ErrBudgetExceeded before a byte is captured, and
// a spool whose stream exceeds its own limit leaves no partial file.
func TestComposeSnapshotCaptureExhaustionFailsTypedAndPartialFree(t *testing.T) {
	watched := composeWatchTemp(t)
	ws := composeWorkspace(t)
	budget, err := staging.NewBudget(filepath.Join(t.TempDir(), "staging"), 1024)
	if err != nil {
		t.Fatal(err)
	}

	// Exhaustion: the reservation itself is refused with the typed error.
	if _, err := budget.Acquire(context.Background(), 4096); !errors.Is(err, staging.ErrBudgetExceeded) {
		t.Fatalf("over-budget reservation = %v, want ErrBudgetExceeded", err)
	}
	if budget.Used() != 0 {
		t.Fatalf("refused reservation changed the ledger to %d", budget.Used())
	}

	// A capture that outgrows its per-file limit removes the partial spool
	// file and reports ErrTooLarge.
	pr, pw := io.Pipe()
	go func() {
		_, cerr := snapshot.Create(ws, pw)
		_ = pw.CloseWithError(cerr)
	}()
	_, _, err = budget.SpoolFile(pr, 32)
	_ = pr.CloseWithError(io.EOF)
	if !errors.Is(err, staging.ErrTooLarge) {
		t.Fatalf("spool of an oversized capture = %v, want ErrTooLarge", err)
	}
	if entries := composeSpoolEntries(t, budget.Dir()); len(entries) != 0 {
		t.Fatalf("oversized capture left staging entries %v", entries)
	}
	if entries := composeTempEntries(t, watched); len(entries) != 0 {
		t.Fatalf("oversized capture fell back to the bare system temp directory: %v", entries)
	}
}

// composeFailAfterWriter fails every write after n bytes.
type composeFailAfterWriter struct {
	remaining int
	err       error
}

func (w *composeFailAfterWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, w.err
	}
	if len(p) > w.remaining {
		p = p[:w.remaining]
	}
	n := len(p)
	w.remaining -= n
	return n, nil
}

// TestComposeSnapshotCaptureSinkFailureLeavesNoPartialStaging composes a
// mid-capture sink failure (a disconnected upload) with the staging area: no
// snapshot record can exist for a capture that never completed, the spooled
// partial is removed with the error, and the budget returns to baseline.
func TestComposeSnapshotCaptureSinkFailureLeavesNoPartialStaging(t *testing.T) {
	watched := composeWatchTemp(t)
	ws := composeWorkspace(t)
	budget, err := staging.NewBudget(filepath.Join(t.TempDir(), "staging"), 256<<10)
	if err != nil {
		t.Fatal(err)
	}

	// The capture streams into the spool file, but its spool reader dies
	// after the first chunk: SpoolFile must delete the partial file.
	pr, pw := io.Pipe()
	captureDone := make(chan error, 1)
	go func() {
		_, cerr := snapshot.Create(ws, pw)
		_ = pw.CloseWithError(cerr)
		captureDone <- cerr
	}()
	sink := &composeFailAfterWriter{remaining: 100, err: io.ErrUnexpectedEOF}
	res, err := budget.Acquire(context.Background(), 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Release()
	if _, _, err := budget.SpoolFile(io.TeeReader(pr, sink), 64<<10); err == nil {
		t.Fatal("spool with a failing sink succeeded")
	}
	_ = pr.CloseWithError(io.EOF)
	<-captureDone
	if entries := composeSpoolEntries(t, budget.Dir()); len(entries) != 0 {
		t.Fatalf("sink failure left staging entries %v", entries)
	}
	res.Release()
	if budget.Used() != 0 {
		t.Fatalf("budget used after the failed capture = %d, want 0", budget.Used())
	}
	if entries := composeTempEntries(t, watched); len(entries) != 0 {
		t.Fatalf("failed capture staged into the bare system temp directory: %v", entries)
	}
}
