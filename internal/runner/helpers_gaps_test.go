//go:build unix

package runner

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMetricsNilAndWriterFailureArms covers the defensive nil receivers and
// the exposition write-failure path.
func TestMetricsNilAndWriterFailureArms(t *testing.T) {
	var nilMetrics *Metrics
	nilMetrics.Counter("x", 1)
	nilMetrics.GaugeFunc("x", func() float64 { return 0 })
	if err := nilMetrics.Expose(io.Discard); err != nil {
		t.Fatalf("nil Expose = %v, want nil", err)
	}

	m := NewMetrics()
	m.GaugeFunc("", func() float64 { return 1 })
	m.GaugeFunc("g", nil)
	if err := m.Expose(failingWriter{}); err != nil {
		t.Fatalf("empty registry Expose = %v", err)
	}
	m.Counter("c", 2)
	if err := m.Expose(failingWriter{}); err == nil {
		t.Fatal("Expose ignored a write failure")
	}
}

// TestBearerRunnerIdentityHelpers covers the identity-file path derivation,
// the corrupt/unreadable/entropy failure arms, and the persistence failure
// arms.
func TestBearerRunnerIdentityHelpers(t *testing.T) {
	if got := truncationMarker(true); got != " [output truncated]" {
		t.Fatalf("truncationMarker(true) = %q", got)
	}
	if got := truncationMarker(false); got != "" {
		t.Fatalf("truncationMarker(false) = %q", got)
	}

	named := &Runner{Cfg: Config{IdentityDir: t.TempDir(), Name: "runner-one"}}
	p, err := named.bearerRunnerIDPath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(p), "runner-id-") {
		t.Fatalf("named identity path = %q", p)
	}
	unnamed := &Runner{Cfg: Config{IdentityDir: t.TempDir()}}
	p, err = unnamed.bearerRunnerIDPath()
	if err != nil || filepath.Base(p) != "runner-id" {
		t.Fatalf("unnamed identity path = %q/%v", p, err)
	}

	t.Setenv("HOME", "")
	homeless := &Runner{}
	if _, err := homeless.bearerRunnerIDPath(); err == nil {
		t.Fatal("bearerRunnerIDPath without any directory succeeded")
	}
	if _, err := homeless.persistedBearerRunnerID(); err == nil {
		t.Fatal("persistedBearerRunnerID without any directory succeeded")
	}
	if err := homeless.persistBearerRunnerID("x"); err == nil {
		t.Fatal("persistBearerRunnerID without any directory succeeded")
	}

	dir := t.TempDir()
	corrupt := &Runner{Cfg: Config{IdentityDir: dir}}
	if err := os.WriteFile(filepath.Join(dir, "runner-id"), []byte("not-hex"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := corrupt.persistedBearerRunnerID(); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("corrupt identity file = %v", err)
	}

	dir2 := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir2, "runner-id"), 0o700); err != nil {
		t.Fatal(err)
	}
	unreadable := &Runner{Cfg: Config{IdentityDir: dir2}}
	if _, err := unreadable.persistedBearerRunnerID(); err == nil || !strings.Contains(err.Error(), "read runner identity file") {
		t.Fatalf("directory identity path = %v", err)
	}

	fresh := &Runner{Cfg: Config{IdentityDir: t.TempDir(), Name: "fresh"}}
	origRand := randReader
	randReader = entropyFailReader{err: errors.New("no entropy")}
	_, err = fresh.persistedBearerRunnerID()
	randReader = origRand
	if err == nil {
		t.Fatal("entropy failure not surfaced")
	}
	if _, err := fresh.persistedBearerRunnerID(); err != nil {
		t.Fatalf("healthy generation: %v", err)
	}

	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocked := &Runner{Cfg: Config{IdentityDir: filepath.Join(file, "identity")}}
	if err := blocked.persistBearerRunnerID("x"); err == nil {
		t.Fatal("persist under a file succeeded")
	}
}

// TestResolveStateDirAndJournalGuards covers the no-state-directory failure
// and the journal-less guard.
func TestResolveStateDirAndJournalGuards(t *testing.T) {
	t.Setenv("HOME", "")
	r := &Runner{}
	if err := r.resolveStateDir(); err == nil {
		t.Fatal("resolveStateDir without any configuration succeeded")
	}
	if _, err := r.openJobLogJournal("job", 1, nil); err == nil || !strings.Contains(err.Error(), "state directory is not resolved") {
		t.Fatalf("journal without state dir = %v", err)
	}
	r.journalOptOut = true
	if j, err := r.openJobLogJournal("job", 1, nil); err != nil || j != nil {
		t.Fatalf("journal opt-out = %v/%v", j, err)
	}
}

// TestAcquireRunnerIdentityLockWritableFile proves a group/world-writable
// identity lock file is refused.
func TestAcquireRunnerIdentityLockWritableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runner.lock")
	if err := os.WriteFile(path, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireRunnerIdentityLock(dir); err == nil || !strings.Contains(err.Error(), "trustworthy") {
		t.Fatalf("writable lock file = %v, want the trust refusal", err)
	}
}

func TestPruneOlderGenerationsMissingDir(t *testing.T) {
	var j logJournal
	j.generation = 5
	j.pruneOlderGenerations(filepath.Join(t.TempDir(), "missing"))
}
