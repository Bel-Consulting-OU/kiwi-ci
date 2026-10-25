package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/workspace"
)

// External -f: the pipeline AND its image lock are adopted into the frozen
// run-base so a later mutation of the live lock cannot change this run's
// compilation authority (and the live original path is never re-read).
func TestRunLocalAdoptsExternalPipelineLock(t *testing.T) {
	proj := t.TempDir()
	ext := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proj, ".kiwi"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, ".kiwi", "pipeline.yaml"),
		[]byte("version: 1\njobs:\n  base:\n    steps:\n      - run: echo base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ext, ".kiwi"), 0o755); err != nil {
		t.Fatal(err)
	}
	pipePath := filepath.Join(ext, "pipeline.yaml")
	if err := os.WriteFile(pipePath,
		[]byte("version: 1\njobs:\n  j:\n    runtime: native\n    steps:\n      - run: echo ext\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dig := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	lockBody := `{"version":1,"images":[{"ref":"alpine","digest":"alpine@sha256:` + dig + `"}]}` + "\n"
	liveLock := filepath.Join(ext, ".kiwi", "lock.json")
	if err := os.WriteFile(liveLock, []byte(lockBody), 0o644); err != nil {
		t.Fatal(err)
	}

	// Freeze from proj (the working tree RunLocal would use).
	wm, err := workspace.NewManager(proj)
	if err != nil {
		t.Fatal(err)
	}
	defer wm.Close()
	if err := wm.Freeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	base := wm.BasePath()
	if base == "" {
		t.Fatal("no run-base")
	}

	// Adopt the external pipeline the same way RunLocal does.
	adopted, err := wm.AdoptFile(pipePath)
	if err != nil {
		t.Fatalf("AdoptFile pipeline: %v", err)
	}
	frozenRoot, err := wm.AdoptLock(liveLock)
	if err != nil {
		t.Fatalf("AdoptLock: %v", err)
	}
	// Structured layout applyLocalImageLock expects.
	got := filepath.Join(frozenRoot, ".kiwi", "lock.json")
	b, err := os.ReadFile(got)
	if err != nil {
		t.Fatalf("adopted lock path: %v", err)
	}
	if string(b) != lockBody {
		t.Fatalf("adopted lock body = %q want %q", b, lockBody)
	}
	// Live lock mutation after adoption must not change the frozen bytes.
	if err := os.WriteFile(liveLock, []byte(`{"version":1,"images":[]}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(b2) != lockBody {
		t.Fatalf("frozen lock mutated with live file: %q", b2)
	}
	// Adopted pipeline sits under .kiwi-frozen, not the live ext path.
	if filepath.Base(filepath.Dir(adopted)) != ".kiwi-frozen" {
		t.Fatalf("adopted pipeline dir = %q", filepath.Dir(adopted))
	}
	// Directory adoption must fail closed.
	if _, err := wm.AdoptFile(ext); err == nil {
		t.Fatal("AdoptFile of a directory must fail")
	}
	if _, err := wm.AdoptLock(ext); err == nil {
		t.Fatal("AdoptLock of a directory must fail")
	}
}
