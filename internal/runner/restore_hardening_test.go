package runner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// TestRestoreDownloadsRejectsSymlinkedAncestor is the end-to-end P0
// regression: a checkout can leave `evil -> $HOME` in the workspace and a
// declared download path `evil/.ssh` must never write `authorized_keys`
// outside the workspace.
func TestRestoreDownloadsRejectsSymlinkedAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	outside := t.TempDir()
	dep := &dependencyServer{artifacts: map[string][]byte{
		"build/bin": tarGzWithFile(t, "authorized_keys", "pwned"),
	}}
	ts := httptest.NewServer(http.HandlerFunc(dep.serve))
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	ws := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(ws, "evil")); err != nil {
		t.Fatal(err)
	}
	inputs := []pipeline.ArtifactInput{{From: "build", Name: "bin", Path: "evil/.ssh"}}
	err := r.restoreDownloads(context.Background(), downloadTask(), inputs, ws)

	escaped := filepath.Join(outside, ".ssh", "authorized_keys")
	if b, rerr := os.ReadFile(escaped); rerr == nil {
		t.Fatalf("sandbox escape observed: dependency artifact written outside the workspace at %s (%q, restore err = %v)", escaped, b, err)
	}
	if err == nil {
		t.Fatal("restore accepted a symlinked ancestor")
	}
}

// TestRestoreDownloadsNestedPathStillWorks proves the hardened root walk
// still creates and extracts into a normal multi-level destination.
func TestRestoreDownloadsNestedPathStillWorks(t *testing.T) {
	dep := &dependencyServer{artifacts: map[string][]byte{
		"build/bin": tarGzWithFile(t, "app.txt", "nested-dependency"),
	}}
	ts := httptest.NewServer(http.HandlerFunc(dep.serve))
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	ws := t.TempDir()
	inputs := []pipeline.ArtifactInput{{From: "build", Name: "bin", Path: "a/b/c"}}
	if err := r.restoreDownloads(context.Background(), downloadTask(), inputs, ws); err != nil {
		t.Fatalf("restore: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(ws, "a", "b", "c", "app.txt"))
	if err != nil || string(b) != "nested-dependency" {
		t.Fatalf("extracted content = %q, %v", b, err)
	}
}

// TestRestoreDownloadsCapsSpooledBody is the P1 regression: a dependency body
// larger than the hard cap is refused with a typed error, the staged spool is
// removed, and the staging ledger drains to zero (no bytes stay charged).
func TestRestoreDownloadsCapsSpooledBody(t *testing.T) {
	prevCap := dependencyArtifactMaxBytes
	dependencyArtifactMaxBytes = 256
	t.Cleanup(func() { dependencyArtifactMaxBytes = prevCap })

	// Stream far more than the cap in flushable chunks so the response uses
	// chunked encoding with no Content-Length: only the byte cap can stop it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("test writer is not flushable")
			return
		}
		chunk := make([]byte, 1024)
		for i := 0; i < 64; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			fl.Flush()
		}
	}))
	defer srv.Close()

	r := testRunnerFor(t, srv, Config{})
	inputs := []pipeline.ArtifactInput{{From: "build", Name: "bin"}}
	err := r.restoreDownloads(context.Background(), downloadTask(), inputs, t.TempDir())
	if !errors.Is(err, ErrDependencyArtifactTooLarge) {
		t.Fatalf("error = %v, want ErrDependencyArtifactTooLarge", err)
	}
	budget, berr := r.dependencyStaging()
	if berr != nil {
		t.Fatal(berr)
	}
	if used := budget.Used(); used != 0 {
		t.Fatalf("staging ledger = %d bytes after a refused spool, want 0", used)
	}
	if left := spoolFilesIn(t, budget.Dir()); len(left) != 0 {
		t.Fatalf("partial spool left behind: %v", left)
	}
}

// spoolFilesIn lists the staging spool files currently present in dir.
func spoolFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), staging.FilePrefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

// TestRestoreDownloadsRejectsOversizedContentLength proves a peer that
// announces a body above the cap is refused before any spool file is created.
func TestRestoreDownloadsRejectsOversizedContentLength(t *testing.T) {
	prevCap := dependencyArtifactMaxBytes
	dependencyArtifactMaxBytes = 128
	t.Cleanup(func() { dependencyArtifactMaxBytes = prevCap })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4096")
		_, _ = w.Write(make([]byte, 4096))
	}))
	defer srv.Close()

	r := testRunnerFor(t, srv, Config{})
	err := r.restoreDownloads(context.Background(), downloadTask(),
		[]pipeline.ArtifactInput{{From: "build", Name: "bin"}}, t.TempDir())
	if !errors.Is(err, ErrDependencyArtifactTooLarge) {
		t.Fatalf("error = %v, want ErrDependencyArtifactTooLarge", err)
	}
	entries, rerr := os.ReadDir(r.Cfg.CacheRoot)
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, e := range entries {
		t.Fatalf("spool temp file created despite oversized content length: %q", e.Name())
	}
}
