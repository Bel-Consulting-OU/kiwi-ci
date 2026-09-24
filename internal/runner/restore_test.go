package runner

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// dependencyServer serves one tar.gz artifact per declared (producer, name)
// pair on the lease-bound dependency route and records every request path
// and header so tests can assert nothing else was ever fetched.
type dependencyServer struct {
	mu        sync.Mutex
	paths     []string
	headers   []http.Header
	artifacts map[string][]byte // "producer/name" -> tarball bytes
}

func (d *dependencyServer) serve(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	d.paths = append(d.paths, r.URL.Path)
	d.headers = append(d.headers, r.Header.Clone())
	d.mu.Unlock()
	prefix := "/api/v1/jobs/job-1/dependencies/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, prefix)
	body, ok := d.artifacts[key]
	if !ok {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	}
	sum := sha256.Sum256(body)
	w.Header().Set("X-Kiwi-Content-SHA256", hex.EncodeToString(sum[:]))
	w.Header().Set("Content-Type", "application/gzip")
	_, _ = w.Write(body)
}

func tarGzWithFile(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func downloadTask() server.Task {
	return server.Task{
		Job:             model.Job{ID: "job-1", RunID: "run-1", Key: "build", BaseKey: "build"},
		LeaseToken:      "lease-token",
		LeaseGeneration: 3,
	}
}

func TestRestoreDownloadsUsesDependencyEndpoint(t *testing.T) {
	dep := &dependencyServer{artifacts: map[string][]byte{
		"build/bin": tarGzWithFile(t, "app.txt", "hello-dependency"),
	}}
	ts := httptest.NewServer(http.HandlerFunc(dep.serve))
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	workspace := t.TempDir()
	inputs := []pipeline.ArtifactInput{{From: "build", Name: "bin", Path: "deps"}}
	if err := r.restoreDownloads(context.Background(), downloadTask(), inputs, workspace); err != nil {
		t.Fatalf("restore: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(workspace, "deps", "app.txt"))
	if err != nil {
		t.Fatalf("extracted file missing: %v", err)
	}
	if string(data) != "hello-dependency" {
		t.Fatalf("extracted content = %q", data)
	}

	dep.mu.Lock()
	paths := append([]string{}, dep.paths...)
	headers := append([]http.Header{}, dep.headers...)
	dep.mu.Unlock()

	want := "/api/v1/jobs/job-1/dependencies/build/bin"
	if len(paths) != 1 || paths[0] != want {
		t.Fatalf("requests = %v, want exactly [%s]", paths, want)
	}
	for _, p := range paths {
		if strings.Contains(p, "/runs/") || strings.Contains(p, "/artifacts") && !strings.Contains(p, "/dependencies/") {
			t.Fatalf("runner fetched outside the dependency route: %s", p)
		}
	}
	h := headers[0]
	if got := h.Get("X-Kiwi-Runner-ID"); got != "runner-1" {
		t.Fatalf("X-Kiwi-Runner-ID = %q, want runner-1", got)
	}
	if got := h.Get("X-Kiwi-Lease-Token"); got != "lease-token" {
		t.Fatalf("X-Kiwi-Lease-Token = %q, want lease-token", got)
	}
	if got := h.Get("X-Kiwi-Lease-Generation"); got != "3" {
		t.Fatalf("X-Kiwi-Lease-Generation = %q, want 3", got)
	}
}

func TestRestoreDownloadsNeverFetchesUndeclaredNames(t *testing.T) {
	dep := &dependencyServer{artifacts: map[string][]byte{
		"build/bin":   tarGzWithFile(t, "bin.txt", "bin"),
		"build/debug": tarGzWithFile(t, "debug.txt", "debug"),
		"test/cov":    tarGzWithFile(t, "cov.txt", "cov"),
	}}
	ts := httptest.NewServer(http.HandlerFunc(dep.serve))
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	workspace := t.TempDir()
	inputs := []pipeline.ArtifactInput{{From: "build", Name: "bin"}}
	if err := r.restoreDownloads(context.Background(), downloadTask(), inputs, workspace); err != nil {
		t.Fatalf("restore: %v", err)
	}

	dep.mu.Lock()
	paths := append([]string{}, dep.paths...)
	dep.mu.Unlock()
	if len(paths) != 1 || paths[0] != "/api/v1/jobs/job-1/dependencies/build/bin" {
		t.Fatalf("runner fetched undeclared artifacts: %v", paths)
	}
}

func TestRestoreDownloadsMissingDependencyFails(t *testing.T) {
	dep := &dependencyServer{artifacts: map[string][]byte{}}
	ts := httptest.NewServer(http.HandlerFunc(dep.serve))
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	inputs := []pipeline.ArtifactInput{{From: "build", Name: "bin"}}
	err := r.restoreDownloads(context.Background(), downloadTask(), inputs, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("error = %v, want the 404 surfaced", err)
	}
}

func TestRestoreDownloadsRejectsUnsafePath(t *testing.T) {
	dep := &dependencyServer{artifacts: map[string][]byte{}}
	ts := httptest.NewServer(http.HandlerFunc(dep.serve))
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	inputs := []pipeline.ArtifactInput{{From: "build", Name: "bin", Path: "../escape"}}
	err := r.restoreDownloads(context.Background(), downloadTask(), inputs, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "unsafe download path") {
		t.Fatalf("error = %v, want unsafe path refusal", err)
	}
	dep.mu.Lock()
	paths := append([]string{}, dep.paths...)
	dep.mu.Unlock()
	if len(paths) != 0 {
		t.Fatalf("unsafe path still fetched: %v", paths)
	}
}

func TestRestoreDownloadsVerifiesContentSHA(t *testing.T) {
	body := tarGzWithFile(t, "app.txt", "hello")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/jobs/job-1/dependencies/") {
			http.NotFound(w, r)
			return
		}
		// Advertise a digest that does not match the body.
		w.Header().Set("X-Kiwi-Content-SHA256", strings.Repeat("0", 64))
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	inputs := []pipeline.ArtifactInput{{From: "build", Name: "bin"}}
	err := r.restoreDownloads(context.Background(), downloadTask(), inputs, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "integrity mismatch") {
		t.Fatalf("error = %v, want integrity mismatch", err)
	}
}

func TestSafeDownloadDest(t *testing.T) {
	ok, err := safeDownloadDest("sub/dir")
	if err != nil || ok != "sub/dir" {
		t.Fatalf("safeDownloadDest(sub/dir) = %q, %v", ok, err)
	}
	if ok, err = safeDownloadDest(""); err != nil || ok != "" {
		t.Fatalf("safeDownloadDest(\"\") = %q, %v", ok, err)
	}
	if ok, err = safeDownloadDest("."); err != nil || ok != "" {
		t.Fatalf("safeDownloadDest(.) = %q, %v", ok, err)
	}
	for _, bad := range []string{"..", "../x", "/abs", "a/../../x", `a\b`} {
		if _, err := safeDownloadDest(bad); err == nil {
			t.Errorf("path %q accepted", bad)
		}
	}
}
