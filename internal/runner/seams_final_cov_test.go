package runner

import (
	"context"
	"crypto/tls"
	"fmt"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// failingReader never provides entropy; it forces the crypto/rand seams.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, fmt.Errorf("entropy unavailable") }

func withFailingRand(t *testing.T) {
	t.Helper()
	orig := randReader
	randReader = failingReader{}
	t.Cleanup(func() { randReader = orig })
}

func TestFinalSeamRandReaderFailures(t *testing.T) {
	withFailingRand(t)
	if _, err := newRunnerID(); err == nil {
		t.Fatal("identifier generation succeeded without entropy")
	}
	// Run fails while minting a fresh identity.
	r := &Runner{ID: "", Cfg: Config{Server: "http://127.0.0.1:1"}, Metrics: NewMetrics()}
	if err := r.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "entropy unavailable") {
		t.Fatalf("Run = %v", err)
	}
	// Enrollment bootstrap fails while minting the proposed runner ID.
	r = &Runner{Cfg: Config{Server: "https://127.0.0.1:1", EnrollToken: "grant", IdentityDir: t.TempDir()}}
	if err := r.prepareClient(context.Background()); err == nil || !strings.Contains(err.Error(), "entropy unavailable") {
		t.Fatalf("prepareClient = %v", err)
	}
}

func TestFinalSeamCloseTempFailures(t *testing.T) {
	orig := closeRunnerTempFile
	closeRunnerTempFile = func(*os.File) error { return fmt.Errorf("close refused") }
	t.Cleanup(func() { closeRunnerTempFile = orig })

	// restoreDownloads: the close failure is surfaced and the temp file is
	// removed rather than extracted.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("archive-bytes"))
	}))
	defer ts.Close()
	r := &Runner{ID: "r", Cfg: Config{Server: ts.URL}, Client: ts.Client(), Metrics: NewMetrics()}
	err := r.restoreDownloads(context.Background(), basicTask(payloadPipeline), []pipeline.ArtifactInput{{From: "producer", Name: "pkg"}}, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "close refused") {
		t.Fatalf("restoreDownloads = %v", err)
	}
	// uploadJobSnapshot: the close failure is wrapped as a snapshot error.
	if err := r.uploadJobSnapshot(context.Background(), basicTask(payloadPipeline), t.TempDir()); err == nil || !strings.Contains(err.Error(), "snapshot close") {
		t.Fatalf("uploadJobSnapshot = %v", err)
	}
}

func TestFinalSeamEnrollTLSServerCAFallback(t *testing.T) {
	ca, ts, calls, _ := enrollCountingServer(t)
	orig := enrollTLSConfig
	// The seam stands in for a system-trusted listener: enrollment proceeds
	// without an explicit --ca, so the runner adopts the CA certificate from
	// the enroll response.
	enrollTLSConfig = func(_, _ []byte, _ []byte, _ string) (*tls.Config, error) {
		return &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}, nil
	}
	t.Cleanup(func() { enrollTLSConfig = orig })

	dir := t.TempDir()
	r := &Runner{Cfg: Config{Server: ts.URL, Token: "runner-token", EnrollToken: "enroll-secret", IdentityDir: dir}}
	if err := r.prepareClient(context.Background()); err != nil {
		t.Fatalf("prepareClient: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("enroll calls = %d", calls.Load())
	}
	id, ok := (IdentityStore{Dir: dir}).Load()
	if !ok {
		t.Fatal("identity not persisted")
	}
	wantCA, err := runnerpki.ParseCertPEM(caCertPEM(t, ca))
	if err != nil {
		t.Fatal(err)
	}
	gotCA, err := runnerpki.ParseCertPEM(id.CACertPEM)
	if err != nil || string(gotCA.Raw) != string(wantCA.Raw) {
		t.Fatalf("persisted CA = %v, %v", gotCA, err)
	}
	if r.Client == nil {
		t.Fatal("client not built")
	}
}

func TestFinalSeamEnrollTLSConfigError(t *testing.T) {
	orig := enrollTLSConfig
	enrollTLSConfig = func(_, _, _ []byte, _ string) (*tls.Config, error) {
		return nil, fmt.Errorf("tls configuration refused")
	}
	t.Cleanup(func() { enrollTLSConfig = orig })
	r := &Runner{Cfg: Config{Server: "https://127.0.0.1:1", EnrollToken: "grant"}}
	if _, err := r.enroll(context.Background(), nil, []byte("csr")); err == nil || !strings.Contains(err.Error(), "tls configuration refused") {
		t.Fatalf("enroll = %v", err)
	}
}

func TestFinalPrepareClientEnrollRejection(t *testing.T) {
	// A wrong enrollment grant is refused by the control plane and surfaces
	// before any identity is persisted.
	_, ts, _, _ := enrollCountingServer(t)
	dir := t.TempDir()
	r := &Runner{Cfg: Config{Server: ts.URL, Token: "runner-token", EnrollToken: "wrong-grant", IdentityDir: dir}}
	if err := r.prepareClient(context.Background()); err == nil {
		t.Fatal("wrong enrollment grant accepted")
	}
	if _, ok := (IdentityStore{Dir: dir}).Load(); ok {
		t.Fatal("identity persisted after a rejected enrollment")
	}
}

func TestFinalRunGCReportsRemovedResources(t *testing.T) {
	testutil.UnixShell(t)
	// A fake docker that reports one stale labeled container exactly once:
	// the marker directory makes the GC report happen on a single pass so no
	// other goroutine reads the report seam afterwards.
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "gc-mark")
	old := time.Now().Add(-48 * time.Hour).Format("2006-01-02 15:04:05 -0700 MST")
	script := `#!/bin/sh
if [ "$1 $2" = "ps -a" ]; then
  if /bin/mkdir "` + marker + `" 2>/dev/null; then echo "deadbeef ` + old + `"; fi
fi
exit 0
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	reports := make(chan string, 4)
	origReportf := reportf
	reportf = func(format string, args ...any) (int, error) {
		msg := fmt.Sprintf(format, args...)
		reports <- msg
		return len(msg), nil
	}
	t.Cleanup(func() { reportf = origReportf })

	var nextCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/register"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
		case strings.HasSuffix(r.URL.Path, "/next"):
			nextCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, Poll: time.Millisecond, Concurrency: 1,
		WorkDir: t.TempDir(), GCInterval: time.Nanosecond, PrewarmInterval: time.Hour, IdentityDir: t.TempDir()},
		Client: ts.Client(), Metrics: NewMetrics()}
	runDone := make(chan error, 1)
	go func() { runDone <- r.Run(ctx) }()
	select {
	case got := <-reports:
		if !strings.Contains(got, "gc removed 1 containers, 0 networks, 0 VMs") {
			t.Fatalf("GC report = %q", got)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("GC report was not printed")
	}
	cancel()
	select {
	case err := <-runDone:
		if err != nil && !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
	if nextCalls.Load() == 0 {
		t.Fatal("next was never polled")
	}
}
