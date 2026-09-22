package runner

// Coverage for the snapshot streaming error paths: a transport failure whose
// capture succeeded must surface the transport error, and a rejected response
// whose capture failed must surface the CAPTURE error (the actionable one)
// rather than the HTTP status text.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// TestUploadJobSnapshotTransportErrorSurfaces: the capture completes within
// its cap, but the request cannot reach the control plane (the transport
// fails); the returned error is the transport failure, not a capture
// failure. The transport is injected (roundTripFunc, defined in
// runner_cov2_test.go) instead of closing a listener, whose port could be
// rebound by another server and make the request succeed intermittently.
func TestUploadJobSnapshotTransportErrorSurfaces(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()
	r := testRunnerFor(t, ts, Config{})
	dialErr := errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
	r.StreamClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, dialErr
	})}
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "data.txt"), []byte("small"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := r.uploadJobSnapshot(context.Background(), basicTask(payloadPipeline), ws, 1<<20)
	if err == nil {
		t.Fatal("upload through a failing transport succeeded")
	}
	if errors.Is(err, safefs.ErrCapExceeded) {
		t.Fatalf("transport failure reported as a cap failure: %v", err)
	}
	if !errors.Is(err, dialErr) && !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("error %q does not surface the transport failure", err)
	}
}

// TestUploadJobSnapshotRejectedResponsePrefersCaptureError: the control plane
// answers with a non-2xx status AND the capture failed mid-stream; the
// capture error (the cap) is the actionable one and must win.
func TestUploadJobSnapshotRejectedResponsePrefersCaptureError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Do not consume the body: return the rejection immediately.
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("snapshot rejected"))
	}))
	defer ts.Close()
	r := testRunnerFor(t, ts, Config{})

	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "data.bin"), incompressible(t, 256<<10), 0o644); err != nil {
		t.Fatal(err)
	}
	// declared 64 KiB => archive cap 128 KiB, workspace 256 KiB: the stream
	// trips the cap while the server has already rejected the request.
	err := r.uploadJobSnapshot(context.Background(), basicTask(payloadPipeline), ws, 64<<10)
	if err == nil {
		t.Fatal("rejected over-cap upload reported success")
	}
	if !errors.Is(err, safefs.ErrCapExceeded) {
		t.Fatalf("error = %v, want the capture's ErrCapExceeded", err)
	}
}
