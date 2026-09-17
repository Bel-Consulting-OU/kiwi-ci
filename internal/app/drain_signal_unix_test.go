//go:build !windows

package app

// SIGTERM self-delivery (syscall.Kill) is unix-only; the portable drain and
// lifecycle branches are covered in server_cov_test.go.

import (
	"context"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestServerDevLifecycleDrainSignalAndMetrics(t *testing.T) {
	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := startServer(t, ctx, "--listen", addr, "--runner-token", "runner-tok", "--admin-token", "admin-tok",
		"--drain-on-sigterm", "--metrics-listen", "127.0.0.1:0", "--pipeline-path", ".kiwi/pipeline.yaml")
	waitTCPUp(t, addr, errCh, 10*time.Second)
	// The health surface answers before the signal path drives the drain.
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	_ = resp.Body.Close()
	// Deliver SIGTERM to ourselves while the handler is installed: the
	// drain path runs (no active jobs) and the listener keeps serving.
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := stopServer(t, cancel, errCh); err != nil {
		t.Fatalf("Server returned %v after graceful shutdown", err)
	}
}
