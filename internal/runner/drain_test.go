package runner

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// TestDrainRunnerExitsIdle verifies kiwi runner --drain semantics: the
// runner registers with Draining=true, takes no work, and exits cleanly
// instead of polling forever.
func TestDrainRunnerExitsIdle(t *testing.T) {
	srv := server.New("runner-tok")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r := &Runner{Cfg: Config{Server: ts.URL, Token: "runner-tok", Poll: 10 * time.Millisecond, Drain: true}}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("drain runner exited with error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("drain runner did not exit")
	}

	// The server recorded the runner as draining.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/runners", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer runner-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var runners []model.Runner
	if err := json.NewDecoder(resp.Body).Decode(&runners); err != nil {
		t.Fatal(err)
	}
	if len(runners) != 1 || !runners[0].Draining {
		t.Fatalf("server runners = %+v, want exactly one draining runner", runners)
	}
}

// TestDrainRunnerReleasesMetricsPort pins the lifecycle ownership fix: a
// graceful drain happens with the parent context still ALIVE, and Run must
// cancel and join its private components before returning, so the metrics
// listener is closed by the time Run returns and an in-process restart can
// rebind the same port. A detached metrics server (the pre-fix shape) keeps
// the port bound and this test fails.
func TestDrainRunnerReleasesMetricsPort(t *testing.T) {
	// Reserve a concrete address, then free it for the runner to bind.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	srv := server.New("runner-tok")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r := &Runner{Cfg: Config{Server: ts.URL, Token: "runner-tok", Poll: 10 * time.Millisecond, MetricsListen: addr}}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	// Wait for the metrics listener to come up, then drain remotely.
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("metrics listener never came up on %s: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv.BeginDrain("test drain")
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("drain runner exited with error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("drain runner did not exit")
	}
	// Run returned: the metrics port must be immediately rebindable.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("metrics port still bound after Run returned: %v", err)
	}
	ln.Close()
}
