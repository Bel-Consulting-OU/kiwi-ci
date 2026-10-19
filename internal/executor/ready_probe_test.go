package executor

import (
	"context"
	"strings"
	"testing"
	"time"
)

// waitServiceReady now probes inside the job docker network. These tests
// drive the grammar and the fail-closed paths with a fake docker.

func TestWaitServiceReadyRejectsUnknownKind(t *testing.T) {
	err := waitServiceReady(context.Background(), "icmp:1", "db", "net1", func(string) {}, "svc")
	if err == nil || !strings.Contains(err.Error(), "tcp/http/pg_isready") {
		t.Fatalf("want unknown-kind error, got %v", err)
	}
}

func TestWaitServiceReadyRejectsBadForm(t *testing.T) {
	for _, probe := range []string{"", "tcp", "tcp:", "http:", "pg_isready:"} {
		err := waitServiceReady(context.Background(), probe, "db", "net1", func(string) {}, "svc")
		if err == nil {
			t.Fatalf("probe %q: want error", probe)
		}
		if !strings.Contains(err.Error(), "needs the form") {
			t.Fatalf("probe %q error = %v, want form list", probe, err)
		}
	}
}

func TestWaitServiceReadyRejectsEmptyAlias(t *testing.T) {
	err := waitServiceReady(context.Background(), "tcp:6379", "", "net1", func(string) {}, "svc")
	if err == nil || !strings.Contains(err.Error(), "needs the form") {
		t.Fatalf("want form error for empty alias, got %v", err)
	}
}

func TestWaitServiceReadyTimesOutWhenDockerAlwaysFails(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_RUN_FAIL", "1")
	old := serviceReadyTimeout
	serviceReadyTimeout = 400 * time.Millisecond
	defer func() { serviceReadyTimeout = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := waitServiceReady(ctx, "tcp:6379", "redis", "net1", func(string) {}, "redis")
	if err == nil {
		t.Fatal("expected timeout")
	}
}

func TestWaitServiceReadyRespectsCancel(t *testing.T) {
	installFakeBins(t)
	old := serviceReadyTimeout
	serviceReadyTimeout = time.Minute
	defer func() { serviceReadyTimeout = old }()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := waitServiceReady(ctx, "tcp:6379", "redis", "net1", func(string) {}, "redis")
	if err == nil {
		t.Fatal("want cancel error")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("cancel took %s", time.Since(start))
	}
}
