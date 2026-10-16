package perf

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood/system"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// End-to-end CI latency. These are NOT microbenchmarks: each one drives the
// real control plane over HTTP the way a runner or forge would, so the
// numbers include admission, persistence and scheduling — the path an
// operator actually waits on.
//
// Gate policy (scripts/perf-compare.sh): compare the MEDIAN of N samples
// against bench/baseline.txt and an absolute ceiling. Tight budgets need a
// dedicated idle host.

// Digest-pinned container job: the untrusted admission path requires a
// container/tart runtime and an immutable image identity.
const e2ePipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine:3.20@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1
    steps:
      - run: echo hi
`

func launchPerf(b *testing.B) *system.System {
	b.Helper()
	sys, err := system.Launch(system.SystemConfig{
		RunnerToken: "perf-runner",
		AdminToken:  "perf-admin",
		DataDir:     filepath.Join(b.TempDir(), "data"),
	})
	if err != nil {
		b.Fatalf("launch: %v", err)
	}
	b.Cleanup(func() { _ = sys.Close() })
	return sys
}

// BenchmarkE2ESubmitToPersistedRun measures API submit → durable run
// (webhook-equivalent admission path).
func BenchmarkE2ESubmitToPersistedRun(b *testing.B) {
	ctx := context.Background()
	sys := launchPerf(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		opts := system.SubmitOpts{
			RepoFullName: fmt.Sprintf("kiwi-dogfood/perf-%d", i),
			RepoURL:      fmt.Sprintf("https://github.com/kiwi-dogfood/perf-%d.git", i),
		}
		if _, err := sys.SubmitPipeline(ctx, e2ePipeline, opts); err != nil {
			b.Fatalf("submit: %v", err)
		}
	}
}

// BenchmarkE2ESubmitThenLease measures submit → schedulable → runner lease
// pickup. This is the "how long until work can start" number.
func BenchmarkE2ESubmitThenLease(b *testing.B) {
	ctx := context.Background()
	sys := launchPerf(b)
	runnerID, err := sys.RegisterRunner(ctx, "perf-lease", []string{"native", "container"})
	if err != nil {
		b.Fatalf("register: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		opts := system.SubmitOpts{
			RepoFullName: fmt.Sprintf("kiwi-dogfood/lease-%d", i),
			RepoURL:      fmt.Sprintf("https://github.com/kiwi-dogfood/lease-%d.git", i),
		}
		if _, err := sys.SubmitPipeline(ctx, e2ePipeline, opts); err != nil {
			b.Fatalf("submit: %v", err)
		}
		deadline := time.Now().Add(10 * time.Second)
		var leased system.LeaseTask
		for {
			task, ok, err := sys.Next(ctx, runnerID)
			if err == nil && ok {
				leased = task
				break
			}
			if time.Now().After(deadline) {
				b.Fatalf("lease pickup timed out: %v", err)
			}
			time.Sleep(2 * time.Millisecond)
		}
		// The runner holds ONE active lease: complete it before the next
		// pickup or the benchmark measures a stall, not scheduling latency.
		if _, err := sys.Complete(ctx, leased, model.StatusSuccess, ""); err != nil {
			b.Fatalf("complete: %v", err)
		}
	}
}

// BenchmarkE2EFullJobCycle measures submit → lease → complete (terminal
// status). This is the smallest unit of "CI work finished".
func BenchmarkE2EFullJobCycle(b *testing.B) {
	ctx := context.Background()
	sys := launchPerf(b)
	runnerID, err := sys.RegisterRunner(ctx, "perf-cycle", []string{"native", "container"})
	if err != nil {
		b.Fatalf("register: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		opts := system.SubmitOpts{
			RepoFullName: fmt.Sprintf("kiwi-dogfood/cycle-%d", i),
			RepoURL:      fmt.Sprintf("https://github.com/kiwi-dogfood/cycle-%d.git", i),
		}
		if _, err := sys.SubmitPipeline(ctx, e2ePipeline, opts); err != nil {
			b.Fatalf("submit: %v", err)
		}
		var task system.LeaseTask
		deadline := time.Now().Add(10 * time.Second)
		for {
			t, ok, err := sys.Next(ctx, runnerID)
			if err == nil && ok {
				task = t
				break
			}
			if time.Now().After(deadline) {
				b.Fatalf("lease timed out: %v", err)
			}
			time.Sleep(2 * time.Millisecond)
		}
		if _, err := sys.Complete(ctx, task, model.StatusSuccess, ""); err != nil {
			b.Fatalf("complete: %v", err)
		}
	}
}

// BenchmarkE2EParallelSubmit measures concurrent API submits against one
// server — the "many webhooks at once" shape.
func BenchmarkE2EParallelSubmit(b *testing.B) {
	ctx := context.Background()
	sys := launchPerf(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			opts := system.SubmitOpts{
				RepoFullName: fmt.Sprintf("kiwi-dogfood/par-%d", i),
				RepoURL:      fmt.Sprintf("https://github.com/kiwi-dogfood/par-%d.git", i),
			}
			if _, err := sys.SubmitPipeline(ctx, e2ePipeline, opts); err != nil {
				b.Errorf("submit: %v", err)
				return
			}
			i++
		}
	})
}
