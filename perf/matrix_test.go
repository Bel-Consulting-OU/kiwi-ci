package perf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood/system"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Scale matrix. The audit's required shape is 1 → 10 → 100 → 1000
// simultaneous jobs plus a 10k queue. Each benchmark runs N submits in
// parallel and reports per-op cost; the gate compares the MEDIAN.

func benchParallelSubmit(b *testing.B, parallel int) {
	ctx := context.Background()
	sys := launchPerf(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			opts := system.SubmitOpts{
				RepoFullName: fmt.Sprintf("kiwi-dogfood/p%d-%d", parallel, i),
				RepoURL:      fmt.Sprintf("https://github.com/kiwi-dogfood/p%d-%d.git", parallel, i),
			}
			if _, err := sys.SubmitPipeline(ctx, e2ePipeline, opts); err != nil {
				b.Errorf("submit: %v", err)
				return
			}
			i++
		}
	})
}

// BenchmarkScaleSubmit1 through 1000 measure concurrent API admission at
// the audit's required fan-out points.
func BenchmarkScaleSubmit1(b *testing.B)    { benchParallelSubmit(b, 1) }
func BenchmarkScaleSubmit10(b *testing.B)   { benchParallelSubmit(b, 10) }
func BenchmarkScaleSubmit100(b *testing.B)  { benchParallelSubmit(b, 100) }
func BenchmarkScaleSubmit1000(b *testing.B) { benchParallelSubmit(b, 1000) }

// BenchmarkScaleQueue10000 measures enqueueing a large job wave into one
// server (the queue-depth shape) without waiting for execution.
//
// Wave size is PERF_QUEUE_WAVE. The DEFAULT is 200: a gate sample must
// finish in a couple of seconds, not minutes. The audit's full 10,000-job
// queue shape is the opt-in run (`PERF_QUEUE_WAVE=10000 go test -bench
// ScaleQueue`). At 200 the benchmark still exercises the concurrent
// enqueue path (32-way fan-out) without pinning the box.
func BenchmarkScaleQueue10000(b *testing.B) {
	ctx := context.Background()
	sys := launchPerf(b)
	wave := 200
	if v := os.Getenv("PERF_QUEUE_WAVE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			wave = n
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		errCh := make(chan error, wave)
		sem := make(chan struct{}, 32)
		for j := 0; j < wave; j++ {
			wg.Add(1)
			sem <- struct{}{}
			go func(j int) {
				defer wg.Done()
				defer func() { <-sem }()
				opts := system.SubmitOpts{
					RepoFullName: fmt.Sprintf("kiwi-dogfood/q%d-%d", i, j),
					RepoURL:      fmt.Sprintf("https://github.com/kiwi-dogfood/q%d-%d.git", i, j),
				}
				if _, err := sys.SubmitPipeline(ctx, e2ePipeline, opts); err != nil {
					errCh <- err
				}
			}(j)
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			if err != nil {
				b.Fatalf("submit wave: %v", err)
			}
		}
	}
}

// BenchmarkScaleLease100 measures lease pickup with 100 runners competing
// for work — the scheduler hot path.
func BenchmarkScaleLease100(b *testing.B) {
	ctx := context.Background()
	sys := launchPerf(b)
	const runners = 100
	ids := make([]string, runners)
	for r := 0; r < runners; r++ {
		id, err := sys.RegisterRunner(ctx, fmt.Sprintf("perf-r%d", r), []string{"native", "container"})
		if err != nil {
			b.Fatalf("register: %v", err)
		}
		ids[r] = id
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		opts := system.SubmitOpts{
			RepoFullName: fmt.Sprintf("kiwi-dogfood/l%d", i),
			RepoURL:      fmt.Sprintf("https://github.com/kiwi-dogfood/l%d.git", i),
		}
		if _, err := sys.SubmitPipeline(ctx, e2ePipeline, opts); err != nil {
			b.Fatalf("submit: %v", err)
		}
		deadline := time.Now().Add(15 * time.Second)
		for {
			leased := false
			for _, rid := range ids {
				task, ok, err := sys.Next(ctx, rid)
				if err == nil && ok {
					if _, err := sys.Complete(ctx, task, model.StatusSuccess, ""); err != nil {
						b.Fatalf("complete: %v", err)
					}
					leased = true
					break
				}
			}
			if leased {
				break
			}
			if time.Now().After(deadline) {
				b.Fatalf("no runner leased within 15s")
			}
		}
	}
}

// BenchmarkScaleEvidenceOverhead measures the evidence fetch + verify path
// on top of a completed job — the audit's "evidence overhead" row.
func BenchmarkScaleEvidenceOverhead(b *testing.B) {
	ctx := context.Background()
	sys := launchPerf(b)
	runnerID, err := sys.RegisterRunner(ctx, "perf-ev", []string{"native", "container"})
	if err != nil {
		b.Fatalf("register: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		opts := system.SubmitOpts{
			RepoFullName: fmt.Sprintf("kiwi-dogfood/e%d", i),
			RepoURL:      fmt.Sprintf("https://github.com/kiwi-dogfood/e%d.git", i),
		}
		runID, err := sys.SubmitPipeline(ctx, e2ePipeline, opts)
		if err != nil {
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
		// Evidence fetch + verify is the overhead under measurement.
		env, err := sys.FetchEvidence(ctx, task.JobID, task.LeaseGeneration)
		if err != nil {
			b.Fatalf("fetch evidence: %v", err)
		}
		if _, err := sys.VerifyEvidence(ctx, env); err != nil {
			b.Fatalf("verify evidence: %v", err)
		}
		_ = runID
	}
}

// BenchmarkScaleCacheOverhead measures cache restore/save wall time for a
// job that declares a cache — the audit's cache row.
func BenchmarkScaleCacheOverhead(b *testing.B) {
	ctx := context.Background()
	dir := b.TempDir()
	sys, err := system.Launch(system.SystemConfig{
		RunnerToken: "perf-runner",
		AdminToken:  "perf-admin",
		DataDir:     filepath.Join(dir, "data"),
	})
	if err != nil {
		b.Fatalf("launch: %v", err)
	}
	b.Cleanup(func() { _ = sys.Close() })
	runnerID, err := sys.RegisterRunner(ctx, "perf-cache", []string{"native", "container"})
	if err != nil {
		b.Fatalf("register: %v", err)
	}
	cached := `version: 1
jobs:
  build:
    runtime: container
    image: alpine:3.20@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1
    cache:
      - name: c
        paths: [".kiwi/cache"]
        hash_files: ["go.sum"]
    steps:
      - run: mkdir -p .kiwi/cache && echo x > .kiwi/cache/f
`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		opts := system.SubmitOpts{
			RepoFullName: fmt.Sprintf("kiwi-dogfood/c%d", i),
			RepoURL:      fmt.Sprintf("https://github.com/kiwi-dogfood/c%d.git", i),
		}
		if _, err := sys.SubmitPipeline(ctx, cached, opts); err != nil {
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
