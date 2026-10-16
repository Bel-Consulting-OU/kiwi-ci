package perf

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood/system"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Percentile benchmarks record the full latency distribution, not just a
// mean. The audit's required shape is p50/p95/p99 at the fan-out points.
//
// Contract: every iteration IS one sample, so the benchmark's ns/op is the
// arithmetic mean of the real work. p50/p95/p99 are reported as extra
// metrics (p50-ns / p95-ns / p99-ns) so a reader sees the tail, and
// perf-compare.sh's ns/op parser keeps working unchanged.

// reportPercentiles sorts the collected samples and publishes p50/p95/p99.
func reportPercentiles(b *testing.B, samples []time.Duration) {
	if len(samples) == 0 {
		return
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	pct := func(q float64) float64 {
		idx := int(float64(len(samples)-1) * q)
		if idx < 0 {
			idx = 0
		}
		if idx >= len(samples) {
			idx = len(samples) - 1
		}
		return float64(samples[idx].Nanoseconds())
	}
	b.ReportMetric(pct(0.50), "p50-ns")
	b.ReportMetric(pct(0.95), "p95-ns")
	b.ReportMetric(pct(0.99), "p99-ns")
}

// BenchmarkPercentileSubmit: API submit → persisted run.
func BenchmarkPercentileSubmit(b *testing.B) {
	ctx := context.Background()
	sys := launchPerf(b)
	var samples []time.Duration
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		opts := system.SubmitOpts{
			RepoFullName: fmt.Sprintf("kiwi-dogfood/pct-%d", i),
			RepoURL:      fmt.Sprintf("https://github.com/kiwi-dogfood/pct-%d.git", i),
		}
		start := time.Now()
		if _, err := sys.SubmitPipeline(ctx, e2ePipeline, opts); err != nil {
			b.Fatalf("submit: %v", err)
		}
		samples = append(samples, time.Since(start))
	}
	b.StopTimer()
	reportPercentiles(b, samples)
}

// BenchmarkPercentileFullCycle: submit → lease → complete.
func BenchmarkPercentileFullCycle(b *testing.B) {
	ctx := context.Background()
	sys := launchPerf(b)
	runnerID, err := sys.RegisterRunner(ctx, "perf-pct", []string{"native", "container"})
	if err != nil {
		b.Fatalf("register: %v", err)
	}
	var samples []time.Duration
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		opts := system.SubmitOpts{
			RepoFullName: fmt.Sprintf("kiwi-dogfood/pctc-%d", i),
			RepoURL:      fmt.Sprintf("https://github.com/kiwi-dogfood/pctc-%d.git", i),
		}
		start := time.Now()
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
		samples = append(samples, time.Since(start))
	}
	b.StopTimer()
	reportPercentiles(b, samples)
}

// BenchmarkPercentileParallelSubmit: 8-way concurrent submit — the
// "many webhooks at once" shape where tail latency matters most.
func BenchmarkPercentileParallelSubmit(b *testing.B) {
	ctx := context.Background()
	sys := launchPerf(b)
	var samples []time.Duration
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		done := make(chan error, 8)
		for j := 0; j < 8; j++ {
			go func(j int) {
				opts := system.SubmitOpts{
					RepoFullName: fmt.Sprintf("kiwi-dogfood/pctp-%d-%d", i, j),
					RepoURL:      fmt.Sprintf("https://github.com/kiwi-dogfood/pctp-%d-%d.git", i, j),
				}
				_, err := sys.SubmitPipeline(ctx, e2ePipeline, opts)
				done <- err
			}(j)
		}
		for j := 0; j < 8; j++ {
			if err := <-done; err != nil {
				b.Errorf("submit: %v", err)
			}
		}
		samples = append(samples, time.Since(start))
	}
	b.StopTimer()
	reportPercentiles(b, samples)
}

// BenchmarkPercentileEvidence: evidence fetch + verify — the audit's
// "evidence overhead" row with tail visibility.
func BenchmarkPercentileEvidence(b *testing.B) {
	ctx := context.Background()
	sys := launchPerf(b)
	runnerID, err := sys.RegisterRunner(ctx, "perf-pct-ev", []string{"native", "container"})
	if err != nil {
		b.Fatalf("register: %v", err)
	}
	var samples []time.Duration
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		opts := system.SubmitOpts{
			RepoFullName: fmt.Sprintf("kiwi-dogfood/pcte-%d", i),
			RepoURL:      fmt.Sprintf("https://github.com/kiwi-dogfood/pcte-%d.git", i),
		}
		start := time.Now()
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
		env, err := sys.FetchEvidence(ctx, task.JobID, task.LeaseGeneration)
		if err != nil {
			b.Fatalf("fetch evidence: %v", err)
		}
		if _, err := sys.VerifyEvidence(ctx, env); err != nil {
			b.Fatalf("verify evidence: %v", err)
		}
		samples = append(samples, time.Since(start))
	}
	b.StopTimer()
	reportPercentiles(b, samples)
}
