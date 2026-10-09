package storage

// BenchmarkExecutionEventCursorContention measures the commit-ordered
// execution event cursor under 1,000 concurrent status-transition
// transactions (one PostgreSQL UPDATE per job, the migration 0045 trigger
// allocating the single-row cursor in each transaction). It is a MEASUREMENT
// only: the cursor design is deliberately not changed based on this number.
//
// Run (never part of the hermetic suite; skips without a DSN):
//
//	KIWI_TEST_POSTGRES_URL='postgres://postgres:postgres@127.0.0.1:5433/kiwi_it?sslmode=disable' \
//	  go test ./internal/storage -run '^$' -bench BenchmarkExecutionEventCursorContention -benchtime=1x
//
// Reference-host result (2026-10-08, 13th Gen Intel i7-13620H, local
// PostgreSQL with max_connections=100, template clone, synchronous_commit=off,
// 1,000 concurrent worker goroutines, pool max 64):
//
//	iterations      1
//	tx/s            3468
//	p50_ms          182.8
//	p99_ms          284.4
//	p999_ms         285.8
//
// The proposed SLO is p99 end-to-end transition latency < 50 ms at 1,000
// concurrent transitions on the reference host; it was NOT met in this
// configuration (p99 284.4 ms). The dominant term is orthogonal to the cursor
// design: 1,000 goroutines share a 64-connection pool and the cursor
// serializes the actual database work, so queueing for a connection and for
// the cursor row dominates the tail. The measurement is reported as-is (the
// cursor is deliberately NOT redesigned from this number); a smaller
// concurrency/connection ratio (or a pool near the server's
// max_connections) is the first lever to re-measure before setting a tighter
// SLO.
//
// An operator can raise the pool ceiling with KIWI_BENCH_PG_CONNS (default
// 64) as long as the server's max_connections allows it.

import (
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
)

const benchCursorTransitions = 1000

// benchPGStore opens a migrated store on a throwaway clone for the benchmark
// (same template path as the integration tests, via testing.TB).
func benchPGStore(b *testing.B) *PostgresStore {
	b.Helper()
	if testing.Short() {
		b.Skip("postgres benchmark skipped in -short mode")
	}
	base := strings.TrimSpace(os.Getenv("KIWI_TEST_POSTGRES_URL"))
	if base == "" {
		b.Skip("KIWI_TEST_POSTGRES_URL not set; skipping PostgreSQL benchmark")
	}
	conns := 64
	if raw := strings.TrimSpace(os.Getenv("KIWI_BENCH_PG_CONNS")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			conns = v
		}
	}
	testutil.EnsureTemplate(b, testutil.TemplateSpec{
		BaseDSN: base,
		Name:    pgITTemplateName,
		Migrate: func(ctx context.Context, dsn string) error {
			return pgITMigrateTemplate(ctx, dsn, 0)
		},
	}, pgITClonePrefix)
	clone := testutil.CloneDatabase(b, base, pgITTemplateName, pgITClonePrefix)
	st, err := NewPostgresOpt(context.Background(), clone, func(c *pgxpool.Config) {
		if c.ConnConfig.RuntimeParams == nil {
			c.ConnConfig.RuntimeParams = map[string]string{}
		}
		c.ConnConfig.RuntimeParams["search_path"] = "public"
		c.ConnConfig.RuntimeParams["synchronous_commit"] = "off"
		c.MaxConns = int32(conns)
	})
	if err != nil {
		b.Fatalf("open benchmark store: %v", err)
	}
	b.Cleanup(func() { _ = st.Close() })
	st.DisableSchemaFenceForTests()
	return st
}

// benchSeedTransitions seeds one run with n queued jobs in ONE transaction
// (no cursor contention during seeding) and returns the job IDs.
func benchSeedTransitions(b *testing.B, st *PostgresStore, n int) []string {
	b.Helper()
	ctx := context.Background()
	runID := pgITNewID(b)
	jobs := make(map[string]model.Job, n)
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id := pgITNewID(b)
		jobs[id] = pgITJob(runID, id, pgITRepo)
		ids = append(ids, id)
	}
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: jobs,
	}); err != nil {
		b.Fatalf("seed %d jobs: %v", n, err)
	}
	return ids
}

// BenchmarkExecutionEventCursorContention runs benchCursorTransitions
// concurrent status transitions per iteration and reports throughput plus the
// p50/p99 per-transition latency.
func BenchmarkExecutionEventCursorContention(b *testing.B) {
	st := benchPGStore(b)
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ids := benchSeedTransitions(b, st, benchCursorTransitions)
		b.StartTimer()

		durations := make([]time.Duration, len(ids))
		start := make(chan struct{})
		var wg sync.WaitGroup
		var firstErr error
		var errOnce sync.Once
		begin := time.Now()
		for i, id := range ids {
			wg.Add(1)
			go func(i int, id string) {
				defer wg.Done()
				<-start
				t0 := time.Now()
				_, err := st.pool.Exec(ctx, `UPDATE jobs SET status = 'blocked', error = 'cursor-bench' WHERE id = $1`, id)
				durations[i] = time.Since(t0)
				if err != nil {
					errOnce.Do(func() { firstErr = err })
				}
			}(i, id)
		}
		close(start)
		wg.Wait()
		elapsed := time.Since(begin)
		if firstErr != nil {
			b.Fatalf("benchmark transition failed: %v", firstErr)
		}

		sorted := append([]time.Duration(nil), durations...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		p := func(q float64) time.Duration {
			if len(sorted) == 0 {
				return 0
			}
			idx := int(q * float64(len(sorted)-1))
			return sorted[idx]
		}
		b.ReportMetric(float64(len(ids))/elapsed.Seconds(), "tx/s")
		b.ReportMetric(float64(p(0.50).Microseconds())/1000, "p50_ms")
		b.ReportMetric(float64(p(0.99).Microseconds())/1000, "p99_ms")
		b.ReportMetric(float64(p(0.999).Microseconds())/1000, "p999_ms")
	}
}
