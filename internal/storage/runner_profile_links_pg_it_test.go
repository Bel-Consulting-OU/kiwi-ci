package storage

// Real-PostgreSQL integration tests for the runner-ID -> profile binding
// (migration 0031). Gated on KIWI_TEST_POSTGRES_URL exactly like the other
// *_it_test.go files in this package: a throwaway schema per test, skipped
// when the variable is unset or in -short mode.
//
// The contract body is shared with the mem store
// (TestRunnerProfileLinksMemoryParity), so this file proves the durable
// table and the in-memory mirror answer identically, and then pins the two
// properties only the database can provide: the runner_id PRIMARY KEY and
// concurrent re-link convergence to exactly one row.

import (
	"context"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestIntegrationRunnerProfileLinksPostgres runs the shared
// RunnerProfileLinkStore contract against a real migrated PostgreSQL store
// and then exercises the PRIMARY KEY under concurrency.
func TestIntegrationRunnerProfileLinksPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	runRunnerProfileLinkContract(t, st)

	// The table exists with the expected primary key, so a duplicate
	// runner_id insert must be rejected by the database itself (the
	// uniqueness the old payload-serial scan could never provide).
	if _, err := st.pool.Exec(ctx, `INSERT INTO runner_profile_links (runner_id, profile_id) VALUES ('pk-runner', 'p-primary')`); err != nil {
		t.Fatalf("insert binding: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `INSERT INTO runner_profile_links (runner_id, profile_id) VALUES ('pk-runner', 'p-secondary')`); err == nil {
		t.Fatal("duplicate runner_id insert must violate the PRIMARY KEY")
	}
	if _, err := st.pool.Exec(ctx, `DELETE FROM runner_profile_links WHERE runner_id='pk-runner'`); err != nil {
		t.Fatalf("cleanup binding: %v", err)
	}

	// Concurrent re-links of one runner converge to exactly one binding
	// (last writer wins), never two profiles for one runner.
	for _, id := range []string{"race-a", "race-b"} {
		if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: id, MaxCapacity: 1}); err != nil {
			t.Fatalf("UpsertProfile %s: %v", id, err)
		}
	}
	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			target := "race-a"
			if i%2 == 1 {
				target = "race-b"
			}
			if err := st.LinkRunnerProfile(ctx, "race-runner", target); err != nil {
				t.Errorf("concurrent link: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if _, ok, err := st.ProfileForRunnerID(ctx, "race-runner"); err != nil || !ok {
		t.Fatalf("concurrent binding resolve ok=%v err=%v", ok, err)
	}
	rows, err := st.pool.Query(ctx, `SELECT profile_id FROM runner_profile_links WHERE runner_id='race-runner'`)
	if err != nil {
		t.Fatalf("query bindings: %v", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("runner has %d bindings, want exactly 1", count)
	}
}

// TestIntegrationRunnerProfileLinkReadsFailOnDroppedTable proves the read
// paths report a store error (not "not found") when the durable binding
// relation is gone, so a registration cannot mistake an outage for the
// unbound state.
func TestIntegrationRunnerProfileLinkReadsFailOnDroppedTable(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	if _, err := st.pool.Exec(ctx, `DROP TABLE runner_profile_links`); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	if _, ok, err := st.ProfileForRunnerID(ctx, "r1"); err == nil || ok {
		t.Fatalf("ProfileForRunnerID after drop = (ok=%v, err=%v), want an error", ok, err)
	}
	if _, err := st.RunnerIDsForProfile(ctx, "p"); err == nil {
		t.Fatal("RunnerIDsForProfile after drop must error")
	}
	if err := st.LinkRunnerProfile(ctx, "r1", "p"); err == nil {
		t.Fatal("LinkRunnerProfile after drop must error")
	}
	if err := st.UnlinkRunnerProfile(ctx, "r1"); err == nil {
		t.Fatal("UnlinkRunnerProfile after drop must error")
	}
}
