package storage

// Real-PostgreSQL integration tests for the keyset-paged runs collection
// (RunPageStore). They are gated on KIWI_TEST_POSTGRES_URL exactly like the
// other storage integration tests: skipped when the variable is unset and in
// -short mode. Each test opens its own throwaway schema through pgITStore.
//
// The tests pin the properties the collection endpoint relies on: a walk
// over more than one default page returns every run exactly once in
// (created_at DESC, id DESC) order, inserting runs between page reads can
// neither duplicate nor skip rows, and the memory implementation returns the
// same pages as the SQL implementation for the same cursor.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// runsPageITID returns the i-th 32-hex run id. Lexicographic order matches
// numeric order for a fixed 32-character encoding, which the tests use to
// predict the keyset order.
func runsPageITID(i int) string { return fmt.Sprintf("%032x", i+1) }

// runsPageITSeedOrdered inserts total runs with strictly increasing
// created_at (one second apart) and runsPageITID ids, returning the runs in
// insertion order.
func runsPageITSeedOrdered(t *testing.T, st *PostgresStore, total int) []model.Run {
	t.Helper()
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Microsecond)
	runs := make([]model.Run, total)
	for i := range runs {
		runs[i] = model.Run{
			ID:        runsPageITID(i),
			Status:    model.StatusSuccess,
			CreatedAt: base.Add(time.Duration(i) * time.Second),
		}
		if err := st.InsertRun(ctx, runs[i]); err != nil {
			t.Fatalf("insert run %d: %v", i, err)
		}
	}
	return runs
}

// TestPostgresIntegrationRunsPageBeyondDefaultLimit walks 1005 runs with the
// default page size: the first page is the historical newest-1000 window and
// the second page carries the five runs that used to disappear, with no
// duplicate and no omission against the non-paged ListRuns order.
func TestPostgresIntegrationRunsPageBeyondDefaultLimit(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	const total = 1005
	runsPageITSeedOrdered(t, st, total)

	legacy, err := st.ListRuns(ctx, MaxRunsPageLimit)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(legacy) != total {
		t.Fatalf("ListRuns window = %d runs, want %d", len(legacy), total)
	}
	if legacy[0].ID != runsPageITID(total-1) || legacy[total-1].ID != runsPageITID(0) {
		t.Fatalf("ListRuns order = first %s last %s, want newest-first", legacy[0].ID, legacy[total-1].ID)
	}

	// limit 0 selects the default page size.
	page1, err := st.ListRunsPage(ctx, time.Time{}, "", 0)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Runs) != DefaultRunsPageLimit {
		t.Fatalf("page1 = %d runs, want the %d default", len(page1.Runs), DefaultRunsPageLimit)
	}
	if !page1.HasMore || page1.NextID != legacy[DefaultRunsPageLimit-1].ID {
		t.Fatalf("page1 boundary = HasMore %v next %q, want %q", page1.HasMore, page1.NextID, legacy[DefaultRunsPageLimit-1].ID)
	}

	page2, err := st.ListRunsPage(ctx, page1.NextCreatedAt, page1.NextID, 0)
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Runs) != total-DefaultRunsPageLimit {
		t.Fatalf("page2 = %d runs, want %d", len(page2.Runs), total-DefaultRunsPageLimit)
	}
	if page2.HasMore || page2.NextID != "" || !page2.NextCreatedAt.IsZero() {
		t.Fatalf("page2 = HasMore %v next %q, want terminal", page2.HasMore, page2.NextID)
	}

	walk := make([]model.Run, 0, total)
	walk = append(walk, page1.Runs...)
	walk = append(walk, page2.Runs...)
	seen := make(map[string]bool, total)
	for i, run := range walk {
		if seen[run.ID] {
			t.Fatalf("duplicate run %s in the walk", run.ID)
		}
		seen[run.ID] = true
		if run.ID != legacy[i].ID {
			t.Fatalf("walk[%d] = %s, legacy = %s", i, run.ID, legacy[i].ID)
		}
	}
	if len(seen) != total {
		t.Fatalf("walk covered %d runs, want %d", len(seen), total)
	}
}

// TestPostgresIntegrationRunsPageMemoryParity runs the identical seed and
// cursor walk against memStore and PostgresStore — including an insert
// between pages — and requires page-for-page equality (ids, order, HasMore,
// next position). Memory and SQL pages share the PageRuns definition, and
// this pins that they cannot drift.
func TestPostgresIntegrationRunsPageMemoryParity(t *testing.T) {
	st := pgITStore(t)
	mem := newMemStore()
	ctx := context.Background()
	const total = 25
	base := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < total; i++ {
		run := model.Run{
			ID:     fmt.Sprintf("%032x", i+1),
			Status: model.StatusSuccess,
			// Three runs per instant so the id tiebreak is exercised.
			CreatedAt: base.Add(time.Duration(i/3) * time.Millisecond),
		}
		if err := st.InsertRun(ctx, run); err != nil {
			t.Fatalf("pg insert %d: %v", i, err)
		}
		if err := mem.InsertRun(ctx, run); err != nil {
			t.Fatalf("mem insert %d: %v", i, err)
		}
	}

	// Walk both stores from the cursor until both report the end, comparing
	// every page and requiring strict cursor progress.
	parityWalk := func(label string) []string {
		t.Helper()
		afterAt, afterID := time.Time{}, ""
		var ids []string
		for page := 0; ; page++ {
			if page > total+2 {
				t.Fatalf("%s walk did not terminate", label)
			}
			pgPage, err := st.ListRunsPage(ctx, afterAt, afterID, 7)
			if err != nil {
				t.Fatalf("%s pg page %d: %v", label, page, err)
			}
			memPage, err := mem.ListRunsPage(ctx, afterAt, afterID, 7)
			if err != nil {
				t.Fatalf("%s mem page %d: %v", label, page, err)
			}
			pgIDs, memIDs := runsPageIDs(pgPage), runsPageIDs(memPage)
			if strings.Join(pgIDs, ",") != strings.Join(memIDs, ",") {
				t.Fatalf("%s page %d: pg %v != mem %v", label, page, pgIDs, memIDs)
			}
			if pgPage.HasMore != memPage.HasMore ||
				pgPage.NextID != memPage.NextID ||
				!pgPage.NextCreatedAt.Equal(memPage.NextCreatedAt) {
				t.Fatalf("%s page %d boundary: pg (hm=%v next=%q) != mem (hm=%v next=%q)",
					label, page, pgPage.HasMore, pgPage.NextID, memPage.HasMore, memPage.NextID)
			}
			ids = append(ids, pgIDs...)
			if !pgPage.HasMore {
				return ids
			}
			afterAt, afterID = pgPage.NextCreatedAt, pgPage.NextID
		}
	}

	all := parityWalk("initial")
	if len(all) != total {
		t.Fatalf("initial walk = %d runs, want %d", len(all), total)
	}
	if all[0] != fmt.Sprintf("%032x", total) || all[total-1] != fmt.Sprintf("%032x", 1) {
		t.Fatalf("initial walk order = %s..%s, want newest-first", all[0], all[total-1])
	}

	// First page of a fresh walk, then insert between pages in BOTH stores: a
	// newer run (never part of the ongoing walk) and a row tied with the
	// cursor instant but with a smaller id (must appear later, exactly once).
	pg1, err := st.ListRunsPage(ctx, time.Time{}, "", 5)
	if err != nil {
		t.Fatalf("pg page1: %v", err)
	}
	mem1, err := mem.ListRunsPage(ctx, time.Time{}, "", 5)
	if err != nil {
		t.Fatalf("mem page1: %v", err)
	}
	if strings.Join(runsPageIDs(pg1), ",") != strings.Join(runsPageIDs(mem1), ",") {
		t.Fatalf("page1 parity: pg %v mem %v", runsPageIDs(pg1), runsPageIDs(mem1))
	}
	tie := model.Run{ID: fmt.Sprintf("%032x", 0), Status: model.StatusSuccess, CreatedAt: pg1.NextCreatedAt}
	newest := model.Run{ID: fmt.Sprintf("%032x", 99), Status: model.StatusSuccess, CreatedAt: base.Add(time.Hour)}
	for _, run := range []model.Run{tie, newest} {
		if err := st.InsertRun(ctx, run); err != nil {
			t.Fatalf("pg insert %s: %v", run.ID, err)
		}
		if err := mem.InsertRun(ctx, run); err != nil {
			t.Fatalf("mem insert %s: %v", run.ID, err)
		}
	}

	// Continue the walk on both stores from the page1 cursor.
	afterAt, afterID := pg1.NextCreatedAt, pg1.NextID
	var tail []string
	for page := 0; ; page++ {
		if page > total+2 {
			t.Fatal("continuation walk did not terminate")
		}
		pgPage, err := st.ListRunsPage(ctx, afterAt, afterID, 7)
		if err != nil {
			t.Fatalf("pg continuation %d: %v", page, err)
		}
		memPage, err := mem.ListRunsPage(ctx, afterAt, afterID, 7)
		if err != nil {
			t.Fatalf("mem continuation %d: %v", page, err)
		}
		if strings.Join(runsPageIDs(pgPage), ",") != strings.Join(runsPageIDs(memPage), ",") {
			t.Fatalf("continuation %d: pg %v != mem %v", page, runsPageIDs(pgPage), runsPageIDs(memPage))
		}
		tail = append(tail, runsPageIDs(pgPage)...)
		if !pgPage.HasMore {
			break
		}
		afterAt, afterID = pgPage.NextCreatedAt, pgPage.NextID
	}
	counts := map[string]int{}
	for _, id := range tail {
		counts[id]++
	}
	if counts[tie.ID] != 1 {
		t.Fatalf("tie row appeared %d times in the continuation, want 1", counts[tie.ID])
	}
	if counts[newest.ID] != 0 {
		t.Fatalf("newer insert appeared in the ongoing walk (%d times)", counts[newest.ID])
	}
	if want := total - len(pg1.Runs) + 1; len(tail) != want {
		t.Fatalf("continuation covered %d runs, want %d", len(tail), want)
	}

	// A fresh walk starts from the newest insert.
	fresh, err := st.ListRunsPage(ctx, time.Time{}, "", 1)
	if err != nil {
		t.Fatalf("fresh pg page: %v", err)
	}
	if len(fresh.Runs) != 1 || fresh.Runs[0].ID != newest.ID {
		t.Fatalf("fresh first page = %v, want the newest insert", runsPageIDs(fresh))
	}
}

// TestPostgresIntegrationRunsPageClosedPoolFails covers the query-error
// branch: a closed pool must report an error rather than an empty page (an
// empty page would read as "no runs", not "unknown").
func TestPostgresIntegrationRunsPageClosedPoolFails(t *testing.T) {
	dsn := pgITDSN(t)
	st, err := NewPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatalf("NewPostgres: %v", err)
	}
	_ = st.Close()
	if _, err := st.ListRunsPage(context.Background(), time.Time{}, "", 5); err == nil {
		t.Fatal("ListRunsPage on a closed pool = nil error")
	}
}
