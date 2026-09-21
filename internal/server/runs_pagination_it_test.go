package server

// Real-PostgreSQL integration tests for the keyset-paginated runs API: the
// collection is driven over the HTTP handlers against a live store, so the
// cursor, the limit cap, the ordering and the after-paging RBAC filter are
// exercised end to end against Postgres (the memory-mode equivalents live in
// runs_pagination_test.go). Gated on KIWI_TEST_POSTGRES_URL exactly like the
// other server integration tests.
//
// The store is attached directly (s.DB = st): these tests are read-path only
// and do not need the scheduler wiring SwitchToDB installs.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// pgITRunsPageID returns the i-th 32-hex run id (lexicographic order matches
// numeric order at a fixed width).
func pgITRunsPageID(i int) string { return fmt.Sprintf("%032x", i+1) }

// pgITRunsPageRun builds run i in the requested repository with a distinct
// created_at (one second apart) and a stable id.
func pgITRunsPageRun(i int, base time.Time, repoA bool) model.Run {
	run := model.Run{
		ID:        pgITRunsPageID(i),
		Status:    model.StatusSuccess,
		CreatedAt: base.Add(time.Duration(i) * time.Second),
	}
	if repoA {
		run.Repo = "https://github.com/o/repo-a.git"
		run.RepoFullName = "o/repo-a"
	} else {
		run.Repo = "https://github.com/o/repo-b.git"
		run.RepoFullName = "o/repo-b"
	}
	return run
}

func pgITRunsPageSeed(t *testing.T, st *storage.PostgresStore, runs []model.Run) {
	t.Helper()
	for _, run := range runs {
		if err := st.InsertRun(context.Background(), run); err != nil {
			t.Fatalf("insert run %s: %v", run.ID, err)
		}
	}
}

type pgITRunsPageWalkPage struct {
	ids    []string
	cursor string
	capHdr string
}

// pgITRunsPageWalk follows the collection's cursor contract until the next
// cursor header is absent.
func pgITRunsPageWalk(t *testing.T, s *Server, bearer string, limit, maxPages int) []pgITRunsPageWalkPage {
	t.Helper()
	pages := []pgITRunsPageWalkPage{}
	cursor := ""
	for i := 0; i < maxPages; i++ {
		path := "/api/v1/runs?limit=" + strconv.Itoa(limit)
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		w := pgITDo(t, s, http.MethodGet, path, bearer, "", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("page %d = %d: %s", i, w.Code, w.Body.String())
		}
		pages = append(pages, pgITRunsPageWalkPage{
			ids:    runIDs(t, w.Body.String()),
			cursor: w.Header().Get("X-Kiwi-Next-Cursor"),
			capHdr: w.Header().Get("X-Kiwi-Runs-Limit-Cap"),
		})
		cursor = pages[len(pages)-1].cursor
		if cursor == "" {
			return pages
		}
	}
	t.Fatalf("walk did not terminate within %d pages", maxPages)
	return nil
}

// TestPostgresIntegrationRunsPaginationHTTP is the end-to-end regression pin
// for the defect: with 1005 runs the first HTTP page is still the newest
// 1000 and the cursor header leads to the remaining five — no duplicate, no
// omission — and the cap is advertised.
func TestPostgresIntegrationRunsPaginationHTTP(t *testing.T) {
	env := pgITServerSetup(t)
	st := env.open(t)
	s := New("token")
	s.DB = st

	const total = 1005
	base := time.Now().UTC().Truncate(time.Microsecond)
	runs := make([]model.Run, 0, total)
	for i := 0; i < total; i++ {
		runs = append(runs, pgITRunsPageRun(i, base, true))
	}
	pgITRunsPageSeed(t, st, runs)

	pages := pgITRunsPageWalk(t, s, "token", storage.DefaultRunsPageLimit, 4)
	if len(pages) != 2 {
		t.Fatalf("walk = %d pages, want 2", len(pages))
	}
	if len(pages[0].ids) != storage.DefaultRunsPageLimit {
		t.Fatalf("first page = %d runs, want %d", len(pages[0].ids), storage.DefaultRunsPageLimit)
	}
	if len(pages[1].ids) != total-storage.DefaultRunsPageLimit || pages[1].cursor != "" {
		t.Fatalf("second page = %d runs cursor %q", len(pages[1].ids), pages[1].cursor)
	}
	if pages[0].capHdr != strconv.Itoa(storage.MaxRunsPageLimit) {
		t.Fatalf("limit cap header = %q, want %d", pages[0].capHdr, storage.MaxRunsPageLimit)
	}
	all := append(append([]string{}, pages[0].ids...), pages[1].ids...)
	if len(all) != total {
		t.Fatalf("walk covered %d runs, want %d", len(all), total)
	}
	seen := map[string]bool{}
	for i, id := range all {
		if seen[id] {
			t.Fatalf("duplicate run %s in the walk", id)
		}
		seen[id] = true
		if want := pgITRunsPageID(total - 1 - i); id != want {
			t.Fatalf("walk[%d] = %s, want %s", i, id, want)
		}
	}
}

// TestPostgresIntegrationRunsPaginationInsertStability proves that inserts
// between HTTP page reads can neither duplicate nor skip: a newer run never
// enters the ongoing walk, a row tied with the cursor instant and a smaller
// id is reached once on the next page, and a fresh first page starts at the
// newest insert.
func TestPostgresIntegrationRunsPaginationInsertStability(t *testing.T) {
	env := pgITServerSetup(t)
	st := env.open(t)
	s := New("token")
	s.DB = st

	base := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < 12; i++ {
		pgITRunsPageSeed(t, st, []model.Run{pgITRunsPageRun(i, base, true)})
	}

	page1 := pgITDo(t, s, http.MethodGet, "/api/v1/runs?limit=3", "token", "", nil)
	if page1.Code != http.StatusOK {
		t.Fatalf("page1 = %d: %s", page1.Code, page1.Body.String())
	}
	if ids := runIDs(t, page1.Body.String()); strings.Join(ids, ",") != pgITRunsPageID(11)+","+pgITRunsPageID(10)+","+pgITRunsPageID(9) {
		t.Fatalf("page1 = %v", ids)
	}
	cursor := page1.Header().Get("X-Kiwi-Next-Cursor")
	if cursor == "" {
		t.Fatal("page1 carried no next cursor")
	}

	newer1 := pgITRunsPageRun(89, base, true) // ids 90, 91; newer than every seed
	newer1.CreatedAt = base.Add(time.Hour)
	newer2 := pgITRunsPageRun(90, base, true)
	newer2.CreatedAt = base.Add(time.Hour)
	tie := pgITRunsPageRun(0, base, true)
	tie.ID = fmt.Sprintf("%032x", 0) // same instant as the cursor, smaller id
	tie.CreatedAt = base.Add(9 * time.Second)
	pgITRunsPageSeed(t, st, []model.Run{newer1, newer2, tie})

	tail := []string{}
	next := cursor
	for page := 0; next != ""; page++ {
		if page > 12 {
			t.Fatal("walk did not terminate")
		}
		w := pgITDo(t, s, http.MethodGet, "/api/v1/runs?limit=4&cursor="+url.QueryEscape(next), "token", "", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("continuation %d = %d: %s", page, w.Code, w.Body.String())
		}
		tail = append(tail, runIDs(t, w.Body.String())...)
		next = w.Header().Get("X-Kiwi-Next-Cursor")
	}
	if len(tail) != 10 {
		t.Fatalf("continuation covered %d runs, want 10", len(tail))
	}
	if tail[0] != tie.ID {
		t.Fatalf("continuation starts at %s, want the tied row %s", tail[0], tie.ID)
	}
	counts := map[string]int{}
	for _, id := range tail {
		counts[id]++
	}
	if counts[tie.ID] != 1 {
		t.Fatalf("tied row appeared %d times, want 1", counts[tie.ID])
	}
	for _, run := range []model.Run{newer1, newer2} {
		if counts[run.ID] != 0 {
			t.Fatalf("newer insert %s entered the ongoing walk", run.ID)
		}
	}
	seen := map[string]bool{}
	for _, id := range append(append([]string{}, runIDs(t, page1.Body.String())...), tail...) {
		if seen[id] {
			t.Fatalf("duplicate run %s in the walk", id)
		}
		seen[id] = true
	}

	fresh := pgITDo(t, s, http.MethodGet, "/api/v1/runs?limit=2", "token", "", nil)
	if ids := runIDs(t, fresh.Body.String()); strings.Join(ids, ",") != newer2.ID+","+newer1.ID {
		t.Fatalf("fresh first page = %v, want the newest inserts", ids)
	}
}

// TestPostgresIntegrationRunsPaginationRBAC pins after-paging authorization
// against real Postgres: the newest page of a repo-scoped reader is entirely
// invisible and still carries a cursor, the visible runs arrive on later
// pages, and the walk terminates — a false last page can never hide them.
func TestPostgresIntegrationRunsPaginationRBAC(t *testing.T) {
	env := pgITServerSetup(t)
	st := env.open(t)
	s := New("token")
	s.DB = st
	if err := s.AuthStore.AddToken("reader", auth.Principal{
		Subject:      "reader",
		Repositories: map[string]auth.RepositoryPermission{"o/repo-a": {Read: true}},
	}); err != nil {
		t.Fatal(err)
	}

	base := time.Now().UTC().Truncate(time.Microsecond)
	// Newest-first layout over i = 7..0: H H V V V V H H.
	for i := 7; i >= 0; i-- {
		pgITRunsPageSeed(t, st, []model.Run{pgITRunsPageRun(i, base, i >= 2 && i <= 5)})
	}

	pages := pgITRunsPageWalk(t, s, "reader", 2, 8)
	if len(pages) != 4 {
		t.Fatalf("reader walk = %d pages, want 4", len(pages))
	}
	if len(pages[0].ids) != 0 || pages[0].cursor == "" {
		t.Fatalf("first page = %v cursor %q, want empty with a next cursor", pages[0].ids, pages[0].cursor)
	}
	if strings.Join(pages[1].ids, ",") != pgITRunsPageID(5)+","+pgITRunsPageID(4) ||
		strings.Join(pages[2].ids, ",") != pgITRunsPageID(3)+","+pgITRunsPageID(2) {
		t.Fatalf("visible pages = %v / %v", pages[1].ids, pages[2].ids)
	}
	if len(pages[3].ids) != 0 || pages[3].cursor != "" {
		t.Fatalf("last page = %v cursor %q, want empty and terminal", pages[3].ids, pages[3].cursor)
	}
	seen := map[string]bool{}
	for _, page := range pages {
		for _, id := range page.ids {
			if seen[id] {
				t.Fatalf("duplicate visible run %s", id)
			}
			seen[id] = true
		}
	}
	if len(seen) != 4 {
		t.Fatalf("reader saw %d runs, want the 4 repo-a runs", len(seen))
	}

	adminPages := pgITRunsPageWalk(t, s, "token", 2, 8)
	if len(adminPages) != 4 {
		t.Fatalf("admin walk = %d pages, want 4", len(adminPages))
	}
	all := []string{}
	for _, page := range adminPages {
		all = append(all, page.ids...)
	}
	if len(all) != 8 {
		t.Fatalf("admin saw %d runs, want 8", len(all))
	}
}
