package server

// Real-PostgreSQL integration tests for the keyset-paginated runs API: the
// collection is driven over the HTTP handlers against a live store, so the
// cursor, the limit cap, the ordering and the BEFORE-paging authorization
// filter are exercised end to end against Postgres (the memory-mode
// equivalents live in runs_pagination_test.go). Gated on
// KIWI_TEST_POSTGRES_URL exactly like the other server integration tests.
//
// The store is attached directly (s.DB = st): these tests are read-path only
// and do not need the scheduler wiring SwitchToDB installs.

import (
	"context"
	"encoding/json"
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

// TestPostgresIntegrationRunsPaginationAuthorizedPagesExcludeInvisibleRuns
// pins before-paging authorization against real Postgres: a repo-scoped
// reader's walk contains only its visible runs, every cursor is the last
// visible run of its page, and no empty intermediate page appears.
func TestPostgresIntegrationRunsPaginationAuthorizedPagesExcludeInvisibleRuns(t *testing.T) {
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
	if len(pages) != 2 {
		t.Fatalf("reader walk = %d pages, want 2", len(pages))
	}
	if strings.Join(pages[0].ids, ",") != pgITRunsPageID(5)+","+pgITRunsPageID(4) ||
		strings.Join(pages[1].ids, ",") != pgITRunsPageID(3)+","+pgITRunsPageID(2) {
		t.Fatalf("visible pages = %v / %v", pages[0].ids, pages[1].ids)
	}
	if pages[0].cursor == "" || pages[1].cursor != "" {
		t.Fatalf("cursors = %q / %q, want a next cursor only on the first page", pages[0].cursor, pages[1].cursor)
	}
	// Every cursor decodes to the last VISIBLE run of its page: the invisible
	// runs surrounding it (ids 7,6 newer; 1,0 older) must never appear.
	for i, page := range pages[:len(pages)-1] {
		decoded, ok := decodeRunsCursor(page.cursor)
		if !ok {
			t.Fatalf("page %d cursor does not decode", i)
		}
		if decoded.id != page.ids[len(page.ids)-1] {
			t.Fatalf("page %d cursor id = %q, want the last visible run %q", i, decoded.id, page.ids[len(page.ids)-1])
		}
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

// pgITRunsPageAOnlyServer opens a SECOND throwaway schema seeded with only
// the readable runs, so the mixed-collection walk can be compared against an
// equivalent data set that contains no private rows.
func pgITRunsPageAOnlyServer(t *testing.T, runs []model.Run) *Server {
	t.Helper()
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
	pgITRunsPageSeed(t, st, runs)
	return s
}

// TestPostgresIntegrationRunsPaginationAuthorizedReposNoLeak is the real-PG
// P1 regression: 2,500 private-B runs surround three readable-A runs and an
// A-only principal must observe (a) exactly the A runs with no B id or
// timestamp anywhere, (b) cursors that decode to the last visible A run,
// (c) the same pages as an equivalent A-only data set, and (d) no empty
// intermediate page that would reveal B density.
func TestPostgresIntegrationRunsPaginationAuthorizedReposNoLeak(t *testing.T) {
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
	const (
		total  = 2500
		firstA = 1200
		lastA  = 1202
	)
	aRuns := make([]model.Run, 0, 3)
	for i := 0; i < total; i++ {
		run := pgITRunsPageRun(i, base, i >= firstA && i <= lastA)
		pgITRunsPageSeed(t, st, []model.Run{run})
		if i >= firstA && i <= lastA {
			aRuns = append(aRuns, run)
		}
	}
	wantIDs := []string{aRuns[2].ID, aRuns[1].ID, aRuns[0].ID}
	aTimes := map[string]time.Time{}
	for _, run := range aRuns {
		aTimes[run.ID] = run.CreatedAt
	}

	// (a)+(b) Walk one A run at a time so every page boundary and every
	// returned timestamp is observable: each page must carry exactly one A
	// run, and its cursor must decode to that same visible run's position.
	type runDTO struct {
		ID        string    `json:"id"`
		CreatedAt time.Time `json:"created_at"`
	}
	var gotIDs []string
	pages := []pgITRunsPageWalkPage{}
	cursor := ""
	for i := 0; ; i++ {
		if i > 8 {
			t.Fatal("reader walk did not terminate")
		}
		path := "/api/v1/runs?limit=1"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		w := pgITDo(t, s, http.MethodGet, path, "reader", "", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("page %d = %d: %s", i, w.Code, w.Body.String())
		}
		var body []runDTO
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("page %d body: %v", i, err)
		}
		if len(body) != 1 {
			t.Fatalf("page %d = %d runs, want exactly one visible A run (no empty page)", i, len(body))
		}
		run := body[0]
		want, ok := aTimes[run.ID]
		if !ok {
			t.Fatalf("page %d leaked a private-B run id %s", i, run.ID)
		}
		if !run.CreatedAt.Equal(want) {
			t.Fatalf("page %d run %s timestamp = %v, want the readable run's %v", i, run.ID, run.CreatedAt, want)
		}
		gotIDs = append(gotIDs, run.ID)
		cursor = w.Header().Get("X-Kiwi-Next-Cursor")
		pages = append(pages, pgITRunsPageWalkPage{ids: []string{run.ID}, cursor: cursor, capHdr: w.Header().Get("X-Kiwi-Runs-Limit-Cap")})
		if cursor == "" {
			break
		}
		decoded, ok := decodeRunsCursor(cursor)
		if !ok {
			t.Fatalf("page %d cursor does not decode", i)
		}
		if decoded.id != run.ID || !decoded.createdAt.Equal(want) {
			t.Fatalf("page %d cursor = (%q, %v), want the visible run (%q, %v)", i, decoded.id, decoded.createdAt, run.ID, want)
		}
	}
	if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
		t.Fatalf("reader walk = %v, want exactly %v", gotIDs, wantIDs)
	}
	if len(pages) != len(wantIDs) {
		t.Fatalf("reader walk = %d pages, want %d (no empty intermediate page may reveal B density)", len(pages), len(wantIDs))
	}

	// (c) The equivalent A-only data set pages identically.
	onlyA := pgITRunsPageAOnlyServer(t, aRuns)
	onlyAPages := pgITRunsPageWalk(t, onlyA, "reader", 1, 8)
	if len(onlyAPages) != len(pages) {
		t.Fatalf("A-only walk = %d pages, mixed walk = %d", len(onlyAPages), len(pages))
	}
	for i := range pages {
		if strings.Join(pages[i].ids, ",") != strings.Join(onlyAPages[i].ids, ",") || pages[i].cursor != onlyAPages[i].cursor {
			t.Fatalf("page %d differs from the A-only data set: mixed %v/%q, only-A %v/%q",
				i, pages[i].ids, pages[i].cursor, onlyAPages[i].ids, onlyAPages[i].cursor)
		}
	}

	// Sanity: the private rows really exist (the unrestricted admin walk
	// covers the whole collection).
	adminPages := pgITRunsPageWalk(t, s, "token", storage.DefaultRunsPageLimit, 4)
	adminSeen := 0
	for _, page := range adminPages {
		adminSeen += len(page.ids)
	}
	if adminSeen != total {
		t.Fatalf("admin walk covered %d runs, want %d", adminSeen, total)
	}
}

// TestPostgresIntegrationRunsPaginationAuthorizedAliasAndEmpty covers the
// remaining regression cases against real Postgres: a principal allowed on
// several repositories, alias/case parity between grant spellings, and a
// principal whose permitted set is empty (terminal empty page, no cursor).
func TestPostgresIntegrationRunsPaginationAuthorizedAliasAndEmpty(t *testing.T) {
	env := pgITServerSetup(t)
	st := env.open(t)
	s := New("token")
	s.DB = st
	for raw, grants := range map[string]map[string]auth.RepositoryPermission{
		// Bare alias for repo-a: host-agnostic by auth semantics.
		"reader": {"o/repo-a": {Read: true}, "GitHub.com/o/repo-b": {Read: true}, "github.com:443/o/repo-c": {Read: true}},
		// The same grants in exact canonical spelling must page identically.
		"canonical": {"github.com/o/repo-a": {Read: true}, "github.com/o/repo-b": {Read: true}, "github.com/o/repo-c": {Read: true}},
		// A grant that matches no run: empty authorized set.
		"empty": {"o/repo-z": {Read: true}},
	} {
		if err := s.AuthStore.AddToken(raw, auth.Principal{Subject: raw, Repositories: grants}); err != nil {
			t.Fatal(err)
		}
	}

	base := time.Now().UTC().Truncate(time.Microsecond)
	seed := []model.Run{
		{ID: pgITRunsPageID(0), Status: model.StatusSuccess, CreatedAt: base.Add(time.Second), Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a"},
		{ID: pgITRunsPageID(1), Status: model.StatusSuccess, CreatedAt: base.Add(2 * time.Second), Repo: "ssh://git@GitHub.com/o/repo-b.git", RepoFullName: "o/repo-b"},
		{ID: pgITRunsPageID(2), Status: model.StatusSuccess, CreatedAt: base.Add(3 * time.Second), Repo: "https://gitlab.com/o/repo-a.git", RepoFullName: "o/repo-a"},
		{ID: pgITRunsPageID(3), Status: model.StatusSuccess, CreatedAt: base.Add(4 * time.Second), Repo: "https://github.com:443/o/repo-c.git", RepoFullName: "o/repo-c"},
		{ID: pgITRunsPageID(4), Status: model.StatusSuccess, CreatedAt: base.Add(5 * time.Second), Repo: "https://github.com/o/other.git", RepoFullName: "o/other"},
	}
	pgITRunsPageSeed(t, st, seed)

	aliasPages := pgITRunsPageWalk(t, s, "reader", 2, 8)
	canonicalPages := pgITRunsPageWalk(t, s, "canonical", 2, 8)
	aliasIDs := []string{}
	for _, page := range aliasPages {
		aliasIDs = append(aliasIDs, page.ids...)
	}
	// Newest-first: repo-c, gitlab-repo-a (bare alias is host-agnostic),
	// repo-b, github-repo-a.
	wantAlias := []string{pgITRunsPageID(3), pgITRunsPageID(2), pgITRunsPageID(1), pgITRunsPageID(0)}
	if strings.Join(aliasIDs, ",") != strings.Join(wantAlias, ",") {
		t.Fatalf("alias walk = %v, want %v", aliasIDs, wantAlias)
	}
	if len(canonicalPages) != 2 {
		t.Fatalf("canonical walk = %d pages, want 2", len(canonicalPages))
	}
	canonicalIDs := []string{}
	for _, page := range canonicalPages {
		canonicalIDs = append(canonicalIDs, page.ids...)
	}
	// The canonical principal is host-scoped: the GitLab repo-a run and the
	// unrelated repo must not appear.
	wantCanonical := []string{pgITRunsPageID(3), pgITRunsPageID(1), pgITRunsPageID(0)}
	if strings.Join(canonicalIDs, ",") != strings.Join(wantCanonical, ",") {
		t.Fatalf("canonical walk = %v, want %v", canonicalIDs, wantCanonical)
	}

	// Empty permitted set: terminal empty page with no cursor.
	w := pgITDo(t, s, http.MethodGet, "/api/v1/runs?limit=2", "empty", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("empty principal = %d: %s", w.Code, w.Body.String())
	}
	if body := strings.TrimSpace(w.Body.String()); body != "[]" {
		t.Fatalf("empty principal body = %q, want the empty page", body)
	}
	if cursor := w.Header().Get("X-Kiwi-Next-Cursor"); cursor != "" {
		t.Fatalf("empty principal carried a cursor %q", cursor)
	}
}
