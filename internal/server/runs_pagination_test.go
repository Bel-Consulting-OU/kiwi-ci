package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// runsPaginationServer builds a memory-mode server whose admin bearer is
// "admin" and, when grants are given, a repo-scoped reader bearer "reader".
func runsPaginationServer(t *testing.T, grants map[string]auth.RepositoryPermission) *Server {
	t.Helper()
	s := New("admin")
	if len(grants) > 0 {
		if err := s.AuthStore.AddToken("reader", auth.Principal{Subject: "reader", Repositories: grants}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// runsPaginationRun builds run i with a distinct created_at and a stable id.
func runsPaginationRun(i int, base time.Time, repoA bool) model.Run {
	run := model.Run{
		ID:        fmt.Sprintf("run-%04d", i),
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

func runsPaginationSeed(t *testing.T, s *Server, runs []model.Run) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, run := range runs {
		s.runs[run.ID] = run
	}
}

// runsPaginationDescending returns the ids of runs 0..n-1 newest-first.
func runsPaginationDescending(n int) []string {
	ids := make([]string, 0, n)
	for i := n - 1; i >= 0; i-- {
		ids = append(ids, fmt.Sprintf("run-%04d", i))
	}
	return ids
}

type runsPageWalkPage struct {
	ids      []string
	cursor   string
	limitCap string
}

// walkRunsPages follows the collection's page contract: request with the
// optional limit, then with each returned X-Kiwi-Next-Cursor, until the
// header is absent. limit <= 0 omits the parameter (the default page size).
func walkRunsPages(t *testing.T, s *Server, bearer string, limit, maxPages int) []runsPageWalkPage {
	t.Helper()
	pages := []runsPageWalkPage{}
	cursor := ""
	for i := 0; i < maxPages; i++ {
		path := "/api/v1/runs"
		sep := "?"
		if limit > 0 {
			path += sep + "limit=" + strconv.Itoa(limit)
			sep = "&"
		}
		if cursor != "" {
			path += sep + "cursor=" + url.QueryEscape(cursor)
		}
		w := doJSON(t, s, http.MethodGet, path, bearer, "")
		if w.Code != http.StatusOK {
			t.Fatalf("page %d = %d: %s", i, w.Code, w.Body.String())
		}
		pages = append(pages, runsPageWalkPage{
			ids:      runIDs(t, w.Body.String()),
			cursor:   w.Header().Get("X-Kiwi-Next-Cursor"),
			limitCap: w.Header().Get("X-Kiwi-Runs-Limit-Cap"),
		})
		cursor = pages[len(pages)-1].cursor
		if cursor == "" {
			return pages
		}
	}
	t.Fatalf("walk did not terminate within %d pages", maxPages)
	return nil
}

// TestListRunsPaginationMemoryBeyondDefaultLimit is the regression pin for
// the defect: 1005 runs in memory mode, the default first page is still the
// newest 1000, and the cursor reaches the remaining five with no duplicate
// and no omission.
func TestListRunsPaginationMemoryBeyondDefaultLimit(t *testing.T) {
	s := runsPaginationServer(t, nil)
	const total = 1005
	base := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	runs := make([]model.Run, 0, total)
	for i := 0; i < total; i++ {
		runs = append(runs, runsPaginationRun(i, base, true))
	}
	runsPaginationSeed(t, s, runs)

	pages := walkRunsPages(t, s, "admin", 0, 4)
	if len(pages) != 2 {
		t.Fatalf("walk = %d pages, want 2", len(pages))
	}
	if len(pages[0].ids) != storage.DefaultRunsPageLimit {
		t.Fatalf("first page = %d runs, want the %d default", len(pages[0].ids), storage.DefaultRunsPageLimit)
	}
	if len(pages[1].ids) != total-storage.DefaultRunsPageLimit {
		t.Fatalf("second page = %d runs, want %d", len(pages[1].ids), total-storage.DefaultRunsPageLimit)
	}
	if pages[0].cursor == "" {
		t.Fatal("first page carried no next cursor")
	}
	if pages[1].cursor != "" {
		t.Fatalf("last page carried a next cursor %q", pages[1].cursor)
	}
	if pages[0].limitCap != strconv.Itoa(storage.MaxRunsPageLimit) {
		t.Fatalf("limit cap header = %q, want %d", pages[0].limitCap, storage.MaxRunsPageLimit)
	}
	got := append(append([]string{}, pages[0].ids...), pages[1].ids...)
	if strings.Join(got, ",") != strings.Join(runsPaginationDescending(total), ",") {
		t.Fatalf("walk = %d ids; first %s last %s, want newest-first without duplicates", len(got), got[0], got[len(got)-1])
	}
}

// TestListRunsPaginationLimitParamBounds pins the bounded limit: a smaller
// page works, and absent/unparsable/non-positive values select the default
// (both preserve the newest-first order).
func TestListRunsPaginationLimitParamBounds(t *testing.T) {
	s := runsPaginationServer(t, nil)
	base := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	for i := 0; i < 5; i++ {
		runsPaginationSeed(t, s, []model.Run{runsPaginationRun(i, base, true)})
	}

	w := doJSON(t, s, http.MethodGet, "/api/v1/runs?limit=2", "admin", "")
	if w.Code != http.StatusOK {
		t.Fatalf("limit=2 = %d: %s", w.Code, w.Body.String())
	}
	if ids := runIDs(t, w.Body.String()); strings.Join(ids, ",") != "run-0004,run-0003" {
		t.Fatalf("limit=2 page = %v", ids)
	}
	if w.Header().Get("X-Kiwi-Next-Cursor") == "" {
		t.Fatal("limit=2 page carried no next cursor")
	}

	for _, path := range []string{
		"/api/v1/runs?limit=0",
		"/api/v1/runs?limit=-3",
		"/api/v1/runs?limit=not-a-number",
		"/api/v1/runs?limit=999999",
		"/api/v1/runs",
	} {
		w := doJSON(t, s, http.MethodGet, path, "admin", "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d: %s", path, w.Code, w.Body.String())
		}
		if ids := runIDs(t, w.Body.String()); strings.Join(ids, ",") != strings.Join(runsPaginationDescending(5), ",") {
			t.Fatalf("%s page = %v, want all five newest-first", path, ids)
		}
		if w.Header().Get("X-Kiwi-Runs-Limit-Cap") != strconv.Itoa(storage.MaxRunsPageLimit) {
			t.Fatalf("%s limit cap header = %q", path, w.Header().Get("X-Kiwi-Runs-Limit-Cap"))
		}
	}
}

// TestListRunsCursorStabilityOnInsert proves keyset stability over the HTTP
// contract: a run inserted between page reads is newer than the cursor and
// never appears in the ongoing walk (a fresh first page sees it), and an
// older insert is reached by a later page — no duplicates, no skips.
func TestListRunsCursorStabilityOnInsert(t *testing.T) {
	s := runsPaginationServer(t, nil)
	base := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	for i := 0; i < 6; i++ {
		runsPaginationSeed(t, s, []model.Run{runsPaginationRun(i, base, true)})
	}

	page1 := doJSON(t, s, http.MethodGet, "/api/v1/runs?limit=2", "admin", "")
	if ids := runIDs(t, page1.Body.String()); strings.Join(ids, ",") != "run-0005,run-0004" {
		t.Fatalf("page1 = %v", ids)
	}
	cursor := page1.Header().Get("X-Kiwi-Next-Cursor")
	if cursor == "" {
		t.Fatal("page1 carried no next cursor")
	}

	newer := runsPaginationRun(99, base, true)
	newer.CreatedAt = base.Add(time.Hour)
	older := runsPaginationRun(0, base, true)
	older.ID = "run-old"
	older.CreatedAt = base.Add(-time.Second)
	runsPaginationSeed(t, s, []model.Run{newer, older})

	var seen []string
	next := cursor
	for pages := 0; next != ""; pages++ {
		if pages > 6 {
			t.Fatal("walk did not terminate")
		}
		w := doJSON(t, s, http.MethodGet, "/api/v1/runs?limit=2&cursor="+url.QueryEscape(next), "admin", "")
		if w.Code != http.StatusOK {
			t.Fatalf("page %d = %d: %s", pages, w.Code, w.Body.String())
		}
		seen = append(seen, runIDs(t, w.Body.String())...)
		next = w.Header().Get("X-Kiwi-Next-Cursor")
	}
	want := []string{"run-0003", "run-0002", "run-0001", "run-0000", "run-old"}
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Fatalf("continuation = %v, want %v", seen, want)
	}

	// The newer insert starts a fresh first page instead.
	fresh := doJSON(t, s, http.MethodGet, "/api/v1/runs?limit=1", "admin", "")
	if ids := runIDs(t, fresh.Body.String()); len(ids) != 1 || ids[0] != newer.ID {
		t.Fatalf("fresh first page = %v, want %s", ids, newer.ID)
	}
}

// TestListRunsInvalidCursorOpaque400 pins the malformed-cursor contract: a
// 400 with a fixed opaque body that never echoes the input, while the empty
// cursor and a cursor this server produced are accepted.
func TestListRunsInvalidCursorOpaque400(t *testing.T) {
	s := runsPaginationServer(t, nil)
	base := time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC)
	runsPaginationSeed(t, s, []model.Run{runsPaginationRun(0, base, true)})

	b64 := func(raw string) string { return base64.RawURLEncoding.EncodeToString([]byte(raw)) }
	cases := []struct{ name, cursor string }{
		{"plain garbage", "not-a-cursor"},
		{"bad base64", runsCursorPrefix + "!!!"},
		{"wrong version prefix", "rk2:" + b64(`["2026-01-02T03:04:05Z","id"]`)},
		{"json object", runsCursorPrefix + b64(`{}`)},
		{"short array", runsCursorPrefix + b64(`["2026-01-02T03:04:05Z"]`)},
		{"unparsable time", runsCursorPrefix + b64(`["yesterday","id"]`)},
		{"empty id", runsCursorPrefix + b64(`["2026-01-02T03:04:05Z",""]`)},
		{"raw json", `["2026-01-02T03:04:05Z","id"]`},
		{"truncated base64", runsCursorPrefix + b64(`["2026-01-02T03:04:05Z","id"`)[:6]},
	}
	for _, tc := range cases {
		w := doJSON(t, s, http.MethodGet, "/api/v1/runs?cursor="+url.QueryEscape(tc.cursor), "admin", "")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400: %s", tc.name, w.Code, w.Body.String())
		}
		if body := w.Body.String(); body != "invalid cursor\n" {
			t.Fatalf("%s: body = %q, want the opaque message only", tc.name, body)
		}
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs?cursor=", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("empty cursor = %d, want 200", w.Code)
	}
	valid := encodeRunsCursor(base.Add(30*time.Second), "run-0030")
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs?cursor="+url.QueryEscape(valid), "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("valid cursor = %d, want 200: %s", w.Code, w.Body.String())
	}
}

// TestListRunsRBACFilteredPagesAdvanceAndTerminate pins filtering AFTER
// paging: the newest page is entirely invisible to the repo reader and still
// carries a next cursor, later pages deliver the visible runs, and the walk
// terminates on a page whose rows are invisible — no visible run is lost to
// a false last page.
func TestListRunsRBACFilteredPagesAdvanceAndTerminate(t *testing.T) {
	s := runsPaginationServer(t, map[string]auth.RepositoryPermission{"o/repo-a": {Read: true}})
	base := time.Date(2026, 7, 8, 9, 10, 11, 0, time.UTC)
	// Newest-first layout: H H V V V V H H (i = 7..0).
	for i := 7; i >= 0; i-- {
		runsPaginationSeed(t, s, []model.Run{runsPaginationRun(i, base, i >= 2 && i <= 5)})
	}

	pages := walkRunsPages(t, s, "reader", 2, 8)
	if len(pages) != 4 {
		t.Fatalf("reader walk = %d pages, want 4", len(pages))
	}
	if len(pages[0].ids) != 0 || pages[0].cursor == "" {
		t.Fatalf("first page = %v cursor %q, want an empty page with a next cursor", pages[0].ids, pages[0].cursor)
	}
	if strings.Join(pages[1].ids, ",") != "run-0005,run-0004" || strings.Join(pages[2].ids, ",") != "run-0003,run-0002" {
		t.Fatalf("visible pages = %v / %v", pages[1].ids, pages[2].ids)
	}
	if len(pages[3].ids) != 0 || pages[3].cursor != "" {
		t.Fatalf("last page = %v cursor %q, want an empty terminal page", pages[3].ids, pages[3].cursor)
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

	// The admin walk sees every run across four non-empty pages.
	adminPages := walkRunsPages(t, s, "admin", 2, 8)
	if len(adminPages) != 4 {
		t.Fatalf("admin walk = %d pages, want 4", len(adminPages))
	}
	all := []string{}
	for _, page := range adminPages {
		if len(page.ids) != 2 {
			t.Fatalf("admin page = %v, want two runs", page.ids)
		}
		all = append(all, page.ids...)
	}
	if strings.Join(all, ",") != strings.Join(runsPaginationDescending(8), ",") {
		t.Fatalf("admin walk = %v, want newest-first full collection", all)
	}
}

// pagedRunsFake is a dbFakeStore that also implements storage.RunPageStore,
// so the handler's native paged path is exercised without PostgreSQL.
type pagedRunsFake struct {
	*dbFakeStore
	mu        sync.Mutex
	pageCalls int
	pageErr   error
}

func (p *pagedRunsFake) ListRunsPage(ctx context.Context, afterCreatedAt time.Time, afterID string, limit int) (storage.RunPage, error) {
	p.mu.Lock()
	p.pageCalls++
	err := p.pageErr
	p.mu.Unlock()
	if err != nil {
		return storage.RunPage{}, err
	}
	p.dbFakeStore.mu.Lock()
	runs := make([]model.Run, 0, len(p.runs))
	for _, run := range p.runs {
		runs = append(runs, run)
	}
	p.dbFakeStore.mu.Unlock()
	return storage.PageRuns(runs, afterCreatedAt, afterID, limit), nil
}

func (p *pagedRunsFake) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pageCalls
}

// TestListRunsPagedStoreAndFallbackParity proves both store paths in DB mode
// produce the same pages: a store implementing RunPageStore is read through
// it, while a legacy store without the capability is served the bounded
// ListRuns snapshot through the same PageRuns contract. A failing page read
// stays a 500.
func TestListRunsPagedStoreAndFallbackParity(t *testing.T) {
	f := newDBFakeStore()
	base := time.Date(2026, 8, 9, 10, 11, 12, 0, time.UTC)
	f.mu.Lock()
	for i := 0; i < 5; i++ {
		run := runsPaginationRun(i, base, true)
		f.runs[run.ID] = run
	}
	f.mu.Unlock()

	fallback := New("admin")
	fallback.DB = f
	fallbackPages := walkRunsPages(t, fallback, "admin", 2, 5)
	if len(fallbackPages) != 3 {
		t.Fatalf("fallback walk = %d pages, want 3", len(fallbackPages))
	}

	paged := New("admin")
	pf := &pagedRunsFake{dbFakeStore: f}
	paged.DB = pf
	pagedPages := walkRunsPages(t, paged, "admin", 2, 5)
	if pf.calls() == 0 {
		t.Fatal("paged store capability was not used")
	}
	if len(pagedPages) != len(fallbackPages) {
		t.Fatalf("paged walk = %d pages, fallback = %d", len(pagedPages), len(fallbackPages))
	}
	for i := range pagedPages {
		if strings.Join(pagedPages[i].ids, ",") != strings.Join(fallbackPages[i].ids, ",") {
			t.Fatalf("page %d: paged %v != fallback %v", i, pagedPages[i].ids, fallbackPages[i].ids)
		}
	}

	pf.mu.Lock()
	pf.pageErr = errors.New("page read down")
	pf.mu.Unlock()
	if w := doJSON(t, paged, http.MethodGet, "/api/v1/runs", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("failing paged read = %d, want 500", w.Code)
	}
}
