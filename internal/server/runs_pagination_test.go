package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// TestListRunsRBACAuthorizedPagesExcludeInvisibleRuns pins the fixed
// authorization contract: the repo reader's walk contains ONLY visible runs,
// every page boundary (and therefore every X-Kiwi-Next-Cursor) is derived
// from the last visible run of that page, and there are no empty
// intermediate pages. The pre-fix behavior — an empty newest page carrying a
// cursor computed from an invisible run — is exactly what must not happen.
func TestListRunsRBACAuthorizedPagesExcludeInvisibleRuns(t *testing.T) {
	s := runsPaginationServer(t, map[string]auth.RepositoryPermission{"o/repo-a": {Read: true}})
	base := time.Date(2026, 7, 8, 9, 10, 11, 0, time.UTC)
	// Newest-first layout: H H V V V V H H (i = 7..0).
	for i := 7; i >= 0; i-- {
		runsPaginationSeed(t, s, []model.Run{runsPaginationRun(i, base, i >= 2 && i <= 5)})
	}

	pages := walkRunsPages(t, s, "reader", 2, 8)
	if len(pages) != 2 {
		t.Fatalf("reader walk = %d pages, want 2", len(pages))
	}
	if strings.Join(pages[0].ids, ",") != "run-0005,run-0004" || strings.Join(pages[1].ids, ",") != "run-0003,run-0002" {
		t.Fatalf("visible pages = %v / %v", pages[0].ids, pages[1].ids)
	}
	if pages[0].cursor == "" || pages[1].cursor != "" {
		t.Fatalf("cursors = %q / %q, want a next cursor only on the first page", pages[0].cursor, pages[1].cursor)
	}
	// Every cursor decodes to the LAST VISIBLE run of its page: no invisible
	// run's timestamp or id can appear in the position the client receives.
	for i, page := range pages[:len(pages)-1] {
		last := page.ids[len(page.ids)-1]
		decoded, ok := decodeRunsCursor(page.cursor)
		if !ok {
			t.Fatalf("page %d cursor %q does not decode", i, page.cursor)
		}
		if decoded.id != last {
			t.Fatalf("page %d cursor id = %q, want the last visible run %q", i, decoded.id, last)
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

// TestListRunsRBACNoLeakLargeMixedCollection is the memory half of the P1
// regression: 2,500 private-B runs surround three readable-A runs, and an
// A-only principal must observe exactly the A runs — (a) no B ids/timestamps
// anywhere, (b) every cursor decodes to the last visible A run, (c) the same
// pages as the equivalent A-only data set, (d) no empty intermediate page
// that would reveal B density.
func TestListRunsRBACNoLeakLargeMixedCollection(t *testing.T) {
	s := runsPaginationServer(t, map[string]auth.RepositoryPermission{"o/repo-a": {Read: true}})
	base := time.Date(2026, 7, 9, 10, 11, 12, 0, time.UTC)
	const (
		total  = 2500
		firstA = 1200
		lastA  = 1202
	)
	runs := make([]model.Run, 0, total)
	for i := 0; i < total; i++ {
		runs = append(runs, runsPaginationRun(i, base, i >= firstA && i <= lastA))
	}
	runsPaginationSeed(t, s, runs)

	const pageSize = 7
	pages := walkRunsPages(t, s, "reader", pageSize, 16)
	wantIDs := []string{
		fmt.Sprintf("run-%04d", lastA),
		fmt.Sprintf("run-%04d", lastA-1),
		fmt.Sprintf("run-%04d", firstA),
	}
	gotIDs := []string{}
	for i, page := range pages {
		if page.cursor == "" && i != len(pages)-1 {
			t.Fatalf("page %d ended the walk while more visible runs exist", i)
		}
		if len(page.ids) == 0 && i != len(pages)-1 {
			t.Fatalf("page %d is empty and not terminal: an empty intermediate page leaks invisible density", i)
		}
		for _, id := range page.ids {
			n, err := strconv.Atoi(strings.TrimPrefix(id, "run-"))
			if err != nil {
				t.Fatalf("unexpected id %q", id)
			}
			if n < firstA || n > lastA {
				t.Fatalf("page %d leaked a private-B run %s", i, id)
			}
			if pages[i].cursor != "" {
				decoded, ok := decodeRunsCursor(pages[i].cursor)
				if !ok {
					t.Fatalf("page %d cursor does not decode", i)
				}
				if decoded.id != page.ids[len(page.ids)-1] {
					t.Fatalf("page %d cursor id = %q, want the last visible run %q", i, decoded.id, page.ids[len(page.ids)-1])
				}
				if n < firstA || n > lastA {
					t.Fatalf("page %d cursor derived from an invisible run", i)
				}
			}
			gotIDs = append(gotIDs, id)
		}
	}
	if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
		t.Fatalf("reader walk = %v, want exactly the A runs %v", gotIDs, wantIDs)
	}
	if len(pages) != 1 {
		t.Fatalf("reader walk = %d pages, want 1 (three visible runs fit %d)", len(pages), pageSize)
	}

	// (c) The equivalent data set containing ONLY the A runs pages
	// identically: invisible rows are not page filler.
	onlyA := runsPaginationServer(t, map[string]auth.RepositoryPermission{"o/repo-a": {Read: true}})
	runsPaginationSeed(t, onlyA, []model.Run{runs[firstA], runs[firstA+1], runs[firstA+2]})
	onlyAPages := walkRunsPages(t, onlyA, "reader", pageSize, 4)
	if len(onlyAPages) != len(pages) {
		t.Fatalf("A-only walk = %d pages, mixed walk = %d pages", len(onlyAPages), len(pages))
	}
	for i := range pages {
		if strings.Join(pages[i].ids, ",") != strings.Join(onlyAPages[i].ids, ",") || pages[i].cursor != onlyAPages[i].cursor {
			t.Fatalf("page %d differs from the A-only walk: mixed %v/%q, only-A %v/%q",
				i, pages[i].ids, pages[i].cursor, onlyAPages[i].ids, onlyAPages[i].cursor)
		}
	}

	// Sanity: the unrestricted admin walk still sees the whole collection
	// (the mixed data really is there), newest-first, without duplication.
	adminPages := walkRunsPages(t, s, "admin", storage.MaxRunsPageLimit, 4)
	adminSeen := 0
	for _, page := range adminPages {
		adminSeen += len(page.ids)
	}
	if adminSeen != total {
		t.Fatalf("admin walk covered %d runs, want %d", adminSeen, total)
	}
}

// TestListRunsRBACMultipleReposAndAliasParity covers a principal granted on
// several repositories plus the alias/case parity contract: grant spellings
// that differ only in host case, default port or a trailing dot resolve to
// the same authorized pages as an equivalent canonical grant, a bare alias is
// host-agnostic by auth semantics, and a host-scoped grant never leaks a
// same-named repository on another host.
func TestListRunsRBACMultipleReposAndAliasParity(t *testing.T) {
	base := time.Date(2026, 7, 10, 11, 12, 13, 0, time.UTC)
	seed := func(s *Server) {
		runs := []model.Run{
			{ID: "run-a-https", Status: model.StatusSuccess, CreatedAt: base.Add(time.Second), Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a"},
			{ID: "run-b-ssh", Status: model.StatusSuccess, CreatedAt: base.Add(2 * time.Second), Repo: "ssh://git@GitHub.com/o/repo-b.git", RepoFullName: "o/repo-b"},
			{ID: "run-a-other-host", Status: model.StatusSuccess, CreatedAt: base.Add(3 * time.Second), Repo: "https://gitlab.com/o/repo-a.git", RepoFullName: "o/repo-a"},
			{ID: "run-c", Status: model.StatusSuccess, CreatedAt: base.Add(4 * time.Second), Repo: "https://github.com/o/repo-c.git", RepoFullName: "o/repo-c"},
		}
		runsPaginationSeed(t, s, runs)
	}

	// Exact canonical grants for the three github.com repositories.
	exact := runsPaginationServer(t, map[string]auth.RepositoryPermission{
		"github.com/o/repo-a": {Read: true},
		"github.com/o/repo-b": {Read: true},
		"github.com/o/repo-c": {Read: true},
	})
	seed(exact)
	// Spelling variants of the SAME set: host case, a default port and a
	// trailing dot. They must resolve to identical pages.
	spelled := runsPaginationServer(t, map[string]auth.RepositoryPermission{
		"GitHub.com/o/repo-a":     {Read: true},
		"github.com:443/o/repo-b": {Read: true},
		"github.com./o/repo-c":    {Read: true},
	})
	seed(spelled)
	// A bare alias for repo-a: host-agnostic by auth semantics (a bare key
	// matches the same full name on any forge), so the GitLab repo-a run is
	// visible to it.
	bare := runsPaginationServer(t, map[string]auth.RepositoryPermission{"o/repo-a": {Read: true}})
	seed(bare)

	exactPages := walkRunsPages(t, exact, "reader", 2, 8)
	exactIDs := []string{}
	for _, page := range exactPages {
		exactIDs = append(exactIDs, page.ids...)
	}
	wantExact := []string{"run-c", "run-b-ssh", "run-a-https"}
	if strings.Join(exactIDs, ",") != strings.Join(wantExact, ",") {
		t.Fatalf("exact walk = %v, want %v", exactIDs, wantExact)
	}

	spelledPages := walkRunsPages(t, spelled, "reader", 2, 8)
	if len(spelledPages) != len(exactPages) {
		t.Fatalf("spelled walk = %d pages, exact walk = %d", len(spelledPages), len(exactPages))
	}
	for i := range spelledPages {
		if strings.Join(spelledPages[i].ids, ",") != strings.Join(exactPages[i].ids, ",") || spelledPages[i].cursor != exactPages[i].cursor {
			t.Fatalf("page %d: spelled %v/%q != exact %v/%q", i, spelledPages[i].ids, spelledPages[i].cursor, exactPages[i].ids, exactPages[i].cursor)
		}
	}

	barePages := walkRunsPages(t, bare, "reader", 2, 8)
	bareIDs := []string{}
	for _, page := range barePages {
		bareIDs = append(bareIDs, page.ids...)
	}
	wantBare := []string{"run-a-other-host", "run-a-https"}
	if strings.Join(bareIDs, ",") != strings.Join(wantBare, ",") {
		t.Fatalf("bare alias walk = %v, want %v", bareIDs, wantBare)
	}

	// A host-scoped grant never authorizes the same name on another host.
	hostScoped := runsPaginationServer(t, map[string]auth.RepositoryPermission{"github.com/o/repo-a": {Read: true}})
	seed(hostScoped)
	pages := walkRunsPages(t, hostScoped, "reader", 10, 4)
	got := []string{}
	for _, page := range pages {
		got = append(got, page.ids...)
	}
	if strings.Join(got, ",") != "run-a-https" {
		t.Fatalf("host-scoped walk = %v, want only the github.com run", got)
	}
}

// TestListRunsRBACEmptyAuthorizedSet pins the empty-permitted-set contract:
// a principal that passes the coarse read gate but whose permitted canonical
// repository set is empty receives a terminal empty page with no cursor —
// never a fallback to the whole collection and never a cursor at all.
func TestListRunsRBACEmptyAuthorizedSet(t *testing.T) {
	base := time.Date(2026, 7, 11, 12, 13, 14, 0, time.UTC)
	onlyB := []model.Run{
		{ID: "run-b1", Status: model.StatusSuccess, CreatedAt: base.Add(time.Second), Repo: "https://github.com/o/repo-b.git", RepoFullName: "o/repo-b"},
		{ID: "run-b2", Status: model.StatusSuccess, CreatedAt: base.Add(2 * time.Second), Repo: "https://github.com/o/repo-b.git", RepoFullName: "o/repo-b"},
	}

	cases := []struct {
		name string
		p    auth.Principal
	}{
		// A read grant on a repository with no runs: the gate opens, the
		// authorized set is empty.
		{"grant on a repository with no runs", auth.Principal{Subject: "reader", Repositories: map[string]auth.RepositoryPermission{"o/repo-a": {Read: true}}}},
		// A global read role with an explicit deny on every present
		// repository: the entries are authoritative, so nothing is permitted.
		{"global read with a deny entry", auth.Principal{Subject: "reader", Roles: []auth.Role{auth.RoleRead}, Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-b": {Read: false}}}},
		// Conflicting equivalent entries fail closed to an empty set.
		{"conflicting entries", auth.Principal{Subject: "reader", Repositories: map[string]auth.RepositoryPermission{
			"github.com/o/repo-b": {Read: true},
			"GitHub.com/o/repo-b": {Read: true, Run: true},
		}}},
	}
	for _, tc := range cases {
		s := New("admin")
		if err := s.AuthStore.AddToken("reader", tc.p); err != nil {
			t.Fatal(err)
		}
		runsPaginationSeed(t, s, onlyB)
		// The page size is smaller than the invisible collection on purpose:
		// if authorization ran after paging, the post-filtered page would be
		// empty yet still carry a cursor derived from a B run.
		w := doJSON(t, s, http.MethodGet, "/api/v1/runs?limit=1", "reader", "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d: %s", tc.name, w.Code, w.Body.String())
		}
		if body := strings.TrimSpace(w.Body.String()); body != "[]" {
			t.Fatalf("%s: body = %q, want the empty page", tc.name, body)
		}
		if cursor := w.Header().Get("X-Kiwi-Next-Cursor"); cursor != "" {
			t.Fatalf("%s: empty authorized page carried a cursor %q", tc.name, cursor)
		}
		if cap := w.Header().Get("X-Kiwi-Runs-Limit-Cap"); cap != strconv.Itoa(storage.MaxRunsPageLimit) {
			t.Fatalf("%s: limit cap = %q", tc.name, cap)
		}
	}
}

// TestRunAuthzPolicyResolution pins the resolution itself: which requests
// resolve to the unrestricted form and which resolve to an exact predicate
// over the principal's normalized grants (canonical identities, bare aliases,
// host canonicalization, deny overrides).
func TestRunAuthzPolicyResolution(t *testing.T) {
	base := time.Date(2026, 7, 12, 13, 14, 15, 0, time.UTC)
	s := runsPaginationServer(t, nil)
	runsPaginationSeed(t, s, []model.Run{
		{ID: "run-a", Status: model.StatusSuccess, CreatedAt: base.Add(time.Second), PolicyRepoID: "github.com/o/repo-a"},
		{ID: "run-b", Status: model.StatusSuccess, CreatedAt: base.Add(2 * time.Second), PolicyRepoID: "github.com/o/repo-b"},
		{ID: "run-g", Status: model.StatusSuccess, CreatedAt: base.Add(3 * time.Second), PolicyRepoID: "gitlab.com/o/repo-a"},
	})

	request := func(p *auth.Principal) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
		if p != nil {
			r = r.WithContext(auth.WithPrincipal(r.Context(), *p))
		}
		return r
	}

	cases := []struct {
		name           string
		p              *auth.Principal
		wantUnrestrict bool
		want           map[string]bool
	}{
		{"no principal", nil, true, nil},
		{"admin", &auth.Principal{Roles: []auth.Role{auth.RoleAdmin}}, true, nil},
		{"global read without entries", &auth.Principal{Roles: []auth.Role{auth.RoleRead}}, true, nil},
		{"bare alias", &auth.Principal{Repositories: map[string]auth.RepositoryPermission{"o/repo-a": {Read: true}}}, false,
			map[string]bool{"github.com/o/repo-a": true, "gitlab.com/o/repo-a": true, "github.com/o/repo-b": false}},
		{"host-case grant", &auth.Principal{Repositories: map[string]auth.RepositoryPermission{"GitHub.com/o/repo-b": {Read: true}}}, false,
			map[string]bool{"github.com/o/repo-b": true, "github.com/o/repo-a": false, "gitlab.com/o/repo-a": false}},
		{"global read with a deny entry", &auth.Principal{Roles: []auth.Role{auth.RoleRead}, Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-b": {Read: false}}}, false,
			map[string]bool{"github.com/o/repo-a": true, "gitlab.com/o/repo-a": true, "github.com/o/repo-b": false}},
		{"no matching grant", &auth.Principal{Repositories: map[string]auth.RepositoryPermission{"o/repo-z": {Read: true}}}, false,
			map[string]bool{"github.com/o/repo-a": false, "github.com/o/repo-b": false, "gitlab.com/o/repo-a": false}},
	}
	for _, tc := range cases {
		policy := s.runAuthzPolicy(request(tc.p))
		if tc.wantUnrestrict {
			if !policy.IsUnrestricted() {
				t.Fatalf("%s = restricted, want the unrestricted form", tc.name)
			}
			continue
		}
		if policy.IsUnrestricted() {
			t.Fatalf("%s = unrestricted, want an exact predicate", tc.name)
		}
		for candidate, want := range tc.want {
			if got := policy.Allows(candidate); got != want {
				t.Fatalf("%s: Allows(%q) = %v, want %v", tc.name, candidate, got, want)
			}
		}
	}
}

// pagedRunsFake is a dbFakeStore that also implements
// storage.RunPageAuthorizedStore, so the handler's authorized paged path is
// exercised without PostgreSQL. It records the normalized policy, the cursor
// and the limit each page read received, which pins that the handler resolves
// authorization first and delegates the keyset position to the store.
// legacyCalls counts uses of the UNFILTERED page method: the handler must
// never take that path.
type pagedRunsFake struct {
	*dbFakeStore
	mu          sync.Mutex
	pageCalls   int
	legacyCalls int
	pageErr     error
	afterIDs    []string
	limits      []int
	policies    []storage.RunAuthzPolicy
}

func (p *pagedRunsFake) ListRunsPageAuthorized(ctx context.Context, policy storage.RunAuthzPolicy, afterCreatedAt time.Time, afterID string, limit int) (storage.RunPage, error) {
	p.mu.Lock()
	p.pageCalls++
	p.afterIDs = append(p.afterIDs, afterID)
	p.limits = append(p.limits, limit)
	p.policies = append(p.policies, policy)
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
	return storage.PageRunsAuthorized(runs, policy, afterCreatedAt, afterID, limit), nil
}

// ListRunsPage is the unfiltered legacy capability. The handler must never
// call it (that is the pre-fix leak); it is recorded so tests can assert so,
// and still serves a correct page for any direct caller.
func (p *pagedRunsFake) ListRunsPage(ctx context.Context, afterCreatedAt time.Time, afterID string, limit int) (storage.RunPage, error) {
	p.mu.Lock()
	p.legacyCalls++
	p.mu.Unlock()
	return p.dbFakeStore.ListRunsPage(ctx, afterCreatedAt, afterID, limit)
}

func (p *pagedRunsFake) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pageCalls
}

func (p *pagedRunsFake) legacy() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.legacyCalls
}

// TestListRunsPagedStorePathUnchanged pins the supported path: a store that
// implements the authorized page contract is read through
// ListRunsPageAuthorized only — the handler resolves the principal's
// normalized policy FIRST, passes it with the cursor position and the bounded
// limit straight through, and never touches the unfiltered legacy page
// method. Its first page is byte-identical to memory mode, and a failing page
// read stays a 500.
func TestListRunsPagedStorePathUnchanged(t *testing.T) {
	f := newDBFakeStore()
	base := time.Date(2026, 8, 9, 10, 11, 12, 0, time.UTC)
	runs := make([]model.Run, 0, 5)
	for i := 0; i < 5; i++ {
		runs = append(runs, runsPaginationRun(i, base, true))
	}
	f.mu.Lock()
	for _, run := range runs {
		f.runs[run.ID] = run
	}
	f.mu.Unlock()

	paged := New("admin")
	pf := &pagedRunsFake{dbFakeStore: f}
	paged.DB = pf
	pagedPages := walkRunsPages(t, paged, "admin", 2, 5)
	if len(pagedPages) != 3 {
		t.Fatalf("paged walk = %d pages, want 3", len(pagedPages))
	}
	if pf.calls() == 0 {
		t.Fatal("authorized paged store capability was not used")
	}
	if pf.legacy() != 0 {
		t.Fatal("handler used the unfiltered legacy page path")
	}
	want := runsPaginationDescending(5)
	got := []string{}
	for i, page := range pagedPages {
		if pf.limits[i] != 2 {
			t.Fatalf("page %d limit = %d, want the requested 2", i, pf.limits[i])
		}
		if !pf.policies[i].IsUnrestricted() {
			t.Fatalf("admin page %d received a restricted policy, want the unrestricted form", i)
		}
		got = append(got, page.ids...)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("paged walk = %v, want %v", got, want)
	}
	// The continuation cursor was handed back to the store as the position,
	// never re-derived from a newest-first window.
	if pf.afterIDs[0] != "" || pf.afterIDs[1] != "run-0003" || pf.afterIDs[2] != "run-0001" {
		t.Fatalf("page cursor positions = %v, want the previous page boundary", pf.afterIDs)
	}

	// A repo-scoped reader reaches the same store with a policy that allows
	// only the run's canonical policy identity (the bare grant resolves
	// host-agnostically to it).
	if err := paged.AuthStore.AddToken("reader", auth.Principal{
		Subject:      "reader",
		Repositories: map[string]auth.RepositoryPermission{"o/repo-a": {Read: true}},
	}); err != nil {
		t.Fatal(err)
	}
	pf.mu.Lock()
	pf.pageCalls, pf.afterIDs, pf.limits, pf.policies, pf.legacyCalls = 0, nil, nil, nil, 0
	pf.mu.Unlock()
	readerPages := walkRunsPages(t, paged, "reader", 2, 5)
	if len(readerPages) != 3 {
		t.Fatalf("reader paged walk = %d pages, want 3", len(readerPages))
	}
	for i, policy := range pf.policies {
		if policy.IsUnrestricted() {
			t.Fatalf("reader page %d received the unrestricted policy", i)
		}
		if !policy.Allows("github.com/o/repo-a") || policy.Allows("github.com/o/repo-b") {
			t.Fatalf("reader page %d policy does not isolate the granted repository", i)
		}
	}
	if pf.legacy() != 0 {
		t.Fatal("reader handler used the unfiltered legacy page path")
	}

	// Memory mode produces the identical first page: the paged store path is
	// additive, not a rendering change.
	mem := New("admin")
	runsPaginationSeed(t, mem, runs)
	memPage := doJSON(t, mem, http.MethodGet, "/api/v1/runs?limit=2", "admin", "")
	pagedPage := doJSON(t, paged, http.MethodGet, "/api/v1/runs?limit=2", "admin", "")
	if memPage.Body.String() != pagedPage.Body.String() {
		t.Fatalf("memory %s != paged %s", memPage.Body.String(), pagedPage.Body.String())
	}
	if memPage.Header().Get("X-Kiwi-Next-Cursor") != pagedPage.Header().Get("X-Kiwi-Next-Cursor") {
		t.Fatal("memory and paged stores disagree on the next cursor")
	}

	pf.mu.Lock()
	pf.pageErr = errors.New("page read down")
	pf.mu.Unlock()
	if w := doJSON(t, paged, http.MethodGet, "/api/v1/runs", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("failing paged read = %d, want 500", w.Code)
	}
}

// Capability-hiding wrappers: each exposes the static storage.Store type with
// at most the OLD unfiltered page capability, so the handler's fail-closed
// check can be exercised without PostgreSQL.
type (
	// noPageStore satisfies Store only.
	noPageStore struct {
		storage.Store
	}
	// legacyUnfilteredPageStore exposes the OLD unfiltered page capability
	// (storage.RunPageStore) and nothing else: it must never be used as a
	// fallback, because its page boundary is computed before authorization.
	legacyUnfilteredPageStore struct {
		storage.Store
		inner storage.RunPageStore
	}
)

func (l legacyUnfilteredPageStore) ListRunsPage(ctx context.Context, afterCreatedAt time.Time, afterID string, limit int) (storage.RunPage, error) {
	return l.inner.ListRunsPage(ctx, afterCreatedAt, afterID, limit)
}

// TestListRunsStoreWithoutAuthorizedPageContractFailsClosed pins the
// fail-closed contract: a store missing the authorized page contract cannot
// serve the collection, so every /runs request — first page, explicit limit,
// or an older cursor — answers the opaque 500 instead of a page whose
// boundary could leak. In particular the legacy unfiltered RunPageStore is
// NOT a fallback.
func TestListRunsStoreWithoutAuthorizedPageContractFailsClosed(t *testing.T) {
	f := newDBFakeStore()
	base := time.Date(2026, 9, 10, 11, 12, 13, 0, time.UTC)
	for i := 0; i < 5; i++ {
		run := runsPaginationRun(i, base, true)
		f.mu.Lock()
		f.runs[run.ID] = run
		f.mu.Unlock()
	}

	cursor := url.QueryEscape(encodeRunsCursor(base.Add(30*time.Second), "run-0030"))
	paths := []string{
		"/api/v1/runs",
		"/api/v1/runs?limit=2",
		"/api/v1/runs?cursor=" + cursor,
	}
	stores := []struct {
		name  string
		store storage.Store
	}{
		{"store only", noPageStore{Store: f}},
		{"legacy unfiltered page only", legacyUnfilteredPageStore{Store: f, inner: f}},
	}
	for _, tc := range stores {
		s := New("admin")
		// A repository-scoped reader exercises the policy path; an admin
		// still fails closed without the authorized page contract.
		if err := s.AuthStore.AddToken("reader", auth.Principal{
			Subject:      "reader",
			Repositories: map[string]auth.RepositoryPermission{"o/repo-a": {Read: true}},
		}); err != nil {
			t.Fatal(err)
		}
		s.DB = tc.store
		for _, path := range paths {
			w := doJSON(t, s, http.MethodGet, path, "reader", "")
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("%s: %s = %d, want the opaque 500: %s", tc.name, path, w.Code, w.Body.String())
			}
			if w.Body.String() != "internal server error\n" {
				t.Fatalf("%s: %s body = %q, want the opaque 500 body", tc.name, path, w.Body.String())
			}
			if w.Header().Get("X-Kiwi-Next-Cursor") != "" {
				t.Fatalf("%s: %s carried a next cursor despite the unsupported store", tc.name, path)
			}
		}
	}

	// The page helper rejects the legacy unfiltered capability with the
	// documented fail-closed error.
	policy := storage.RunAuthzPolicyForPrincipal(nil)
	if _, err := listRunsPageAuthorized(context.Background(), legacyUnfilteredPageStore{Store: f, inner: f}, policy, runsCursor{}, 2); !errors.Is(err, errRunsPaginationUnsupported) {
		t.Fatalf("legacy store error = %v, want errRunsPaginationUnsupported", err)
	} else if !strings.Contains(err.Error(), "authorized runs pagination unsupported by configured store") {
		t.Fatalf("legacy store error = %q, want the documented detail", err)
	}
}
