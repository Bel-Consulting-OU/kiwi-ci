package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// snapPageSeed builds n records for runID with strictly increasing
// created_at values (one second apart) and fixed-width ids, so the expected
// oldest-first order is the numeric id order.
func snapPageSeed(runID string, n int, base time.Time) []model.SnapshotRecord {
	out := make([]model.SnapshotRecord, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, model.SnapshotRecord{
			ID:         fmt.Sprintf("snap-%032d", i),
			RunID:      runID,
			JobID:      "job-a",
			Size:       int64(i + 1),
			SHA256:     fmt.Sprintf("%064d", i),
			RootSHA256: fmt.Sprintf("root-%d", i),
			CreatedAt:  base.Add(time.Duration(i) * time.Second),
		})
	}
	return out
}

// snapPageIDs decodes the id list of a snapshot listing body.
func snapPageIDs(t *testing.T, body []byte) []string {
	t.Helper()
	var recs []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &recs); err != nil {
		t.Fatalf("decode snapshot page: %v (%s)", err, body)
	}
	out := make([]string, 0, len(recs))
	for _, rec := range recs {
		out = append(out, rec.ID)
	}
	return out
}

// snapPageWalk follows the snapshot listing cursor contract until the next
// cursor header is absent, returning every page's ids in walk order.
func snapPageWalk(t *testing.T, s *Server, bearer string, limit, maxPages int) [][]string {
	t.Helper()
	pages := [][]string{}
	cursor := ""
	for i := 0; i < maxPages; i++ {
		path := "/api/v1/runs/run-c/snapshots?limit=" + strconv.Itoa(limit)
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		w := doJSON(t, s, http.MethodGet, path, bearer, "")
		if w.Code != http.StatusOK {
			t.Fatalf("snapshot page %d = %d: %s", i, w.Code, w.Body.String())
		}
		if got := w.Header().Get("X-Kiwi-Snapshots-Limit-Cap"); got != strconv.Itoa(storage.MaxSnapshotPageLimit) {
			t.Fatalf("limit cap header = %q, want %d", got, storage.MaxSnapshotPageLimit)
		}
		ids := snapPageIDs(t, w.Body.Bytes())
		if len(ids) > limit {
			t.Fatalf("page %d returned %d records, over the requested limit %d", i, len(ids), limit)
		}
		pages = append(pages, ids)
		cursor = w.Header().Get("X-Kiwi-Next-Cursor")
		if cursor == "" {
			return pages
		}
	}
	t.Fatalf("snapshot walk did not terminate within %d pages", maxPages)
	return nil
}

// TestSnapshotListingPaginationMemory proves the memory-mode listing is a
// bounded keyset walk: 5 records at limit 2 arrive as pages [2 2 1] in
// oldest-first order with no duplicate or omission, each response is capped
// by the requested limit, and the cap header advertises the hard bound.
func TestSnapshotListingPaginationMemory(t *testing.T) {
	s, _ := fcMemoryBlobServer(t)
	base := time.Now().UTC().Truncate(time.Microsecond)
	seed := snapPageSeed("run-c", 5, base)
	s.mu.Lock()
	s.runs["run-c"] = model.Run{ID: "run-c", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusRunning}
	for _, rec := range seed {
		s.snapshots[rec.ID] = rec
	}
	s.mu.Unlock()

	pages := snapPageWalk(t, s, "admin-tok", 2, 4)
	if len(pages) != 3 {
		t.Fatalf("pages = %d, want 3: %v", len(pages), pages)
	}
	if len(pages[0]) != 2 || len(pages[1]) != 2 || len(pages[2]) != 1 {
		t.Fatalf("page sizes = %d %d %d, want 2 2 1", len(pages[0]), len(pages[1]), len(pages[2]))
	}
	var walk []string
	for _, page := range pages {
		walk = append(walk, page...)
	}
	if len(walk) != len(seed) {
		t.Fatalf("walk covered %d records, want %d", len(walk), len(seed))
	}
	seen := map[string]bool{}
	for i, id := range walk {
		if seen[id] {
			t.Fatalf("duplicate record %s in the walk", id)
		}
		seen[id] = true
		if id != seed[i].ID {
			t.Fatalf("walk[%d] = %s, want %s (deterministic oldest-first order)", i, id, seed[i].ID)
		}
	}
}

// TestSnapshotListingPaginationDB is the DB-mode counterpart: the page comes
// from SnapshotPageStore with the same bounded contract, and the response
// never carries manifests of records outside the page.
func TestSnapshotListingPaginationDB(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	base := time.Now().UTC().Truncate(time.Microsecond)
	for _, rec := range snapPageSeed("run-c", 5, base) {
		rec.Entries = []model.SnapshotEntry{{Path: "private/" + rec.ID, Mode: 0o600, Size: 3, SHA256: rec.SHA256}}
		f.mu.Lock()
		f.snapshots = append(f.snapshots, rec)
		f.mu.Unlock()
	}

	pages := snapPageWalk(t, s, "admin-tok", 2, 4)
	if len(pages) != 3 || len(pages[0]) != 2 || len(pages[1]) != 2 || len(pages[2]) != 1 {
		t.Fatalf("DB page shape = %v", pages)
	}
	// A page is bounded: the body of the first page holds exactly the two
	// records of the page, never the whole collection.
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots?limit=2", "admin-tok", "")
	var first []model.SnapshotRecord
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 {
		t.Fatalf("DB first page = %d records, want 2", len(first))
	}
	for _, rec := range first {
		if rec.RunID != "run-c" {
			t.Fatalf("page leaked a record of run %q", rec.RunID)
		}
	}
}

// TestSnapshotListingPaginationTieCursor proves the keyset order is total:
// records sharing a created_at are paginated by id with no duplicate and no
// omission across the page boundary.
func TestSnapshotListingPaginationTieCursor(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	instant := time.Now().UTC().Truncate(time.Microsecond)
	ids := []string{
		fmt.Sprintf("snap-%032d", 0),
		fmt.Sprintf("snap-%032d", 1),
		fmt.Sprintf("snap-%032d", 2),
	}
	for _, id := range ids {
		f.mu.Lock()
		f.snapshots = append(f.snapshots, model.SnapshotRecord{ID: id, RunID: "run-c", CreatedAt: instant})
		f.mu.Unlock()
	}
	pages := snapPageWalk(t, s, "admin-tok", 1, 5)
	var walk []string
	for _, page := range pages {
		walk = append(walk, page...)
	}
	if len(walk) != 3 {
		t.Fatalf("tie walk covered %d records, want 3: %v", len(walk), walk)
	}
	for i, id := range walk {
		if id != ids[i] {
			t.Fatalf("tie walk[%d] = %s, want %s", i, id, ids[i])
		}
	}
}

// TestSnapshotListingPaginationLimitClamp proves the requested page size is
// bounded: an absurd limit is clamped to the advertised hard cap and the
// response honours the cap.
func TestSnapshotListingPaginationLimitClamp(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	base := time.Now().UTC().Truncate(time.Microsecond)
	for _, rec := range snapPageSeed("run-c", 3, base) {
		f.mu.Lock()
		f.snapshots = append(f.snapshots, rec)
		f.mu.Unlock()
	}
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots?limit=1000000", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("clamped listing = %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Kiwi-Snapshots-Limit-Cap"); got != strconv.Itoa(storage.MaxSnapshotPageLimit) {
		t.Fatalf("limit cap header = %q, want %d", got, storage.MaxSnapshotPageLimit)
	}
	if got := len(snapPageIDs(t, w.Body.Bytes())); got != 3 {
		t.Fatalf("clamped listing returned %d records, want 3", got)
	}
}

// TestSnapshotListingPaginationInvalidCursor proves a malformed cursor is
// answered with an opaque 400 before any store or memory read, and that the
// decoder never guesses a position.
func TestSnapshotListingPaginationInvalidCursor(t *testing.T) {
	s, _, _, _ := cacheFixture(t)
	for _, cur := range []string{"not-a-cursor", "sk1:%%%", "rk1:abc"} {
		w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots?cursor="+url.QueryEscape(cur), "admin-tok", "")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("cursor %q = %d, want 400: %s", cur, w.Code, w.Body.String())
		}
	}
	// Memory mode decodes the cursor before resolving the run too.
	sm, _ := fcMemoryBlobServer(t)
	if w := doJSON(t, sm, http.MethodGet, "/api/v1/runs/run-c/snapshots?cursor=bogus", "admin-tok", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("memory invalid cursor = %d, want 400", w.Code)
	}
}

// TestSnapshotListingCursorRoundTrip proves the opaque cursor encoding round
// trips arbitrary id bytes and instants exactly, and that the zero cursor
// decodes to the first-page position.
func TestSnapshotListingCursorRoundTrip(t *testing.T) {
	if c, ok := decodeSnapshotsCursor(""); !ok || !c.createdAt.IsZero() || c.id != "" {
		t.Fatalf("zero cursor = %+v ok=%v", c, ok)
	}
	instant := time.Date(2026, 9, 22, 12, 34, 56, 789, time.UTC)
	for _, id := range []string{"snap-1", "a/b c?d=e&f", "ünïcøde-ид", ""} {
		raw := encodeSnapshotsCursor(instant, id)
		got, ok := decodeSnapshotsCursor(raw)
		if !ok || !got.createdAt.Equal(instant) || got.id != id {
			t.Fatalf("round trip %q = %+v ok=%v (raw %q)", id, got, ok, raw)
		}
	}
	if _, ok := decodeSnapshotsCursor(encodeSnapshotsCursor(instant, "x") + "!"); ok {
		t.Fatal("trailing garbage accepted as a cursor")
	}
}
