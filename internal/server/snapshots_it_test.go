package server

// Real-PostgreSQL integration tests for the workspace snapshot surface: the
// admin-tier listing over the live SnapshotPageStore and the single-record
// download lookup, driven over the HTTP handlers. Gated on
// KIWI_TEST_POSTGRES_URL exactly like the other server integration tests
// (each test owns a throwaway schema).
//
// The store is attached directly (s.DB = st), following the runs-pagination
// IT: these tests are read-path only and do not need the scheduler wiring
// SwitchToDB installs.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// itSnapshotRecord builds one snapshot record with a manifest entry and a
// microsecond-truncated instant.
func itSnapshotRecord(t *testing.T, runID string, i int, base time.Time) model.SnapshotRecord {
	t.Helper()
	return model.SnapshotRecord{
		ID:         fmt.Sprintf("%032x", i+1),
		RunID:      runID,
		JobID:      fmt.Sprintf("%032x", i+101),
		JobKey:     "build",
		Path:       "cas:" + strings.Repeat("a", 64),
		Size:       int64(i + 1),
		SHA256:     fmt.Sprintf("%064d", i),
		Version:    1,
		RootSHA256: fmt.Sprintf("root-%032d", i),
		Entries: []model.SnapshotEntry{
			{Path: fmt.Sprintf("private/secret-%d.pem", i), Mode: 0o600, Size: int64(i), SHA256: fmt.Sprintf("%064d", i)},
		},
		CreatedAt: base.Add(time.Duration(i) * time.Second),
	}
}

// itSnapshotInsertRun seeds one readable run in the repository the snapshot
// principals are granted.
func itSnapshotInsertRun(t *testing.T, st *storage.PostgresStore, runID string) {
	t.Helper()
	if err := st.InsertRun(context.Background(), model.Run{
		ID:           runID,
		Repo:         "https://github.com/o/repo-a.git",
		RepoFullName: "o/repo-a",
		Status:       model.StatusSuccess,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("insert run %s: %v", runID, err)
	}
}

// TestIntegrationSnapshotListingAdminTierAndPagination is the end-to-end
// L4-A/L4-B pin against a live database: a repository-read grant cannot
// obtain the workspace inventory (403 with no file name, entry array or
// digest), while an admin walks the collection in bounded keyset pages whose
// concatenation is the exact oldest-first record order.
func TestIntegrationSnapshotListingAdminTierAndPagination(t *testing.T) {
	env := pgITServerSetup(t)
	st := env.open(t)
	s := New("token")
	s.DB = st

	runID := fmt.Sprintf("%032x", 1)
	itSnapshotInsertRun(t, st, runID)
	base := time.Now().UTC().Truncate(time.Microsecond)
	const total = 5
	seeded := make([]model.SnapshotRecord, 0, total)
	for i := 0; i < total; i++ {
		rec := itSnapshotRecord(t, runID, i, base)
		if err := st.InsertSnapshotRecord(context.Background(), rec); err != nil {
			t.Fatalf("insert snapshot %s: %v", rec.ID, err)
		}
		seeded = append(seeded, rec)
	}

	if err := s.AuthStore.AddToken("repo-reader", auth.Principal{
		Subject: "repo-reader",
		Repositories: map[string]auth.RepositoryPermission{
			"github.com/o/repo-a": {Read: true, ArtifactRead: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	w := pgITDo(t, s, http.MethodGet, "/api/v1/runs/"+runID+"/snapshots", "repo-reader", "", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("repo-reader listing = %d, want 403: %s", w.Code, w.Body.String())
	}
	for _, leak := range []string{seeded[0].Entries[0].Path, seeded[0].SHA256, seeded[0].RootSHA256, `"entries"`} {
		if strings.Contains(w.Body.String(), leak) {
			t.Fatalf("repo-reader listing leaked %q: %s", leak, w.Body.String())
		}
	}

	// Admin walk: pages of 2 concatenate to the exact seeded order.
	var walk []string
	cursor := ""
	pages := 0
	for {
		pages++
		if pages > 5 {
			t.Fatalf("snapshot walk did not terminate")
		}
		path := "/api/v1/runs/" + runID + "/snapshots?limit=2"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		page := pgITDo(t, s, http.MethodGet, path, "token", "", nil)
		if page.Code != http.StatusOK {
			t.Fatalf("page %d = %d: %s", pages, page.Code, page.Body.String())
		}
		if got := page.Header().Get("X-Kiwi-Snapshots-Limit-Cap"); got != strconv.Itoa(storage.MaxSnapshotPageLimit) {
			t.Fatalf("limit cap header = %q, want %d", got, storage.MaxSnapshotPageLimit)
		}
		var recs []model.SnapshotRecord
		if err := json.Unmarshal(page.Body.Bytes(), &recs); err != nil {
			t.Fatal(err)
		}
		if len(recs) > 2 {
			t.Fatalf("page %d returned %d records, over the limit 2", pages, len(recs))
		}
		for _, rec := range recs {
			if len(rec.Entries) != 1 || rec.RootSHA256 == "" || rec.SHA256 == "" {
				t.Fatalf("admin page lost the manifest: %+v", rec)
			}
			walk = append(walk, rec.ID)
		}
		cursor = page.Header().Get("X-Kiwi-Next-Cursor")
		if cursor == "" {
			break
		}
	}
	if len(walk) != total || pages != 3 {
		t.Fatalf("walk = %d records over %d pages, want %d over 3", len(walk), pages, total)
	}
	for i, id := range walk {
		if id != seeded[i].ID {
			t.Fatalf("walk[%d] = %s, want %s", i, id, seeded[i].ID)
		}
	}
}

// TestIntegrationSnapshotDownloadSingleRecordLookup proves the live download
// path resolves the record through the (run_id, id) point read: the
// collection read is never called (its counter stays zero even though it is
// instrumented), and a cross-run id is a not-found.
func TestIntegrationSnapshotDownloadSingleRecordLookup(t *testing.T) {
	env := pgITServerSetup(t)
	st := env.open(t)
	counter := &itCountingSnapshotStore{PostgresStore: st}
	s := New("token")
	s.DB = counter

	runID := fmt.Sprintf("%032x", 1)
	otherRun := fmt.Sprintf("%032x", 2)
	itSnapshotInsertRun(t, st, runID)
	itSnapshotInsertRun(t, st, otherRun)

	// A node-local archive path keeps the download test free of CAS wiring.
	// The record carries the archive's REAL size and digest: the download
	// preverifies before committing the response, so a record that disagrees
	// with its bytes is refused.
	dir := t.TempDir()
	archive := filepath.Join(dir, "snapshot.tar.gz")
	data := []byte("legacy-archive-bytes")
	if err := os.WriteFile(archive, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := fileSHA256(archive)
	if err != nil {
		t.Fatal(err)
	}
	rec := model.SnapshotRecord{ID: fmt.Sprintf("%032x", 7), RunID: runID, JobKey: "build", Path: archive, Size: int64(len(data)), SHA256: digest, CreatedAt: time.Now().UTC()}
	if err := st.InsertSnapshotRecord(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	foreign := model.SnapshotRecord{ID: fmt.Sprintf("%032x", 8), RunID: otherRun, Path: archive, Size: int64(len(data)), SHA256: digest, CreatedAt: time.Now().UTC()}
	if err := st.InsertSnapshotRecord(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}

	w := pgITDo(t, s, http.MethodGet, "/api/v1/runs/"+runID+"/snapshots/"+rec.ID, "token", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("download = %d, want 200: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "legacy-archive-bytes" {
		t.Fatalf("download body = %q", w.Body.String())
	}
	if got := counter.getCalls.Load(); got != 1 {
		t.Fatalf("GetSnapshot calls = %d, want 1", got)
	}
	if got := counter.listCalls.Load(); got != 0 {
		t.Fatalf("ListSnapshotsByRun calls = %d, want 0 (download must use the point read)", got)
	}

	// The other run's record never resolves through this run's URL.
	counter.getCalls.Store(0)
	w = pgITDo(t, s, http.MethodGet, "/api/v1/runs/"+runID+"/snapshots/"+foreign.ID, "token", "", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-run download = %d, want 404", w.Code)
	}
	if got := counter.getCalls.Load(); got != 1 {
		t.Fatalf("cross-run GetSnapshot calls = %d, want 1", got)
	}
}

// itCountingSnapshotStore counts the two snapshot reads over the live store.
type itCountingSnapshotStore struct {
	*storage.PostgresStore
	getCalls  atomic.Int32
	listCalls atomic.Int32
}

func (c *itCountingSnapshotStore) GetSnapshot(ctx context.Context, runID, snapshotID string) (model.SnapshotRecord, bool, error) {
	c.getCalls.Add(1)
	return c.PostgresStore.GetSnapshot(ctx, runID, snapshotID)
}

func (c *itCountingSnapshotStore) ListSnapshotsByRun(ctx context.Context, runID string) ([]model.SnapshotRecord, error) {
	c.listCalls.Add(1)
	return c.PostgresStore.ListSnapshotsByRun(ctx, runID)
}
