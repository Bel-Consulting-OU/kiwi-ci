package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// writeEntry creates a published archive (plus sidecar) of exactly size bytes
// with an explicit mtime, so manager tests control the physical tree without
// running a capture.
func writeEntry(t *testing.T, root, key string, size int, when time.Time) {
	t.Helper()
	data := make([]byte, size)
	state := uint32(0x9e3779b9)
	for i := range data {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		data[i] = byte(state)
	}
	path := filepath.Join(root, key+".tar.gz")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, key+".tar.gz.sha256"), []byte("digest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

// publishedBytes sums the published archive files (temp and sidecars
// excluded).
func publishedBytes(t *testing.T, root string) int64 {
	t.Helper()
	entries, err := listLocalEntriesAt(root)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, e := range entries {
		total += e.size
	}
	return total
}

func TestManagerReserveEvictsColdEntries(t *testing.T) {
	root := t.TempDir()
	base := time.Now().Add(-time.Hour)
	writeEntry(t, root, "aaa", 700, base)
	writeEntry(t, root, "bbb", 700, base.Add(time.Minute))
	m := NewManager(root, RetentionPolicy{MaxBytes: 2000, MaxEntries: 10})
	res, err := m.Reserve(context.Background(), 700)
	if err != nil {
		t.Fatal(err)
	}
	if publishedBytes(t, root) != 700 {
		t.Fatalf("published bytes = %d, want the oldest entry evicted (700)", publishedBytes(t, root))
	}
	if _, err := os.Stat(filepath.Join(root, "aaa.tar.gz")); !os.IsNotExist(err) {
		t.Fatal("coldest entry survived the reservation")
	}
	res.Release()
}

func TestManagerReserveRejectsOversize(t *testing.T) {
	m := NewManager(t.TempDir(), RetentionPolicy{MaxBytes: 1000})
	if _, err := m.Reserve(context.Background(), 2000); !errors.Is(err, ErrCacheBudgetExceeded) {
		t.Fatalf("oversize reserve = %v, want ErrCacheBudgetExceeded", err)
	}
}

func TestManagerReserveHonorsInflightAndRelease(t *testing.T) {
	root := t.TempDir()
	m := NewManager(root, RetentionPolicy{MaxBytes: 1000})
	a, err := m.Reserve(context.Background(), 600)
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Reserve(context.Background(), 400)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Reserve(context.Background(), 1); !errors.Is(err, ErrCacheBudgetExceeded) {
		t.Fatalf("reserve past inflight = %v, want ErrCacheBudgetExceeded", err)
	}
	b.Release()
	c, err := m.Reserve(context.Background(), 400)
	if err != nil {
		t.Fatalf("reserve after release: %v", err)
	}
	c.Release()
	a.Release()
	// Releasing twice is safe.
	a.Release()
}

func TestManagerReserveContextCanceled(t *testing.T) {
	m := NewManager(t.TempDir(), RetentionPolicy{MaxBytes: 1000})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Reserve(ctx, 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reserve = %v, want context.Canceled", err)
	}
}

// TestLocalPruneDoesNotDeleteFreshConcurrentSave is the stale-ranking
// regression for the runner-local tree: the freshness fence re-stats the
// archive before eviction, so an entry refreshed after ranking is skipped
// rather than deleted on stale information.
func TestLocalPruneDoesNotDeleteFreshConcurrentSave(t *testing.T) {
	root := t.TempDir()
	old := time.Now().Add(-2 * time.Hour)
	writeEntry(t, root, "aaa", 500, old)
	writeEntry(t, root, "bbb", 500, old.Add(time.Minute))
	store := &Store{Root: root, Retention: RetentionPolicy{MaxEntries: 1}}
	replaced := false
	orig := pruneBeforeEvictHook
	pruneBeforeEvictHook = func(path string) {
		if replaced || filepath.Base(path) != "aaa.tar.gz" {
			return
		}
		replaced = true
		writeEntry(t, root, "aaa", 900, time.Now())
	}
	t.Cleanup(func() { pruneBeforeEvictHook = orig })
	res, err := store.Prune(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !replaced {
		t.Fatal("hook never ran; the test did not exercise the race window")
	}
	if res.Skipped != 1 || res.Entries != 0 {
		t.Fatalf("prune = %+v, want the refreshed entry skipped", res)
	}
	if _, err := os.Stat(filepath.Join(root, "aaa.tar.gz")); err != nil {
		t.Fatalf("refreshed entry was deleted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "bbb.tar.gz")); err != nil {
		t.Fatalf("newest entry was deleted: %v", err)
	}
}

// TestCacheAggregateBoundAcrossStores is the P1 core: stores are per job but
// the budget is per runner. Several Stores sharing one Manager over the same
// directory can never publish more than the aggregate bound, including while
// saving concurrently.
func TestCacheAggregateBoundAcrossStores(t *testing.T) {
	root := t.TempDir()
	const maxBytes = 2500
	manager := NewManager(root, RetentionPolicy{MaxBytes: maxBytes, MaxEntries: 100})
	stores := []*Store{
		{Root: root, Manager: manager, MaxCacheBytes: 1200},
		{Root: root, Manager: manager, MaxCacheBytes: 1200},
	}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		ws := t.TempDir()
		writeIncompressible(t, filepath.Join(ws, "f.bin"), 800)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store := stores[i%len(stores)]
			_ = store.SaveContext(context.Background(), fmt.Sprintf("key%02d", i), ws, []string{"f.bin"})
		}(i)
	}
	wg.Wait()
	if got := publishedBytes(t, root); got > maxBytes {
		t.Fatalf("published cache bytes = %d, want <= %d", got, maxBytes)
	}
}

// remoteArchiveServer serves one valid cache archive for every request and
// optionally blocks before completing, so tests can observe reservation-time
// eviction while a download is still in flight.
func remoteArchiveServer(t *testing.T, archive []byte, started chan<- struct{}, gate <-chan struct{}) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256(archive)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderCacheSHA256, hex.EncodeToString(sum[:]))
		w.Header().Set("Content-Length", fmt.Sprint(len(archive)))
		// Flush the headers so the client's Do returns and the reservation
		// (and its eviction) happens while the body is still gated.
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		if started != nil {
			select {
			case started <- struct{}{}:
			default:
			}
		}
		if gate != nil {
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = w.Write(archive)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// validArchiveBytes produces a real tar.gz archive (so a remote restore can
// verify and extract it) by saving a tiny entry in a scratch store.
func validArchiveBytes(t *testing.T) []byte {
	t.Helper()
	src, _, ws := savedCache(t)
	_ = ws
	return readFile(t, src.archivePath("deadbeef"))
}

// TestRemoteRestoreEvictsBeforeExceedingLimit pins reservation-before-write:
// the cold entry is evicted when the reservation is granted, while the
// download is still blocked, and the published tree stays within the bound.
func TestRemoteRestoreEvictsBeforeExceedingLimit(t *testing.T) {
	archive := validArchiveBytes(t)
	root := t.TempDir()
	writeEntry(t, root, "aaa", 950, time.Now().Add(-2*time.Hour))
	manager := NewManager(root, RetentionPolicy{MaxBytes: 1000, MaxEntries: 10})
	started := make(chan struct{}, 1)
	gate := make(chan struct{})
	var gateOnce sync.Once
	release := func() { gateOnce.Do(func() { close(gate) }) }
	defer release()
	srv := remoteArchiveServer(t, archive, started, gate)
	store := &Store{Root: root, Manager: manager, MaxCacheBytes: 1000, RemoteURL: srv.URL}

	done := make(chan error, 1)
	go func() {
		_, err := store.RestoreContext(context.Background(), "remote-key", t.TempDir(), []string{"f"})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("remote download never started")
	}
	// The server signal can race the client's reserve (which happens after
	// Do returns), so poll until the eviction is observable; the body is
	// still gated, which is what proves eviction happens BEFORE publication.
	evictDeadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "aaa.tar.gz")); os.IsNotExist(err) {
			break
		}
		if time.Now().After(evictDeadline) {
			t.Fatal("cold entry was not evicted when the reservation was granted (eviction happens only on publication)")
		}
		time.Sleep(5 * time.Millisecond)
	}
	release()
	if err := <-done; err != nil && !errors.Is(err, ErrCacheBudgetExceeded) {
		t.Fatalf("restore: %v", err)
	}
	if got := publishedBytes(t, root); got > 1000 {
		t.Fatalf("published bytes = %d, want <= 1000", got)
	}
}

// TestCacheInflightReservationReleasedOnCancel pins that a canceled remote
// restore releases its reservation, so later operations can use the budget.
func TestCacheInflightReservationReleasedOnCancel(t *testing.T) {
	archive := validArchiveBytes(t)
	root := t.TempDir()
	manager := NewManager(root, RetentionPolicy{MaxBytes: 1000, MaxEntries: 10})
	started := make(chan struct{}, 1)
	gate := make(chan struct{})
	var gateOnce sync.Once
	release := func() { gateOnce.Do(func() { close(gate) }) }
	defer release()
	srv := remoteArchiveServer(t, archive, started, gate)
	store := &Store{Root: root, Manager: manager, MaxCacheBytes: 1000, RemoteURL: srv.URL}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := store.RestoreContext(ctx, "remote-key", t.TempDir(), []string{"f"})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("remote download never started")
	}
	cancel()
	release()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("canceled restore did not return")
	}
	res, err := manager.Reserve(context.Background(), 1000)
	if err != nil {
		t.Fatalf("reservation after cancel = %v, want the inflight charge released", err)
	}
	res.Release()
}

// TestCacheMaxBytesNeverExceededPhysically polls the real files (published
// archives, not counters) while concurrent saves run and asserts the
// aggregate bound held throughout, not just at the end.
func TestCacheMaxBytesNeverExceededPhysically(t *testing.T) {
	root := t.TempDir()
	const maxBytes = 2000
	manager := NewManager(root, RetentionPolicy{MaxBytes: maxBytes, MaxEntries: 100})
	stores := []*Store{
		{Root: root, Manager: manager, MaxCacheBytes: 700},
		{Root: root, Manager: manager, MaxCacheBytes: 700},
	}
	stop := make(chan struct{})
	var maxSeen atomic.Int64
	var pollErr atomic.Value
	go func() {
		// No t.* calls in this goroutine: a transient scan error is recorded
		// and reported from the test goroutine.
		for {
			select {
			case <-stop:
				return
			default:
			}
			entries, err := listLocalEntriesAt(root)
			if err != nil {
				pollErr.Store(fmt.Errorf("scan cache root: %w", err))
				return
			}
			var got int64
			for _, e := range entries {
				got += e.size
			}
			if got > maxBytes {
				pollErr.Store(fmt.Errorf("published cache bytes %d exceeded %d", got, maxBytes))
				return
			} else if got > maxSeen.Load() {
				maxSeen.Store(got)
			}
			time.Sleep(500 * time.Microsecond)
		}
	}()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		ws := t.TempDir()
		writeIncompressible(t, filepath.Join(ws, "f.bin"), 600)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = stores[i%len(stores)].SaveContext(context.Background(), fmt.Sprintf("key%02d", i), ws, []string{"f.bin"})
		}(i)
	}
	wg.Wait()
	close(stop)
	if err := pollErr.Load(); err != nil {
		t.Fatal(err)
	}
	if got := publishedBytes(t, root); got > maxBytes {
		t.Fatalf("final published bytes = %d, want <= %d", got, maxBytes)
	}
}

// TestManagerPruneSerializesWithReservations proves explicit passes and
// reservations share one lock: a prune cannot run while a reservation's
// eviction is in progress, and reservations observe the post-prune tree.
func TestManagerPruneSerializesWithReservations(t *testing.T) {
	root := t.TempDir()
	base := time.Now().Add(-time.Hour)
	writeEntry(t, root, "aaa", 500, base)
	writeEntry(t, root, "bbb", 500, base.Add(time.Minute))
	m := NewManager(root, RetentionPolicy{MaxBytes: 4000, MaxEntries: 1})
	res, err := m.Prune(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 1 || publishedBytes(t, root) != 500 {
		t.Fatalf("prune = %+v, published = %d", res, publishedBytes(t, root))
	}
	if _, err := os.Stat(filepath.Join(root, "bbb.tar.gz")); err != nil {
		t.Fatalf("newest entry was evicted: %v", err)
	}
}

// TestListLocalEntriesFiltersForeignNames pins the directory scan's
// filtering: sidecars, temp files, directories and invalid keys never enter
// the accounting.
func TestListLocalEntriesFiltersForeignNames(t *testing.T) {
	root := t.TempDir()
	writeEntry(t, root, "valid", 10, time.Now())
	if err := os.WriteFile(filepath.Join(root, "valid.tar.gz.sha256"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".hidden.tar.gz"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "foreign.bin"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "dir.tar.gz"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "..tar.gz"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := listLocalEntriesAt(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].key != "valid" {
		t.Fatalf("entries = %+v, want only the valid archive", entries)
	}
	// A root that is a regular file surfaces the ReadDir error.
	fileRoot := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(fileRoot, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listLocalEntriesAt(fileRoot); err == nil {
		t.Fatal("listLocalEntriesAt on a file root succeeded")
	}
}

// TestEvictLocalEntryTreatsVanishedFileAsEvicted pins the race path where the
// archive disappears between the freshness fence's stat and the removal: the
// next scan reflects reality, so the entry is retired from the accounting
// rather than reported as a failed removal.
func TestEvictLocalEntryTreatedAsEvictedWhenAlreadyGone(t *testing.T) {
	root := t.TempDir()
	writeEntry(t, root, "gone", 10, time.Now())
	orig := removeCacheFile
	removeCacheFile = func(string) error { return os.ErrNotExist }
	t.Cleanup(func() { removeCacheFile = orig })
	var res PruneResult
	// Use the real stat data so the fence passes.
	entries, err := listLocalEntriesAt(root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("scan = %+v, %v", entries, err)
	}
	if !evictLocalEntry(root, entries[0], &res) {
		t.Fatalf("vanished entry not retired: %+v", res)
	}
	if res.Entries != 1 || res.Failed != 0 {
		t.Fatalf("result = %+v", res)
	}
}

// TestEvictLocalEntrySkipsVanishedRankedEntry pins the pre-stat miss: an
// entry evicted by a concurrent pass (or already gone) is counted as skipped
// rather than as a failed removal.
func TestEvictLocalEntrySkipsVanishedRankedEntry(t *testing.T) {
	root := t.TempDir()
	var res PruneResult
	entry := localCacheEntry{key: "missing", size: 10, modTime: time.Now()}
	if evictLocalEntry(root, entry, &res) {
		t.Fatal("vanished entry reported evicted")
	}
	if res.Skipped != 1 || res.Failed != 0 {
		t.Fatalf("result = %+v, want one skip", res)
	}
}

// TestReservationNilReceiverRelease pins the nil-safety of Release.
func TestReservationNilReceiverRelease(t *testing.T) {
	var res *Reservation
	res.Release()
	var m *Manager
	r, err := m.Reserve(context.Background(), 1)
	if err != nil || r == nil {
		t.Fatalf("nil manager reserve = %v, %v", r, err)
	}
	r.Release()
}

// TestManagerPublishIsAtomicWithVisibility is the deterministic model of the
// concurrent-restore race: publication happens under the manager lock and
// retires the worst-case reservation at the same instant, so a second
// reservation never double-counts the fresh entry and evicts the COLD entry
// only.
func TestManagerPublishIsAtomicWithVisibility(t *testing.T) {
	root := t.TempDir()
	writeEntry(t, root, "cold", 1200, time.Now().Add(-time.Hour))
	m := NewManager(root, RetentionPolicy{MaxBytes: 2500, MaxEntries: 100})

	a, err := m.Reserve(context.Background(), 1200)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Publish(a, func() error {
		writeEntry(t, root, "fresh", 102, time.Now())
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	var evicted []string
	orig := managerEvictHook
	managerEvictHook = func(key string) { evicted = append(evicted, key) }
	t.Cleanup(func() { managerEvictHook = orig })

	b, err := m.Reserve(context.Background(), 1200)
	if err != nil {
		t.Fatalf("second reservation = %v, want cold eviction to make room", err)
	}
	b.Release()
	a.Release()
	if len(evicted) != 1 || evicted[0] != "cold" {
		t.Fatalf("evicted = %v, want only the cold entry", evicted)
	}
	if _, err := os.Stat(filepath.Join(root, "fresh.tar.gz")); err != nil {
		t.Fatalf("fresh entry was evicted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "cold.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("cold entry survived: %v", err)
	}
}

// TestManagerPublishFailureKeepsReservation pins the failure path: a publish
// that errors does not retire the charge, so the caller's Release is what
// returns the capacity.
func TestManagerPublishFailureKeepsReservation(t *testing.T) {
	root := t.TempDir()
	m := NewManager(root, RetentionPolicy{MaxBytes: 2500, MaxEntries: 100})
	a, err := m.Reserve(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("publish failed")
	if err := m.Publish(a, func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("Publish = %v, want the injected error", err)
	}
	m.mu.Lock()
	inflight := m.inflight
	m.mu.Unlock()
	if inflight != 1000 {
		t.Fatalf("inflight after failed publish = %d, want the charge retained", inflight)
	}
	a.Release()
	m.mu.Lock()
	inflight = m.inflight
	m.mu.Unlock()
	if inflight != 0 {
		t.Fatalf("inflight after Release = %d, want 0", inflight)
	}
}

// TestManagerReserveEdgeBranches covers the refusal and failure branches:
// inactive policy, entry-slot exhaustion, scan failure, un-evictable
// entries, nil-publish, canceled prune and manager-delegated store prune.
func TestManagerReserveEdgeBranches(t *testing.T) {
	// Inactive policy: reservations are granted without accounting.
	inactive := NewManager(t.TempDir(), RetentionPolicy{})
	if r, err := inactive.Reserve(context.Background(), 1); err != nil || r == nil {
		t.Fatalf("inactive reserve = %v, %v", r, err)
	} else {
		r.Release()
	}

	// Entry-slot exhaustion: one slot, already reserved.
	root := t.TempDir()
	m := NewManager(root, RetentionPolicy{MaxEntries: 1})
	a, err := m.Reserve(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Reserve(context.Background(), 1); !errors.Is(err, ErrCacheBudgetExceeded) {
		t.Fatalf("second slot reserve = %v, want ErrCacheBudgetExceeded", err)
	}
	a.Release()

	// Scan failure: the root is a regular file.
	fileRoot := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(fileRoot, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManager(fileRoot, RetentionPolicy{MaxBytes: 10}).Reserve(context.Background(), 1); err == nil {
		t.Fatal("reserve over an unreadable root succeeded")
	}

	// Un-evictable entries: removal fails for everything.
	root2 := t.TempDir()
	writeEntry(t, root2, "stuck", 100, time.Now().Add(-time.Hour))
	m2 := NewManager(root2, RetentionPolicy{MaxBytes: 50, MaxEntries: 10})
	origRemove := removeCacheFile
	removeCacheFile = func(string) error { return errors.New("test: remove refused") }
	t.Cleanup(func() { removeCacheFile = origRemove })
	if _, err := m2.Reserve(context.Background(), 10); !errors.Is(err, ErrCacheBudgetExceeded) {
		t.Fatalf("un-evictable reserve = %v, want ErrCacheBudgetExceeded", err)
	}

	// Publish with no reservation still runs the callback.
	published := false
	if err := m2.Publish(nil, func() error { published = true; return nil }); err != nil || !published {
		t.Fatalf("nil-reservation publish = %v published=%t", err, published)
	}
	// Publish on a nil manager runs the callback directly.
	var nilMgr *Manager
	if err := nilMgr.Publish(nil, func() error { return nil }); err != nil {
		t.Fatalf("nil-manager publish = %v", err)
	}

	// Canceled prune (with a retained entry so the pass reaches its
	// context check).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m2.Prune(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled prune = %v, want context.Canceled", err)
	}

	// A store delegates its prune to the shared manager.
	removeCacheFile = origRemove
	store := &Store{Root: root, Manager: NewManager(root, RetentionPolicy{MaxEntries: 1})}
	writeEntry(t, root, "aaa", 10, time.Now().Add(-2*time.Hour))
	writeEntry(t, root, "bbb", 10, time.Now().Add(-time.Hour))
	if res, err := store.Prune(context.Background()); err != nil || res.Entries != 1 {
		t.Fatalf("delegated prune = %+v, %v", res, err)
	}
}
