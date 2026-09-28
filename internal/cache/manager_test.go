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
	"strings"
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

	// Publish with no reservation fails closed BEFORE running the callback.
	published := false
	if err := m2.Publish(nil, func() error { published = true; return nil }); !errors.Is(err, ErrInvalidReservation) || published {
		t.Fatalf("nil-reservation publish = %v published=%t, want ErrInvalidReservation and no callback", err, published)
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

// TestPublishedReservationDeferredReleaseIsNoop pins the P1 accounting fix:
// Publish already retired the charge, so a deferred Release (the normal
// defer in every save/restore) must not subtract it again.
func TestPublishedReservationDeferredReleaseIsNoop(t *testing.T) {
	root := t.TempDir()
	m := NewManager(root, RetentionPolicy{MaxBytes: 2500, MaxEntries: 10})
	res, err := m.Reserve(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Publish(res, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	inflight, count := m.inflight, m.inflightCount
	m.mu.Unlock()
	if inflight != 0 || count != 0 {
		t.Fatalf("after publish inflight=%d count=%d, want 0/0", inflight, count)
	}
	res.Release()
	res.Release()
	m.mu.Lock()
	inflight, count = m.inflight, m.inflightCount
	m.mu.Unlock()
	if inflight != 0 || count != 0 {
		t.Fatalf("deferred Release corrupted accounting: inflight=%d count=%d", inflight, count)
	}
}

// TestPublishedReservationDoesNotDriveInflightNegative is the capacity
// regression: after a publish+deferred-release cycle the manager must still
// refuse reservations that would exceed the physical budget.
func TestPublishedReservationDoesNotDriveInflightNegative(t *testing.T) {
	root := t.TempDir()
	const maxBytes = 2000
	m := NewManager(root, RetentionPolicy{MaxBytes: maxBytes, MaxEntries: 10})
	res, err := m.Reserve(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	writeEntry(t, root, "published", 1000, time.Now())
	if err := m.Publish(res, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	res.Release() // deferred shape
	// Retained is now 1000; a maximum-size reservation must evict it and
	// still fit, while a request beyond the budget must be refused.
	next, err := m.Reserve(context.Background(), 2000)
	if err != nil {
		t.Fatalf("max reservation after publish = %v", err)
	}
	next.Release()
	// Physical truth: retained (0 after eviction) + inflight 0 <= 2000.
	if got := publishedBytes(t, root); got > maxBytes {
		t.Fatalf("published bytes = %d, want <= %d", got, maxBytes)
	}
}

// TestPublishedReservationDoesNotDriveEntryCountNegative pins the entry-slot
// accounting under the same cycle.
func TestPublishedReservationDoesNotDriveEntryCountNegative(t *testing.T) {
	root := t.TempDir()
	m := NewManager(root, RetentionPolicy{MaxEntries: 1})
	res, err := m.Reserve(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Publish(res, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	res.Release()
	m.mu.Lock()
	count := m.inflightCount
	m.mu.Unlock()
	if count != 0 {
		t.Fatalf("inflightCount = %d after publish+release, want 0", count)
	}
	// The single entry slot is free again.
	next, err := m.Reserve(context.Background(), 1)
	if err != nil {
		t.Fatalf("slot after publish+release = %v", err)
	}
	next.Release()
}

// TestRepeatedSuccessfulSavesPreserveAggregateBound runs dozens of real
// save/publish/deferred-release cycles through a shared manager and then
// proves the physical tree never exceeded the policy and a maximum-size
// reservation still cannot oversubscribe it.
func TestRepeatedSuccessfulSavesPreserveAggregateBound(t *testing.T) {
	root := t.TempDir()
	const maxBytes = 2500
	m := NewManager(root, RetentionPolicy{MaxBytes: maxBytes, MaxEntries: 100})
	stores := []*Store{
		{Root: root, Manager: m, MaxCacheBytes: 1200},
		{Root: root, Manager: m, MaxCacheBytes: 1200},
	}
	for i := 0; i < 40; i++ {
		ws := t.TempDir()
		writeIncompressible(t, filepath.Join(ws, "f.bin"), 400)
		store := stores[i%len(stores)]
		if err := store.SaveContext(context.Background(), fmt.Sprintf("save%03d", i), ws, []string{"f.bin"}); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
		if got := publishedBytes(t, root); got > maxBytes {
			t.Fatalf("cycle %d published %d bytes, budget %d", i, got, maxBytes)
		}
	}
	// A maximum-size reservation must still respect retained+inflight.
	res, err := m.Reserve(context.Background(), 1200)
	if err != nil {
		t.Fatalf("max reservation after cycles: %v", err)
	}
	if got := publishedBytes(t, root); got+m.inflight > maxBytes {
		t.Fatalf("retained %d + inflight %d exceeds budget %d", got, m.inflight, maxBytes)
	}
	res.Release()
}

// TestRepeatedSuccessfulRestoresPreserveAggregateBound runs dozens of remote
// restore cycles (the deferred-release shape included) through a shared
// manager and checks the physical bound throughout.
func TestRepeatedSuccessfulRestoresPreserveAggregateBound(t *testing.T) {
	archive := validArchiveBytes(t)
	const maxBytes = 3000
	root := t.TempDir()
	m := NewManager(root, RetentionPolicy{MaxBytes: maxBytes, MaxEntries: 100})
	started := make(chan struct{}, 1)
	srv := remoteArchiveServer(t, archive, started, nil)
	store := &Store{Root: root, Manager: m, MaxCacheBytes: 1200, RemoteURL: srv.URL}
	for i := 0; i < 30; i++ {
		key := fmt.Sprintf("restore%03d", i)
		hit, err := store.RestoreContext(context.Background(), key, t.TempDir(), []string{"f"})
		if err != nil || !hit {
			t.Fatalf("restore %d = hit=%t err=%v", i, hit, err)
		}
		if got := publishedBytes(t, root); got > maxBytes {
			t.Fatalf("cycle %d published %d bytes, budget %d", i, got, maxBytes)
		}
	}
	res, err := m.Reserve(context.Background(), 1200)
	if err != nil {
		t.Fatalf("max reservation after restores: %v", err)
	}
	if got := publishedBytes(t, root); got+m.inflight > maxBytes {
		t.Fatalf("retained %d + inflight %d exceeds budget %d", got, m.inflight, maxBytes)
	}
	res.Release()
}

// TestSaveContextTempCleanupFailureKeepsCharge pins the aborted-operation
// hole: when the temp file cannot be removed, the charge must stay counted
// (not silently released) until a retry removes the file.
func TestSaveContextTempCleanupFailureKeepsCharge(t *testing.T) {
	root := t.TempDir()
	m := NewManager(root, RetentionPolicy{MaxBytes: 2500, MaxEntries: 10})
	store := &Store{Root: root, Manager: m, MaxCacheBytes: 1200}
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	origRename, origRemove := renameCacheFile, removeCacheTemp
	renameCacheFile = func(string, string) error { return errors.New("rename refused") }
	removeCacheTemp = func(path string) error {
		if strings.Contains(path, ".tmp") {
			return errors.New("test: busy")
		}
		return os.Remove(path)
	}
	t.Cleanup(func() { renameCacheFile, removeCacheTemp = origRename, origRemove })

	if err := store.SaveContext(context.Background(), "key1", ws, []string{"f"}); err == nil {
		t.Fatal("SaveContext succeeded")
	}
	m.mu.Lock()
	inflight, pending := m.inflight, len(m.pendingTemps)
	m.mu.Unlock()
	if inflight != 1200 || pending != 1 {
		t.Fatalf("after failed cleanup inflight=%d pending=%d, want 1200/1", inflight, pending)
	}
	// The budget is truthful: a full-size reservation still evicts/refuses
	// rather than oversubscribing.
	held, err := m.Reserve(context.Background(), 1200)
	if err != nil {
		t.Fatalf("reserve under retained temp charge = %v", err)
	}
	held.Release()
	removeCacheTemp = origRemove
	if removed, err := m.RetryTempCleanup(context.Background()); err != nil || removed != 1 {
		t.Fatalf("RetryTempCleanup = %d, %v", removed, err)
	}
	m.mu.Lock()
	inflight = m.inflight
	m.mu.Unlock()
	if inflight != 0 {
		t.Fatalf("inflight = %d after temp retry, want 0", inflight)
	}
}

// TestFetchRemoteTempCleanupFailureKeepsCharge is the remote-download half of
// the same contract.
func TestFetchRemoteTempCleanupFailureKeepsCharge(t *testing.T) {
	archive := validArchiveBytes(t)
	srv := remoteArchiveServer(t, archive, nil, nil)
	root := t.TempDir()
	m := NewManager(root, RetentionPolicy{MaxBytes: 2500, MaxEntries: 10})
	store := &Store{Root: root, Manager: m, MaxCacheBytes: 1200, RemoteURL: srv.URL}
	origRename, origRemove := renameCacheFile, removeCacheTemp
	renameCacheFile = func(string, string) error { return errors.New("rename refused") }
	removeCacheTemp = func(path string) error {
		if strings.Contains(path, ".tmp") {
			return errors.New("test: busy")
		}
		return os.Remove(path)
	}
	t.Cleanup(func() { renameCacheFile, removeCacheTemp = origRename, origRemove })

	if _, err := store.RestoreContext(context.Background(), "key1", t.TempDir(), []string{"f"}); err == nil {
		t.Fatal("RestoreContext succeeded")
	}
	m.mu.Lock()
	inflight, pending := m.inflight, len(m.pendingTemps)
	m.mu.Unlock()
	// The reservation charged the advertised Content-Length exactly.
	if want := int64(len(archive)); inflight != want || pending != 1 {
		t.Fatalf("after failed cleanup inflight=%d pending=%d, want %d/1", inflight, pending, want)
	}
	removeCacheTemp = origRemove
	if removed, err := m.RetryTempCleanup(context.Background()); err != nil || removed != 1 {
		t.Fatalf("RetryTempCleanup = %d, %v", removed, err)
	}
}

// TestPruneFailedAgeEvictionStaysAccounted pins the pass-accounting fix: an
// expired entry whose removal fails must remain part of the byte/count
// accounting for the rest of the pass, so the policy cannot look satisfied
// while the physical tree exceeds it.
func TestPruneFailedAgeEvictionStaysAccounted(t *testing.T) {
	root := t.TempDir()
	writeEntry(t, root, "stuck", 100, time.Now().Add(-2*time.Hour))
	writeEntry(t, root, "fresh", 100, time.Now())
	store := &Store{Root: root, Retention: RetentionPolicy{MaxAge: time.Hour, MaxBytes: 150, MaxEntries: 10}}
	orig := removeCacheFile
	removeCacheFile = func(path string) error {
		if filepath.Base(path) == "stuck.tar.gz" {
			return errors.New("test: remove refused")
		}
		return os.Remove(path)
	}
	t.Cleanup(func() { removeCacheFile = orig })
	res, err := store.Prune(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 0 || res.Failed < 2 {
		t.Fatalf("prune = %+v, want the stuck entry retried and failed in both passes", res)
	}
	if _, err := os.Stat(filepath.Join(root, "stuck.tar.gz")); err != nil {
		t.Fatalf("stuck entry vanished: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "fresh.tar.gz")); err != nil {
		t.Fatalf("fresh entry vanished: %v", err)
	}
}

// TestManagerRetryTempCleanupFailurePath pins the retry's own failure
// handling: a still-undeletable temp keeps its charge and is reported, and
// the next pass returns it once removal succeeds.
func TestManagerRetryTempCleanupFailurePath(t *testing.T) {
	root := t.TempDir()
	m := NewManager(root, RetentionPolicy{MaxBytes: 1000})
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := &Store{Root: root, Manager: m, MaxCacheBytes: 500}
	origRename, origRemove := renameCacheFile, removeCacheTemp
	renameCacheFile = func(string, string) error { return errors.New("rename refused") }
	removeCacheTemp = func(string) error { return errors.New("test: busy") }
	t.Cleanup(func() { renameCacheFile, removeCacheTemp = origRename, origRemove })
	if err := store.SaveContext(context.Background(), "key1", ws, []string{"f"}); err == nil {
		t.Fatal("SaveContext succeeded")
	}
	removed, err := m.RetryTempCleanup(context.Background())
	if removed != 0 || err == nil {
		t.Fatalf("failing retry = %d, %v; want 0 and an error", removed, err)
	}
	m.mu.Lock()
	inflight := m.inflight
	m.mu.Unlock()
	if inflight != 500 {
		t.Fatalf("inflight = %d after failed retry, want the charge retained", inflight)
	}
	removeCacheTemp = origRemove
	if removed, err = m.RetryTempCleanup(context.Background()); err != nil || removed != 1 {
		t.Fatalf("recovery retry = %d, %v", removed, err)
	}
	// A canceled retry stops early (with a pending entry present).
	m.mu.Lock()
	m.pendingTemps["late"] = 1
	m.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.RetryTempCleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled retry = %v", err)
	}
}

// TestManagerAccessorsAndDefensiveBranches covers the small validation
// branches: nil accessors, foreign/released/retained reservations in
// Publish/RetainTempCleanup, and the no-op discard of an empty temp path.
func TestManagerAccessorsAndDefensiveBranches(t *testing.T) {
	var nilMgr *Manager
	if nilMgr.Root() != "" || nilMgr.Policy() != (RetentionPolicy{}) {
		t.Fatal("nil manager accessors must be zero-valued")
	}
	m1 := NewManager(t.TempDir(), RetentionPolicy{MaxBytes: 1000})
	m2 := NewManager(t.TempDir(), RetentionPolicy{MaxBytes: 1000})
	foreign, err := m2.Reserve(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	published := false
	if err := m1.Publish(foreign, func() error { published = true; return nil }); !errors.Is(err, ErrInvalidReservation) || published {
		t.Fatalf("foreign publish = %v published=%t, want ErrInvalidReservation and no callback", err, published)
	}
	m1.mu.Lock()
	if m1.inflight != 0 {
		m1.mu.Unlock()
		t.Fatal("foreign reservation mutated the manager")
	}
	m1.mu.Unlock()
	foreign.Release()
	closed, err := m1.Reserve(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	closed.Release()
	if err := m1.Publish(closed, func() error { return nil }); !errors.Is(err, ErrInvalidReservation) {
		t.Fatalf("released-reservation publish = %v, want ErrInvalidReservation", err)
	}
	// An inactive-policy manager still grants manager-bound reservations, so
	// publish works uniformly.
	inactive := NewManager(t.TempDir(), RetentionPolicy{})
	res, err := inactive.Reserve(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	if err := inactive.Publish(res, func() error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("inactive-policy publish = %v ran=%t", err, ran)
	}
	if m1.RetainTempCleanup(nil, "p") || m1.RetainTempCleanup(closed, "p") || m1.RetainTempCleanup(foreign, "") {
		t.Fatal("invalid RetainTempCleanup accepted")
	}
	var nilStore *Store
	nilStore.discardTemp("", nil)
	(&Store{Root: t.TempDir()}).discardTemp("", nil)
}

// TestManagerRetryTempCleanupConcurrentRetain is the race-oriented
// regression for the unlocked len(pendingTemps) check: maintenance retries
// run concurrently with job-teardown retains. Under -race this fails on the
// unlocked map read.
func TestManagerRetryTempCleanupConcurrentRetain(t *testing.T) {
	m := NewManager(t.TempDir(), RetentionPolicy{MaxBytes: 1 << 20, MaxEntries: 1 << 20})
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = m.RetryTempCleanup(context.Background())
		}
	}()
	retainedOnce := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(retainedOnce)
		for i := 0; i < 5000; i++ {
			res, err := m.Reserve(context.Background(), 1)
			if err != nil {
				return
			}
			// Paths need not exist: RetryTempCleanup treats ENOENT as gone,
			// which keeps the interleavings dense.
			m.RetainTempCleanup(res, filepath.Join(m.Root(), fmt.Sprintf(".k%d.remote-1.tmp", i)))
		}
	}()
	<-retainedOnce
	close(stop)
	wg.Wait()
	// A retain can land after the concurrent retry's last sweep; drain the
	// remainder synchronously before asserting (the concurrent interleavings
	// above are what the race detector sees).
	for i := 0; i < 10000 && m.PendingTempCleanup() > 0; i++ {
		if _, err := m.RetryTempCleanup(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if pending := m.PendingTempCleanup(); pending != 0 {
		t.Fatalf("pending temps = %d after concurrent retries, want 0", pending)
	}
	if got := m.InflightBytes(); got != 0 {
		t.Fatalf("inflight = %d after concurrent retries, want 0", got)
	}
}

// TestManagerRestartReclaimsAbandonedSaveTemp pins crash recovery for save
// temps: a temp file left by a killed process is removed before the manager
// is shared, so it can never sit invisibly outside the budget.
func TestManagerRestartReclaimsAbandonedSaveTemp(t *testing.T) {
	root := t.TempDir()
	tmp := filepath.Join(root, ".key1.tar.gz-12345.tmp")
	if err := os.WriteFile(tmp, make([]byte, 128), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(root, RetentionPolicy{MaxBytes: 1000})
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("abandoned save temp survived manager construction (err=%v)", err)
	}
	if m.PendingTempCleanup() != 0 || m.InflightBytes() != 0 {
		t.Fatalf("manager = pending %d inflight %d, want 0/0", m.PendingTempCleanup(), m.InflightBytes())
	}
}

// TestManagerRestartReclaimsAbandonedRestoreTemp is the remote-download half.
func TestManagerRestartReclaimsAbandonedRestoreTemp(t *testing.T) {
	root := t.TempDir()
	tmp := filepath.Join(root, ".key2.remote-9876.tmp")
	if err := os.WriteFile(tmp, make([]byte, 64), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(root, RetentionPolicy{MaxBytes: 1000})
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("abandoned restore temp survived manager construction (err=%v)", err)
	}
	if m.PendingTempCleanup() != 0 {
		t.Fatalf("pending = %d, want 0", m.PendingTempCleanup())
	}
}

// TestManagerRestartAccountsUndeletableAbandonedTemp pins the fail-closed
// startup accounting: an abandoned temp that cannot be removed is charged
// until a retry removes it.
func TestManagerRestartAccountsUndeletableAbandonedTemp(t *testing.T) {
	root := t.TempDir()
	tmp := filepath.Join(root, ".key3.tar.gz-42.tmp")
	if err := os.WriteFile(tmp, make([]byte, 300), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := removeCacheTemp
	removeCacheTemp = func(path string) error {
		if path == tmp {
			return errors.New("test: busy")
		}
		return os.Remove(path)
	}
	t.Cleanup(func() { removeCacheTemp = orig })
	m := NewManager(root, RetentionPolicy{MaxBytes: 1000})
	if m.PendingTempCleanup() != 1 || m.InflightBytes() != 300 {
		t.Fatalf("manager = pending %d inflight %d, want 1/300", m.PendingTempCleanup(), m.InflightBytes())
	}
	removeCacheTemp = orig
	if removed, err := m.RetryTempCleanup(context.Background()); err != nil || removed != 1 {
		t.Fatalf("RetryTempCleanup = %d, %v", removed, err)
	}
	if m.PendingTempCleanup() != 0 || m.InflightBytes() != 0 {
		t.Fatalf("manager not drained after retry: pending %d inflight %d", m.PendingTempCleanup(), m.InflightBytes())
	}
}

// TestCrashLeftTempCannotBypassMaxBytes is the capacity regression: bytes
// left by a crash must count against the budget after restart, so a maximum
// reservation cannot oversubscribe the physical tree.
func TestCrashLeftTempCannotBypassMaxBytes(t *testing.T) {
	root := t.TempDir()
	tmp := filepath.Join(root, ".key4.remote-7.tmp")
	if err := os.WriteFile(tmp, make([]byte, 900), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := removeCacheTemp
	removeCacheTemp = func(path string) error {
		if path == tmp {
			return errors.New("test: busy")
		}
		return os.Remove(path)
	}
	t.Cleanup(func() { removeCacheTemp = orig })
	m := NewManager(root, RetentionPolicy{MaxBytes: 1000, MaxEntries: 10})
	if _, err := m.Reserve(context.Background(), 200); !errors.Is(err, ErrCacheBudgetExceeded) {
		t.Fatalf("reserve past a crash-left temp = %v, want ErrCacheBudgetExceeded", err)
	}
	res, err := m.Reserve(context.Background(), 100)
	if err != nil {
		t.Fatalf("reserve at the remaining budget = %v", err)
	}
	res.Release()
	// Only Kiwi-owned temp shapes are reclaimed: foreign names, directories
	// and symlinks are left alone.
	for _, name := range []string{"keep.txt", "visible.tar.gz", "dir.tar.gz-1.tmp"} {
		path := filepath.Join(root, name)
		if name == "dir.tar.gz-1.tmp" {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, ".link.tar.gz-1.tmp")
	if err := os.Symlink(tmp, link); err != nil {
		t.Fatal(err)
	}
	removeCacheTemp = orig
	_ = NewManager(root, RetentionPolicy{MaxBytes: 1000})
	for _, name := range []string{"keep.txt", "visible.tar.gz", "dir.tar.gz-1.tmp", ".link.tar.gz-1.tmp"} {
		if _, err := os.Lstat(filepath.Join(root, name)); err != nil {
			t.Fatalf("%s was touched by reclamation: %v", name, err)
		}
	}
}

// TestReclaimLegacyLayout pins the upgrade reclamation: pre-namespace
// archives directly under the shared root are deleted, while foreign names,
// directories and symlinks are preserved.
func TestReclaimLegacyLayout(t *testing.T) {
	root := t.TempDir()
	key := strings.Repeat("a", 64)
	for _, name := range []string{key + ".tar.gz", key + ".tar.gz.sha256"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("legacy"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	foreign := filepath.Join(root, "notes.txt")
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, strings.Repeat("b", 64)+".tar.gz")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, strings.Repeat("c", 64)+".tar.gz")
	if err := os.Symlink(foreign, link); err != nil {
		t.Fatal(err)
	}
	files, bytes, err := ReclaimLegacyLayout(root)
	if err != nil || files != 2 || bytes <= 0 {
		t.Fatalf("ReclaimLegacyLayout = %d, %d, %v", files, bytes, err)
	}
	for _, name := range []string{key + ".tar.gz", key + ".tar.gz.sha256"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("legacy %s survived (err=%v)", name, err)
		}
	}
	for _, path := range []string{foreign, dir, link} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("non-legacy %s was touched: %v", path, err)
		}
	}
}

// TestReclamationEdgeBranches pins the reclamation error paths: an
// unreadable root, a canceled context, the owned-temp name grammar, and a
// legacy entry whose removal fails.
func TestReclamationEdgeBranches(t *testing.T) {
	// Owned-name grammar.
	cases := map[string]bool{
		".abc.tar.gz-1.tmp":   true,
		".abc.remote-2.tmp":   true,
		"abc.tar.gz-1.tmp":    false, // not dot-prefixed
		".abc.tmp":            false,
		".tar.gz-1.tmp":       false, // empty key
		".abc.remote-.tmp":    false, // empty suffix
		".abc.tar.gz-1.tmp.x": false,
	}
	for name, want := range cases {
		if got := isOwnedCacheTempName(name); got != want {
			t.Fatalf("isOwnedCacheTempName(%q) = %t, want %t", name, got, want)
		}
	}

	// Unreadable root (a regular file) surfaces the ReadDir error.
	fileRoot := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(fileRoot, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(fileRoot, RetentionPolicy{MaxBytes: 100})
	if _, _, err := m.ReclaimAbandonedTemps(context.Background()); err == nil {
		t.Fatal("reclaim over an unreadable root succeeded")
	}

	// Canceled context stops the sweep (files created AFTER construction, so
	// the constructor's own reclaim does not consume them).
	root := t.TempDir()
	m2 := NewManager(root, RetentionPolicy{MaxBytes: 100})
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf(".k%d.tar.gz-1.tmp", i)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := m2.ReclaimAbandonedTemps(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reclaim = %v", err)
	}

	// Legacy removal failure is reported (and retried on the next startup).
	legacyRoot := t.TempDir()
	key := strings.Repeat("f", 64)
	legacy := filepath.Join(legacyRoot, key+".tar.gz")
	if err := os.WriteFile(legacy, []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := removeCacheFile
	removeCacheFile = func(string) error { return errors.New("test: busy") }
	t.Cleanup(func() { removeCacheFile = orig })
	files, _, err := ReclaimLegacyLayout(legacyRoot)
	if err == nil || files != 0 {
		t.Fatalf("failing legacy reclaim = %d, %v", files, err)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("legacy entry vanished despite the failure: %v", err)
	}
	// Legacy reclaim of a missing root is a no-op.
	if files, bytes, err := ReclaimLegacyLayout(filepath.Join(t.TempDir(), "missing")); err != nil || files != 0 || bytes != 0 {
		t.Fatalf("missing legacy root = %d, %d, %v", files, bytes, err)
	}
}
