package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// memClusterKeyRow is one row of the in-memory ClusterKeyBlobStore.
type memClusterKeyRow struct {
	data    []byte
	version int64
}

// memClusterKeyBlobs is an in-memory storage.ClusterKeyBlobStore with the
// same CAS-create / versioned-put / fence semantics as the SQL implementation.
type memClusterKeyBlobs struct {
	mu          sync.Mutex
	rows        map[string]memClusterKeyRow
	fence       sync.Mutex
	creates     int
	puts        int
	fenceCalls  int
	fenceErr    error
	createdWith map[string]bool
}

var _ storage.ClusterKeyBlobStore = (*memClusterKeyBlobs)(nil)

func newMemClusterKeyBlobs() *memClusterKeyBlobs {
	return &memClusterKeyBlobs{rows: map[string]memClusterKeyRow{}, createdWith: map[string]bool{}}
}

func (m *memClusterKeyBlobs) EnsureClusterKeySchema(context.Context) error { return nil }

func (m *memClusterKeyBlobs) GetClusterKey(_ context.Context, kind string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.rows[kind]
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), row.data...), true, nil
}

func (m *memClusterKeyBlobs) CreateClusterKey(_ context.Context, kind string, data []byte) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if row, ok := m.rows[kind]; ok {
		return append([]byte(nil), row.data...), false, nil
	}
	m.creates++
	m.createdWith[kind] = true
	m.rows[kind] = memClusterKeyRow{data: append([]byte(nil), data...), version: 1}
	return append([]byte(nil), data...), true, nil
}

func (m *memClusterKeyBlobs) PutClusterKey(_ context.Context, kind string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.puts++
	row := m.rows[kind]
	row.data = append([]byte(nil), data...)
	row.version++
	m.rows[kind] = row
	return nil
}

func (m *memClusterKeyBlobs) WithClusterKeyRotationFence(ctx context.Context, _ string, fn func() error) error {
	m.mu.Lock()
	m.fenceCalls++
	m.mu.Unlock()
	if m.fenceErr != nil {
		return m.fenceErr
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	m.fence.Lock()
	defer m.fence.Unlock()
	return fn()
}

func (m *memClusterKeyBlobs) version(kind string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rows[kind].version
}

func (m *memClusterKeyBlobs) ClusterKeyVersion(_ context.Context, kind string) (int64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.rows[kind]
	if !ok {
		return 0, false, nil
	}
	return row.version, true, nil
}

// TestDBClusterKeyStoreCASCreate proves two replicas racing to create the
// same kind converge on one winning blob: the SQL create is insert-if-absent
// and the loser reads the winner's material instead of activating its own.
func TestDBClusterKeyStoreCASCreate(t *testing.T) {
	blobs := newMemClusterKeyBlobs()
	a := &DBClusterKeyStore{Blobs: blobs}
	b := &DBClusterKeyStore{Blobs: blobs}
	var wg sync.WaitGroup
	out := make([][]byte, 2)
	for i, store := range []*DBClusterKeyStore{a, b} {
		wg.Add(1)
		go func(i int, store *DBClusterKeyStore) {
			defer wg.Done()
			got, err := store.LoadOrCreate(clusterKindOIDC)
			if err != nil {
				t.Error(err)
				return
			}
			out[i] = got
		}(i, store)
	}
	wg.Wait()
	if len(out[0]) == 0 || len(out[1]) == 0 {
		t.Fatal("concurrent LoadOrCreate returned empty material")
	}
	if string(out[0]) != string(out[1]) {
		t.Fatal("concurrent creators diverged: the CAS loser did not adopt the winner's key")
	}
	if blobs.creates != 1 {
		t.Fatalf("create calls = %d, want exactly one winner", blobs.creates)
	}
	if v := blobs.version(clusterKindOIDC); v != 1 {
		t.Fatalf("row version after create = %d, want 1", v)
	}
}

// TestDBClusterKeyStoreSeedMigration proves an upgrading deployment keeps its
// node-local trust roots: material present only in the seed store is migrated
// into the shared table on first use, and later loads read the shared copy.
func TestDBClusterKeyStoreSeedMigration(t *testing.T) {
	seed := &FSClusterKeyStore{Dir: t.TempDir()}
	seeded, err := seed.LoadOrCreate(clusterKindLease)
	if err != nil {
		t.Fatal(err)
	}
	blobs := newMemClusterKeyBlobs()
	store := &DBClusterKeyStore{Blobs: blobs, Seed: seed}
	got, err := store.LoadOrCreate(clusterKindLease)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(seeded) {
		t.Fatal("seeded material not migrated unchanged")
	}
	stored, ok, err := blobs.GetClusterKey(context.Background(), clusterKindLease)
	if err != nil || !ok {
		t.Fatalf("seed migration did not persist: ok=%v err=%v", ok, err)
	}
	if string(stored) != string(seeded) {
		t.Fatal("shared row does not hold the seed material")
	}
	// Lookup migrates without generating: a fresh store over the same blobs
	// serves the migrated bytes too.
	second := &DBClusterKeyStore{Blobs: blobs}
	looked, ok, err := second.Lookup(clusterKindLease)
	if err != nil || !ok || string(looked) != string(seeded) {
		t.Fatalf("shared lookup = ok=%v err=%v", ok, err)
	}
}

// TestDBClusterKeyStoreLookupMigrates proves Lookup also seeds the shared
// table (the runner-CA loader only ever looks up), so a pre-existing node-local
// CA is adopted instead of silently disabling mTLS on the shared store.
func TestDBClusterKeyStoreLookupMigrates(t *testing.T) {
	seed := &FSClusterKeyStore{Dir: t.TempDir()}
	seeded, err := seed.LoadOrCreate(clusterKindRunnerCA)
	if err != nil {
		t.Fatal(err)
	}
	blobs := newMemClusterKeyBlobs()
	store := &DBClusterKeyStore{Blobs: blobs, Seed: seed}
	got, ok, err := store.Lookup(clusterKindRunnerCA)
	if err != nil || !ok {
		t.Fatalf("lookup = ok=%v err=%v", ok, err)
	}
	if string(got) != string(seeded) {
		t.Fatal("runner CA seed material not migrated unchanged")
	}
	if _, ok, _ := blobs.GetClusterKey(context.Background(), clusterKindRunnerCA); !ok {
		t.Fatal("runner CA not persisted into the shared table")
	}
}

// TestDBClusterKeyStoreRotationBumpsVersion covers the explicit rotation
// write and the fence delegation.
func TestDBClusterKeyStoreRotationBumpsVersion(t *testing.T) {
	blobs := newMemClusterKeyBlobs()
	store := &DBClusterKeyStore{Blobs: blobs}
	if _, err := store.LoadOrCreate(clusterKindOIDC); err != nil {
		t.Fatal(err)
	}
	if err := store.Store(clusterKindOIDC, []byte(`{"active":{"kid":"rotated"}}`)); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Lookup(clusterKindOIDC)
	if err != nil || !ok || !strings.Contains(string(got), "rotated") {
		t.Fatalf("rotated lookup = ok=%v err=%v body=%s", ok, err, got)
	}
	if v := blobs.version(clusterKindOIDC); v != 2 {
		t.Fatalf("version after one rotation = %d, want 2", v)
	}
	ran := false
	if err := store.WithClusterKeyRotationFence(context.Background(), clusterKindOIDC, func() error {
		ran = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !ran || blobs.fenceCalls != 1 {
		t.Fatalf("fence delegation: ran=%v calls=%d", ran, blobs.fenceCalls)
	}
}

// TestDBClusterKeyStoreErrors covers the nil-blob-store refusals.
func TestDBClusterKeyStoreErrors(t *testing.T) {
	store := &DBClusterKeyStore{}
	if _, err := store.LoadOrCreate(clusterKindLease); err == nil {
		t.Fatal("LoadOrCreate without a blob store = nil error")
	}
	if _, _, err := store.Lookup(clusterKindLease); err == nil {
		t.Fatal("Lookup without a blob store = nil error")
	}
	if err := store.Store(clusterKindLease, []byte("x")); err == nil {
		t.Fatal("Store without a blob store = nil error")
	}
	if err := store.WithClusterKeyRotationFence(context.Background(), clusterKindLease, func() error { return nil }); err == nil {
		t.Fatal("fence without a blob store = nil error")
	}
}

// TestValidateHAReadyRejectsNodeLocalDataDirStore proves the HA readiness
// gate no longer accepts the implicit per-node data-dir store as proof of a
// shared trust root.
func TestValidateHAReadyRejectsNodeLocalDataDirStore(t *testing.T) {
	dataDir := t.TempDir()
	s, err := NewPersistent("t", "t", dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(newDBFakeStore()); err != nil {
		t.Fatal(err)
	}
	err = s.ValidateHAReady()
	if err == nil || !strings.Contains(err.Error(), "shared cluster key store") {
		t.Fatalf("node-local data-dir store accepted: %v", err)
	}
	// A filesystem alias of the data dir is still node-local.
	alias := filepath.Join(t.TempDir(), "data-dir-alias")
	if serr := os.Symlink(dataDir, alias); serr == nil {
		s2, err := NewPersistentWithCluster("t", "t", dataDir, &FSClusterKeyStore{Dir: alias})
		if err != nil {
			t.Fatal(err)
		}
		if err := s2.SwitchToDB(newDBFakeStore()); err != nil {
			t.Fatal(err)
		}
		if verr := s2.ValidateHAReady(); verr == nil || !strings.Contains(verr.Error(), "shared cluster key store") {
			t.Fatalf("data-dir symlink alias accepted: %v", verr)
		}
	}
}

// TestValidateHAReadyAcceptsSharedProviders proves the two deliberate shared
// providers pass: an explicit shared --cluster-key-dir, and the DB-backed
// store.
func TestValidateHAReadyAcceptsSharedProviders(t *testing.T) {
	dataDir := t.TempDir()
	sharedDir := t.TempDir()
	s, err := NewPersistentWithCluster("t", "t", dataDir, &FSClusterKeyStore{Dir: sharedDir})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(newDBFakeStore()); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateHAReady(); err != nil {
		t.Fatalf("explicit shared cluster dir rejected: %v", err)
	}

	s2, err := NewPersistent("t", "t", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	blobs := newMemClusterKeyBlobs()
	if err := s2.UseClusterKeyStore(&DBClusterKeyStore{Blobs: blobs, Seed: s2.ClusterKeys}); err != nil {
		t.Fatal(err)
	}
	if err := s2.SwitchToDB(newDBFakeStore()); err != nil {
		t.Fatal(err)
	}
	if err := s2.ValidateHAReady(); err != nil {
		t.Fatalf("DB-backed key store rejected: %v", err)
	}
}

// TestValidateHAReadyDevModeUnchanged proves non-HA/dev servers (no DB) are
// unaffected by the node-local rule.
func TestValidateHAReadyDevModeUnchanged(t *testing.T) {
	s, err := NewPersistent("t", "t", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateHAReady(); err != nil {
		t.Fatalf("dev server rejected by ValidateHAReady: %v", err)
	}
	// A DB-mode server with no cluster store at all still fails.
	bare := New("t")
	if err := bare.SwitchToDB(newDBFakeStore()); err != nil {
		t.Fatal(err)
	}
	if err := bare.ValidateHAReady(); err == nil || !strings.Contains(err.Error(), "cluster key store") {
		t.Fatalf("DB server without a key store = %v", err)
	}
}

// TestUseClusterKeyStoreLoadsEveryMaterial proves UseClusterKeyStore swaps
// the store and loads the full material set through it.
func TestUseClusterKeyStoreLoadsEveryMaterial(t *testing.T) {
	s, err := NewPersistent("t", "t", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	blobs := newMemClusterKeyBlobs()
	store := &DBClusterKeyStore{Blobs: blobs}
	if err := s.UseClusterKeyStore(store); err != nil {
		t.Fatal(err)
	}
	if s.ClusterKeys != ClusterKeyStore(store) {
		t.Fatal("cluster key store not swapped in")
	}
	fp := s.KeyFingerprints()
	for _, kind := range []string{clusterKindLease, clusterKindOIDC, clusterKindProvenance, clusterKindCacheSigning, clusterKindWebSession} {
		if fp[kind] == "" {
			t.Fatalf("material %q not loaded through the new store", kind)
		}
	}
	// The OIDC signer must be bound to the new store so reload/rotation use it.
	s.mu.Lock()
	cluster := s.oidc.cluster
	s.mu.Unlock()
	if cluster == nil {
		t.Fatal("OIDC signer not bound to the new cluster store")
	}
	if err := s.UseClusterKeyStore(nil); err == nil {
		t.Fatal("nil store accepted")
	}
}
