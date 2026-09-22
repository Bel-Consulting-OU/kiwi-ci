package server

import (
	"context"
	"errors"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// clusterKeyStoreOpTimeout bounds one durable cluster-key operation. The
// methods of ClusterKeyStore carry no context, so the DB-backed store imposes
// its own hard bound: a stalled database must not pin the server mutex (the
// OIDC reload runs under s.mu) or the startup path forever.
var clusterKeyStoreOpTimeout = 10 * time.Second

// DBClusterKeyStore is the preferred HA cluster key store in DB mode: every
// signing material lives in the shared cluster_keys table, so replicas load
// identical material from PostgreSQL and node-local data-dir keys are never
// proof of a shared trust root. Creation is cross-replica CAS (insert-if-
// absent, winner's bytes returned); Store is the explicit rotation write.
//
// Seed optionally migrates pre-existing node-local key material into the
// shared table on first use: when the table has no row for a kind and the
// seed store does, the seed bytes are inserted with create-if-absent
// semantics. That keeps an upgrading single-node deployment's OIDC trust
// root, provenance key and runner CA unchanged, while the first replica to
// reach the database wins the migration.
type DBClusterKeyStore struct {
	Blobs storage.ClusterKeyBlobStore
	Seed  ClusterKeyStore
}

var (
	_ ClusterKeyStore          = (*DBClusterKeyStore)(nil)
	_ ClusterKeyWriter         = (*DBClusterKeyStore)(nil)
	_ ClusterKeyLookup         = (*DBClusterKeyStore)(nil)
	_ ClusterKeyInstaller      = (*DBClusterKeyStore)(nil)
	_ ClusterKeyRotationFencer = (*DBClusterKeyStore)(nil)
)

func (s *DBClusterKeyStore) opCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), clusterKeyStoreOpTimeout)
}

// create returns fresh material for kind in the canonical wire format.
func (s *DBClusterKeyStore) create(kind string) ([]byte, error) {
	if kind == clusterKindWebSession {
		return createWebSessionKey()
	}
	return createClusterKey(kind)
}

// LoadOrCreate returns the kind's shared blob, creating it (seeded from the
// node-local store when available, otherwise freshly generated) on first use.
// Creation never returns freshly generated material when the table already
// holds a value: the CAS insert re-reads the winner.
func (s *DBClusterKeyStore) LoadOrCreate(kind string) ([]byte, error) {
	if s.Blobs == nil {
		return nil, errors.New("cluster keys: database-backed store requires a blob store")
	}
	ctx, cancel := s.opCtx()
	defer cancel()
	if b, ok, err := s.Blobs.GetClusterKey(ctx, kind); err != nil {
		return nil, err
	} else if ok {
		return b, nil
	}
	b, ok, err := s.seedBytes(kind)
	if err != nil {
		return nil, err
	}
	if !ok {
		if b, err = s.create(kind); err != nil {
			return nil, err
		}
	}
	stored, _, err := s.Blobs.CreateClusterKey(ctx, kind, b)
	return stored, err
}

// seedBytes resolves pre-existing node-local material for kind without
// creating any. ok=false means the seed store has nothing.
func (s *DBClusterKeyStore) seedBytes(kind string) ([]byte, bool, error) {
	if s.Seed == nil {
		return nil, false, nil
	}
	lookup, ok := s.Seed.(ClusterKeyLookup)
	if !ok {
		return nil, false, nil
	}
	return lookup.Lookup(kind)
}

// Lookup reports the shared blob for kind without generating material. When
// the table has no row yet and the seed store does, the seed material is
// migrated into the table (create-if-absent) first, mirroring the filesystem
// store's legacy-file migration.
func (s *DBClusterKeyStore) Lookup(kind string) ([]byte, bool, error) {
	if s.Blobs == nil {
		return nil, false, errors.New("cluster keys: database-backed store requires a blob store")
	}
	ctx, cancel := s.opCtx()
	defer cancel()
	b, ok, err := s.Blobs.GetClusterKey(ctx, kind)
	if err != nil {
		return nil, false, err
	}
	if ok {
		return b, true, nil
	}
	seed, seeded, err := s.seedBytes(kind)
	if err != nil {
		return nil, false, err
	}
	if !seeded {
		return nil, false, nil
	}
	stored, _, err := s.Blobs.CreateClusterKey(ctx, kind, seed)
	if err != nil {
		return nil, false, err
	}
	return stored, true, nil
}

// InstallOrLoad atomically installs data for kind when the shared table has
// no row yet and returns the stored bytes; created reports whether this
// caller's bytes were installed. CreateClusterKey is insert-if-absent, so a
// concurrent installer's material wins and is returned instead of data.
// Unlike LoadOrCreate/Lookup the node-local Seed migration is deliberately
// NOT consulted: explicit material (an operator-provided runner CA) must be
// installed as given and compared against the shared row, never silently
// replaced by node-local state.
func (s *DBClusterKeyStore) InstallOrLoad(kind string, data []byte) ([]byte, bool, error) {
	if s.Blobs == nil {
		return nil, false, errors.New("cluster keys: database-backed store requires a blob store")
	}
	if len(data) == 0 {
		return nil, false, errors.New("cluster keys: empty key material")
	}
	ctx, cancel := s.opCtx()
	defer cancel()
	stored, created, err := s.Blobs.CreateClusterKey(ctx, kind, data)
	if err != nil {
		return nil, false, err
	}
	return stored, created, nil
}

// Store persists a rotated blob (OIDC ring) through the shared table.
func (s *DBClusterKeyStore) Store(kind string, data []byte) error {
	if s.Blobs == nil {
		return errors.New("cluster keys: database-backed store requires a blob store")
	}
	ctx, cancel := s.opCtx()
	defer cancel()
	return s.Blobs.PutClusterKey(ctx, kind, data)
}

// WithClusterKeyRotationFence acquires the cross-replica rotation fence for
// kind and runs fn while holding it. fn is expected to reload the ring,
// re-check whether rotation is still due, and rotate and persist exactly
// once; the caller's bounded context bounds lock contention.
func (s *DBClusterKeyStore) WithClusterKeyRotationFence(ctx context.Context, kind string, fn func() error) error {
	if s.Blobs == nil {
		return errors.New("cluster keys: database-backed store requires a blob store")
	}
	return s.Blobs.WithClusterKeyRotationFence(ctx, kind, fn)
}
