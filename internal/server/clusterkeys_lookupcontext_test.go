package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// blockingClusterBlobs models a database read that only ends when its
// context does (embedded interface satisfies the rest of the contract).
type blockingClusterBlobs struct{ storage.ClusterKeyBlobStore }

func (blockingClusterBlobs) GetClusterKey(ctx context.Context, _ string) ([]byte, bool, error) {
	<-ctx.Done()
	return nil, false, ctx.Err()
}

// TestDBClusterKeyLookupContextHonorsCancellation: an abandoned JWKS/refresh
// request must abort the key-store read promptly, not at the store's own
// 10-second bound.
func TestDBClusterKeyLookupContextHonorsCancellation(t *testing.T) {
	store := &DBClusterKeyStore{Blobs: blockingClusterBlobs{}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := store.LookupContext(ctx, clusterKindOIDC)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("LookupContext = %v, want the caller deadline", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancellation took %v", elapsed)
	}
}

// blockingSeedStore is a LEGACY (non-context) seed whose lookup blocks until
// the test releases it (embedded interface satisfies the rest of the store).
type blockingSeedStore struct {
	ClusterKeyStore
	release chan struct{}
}

func (b *blockingSeedStore) Lookup(string) ([]byte, bool, error) {
	<-b.release
	return []byte("seed"), true, nil
}

// TestDBClusterKeySeedLookupHonorsCallerCancellation: an abandoned JWKS
// request must stop waiting on a blocking legacy seed promptly instead of
// parking until the seed returns.
func TestDBClusterKeySeedLookupHonorsCallerCancellation(t *testing.T) {
	seed := &blockingSeedStore{release: make(chan struct{})}
	store := &DBClusterKeyStore{Blobs: blockingClusterBlobs{}, Seed: seed}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	// The blob leg returns ctx.Err() (blockingClusterBlobs waits on ctx), so
	// exercise the seed leg directly through lookupWithContext with a
	// context-aware blob double that misses immediately is overkill: call
	// seedBytes via the same path the store uses.
	_, _, err := store.seedBytes(ctx, "oidc")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("seed lookup = %v, want the caller deadline", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("seed cancellation took %v", elapsed)
	}
	close(seed.release)

	// A context-aware seed is called directly through its LookupContext.
	aware := &contextAwareSeedStore{}
	store2 := &DBClusterKeyStore{Blobs: blockingClusterBlobs{}, Seed: aware}
	b, ok, err := store2.seedBytes(context.Background(), "oidc")
	if err != nil || !ok || string(b) != "ctx-seed" || !aware.called {
		t.Fatalf("context-aware seed = (%q, %v, %v) called=%v", b, ok, err, aware.called)
	}
}

// contextAwareSeedStore implements LookupContext and records the call.
type contextAwareSeedStore struct {
	ClusterKeyStore
	called bool
}

func (c *contextAwareSeedStore) Lookup(string) ([]byte, bool, error) { return nil, false, nil }
func (c *contextAwareSeedStore) LookupContext(context.Context, string) ([]byte, bool, error) {
	c.called = true
	return []byte("ctx-seed"), true, nil
}
