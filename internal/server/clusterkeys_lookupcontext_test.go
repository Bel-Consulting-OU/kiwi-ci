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
