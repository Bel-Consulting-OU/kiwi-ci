package server

// Real-PostgreSQL integration test for the DB-mode cache-manifest retention
// path. Gated on KIWI_TEST_POSTGRES_URL like the rest of the integration
// lane.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestIntegrationPruneCacheManifestsPostgresDB drives the server's
// DB-mode pruning branch against a live store: the oldest manifest in a
// namespace is evicted, the newest survives.
func TestIntegrationPruneCacheManifestsPostgresDB(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	ctx := context.Background()
	s.CacheManifestRetention = -1
	s.MaxCacheManifestsPerRepo = 1
	s.MaxCacheManifestBytesPerRepo = -1

	repo := "repo-" + pgITServerRandomHex(t, 8)
	now := time.Now().UTC()
	put := func(key, digest string, created time.Time) {
		t.Helper()
		if err := st.PutCacheManifest(ctx, storage.CacheManifestRecord{
			Repo: repo, TrustDomain: "t", LogicalKey: key,
			BlobSHA256: digest, BlobSize: 10, CreatedAt: created,
		}); err != nil {
			t.Fatal(err)
		}
	}
	put("old", strings.Repeat("a", 64), now.Add(-2*time.Hour))
	put("new", strings.Repeat("b", 64), now)

	s.pruneCacheManifests(ctx, now)
	if _, ok, err := st.GetCacheManifest(ctx, repo, "t", "old"); ok || err != nil {
		t.Fatalf("old manifest survived DB prune (ok=%t err=%v)", ok, err)
	}
	if _, ok, err := st.GetCacheManifest(ctx, repo, "t", "new"); !ok || err != nil {
		t.Fatalf("new manifest was evicted (ok=%t err=%v)", ok, err)
	}
}
