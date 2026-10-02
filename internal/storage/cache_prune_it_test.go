package storage

// Real-PostgreSQL integration test for the cache-manifest retention fence.
// Gated on KIWI_TEST_POSTGRES_URL like the rest of the integration lane.

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestIntegrationPruneCacheManifestsFencesConcurrentRefreshPostgres proves
// the victim identity fence under real row-lock contention: a manifest
// ranked as a victim is refreshed inside an uncommitted transaction while
// the prune blocks on its row lock; when the refresh commits, the DELETE's
// re-evaluation must NOT delete the refreshed row (created_at/blob changed).
// Without the created_at + blob_sha256 conditions the PK-only match deletes
// it on stale information.
func TestIntegrationPruneCacheManifestsFencesConcurrentRefreshPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo := "repo-" + pgITNewID(t)

	mk := func(key, digest string, size int64, created time.Time) {
		t.Helper()
		// Seed through raw SQL with an EXPLICIT created_at: the ranking in
		// this test is about the victim-identity fence, and the production
		// writers stamp created_at from the database clock (covered by the
		// cache-clock tests).
		payload, err := jsonMarshal(CacheManifestRecord{
			Repo: repo, TrustDomain: "t", LogicalKey: key,
			BlobSHA256: digest, BlobSize: size, CreatedAt: created,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.pool.Exec(ctx, `INSERT INTO cache_manifests (repo, trust_domain, logical_key, blob_sha256, blob_size, created_at, payload) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (repo, trust_domain, logical_key) DO UPDATE SET blob_sha256=EXCLUDED.blob_sha256, blob_size=EXCLUDED.blob_size, created_at=EXCLUDED.created_at, payload=EXCLUDED.payload`,
			repo, "t", key, digest, size, created, payload); err != nil {
			t.Fatal(err)
		}
	}
	mk("k-old", strings.Repeat("a", 64), 10, time.Now().UTC().Add(-2*time.Hour))
	mk("k-new", strings.Repeat("b", 64), 10, time.Now().UTC())

	refreshed := CacheManifestRecord{
		Repo: repo, TrustDomain: "t", LogicalKey: "k-old",
		BlobSHA256: strings.Repeat("c", 64), BlobSize: 11, CreatedAt: time.Now().UTC(),
	}
	payload, err := jsonMarshal(refreshed)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`UPDATE cache_manifests SET blob_sha256=$1, blob_size=$2, created_at=$3, payload=$4 WHERE repo=$5 AND trust_domain=$6 AND logical_key=$7`,
		refreshed.BlobSHA256, refreshed.BlobSize, refreshed.CreatedAt, payload, repo, "t", "k-old"); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	var (
		res      CacheManifestPruneResult
		pruneErr error
	)
	go func() {
		res, pruneErr = st.PruneCacheManifests(ctx, CacheManifestPrunePolicy{PerRepoMaxEntries: 1})
		close(done)
	}()

	// Deterministic barrier: wait until the prune's DELETE is blocked on the
	// cache_manifests row lock this transaction holds.
	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case <-done:
			t.Fatalf("prune finished before blocking on the row lock: res=%+v err=%v", res, pruneErr)
		default:
		}
		var blocked int
		if err := st.pool.QueryRow(ctx, `
SELECT count(*) FROM pg_stat_activity
WHERE wait_event_type = 'Lock' AND state <> 'idle'`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("prune never blocked on the refreshed manifest's row lock")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("prune did not finish after the refresh committed")
	}
	if pruneErr != nil {
		t.Fatal(pruneErr)
	}
	if res.Manifests != 0 {
		t.Fatalf("prune deleted %d manifests; a refreshed victim must not match the stale identity", res.Manifests)
	}
	got, ok, err := st.GetCacheManifest(ctx, repo, "t", "k-old")
	if err != nil || !ok {
		t.Fatalf("refreshed manifest missing: ok=%t err=%v", ok, err)
	}
	if got.BlobSHA256 != refreshed.BlobSHA256 {
		t.Fatalf("manifest digest = %q, want the refreshed %q", got.BlobSHA256, refreshed.BlobSHA256)
	}
}
