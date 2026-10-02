package storage

// Real-PostgreSQL integration tests for cache retention clock authority: the
// relational cache_manifests.created_at used by ranking/pruning (and the age
// cutoff itself) come from the DATABASE clock, while the producer instant
// stays in the payload as provenance. A skewed publishing or pruning replica
// therefore cannot prematurely age a fresh entry, pin a stale one, or change
// which entry the per-repo quota evicts.

import (
	"context"
	"strings"
	"testing"
	"time"
)

// cacheManifestColumnCreatedAt reads the retention-authority column.
func cacheManifestColumnCreatedAt(t *testing.T, st *PostgresStore, repo, trust, key string) time.Time {
	t.Helper()
	var col time.Time
	if err := st.pool.QueryRow(context.Background(), `SELECT created_at FROM cache_manifests WHERE repo=$1 AND trust_domain=$2 AND logical_key=$3`, repo, trust, key).Scan(&col); err != nil {
		t.Fatal(err)
	}
	return col.UTC()
}

// seedCacheManifestClock inserts one manifest row directly with an explicit
// relational created_at, modelling a row whose durable commit time is old (or
// fresh) while the payload carries an arbitrary producer instant.
func seedCacheManifestClock(t *testing.T, st *PostgresStore, repo, key string, size int64, producer time.Time, columnCreated time.Time) {
	t.Helper()
	payload, err := jsonMarshal(CacheManifestRecord{
		Repo: repo, TrustDomain: "t", LogicalKey: key,
		BlobSHA256: strings.Repeat("a", 64), BlobSize: size, CreatedAt: producer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(context.Background(), `INSERT INTO cache_manifests (repo, trust_domain, logical_key, blob_sha256, blob_size, created_at, payload) VALUES ($1, 't', $2, $3, $4, $5, $6)`,
		repo, key, strings.Repeat("a", 64), size, columnCreated, payload); err != nil {
		t.Fatal(err)
	}
}

func cacheManifestExists(t *testing.T, st *PostgresStore, repo, key string) bool {
	t.Helper()
	_, ok, err := st.GetCacheManifest(context.Background(), repo, "t", key)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// TestIntegrationCacheManifestCommitTimeUsesDBClock pins the plain writer:
// the producer's wildly skewed CreatedAt stays in the payload as provenance,
// while the relational retention column is the database commit instant.
func TestIntegrationCacheManifestCommitTimeUsesDBClock(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo := "repo-" + pgITNewID(t)
	producer := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Microsecond)
	rec := CacheManifestRecord{Repo: repo, TrustDomain: "t", LogicalKey: "skewed", BlobSHA256: strings.Repeat("a", 64), BlobSize: 10, CreatedAt: producer}
	before := leaseClockITDBNow(t, st)
	if err := st.PutCacheManifest(ctx, rec); err != nil {
		t.Fatal(err)
	}
	after := leaseClockITDBNow(t, st)
	col := cacheManifestColumnCreatedAt(t, st, repo, "t", "skewed")
	if col.Before(before.Add(-time.Second)) || col.After(after.Add(time.Second)) {
		t.Fatalf("cache commit time %v outside the database window [%v, %v]: the producer clock was used", col, before, after)
	}
	got, ok, err := st.GetCacheManifest(ctx, repo, "t", "skewed")
	if err != nil || !ok {
		t.Fatalf("get manifest: ok=%t err=%v", ok, err)
	}
	if !got.CreatedAt.Equal(producer) {
		t.Fatalf("payload provenance = %v, want the producer instant %v", got.CreatedAt, producer)
	}
}

// TestIntegrationCacheManifestLeaseCommitUsesDBClock pins the lease-fenced
// writer: coords.DBNow stamps the retention column even when the producer
// claims a far-future instant.
func TestIntegrationCacheManifestLeaseCommitUsesDBClock(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, runnerID := leaseClockITSetup(t, st)
	if _, err := st.AcquireLeaseWithTTL(ctx, leaseClockITClaim(jobID, runnerID, time.Minute)); err != nil {
		t.Fatal(err)
	}
	job, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	repo := RepoIDForJob(job)
	producer := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Microsecond)
	rec := CacheManifestRecord{Repo: repo, TrustDomain: cacheTrustDomain(job.Trusted), LogicalKey: "fenced-skew", BlobSHA256: strings.Repeat("b", 64), BlobSize: 11, CreatedAt: producer}
	before := leaseClockITDBNow(t, st)
	if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, job.LeaseGeneration, rec); err != nil {
		t.Fatalf("PutCacheManifestForLease: %v", err)
	}
	after := leaseClockITDBNow(t, st)
	col := cacheManifestColumnCreatedAt(t, st, repo, rec.TrustDomain, rec.LogicalKey)
	if col.Before(before.Add(-time.Second)) || col.After(after.Add(time.Second)) {
		t.Fatalf("fenced cache commit time %v outside the database window [%v, %v]: the producer clock was used", col, before, after)
	}
	got, ok, err := st.GetCacheManifest(ctx, repo, rec.TrustDomain, rec.LogicalKey)
	if err != nil || !ok {
		t.Fatalf("get manifest: ok=%t err=%v", ok, err)
	}
	if !got.CreatedAt.Equal(producer) {
		t.Fatalf("payload provenance = %v, want the producer instant %v", got.CreatedAt, producer)
	}
}

// TestIntegrationCacheReplicaClockSkewCannotImmediatelyExpireFreshEntry pins
// the age pruner: a fresh DB commit with a producer timestamp 72 hours in
// the past must survive a 1-hour retention window (the cutoff is the database
// clock).
func TestIntegrationCacheReplicaClockSkewCannotImmediatelyExpireFreshEntry(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo := "repo-" + pgITNewID(t)
	rec := CacheManifestRecord{Repo: repo, TrustDomain: "t", LogicalKey: "fresh", BlobSHA256: strings.Repeat("a", 64), BlobSize: 10, CreatedAt: time.Now().UTC().Add(-72 * time.Hour)}
	if err := st.PutCacheManifest(ctx, rec); err != nil {
		t.Fatal(err)
	}
	res, err := st.PruneCacheManifests(ctx, CacheManifestPrunePolicy{OlderThan: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifests != 0 || !cacheManifestExists(t, st, repo, "fresh") {
		t.Fatalf("prune evicted a fresh entry on the producer's skewed clock: %+v", res)
	}
}

// TestIntegrationCacheReplicaClockSkewCannotPinEntry pins the mirror case: an
// entry whose DURABLE commit time is 72 hours old is age-pruned even though
// its payload claims a far-future producer instant.
func TestIntegrationCacheReplicaClockSkewCannotPinEntry(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo := "repo-" + pgITNewID(t)
	old := leaseClockITDBNow(t, st).Add(-72 * time.Hour).Truncate(time.Microsecond)
	seedCacheManifestClock(t, st, repo, "pinned", 10, time.Now().UTC().Add(72*time.Hour), old)
	res, err := st.PruneCacheManifests(ctx, CacheManifestPrunePolicy{OlderThan: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifests != 1 || cacheManifestExists(t, st, repo, "pinned") {
		t.Fatalf("future producer instant pinned an old durable entry: %+v", res)
	}
}

// TestIntegrationCacheQuotaOrderingIndependentOfProducerClock pins quota
// eviction: entries are ranked by their DATABASE commit order, not by the
// deliberately inverted producer instants (k1 claims +72h yet committed
// first, k3 claims -72h yet committed last). Both the entry and the byte
// budgets must evict k1.
func TestIntegrationCacheQuotaOrderingIndependentOfProducerClock(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	publish := func(repo string) {
		t.Helper()
		producers := []time.Time{
			time.Now().UTC().Add(72 * time.Hour),  // k1: claims newest, committed first
			time.Now().UTC(),                      // k2
			time.Now().UTC().Add(-72 * time.Hour), // k3: claims oldest, committed last
		}
		for i, key := range []string{"k1", "k2", "k3"} {
			if err := st.PutCacheManifest(ctx, CacheManifestRecord{Repo: repo, TrustDomain: "t", LogicalKey: key, BlobSHA256: string(rune('a'+i)) + strings.Repeat("0", 63), BlobSize: 100, CreatedAt: producers[i]}); err != nil {
				t.Fatal(err)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}

	entriesRepo := "repo-entries-" + pgITNewID(t)
	publish(entriesRepo)
	res, err := st.PruneCacheManifests(ctx, CacheManifestPrunePolicy{PerRepoMaxEntries: 2})
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifests != 1 {
		t.Fatalf("entry quota evicted %d manifests, want 1", res.Manifests)
	}
	if cacheManifestExists(t, st, entriesRepo, "k1") {
		t.Fatal("entry quota evicted by the producer clock: k1 (first DB commit) survived")
	}
	if !cacheManifestExists(t, st, entriesRepo, "k2") || !cacheManifestExists(t, st, entriesRepo, "k3") {
		t.Fatal("entry quota evicted the newest database commits")
	}

	bytesRepo := "repo-bytes-" + pgITNewID(t)
	publish(bytesRepo)
	res, err = st.PruneCacheManifests(ctx, CacheManifestPrunePolicy{PerRepoMaxBytes: 250})
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifests != 1 || res.Bytes != 100 {
		t.Fatalf("byte quota evicted %d manifests / %d bytes, want 1 / 100", res.Manifests, res.Bytes)
	}
	if cacheManifestExists(t, st, bytesRepo, "k1") {
		t.Fatal("byte quota evicted by the producer clock: k1 (first DB commit) survived")
	}
	if !cacheManifestExists(t, st, bytesRepo, "k2") || !cacheManifestExists(t, st, bytesRepo, "k3") {
		t.Fatal("byte quota evicted the newest database commits")
	}
}
