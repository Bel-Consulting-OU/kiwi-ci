package storage

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func cachePruneRec(repo, trust, key, digest string, size int64, created time.Time) CacheManifestRecord {
	return CacheManifestRecord{
		Repo:        repo,
		TrustDomain: trust,
		LogicalKey:  key,
		BlobSHA256:  digest,
		BlobSize:    size,
		CreatedAt:   created,
	}
}

// TestPruneCacheManifestsPerRepoIsolation is the per-repository accounting
// regression: filling one repository's quota must never evict another
// repository's manifests.
func TestPruneCacheManifestsPerRepoIsolation(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	base := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 3; i++ {
		if err := m.PutCacheManifest(ctx, cachePruneRec("repo-a", "t", fmt.Sprintf("k%d", i), "aa"+fmt.Sprint(i), 100, base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.PutCacheManifest(ctx, cachePruneRec("repo-b", "t", "kB", "bb1", 100, base)); err != nil {
		t.Fatal(err)
	}
	res, err := m.PruneCacheManifests(ctx, CacheManifestPrunePolicy{PerRepoMaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifests != 2 {
		t.Fatalf("pruned %d manifests, want repo-a's 2 oldest", res.Manifests)
	}
	if _, ok, _ := m.GetCacheManifest(ctx, "repo-a", "t", "k2"); !ok {
		t.Fatal("repo-a's newest manifest was evicted")
	}
	if _, ok, _ := m.GetCacheManifest(ctx, "repo-a", "t", "k0"); ok {
		t.Fatal("repo-a's oldest manifest survived")
	}
	if _, ok, _ := m.GetCacheManifest(ctx, "repo-b", "t", "kB"); !ok {
		t.Fatal("repo-b's only manifest was evicted by repo-a's accounting")
	}
}

// TestPruneCacheManifestsAge pins the age dimension.
func TestPruneCacheManifestsAge(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	now := time.Now()
	if err := m.PutCacheManifest(ctx, cachePruneRec("r", "t", "old", "d1", 10, now.Add(-2*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := m.PutCacheManifest(ctx, cachePruneRec("r", "t", "fresh", "d2", 10, now)); err != nil {
		t.Fatal(err)
	}
	res, err := m.PruneCacheManifests(ctx, CacheManifestPrunePolicy{OlderThan: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifests != 1 {
		t.Fatalf("pruned %d, want the aged one", res.Manifests)
	}
	if _, ok, _ := m.GetCacheManifest(ctx, "r", "t", "fresh"); !ok {
		t.Fatal("fresh manifest was evicted")
	}
}

// TestPruneCacheManifestsByteBound pins the per-repo byte accounting: once
// the running (newest-first) sum exceeds the bound, that manifest and every
// older one are evicted.
func TestPruneCacheManifestsByteBound(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 3; i++ {
		if err := m.PutCacheManifest(ctx, cachePruneRec("r", "t", fmt.Sprintf("k%d", i), fmt.Sprintf("d%d", i), 100, base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	res, err := m.PruneCacheManifests(ctx, CacheManifestPrunePolicy{PerRepoMaxBytes: 150})
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifests != 2 || res.Bytes != 200 {
		t.Fatalf("prune = %+v, want the 2 older manifests (200 bytes)", res)
	}
	if _, ok, _ := m.GetCacheManifest(ctx, "r", "t", "k2"); !ok {
		t.Fatal("newest manifest was evicted")
	}
}

// TestPruneCacheManifestsSkipsEmptyDigest pins the CAS-reference parity: a
// record without a blob digest is not a live reference and is not ranked.
func TestPruneCacheManifestsSkipsEmptyDigest(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	if err := m.PutCacheManifest(ctx, cachePruneRec("r", "t", "empty", "", 0, time.Now().Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	res, err := m.PruneCacheManifests(ctx, CacheManifestPrunePolicy{OlderThan: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifests != 0 {
		t.Fatalf("pruned %d digestless manifests, want 0", res.Manifests)
	}
	if _, ok, _ := m.GetCacheManifest(ctx, "r", "t", "empty"); !ok {
		t.Fatal("digestless manifest was evicted")
	}
}

// TestPruneCacheManifestsDisabledPolicyIsNoop pins the zero-policy guard.
func TestPruneCacheManifestsDisabledPolicyIsNoop(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	if err := m.PutCacheManifest(ctx, cachePruneRec("r", "t", "k", "d", 1, time.Now())); err != nil {
		t.Fatal(err)
	}
	res, err := m.PruneCacheManifests(ctx, CacheManifestPrunePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifests != 0 {
		t.Fatalf("disabled policy pruned %d", res.Manifests)
	}
}
