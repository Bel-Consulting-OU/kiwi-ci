package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
)

// writeFSCacheManifestForTest writes one signed fs-mode manifest envelope
// under the server's data dir, mirroring what an upload persists.
func writeFSCacheManifestForTest(t *testing.T, s *Server, repo, trust, key, digest string, size int64, created time.Time) string {
	t.Helper()
	signer := s.ensureCacheSigner()
	m := cache.CacheManifest{
		Version:     1,
		Repository:  repo,
		TrustDomain: trust,
		LogicalKey:  key,
		BlobSHA256:  digest,
		BlobSize:    size,
		CreatedAt:   created,
	}
	b, err := cache.SignManifest(m, signer.KID, signer.Private)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.store.Root, "cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, key+".manifest.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestPruneCacheManifestsFilesReleaseCASBlobs is the durable-retention
// regression: once the oldest manifest is pruned it stops referencing its
// blob, so the reference-aware CAS collector reclaims it, while the newest
// manifest's blob survives.
func TestPruneCacheManifestsFilesReleaseCASBlobs(t *testing.T) {
	s, _ := casGCTestServer(t)
	s.CacheManifestRetention = -1
	s.MaxCacheManifestsPerRepo = 1
	s.MaxCacheManifestBytesPerRepo = -1
	ctx := context.Background()

	oldBlob := putCASBlob(t, s, "old-cache-payload")
	newBlob := putCASBlob(t, s, "new-cache-payload")
	ageCASBlob(t, s, oldBlob.SHA256, 48*time.Hour)
	ageCASBlob(t, s, newBlob.SHA256, 48*time.Hour)

	oldPath := writeFSCacheManifestForTest(t, s, "repo", "t", "k-old", oldBlob.SHA256, oldBlob.Size, time.Now().Add(-2*time.Hour))
	newPath := writeFSCacheManifestForTest(t, s, "repo", "t", "k-new", newBlob.SHA256, newBlob.Size, time.Now())

	s.pruneCacheManifests(ctx, time.Now())
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("aged manifest was not pruned (err=%v)", err)
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Fatalf("newest manifest was pruned: %v", err)
	}
	if _, err := s.runCASGC(ctx, casGCOptions{MinAge: 24 * time.Hour, Batch: 100, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if casBlobExists(t, s, oldBlob.SHA256) {
		t.Fatal("blob of the pruned manifest was not reclaimed")
	}
	if !casBlobExists(t, s, newBlob.SHA256) {
		t.Fatal("blob still referenced by a live manifest was reclaimed")
	}
}

// TestPruneCacheManifestsSharedDigestSurvivesEviction pins the reference
// semantics: the same digest referenced by two manifests survives one
// manifest's eviction, and is reclaimed only when the last reference is gone.
func TestPruneCacheManifestsSharedDigestSurvivesEviction(t *testing.T) {
	s, _ := casGCTestServer(t)
	s.CacheManifestRetention = -1
	s.MaxCacheManifestsPerRepo = 1
	s.MaxCacheManifestBytesPerRepo = -1
	ctx := context.Background()

	shared := putCASBlob(t, s, "shared-cache-payload")
	ageCASBlob(t, s, shared.SHA256, 48*time.Hour)
	writeFSCacheManifestForTest(t, s, "repo", "t", "k-old", shared.SHA256, shared.Size, time.Now().Add(-2*time.Hour))
	newPath := writeFSCacheManifestForTest(t, s, "repo", "t", "k-new", shared.SHA256, shared.Size, time.Now())

	s.pruneCacheManifests(ctx, time.Now())
	if _, err := s.runCASGC(ctx, casGCOptions{MinAge: 24 * time.Hour, Batch: 100, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if !casBlobExists(t, s, shared.SHA256) {
		t.Fatal("blob still referenced by the surviving manifest was reclaimed")
	}

	if err := os.Remove(newPath); err != nil {
		t.Fatal(err)
	}
	if _, err := s.runCASGC(ctx, casGCOptions{MinAge: 24 * time.Hour, Batch: 100, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if casBlobExists(t, s, shared.SHA256) {
		t.Fatal("blob survived after its last manifest was removed")
	}
}

// TestPruneCacheManifestsPolicyDisable pins the operator escape hatch:
// negative dimensions disable pruning entirely.
func TestPruneCacheManifestsPolicyDisable(t *testing.T) {
	s := &Server{CacheManifestRetention: -1, MaxCacheManifestsPerRepo: -1, MaxCacheManifestBytesPerRepo: -1}
	p := s.cacheManifestPolicy()
	if cacheManifestPolicyActive(p) {
		t.Fatalf("policy %+v should be inactive", p)
	}
	s2 := &Server{}
	p2 := s2.cacheManifestPolicy()
	if p2.OlderThan != defaultCacheManifestRetention || p2.PerRepoMaxEntries != defaultMaxCacheManifestsPerRepo || p2.PerRepoMaxBytes != defaultCacheManifestBytesRepo {
		t.Fatalf("defaults not applied: %+v", p2)
	}
}
