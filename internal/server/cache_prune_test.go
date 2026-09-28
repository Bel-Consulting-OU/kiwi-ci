package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// TestPruneCacheManifestsTrustDomainIsolationFS pins the fs-mode namespace
// partition: a trusted manifest at the trusted namespace's cap survives an
// untrusted (fork PR) flood in the same repository.
func TestPruneCacheManifestsTrustDomainIsolationFS(t *testing.T) {
	s, _ := casGCTestServer(t)
	s.CacheManifestRetention = -1
	s.MaxCacheManifestsPerRepo = 1
	s.MaxCacheManifestBytesPerRepo = -1
	ctx := context.Background()

	trustedPath := writeFSCacheManifestForTest(t, s, "repo", "trusted", "k-trusted", strings.Repeat("a", 64), 10, time.Now().Add(-2*time.Hour))
	for i := 0; i < 5; i++ {
		writeFSCacheManifestForTest(t, s, "repo", "untrusted", fmt.Sprintf("k-u%d", i), strings.Repeat(fmt.Sprint(i), 64), 10, time.Now().Add(time.Duration(-i)*time.Minute))
	}
	s.pruneCacheManifests(ctx, time.Now())
	if _, err := os.Stat(trustedPath); err != nil {
		t.Fatalf("trusted manifest was evicted by the untrusted flood: %v", err)
	}
}

// TestPruneDoesNotDeleteConcurrentManifestRefreshFS is the stale-ranking
// regression for fs mode: the freshness fence re-reads the manifest
// immediately before removal, so a file replaced between ranking and
// eviction survives with its new identity.
func TestPruneDoesNotDeleteConcurrentManifestRefreshFS(t *testing.T) {
	s, _ := casGCTestServer(t)
	s.CacheManifestRetention = -1
	s.MaxCacheManifestsPerRepo = 1
	s.MaxCacheManifestBytesPerRepo = -1
	ctx := context.Background()

	oldPath := writeFSCacheManifestForTest(t, s, "repo", "t", "k-old", strings.Repeat("a", 64), 10, time.Now().Add(-2*time.Hour))
	writeFSCacheManifestForTest(t, s, "repo", "t", "k-new", strings.Repeat("b", 64), 10, time.Now())

	orig := cachePruneBeforeRemove
	refreshed := false
	cachePruneBeforeRemove = func(path string) {
		if refreshed || path != oldPath {
			return
		}
		refreshed = true
		// Simulate a concurrent upload atomically replacing the manifest
		// with a fresh digest/created stamp between ranking and deletion.
		writeFSCacheManifestForTest(t, s, "repo", "t", "k-old", strings.Repeat("c", 64), 11, time.Now())
	}
	t.Cleanup(func() { cachePruneBeforeRemove = orig })

	s.pruneCacheManifests(ctx, time.Now())
	if !refreshed {
		t.Fatal("hook never ran; the test did not exercise the race window")
	}
	man, err := cacheManifestFields(oldPath)
	if err != nil {
		t.Fatalf("refreshed manifest was deleted: %v", err)
	}
	if man.BlobSHA256 != strings.Repeat("c", 64) {
		t.Fatalf("refreshed manifest has stale content: %q", man.BlobSHA256)
	}
}

// TestPruneCacheManifestsWithoutStoreIsNoop pins the early return: a server
// with neither a DB nor an fs store (or an inactive policy) does nothing.
func TestPruneCacheManifestsWithoutStoreIsNoop(t *testing.T) {
	s := &Server{}
	s.pruneCacheManifests(context.Background(), time.Now())
	s2 := &Server{CacheManifestRetention: -1, MaxCacheManifestsPerRepo: -1, MaxCacheManifestBytesPerRepo: -1}
	s2.pruneCacheManifests(context.Background(), time.Now())
}

// TestCacheManifestFieldsErrorBranches pins the parser's fail-closed error
// surface used by the fs-mode reference pass and retention fence.
func TestCacheManifestFieldsErrorBranches(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		body string
	}{
		{"empty payload", `{"payload":""}`},
		{"bad json", `not-json`},
		{"bad base64", `{"payload":"###"}`},
		{"bad statement", `{"payload":"bm90LWpzb24="}`},
	}
	for _, tc := range cases {
		path := filepath.Join(dir, tc.name+".manifest.json")
		if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cacheManifestFields(path); err == nil {
			t.Fatalf("%s decoded successfully", tc.name)
		}
	}
	if _, err := cacheManifestFields(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing manifest decoded successfully")
	}
}

// TestPruneCacheManifestFilesSkipsUnreadableAndUsesFileMtime pins the two
// fs-mode fallbacks: an unreadable/corrupt manifest is skipped rather than
// failing the pass, and a zero CreatedAt stamp falls back to the file mtime
// for ranking.
func TestPruneCacheManifestFilesSkipsUnreadableAndUsesFileMtime(t *testing.T) {
	s, _ := casGCTestServer(t)
	s.CacheManifestRetention = -1
	s.MaxCacheManifestsPerRepo = 1
	s.MaxCacheManifestBytesPerRepo = -1
	ctx := context.Background()

	// Corrupt manifest: skipped, never fatal.
	corrupt := filepath.Join(s.store.Root, "cache", "corrupt.manifest.json")
	if err := os.MkdirAll(filepath.Dir(corrupt), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corrupt, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Zero CreatedAt: ranked by file mtime (old), so it is the victim.
	zeroPath := writeFSCacheManifestForTest(t, s, "repo", "t", "k-zero", strings.Repeat("a", 64), 10, time.Time{})
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(zeroPath, old, old); err != nil {
		t.Fatal(err)
	}
	writeFSCacheManifestForTest(t, s, "repo", "t", "k-new", strings.Repeat("b", 64), 10, time.Now())

	res, err := s.pruneCacheManifestFiles(ctx, s.cacheManifestPolicy(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifests != 1 {
		t.Fatalf("prune = %+v, want the zero-created entry evicted via file mtime", res)
	}
	if _, err := os.Stat(zeroPath); !os.IsNotExist(err) {
		t.Fatalf("zero-created entry survived (err=%v)", err)
	}
	if _, err := os.Stat(corrupt); err != nil {
		t.Fatalf("corrupt manifest must be left in place: %v", err)
	}
}
