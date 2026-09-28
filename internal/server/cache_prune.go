package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// Durable shared-cache manifests are a reference source for the CAS garbage
// collector: every unique (repo, trust_domain, logical_key) row pins its
// referenced blob. Without retention a repository that rotates its logical
// cache keys on every run accumulates manifests (and pinned blobs) forever,
// which is a persistent-storage exhaustion primitive for untrusted code.
// These bounds are per repository and oldest-first, so one repository can
// never evict another's accounting.
const (
	defaultCacheManifestRetention   = 30 * 24 * time.Hour
	defaultMaxCacheManifestsPerRepo = 4096
	defaultCacheManifestBytesRepo   = 64 << 30
	// cacheManifestPruneEvery is the durable-retention cadence inside the
	// 5-second Maintain tick.
	cacheManifestPruneEvery = 10 * time.Minute
)

// cacheManifestPolicy resolves the configured retention policy. Zero values
// select the built-in defaults; negative values disable that dimension.
func (s *Server) cacheManifestPolicy() storage.CacheManifestPrunePolicy {
	p := storage.CacheManifestPrunePolicy{
		OlderThan:         s.CacheManifestRetention,
		PerRepoMaxEntries: s.MaxCacheManifestsPerRepo,
		PerRepoMaxBytes:   s.MaxCacheManifestBytesPerRepo,
	}
	if p.OlderThan == 0 {
		p.OlderThan = defaultCacheManifestRetention
	}
	if p.PerRepoMaxEntries == 0 {
		p.PerRepoMaxEntries = defaultMaxCacheManifestsPerRepo
	}
	if p.PerRepoMaxBytes == 0 {
		p.PerRepoMaxBytes = defaultCacheManifestBytesRepo
	}
	if p.OlderThan < 0 {
		p.OlderThan = 0
	}
	if p.PerRepoMaxEntries < 0 {
		p.PerRepoMaxEntries = 0
	}
	if p.PerRepoMaxBytes < 0 {
		p.PerRepoMaxBytes = 0
	}
	return p
}

func cacheManifestPolicyActive(p storage.CacheManifestPrunePolicy) bool {
	return p.OlderThan > 0 || p.PerRepoMaxEntries > 0 || p.PerRepoMaxBytes > 0
}

// pruneCacheManifests runs one durable-retention pass: DB-mode rows through
// the store's ranked prune, fs-mode manifest files through the mirrored
// per-repo ranking. After manifests are gone the CAS collector no longer
// enumerates their digests, so the blobs become reclaimable unless another
// artifact, snapshot or manifest still references them.
func (s *Server) pruneCacheManifests(ctx context.Context, now time.Time) {
	policy := s.cacheManifestPolicy()
	if !cacheManifestPolicyActive(policy) {
		return
	}
	if s.DB != nil {
		pruner, ok := s.DB.(storage.CacheManifestPruner)
		if !ok {
			// A store without retention support cannot be pruned; the CAS
			// collector still fails closed on its references.
			return
		}
		res, err := pruner.PruneCacheManifests(ctx, policy)
		if err != nil {
			s.logError("cache manifests: prune failed", "error", err.Error())
			return
		}
		if res.Manifests > 0 {
			s.logInfo("cache manifests: pruned", "manifests", res.Manifests, "bytes", res.Bytes)
		}
		return
	}
	res, err := s.pruneCacheManifestFiles(ctx, policy, now)
	if err != nil {
		s.logError("cache manifests: file prune failed", "error", err.Error())
		return
	}
	if res.Manifests > 0 {
		s.logInfo("cache manifests: pruned files", "manifests", res.Manifests, "bytes", res.Bytes)
	}
}

// fsCacheManifest is one fs-mode manifest file with the fields retention
// needs. Repository/trust/size/created come from the signed payload (parsed
// without verification: retention only ever deletes a manifest, and deleting
// a tampered manifest cannot expose content that the CAS collector would
// keep only because of it).
type fsCacheManifest struct {
	path      string
	repo      string
	trust     string
	size      int64
	digest    string
	createdAt time.Time
}

// fsCacheQuotaKey is the fs-mode retention namespace: repository PLUS trust
// domain, mirroring the SQL partition. Untrusted (fork/PR) manifests share
// the base repository but must never evict the protected repository's
// trusted entries.
type fsCacheQuotaKey struct {
	Repo  string
	Trust string
}

// cachePruneBeforeRemove, when set (tests only), runs after a manifest has
// been ranked and before the freshness fence re-reads it. It lets a test
// deterministically replace the file to prove a stale ranking never deletes
// a refreshed manifest.
var cachePruneBeforeRemove func(path string)

// pruneCacheManifestFiles applies the same per-repo policy to the fs-mode
// manifest envelopes under <dataDir>/cache.
func (s *Server) pruneCacheManifestFiles(ctx context.Context, policy storage.CacheManifestPrunePolicy, now time.Time) (storage.CacheManifestPruneResult, error) {
	var res storage.CacheManifestPruneResult
	if s.store == nil {
		return res, nil
	}
	matches, err := filepath.Glob(filepath.Join(s.store.Root, "cache", "*.manifest.json"))
	if err != nil {
		return res, fmt.Errorf("scan cache manifests: %w", err)
	}
	byNamespace := map[fsCacheQuotaKey][]fsCacheManifest{}
	for _, path := range matches {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		man, err := cacheManifestFields(path)
		if err != nil {
			// An unreadable manifest cannot be ranked; leave it for the CAS
			// collector's fail-closed reference pass and retry next time.
			continue
		}
		created := man.CreatedAt
		if created.IsZero() {
			if fi, serr := os.Stat(path); serr == nil {
				created = fi.ModTime()
			}
		}
		key := fsCacheQuotaKey{Repo: man.Repository, Trust: man.TrustDomain}
		byNamespace[key] = append(byNamespace[key], fsCacheManifest{path: path, repo: man.Repository, trust: man.TrustDomain, size: man.BlobSize, digest: man.BlobSHA256, createdAt: created})
	}
	cutoff := time.Time{}
	if policy.OlderThan > 0 {
		cutoff = now.UTC().Add(-policy.OlderThan)
	}
	for _, recs := range byNamespace {
		sort.Slice(recs, func(i, j int) bool {
			if !recs[i].createdAt.Equal(recs[j].createdAt) {
				return recs[i].createdAt.After(recs[j].createdAt)
			}
			return recs[i].path > recs[j].path
		})
		var running int64
		for i, rec := range recs {
			drop := false
			if policy.OlderThan > 0 && rec.createdAt.Before(cutoff) {
				drop = true
			}
			if policy.PerRepoMaxEntries > 0 && i+1 > policy.PerRepoMaxEntries {
				drop = true
			}
			running += rec.size
			if policy.PerRepoMaxBytes > 0 && running > policy.PerRepoMaxBytes {
				drop = true
			}
			if !drop {
				continue
			}
			if cachePruneBeforeRemove != nil {
				cachePruneBeforeRemove(rec.path)
			}
			// Freshness fence: re-read immediately before removing and only
			// delete the exact version that was ranked. An upload that
			// atomically replaced the manifest between ranking and here
			// changes the digest/created stamp, so the refreshed entry is
			// left for the next pass instead of being deleted on stale
			// information.
			cur, cerr := cacheManifestFields(rec.path)
			if cerr != nil {
				continue
			}
			// Compare the SAME effective timestamp the ranking used: a
			// manifest without a CreatedAt stamp ranked by its file mtime,
			// so the fence must apply the identical fallback or it could
			// never delete such an entry.
			curCreated := cur.CreatedAt
			if curCreated.IsZero() {
				if fi, serr := os.Stat(rec.path); serr == nil {
					curCreated = fi.ModTime()
				}
			}
			if cur.BlobSHA256 != rec.digest || cur.BlobSize != rec.size || !curCreated.Equal(rec.createdAt) {
				continue
			}
			if rerr := os.Remove(rec.path); rerr != nil && !os.IsNotExist(rerr) {
				continue
			}
			res.Manifests++
			res.Bytes += rec.size
		}
	}
	return res, nil
}

// cacheManifestFields decodes one fs-mode manifest envelope into the full
// cache manifest (payload only, signature unverified; callers that serve or
// reference bytes verify through the normal paths).
func cacheManifestFields(path string) (cache.CacheManifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return cache.CacheManifest{}, fmt.Errorf("read cache manifest %s: %w", path, err)
	}
	var envelope struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return cache.CacheManifest{}, fmt.Errorf("decode cache manifest %s: %w", path, err)
	}
	if envelope.Payload == "" {
		return cache.CacheManifest{}, fmt.Errorf("cache manifest %s has no signed payload", path)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return cache.CacheManifest{}, fmt.Errorf("decode cache manifest payload %s: %w", path, err)
	}
	var manifest cache.CacheManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return cache.CacheManifest{}, fmt.Errorf("decode cache manifest statement %s: %w", path, err)
	}
	return manifest, nil
}
