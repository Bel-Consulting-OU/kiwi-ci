package storage

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// CacheManifestPrunePolicy bounds the durable shared-cache manifests. A zero
// dimension is disabled; the server resolves its built-in defaults before
// calling. Eviction is PER REPOSITORY and oldest-first, so one repository can
// never consume another repository's accounting, and an entry that another
// live manifest still references is never touched.
type CacheManifestPrunePolicy struct {
	// OlderThan evicts manifests created earlier than now-OlderThan.
	OlderThan time.Duration
	// PerRepoMaxEntries bounds each repository's manifest count.
	PerRepoMaxEntries int
	// PerRepoMaxBytes bounds each namespace's LOGICAL referenced bytes: the
	// sum of blob_size across the namespace's manifests, newest first, with
	// no digest deduplication (fifty keys pointing at one digest count that
	// blob fifty times). This is deliberately conservative: it is an upper
	// bound on the physical CAS bytes the namespace can pin, and the
	// per-namespace entry cap already bounds logical-key fanout. It is not a
	// physical deduplicated storage measurement.
	PerRepoMaxBytes int64
}

// CacheManifestPruneResult reports one eviction pass.
type CacheManifestPruneResult struct {
	// Manifests and Bytes are the evicted manifest count and their
	// referenced blob bytes. After the manifests are gone, the CAS
	// collector's reference enumeration no longer sees those digests, so the
	// blobs become reclaimable once no other manifest/artifact/snapshot
	// names them.
	Manifests int
	Bytes     int64
}

// CacheManifestPruner is the durable-retention half of the cache-manifest
// contract. Without it a hostile or merely busy repository can pin shared CAS
// storage forever by rotating its logical cache keys: every unique key leaves
// one manifest row that the CAS collector treats as a live reference.
type CacheManifestPruner interface {
	PruneCacheManifests(ctx context.Context, policy CacheManifestPrunePolicy) (CacheManifestPruneResult, error)
}

var _ CacheManifestPruner = (*PostgresStore)(nil)
var _ CacheManifestPruner = (*memStore)(nil)

// prunePolicyActive reports whether the policy can evict anything.
func prunePolicyActive(p CacheManifestPrunePolicy) bool {
	return p.OlderThan > 0 || p.PerRepoMaxEntries > 0 || p.PerRepoMaxBytes > 0
}

// PruneCacheManifests deletes durable cache-manifest rows that exceed the
// policy, per (repository, trust domain) namespace. The trust domain
// partition is deliberate: a fork PR runs under the base repository with
// trust_domain=untrusted and may produce many manifests, and it must never
// evict the protected repository's trusted entries (a cross-trust cache
// availability DoS). Only manifests that still reference a blob
// (blob_sha256 non-empty) participate, mirroring the CAS reference
// enumeration.
//
// The age cutoff is computed by the DATABASE (`clock_timestamp()` minus the
// policy interval), never by the pruning replica's application clock: with
// created_at also database-stamped, retention is decided entirely in the
// database clock domain, so a skewed replica can neither evict a fresh entry
// nor keep an old one.
//
// The victim identity carries created_at AND blob_sha256, and the DELETE
// re-matches on them: a concurrent upsert that refreshed a ranked row under
// a row lock is re-evaluated against the new version under READ COMMITTED
// and no longer matches, so a freshly refreshed manifest can never be
// deleted on a stale ranking.
func (s *PostgresStore) PruneCacheManifests(ctx context.Context, policy CacheManifestPrunePolicy) (CacheManifestPruneResult, error) {
	var res CacheManifestPruneResult
	if !prunePolicyActive(policy) {
		return res, nil
	}
	rows, err := s.pool.Query(ctx, `
WITH ranked AS (
    SELECT repo, trust_domain, logical_key, blob_sha256, blob_size, created_at,
           row_number() OVER (PARTITION BY repo, trust_domain ORDER BY created_at DESC, logical_key DESC) AS rn,
           sum(blob_size) OVER (PARTITION BY repo, trust_domain ORDER BY created_at DESC, logical_key DESC ROWS UNBOUNDED PRECEDING) AS running_bytes
    FROM cache_manifests
    WHERE blob_sha256 IS NOT NULL AND blob_sha256 <> ''
),
victims AS (
    SELECT repo, trust_domain, logical_key, blob_sha256, created_at FROM ranked
    WHERE ($1::boolean AND created_at < clock_timestamp() - make_interval(secs => $2::double precision))
       OR ($3::bigint > 0 AND rn > $3)
       OR ($4::bigint > 0 AND running_bytes > $4)
)
DELETE FROM cache_manifests c
USING victims v
WHERE c.repo = v.repo
  AND c.trust_domain = v.trust_domain
  AND c.logical_key = v.logical_key
  AND c.created_at = v.created_at
  AND c.blob_sha256 = v.blob_sha256
RETURNING c.blob_size`,
		policy.OlderThan > 0, policy.OlderThan.Seconds(), int64(policy.PerRepoMaxEntries), policy.PerRepoMaxBytes)
	if err != nil {
		return res, fmt.Errorf("storage: prune cache manifests: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var size int64
		if err := rows.Scan(&size); err != nil {
			return res, err
		}
		res.Manifests++
		res.Bytes += size
	}
	return res, rows.Err()
}

// cacheQuotaKey is the durable retention namespace: repository PLUS trust
// domain. Untrusted (fork/PR) runs share the base repository but must never
// evict the protected repository's trusted entries.
type cacheQuotaKey struct {
	Repo  string
	Trust string
}

// PruneCacheManifests is the in-memory mirror of the SQL ranking: group by
// (repository, trust domain), order newest-first with a deterministic
// tiebreak, evict expired entries and everything beyond the per-namespace
// caps. The delete re-checks the ranked identity so a concurrent refresh
// (new CreatedAt/blob) is never deleted on stale information.
func (m *memStore) PruneCacheManifests(ctx context.Context, policy CacheManifestPrunePolicy) (CacheManifestPruneResult, error) {
	var res CacheManifestPruneResult
	if !prunePolicyActive(policy) {
		return res, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	byNamespace := map[cacheQuotaKey][]CacheManifestRecord{}
	for _, rec := range m.cacheMans {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if rec.BlobSHA256 == "" {
			continue
		}
		key := cacheQuotaKey{Repo: rec.Repo, Trust: rec.TrustDomain}
		byNamespace[key] = append(byNamespace[key], rec)
	}
	cutoff := time.Time{}
	if policy.OlderThan > 0 {
		cutoff = time.Now().UTC().Add(-policy.OlderThan)
	}
	for key, recs := range byNamespace {
		sort.Slice(recs, func(i, j int) bool {
			if !recs[i].CreatedAt.Equal(recs[j].CreatedAt) {
				return recs[i].CreatedAt.After(recs[j].CreatedAt)
			}
			return recs[i].LogicalKey > recs[j].LogicalKey
		})
		var running int64
		for i, rec := range recs {
			drop := false
			if policy.OlderThan > 0 && rec.CreatedAt.Before(cutoff) {
				drop = true
			}
			if policy.PerRepoMaxEntries > 0 && i+1 > policy.PerRepoMaxEntries {
				drop = true
			}
			running += rec.BlobSize
			if policy.PerRepoMaxBytes > 0 && running > policy.PerRepoMaxBytes {
				drop = true
			}
			if !drop {
				continue
			}
			mapKey := cacheManifestKey(key.Repo, key.Trust, rec.LogicalKey)
			// Freshness fence: only delete the exact version that was
			// ranked. memStore replaces records wholesale under the same
			// lock, so a mismatch here can only come from a refresh between
			// grouping and this point (kept possible by future lock
			// refactors).
			cur, ok := m.cacheMans[mapKey]
			if !ok || !cur.CreatedAt.Equal(rec.CreatedAt) || cur.BlobSHA256 != rec.BlobSHA256 {
				continue
			}
			delete(m.cacheMans, mapKey)
			res.Manifests++
			res.Bytes += rec.BlobSize
		}
	}
	return res, nil
}

// cacheManifestKey is the memStore map key for one manifest.
func cacheManifestKey(repo, trustDomain, logicalKey string) string {
	return repo + "\x00" + trustDomain + "\x00" + logicalKey
}
