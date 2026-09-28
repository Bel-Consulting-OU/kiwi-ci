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
	// PerRepoMaxBytes bounds each repository's referenced blob bytes
	// (newest manifests counted first; once the running sum exceeds the
	// bound, that manifest and every older one are evicted).
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
// policy, per repository. Only manifests that still reference a blob
// (blob_sha256 non-empty) participate, mirroring the CAS reference
// enumeration; the deletion is a single statement, so an interrupted pass
// either evicts its ranked set or nothing.
func (s *PostgresStore) PruneCacheManifests(ctx context.Context, policy CacheManifestPrunePolicy) (CacheManifestPruneResult, error) {
	var res CacheManifestPruneResult
	if !prunePolicyActive(policy) {
		return res, nil
	}
	cutoff := time.Time{}
	if policy.OlderThan > 0 {
		cutoff = time.Now().UTC().Add(-policy.OlderThan)
	}
	rows, err := s.pool.Query(ctx, `
WITH ranked AS (
    SELECT repo, trust_domain, logical_key, blob_size, created_at,
           row_number() OVER (PARTITION BY repo ORDER BY created_at DESC, trust_domain DESC, logical_key DESC) AS rn,
           sum(blob_size) OVER (PARTITION BY repo ORDER BY created_at DESC, trust_domain DESC, logical_key DESC ROWS UNBOUNDED PRECEDING) AS running_bytes
    FROM cache_manifests
    WHERE blob_sha256 IS NOT NULL AND blob_sha256 <> ''
),
victims AS (
    SELECT repo, trust_domain, logical_key FROM ranked
    WHERE ($1::boolean AND created_at < $2)
       OR ($3::bigint > 0 AND rn > $3)
       OR ($4::bigint > 0 AND running_bytes > $4)
)
DELETE FROM cache_manifests
WHERE (repo, trust_domain, logical_key) IN (SELECT repo, trust_domain, logical_key FROM victims)
RETURNING blob_size`,
		policy.OlderThan > 0, cutoff, int64(policy.PerRepoMaxEntries), policy.PerRepoMaxBytes)
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

// PruneCacheManifests is the in-memory mirror of the SQL ranking: group by
// repository, order newest-first with a deterministic tiebreak, evict expired
// entries and everything beyond the per-repo caps.
func (m *memStore) PruneCacheManifests(ctx context.Context, policy CacheManifestPrunePolicy) (CacheManifestPruneResult, error) {
	var res CacheManifestPruneResult
	if !prunePolicyActive(policy) {
		return res, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	byRepo := map[string][]CacheManifestRecord{}
	for _, rec := range m.cacheMans {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if rec.BlobSHA256 == "" {
			continue
		}
		byRepo[rec.Repo] = append(byRepo[rec.Repo], rec)
	}
	cutoff := time.Time{}
	if policy.OlderThan > 0 {
		cutoff = time.Now().UTC().Add(-policy.OlderThan)
	}
	for repo, recs := range byRepo {
		sort.Slice(recs, func(i, j int) bool {
			if !recs[i].CreatedAt.Equal(recs[j].CreatedAt) {
				return recs[i].CreatedAt.After(recs[j].CreatedAt)
			}
			if recs[i].TrustDomain != recs[j].TrustDomain {
				return recs[i].TrustDomain > recs[j].TrustDomain
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
			delete(m.cacheMans, cacheManifestKey(repo, rec.TrustDomain, rec.LogicalKey))
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
