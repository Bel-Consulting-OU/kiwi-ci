package cache

import (
	"context"
	"os"
	"sort"
	"strings"
	"time"
)

// RetentionPolicy bounds the WHOLE local cache tree (every entry), distinct
// from MaxCacheBytes which bounds ONE archive. Without it, a pipeline that
// derives a fresh logical key on every run (a trivial pattern) can accumulate
// 8 GiB archives forever: the per-entry cap is not an aggregate host-disk
// bound, and cache archives live outside the job workspace quota. Zero fields
// disable that dimension; a zero policy preserves the historical "no
// aggregate bound" behavior for direct local-CLI stores, while distributed
// runners install a concrete policy (see runner.Config).
type RetentionPolicy struct {
	// MaxBytes bounds the sum of archive sizes. The newest entry is always
	// kept even when it alone exceeds the bound (a single archive cannot be
	// split), so the effective invariant is "sum <= MaxBytes, always, and
	// sum <= MaxBytes + newest-entry otherwise".
	MaxBytes int64
	// MaxEntries bounds the number of stored archives.
	MaxEntries int
	// MaxAge evicts entries whose last save/restore is older than this,
	// regardless of the caps.
	MaxAge time.Duration
}

// Active reports whether any dimension is configured.
func (p RetentionPolicy) Active() bool {
	return p.MaxBytes > 0 || p.MaxEntries > 0 || p.MaxAge > 0
}

// PruneResult reports one pruning pass.
type PruneResult struct {
	// Entries and Bytes are the successfully removed archive count/size.
	Entries int
	Bytes   int64
	// Failed counts entries that could not be removed; they stay in the tree
	// and remain accounted by the next pass (a transient EBUSY/EPERM never
	// silently frees cache capacity).
	Failed int
}

// localCacheEntry is one archive found in the store root.
type localCacheEntry struct {
	key     string
	size    int64
	modTime time.Time
}

// Prune evicts local cache entries until the policy holds: expired entries
// first, then the least-recently-used entries while the byte or entry caps
// are exceeded. Removal failures are counted and retried on the next pass;
// the archive and its digest sidecar are removed together so a partially
// evicted entry can only ever surface as a cache miss. The context is
// checked between entries so a shutdown stops the pass promptly.
func (s *Store) Prune(ctx context.Context) (PruneResult, error) {
	var res PruneResult
	policy := s.Retention
	if !policy.Active() {
		return res, nil
	}
	s.pruneMu.Lock()
	defer s.pruneMu.Unlock()
	entries, err := s.listLocalEntries()
	if err != nil {
		return res, err
	}
	now := time.Now()
	kept := entries[:0]
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if policy.MaxAge > 0 && now.Sub(e.modTime) > policy.MaxAge {
			s.evictLocal(e, &res)
			continue
		}
		kept = append(kept, e)
	}
	// Keep the most recently used entries: sort newest-first and evict from
	// the tail while a cap is exceeded. The newest entry is always kept even
	// if it alone exceeds the byte cap.
	sort.Slice(kept, func(i, j int) bool { return kept[i].modTime.After(kept[j].modTime) })
	var total int64
	for i, e := range kept {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if i > 0 {
			overBytes := policy.MaxBytes > 0 && total+e.size > policy.MaxBytes
			overEntries := policy.MaxEntries > 0 && i > policy.MaxEntries-1
			if overBytes || overEntries {
				s.evictLocal(e, &res)
				continue
			}
		}
		total += e.size
	}
	return res, nil
}

// listLocalEntries enumerates the valid archive entries in the store root.
// Temp files (dot-prefixed), sidecars and foreign names are ignored.
func (s *Store) listLocalEntries() ([]localCacheEntry, error) {
	dir, err := os.ReadDir(s.Root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []localCacheEntry
	for _, de := range dir {
		name := de.Name()
		if de.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".tar.gz") {
			continue
		}
		key := strings.TrimSuffix(name, ".tar.gz")
		if !validKey(key) {
			continue
		}
		fi, ierr := de.Info()
		if ierr != nil {
			continue
		}
		out = append(out, localCacheEntry{key: key, size: fi.Size(), modTime: fi.ModTime()})
	}
	return out, nil
}

// evictLocal removes one entry (archive + digest sidecar). A failed archive
// removal leaves the entry fully accounted for a later pass; the sidecar is
// best-effort because an orphan sidecar without an archive can only ever be
// read by a same-key save that overwrites it.
func (s *Store) evictLocal(e localCacheEntry, res *PruneResult) {
	if err := removeCacheFile(s.archivePath(e.key)); err != nil && !os.IsNotExist(err) {
		res.Failed++
		return
	}
	_ = os.Remove(s.stripChecksumPath(e.key))
	res.Entries++
	res.Bytes += e.size
}

// touchLocal marks an entry as recently used so age/LRU eviction prefers
// colder entries. It is best-effort: a failed touch never fails a restore.
func (s *Store) touchLocal(key string) {
	now := time.Now()
	_ = os.Chtimes(s.archivePath(key), now, now)
}
