package cache

import (
	"context"
	"os"
	"path/filepath"
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
	// Skipped counts entries whose identity changed between ranking and
	// eviction (a concurrent save refreshed the key) or whose eviction lost
	// the freshness fence; they are deliberately left for the next pass
	// rather than deleted on stale information.
	Skipped int
}

// localCacheEntry is one archive found in the store root.
type localCacheEntry struct {
	key     string
	size    int64
	modTime time.Time
}

// pruneBeforeEvictHook, when set (tests only), observes the path a pass is
// about to evict, after ranking and before the freshness fence. It lets a
// test deterministically replace the entry to prove stale rankings never
// delete a refreshed entry.
var pruneBeforeEvictHook func(path string)

// Prune evicts local cache entries until the policy holds: expired entries
// first, then the least-recently-used entries while the byte or entry caps
// are exceeded. Removal failures are counted and retried on the next pass;
// entries refreshed after ranking are skipped by the freshness fence. The
// archive and its digest sidecar are removed together so a partially evicted
// entry can only ever surface as a cache miss. The context is checked
// between entries so a shutdown (or a job deadline) stops the pass promptly.
func (s *Store) Prune(ctx context.Context) (PruneResult, error) {
	if s.Manager != nil {
		return s.Manager.Prune(ctx)
	}
	if !s.Retention.Active() {
		return PruneResult{}, nil
	}
	s.pruneMu.Lock()
	defer s.pruneMu.Unlock()
	return pruneLocalDir(ctx, s.Root, s.Retention)
}

// pruneLocalDir is the single implementation behind Store.Prune and
// Manager.Prune: age eviction first, then LRU eviction while a cap is
// exceeded, each eviction fenced against concurrent refreshes.
func pruneLocalDir(ctx context.Context, root string, policy RetentionPolicy) (PruneResult, error) {
	var res PruneResult
	entries, err := listLocalEntriesAt(root)
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
			evictLocalEntry(root, e, &res)
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
				evictLocalEntry(root, e, &res)
				continue
			}
		}
		total += e.size
	}
	return res, nil
}

// listLocalEntriesAt enumerates the valid archive entries in dir. Temp files
// (dot-prefixed), sidecars and foreign names are ignored.
func listLocalEntriesAt(dir string) ([]localCacheEntry, error) {
	d, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []localCacheEntry
	for _, de := range d {
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

// evictLocalEntry removes one entry (archive + digest sidecar) and reports
// whether it was actually removed. The freshness fence re-stats the archive
// after ranking: an entry whose size or mtime changed (a concurrent save
// published a new archive under the same key) is SKIPPED, never deleted on
// stale information, and a removal failure leaves the entry fully accounted
// for a later pass. The sidecar is best-effort because an orphan sidecar
// without an archive can only ever be read by a same-key save that
// overwrites it.
func evictLocalEntry(root string, e localCacheEntry, res *PruneResult) bool {
	archive := archivePathAt(root, e.key)
	if pruneBeforeEvictHook != nil {
		pruneBeforeEvictHook(archive)
	}
	fi, err := os.Stat(archive)
	if err != nil {
		if os.IsNotExist(err) {
			// Already gone (a concurrent eviction or refresh): count as
			// skipped, not failed; the next scan reflects reality.
			res.Skipped++
			return false
		}
		res.Failed++
		return false
	}
	if fi.Size() != e.size || !fi.ModTime().Equal(e.modTime) {
		res.Skipped++
		return false
	}
	if err := removeCacheFile(archive); err != nil && !os.IsNotExist(err) {
		res.Failed++
		return false
	}
	_ = os.Remove(stripChecksumPathAt(root, e.key))
	res.Entries++
	res.Bytes += e.size
	return true
}

func archivePathAt(root, key string) string {
	return filepath.Join(root, key+".tar.gz")
}

func stripChecksumPathAt(root, key string) string {
	return filepath.Join(root, key+".tar.gz.sha256")
}

// touchLocal marks an entry as recently used so age/LRU eviction prefers
// colder entries. It is best-effort: a failed touch never fails a restore.
func (s *Store) touchLocal(key string) {
	now := time.Now()
	_ = os.Chtimes(s.archivePath(key), now, now)
}
