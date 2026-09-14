package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// tempFileMaxAge is how long orphaned *.tmp files may survive in the store
// directories before GC removes them. Well above any upload lifetime.
const tempFileMaxAge = 24 * time.Hour

// GCStats reports what one garbage-collection pass removed.
type GCStats struct {
	ArtifactsRemoved int `json:"artifacts_removed"`
	TempFilesRemoved int `json:"temp_files_removed"`
}

// GC garbage-collects expired artifacts and orphaned temporary files. It is
// safe to call in both DB and memory modes: artifact expiry works on the
// in-memory records in memory mode, temp-file sweeping works on the
// filesystem store when one is attached, and stale deliveries are pruned
// in both. Container/Tart workspace cleanup is executor-owned and out of
// scope here.
func (s *Server) GC(ctx context.Context, now time.Time) GCStats {
	var stats GCStats
	s.mu.Lock()
	stats.ArtifactsRemoved = s.cleanupExpiredArtifactsLocked(now)
	s.pruneDeliveriesLocked(now)
	s.mu.Unlock()
	if s.store != nil {
		stats.TempFilesRemoved = sweepTempFiles(s.store.Root, now)
	}
	_ = ctx
	return stats
}

// pruneDeliveriesLocked drops webhook delivery dedupe records older than the
// cutoff so long-lived control planes do not accumulate stale ids. Delivery
// retries happen within minutes, so a day of retention is generous.
func (s *Server) pruneDeliveriesLocked(now time.Time) {
	cutoff := now.Add(-24 * time.Hour)
	for delivery, runID := range s.deliveries {
		run, ok := s.runs[runID]
		if !ok || run.CreatedAt.Before(cutoff) {
			delete(s.deliveries, delivery)
		}
	}
}

// sweepTempFiles removes *.tmp files under the artifacts/ and cache/
// directories older than tempFileMaxAge. It never touches anything else,
// so a misbehaving sweep cannot remove live blobs.
func sweepTempFiles(root string, now time.Time) int {
	if root == "" {
		return 0
	}
	removed := 0
	for _, sub := range []string{"artifacts", "cache"} {
		dir := filepath.Join(root, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".tmp") {
				continue
			}
			path := filepath.Join(dir, name)
			info, err := e.Info()
			if err != nil {
				info, err = os.Lstat(path)
			}
			if err != nil {
				continue
			}
			if info.ModTime().After(now.Add(-tempFileMaxAge)) {
				continue
			}
			if os.Remove(path) == nil {
				removed++
			}
		}
		// Artifact upload temp files live two levels deeper
		// (artifacts/<run>/<job>/.<id>.tmp); walk those too.
		if sub == "artifacts" {
			removed += sweepTempFilesRecursive(dir, 0, now)
		}
	}
	return removed
}

// sweepTempFilesRecursive descends at most two levels below dir looking for
// upload scratch files (".<id>.tmp" pattern used by uploadArtifact).
func sweepTempFilesRecursive(dir string, depth int, now time.Time) int {
	if depth > 2 {
		return 0
	}
	removed := 0
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if e.IsDir() {
			removed += sweepTempFilesRecursive(filepath.Join(dir, e.Name()), depth+1, now)
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".tmp") {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(now.Add(-tempFileMaxAge)) {
			continue
		}
		if os.Remove(path) == nil {
			removed++
		}
	}
	return removed
}
