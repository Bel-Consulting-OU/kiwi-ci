package server

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// tempFileMaxAge is how long orphaned *.tmp files may survive in the store
// directories before GC removes them. Well above any upload lifetime.
const tempFileMaxAge = 24 * time.Hour

// GCStats reports what one garbage-collection pass removed.
type GCStats struct {
	ArtifactsRemoved int `json:"artifacts_removed"`
	TempFilesRemoved int `json:"temp_files_removed"`
	// RunsRemoved counts fs-mode terminal runs pruned by the retention
	// policy together with their jobs, reports, snapshots and indexes.
	RunsRemoved int `json:"runs_removed"`
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
	// Retention runs BEFORE the delivery prune so a pruned run's delivery
	// dedupe records are visible to pruneDeliveriesLocked in the same pass.
	prunedRuns := s.pruneRunsLocked(now)
	stats.RunsRemoved = len(prunedRuns)
	if stats.RunsRemoved > 0 {
		// Bound state.json: persist the pruned set immediately instead of
		// waiting for the next unrelated mutation. A failure only degrades
		// readiness (the in-memory set is already pruned and the next tick
		// retries), so GC never fails the maintenance loop.
		if err := s.persistCheckedErrLocked("gc.retention"); err != nil {
			s.logError("retention persist failed", "error", err.Error())
		}
	}
	s.pruneDeliveriesLocked(now)
	if s.DB == nil {
		s.pruneJobLocksLocked()
	}
	s.mu.Unlock()
	if stats.RunsRemoved > 0 {
		// Reclaim the pruned runs' committed log batches too: their run rows
		// are gone, so the run-keyed log-batch reclamation hook would never
		// see them again. Done after unlocking (disk I/O) and is a no-op in
		// memory/DB mode.
		s.pruneLogBatchesForRuns(prunedRuns)
		// Quota consistency: the trailing-24h budget window is rebuilt from
		// the surviving jobs, so a pruned run can never keep contributing
		// cost/energy (nor can a surviving job be under-counted). The map is
		// snapshotted under the lock because rebuildUsageWindow re-locks.
		s.mu.Lock()
		jobs := make(map[string]model.Job, len(s.jobs))
		for id, j := range s.jobs {
			jobs[id] = j
		}
		s.mu.Unlock()
		s.rebuildUsageWindow(jobs)
	}
	// Pending SBOM/sigstore rows older than the retention window are
	// pruned here: the durable table in DB mode, the dev-mode mirror
	// otherwise. Pruning never deletes CAS blobs.
	s.pruneExpiredPendingSidecars(ctx, now)
	if s.store != nil {
		stats.TempFilesRemoved = sweepTempFiles(s.store.Root, now)
	}
	return stats
}

// pruneRunsLocked applies the fs-mode run retention policy and cascades the
// eviction to every derived record so a pruned run leaves no dangling
// dependents. DB mode retains through the SQL store and is untouched.
//
// Policy (documented at Server.RunRetention / MaxRetainedRuns):
//
//   - age: every TERMINAL run (success/failure/cancelled/skipped/blocked)
//     whose finish time is older than RunRetention is pruned. Active runs
//     (queued/running/etc.) are never pruned, so the retention policy cannot
//     drop work that is still in flight.
//   - count: when the total run count exceeds MaxRetainedRuns, the oldest
//     terminal runs are pruned first until the count is back within the
//     bound. If only active runs remain, the count may stay above the bound
//     until they finish; that is deliberate (never evict live work).
//
// Both bounds are independently optional (0 disables one). The eviction
// removes the run and its jobs plus the reports, snapshots, deployments,
// schedule occurrences and downstream-link indexes derived from them, so
// state.json stays bounded and no consumer observes a job without its run.
// It does NOT delete artifact records (those have their own expiry-driven
// retention) nor CAS blobs (shared content addresses).
func (s *Server) pruneRunsLocked(now time.Time) []string {
	if s.DB != nil || (s.RunRetention <= 0 && s.MaxRetainedRuns <= 0) {
		return nil
	}
	type runCandidate struct {
		id string
		at time.Time
	}
	candidates := make([]runCandidate, 0, len(s.runs))
	for id, run := range s.runs {
		if !run.Status.Terminal() {
			continue
		}
		at := run.CreatedAt
		if run.FinishedAt != nil {
			at = *run.FinishedAt
		}
		candidates = append(candidates, runCandidate{id: id, at: at})
	}
	if len(candidates) == 0 {
		return nil
	}
	// Oldest first; the id tiebreak keeps the choice deterministic.
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].at.Equal(candidates[j].at) {
			return candidates[i].at.Before(candidates[j].at)
		}
		return candidates[i].id < candidates[j].id
	})
	prunable := map[string]bool{}
	if s.RunRetention > 0 {
		cutoff := now.Add(-s.RunRetention)
		for _, c := range candidates {
			if c.at.Before(cutoff) {
				prunable[c.id] = true
			}
		}
	}
	if s.MaxRetainedRuns > 0 {
		remaining := len(s.runs) - len(prunable)
		for _, c := range candidates {
			if remaining <= s.MaxRetainedRuns {
				break
			}
			if prunable[c.id] {
				continue
			}
			prunable[c.id] = true
			remaining--
		}
	}
	if len(prunable) == 0 {
		return nil
	}
	// Jobs of pruned runs, and the job-ID set every index is filtered by.
	prunedJobs := map[string]bool{}
	for id, j := range s.jobs {
		if prunable[j.RunID] {
			delete(s.jobs, id)
			prunedJobs[id] = true
		}
	}
	for id := range prunable {
		delete(s.runs, id)
	}
	for id, rep := range s.reports {
		if prunable[rep.RunID] {
			delete(s.reports, id)
		}
	}
	for id, rec := range s.snapshots {
		if prunable[rec.RunID] {
			delete(s.snapshots, id)
		}
	}
	for id, d := range s.deployments {
		if prunable[d.RunID] || prunedJobs[d.JobID] {
			delete(s.deployments, id)
		}
	}
	completedRemoved := false
	for key, rec := range s.completions {
		if prunedJobs[rec.JobID] {
			delete(s.completions, key)
			delete(s.completionReceiptAt, key)
			completedRemoved = true
		}
	}
	if completedRemoved {
		s.markCompletionReceiptsChangedLocked()
	}
	for delivery, runID := range s.deliveries {
		if prunable[runID] {
			delete(s.deliveries, delivery)
		}
	}
	for key, links := range s.downstreamLinks {
		if prunedJobs[links.ParentJobID] {
			delete(s.downstreamLinks, key)
		}
	}
	for scheduleID, occ := range s.occurrences {
		for unix, runID := range occ {
			if prunable[runID] {
				delete(occ, unix)
			}
		}
		if len(occ) == 0 {
			delete(s.occurrences, scheduleID)
		}
	}
	for key := range s.orphanOccurrences {
		// Keys are scheduleID\x00unix\x00runID; drop claims of pruned runs.
		if i := strings.LastIndexByte(key, '\x00'); i >= 0 && prunable[key[i+1:]] {
			delete(s.orphanOccurrences, key)
		}
	}
	s.auditLocked("run.retained_pruned", "scheduler", "", "", "fs-mode run retention pruned terminal runs",
		map[string]string{"runs": strconv.Itoa(len(prunable))})
	ids := make([]string, 0, len(prunable))
	for id := range prunable {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// pruneJobLocksLocked drops the per-job upload mutexes for jobs that no
// longer exist, so the lock map stays bounded over a long-lived process.
func (s *Server) pruneJobLocksLocked() {
	for id := range s.jobLocks {
		if _, ok := s.jobs[id]; !ok {
			delete(s.jobLocks, id)
		}
	}
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
