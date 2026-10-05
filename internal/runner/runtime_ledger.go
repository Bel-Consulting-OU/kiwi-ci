package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

// atomicWriteFile is the durable-write seam: tests inject failures at each
// ledger publication point to prove no externally-visible resource is
// created without a durable ownership record.
var atomicWriteFile = fsutil.AtomicWriteFile

// removeArtifactScratch is the artifact-scratch removal seam: a failed
// removal must raise recovery debt and retain the ledger entry.
var removeArtifactScratch = os.RemoveAll

// removeLedgerPath is the ledger-reclaim removal seam (workspaces and
// artifact scratch): tests force failures to prove the entry is retained.
var removeLedgerPath = os.RemoveAll

// runtimeLedgerEntry is the durable ownership record for one job's
// externally-visible host state. It is written BEFORE the workspace becomes
// visible to the job so a hard crash leaves enough information for the next
// incarnation to reclaim what the deferred cleanup could not. Every entry
// carries the STABLE runner identity that owns it, so a different runner
// sharing the same WorkDir can never mistake it for its own predecessor.
type runtimeLedgerEntry struct {
	// ID is the ledger entry id (the file name).
	ID string `json:"id"`
	// RunnerID is the stable runner identity (never the volatile instance).
	RunnerID  string   `json:"runner_id"`
	Instance  string   `json:"instance"`
	JobID     string   `json:"job"`
	Workspace string   `json:"workspace,omitempty"`
	Artifacts []string `json:"artifacts,omitempty"`
	// XFS is the installed project-quota assignment: after a hard crash the
	// next incarnation removes the assignment and clears the hard limit
	// before retiring the entry, so crashed jobs cannot leak project IDs.
	XFS *executor.WorkspaceQuotaAssignment `json:"xfs,omitempty"`
	// Cgroup is the job-scoped parent cgroup created for the declared
	// resources envelope; reclaimed after a crash once the containers are
	// proven gone.
	Cgroup    string    `json:"cgroup,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// runtimeLedgerDir returns the ledger directory for THIS runner. The
// namespace is keyed by the hash of the stable runner id: runners sharing a
// WorkDir (the default configuration uses os.TempDir()) each get an isolated
// directory, so reconciliation can never read, reclaim or delete another
// runner's live state. The hash keeps ids that are not filesystem-safe out
// of the path.
func (r *Runner) runtimeLedgerDir() string {
	sum := sha256.Sum256([]byte(r.ID))
	// Mirror the documented CLI default: an unset WorkDir means the system
	// temp dir, never the process CWD (a relative ledger would pollute
	// whatever directory the runner happens to start in).
	workDir := strings.TrimSpace(r.Cfg.WorkDir)
	if workDir == "" {
		workDir = os.TempDir()
	}
	return filepath.Join(workDir, ".kiwi-runtime", hex.EncodeToString(sum[:]), "ledger")
}

// ledgerAdd records one job's runtime ownership atomically. A failure is
// FATAL for the job: the caller must not create the workspace-visible state
// this entry exists to make reclaimable.
func (r *Runner) ledgerAdd(entry runtimeLedgerEntry) (string, error) {
	if strings.TrimSpace(r.ID) == "" {
		return "", fmt.Errorf("crash-recovery ledger: runner identity is empty")
	}
	entry.RunnerID = r.ID
	entry.ID = newRunnerInstanceID()
	entry.CreatedAt = time.Now().UTC()
	b, err := json.Marshal(entry)
	if err != nil {
		return "", fmt.Errorf("crash-recovery ledger: encode entry: %w", err)
	}
	dir := r.runtimeLedgerDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("crash-recovery ledger: create %s: %w", dir, err)
	}
	if err := atomicWriteFile(filepath.Join(dir, entry.ID+".json"), b, 0o600); err != nil {
		return "", fmt.Errorf("crash-recovery ledger: write entry: %w", err)
	}
	return entry.ID, nil
}

// ledgerUpdate is the strict read-modify-write used by every follow-up
// record. Every failure is returned so a caller can refuse to let the
// corresponding external state exist.
func (r *Runner) ledgerUpdate(id string, mutate func(*runtimeLedgerEntry)) error {
	if id == "" {
		return fmt.Errorf("crash-recovery ledger: missing entry id")
	}
	path := filepath.Join(r.runtimeLedgerDir(), id+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("crash-recovery ledger: read %s: %w", id, err)
	}
	var entry runtimeLedgerEntry
	if err := json.Unmarshal(b, &entry); err != nil {
		return fmt.Errorf("crash-recovery ledger: decode %s: %w", id, err)
	}
	mutate(&entry)
	updated, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("crash-recovery ledger: encode %s: %w", id, err)
	}
	if err := atomicWriteFile(path, updated, 0o600); err != nil {
		return fmt.Errorf("crash-recovery ledger: update %s: %w", id, err)
	}
	return nil
}

// ledgerAddArtifacts appends one artifact scratch directory to an existing
// entry so a crash after its creation still records it. The caller creates
// the scratch directory only after this returns nil.
func (r *Runner) ledgerAddArtifacts(id, dir string) error {
	if dir == "" {
		return nil
	}
	return r.ledgerUpdate(id, func(entry *runtimeLedgerEntry) {
		for _, existing := range entry.Artifacts {
			if existing == dir {
				return
			}
		}
		entry.Artifacts = append(entry.Artifacts, dir)
	})
}

// ledgerSetXFS records the installed XFS project quota on an existing entry
// so a crash after this point is reclaimable by the next incarnation. It runs
// BEFORE the quota command: a nil return is the precondition for the
// assignment to become externally visible.
func (r *Runner) ledgerSetXFS(id string, assignment *executor.WorkspaceQuotaAssignment) error {
	if assignment == nil {
		return nil
	}
	return r.ledgerUpdate(id, func(entry *runtimeLedgerEntry) {
		entry.XFS = assignment
	})
}

// ledgerSetCgroup records the job-scoped cgroup on an existing entry before
// the caller allows the cgroup to host any workload.
func (r *Runner) ledgerSetCgroup(id, cgroup string) error {
	if cgroup == "" {
		return nil
	}
	return r.ledgerUpdate(id, func(entry *runtimeLedgerEntry) {
		entry.Cgroup = cgroup
	})
}

// ledgerRemove retires a completed job's entry. It is deliberately
// best-effort: a failed removal leaves the entry for the next incarnation's
// reclaim, which is safe because every reclaim step is idempotent.
func (r *Runner) ledgerRemove(id string) {
	if id == "" {
		return
	}
	_ = os.Remove(filepath.Join(r.runtimeLedgerDir(), id+".json"))
}

// reclaimWorkspaceQuota is the XFS-reclaim seam (tests substitute a fake).
var reclaimWorkspaceQuota = executor.ReclaimWorkspaceQuota

// reclaimJobCgroup is the cgroup-reclaim seam.
var reclaimJobCgroup = executor.ReclaimJobCgroup

// ledgerReconcileResult reports one startup reconciliation pass over THIS
// runner's own namespace.
type ledgerReconcileResult struct {
	Reclaimed int
	Pending   int
	Corrupt   int
	Errors    []error
}

// reconcileRuntimeLedger reclaims host state recorded by PREVIOUS
// incarnations of THIS runner after runtime reconciliation proved the
// workloads gone. Only entries whose recorded paths look runner-created (a
// kiwi- basename) are removed; an entry whose paths cannot be deleted stays
// for a later retry.
//
// Fail-closed contract: an unreadable entry, a foreign runner id inside this
// runner's namespace, or a reclaim that cannot be proven is unresolved
// recovery debt and is returned as an error so the caller refuses to lease
// new work. Entries from OTHER runners are unreachable by construction (the
// directory is per-runner), and legacy unscoped entries in the old shared
// directory are never adopted: they stay for explicit operator cleanup
// instead of being mistaken for this runner's crashed state.
func (r *Runner) reconcileRuntimeLedger(runInstanceID string) (ledgerReconcileResult, error) {
	var res ledgerReconcileResult
	dir := r.runtimeLedgerDir()
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("crash-recovery ledger: stat %s: %w", dir, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !fileOwnedByEUID(info) {
		return res, fmt.Errorf("crash-recovery ledger: refusing to reclaim through untrusted ledger directory %s", dir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		// We created this directory; tighten it rather than trust it.
		if chmodErr := os.Chmod(dir, 0o700); chmodErr != nil {
			return res, fmt.Errorf("crash-recovery ledger: tighten %s: %w", dir, chmodErr)
		}
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return res, fmt.Errorf("crash-recovery ledger: read %s: %w", dir, err)
	}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, f.Name())
		entryInfo, err := os.Lstat(path)
		if err != nil || !entryInfo.Mode().IsRegular() || !fileOwnedByEUID(entryInfo) || entryInfo.Mode().Perm()&0o022 != 0 {
			res.Corrupt++
			res.Errors = append(res.Errors, fmt.Errorf("ledger entry %s is not a trusted regular file", f.Name()))
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			res.Corrupt++
			res.Errors = append(res.Errors, fmt.Errorf("ledger entry %s unreadable: %w", f.Name(), err))
			continue
		}
		var entry runtimeLedgerEntry
		if err := json.Unmarshal(b, &entry); err != nil {
			res.Corrupt++
			res.Errors = append(res.Errors, fmt.Errorf("ledger entry %s undecodable: %w", f.Name(), err))
			continue
		}
		if entry.RunnerID != r.ID {
			// A foreign (or pre-namespace) identity inside this runner's
			// directory: never reclaim it, and never lease past it blindly.
			res.Corrupt++
			res.Errors = append(res.Errors, fmt.Errorf("ledger entry %s belongs to runner %q, not %q", f.Name(), entry.RunnerID, r.ID))
			continue
		}
		if entry.Instance == runInstanceID {
			continue
		}
		if entry.Cgroup != "" {
			// The containers were proven gone by runtime reconciliation, so
			// the job-scoped parent cgroup should be empty; a failure keeps
			// the entry retryable.
			if err := reclaimJobCgroup(entry.Cgroup); err != nil {
				res.Pending++
				res.Errors = append(res.Errors, fmt.Errorf("reclaim cgroup %s (%s): %w", entry.Cgroup, f.Name(), err))
				continue
			}
		}
		if entry.XFS != nil {
			// Remove the QUOTA before the workspace it bounds; if the
			// filesystem cleanup cannot be proven, keep the entry (and the
			// workspace) so a later run retries instead of leaking the
			// project ID and its hard limit.
			if err := reclaimWorkspaceQuota(*entry.XFS); err != nil {
				res.Pending++
				res.Errors = append(res.Errors, fmt.Errorf("reclaim workspace quota (%s): %w", f.Name(), err))
				continue
			}
		}
		ok := true
		paths := append([]string{entry.Workspace}, entry.Artifacts...)
		for _, p := range paths {
			if !ledgerPathIsRunnerOwned(p) {
				continue
			}
			if err := removeLedgerPath(p); err != nil && !os.IsNotExist(err) {
				ok = false
			}
		}
		if !ok {
			res.Pending++
			res.Errors = append(res.Errors, fmt.Errorf("reclaim workspace/artifacts for %s failed", f.Name()))
			continue
		}
		if err := atomicWriteFile(path+".reclaimed", []byte("reclaimed\n"), 0o600); err != nil {
			res.Pending++
			res.Errors = append(res.Errors, fmt.Errorf("write reclaim marker for %s: %w", f.Name(), err))
			continue
		}
		if err := os.Remove(path); err != nil {
			res.Pending++
			res.Errors = append(res.Errors, fmt.Errorf("retire reclaimed entry %s: %w", f.Name(), err))
			continue
		}
		res.Reclaimed++
	}
	if len(res.Errors) > 0 {
		return res, fmt.Errorf("crash-recovery ledger: %d unresolved entry/entries: %w", len(res.Errors), errors.Join(res.Errors...))
	}
	return res, nil
}

// ledgerPathIsRunnerOwned is the safety gate for deletion: only paths whose
// base name carries the kiwi scratch prefix are ever removed.
func ledgerPathIsRunnerOwned(p string) bool {
	if strings.TrimSpace(p) == "" {
		return false
	}
	base := filepath.Base(filepath.Clean(p))
	return strings.HasPrefix(base, "kiwi-run-") || strings.HasPrefix(base, "kiwi-artifacts-")
}
