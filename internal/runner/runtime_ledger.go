package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

// runtimeLedgerEntry is the durable ownership record for one job's
// externally-visible host state. It is written BEFORE the workspace becomes
// visible to the job so a hard crash leaves enough information for the next
// incarnation to reclaim what the deferred cleanup could not.
type runtimeLedgerEntry struct {
	ID        string   `json:"id"`
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

func (r *Runner) runtimeLedgerDir() string {
	return filepath.Join(r.Cfg.WorkDir, ".kiwi-runtime", "ledger")
}

// ledgerAdd records one job's runtime ownership atomically and returns its
// ledger ID. Failures are non-fatal (the job still runs) but are reported to
// stderr: without the entry a crash leaks the workspace.
func (r *Runner) ledgerAdd(entry runtimeLedgerEntry) string {
	entry.ID = newRunnerInstanceID()
	entry.CreatedAt = time.Now().UTC()
	b, err := json.Marshal(entry)
	if err != nil {
		return ""
	}
	dir := r.runtimeLedgerDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ""
	}
	if err := fsutil.AtomicWriteFile(filepath.Join(dir, entry.ID+".json"), b, 0o600); err != nil {
		return ""
	}
	return entry.ID
}

// ledgerAddArtifacts appends one artifact scratch directory to an existing
// entry so a crash after its creation still records it.
func (r *Runner) ledgerAddArtifacts(id, dir string) {
	if id == "" || dir == "" {
		return
	}
	path := filepath.Join(r.runtimeLedgerDir(), id+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var entry runtimeLedgerEntry
	if err := json.Unmarshal(b, &entry); err != nil {
		return
	}
	for _, existing := range entry.Artifacts {
		if existing == dir {
			return
		}
	}
	entry.Artifacts = append(entry.Artifacts, dir)
	updated, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_ = fsutil.AtomicWriteFile(path, updated, 0o600)
}

// ledgerSetXFS records the installed XFS project quota on an existing entry
// so a crash after this point is reclaimable by the next incarnation.
func (r *Runner) ledgerSetXFS(id string, assignment *executor.WorkspaceQuotaAssignment) {
	if id == "" || assignment == nil {
		return
	}
	path := filepath.Join(r.runtimeLedgerDir(), id+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var entry runtimeLedgerEntry
	if err := json.Unmarshal(b, &entry); err != nil {
		return
	}
	entry.XFS = assignment
	updated, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_ = fsutil.AtomicWriteFile(path, updated, 0o600)
}

// reclaimWorkspaceQuota is the XFS-reclaim seam (tests substitute a fake).
var reclaimWorkspaceQuota = executor.ReclaimWorkspaceQuota

// reclaimJobCgroup is the cgroup-reclaim seam.
var reclaimJobCgroup = executor.ReclaimJobCgroup

// ledgerSetCgroup records the job-scoped cgroup on an existing entry.
func (r *Runner) ledgerSetCgroup(id, cgroup string) {
	if id == "" || cgroup == "" {
		return
	}
	path := filepath.Join(r.runtimeLedgerDir(), id+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var entry runtimeLedgerEntry
	if err := json.Unmarshal(b, &entry); err != nil {
		return
	}
	entry.Cgroup = cgroup
	updated, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_ = fsutil.AtomicWriteFile(path, updated, 0o600)
}

// ledgerRemove retires a completed job's entry.
func (r *Runner) ledgerRemove(id string) {
	if id == "" {
		return
	}
	_ = os.Remove(filepath.Join(r.runtimeLedgerDir(), id+".json"))
}

// reconcileRuntimeLedger reclaims host state recorded by PREVIOUS
// incarnations after runtime reconciliation proved the workloads gone. Only
// entries whose recorded paths look runner-created (a kiwi- basename) are
// removed; an entry whose paths cannot be deleted stays for a later retry.
// It returns the number of entries fully reclaimed.
func (r *Runner) reconcileRuntimeLedger(runInstanceID string) int {
	dir := r.runtimeLedgerDir()
	info, err := os.Lstat(dir)
	if err != nil {
		return 0
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !fileOwnedByEUID(info) {
		fmt.Fprintf(os.Stderr, "kiwi runner %s: refusing to reclaim through untrusted ledger directory %s\n", r.ID, dir)
		return 0
	}
	if info.Mode().Perm()&0o077 != 0 {
		// We created this directory; tighten it rather than trust it.
		_ = os.Chmod(dir, 0o700)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	reclaimed := 0
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, f.Name())
		entryInfo, err := os.Lstat(path)
		if err != nil || !entryInfo.Mode().IsRegular() || !fileOwnedByEUID(entryInfo) || entryInfo.Mode().Perm()&0o022 != 0 {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var entry runtimeLedgerEntry
		if err := json.Unmarshal(b, &entry); err != nil {
			// Unreadable ledger entry: leave it for manual inspection.
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
				continue
			}
		}
		if entry.XFS != nil {
			// Remove the QUOTA before the workspace it bounds; if the
			// filesystem cleanup cannot be proven, keep the entry (and the
			// workspace) so a later run retries instead of leaking the
			// project ID and its hard limit.
			if err := reclaimWorkspaceQuota(*entry.XFS); err != nil {
				continue
			}
		}
		ok := true
		paths := append([]string{entry.Workspace}, entry.Artifacts...)
		for _, p := range paths {
			if !ledgerPathIsRunnerOwned(p) {
				continue
			}
			if err := os.RemoveAll(p); err != nil && !os.IsNotExist(err) {
				ok = false
			}
		}
		if ok {
			_ = fsutil.AtomicWriteFile(path+".reclaimed", []byte("reclaimed"+"\n"), 0o600)
			_ = os.Remove(path)
			reclaimed++
		}
	}
	return reclaimed
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
