package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
)

// Snapshot archive bound. Capturing a snapshot writes the whole workspace
// into a local temporary tarball before uploading it, so an unbounded
// capture costs a second workspace-sized chunk of runner disk. The archive
// is therefore capped independently of the workspace itself:
//
//   - a job that declared resources.disk gets archiveMax = declared bound ×
//     snapshotArchiveFactor. The factor covers the framing an archive adds
//     over the sum of the workspace file sizes: tar stores a 512-byte header
//     plus 512-byte padding granularity per member and gzip adds framing
//     bytes even for incompressible data, so an archive of a workspace at
//     exactly its declared bound can exceed the bound without anything
//     misbehaving.
//   - a job without a disk declaration falls back to
//     DefaultSnapshotArchiveMaxBytes, the same 8 GiB hard ceiling the
//     control plane enforces on every blob/snapshot upload
//     (internal/server/blobs.go maxBlobBytes), which is also the 8 GiB
//     object class the runner's own streaming client policy is documented
//     against (see streamIdleTimeout in runner.go). Unifying with that
//     ceiling keeps runner-side behavior consistent with the receiver: the
//     runner never assembles an archive larger than the control plane's hard
//     limit, and the fallback is bounded rather than workspace-sized.
//
// The cap is enforced while streaming (safefs.CappedWriter), so an oversized
// workspace aborts the capture without buffering it in memory, and the
// partial temporary file is removed before the error is returned.
const (
	// DefaultSnapshotArchiveMaxBytes is the runner-side snapshot archive cap
	// used when the job declares no resources.disk: 8 GiB, matching the
	// control plane's hard upload ceiling.
	DefaultSnapshotArchiveMaxBytes int64 = 8 << 30
	// snapshotArchiveFactor scales a declared workspace bound into the
	// archive bound (see above). Maximum declared disk is 1 PiB
	// (pipeline.maxDiskRequest), so the product stays far below int64.
	snapshotArchiveFactor int64 = 2
)

// snapshotArchiveMaxBytes derives the local cap for one snapshot archive from
// the job's workspace bound (executor.Options.WorkspaceMaxBytes). A zero
// bound means the job declared no resources.disk and the documented fallback
// applies.
func snapshotArchiveMaxBytes(workspaceMaxBytes int64) int64 {
	if workspaceMaxBytes <= 0 {
		return DefaultSnapshotArchiveMaxBytes
	}
	return workspaceMaxBytes * snapshotArchiveFactor
}

// uploadJobSnapshot archives the job workspace with snapshot.Create and
// POSTs it to /api/v1/jobs/{id}/snapshots under the active lease. The
// caller treats any error as a warning: snapshot uploads never fail a job.
//
// workspaceMaxBytes is the job's declared disk bound (zero when none was
// declared); the temporary archive is capped with snapshotArchiveMaxBytes
// and an over-cap archive aborts the capture with a clear error instead of
// filling the runner's disk.
func (r *Runner) uploadJobSnapshot(ctx context.Context, t server.Task, workspace string, workspaceMaxBytes int64) error {
	limit := snapshotArchiveMaxBytes(workspaceMaxBytes)
	tmp, err := os.CreateTemp("", "kiwi-snapshot-*.tar.gz")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := snapshot.Create(workspace, safefs.NewCappedWriter(tmp, limit)); err != nil {
		tmp.Close()
		if errors.Is(err, safefs.ErrCapExceeded) {
			return fmt.Errorf("snapshot archive exceeds the runner limit of %d bytes (declared workspace bound %d bytes): %w", limit, workspaceMaxBytes, err)
		}
		return fmt.Errorf("snapshot create: %w", err)
	}
	if err := closeRunnerTempFile(tmp); err != nil {
		return fmt.Errorf("snapshot close: %w", err)
	}
	f, err := os.Open(tmpPath)
	if err != nil {
		return err
	}
	defer f.Close()
	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	guard := newStallGuard(cancel, streamIdleTimeout)
	defer guard.stop()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, r.Cfg.Server+"/api/v1/jobs/"+t.Job.ID+"/snapshots", &stallGuardReader{r: f, guard: guard})
	if err != nil {
		return err
	}
	r.auth(req)
	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("X-Kiwi-Runner-ID", r.ID)
	req.Header.Set("X-Kiwi-Lease-Token", t.LeaseToken)
	req.Header.Set("X-Kiwi-Lease-Generation", fmt.Sprint(t.LeaseGeneration))
	resp, err := r.streamClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("snapshot upload %s: %s", resp.Status, string(b))
	}
	return nil
}
