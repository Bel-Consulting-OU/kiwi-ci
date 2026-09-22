package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

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
//     DefaultSnapshotArchiveMaxBytes, which IS the shared
//     snapshot.MaxArchiveBytes budget every layer uses.
//
// The derived cap is min(2 x declared bound, DefaultSnapshotArchiveMaxBytes):
// the same budget the receiver's HTTP body limit and snapshot.Parse enforce,
// so the runner can never assemble an archive the control plane necessarily
// rejects. (Before this source existed the fallback and the 2x product were
// unclamped 8 GiB against a 4 GiB parser default.)
//
// The cap is enforced while streaming (safefs.CappedWriter), so an oversized
// workspace aborts the capture without buffering it in memory, and the
// partial temporary file is removed before the error is returned.
const (
	// DefaultSnapshotArchiveMaxBytes is the runner-side snapshot archive cap
	// used when the job declares no resources.disk, and the hard ceiling of
	// the derived 2x cap: the shared snapshot.MaxArchiveBytes budget
	// (4 GiB), which is exactly what the control plane's snapshot upload
	// endpoints and snapshot.Parse accept.
	DefaultSnapshotArchiveMaxBytes int64 = snapshot.MaxArchiveBytes
	// snapshotArchiveFactor scales a declared workspace bound into the
	// archive bound (see above). Maximum declared disk is 1 PiB
	// (pipeline.maxDiskRequest), so the product stays far below int64.
	snapshotArchiveFactor int64 = 2
)

// snapshotArchiveMaxBytes derives the local cap for one snapshot archive from
// the job's workspace bound (executor.Options.WorkspaceMaxBytes): the
// documented 2x framing factor, clamped to the shared
// DefaultSnapshotArchiveMaxBytes ceiling either way. A zero bound means the
// job declared no resources.disk and the documented fallback applies.
func snapshotArchiveMaxBytes(workspaceMaxBytes int64) int64 {
	limit := DefaultSnapshotArchiveMaxBytes
	if workspaceMaxBytes <= 0 || workspaceMaxBytes > limit/snapshotArchiveFactor {
		return limit
	}
	return workspaceMaxBytes * snapshotArchiveFactor
}

// uploadJobSnapshot archives the job workspace with snapshot.Create and
// POSTs it to /api/v1/jobs/{id}/snapshots under the active lease. The
// caller treats any error as a warning: snapshot uploads never fail a job.
//
// The archive is STREAMED directly into the request body through an io.Pipe:
// the tar.gz bytes are produced by snapshot.Create and consumed by the HTTP
// transport as they are written, so no second workspace-sized copy is ever
// materialized on the runner's disk. The old implementation wrote the whole
// archive to a temporary file under TMPDIR (up to the shared 4 GiB cap)
// outside the workspace quota and the scheduler's disk reservation, which
// doubled the runner's peak disk cost for a capture that defaults on. The
// archive cap is still enforced WHILE STREAMING by the same
// safefs.CappedWriter the file path used, so an oversized workspace aborts
// the capture with the same clear error (and the aborted request body is
// rejected by the control plane's upload handler, which removes its partial
// file and never records an archive).
//
// workspaceMaxBytes is the job's declared disk bound (zero when none was
// declared).
func (r *Runner) uploadJobSnapshot(ctx context.Context, t server.Task, workspace string, workspaceMaxBytes int64) error {
	limit := snapshotArchiveMaxBytes(workspaceMaxBytes)
	pr, pw := io.Pipe()
	// capture carries snapshot.Create's result from its goroutine. The writer
	// end is always closed with that result, so the reader (the HTTP body and
	// then this function) observes the capture error as a body error instead
	// of a hang.
	capture := make(chan error, 1)
	go func() {
		_, err := snapshot.Create(workspace, safefs.NewCappedWriter(pw, limit))
		if err != nil {
			if errors.Is(err, safefs.ErrCapExceeded) {
				err = fmt.Errorf("snapshot archive exceeds the runner limit of %d bytes (declared workspace bound %d bytes): %w", limit, workspaceMaxBytes, err)
			} else {
				err = fmt.Errorf("snapshot create: %w", err)
			}
		}
		_ = pw.CloseWithError(err)
		capture <- err
	}()
	// The transport closes the request body when the request finishes; this
	// close also covers the paths where it does not, so the capture goroutine
	// can never block a write forever after the request is gone.
	defer pr.Close()
	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	guard := newStallGuard(cancel, streamIdleTimeout)
	defer guard.stop()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, r.Cfg.Server+"/api/v1/jobs/"+t.Job.ID+"/snapshots", &stallGuardReader{r: pr, guard: guard})
	if err != nil {
		_ = pr.CloseWithError(err)
		<-capture
		return err
	}
	r.auth(req)
	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("X-Kiwi-Runner-ID", r.ID)
	req.Header.Set("X-Kiwi-Lease-Token", t.LeaseToken)
	req.Header.Set("X-Kiwi-Lease-Generation", fmt.Sprint(t.LeaseGeneration))
	resp, err := r.streamClient().Do(req)
	if err != nil {
		// Abort a capture that may still be writing, then surface the
		// capture failure (the cap-exceeded error is the actionable one) or
		// the transport error.
		_ = pr.CloseWithError(err)
		if cerr := <-capture; cerr != nil {
			return cerr
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = pr.CloseWithError(errors.New("snapshot upload rejected"))
		if cerr := <-capture; cerr != nil {
			return cerr
		}
		return fmt.Errorf("snapshot upload %s: %s", resp.Status, string(b))
	}
	// The response is in; the body was fully consumed, so the capture has
	// finished. Surface a capture error even if the server answered 2xx
	// before observing the very end of the stream.
	return <-capture
}
