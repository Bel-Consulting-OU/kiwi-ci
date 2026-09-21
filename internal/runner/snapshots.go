package runner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
)

// uploadJobSnapshot archives the job workspace with snapshot.Create and
// POSTs it to /api/v1/jobs/{id}/snapshots under the active lease. The
// caller treats any error as a warning: snapshot uploads never fail a job.
func (r *Runner) uploadJobSnapshot(ctx context.Context, t server.Task, workspace string) error {
	tmp, err := os.CreateTemp("", "kiwi-snapshot-*.tar.gz")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := snapshot.Create(workspace, tmp); err != nil {
		tmp.Close()
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
