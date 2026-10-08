package runner

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
)

// TestExecuteUploadsPreJobAndPostJobSnapshots proves the runner wires the
// executor's pre-execution checkpoint when snapshot capture is enabled: one
// pre_job upload (the checkpointed workspace, before any step ran) and one
// post_job upload (the outcome workspace) travel under the active lease with
// the phase header, and each archive reflects its capture point.
func TestExecuteUploadsPreJobAndPostJobSnapshots(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	r := testRunnerFor(t, ts, Config{CaptureSnapshots: true})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "checkout.txt"), []byte("checkout"), 0o644)
	}
	text := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo step > step.txt\n"
	r.execute(context.Background(), basicTask(text))

	fsrv.mu.Lock()
	var phases []string
	var bodies [][]byte
	bi := 0
	for _, req := range fsrv.requests {
		if req.Method != http.MethodPost || !strings.HasSuffix(req.Path, "/snapshots") {
			continue
		}
		phases = append(phases, req.Header.Get("X-Kiwi-Snapshot-Phase"))
		if bi < len(fsrv.snapshotBodies) {
			bodies = append(bodies, append([]byte(nil), fsrv.snapshotBodies[bi]...))
		}
		bi++
	}
	fsrv.mu.Unlock()

	if len(phases) != 2 {
		t.Fatalf("snapshot uploads = %v (%d bodies), want one pre_job and one post_job", phases, len(bodies))
	}
	if phases[0] != model.SnapshotPhasePreJob || phases[1] != model.SnapshotPhasePostJob {
		t.Fatalf("snapshot phases = %v, want [pre_job post_job]", phases)
	}
	pre, err := snapshot.Parse(bytes.NewReader(bodies[0]))
	if err != nil {
		t.Fatalf("pre_job archive: %v", err)
	}
	post, err := snapshot.Parse(bytes.NewReader(bodies[1]))
	if err != nil {
		t.Fatalf("post_job archive: %v", err)
	}
	if !snapshotHas(pre, "checkout.txt") || snapshotHas(pre, "step.txt") {
		t.Fatalf("pre_job archive entries = %v, want checkout only (captured before the step)", snapshotPaths(pre))
	}
	if !snapshotHas(post, "step.txt") {
		t.Fatalf("post_job archive entries = %v, want the step output", snapshotPaths(post))
	}

	complete, ok := fsrv.lastComplete()
	if !ok || complete.Status != model.StatusSuccess {
		t.Fatalf("complete = %+v ok %t", complete, ok)
	}
	// Checkpoint capture failures never surface as job failures; a healthy
	// fake control plane means no snapshot warnings either.
	fsrv.mu.Lock()
	logs := strings.Join(fsrv.logLines, "\n")
	fsrv.mu.Unlock()
	if strings.Contains(logs, "pre-job checkpoint warning") {
		t.Fatalf("healthy pre_job capture warned: %q", logs)
	}
}

func snapshotHas(m snapshot.Manifest, path string) bool {
	for _, e := range m.Entries {
		if e.Path == path {
			return true
		}
	}
	return false
}

func snapshotPaths(m snapshot.Manifest) []string {
	out := make([]string, 0, len(m.Entries))
	for _, e := range m.Entries {
		out = append(out, e.Path)
	}
	return out
}
