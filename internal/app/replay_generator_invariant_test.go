package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// generatorPipeline is a recorded GENERATOR job: the job declares
// generate.path and its step PRODUCES fragment.json, so the fragment read at
// the end of the job can only succeed when the step ran locally in the replay
// workspace (snapshotArchive contains no such file).
const generatorPipeline = `version: 1
jobs:
  gen:
    generate:
      path: fragment.json
    steps:
      - run: |
          cat > fragment.json <<'EOF'
          {"jobs":{"child":{"steps":[{"run":"echo child"}]}},"deps":{}}
          EOF
`

// TestReplayExactGeneratorNeverSchedulesChildren pins docs/INVARIANTS.md I5:
// exact replay of a recorded generator job executes the generator step
// LOCALLY (the job succeeds, which requires the step-written fragment to be
// readable) but never uploads the fragment to the control plane and never
// schedules any child work — the recorded control-plane traffic is read-only
// and contains no /generated call. The structural reason is pinned in
// replay.go: executor.Options.GenerateUpload is never wired by replay, so the
// only path from a generated fragment to child jobs does not exist.
func TestReplayExactGeneratorNeverSchedulesChildren(t *testing.T) {
	env := newExactReplayEnv(t,
		recordedExport(t, generatorPipeline, "gen", nil),
		[][]model.SnapshotRecord{exactPage(model.SnapshotRecord{
			ID: "snap-pre", JobKey: "gen", LeaseGeneration: 1,
			Phase: model.SnapshotPhasePreJob, CreatedAt: time.Now().UTC(),
		})},
		nil,
		map[string][]byte{"snap-pre": snapshotArchive(t)},
	)
	if err := Replay(context.Background(), []string{"--server", env.srv.URL, "run1", "gen"}); err != nil {
		t.Fatalf("exact replay of a generator job: %v", err)
	}
	if len(env.downloads) != 1 || env.downloads[0] != "snap-pre" {
		t.Fatalf("downloads = %v, want exactly the pre_job snapshot", env.downloads)
	}
	if len(env.requests) == 0 {
		t.Fatal("no control-plane requests recorded; the replay never fetched the record")
	}
	for _, req := range env.requests {
		if !strings.HasPrefix(req, "GET ") {
			t.Fatalf("replay issued a mutating request %q; replay cannot add work", req)
		}
		if strings.Contains(req, "/generated") {
			t.Fatalf("replay called the generated-fragment endpoint: %q", req)
		}
	}
}
