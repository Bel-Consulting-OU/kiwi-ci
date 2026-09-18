package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestCompletionReceiptsSurviveRestartReplay proves the fs-mode completion
// receipt survives a control-plane restart: the restarted server answers an
// identical completion replay idempotently (204) purely from the restored
// receipt, without re-accounting usage or re-running completion effects, and
// refuses a same-triple payload with a different result hash (409) instead of
// treating it as a duplicate.
func TestCompletionReceiptsSurviveRestartReplay(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID, task := registerUsageRunner(t, s1)
	time.Sleep(20 * time.Millisecond) // non-zero billable duration

	if w := completeTask(t, s1, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("first complete = %d, want 204: %s", w.Code, w.Body.String())
	}
	costFirst, energyFirst := usageMetricsSnapshot(s1)
	if costFirst <= 0 || energyFirst <= 0 {
		t.Fatalf("first completion did not account usage: cost=%v energy=%v", costFirst, energyFirst)
	}
	s1.mu.Lock()
	first := s1.jobs[task.Job.ID]
	completedFirst := s1.runners[runnerID].Completed
	s1.mu.Unlock()
	if !first.UsageRecorded || first.Cost <= 0 || first.EnergyWh <= 0 {
		t.Fatalf("first completion did not persist usage: %+v", first)
	}

	// Restart against the same data dir: the terminal job and the completion
	// receipt must be rebuilt from the durable snapshot, not from the dead
	// process's memory.
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := completionResultHash(model.StatusSuccess, "", nil)
	key := completionReceiptKey(task.Job.ID, task.LeaseGeneration, runnerID)
	s2.mu.Lock()
	rec, has := s2.completions[key]
	recAt := s2.completionReceiptAt[key]
	restored := s2.jobs[task.Job.ID]
	s2.mu.Unlock()
	if !has {
		t.Fatalf("completion receipt %q not restored across restart", key)
	}
	if rec.JobID != task.Job.ID || rec.Generation != task.LeaseGeneration || rec.RunnerID != runnerID {
		t.Fatalf("restored receipt %+v does not match the completed triple", rec)
	}
	if rec.ResultHash != wantHash {
		t.Fatalf("restored receipt hash = %q, want %q", rec.ResultHash, wantHash)
	}
	if recAt.IsZero() {
		t.Fatal("restored receipt lost its recorded-at timestamp")
	}
	if restored.Status != model.StatusSuccess || !restored.UsageRecorded {
		t.Fatalf("restored terminal job = %+v", restored)
	}

	// The identical replay is idempotent: 204 from the restored receipt. The
	// restarted process starts with zero usage metrics and an empty usage
	// window, so any second accounting would be visible here.
	if w := completeTask(t, s2, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("replayed complete = %d, want 204: %s", w.Code, w.Body.String())
	}
	costReplay, energyReplay := usageMetricsSnapshot(s2)
	if costReplay != 0 || energyReplay != 0 {
		t.Fatalf("replayed completion re-accounted usage metrics: cost=%v energy=%v", costReplay, energyReplay)
	}
	s2.usageMu.Lock()
	usageLen := len(s2.usage)
	s2.usageMu.Unlock()
	if usageLen != 0 {
		t.Fatalf("replayed completion appended %d usage window entries", usageLen)
	}
	s2.mu.Lock()
	replayed := s2.jobs[task.Job.ID]
	completedReplay := s2.runners[runnerID].Completed
	s2.mu.Unlock()
	if replayed.Cost != first.Cost || replayed.EnergyWh != first.EnergyWh || !replayed.UsageRecorded {
		t.Fatalf("replayed completion moved job usage: %+v (first: cost=%v energy=%v)", replayed, first.Cost, first.EnergyWh)
	}
	if replayed.FinishedAt == nil || first.FinishedAt == nil || !replayed.FinishedAt.Equal(*first.FinishedAt) {
		t.Fatalf("replayed completion moved finished_at: %v -> %v", first.FinishedAt, replayed.FinishedAt)
	}
	if completedReplay != completedFirst {
		t.Fatalf("replayed completion moved runner completions: %d -> %d", completedFirst, completedReplay)
	}

	// A same-triple payload with a different result hash is not a duplicate:
	// the terminal job has no matching receipt, so the completion is refused
	// (409) and mutates nothing.
	if w := completeTask(t, s2, task, runnerID, "failure"); w.Code != http.StatusConflict {
		t.Fatalf("divergent replay = %d, want 409: %s", w.Code, w.Body.String())
	}
	s2.mu.Lock()
	divergent := s2.jobs[task.Job.ID]
	s2.mu.Unlock()
	if divergent.Status != model.StatusSuccess || divergent.Cost != first.Cost || divergent.EnergyWh != first.EnergyWh {
		t.Fatalf("divergent replay mutated the job: %+v", divergent)
	}
	if costAfter, energyAfter := usageMetricsSnapshot(s2); costAfter != 0 || energyAfter != 0 {
		t.Fatalf("divergent replay moved usage metrics: cost=%v energy=%v", costAfter, energyAfter)
	}
}
