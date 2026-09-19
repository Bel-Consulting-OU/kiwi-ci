package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// Part 1: crash after every durable boundary in fs mode. A crash is
// simulated by restoring a fresh Server from the on-disk state rather than
// killing a process: every test drives the mutation against a persistent
// server, snapshots/inspects the disk, and then opens a new server over the
// SAME data dir. Where the code path cannot be paused at the boundary (the
// completion handler runs its post-persist steps in the same call), the
// boundary state is constructed by directly editing the durable artifacts so
// the disk exactly matches the crash point; each construction says so.

// crashEffectsServer builds a persistent server whose admission policy
// grants the cross-repo trigger and whose downstream target is allowlisted,
// so a completed job's downstream effect (link + dispatch intent) is
// observable.
func crashEffectsServer(t *testing.T, dir string) *Server {
	t.Helper()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{"o/r": {CrossRepoTrigger: boolPtr(true)}}}
	s.DownstreamAllowlist = map[string][]string{"acme/child": {"o/r"}}
	s.DownstreamPipelineFetcher = func(context.Context, string, string) (string, error) {
		return childPipeline, nil
	}
	return s
}

// crashDownstreamLinkKey is the fs-mode link key of the downstreamPipeline
// fixture.
func crashDownstreamLinkKey(jobID string) string {
	return downstreamLinkKey(jobID, "acme/child", "refs/heads/main")
}

// crashStripCompletionArtifacts rewrites the durable artifacts to the exact
// state at "job.complete snapshot persisted, post-persist steps not yet run":
// the downstream link is removed from state.json and the completion effect /
// downstream intents are removed from outbox.jsonl. The complete handler
// writes the snapshot BEFORE any of these appends, so a process death in that
// window leaves exactly this disk state; the removal is a faithful
// reconstruction, not a mutation of a different path's output.
func crashStripCompletionArtifacts(t *testing.T, dir, jobID string) {
	t.Helper()
	repo := storage.New(dir)
	snap, err := repo.Load()
	if err != nil {
		t.Fatal(err)
	}
	delete(snap.DownstreamLinks, crashDownstreamLinkKey(jobID))
	if err := repo.Save(snap); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, outboxFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	var kept [][]byte
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var it forge.OutboxItem
		if err := json.Unmarshal(line, &it); err == nil {
			switch it.Kind {
			case storage.OutboxKindCompletionReconcile, storage.OutboxKindForgeDelivery, forge.OutboxKindDownstream:
				continue
			}
		}
		kept = append(kept, line)
	}
	if err := os.WriteFile(path, bytes.Join(kept, []byte("\n")), 0o600); err != nil {
		t.Fatal(err)
	}
}

// crashPendingKindCount counts queued outbox intents of one kind.
func crashPendingKindCount(s *Server, kind string) int {
	n := 0
	for _, it := range s.outbox.Pending() {
		if it.Kind == kind {
			n++
		}
	}
	return n
}

// crashAssertUsageWindowExactlyOne pins the fs usage invariants after a
// restart: the trailing window holds exactly the one durable accounting and
// the process metrics never move (they are process-local and the crash
// happened before/at their update).
func crashAssertUsageWindowExactlyOne(t *testing.T, s *Server, wantCost float64) {
	t.Helper()
	s.usageMu.Lock()
	window := append([]usageEntry(nil), s.usage...)
	s.usageMu.Unlock()
	if len(window) != 1 {
		t.Fatalf("usage window = %d entries, want exactly the 1 rebuilt from disk: %+v", len(window), window)
	}
	if wantCost > 0 && window[0].Cost != wantCost {
		t.Fatalf("usage window cost = %v, want the durable job cost %v", window[0].Cost, wantCost)
	}
	if cost, energy := usageMetricsSnapshot(s); cost != 0 || energy != 0 {
		t.Fatalf("process usage metrics = %v/%v, want 0/0 (a restart must not replay durable usage)", cost, energy)
	}
}

// TestCrashCompletionDurableBeforeEffectsRestartFS is boundary (a)/(e): the
// completion state, the receipt and the usage amounts are durable, but the
// process dies before the completion effects and their outbox intents (and,
// in the second variant, before the intents are dispatched). A restarted,
// fresh Server must converge through the runner replay path / outbox dispatch
// with the usage accounted exactly once and the terminal state unchanged.
func TestCrashCompletionDurableBeforeEffectsRestartFS(t *testing.T) {
	t.Run("crash-before-effect-intents-and-link", func(t *testing.T) {
		dir := t.TempDir()
		s1 := crashEffectsServer(t, dir)
		if _, err := s1.enqueue(SubmitRun{
			RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
			Ref: "refs/heads/main", SHA: "abc", Event: "push",
			Pipeline: downstreamPipeline, Trusted: true,
		}); err != nil {
			t.Fatal(err)
		}
		runnerID, task := registerUsageRunner(t, s1)
		time.Sleep(20 * time.Millisecond) // non-zero billable duration
		if w := completeTask(t, s1, task, runnerID, "success"); w.Code != http.StatusNoContent {
			t.Fatalf("complete = %d, want 204: %s", w.Code, w.Body.String())
		}
		s1.mu.Lock()
		first := s1.jobs[task.Job.ID]
		completedFirst := s1.runners[runnerID].Completed
		s1.mu.Unlock()
		if first.Status != model.StatusSuccess || !first.UsageRecorded || first.Cost <= 0 {
			t.Fatalf("pre-crash completion not durable in memory: %+v", first)
		}

		crashStripCompletionArtifacts(t, dir, task.Job.ID)

		// Restart: only the durable completion (job, receipt, usage) exists.
		s2 := crashEffectsServer(t, dir)
		s2.DailyCostLimit = 1e-9
		key := completionReceiptKey(task.Job.ID, task.LeaseGeneration, runnerID)
		s2.mu.Lock()
		_, hasReceipt := s2.completions[key]
		restored := s2.jobs[task.Job.ID]
		completedRestored := s2.runners[runnerID].Completed
		_, hasLink := s2.downstreamLinks[crashDownstreamLinkKey(task.Job.ID)]
		s2.mu.Unlock()
		if !hasReceipt {
			t.Fatalf("completion receipt %q did not survive the crash", key)
		}
		if restored.Status != model.StatusSuccess || !restored.UsageRecorded || restored.Cost <= 0 {
			t.Fatalf("restored terminal job = %+v", restored)
		}
		if completedRestored != completedFirst {
			t.Fatalf("runner completions = %d, want %d", completedRestored, completedFirst)
		}
		if hasLink {
			t.Fatal("stripped downstream link was resurrected by the restart")
		}
		for _, kind := range []string{storage.OutboxKindCompletionReconcile, storage.OutboxKindForgeDelivery, forge.OutboxKindDownstream} {
			if n := crashPendingKindCount(s2, kind); n != 0 {
				t.Fatalf("kind %q pending = %d after crash, want 0", kind, n)
			}
		}
		crashAssertUsageWindowExactlyOne(t, s2, first.Cost)
		if reason, exceeded := s2.dailyBudgetExceeded(context.Background()); !exceeded || reason != queueReasonDailyCostExceeded {
			t.Fatalf("restarted quota = %q/%v, want %s/true", reason, exceeded, queueReasonDailyCostExceeded)
		}

		// Runner replay: the identical completion finds the restored receipt
		// and reconciles the lost effect (link + intent) without accounting
		// usage a second time.
		if w := completeTask(t, s2, task, runnerID, "success"); w.Code != http.StatusNoContent {
			t.Fatalf("receipt replay = %d, want 204: %s", w.Code, w.Body.String())
		}
		s2.mu.Lock()
		replayed := s2.jobs[task.Job.ID]
		completedReplay := s2.runners[runnerID].Completed
		_, hasLink = s2.downstreamLinks[crashDownstreamLinkKey(task.Job.ID)]
		s2.mu.Unlock()
		if !hasLink {
			t.Fatal("receipt replay did not repair the downstream link")
		}
		if n := crashPendingKindCount(s2, forge.OutboxKindDownstream); n != 1 {
			t.Fatalf("repaired downstream intents = %d, want exactly 1", n)
		}
		if replayed.Status != model.StatusSuccess || !replayed.UsageRecorded || replayed.Cost != first.Cost {
			t.Fatalf("replay moved the durable completion: %+v (first cost %v)", replayed, first.Cost)
		}
		if completedReplay != completedFirst {
			t.Fatalf("replay moved runner completions: %d -> %d", completedFirst, completedReplay)
		}
		crashAssertUsageWindowExactlyOne(t, s2, first.Cost)

		// The repaired intent dispatches to exactly one child run.
		s2.flushOutbox(context.Background())
		if children := childRunsOf(s2); len(children) != 1 {
			t.Fatalf("downstream children = %d, want exactly 1", len(children))
		}
		if pending := len(s2.outbox.Pending()); pending != 0 {
			t.Fatalf("outbox pending after convergence = %d, want 0", pending)
		}
	})

	t.Run("crash-before-dispatch", func(t *testing.T) {
		dir := t.TempDir()
		s1 := crashEffectsServer(t, dir)
		if _, err := s1.enqueue(SubmitRun{
			RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
			Ref: "refs/heads/main", SHA: "abc", Event: "push",
			Pipeline: downstreamPipeline, Trusted: true,
		}); err != nil {
			t.Fatal(err)
		}
		runnerID, task := registerUsageRunner(t, s1)
		time.Sleep(20 * time.Millisecond)
		if w := completeTask(t, s1, task, runnerID, "success"); w.Code != http.StatusNoContent {
			t.Fatalf("complete = %d, want 204: %s", w.Code, w.Body.String())
		}
		s1.mu.Lock()
		first := s1.jobs[task.Job.ID]
		s1.mu.Unlock()

		// The intents were durably enqueued but never dispatched (no Maintain
		// loop ran before the crash).
		s2 := crashEffectsServer(t, dir)
		s2.DailyCostLimit = 1e-9
		if n := crashPendingKindCount(s2, storage.OutboxKindCompletionReconcile); n != 1 {
			t.Fatalf("replayed completion_reconcile intents = %d, want 1", n)
		}
		if n := crashPendingKindCount(s2, forge.OutboxKindDownstream); n != 1 {
			t.Fatalf("replayed downstream intents = %d, want 1", n)
		}

		s2.flushOutbox(context.Background())
		s2.mu.Lock()
		job := s2.jobs[task.Job.ID]
		s2.mu.Unlock()
		if !job.UsageRecorded || job.Cost != first.Cost {
			t.Fatalf("post-restart flush moved the durable completion: %+v (first cost %v)", job, first.Cost)
		}
		crashAssertUsageWindowExactlyOne(t, s2, first.Cost)
		if children := childRunsOf(s2); len(children) != 1 {
			t.Fatalf("downstream children after restart flush = %d, want exactly 1", len(children))
		}
		if pending := len(s2.outbox.Pending()); pending != 0 {
			t.Fatalf("outbox pending after restart flush = %d, want 0", pending)
		}
		if reason, exceeded := s2.dailyBudgetExceeded(context.Background()); !exceeded || reason != queueReasonDailyCostExceeded {
			t.Fatalf("restarted quota = %q/%v, want %s/true", reason, exceeded, queueReasonDailyCostExceeded)
		}
	})
}

// TestCrashOutboxDurableBeforeDispatchRestartFS is boundary (b) at the outbox
// layer: an intent is durably enqueued (JSONL fsync), the process dies before
// any dispatch, and a restarted Outbox replays it exactly once. A third
// restart finds the durable done marker and replays nothing.
func TestCrashOutboxDurableBeforeDispatchRestartFS(t *testing.T) {
	dir := t.TempDir()
	o1 := NewOutbox(storage.New(dir))
	a := testOutboxItem(t, forge.OutboxKindGitHubCheck, `{"repo_full_name":"r","sha":"s"}`)
	b := testOutboxItem(t, forge.OutboxKindGitHubStatus, `{"repo_full_name":"r","sha":"s"}`)
	for _, it := range []forge.OutboxItem{a, b} {
		if err := o1.Enqueue(context.Background(), it); err != nil {
			t.Fatal(err)
		}
	}
	// Crash before any dispatch: no Flush ran.
	o2 := NewOutbox(storage.New(dir))
	pending := o2.Pending()
	if len(pending) != 2 {
		t.Fatalf("restart replay = %d intents, want 2", len(pending))
	}
	d := newOutboxDispatcher()
	if n, err := o2.Flush(context.Background(), d.dispatch); err != nil || n != 2 {
		t.Fatalf("replay flush = n=%d err=%v, want 2/nil", n, err)
	}
	for _, it := range []forge.OutboxItem{a, b} {
		if got := d.count(it.ID); got != 1 {
			t.Fatalf("intent %s dispatched %d times, want exactly 1", it.ID, got)
		}
	}
	o3 := NewOutbox(storage.New(dir))
	if replay := o3.Pending(); len(replay) != 0 {
		t.Fatalf("third restart replayed acked intents: %+v", replay)
	}
}

// TestCrashOutboxRemotePublishedBeforeAckRestartFS is the lost-ACK half of
// boundary (b): the intent is dispatched to a scripted fake forge (counting
// POST/PATCH), the remote check-run ID is durably mapped, and the process
// dies BEFORE the outbox done marker is appended. A restarted server
// re-dispatches the intent idempotently: the persisted mapping turns the
// retry into a PATCH, so the remote side sees no duplicate check.
func TestCrashOutboxRemotePublishedBeforeAckRestartFS(t *testing.T) {
	api, srv := newForgeVersionAPI(t)
	defer srv.Close()
	dir := t.TempDir()
	configure := func(s *Server) {
		s.GitHubToken = "tok"
		s.gitHubAPIBase = srv.URL
	}
	run := model.Run{ID: "run-outbox-crash", ForgeKind: "github", ForgeHost: "github.com",
		RepoFullName: "acme/backend", SHA: "sha-outbox-crash", Status: model.StatusRunning}

	s1, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	configure(s1)
	item := s1.checkIntent(run, "Pipeline", "in_progress", "", "running", nil)
	if err := s1.outbox.Enqueue(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	// Remote publication succeeds and the mapping is persisted; the process
	// dies BEFORE the outbox ACK (the done-file append never runs).
	if err := s1.dispatchOutbox(context.Background(), item); err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	if posts, patches, _ := api.snapshot(); posts != 1 || patches != 0 {
		t.Fatalf("first dispatch = posts=%d patches=%d, want one POST", posts, patches)
	}

	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	configure(s2)
	if n := len(s2.outbox.Pending()); n != 1 {
		t.Fatalf("unacked intent after restart = %d, want 1", n)
	}
	s2.flushOutbox(context.Background())
	posts, patches, published := api.snapshot()
	if posts != 1 || patches != 1 {
		t.Fatalf("restart re-dispatch = posts=%d patches=%d, want 1/1 (PATCH, never a duplicate POST)", posts, patches)
	}
	if len(published) != 2 || published[0] != "in_progress" || published[1] != "in_progress" {
		t.Fatalf("published states = %v, want the same in_progress check twice", published)
	}
	if pending := len(s2.outbox.Pending()); pending != 0 {
		t.Fatalf("outbox pending after idempotent replay = %d, want 0", pending)
	}

	// A third restart sees the ACKed intent gone.
	s3, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	configure(s3)
	if pending := len(s3.outbox.Pending()); pending != 0 {
		t.Fatalf("acked intent replayed after restart: %d", pending)
	}
}

// TestCrashWebhookEnqueueRestartIdempotentFS is boundary (d): the run and its
// durable webhook delivery marker are persisted, then the process dies (the
// HTTP response is not the durability boundary). The forge retry after the
// restart must dedupe to the ORIGINAL run from the durable marker instead of
// creating a ghost duplicate.
func TestCrashWebhookEnqueueRestartIdempotentFS(t *testing.T) {
	dir := t.TempDir()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case filepath.Base(r.URL.Path) == "pipeline.yaml":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"content":  base64.StdEncoding.EncodeToString([]byte(webhookPipeline)),
				"encoding": "base64",
			})
		case strings.Contains(r.URL.Path, "/compare/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"files": []map[string]string{{"filename": "src/main.go"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	newHook := func() *Server {
		t.Helper()
		s, err := NewPersistent("token", "token", dir)
		if err != nil {
			t.Fatal(err)
		}
		s.GitHubWebhookSecret = "hunter2"
		s.gitHubAPIBase = api.URL
		s.PipelinePath = ".kiwi/pipeline.yaml"
		return s
	}

	s1 := newHook()
	body := pushPayload("9049f1265b7d61be4a8904a9a27120d2064dab3b")
	w1 := postWebhook(t, s1, "hunter2", "push", "crash-delivery-1", body)
	if w1.Code != http.StatusAccepted {
		t.Fatalf("first delivery = %d, want 202: %s", w1.Code, w1.Body.String())
	}
	runID1, _ := decodeRun(t, w1)

	// Crash and restart: the delivery marker must be rebuilt from the run's
	// durable metadata, not from the dead process's map.
	s2 := newHook()
	w2 := postWebhook(t, s2, "hunter2", "push", "crash-delivery-1", body)
	if w2.Code != http.StatusOK {
		t.Fatalf("retried delivery after restart = %d, want 200 (idempotent dedupe): %s", w2.Code, w2.Body.String())
	}
	runID2, _ := decodeRun(t, w2)
	if runID2 != runID1 {
		t.Fatalf("retry returned run %s, want the original %s", runID2, runID1)
	}
	s2.mu.Lock()
	n := len(s2.runs)
	marked := s2.deliveries["crash-delivery-1"]
	s2.mu.Unlock()
	if n != 1 {
		t.Fatalf("retried webhook created %d runs, want exactly 1 (no ghost duplicate)", n)
	}
	if marked != runID1 {
		t.Fatalf("restored delivery marker = %q, want %q", marked, runID1)
	}
}

// TestCrashLogBatchJournalCommittedBeforeResponseFS is boundary (c): the fs
// log-batch journal is committed (fsync + atomic publish), then the process
// dies before the runner sees the 204. The runner's retry after the restart
// must be an idempotent 204 with exactly one stored copy. The committed state
// is produced through the production store call the handler uses, so the
// construction is exact (the handler body is the store call + the 204).
func TestCrashLogBatchJournalCommittedBeforeResponseFS(t *testing.T) {
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
	runnerID := registerRollbackRunner(t, s1, 1)
	task := leaseNextRollbackTask(t, s1, runnerID)

	identity := storage.LogBatchIdentity{JobID: task.Job.ID, Generation: task.LeaseGeneration, BatchID: "crash-batch"}
	entries := []model.LogEntry{
		{Seq: 1, RunID: task.Job.RunID, JobID: task.Job.ID, JobKey: task.Job.Key, Step: "run", Line: "one", CreatedAt: time.Now().UTC()},
		{Seq: 2, RunID: task.Job.RunID, JobID: task.Job.ID, JobKey: task.Job.Key, Step: "run", Line: "two", CreatedAt: time.Now().UTC()},
	}
	if err := s1.store.AppendLogBatch(identity, entries); err != nil {
		t.Fatalf("journal commit: %v", err)
	}

	// Restart (the 204 was never delivered) and let the runner retry the
	// identical batch over HTTP.
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	body := fsLogBatchBody(t, runnerID, task, "crash-batch", 1,
		fsLogBatchLine(task.Job.Key, "run", "one"), fsLogBatchLine(task.Job.Key, "run", "two"))
	w := doJSON(t, s2, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/log/batch", "token", body)
	if w.Code != http.StatusNoContent {
		t.Fatalf("post-restart retry = %d, want 204: %s", w.Code, w.Body.String())
	}
	logs, err := s2.store.ReadLogs(task.Job.RunID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Fatalf("post-restart retry stored %d lines, want exactly 2: %+v", len(logs), logs)
	}
	if logs[0].Line != "one" || logs[1].Line != "two" {
		t.Fatalf("post-restart retry altered the committed lines: %+v", logs)
	}
}

// TestCrashScheduleOccurrenceClaimLostRestartFS is boundary (f) as a defect
// probe. The fs fire path commits the run's state.json snapshot BEFORE the
// schedules.json occurrence claim, and the schedules-write failure path has
// no rollback: a crash in that window leaves a durable run with NO durable
// (schedule, nominal) claim. The next tick after a restart then fires the
// same nominal again. Two independent constructions are used (a pure
// crash-window disk reconstruction and the schedules-write failure path); the
// test asserts the exactly-once contract and fails with the duplicate
// evidence. It does not fix production code.
func TestCrashScheduleOccurrenceClaimLostRestartFS(t *testing.T) {
	ctx := context.Background()

	// crashFixture builds the schedule and returns the next due nominal.
	crashFixture := func(t *testing.T, dir string) (*Server, storage.Schedule, time.Time) {
		t.Helper()
		s, err := NewPersistent("token", "token", dir)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		sc := storage.Schedule{
			ID: "s-crash", Repository: "o/r", RepoID: "github.com/o/r", RepoURL: "https://github.com/o/r.git",
			Spec: scheduleSpec, Enabled: true, CreatedAt: now.Add(-3 * time.Minute),
		}
		s.mu.Lock()
		s.schedules[sc.ID] = sc
		s.mu.Unlock()
		if err := s.persistSchedulesLocked(); err != nil {
			t.Fatal(err)
		}
		due, nominal, ok := s.nextDueScheduleFrom(now, map[string]bool{})
		if !ok {
			t.Fatal("no due nominal for the fixture schedule")
		}
		return s, due, nominal
	}

	// assertExactlyOnce restarts on the given dir, verifies the crash state,
	// ticks the fire loop and asserts the nominal still has exactly one run.
	assertExactlyOnce := func(t *testing.T, dir string, sc storage.Schedule, nominal time.Time, construction string) {
		t.Helper()
		s2, err := NewPersistent("token", "token", dir)
		if err != nil {
			t.Fatal(err)
		}
		if n := crashRunsForNominal(t, s2, sc.ID, nominal); n != 1 {
			t.Fatalf("construction %s: restart run count = %d, want the one durable run", construction, n)
		}
		s2.mu.Lock()
		_, claimed := s2.occurrences[sc.ID][nominal.UTC().Unix()]
		s2.mu.Unlock()
		if claimed {
			t.Fatalf("construction %s: the occurrence claim survived the crash", construction)
		}
		s2.fireDueSchedules(ctx, time.Now().UTC())
		if n := crashRunsForNominal(t, s2, sc.ID, nominal); n != 1 {
			t.Fatalf("DEFECT (schedule occurrence exactly-once, %s): crash between the run snapshot and the occurrence claim refired nominal %s after restart: %d runs (want 1). The fs fire path persists state.json before schedules.json with no compensation, so a failed/crashed schedules write leaves a committed run and an unclaimed occurrence.",
				construction, nominal.UTC().Format(time.RFC3339), n)
		}
	}

	t.Run("crash-between-the-two-writes", func(t *testing.T) {
		dir := t.TempDir()
		s1, due, nominal := crashFixture(t, dir)
		schedulesPath := filepath.Join(dir, schedulesFile)
		before, err := os.ReadFile(schedulesPath)
		if err != nil {
			t.Fatal(err)
		}
		// A complete fire commits BOTH files. The crash window is between
		// them: restoring the pre-fire schedules.json bytes makes the disk
		// exactly the state a process death after the state.json fsync (and
		// before the schedules.json fsync) leaves behind — run durable,
		// occurrence claim and last_run gone.
		if _, fired, err := s1.fireSchedule(ctx, due, nominal); err != nil || !fired {
			t.Fatalf("fire = fired=%v err=%v, want a committed run", fired, err)
		}
		if n := crashRunsForNominal(t, s1, due.ID, nominal); n != 1 {
			t.Fatalf("pre-crash runs for the nominal = %d, want 1", n)
		}
		if err := os.WriteFile(schedulesPath, before, 0o600); err != nil {
			t.Fatal(err)
		}
		assertExactlyOnce(t, dir, due, nominal, "crash-between-the-two-writes")
	})

	t.Run("schedules-write-failure", func(t *testing.T) {
		dir := t.TempDir()
		s1, due, nominal := crashFixture(t, dir)
		// Same disk state through the error path: the run snapshot commits,
		// then the schedules write fails and the enqueue returns the error
		// without any compensation of the committed run.
		old := writeSchedulesFile
		writeSchedulesFile = func(string, any) error { return errors.New("process died before the claim was durable") }
		_, fired, ferr := s1.fireSchedule(ctx, due, nominal)
		writeSchedulesFile = old
		if ferr == nil || fired {
			t.Fatalf("fire with a failed schedules write = fired=%v err=%v, want error/false", fired, ferr)
		}
		if n := crashRunsForNominal(t, s1, due.ID, nominal); n != 1 {
			t.Fatalf("construction failed: durable runs for the nominal = %d, want 1 (the run snapshot commits before the failing claim write)", n)
		}
		assertExactlyOnce(t, dir, due, nominal, "schedules-write-failure")
	})
}

// crashRunsForNominal counts durable runs for one (schedule, nominal).
func crashRunsForNominal(t *testing.T, s *Server, scheduleID string, nominal time.Time) int {
	t.Helper()
	want := nominal.UTC().Format(time.RFC3339)
	n := 0
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.runs {
		if r.Metadata["schedule_id"] == scheduleID && r.Metadata["schedule_nominal"] == want {
			n++
		}
	}
	return n
}

// crashStripPostPersistCompletionIntents rewrites outbox.jsonl to the exact
// disk state at "completion snapshot persisted, no post-persist append ran":
// every completion effect intent, forge check intent and downstream intent
// the handler appends after the snapshot write is removed. (The forge check
// intents come from publishForgeStatus, which the completion path calls
// after enqueueCompletionEffects.)
func crashStripPostPersistCompletionIntents(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, outboxFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	var kept [][]byte
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var it forge.OutboxItem
		if err := json.Unmarshal(line, &it); err == nil {
			switch it.Kind {
			case storage.OutboxKindCompletionReconcile, storage.OutboxKindForgeDelivery,
				forge.OutboxKindGitHubCheck, forge.OutboxKindGitLabCheck, forge.OutboxKindForgejoCheck,
				forge.OutboxKindGitHubStatus, forge.OutboxKindDownstream:
				continue
			}
		}
		kept = append(kept, line)
	}
	if err := os.WriteFile(path, bytes.Join(kept, []byte("\n")), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestCrashCompletionBeforeIntentEnqueueReplayRepairsForgeDeliveryFS is FA-1:
// the fs completion snapshot (terminal job, receipt, usage) is durable but the
// process died BEFORE enqueueCompletionEffects appended the completion
// intents. The runner's replayed completion hits the receipt-replay branch,
// which used to reconcile internal effects only, permanently stranding the
// terminal forge publication. The replay must re-ensure BOTH deterministic
// intents (idempotently) before acking, and the scripted forge must see each
// terminal check exactly once across replays.
func TestCrashCompletionBeforeIntentEnqueueReplayRepairsForgeDeliveryFS(t *testing.T) {
	api, srv := newForgeVersionAPI(t)
	defer srv.Close()
	dir := t.TempDir()
	newServer := func() *Server {
		t.Helper()
		s, err := NewPersistent("token", "token", dir)
		if err != nil {
			t.Fatal(err)
		}
		s.GitHubToken = "tok"
		s.gitHubAPIBase = srv.URL
		return s
	}

	s1 := newServer()
	if _, err := s1.enqueue(SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: smokePipeline, Trusted: true,
	}); err != nil {
		t.Fatal(err)
	}
	// Drain the queued-state publication first: the crash window below is
	// "completion persisted, no post-persist intent appended".
	s1.flushOutbox(context.Background())
	runnerID, task := registerUsageRunner(t, s1)
	time.Sleep(20 * time.Millisecond)
	if w := completeTask(t, s1, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d, want 204: %s", w.Code, w.Body.String())
	}
	s1.mu.Lock()
	first := s1.jobs[task.Job.ID]
	s1.mu.Unlock()

	// Reconstruct the crash disk exactly: state.json keeps the terminal job,
	// usage and receipt; outbox.jsonl loses every post-persist append.
	crashStripPostPersistCompletionIntents(t, dir)

	// Restart: the receipt (and terminal state) survived, the intents did not.
	s2 := newServer()
	key := completionReceiptKey(task.Job.ID, task.LeaseGeneration, runnerID)
	s2.mu.Lock()
	_, hasReceipt := s2.completions[key]
	restored := s2.jobs[task.Job.ID]
	s2.mu.Unlock()
	if !hasReceipt {
		t.Fatalf("completion receipt %q did not survive the crash", key)
	}
	if restored.Status != model.StatusSuccess || !restored.UsageRecorded || restored.Cost <= 0 {
		t.Fatalf("restored terminal job = %+v", restored)
	}
	for _, kind := range []string{storage.OutboxKindCompletionReconcile, storage.OutboxKindForgeDelivery, forge.OutboxKindGitHubCheck} {
		if n := crashPendingKindCount(s2, kind); n != 0 {
			t.Fatalf("kind %q pending = %d after crash, want 0", kind, n)
		}
	}

	// The runner replay republishes BOTH deterministic intents before acking.
	if w := completeTask(t, s2, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("receipt replay = %d, want 204: %s", w.Code, w.Body.String())
	}
	if n := crashPendingKindCount(s2, storage.OutboxKindForgeDelivery); n != 1 {
		t.Fatalf("repaired forge_delivery intents = %d, want exactly 1 (terminal publication must not be lost)", n)
	}
	if n := crashPendingKindCount(s2, storage.OutboxKindCompletionReconcile); n != 1 {
		t.Fatalf("repaired completion_reconcile intents = %d, want exactly 1", n)
	}

	// Dispatching the repaired intents publishes the terminal checks exactly
	// once each (pipeline + the one job), all in the terminal completed state.
	// The pipeline check was already mapped by the queued-state publication,
	// so its terminal update is a PATCH; the job check is a fresh POST.
	postsBefore, patchesBefore, publishedBefore := api.snapshot()
	s2.flushOutbox(context.Background())
	posts, patches, published := api.snapshot()
	if (posts-postsBefore)+(patches-patchesBefore) != 2 {
		t.Fatalf("terminal forge publications = %d, want 2 (pipeline + job)", (posts-postsBefore)+(patches-patchesBefore))
	}
	if len(published)-len(publishedBefore) != 2 {
		t.Fatalf("published states = %v, want 2 new terminal states", published[len(publishedBefore):])
	}
	for _, status := range published[len(publishedBefore):] {
		if status != "completed" {
			t.Fatalf("forge publication emitted non-terminal state %q", status)
		}
	}
	if pending := len(s2.outbox.Pending()); pending != 0 {
		t.Fatalf("outbox pending after convergence = %d, want 0", pending)
	}

	// A second replay is a no-op: the deterministic intents are already
	// delivered, the internal effects stay idempotent (usage exactly once)
	// and nothing republishes.
	if w := completeTask(t, s2, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("second replay = %d, want 204: %s", w.Code, w.Body.String())
	}
	s2.flushOutbox(context.Background())
	postsAgain, patchesAgain, publishedAgain := api.snapshot()
	if postsAgain != posts || patchesAgain != patches || len(publishedAgain) != len(published) {
		t.Fatalf("second replay republished: posts %d->%d patches %d->%d published %v->%v", posts, postsAgain, patches, patchesAgain, published, publishedAgain)
	}
	s2.mu.Lock()
	replayed := s2.jobs[task.Job.ID]
	s2.mu.Unlock()
	if !replayed.UsageRecorded || replayed.Cost != first.Cost {
		t.Fatalf("replay moved the durable completion: %+v (first cost %v)", replayed, first.Cost)
	}
	crashAssertUsageWindowExactlyOne(t, s2, first.Cost)
}
