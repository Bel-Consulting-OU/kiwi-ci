package storage

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestMemStoreInsertCompiledRunRejectedQuotaLeavesNoPartialState drives the
// atomic-enqueue contract's rejection paths that are evaluated AFTER another
// reservation was already staged. A rejected enqueue must leave ZERO partial
// state: no increment of an earlier quota key, no consumed downstream
// launch claim, no schedule occurrence.
func TestMemStoreInsertCompiledRunRejectedQuotaLeavesNoPartialState(t *testing.T) {
	repo := "https://github.com/o/r.git"
	team := "github.com/o"

	t.Run("quota team-key rejection rolls back the repo-key increment", func(t *testing.T) {
		m := newMemStore()
		if err := m.AdjustQuotaCounter(ctx(), repo, team, 1, 0); err != nil {
			t.Fatal(err)
		}
		req := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", repo)
		req.Quota = &QuotaReservation{RepoKey: repo, TeamKey: team, JobCount: 1, RepoQueueDepth: 10, TeamConcurrency: 1}
		err := m.InsertCompiledRun(ctx(), req)
		var qe *QuotaExceededError
		if !errors.As(err, &qe) || qe.Reason != "TEAM_QUOTA" {
			t.Fatalf("enqueue = %v, want TEAM_QUOTA", err)
		}
		if _, gerr := m.GetRun(ctx(), req.Run.ID); !errors.Is(gerr, ErrNotFound) {
			t.Fatalf("rejected enqueue leaked a run: %v", gerr)
		}
		running, queued, _ := m.QuotaCounts(ctx(), repo, "")
		if running != 1 || queued != 0 {
			t.Fatalf("repo counters after rejected enqueue = %d/%d, want 1/0 (no partial increment)", running, queued)
		}
		tr, tq, _ := m.QuotaCounts(ctx(), team, "")
		if tr != 1 || tq != 0 {
			t.Fatalf("team counters after rejected enqueue = %d/%d, want 1/0", tr, tq)
		}
	})

	t.Run("quota rejection never consumes the downstream launch claim", func(t *testing.T) {
		m := newMemStore()
		seedRunAndJob(m)
		_ = m.InsertDownstreamLink(ctx(), testDownstreamLink)
		launch := &DownstreamLaunchClaim{
			LinkKey:       testDownstreamLink.ParentJobID + "\x00" + testDownstreamLink.TargetRepo + "\x00" + testDownstreamLink.TargetRef,
			StableChildID: fmt.Sprintf("%064d", 1),
		}
		req := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", "https://github.com/o/r.git")
		req.DownstreamLaunch = launch
		req.Quota = &QuotaReservation{RepoKey: "https://github.com/o/r.git", JobCount: 1, RepoQueueDepth: 0.5}
		err := m.InsertCompiledRun(ctx(), req)
		var qe *QuotaExceededError
		if !errors.As(err, &qe) {
			t.Fatalf("enqueue = %v, want quota rejection", err)
		}
		link, ok, _ := m.GetDownstreamLink(ctx(), testDownstreamLink.ParentJobID, testDownstreamLink.TargetRepo, testDownstreamLink.TargetRef)
		if !ok {
			t.Fatal("downstream link disappeared")
		}
		if link.ChildRunID != "" || link.Reserved {
			t.Fatalf("rejected enqueue consumed the downstream claim: child=%q reserved=%v", link.ChildRunID, link.Reserved)
		}
		if _, gerr := m.GetRun(ctx(), req.Run.ID); !errors.Is(gerr, ErrNotFound) {
			t.Fatalf("rejected enqueue leaked a run: %v", gerr)
		}
	})

	t.Run("schedule-claim loss rolls back the quota reservation", func(t *testing.T) {
		m := newMemStore()
		repo := "https://github.com/o/r.git"
		sch := Schedule{ID: "11111111111111111111111111111111", Repository: repo, Spec: "@daily", Enabled: true, CreatedAt: time.Unix(1010, 0).UTC()}
		if err := m.UpsertSchedule(ctx(), sch); err != nil {
			t.Fatal(err)
		}
		nominal := time.Unix(20000, 0).UTC()
		first := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", repo)
		first.Quota = &QuotaReservation{RepoKey: repo, JobCount: 1}
		first.ScheduleClaim = &ScheduleClaim{ScheduleID: sch.ID, Nominal: nominal}
		if err := m.InsertCompiledRun(ctx(), first); err != nil {
			t.Fatal(err)
		}
		second := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", repo)
		second.Quota = &QuotaReservation{RepoKey: repo, JobCount: 1}
		second.ScheduleClaim = &ScheduleClaim{ScheduleID: sch.ID, Nominal: nominal}
		if err := m.InsertCompiledRun(ctx(), second); !errors.Is(err, ErrScheduleClaimLost) {
			t.Fatalf("replayed occurrence = %v, want ErrScheduleClaimLost", err)
		}
		_, queued, _ := m.QuotaCounts(ctx(), repo, "")
		if queued != 1 {
			t.Fatalf("queued after lost schedule claim = %d, want 1 (no leaked reservation)", queued)
		}
	})
}

// TestMemStoreConcurrentLeaseSingleJobEightPollers races eight pollers for
// ONE queued job: exactly one wins, attempts/started_at/rates are stamped
// exactly once, and the losers leave the runner and quota counters untouched.
func TestMemStoreConcurrentLeaseSingleJobEightPollers(t *testing.T) {
	m := newMemStore()
	seedLeaseRun(m, leaseJobID)
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1, CostPerHour: 4.5, PowerWatts: 12}); err != nil {
		t.Fatal(err)
	}
	if err := m.AdjustQuotaCounter(ctx(), leaseRepo, "", 0, 1); err != nil {
		t.Fatal(err)
	}
	const pollers = 8
	type result struct {
		job model.Job
		err error
	}
	results := make(chan result, pollers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < pollers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			j, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1))
			results <- result{j, err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	winners, conflicts := 0, 0
	var winner model.Job
	for r := range results {
		switch {
		case r.err == nil:
			winners++
			winner = r.job
		case errors.Is(r.err, ErrLeaseConflict):
			conflicts++
		default:
			t.Fatalf("unexpected lease error: %v", r.err)
		}
	}
	if winners != 1 || conflicts != pollers-1 {
		t.Fatalf("winners=%d conflicts=%d, want 1/%d", winners, conflicts, pollers-1)
	}
	// attempts and started_at exactly once; rates frozen once.
	if winner.Attempts != 1 || winner.StartedAt == nil {
		t.Fatalf("winner attempts/started_at = %d/%v, want 1/set", winner.Attempts, winner.StartedAt)
	}
	if winner.CostRate != 4.5 || winner.PowerWatts != 12 {
		t.Fatalf("frozen rates = %v/%v, want 4.5/12", winner.CostRate, winner.PowerWatts)
	}
	if winner.LeaseRunnerID != leaseRunner || winner.LeaseGeneration != 1 {
		t.Fatalf("winner lease = %s/gen%d", winner.LeaseRunnerID, winner.LeaseGeneration)
	}
	stored, err := m.GetJob(ctx(), leaseJobID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Attempts != 1 || stored.Status != model.StatusRunning {
		t.Fatalf("stored job = %s attempts=%d, want running/1", stored.Status, stored.Attempts)
	}
	// Runner holds exactly one slot and is busy; quota moved exactly one
	// slot from queued to running.
	ri, _ := m.GetRunner(ctx(), leaseRunner)
	if len(ri.ActiveJobs) != 1 || ri.ActiveJobs[0] != leaseJobID || !ri.Busy {
		t.Fatalf("runner after race = active=%v busy=%v", ri.ActiveJobs, ri.Busy)
	}
	running, queued, _ := m.QuotaCounts(ctx(), leaseRepo, "")
	if running != 1 || queued != 0 {
		t.Fatalf("quota after race = %d/%d, want 1/0", running, queued)
	}
}

// TestMemStoreEnvironmentConcurrencyRepoScoped proves the environment
// concurrency key is (repository, environment): the same environment name in
// two different repositories does not block, while two jobs of the same
// repository serialize.
func TestMemStoreEnvironmentConcurrencyRepoScoped(t *testing.T) {
	m := newMemStore()
	otherRepo := "https://github.com/other/r.git"
	const secondRunner = "66666666666666666666666666666666"
	_ = m.InsertRun(ctx(), model.Run{ID: leaseRunID, Repo: leaseRepo, Status: model.StatusQueued, CreatedAt: time.Unix(1000, 0).UTC()})
	for _, j := range []model.Job{
		{ID: leaseJobID, RunID: leaseRunID, Key: "deploy-a", Status: model.StatusQueued, RepoURL: leaseRepo, Environment: "prod", EnvironmentConcurrency: 1, CreatedAt: time.Unix(1001, 0).UTC()},
		{ID: leaseJob2ID, RunID: leaseRunID, Key: "deploy-b", Status: model.StatusQueued, RepoURL: leaseRepo, Environment: "prod", EnvironmentConcurrency: 1, CreatedAt: time.Unix(1002, 0).UTC()},
	} {
		_ = m.InsertJob(ctx(), j)
	}
	for _, id := range []string{leaseRunner, secondRunner} {
		if err := m.UpsertRunner(ctx(), model.Runner{ID: id, Capacity: 1}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); err != nil {
		t.Fatalf("first prod lease: %v", err)
	}
	// Same (repo, env) key on a DIFFERENT, free runner: blocked by the
	// repo-scoped environment slot, not by runner capacity.
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJob2ID, secondRunner, 1)); !errors.Is(err, ErrEnvConcurrency) {
		t.Fatalf("second same-repo prod lease = %v, want ErrEnvConcurrency", err)
	}
	// Same environment NAME in another repository: allowed.
	third := model.Job{ID: "77777777777777777777777777777777", RunID: leaseRunID, Key: "deploy-c", Status: model.StatusQueued, RepoURL: otherRepo, Environment: "prod", EnvironmentConcurrency: 1, CreatedAt: time.Unix(1003, 0).UTC()}
	_ = m.InsertJob(ctx(), third)
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(third.ID, secondRunner, 1)); err != nil {
		t.Fatalf("cross-repo prod lease: %v", err)
	}
}

// TestMemStoreQuotaQueuedRunningLifecycle: N queued jobs with a concurrency
// limit of 1 admit exactly one running lease; cancelling that running job
// frees the running slot immediately AND adjusts the reserved counters, so
// the next lease succeeds and completion settles the counters at zero.
func TestMemStoreQuotaQueuedRunningLifecycle(t *testing.T) {
	m := newMemStore()
	repo := "https://github.com/o/r.git"
	team := "github.com/o"
	const queuedJobs = 3
	ids := []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"}
	for i, id := range ids {
		req := compiledRunRequest(id, id, repo)
		req.Run.ID = id
		req.Quota = &QuotaReservation{RepoKey: repo, TeamKey: team, JobCount: 1}
		// One job per run so cancel targets exactly one job.
		job := req.Jobs[id]
		job.RunID = id
		req.Jobs[id] = job
		if err := m.InsertCompiledRun(ctx(), req); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 2}); err != nil {
		t.Fatal(err)
	}
	running, queued, _ := m.QuotaCounts(ctx(), repo, "")
	if running != 0 || queued != queuedJobs {
		t.Fatalf("after enqueues = %d/%d, want 0/%d", running, queued, queuedJobs)
	}
	claim := leaseClaimFor(ids[0], leaseRunner, 2)
	claim.RepoURL = repo
	claim.RepoConcurrency = 1
	if _, err := m.AcquireLeaseAtomic(ctx(), claim); err != nil {
		t.Fatalf("first quota lease: %v", err)
	}
	running, queued, _ = m.QuotaCounts(ctx(), repo, "")
	if running != 1 || queued != queuedJobs-1 {
		t.Fatalf("after lease = %d/%d, want 1/%d", running, queued, queuedJobs-1)
	}
	// The second claim must be rejected by the conditional transition and
	// must not move any counter.
	second := leaseClaimFor(ids[1], leaseRunner, 2)
	second.RepoURL = repo
	second.RepoConcurrency = 1
	if _, err := m.AcquireLeaseAtomic(ctx(), second); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("second quota lease = %v, want ErrQuotaExceeded", err)
	}
	running, queued, _ = m.QuotaCounts(ctx(), repo, "")
	if running != 1 || queued != queuedJobs-1 {
		t.Fatalf("after rejected lease = %d/%d, want 1/%d", running, queued, queuedJobs-1)
	}
	// Cancel the running job: the running slot is released in the same
	// operation, so the next queued job leases immediately.
	if _, err := m.CancelRunJobs(ctx(), ids[0], "test cancel"); err != nil {
		t.Fatal(err)
	}
	running, queued, _ = m.QuotaCounts(ctx(), repo, "")
	if running != 0 || queued != queuedJobs-1 {
		t.Fatalf("after cancel = %d/%d, want 0/%d", running, queued, queuedJobs-1)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), second); err != nil {
		t.Fatalf("lease after cancel: %v", err)
	}
	running, queued, _ = m.QuotaCounts(ctx(), repo, "")
	if running != 1 || queued != queuedJobs-2 {
		t.Fatalf("after second lease = %d/%d, want 1/%d", running, queued, queuedJobs-2)
	}
	// Completing the running job releases the running slot without
	// resurrecting the queued reservation.
	if err := m.CompleteJob(ctx(), ids[1], 1, leaseRunner, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: ids[1], Generation: 1, RunnerID: leaseRunner}); err != nil {
		t.Fatal(err)
	}
	running, queued, _ = m.QuotaCounts(ctx(), repo, "")
	if running != 0 || queued != queuedJobs-2 {
		t.Fatalf("after complete = %d/%d, want 0/%d", running, queued, queuedJobs-2)
	}
	// A late replay of the completion cannot double-release.
	if err := m.CompleteJob(ctx(), ids[1], 1, leaseRunner, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: ids[1], Generation: 1, RunnerID: leaseRunner}); err != nil {
		t.Fatalf("replayed completion: %v", err)
	}
	running, queued, _ = m.QuotaCounts(ctx(), repo, "")
	if running != 0 || queued != queuedJobs-2 {
		t.Fatalf("after replay = %d/%d, want 0/%d", running, queued, queuedJobs-2)
	}
}

// TestMemStoreCancelMatrixRunnerSlotInvariant drives cancel and supersession
// over every non-terminal status and asserts the runner's active set never
// contains a non-running job afterwards, the busy flag is consistent, and a
// completion that arrives after the cancel cannot double-release or
// resurrect counters.
func TestMemStoreCancelMatrixRunnerSlotInvariant(t *testing.T) {
	statuses := []model.Status{model.StatusRunning, model.StatusQueued, model.StatusWaitingApproval}
	for _, status := range statuses {
		t.Run(string(status), func(t *testing.T) {
			m := newMemStore()
			seedLeaseRun(m, leaseJobID)
			if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1}); err != nil {
				t.Fatal(err)
			}
			j, _ := m.GetJob(ctx(), leaseJobID)
			if status == model.StatusRunning {
				if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); err != nil {
					t.Fatalf("lease: %v", err)
				}
			} else {
				j.Status = status
				if err := m.UpdateJob(ctx(), j); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := m.CancelRunJobs(ctx(), leaseRunID, "matrix cancel"); err != nil {
				t.Fatal(err)
			}
			ri, _ := m.GetRunner(ctx(), leaseRunner)
			if len(ri.ActiveJobs) != 0 || ri.Busy || ri.CurrentJob != "" {
				t.Fatalf("runner after cancel = active=%v busy=%v current=%q", ri.ActiveJobs, ri.Busy, ri.CurrentJob)
			}
			if ri.Capacity != 1 {
				t.Fatalf("capacity clamped: %d", ri.Capacity)
			}
			// Completion after cancel must not resurrect anything.
			before := ri
			if err := m.CompleteJob(ctx(), leaseJobID, 1, leaseRunner, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: leaseJobID, Generation: 1, RunnerID: leaseRunner}); !errors.Is(err, ErrGenerationMismatch) {
				t.Fatalf("completion after cancel = %v, want ErrGenerationMismatch", err)
			}
			after, _ := m.GetRunner(ctx(), leaseRunner)
			if after.Completed != before.Completed || after.Failed != before.Failed || len(after.ActiveJobs) != 0 {
				t.Fatalf("completion after cancel mutated runner counters: before=%+v after=%+v", before, after)
			}
			cj, _ := m.GetJob(ctx(), leaseJobID)
			if cj.Status != model.StatusCancelled {
				t.Fatalf("job status after cancel+complete = %s", cj.Status)
			}
		})
	}
}

// TestMemStoreCompleteJobReceiptIdentityGuard: a receipt whose identity does
// not match the completion arguments is rejected before any state changes, so
// the receipt dedupe table can never be poisoned under a foreign key.
func TestMemStoreCompleteJobReceiptIdentityGuard(t *testing.T) {
	m := newMemStore()
	seedLeaseRun(m, leaseJobID)
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); err != nil {
		t.Fatal(err)
	}
	// Negative generations are invalid (SQL parity).
	if err := m.CompleteJob(ctx(), leaseJobID, -1, leaseRunner, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: leaseJobID, Generation: -1, RunnerID: leaseRunner}); err == nil {
		t.Fatal("negative generation completion accepted")
	}
	// A receipt keyed to a different job/generation/runner is refused.
	mismatch := []model.CompletionReceipt{
		{JobID: leaseJob2ID, Generation: 1, RunnerID: leaseRunner},
		{JobID: leaseJobID, Generation: 2, RunnerID: leaseRunner},
		{JobID: leaseJobID, Generation: 1, RunnerID: leaseJob2ID},
	}
	for i, rec := range mismatch {
		if err := m.CompleteJob(ctx(), leaseJobID, 1, leaseRunner, model.StatusSuccess, "", nil, rec); err == nil {
			t.Fatalf("mismatched receipt %d accepted", i)
		}
	}
	j, _ := m.GetJob(ctx(), leaseJobID)
	if j.Status != model.StatusRunning {
		t.Fatalf("job status after rejected completions = %s, want running", j.Status)
	}
	// The correct receipt still completes and dedupes exactly once.
	good := model.CompletionReceipt{JobID: leaseJobID, Generation: 1, RunnerID: leaseRunner, ResultHash: "h"}
	if err := m.CompleteJob(ctx(), leaseJobID, 1, leaseRunner, model.StatusSuccess, "", nil, good); err != nil {
		t.Fatalf("correct completion: %v", err)
	}
	before := len(m.outbox)
	if err := m.CompleteJob(ctx(), leaseJobID, 1, leaseRunner, model.StatusSuccess, "", nil, good); err != nil {
		t.Fatalf("replayed completion: %v", err)
	}
	if len(m.outbox) != before {
		t.Fatalf("replayed completion appended %d effect intents", len(m.outbox)-before)
	}
}

// TestMemStoreOutboxAppendDuplicateIDRejected mirrors the SQL primary key on
// outbox.id: a duplicate append fails instead of stacking a second row that a
// claim could hand out twice under the same stable ID.
func TestMemStoreOutboxAppendDuplicateIDRejected(t *testing.T) {
	m := newMemStore()
	item := OutboxItem{ID: "44444444444444444444444444444444", Kind: "github_check", Payload: []byte("{}"), CreatedAt: time.Unix(1000, 0).UTC()}
	if err := m.OutboxAppend(ctx(), item); err != nil {
		t.Fatal(err)
	}
	if err := m.OutboxAppend(ctx(), item); err == nil {
		t.Fatal("duplicate outbox id accepted")
	}
	pending, _ := m.OutboxPending(ctx())
	if len(pending) != 1 {
		t.Fatalf("outbox rows = %d, want 1", len(pending))
	}
	claimed, _ := m.ClaimOutbox(ctx(), "flusher", 4)
	if len(claimed) != 1 {
		t.Fatalf("claimed = %d, want 1", len(claimed))
	}
}

// TestMemStoreFragmentJobKeyIDMismatchRejected: a fragment whose job map key
// disagrees with the job's own ID (or whose contracts reference a job outside
// the fragment) is rejected with zero rows, because SQL inserts under j.ID and
// the two stores would otherwise disagree on the primary key.
func TestMemStoreFragmentJobKeyIDMismatchRejected(t *testing.T) {
	m := newMemStore()
	seedRunAndJob(m)
	child := testJob
	child.ID = "ffffffffffffffffffffffffffffffff"
	child.Key = "generated"
	child.DynamicDepth = 1
	req := GeneratedFragmentRequest{
		ParentJobID: testJob.ID, Depth: 1, FragmentID: "frag-mismatch",
		Jobs:      map[string]model.Job{"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee": child},
		Contracts: map[string]map[string]ArtifactContract{child.ID: {"dist": {Name: "dist"}}},
		Children:  []GeneratedFragmentChild{{Key: child.Key, ID: child.ID}},
	}
	if _, _, err := m.InsertGeneratedFragmentTx(ctx(), req, nil); err == nil {
		t.Fatal("job key/id mismatch accepted")
	}
	if _, err := m.GetJob(ctx(), "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mismatched fragment leaked a job: %v", err)
	}
	if _, found, _ := m.GetGeneratedFragment(ctx(), testJob.ID, 1, "frag-mismatch"); found {
		t.Fatal("mismatched fragment left a receipt")
	}
	// Contracts outside the fragment are rejected too.
	req2 := GeneratedFragmentRequest{
		ParentJobID: testJob.ID, Depth: 1, FragmentID: "frag-orphan-contract",
		Jobs:      map[string]model.Job{child.ID: child},
		Contracts: map[string]map[string]ArtifactContract{"99999999999999999999999999999999": {"dist": {Name: "dist"}}},
		Children:  []GeneratedFragmentChild{{Key: child.Key, ID: child.ID}},
	}
	if _, _, err := m.InsertGeneratedFragmentTx(ctx(), req2, nil); err == nil {
		t.Fatal("orphan contract accepted")
	}
	if _, err := m.GetJob(ctx(), child.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orphan-contract fragment leaked the job: %v", err)
	}
}

// TestMemStoreSupersedeQuotaMatrix: cancelling a superseded job releases
// exactly its own reservation in every status, while the successor's
// reservation is counted once.
func TestMemStoreSupersedeQuotaMatrix(t *testing.T) {
	repo := "https://github.com/o/r.git"
	cases := []struct {
		name         string
		status       model.Status
		wantRunning  int
		wantQueued   int
		leaseAtFirst bool
	}{
		// The superseded job's own reservation is released (running or
		// queued) and the successor's single queued slot is reserved once.
		{name: "running", status: model.StatusRunning, wantRunning: 0, wantQueued: 1, leaseAtFirst: true},
		{name: "queued", status: model.StatusQueued, wantRunning: 0, wantQueued: 1},
		{name: "waiting_approval", status: model.StatusWaitingApproval, wantRunning: 0, wantQueued: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMemStore()
			old := compiledRunRequest(leaseRunID, leaseJobID, repo)
			old.Quota = &QuotaReservation{RepoKey: repo, JobCount: 1}
			if err := m.InsertCompiledRun(ctx(), old); err != nil {
				t.Fatal(err)
			}
			if tc.leaseAtFirst {
				if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1}); err != nil {
					t.Fatal(err)
				}
				if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); err != nil {
					t.Fatal(err)
				}
			} else {
				j, _ := m.GetJob(ctx(), leaseJobID)
				j.Status = tc.status
				if err := m.UpdateJob(ctx(), j); err != nil {
					t.Fatal(err)
				}
			}
			next := compiledRunRequest(leaseJob2ID, "55555555555555555555555555555555", repo)
			next.Quota = &QuotaReservation{RepoKey: repo, JobCount: 1}
			next.CancelPrevious = []string{leaseJobID}
			if err := m.InsertCompiledRun(ctx(), next); err != nil {
				t.Fatal(err)
			}
			prev, _ := m.GetJob(ctx(), leaseJobID)
			if prev.Status != model.StatusCancelled {
				t.Fatalf("superseded status = %s, want cancelled", prev.Status)
			}
			// Counters: the superseded reservation was released and the
			// successor's queued reservation counted exactly once. A running
			// predecessor is replaced by the successor's queued slot, and a
			// queued/waiting predecessor keeps the queued count flat.
			running, queued, _ := m.QuotaCounts(ctx(), repo, "")
			fresh, _ := m.GetJob(ctx(), "55555555555555555555555555555555")
			if fresh.Status != model.StatusQueued {
				t.Fatalf("successor status = %s", fresh.Status)
			}
			if running != tc.wantRunning || queued != tc.wantQueued {
				t.Fatalf("counters after supersession = %d/%d, want %d/%d", running, queued, tc.wantRunning, tc.wantQueued)
			}
			if tc.leaseAtFirst {
				ri, _ := m.GetRunner(ctx(), leaseRunner)
				if len(ri.ActiveJobs) != 0 || ri.Busy {
					t.Fatalf("superseded runner slot not released: active=%v busy=%v", ri.ActiveJobs, ri.Busy)
				}
			}
		})
	}
}

// TestMemStoreExtremeAndCorruptValues: capacity/counter extremes and negative
// corrupted rows never produce work or negative counters.
func TestMemStoreExtremeAndCorruptValues(t *testing.T) {
	m := newMemStore()
	seedLeaseRun(m, leaseJobID)
	// Negative capacity (corrupted row) means no work.
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: -7}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("negative-capacity lease = %v, want ErrNoCapacity", err)
	}
	// Extreme negative counter deltas clamp at zero.
	if err := m.AdjustQuotaCounter(ctx(), "repo-x", "team-x", -1<<62, -1<<62); err != nil {
		t.Fatal(err)
	}
	running, queued, _ := m.QuotaCounts(ctx(), "repo-x", "")
	if running != 0 || queued != 0 {
		t.Fatalf("negative deltas produced counters %d/%d", running, queued)
	}
	// A negative environment concurrency is not interpreted as "deny all".
	job, _ := m.GetJob(ctx(), leaseJobID)
	job.Environment = "prod"
	job.EnvironmentConcurrency = -1
	if err := m.UpdateJob(ctx(), job); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); err != nil {
		t.Fatalf("negative env concurrency lease: %v", err)
	}
}

// TestMemStoreErrNotFoundPaths: unknown IDs fail with ErrNotFound exactly
// where SQL does, and tolerated misses stay tolerated.
func TestMemStoreErrNotFoundPaths(t *testing.T) {
	m := newMemStore()
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lease of unknown job = %v, want ErrNotFound", err)
	}
	if err := m.HeartbeatLease(ctx(), leaseJobID, leaseRunner, 1, time.Unix(3000, 0).UTC()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("heartbeat of unknown job = %v, want ErrNotFound", err)
	}
	if err := m.CompleteJob(ctx(), leaseJobID, 1, leaseRunner, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: leaseJobID, Generation: 1, RunnerID: leaseRunner}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("complete of unknown job = %v, want ErrNotFound", err)
	}
	if err := m.ReleaseRunnerJob(ctx(), leaseRunner, leaseJobID, model.StatusFailure); !errors.Is(err, ErrNotFound) {
		t.Fatalf("release of unknown runner = %v, want ErrNotFound", err)
	}
	ids, err := m.CancelRunJobs(ctx(), "ffffffffffffffffffffffffffffffff", "no such run")
	if err != nil || len(ids) != 0 {
		t.Fatalf("cancel of unknown run = %v/%v, want empty/nil", ids, err)
	}
	if err := m.OutboxAck(ctx(), "no-such-item"); err != nil {
		t.Fatalf("ack of unknown outbox item: %v", err)
	}
}

// TestMemStoreReleaseRunnerJobMissingRunnerReleasesQuota: a runner row that
// vanished (deregistered/corrupted state) must not strand the job's reserved
// quota slot. The release reports ErrNotFound but still returns the slot.
func TestMemStoreReleaseRunnerJobMissingRunnerReleasesQuota(t *testing.T) {
	repo := "https://github.com/o/r.git"
	for _, requeued := range []bool{false, true} {
		name := "failed"
		if requeued {
			name = "requeued"
		}
		t.Run(name, func(t *testing.T) {
			m := newMemStore()
			req := compiledRunRequest(leaseRunID, leaseJobID, repo)
			req.Quota = &QuotaReservation{RepoKey: repo, JobCount: 1}
			if err := m.InsertCompiledRun(ctx(), req); err != nil {
				t.Fatal(err)
			}
			if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1}); err != nil {
				t.Fatal(err)
			}
			if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); err != nil {
				t.Fatal(err)
			}
			running, queued, _ := m.QuotaCounts(ctx(), repo, "")
			if running != 1 || queued != 0 {
				t.Fatalf("pre-release counters = %d/%d, want 1/0", running, queued)
			}
			if requeued {
				j, _ := m.GetJob(ctx(), leaseJobID)
				j.Status = model.StatusQueued
				j.LeaseRunnerID = ""
				j.LeaseTokenHash = nil
				j.LeaseExpiresAt = nil
				if err := m.UpdateJob(ctx(), j); err != nil {
					t.Fatal(err)
				}
			}
			// Simulate the vanished runner row.
			delete(m.runners, leaseRunner)
			if err := m.ReleaseRunnerJob(ctx(), leaseRunner, leaseJobID, model.StatusFailure); !errors.Is(err, ErrNotFound) {
				t.Fatalf("release = %v, want ErrNotFound", err)
			}
			running, queued, _ = m.QuotaCounts(ctx(), repo, "")
			wantQueued := 0
			if requeued {
				wantQueued = 1
			}
			if running != 0 || queued != wantQueued {
				t.Fatalf("counters after vanished-runner release = %d/%d, want 0/%d", running, queued, wantQueued)
			}
		})
	}
}

// TestMemStoreReleaseRunnerJobCountersParity: ReleaseRunnerJob must bump the
// completing/failing runner counters and last_seen exactly like the SQL
// releaseRunner/completeRunner paths, so lost-runner recovery accounting is
// identical in every storage mode.
func TestMemStoreReleaseRunnerJobCountersParity(t *testing.T) {
	m := newMemStore()
	seedLeaseRun(m, leaseJobID)
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); err != nil {
		t.Fatal(err)
	}
	j, _ := m.GetJob(ctx(), leaseJobID)
	j.Status = model.StatusQueued
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	if err := m.UpdateJob(ctx(), j); err != nil {
		t.Fatal(err)
	}
	before, _ := m.GetRunner(ctx(), leaseRunner)
	if err := m.ReleaseRunnerJob(ctx(), leaseRunner, leaseJobID, model.StatusFailure); err != nil {
		t.Fatal(err)
	}
	after, _ := m.GetRunner(ctx(), leaseRunner)
	if after.Failed != before.Failed+1 {
		t.Fatalf("runner failed count = %d, want %d (SQL parity)", after.Failed, before.Failed+1)
	}
	if !after.LastSeen.After(before.LastSeen) && !after.LastSeen.Equal(before.LastSeen) {
		t.Fatalf("runner last_seen not refreshed: before=%v after=%v", before.LastSeen, after.LastSeen)
	}
	// Success releases bump completed, never failed.
	seedLeaseRun2 := model.Job{ID: leaseJob2ID, RunID: leaseRunID, Key: "second", Status: model.StatusQueued, RepoURL: leaseRepo, RepoFullName: "o/r", CreatedAt: time.Unix(1002, 0).UTC()}
	_ = m.InsertJob(ctx(), seedLeaseRun2)
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJob2ID, leaseRunner, 1)); err != nil {
		t.Fatal(err)
	}
	before, _ = m.GetRunner(ctx(), leaseRunner)
	if err := m.ReleaseRunnerJob(ctx(), leaseRunner, leaseJob2ID, model.StatusSuccess); err != nil {
		t.Fatal(err)
	}
	after, _ = m.GetRunner(ctx(), leaseRunner)
	if after.Completed != before.Completed+1 || after.Failed != before.Failed {
		t.Fatalf("release(success) counters = completed %d failed %d, want %d/%d", after.Completed, after.Failed, before.Completed+1, before.Failed)
	}
}
