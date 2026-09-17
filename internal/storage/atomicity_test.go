package storage

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// compiledRunRequest builds an InsertCompiledRunRequest for one repo with
// one job.
func compiledRunRequest(runID, jobID, repoURL string) InsertCompiledRunRequest {
	return InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: repoURL, Status: model.StatusQueued, CreatedAt: time.Unix(2000, 0).UTC()},
		Jobs: map[string]model.Job{jobID: {ID: jobID, RunID: runID, Key: "build", RepoURL: repoURL, Status: model.StatusQueued, CreatedAt: time.Unix(2001, 0).UTC()}},
	}
}

// TestMemStoreInsertCompiledRunDuplicateDelivery proves the delivery-dedupe
// claim rolls the whole enqueue back with zero rows written.
func TestMemStoreInsertCompiledRunDuplicateDelivery(t *testing.T) {
	m := newMemStore()
	req := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", "https://github.com/o/r.git")
	req.WebhookClaim = &WebhookClaim{Forge: "github", DeliveryID: "del-1", RunID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad"}
	req.Quota = &QuotaReservation{RepoKey: "https://github.com/o/r.git", JobCount: 1}
	if err := m.InsertCompiledRun(ctx(), req); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	// A second delivery with the same ID must fail the whole transaction.
	dup := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "https://github.com/o/r.git")
	dup.WebhookClaim = &WebhookClaim{Forge: "github", DeliveryID: "del-1", RunID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf"}
	dup.Quota = &QuotaReservation{RepoKey: "https://github.com/o/r.git", JobCount: 1}
	if err := m.InsertCompiledRun(ctx(), dup); !errors.Is(err, ErrDeliveryDuplicate) {
		t.Fatalf("duplicate delivery = %v, want ErrDeliveryDuplicate", err)
	}
	if _, err := m.GetRun(ctx(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("duplicate enqueue leaked a run: %v", err)
	}
	if _, err := m.GetJob(ctx(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("duplicate enqueue leaked a job: %v", err)
	}
	// The quota reservation of the rolled-back enqueue must not exist.
	running, queued, err := m.QuotaCounts(ctx(), "https://github.com/o/r.git", "")
	if err != nil {
		t.Fatal(err)
	}
	if running != 0 || queued != 1 {
		t.Fatalf("quota counters after duplicate = %d/%d, want 0/1", running, queued)
	}
}

// TestMemStoreInsertCompiledRunSupersession proves cancel-in-progress
// supersession cancels the prior run's jobs inside the same atomic enqueue.
func TestMemStoreInsertCompiledRunSupersession(t *testing.T) {
	m := newMemStore()
	old := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", "https://github.com/o/r.git")
	if err := m.InsertCompiledRun(ctx(), old); err != nil {
		t.Fatal(err)
	}
	next := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "https://github.com/o/r.git")
	next.CancelPrevious = []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae"}
	if err := m.InsertCompiledRun(ctx(), next); err != nil {
		t.Fatal(err)
	}
	prev, err := m.GetJob(ctx(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae")
	if err != nil {
		t.Fatal(err)
	}
	if prev.Status != model.StatusCancelled || prev.Error != "superseded by run aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf" {
		t.Fatalf("superseded job = %s/%q", prev.Status, prev.Error)
	}
	// The supersession audit row was recorded.
	audit, _ := m.ReadAudit(ctx(), 10)
	found := false
	for _, e := range audit {
		if e.Action == "job.superseded" {
			found = true
		}
	}
	if !found {
		t.Fatal("no job.superseded audit event")
	}
}

// TestMemStoreDuplicateDeliveryRollsBackSupersession proves a replayed
// webhook delivery rolls the WHOLE enqueue back — the staged supersede
// cancellations included — exactly like the SQL transaction: the old run and
// its jobs stay untouched and the new run never exists.
func TestMemStoreDuplicateDeliveryRollsBackSupersession(t *testing.T) {
	repo := "https://github.com/o/r.git"
	m := newMemStore()
	old := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac", repo)
	old.Run.ConcurrencyGroup = "grp"
	old.Run.Status = model.StatusRunning
	if err := m.InsertCompiledRun(ctx(), old); err != nil {
		t.Fatal(err)
	}
	// A prior delivery of del-1 was already processed by another run.
	if err := m.UpsertDelivery(ctx(), "github", "del-1", "cccccccccccccccccccccccccccccccc", "digest"); err != nil {
		t.Fatal(err)
	}
	baseline := m.snapshot()
	dup := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", repo)
	dup.Run.ConcurrencyGroup = "grp"
	dup.Supersede = &SupersedePolicy{RepoID: RepoIDFor("", repo, "o/r"), ConcurrencyGroup: "grp"}
	dup.WebhookClaim = &WebhookClaim{Forge: "github", DeliveryID: "del-1", RunID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad"}
	dup.Quota = &QuotaReservation{RepoKey: repo, JobCount: 1}
	if err := m.InsertCompiledRun(ctx(), dup); !errors.Is(err, ErrDeliveryDuplicate) {
		t.Fatalf("duplicate delivery = %v, want ErrDeliveryDuplicate", err)
	}
	if after := m.snapshot(); !reflect.DeepEqual(after, baseline) {
		t.Fatalf("replayed delivery left partial state (supersession not rolled back):\n before: %+v\n after:  %+v", baseline, after)
	}
}

// TestMemStoreSupersedePolicyAtomic proves the in-transaction supersede
// policy: conflicting non-terminal runs are cancelled in the SAME commit as
// the new run — jobs terminal-cancelled with leases cleared, the running
// job's runner slot and quota released, dependents re-evaluated, and the
// superseded run marked cancelled — while runs of other groups stay
// untouched and the whole request either commits or leaves no trace.
func TestMemStoreSupersedePolicyAtomic(t *testing.T) {
	repo := "https://github.com/o/r.git"
	repoID := RepoIDFor("", repo, "o/r")
	oldRunID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
	oldJobID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"
	runningJobID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf"
	otherRunID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	otherJobID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc"
	depRunID := "dddddddddddddddddddddddddddddddd"
	depJobID := "dddddddddddddddddddddddddddddddc"
	newRunID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad"
	newJobID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae"

	m := newMemStore()
	old := InsertCompiledRunRequest{
		Run: model.Run{ID: oldRunID, Repo: repo, ConcurrencyGroup: "grp", Status: model.StatusRunning, CreatedAt: time.Unix(1000, 0).UTC()},
		Jobs: map[string]model.Job{
			oldJobID:     {ID: oldJobID, RunID: oldRunID, RepoURL: repo, Status: model.StatusQueued, CreatedAt: time.Unix(1001, 0).UTC()},
			runningJobID: {ID: runningJobID, RunID: oldRunID, RepoURL: repo, Status: model.StatusQueued, CreatedAt: time.Unix(1002, 0).UTC()},
		},
		Quota: &QuotaReservation{RepoKey: repoID, JobCount: 2},
	}
	if err := m.InsertCompiledRun(ctx(), old); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(runningJobID, leaseRunner, 1)); err != nil {
		t.Fatal(err)
	}
	// An unrelated run of the same repository but another concurrency group.
	other := compiledRunRequest(otherRunID, otherJobID, repo)
	other.Run.ConcurrencyGroup = "other"
	other.Run.Status = model.StatusRunning
	other.Quota = &QuotaReservation{RepoKey: repoID, JobCount: 1}
	if err := m.InsertCompiledRun(ctx(), other); err != nil {
		t.Fatal(err)
	}
	// A dependent in another run, gated on the superseded job's success: the
	// supersession must re-evaluate it and block it in the same commit.
	if err := m.InsertRun(ctx(), model.Run{ID: depRunID, Repo: repo, Status: model.StatusQueued, CreatedAt: time.Unix(1100, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := m.InsertJob(ctx(), model.Job{ID: depJobID, RunID: depRunID, RepoURL: repo, Status: model.StatusQueued, Condition: "success()", Needs: []string{oldJobID}, CreatedAt: time.Unix(1101, 0).UTC()}); err != nil {
		t.Fatal(err)
	}

	next := InsertCompiledRunRequest{
		Run:          model.Run{ID: newRunID, Repo: repo, ConcurrencyGroup: "grp", Status: model.StatusQueued, CreatedAt: time.Unix(2000, 0).UTC()},
		Jobs:         map[string]model.Job{newJobID: {ID: newJobID, RunID: newRunID, RepoURL: repo, Status: model.StatusQueued, CreatedAt: time.Unix(2001, 0).UTC()}},
		Supersede:    &SupersedePolicy{RepoID: RepoIDFor("", repo, "o/r"), ConcurrencyGroup: "grp"},
		WebhookClaim: &WebhookClaim{Forge: "github", DeliveryID: "del-sup", RunID: newRunID},
		Quota:        &QuotaReservation{RepoKey: repoID, JobCount: 1},
	}
	if err := m.InsertCompiledRun(ctx(), next); err != nil {
		t.Fatal(err)
	}

	// Superseded jobs: terminal-cancelled, leases cleared.
	for _, id := range []string{oldJobID, runningJobID} {
		j, err := m.GetJob(ctx(), id)
		if err != nil {
			t.Fatal(err)
		}
		if j.Status != model.StatusCancelled || j.Error != "superseded by run "+newRunID {
			t.Fatalf("superseded job %s = %s/%q", id, j.Status, j.Error)
		}
		if j.LeaseRunnerID != "" || j.LeaseTokenHash != nil || j.LeaseExpiresAt != nil {
			t.Fatalf("superseded job %s kept lease state: %+v", id, j)
		}
	}
	// Superseded run cancelled in the same commit.
	if prev, err := m.GetRun(ctx(), oldRunID); err != nil || prev.Status != model.StatusCancelled || prev.FinishedAt == nil {
		t.Fatalf("superseded run = %+v err=%v, want cancelled with finished_at", prev, err)
	}
	// Runner slot released.
	if ri, err := m.GetRunner(ctx(), leaseRunner); err != nil || len(ri.ActiveJobs) != 0 || ri.Busy {
		t.Fatalf("runner after supersession = %+v err=%v, want released slot", ri, err)
	}
	// Quota: the running and queued predecessor slots released, the
	// successor's single queued slot reserved.
	running, queued, err := m.QuotaCounts(ctx(), RepoIDFor("", repo, "o/r"), "")
	if err != nil {
		t.Fatal(err)
	}
	if running != 0 || queued != 2 {
		t.Fatalf("quota after supersession = %d/%d, want 0/2 (successor + unrelated)", running, queued)
	}
	// Unrelated run and group untouched.
	otherJob, _ := m.GetJob(ctx(), otherJobID)
	if otherJob.Status != model.StatusQueued {
		t.Fatalf("unrelated job = %s, want queued", otherJob.Status)
	}
	if otherRun, _ := m.GetRun(ctx(), otherRunID); otherRun.Status != model.StatusRunning {
		t.Fatalf("unrelated run = %s, want running", otherRun.Status)
	}
	// Dependent recomputed and blocked in the same commit.
	dep, _ := m.GetJob(ctx(), depJobID)
	if dep.Status != model.StatusBlocked || dep.DependencyStatus != model.StatusCancelled {
		t.Fatalf("dependent = %s/%s, want blocked/cancelled", dep.Status, dep.DependencyStatus)
	}
	// The successor is committed with its job and delivery claim.
	if nextRun, err := m.GetRun(ctx(), newRunID); err != nil || nextRun.Status != model.StatusQueued {
		t.Fatalf("successor run = %+v err=%v", nextRun, err)
	}
	if got, err := m.GetJob(ctx(), newJobID); err != nil || got.Status != model.StatusQueued {
		t.Fatalf("successor job = %+v err=%v", got, err)
	}
	if _, ok, _ := m.FindDelivery(ctx(), "github", "del-sup"); !ok {
		t.Fatal("successful enqueue lost the delivery claim")
	}
}

// TestMemStoreInsertCompiledRunDepsAuthoritative proves the request's Deps
// map is the authoritative dependency-edge source: an entry (including an
// explicitly empty list) replaces the job's Needs, and jobs without an entry
// keep their own Needs.
func TestMemStoreInsertCompiledRunDepsAuthoritative(t *testing.T) {
	m := newMemStore()
	repo := "https://github.com/o/r.git"
	jobA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae"
	jobB := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf"
	req := InsertCompiledRunRequest{
		Run: model.Run{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", Repo: repo, Status: model.StatusQueued, CreatedAt: time.Unix(2000, 0).UTC()},
		Jobs: map[string]model.Job{
			jobA: {ID: jobA, RunID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", RepoURL: repo, Status: model.StatusQueued, Needs: []string{"stale"}},
			jobB: {ID: jobB, RunID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", RepoURL: repo, Status: model.StatusQueued, Needs: []string{jobA}},
		},
		Deps: map[string][]string{jobA: {}},
	}
	if err := m.InsertCompiledRun(ctx(), req); err != nil {
		t.Fatal(err)
	}
	a, _ := m.GetJob(ctx(), jobA)
	if len(a.Needs) != 0 {
		t.Fatalf("job with explicit empty deps kept needs %v", a.Needs)
	}
	b, _ := m.GetJob(ctx(), jobB)
	if len(b.Needs) != 1 || b.Needs[0] != jobA {
		t.Fatalf("job without a deps entry needs = %v, want [%s]", b.Needs, jobA)
	}
}

// TestMemStoreConcurrentSupersedeSingleWinner races superseding enqueues in
// one concurrency group through the memory store: every request commits
// completely or not at all (each run carries exactly its own job), the old
// run is cancelled, and exactly one run stays non-terminal.
func TestMemStoreConcurrentSupersedeSingleWinner(t *testing.T) {
	repo := "https://github.com/o/r.git"
	m := newMemStore()
	old := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac", repo)
	old.Run.ConcurrencyGroup = "grp"
	old.Run.Status = model.StatusRunning
	if err := m.InsertCompiledRun(ctx(), old); err != nil {
		t.Fatal(err)
	}
	const enqueues = 8
	var wg sync.WaitGroup
	errs := make(chan error, enqueues)
	for i := 0; i < enqueues; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			runID := fmt.Sprintf("eeeeeeeeeeeeeeeeeeeeeeeeeeee%04d", n)
			jobID := fmt.Sprintf("ffffffffffffffffffffffffffff%04d", n)
			errs <- m.InsertCompiledRun(ctx(), InsertCompiledRunRequest{
				Run:       model.Run{ID: runID, Repo: repo, ConcurrencyGroup: "grp", Status: model.StatusQueued, CreatedAt: time.Unix(3000+int64(n), 0).UTC()},
				Jobs:      map[string]model.Job{jobID: {ID: jobID, RunID: runID, RepoURL: repo, Status: model.StatusQueued, CreatedAt: time.Unix(3000+int64(n), 0).UTC()}},
				Supersede: &SupersedePolicy{RepoID: RepoIDFor("", repo, "o/r"), ConcurrencyGroup: "grp"},
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent superseding enqueue: %v", err)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if prev := m.runs["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"]; prev.Status != model.StatusCancelled {
		t.Fatalf("old run status = %s, want cancelled", prev.Status)
	}
	active := 0
	for id, r := range m.runs {
		if id == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab" || r.ConcurrencyGroup != "grp" {
			continue
		}
		if !r.Status.Terminal() {
			active++
		}
		jobs := 0
		for _, j := range m.jobs {
			if j.RunID == id {
				jobs++
			}
		}
		if jobs != 1 {
			t.Fatalf("run %s carries %d jobs, want exactly 1 (no partial state)", id, jobs)
		}
	}
	if active != 1 {
		t.Fatalf("non-terminal runs in the group = %d, want exactly one winner", active)
	}
}

// TestMemStoreQuotaReservationLifecycle proves the reserved counters are
// decremented on cancel and complete.
func TestMemStoreQuotaReservationLifecycle(t *testing.T) {
	m := newMemStore()
	seedRunner(m)
	repo := "https://github.com/o/r.git"
	repoID := RepoIDFor("", repo, "o/r")
	req := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", repo)
	req.Quota = &QuotaReservation{RepoKey: repoID, JobCount: 1}
	if err := m.InsertCompiledRun(ctx(), req); err != nil {
		t.Fatal(err)
	}
	running, queued, err := m.QuotaCounts(ctx(), repoID, "")
	if err != nil {
		t.Fatal(err)
	}
	if running != 0 || queued != 1 {
		t.Fatalf("after enqueue = %d/%d, want 0/1", running, queued)
	}
	// Lease moves the slot queued -> running.
	if _, err := m.AcquireLeaseAtomic(ctx(), LeaseClaim{JobID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", RunnerID: testRunner.ID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Unix(3000, 0).UTC(), RunnerCapacity: 2}); err != nil {
		t.Fatal(err)
	}
	running, queued, _ = m.QuotaCounts(ctx(), repoID, "")
	if running != 1 || queued != 0 {
		t.Fatalf("after lease = %d/%d, want 1/0", running, queued)
	}
	// Complete releases the running slot.
	if err := m.CompleteJob(ctx(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", 1, testRunner.ID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", Generation: 1, RunnerID: testRunner.ID}); err != nil {
		t.Fatal(err)
	}
	running, queued, _ = m.QuotaCounts(ctx(), repoID, "")
	if running != 0 || queued != 0 {
		t.Fatalf("after complete = %d/%d, want 0/0", running, queued)
	}

	// Cancel path: a queued job's reservation is released on cancel.
	req2 := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", repo)
	req2.Quota = &QuotaReservation{RepoKey: repoID, JobCount: 1}
	if err := m.InsertCompiledRun(ctx(), req2); err != nil {
		t.Fatal(err)
	}
	_, queued, _ = m.QuotaCounts(ctx(), repoID, "")
	if queued != 1 {
		t.Fatalf("after second enqueue queued = %d, want 1", queued)
	}
	if _, err := m.CancelRunJobs(ctx(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf", "test"); err != nil {
		t.Fatal(err)
	}
	_, queued, _ = m.QuotaCounts(ctx(), repoID, "")
	if queued != 0 {
		t.Fatalf("after cancel queued = %d, want 0", queued)
	}
}

// TestMemStoreQuotaLimitInsideEnqueue proves the limit check runs against
// the reserved counters (no check-then-reserve race) and rejects atomically.
func TestMemStoreQuotaLimitInsideEnqueue(t *testing.T) {
	m := newMemStore()
	repo := "https://github.com/o/r.git"
	req := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", repo)
	req.Quota = &QuotaReservation{RepoKey: repo, JobCount: 1, RepoQueueDepth: 1}
	if err := m.InsertCompiledRun(ctx(), req); err != nil {
		t.Fatal(err)
	}
	req2 := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", repo)
	req2.Quota = &QuotaReservation{RepoKey: repo, JobCount: 1, RepoQueueDepth: 1}
	err := m.InsertCompiledRun(ctx(), req2)
	var qe *QuotaExceededError
	if !errors.As(err, &qe) || qe.Reason != "REPO_QUOTA" {
		t.Fatalf("over-quota enqueue = %v, want REPO_QUOTA", err)
	}
	if _, gerr := m.GetRun(ctx(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf"); !errors.Is(gerr, ErrNotFound) {
		t.Fatalf("rejected enqueue leaked a run: %v", gerr)
	}
}

// TestMemStoreAcquireLeaseAtomicCapacity proves an over-capacity lease is
// rejected without committing the job claim.
func TestMemStoreAcquireLeaseAtomicCapacity(t *testing.T) {
	m := newMemStore()
	seedRunAndJob(m)
	seedRunner(m)
	// The runner has capacity 2; take it once.
	if _, err := m.AcquireLeaseAtomic(ctx(), LeaseClaim{JobID: testJob.ID, RunnerID: testRunner.ID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Unix(3000, 0).UTC(), RunnerCapacity: 2}); err != nil {
		t.Fatal(err)
	}
	// The live runner row now has capacity 1: a second job must fail.
	ri, err := m.GetRunner(ctx(), testRunner.ID)
	if err != nil {
		t.Fatal(err)
	}
	ri.Capacity = 1
	if err := m.UpsertRunner(ctx(), ri); err != nil {
		t.Fatal(err)
	}
	second := testJob
	second.ID = "ffffffffffffffffffffffffffffffff"
	second.Key = "second"
	second.Status = model.StatusQueued
	_ = m.InsertJob(ctx(), second)
	if _, err := m.AcquireLeaseAtomic(ctx(), LeaseClaim{JobID: second.ID, RunnerID: testRunner.ID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Unix(3000, 0).UTC(), RunnerCapacity: 1}); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("over-capacity lease = %v, want ErrNoCapacity", err)
	}
	j, err := m.GetJob(ctx(), second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if j.Status != model.StatusQueued || j.LeaseRunnerID != "" {
		t.Fatalf("rejected lease mutated the job: %+v", j)
	}
}

// TestMemStoreDownstreamReserveFirst proves the reserve-first exactly-once
// claim semantics: one flusher wins, and a launched link never re-reserves.
func TestMemStoreDownstreamReserveFirst(t *testing.T) {
	m := newMemStore()
	seedRunAndJob(m)
	_ = m.InsertDownstreamLink(ctx(), testDownstreamLink)
	won, err := m.ReserveDownstreamLaunch(ctx(), testDownstreamLink.ParentJobID, testDownstreamLink.TargetRepo, testDownstreamLink.TargetRef, "tok")
	if err != nil || !won {
		t.Fatalf("first reserve = %v/%v", won, err)
	}
	won, err = m.ReserveDownstreamLaunch(ctx(), testDownstreamLink.ParentJobID, testDownstreamLink.TargetRepo, testDownstreamLink.TargetRef, "tok")
	if err != nil || won {
		t.Fatalf("second reserve = %v/%v, want lost", won, err)
	}
	// Launch + mark: the reservation is consumed.
	if err := m.MarkDownstreamLaunched(ctx(), testDownstreamLink.ParentJobID, testDownstreamLink.TargetRepo, testDownstreamLink.TargetRef, "child-1"); err != nil {
		t.Fatal(err)
	}
	won, _ = m.ReserveDownstreamLaunch(ctx(), testDownstreamLink.ParentJobID, testDownstreamLink.TargetRepo, testDownstreamLink.TargetRef, "tok")
	if won {
		t.Fatal("launched link must never re-reserve")
	}
}

// TestMemStoreDownstreamReservationExpiry proves a reserved-but-unlaunched
// link is released by the expiry pass so a retried dispatch can launch it.
func TestMemStoreDownstreamReservationExpiry(t *testing.T) {
	m := newMemStore()
	seedRunAndJob(m)
	_ = m.InsertDownstreamLink(ctx(), testDownstreamLink)
	if won, _ := m.ReserveDownstreamLaunch(ctx(), testDownstreamLink.ParentJobID, testDownstreamLink.TargetRepo, testDownstreamLink.TargetRef, "tok"); !won {
		t.Fatal("reserve failed")
	}
	// Fresh reservation is not expired by a past cutoff.
	n, err := m.ExpireDownstreamReservations(ctx(), time.Now().UTC().Add(-time.Hour))
	if err != nil || n != 0 {
		t.Fatalf("past cutoff expired %d reservations: %v", n, err)
	}
	// A cutoff in the future expires it and allows re-reservation.
	n, err = m.ExpireDownstreamReservations(ctx(), time.Now().UTC().Add(time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("future cutoff expired %d reservations: %v", n, err)
	}
	if won, _ := m.ReserveDownstreamLaunch(ctx(), testDownstreamLink.ParentJobID, testDownstreamLink.TargetRepo, testDownstreamLink.TargetRef, "tok"); !won {
		t.Fatal("re-reserve after expiry failed")
	}
}

// TestMemStoreInsertGeneratedFragmentTxVerifier proves the transactional
// verifier rejection leaves zero rows and that acceptance commits the
// fragment together with its idempotency receipt.
func TestMemStoreInsertGeneratedFragmentTxVerifier(t *testing.T) {
	m := newMemStore()
	seedRunAndJob(m)
	child := testJob
	child.ID = "ffffffffffffffffffffffffffffffff"
	child.Key = "generated"
	contracts := map[string]map[string]ArtifactContract{
		child.ID: {"dist": {Name: "dist", Required: true}},
	}
	req := GeneratedFragmentRequest{
		ParentJobID: testJob.ID, Depth: 1, FragmentID: "frag-1",
		Jobs: map[string]model.Job{child.ID: child}, Contracts: contracts, Children: []GeneratedFragmentChild{{Key: child.Key, ID: child.ID}},
	}
	_, _, err := m.InsertGeneratedFragmentTx(ctx(), req, func(parent model.Job, count int) error {
		return errors.New("rejected by verifier")
	})
	if err == nil {
		t.Fatal("verifier rejection must fail the insertion")
	}
	if _, gerr := m.GetJob(ctx(), child.ID); !errors.Is(gerr, ErrNotFound) {
		t.Fatalf("rejected fragment leaked a job: %v", gerr)
	}
	// A rejected fragment must not leak its contracts either.
	if got, ok, _ := m.GetJobContracts(ctx(), child.ID); ok || got != nil {
		t.Fatalf("rejected fragment leaked contracts: %v", got)
	}
	if _, found, _ := m.GetGeneratedFragment(ctx(), testJob.ID, 0, "frag-1"); found {
		t.Fatal("rejected fragment left a receipt")
	}
	// Acceptance inserts the fragment AND its contracts atomically.
	rec, replayed, err := m.InsertGeneratedFragmentTx(ctx(), req, func(parent model.Job, count int) error {
		if count != 1 {
			t.Fatalf("run job count = %d, want 1", count)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if replayed || len(rec.Children) != 1 || rec.Children[0].ID != child.ID {
		t.Fatalf("receipt = %+v replayed=%v", rec, replayed)
	}
	if _, err := m.GetJob(ctx(), child.ID); err != nil {
		t.Fatalf("accepted fragment missing: %v", err)
	}
	if got, ok, err := m.GetJobContracts(ctx(), child.ID); err != nil || !ok || got["dist"].Name != "dist" {
		t.Fatalf("accepted fragment contracts = %v, ok=%v, err=%v", got, ok, err)
	}
	// A replay returns the SAME receipt and inserts nothing new.
	again, replayed, err := m.InsertGeneratedFragmentTx(ctx(), req, func(parent model.Job, count int) error {
		t.Fatalf("replay must not run the verifier (count=%d)", count)
		return nil
	})
	if err != nil || !replayed {
		t.Fatalf("replay = replayed=%v err=%v", replayed, err)
	}
	if len(again.Children) != 1 || again.Children[0].ID != child.ID {
		t.Fatalf("replayed receipt = %+v", again)
	}
	if n := len(m.jobs); n != 2 {
		t.Fatalf("replay duplicated rows: %d jobs, want 2 (run job + child)", n)
	}
}

// TestMigration0004 verifies the 0004 migration carries the quota counters,
// the real cache_manifests contract, and the downstream reservation/forge
// columns.
func TestMigration0004(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0004_quota_reservations.sql")
	if err != nil {
		t.Fatalf("read 0004: %v", err)
	}
	sql := string(raw)
	for _, want := range []string{
		`CREATE TABLE quota_reservations`,
		`running INT NOT NULL DEFAULT 0`,
		`queued INT NOT NULL DEFAULT 0`,
		`daily_cost DOUBLE PRECISION NOT NULL DEFAULT 0`,
		`daily_energy DOUBLE PRECISION NOT NULL DEFAULT 0`,
		`DROP TABLE IF EXISTS cache_manifests`,
		`CREATE TABLE cache_manifests`,
		`repo TEXT NOT NULL`,
		`trust_domain TEXT NOT NULL`,
		`logical_key TEXT NOT NULL`,
		`blob_sha256 TEXT NOT NULL`,
		`blob_size BIGINT NOT NULL DEFAULT 0`,
		`producer_run TEXT`,
		`producer_job TEXT`,
		`PRIMARY KEY (repo, trust_domain, logical_key)`,
		`ADD COLUMN reserved BOOLEAN NOT NULL DEFAULT FALSE`,
		`ADD COLUMN reserved_at TIMESTAMPTZ`,
		`ADD COLUMN target_forge TEXT NOT NULL DEFAULT ''`,
		`ADD COLUMN target_base_url TEXT NOT NULL DEFAULT ''`,
		`ADD COLUMN target_repo_id TEXT NOT NULL DEFAULT ''`,
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("0004_quota_reservations.sql is missing %q", want)
		}
	}
	stmts := migrations.SplitStatements(sql)
	if len(stmts) == 0 {
		t.Fatal("0004 has no statements after splitting")
	}
}
