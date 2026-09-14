package storage

import (
	"errors"
	"strings"
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

// TestMemStoreQuotaReservationLifecycle proves the reserved counters are
// decremented on cancel and complete.
func TestMemStoreQuotaReservationLifecycle(t *testing.T) {
	m := newMemStore()
	seedRunner(m)
	repo := "https://github.com/o/r.git"
	req := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", repo)
	req.Quota = &QuotaReservation{RepoKey: repo, JobCount: 1}
	if err := m.InsertCompiledRun(ctx(), req); err != nil {
		t.Fatal(err)
	}
	running, queued, err := m.QuotaCounts(ctx(), repo, "")
	if err != nil {
		t.Fatal(err)
	}
	if running != 0 || queued != 1 {
		t.Fatalf("after enqueue = %d/%d, want 0/1", running, queued)
	}
	// Lease moves the slot queued -> running.
	if _, err := m.AcquireLeaseAtomic(ctx(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", testRunner.ID, []byte("h"), 1, time.Unix(3000, 0).UTC(), 2); err != nil {
		t.Fatal(err)
	}
	running, queued, _ = m.QuotaCounts(ctx(), repo, "")
	if running != 1 || queued != 0 {
		t.Fatalf("after lease = %d/%d, want 1/0", running, queued)
	}
	// Complete releases the running slot.
	if err := m.CompleteJob(ctx(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", 1, testRunner.ID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", Generation: 1, RunnerID: testRunner.ID}); err != nil {
		t.Fatal(err)
	}
	running, queued, _ = m.QuotaCounts(ctx(), repo, "")
	if running != 0 || queued != 0 {
		t.Fatalf("after complete = %d/%d, want 0/0", running, queued)
	}

	// Cancel path: a queued job's reservation is released on cancel.
	req2 := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", repo)
	req2.Quota = &QuotaReservation{RepoKey: repo, JobCount: 1}
	if err := m.InsertCompiledRun(ctx(), req2); err != nil {
		t.Fatal(err)
	}
	_, queued, _ = m.QuotaCounts(ctx(), repo, "")
	if queued != 1 {
		t.Fatalf("after second enqueue queued = %d, want 1", queued)
	}
	if _, err := m.CancelRunJobs(ctx(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf", "test"); err != nil {
		t.Fatal(err)
	}
	_, queued, _ = m.QuotaCounts(ctx(), repo, "")
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
	if _, err := m.AcquireLeaseAtomic(ctx(), testJob.ID, testRunner.ID, []byte("h"), 1, time.Unix(3000, 0).UTC(), 2); err != nil {
		t.Fatal(err)
	}
	// Second job against the same runner with capacity 1 must fail.
	second := testJob
	second.ID = "ffffffffffffffffffffffffffffffff"
	second.Key = "second"
	second.Status = model.StatusQueued
	_ = m.InsertJob(ctx(), second)
	if _, err := m.AcquireLeaseAtomic(ctx(), second.ID, testRunner.ID, []byte("h"), 1, time.Unix(3000, 0).UTC(), 1); !errors.Is(err, ErrNoCapacity) {
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

// TestMemStoreInsertGeneratedJobsTxVerifier proves the transactional
// verifier rejection leaves zero rows.
func TestMemStoreInsertGeneratedJobsTxVerifier(t *testing.T) {
	m := newMemStore()
	seedRunAndJob(m)
	child := testJob
	child.ID = "ffffffffffffffffffffffffffffffff"
	child.Key = "generated"
	err := m.InsertGeneratedJobsTx(ctx(), testJob.ID, 1, map[string]model.Job{child.ID: child}, nil, func(parent model.Job, count int) error {
		return errors.New("rejected by verifier")
	})
	if err == nil {
		t.Fatal("verifier rejection must fail the insertion")
	}
	if _, gerr := m.GetJob(ctx(), child.ID); !errors.Is(gerr, ErrNotFound) {
		t.Fatalf("rejected fragment leaked a job: %v", gerr)
	}
	// Acceptance inserts the fragment.
	if err := m.InsertGeneratedJobsTx(ctx(), testJob.ID, 1, map[string]model.Job{child.ID: child}, nil, func(parent model.Job, count int) error {
		if count != 1 {
			t.Fatalf("run job count = %d, want 1", count)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetJob(ctx(), child.ID); err != nil {
		t.Fatalf("accepted fragment missing: %v", err)
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
