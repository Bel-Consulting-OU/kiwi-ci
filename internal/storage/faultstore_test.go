package storage

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

var errBoom = errors.New("injected storage failure")

// memSnapshot is a comparable picture of every durable collection in a
// memStore, used to prove a faulted operation left no partial write.
type memSnapshot struct {
	runs            map[string]model.Run
	jobs            map[string]model.Job
	runners         map[string]model.Runner
	receipts        map[string]model.CompletionReceipt
	auditLen        int
	logsLen         int
	artifacts       []model.ArtifactRecord
	reportsLen      int
	deliveries      map[string]string
	outbox          []OutboxItem
	schedules       map[string]Schedule
	occurrences     map[string]map[time.Time]string
	deployments     []model.Deployment
	snapshots       []model.SnapshotRecord
	jobContracts    map[string]map[string]ArtifactContract
	downstream      map[string]DownstreamLink
	quotas          map[string]quotaCounts
	cacheMans       map[string]CacheManifestRecord
	claims          map[string]time.Time
	outboxClaims    map[string]outboxClaim
	fragments       map[string]GeneratedFragmentReceipt
	pendingSidecars map[string]pendingSidecar
}

func (m *memStore) snapshot() memSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	quotas := make(map[string]quotaCounts, len(m.quotas))
	for k, v := range m.quotas {
		quotas[k] = v
	}
	cacheMans := make(map[string]CacheManifestRecord, len(m.cacheMans))
	for k, v := range m.cacheMans {
		cacheMans[k] = v
	}
	return memSnapshot{
		runs:            cloneRuns(m.runs),
		jobs:            cloneJobs(m.jobs),
		runners:         cloneRunners(m.runners),
		receipts:        cloneReceipts(m.receipts),
		auditLen:        len(m.audit),
		logsLen:         len(m.logs),
		artifacts:       append([]model.ArtifactRecord(nil), m.artifacts...),
		reportsLen:      len(m.reports),
		deliveries:      cloneDeliveries(m.deliveries),
		outbox:          append([]OutboxItem(nil), m.outbox...),
		schedules:       cloneSchedules(m.schedules),
		occurrences:     cloneOccurrences(m.occurrences),
		deployments:     append([]model.Deployment(nil), m.deployments...),
		snapshots:       append([]model.SnapshotRecord(nil), m.snapshots...),
		jobContracts:    cloneJobContracts(m.contracts),
		downstream:      cloneDownstreamLinks(m.downstream),
		quotas:          quotas,
		cacheMans:       cacheMans,
		claims:          cloneClaims(m.claims),
		outboxClaims:    cloneOutboxClaims(m.outboxClaims),
		fragments:       cloneFragments(m.fragments),
		pendingSidecars: clonePendingSidecars(m.pendingSidecars),
	}
}

func clonePendingSidecars(in map[string]pendingSidecar) map[string]pendingSidecar {
	out := make(map[string]pendingSidecar, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneOutboxClaims(in map[string]outboxClaim) map[string]outboxClaim {
	out := make(map[string]outboxClaim, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneFragments(in map[string]GeneratedFragmentReceipt) map[string]GeneratedFragmentReceipt {
	out := make(map[string]GeneratedFragmentReceipt, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneClaims(in map[string]time.Time) map[string]time.Time {
	out := make(map[string]time.Time, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneDownstreamLinks(in map[string]DownstreamLink) map[string]DownstreamLink {
	out := make(map[string]DownstreamLink, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneRuns(in map[string]model.Run) map[string]model.Run {
	out := make(map[string]model.Run, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneJobs(in map[string]model.Job) map[string]model.Job {
	out := make(map[string]model.Job, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneRunners(in map[string]model.Runner) map[string]model.Runner {
	out := make(map[string]model.Runner, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneReceipts(in map[string]model.CompletionReceipt) map[string]model.CompletionReceipt {
	out := make(map[string]model.CompletionReceipt, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneDeliveries(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneSchedules(in map[string]Schedule) map[string]Schedule {
	out := make(map[string]Schedule, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneOccurrences(in map[string]map[time.Time]string) map[string]map[time.Time]string {
	out := make(map[string]map[time.Time]string, len(in))
	for k, byNominal := range in {
		cp := make(map[time.Time]string, len(byNominal))
		for nominal, runID := range byNominal {
			cp[nominal] = runID
		}
		out[k] = cp
	}
	return out
}

func cloneJobContracts(in map[string]map[string]ArtifactContract) map[string]map[string]ArtifactContract {
	out := make(map[string]map[string]ArtifactContract, len(in))
	for k, contracts := range in {
		cp := make(map[string]ArtifactContract, len(contracts))
		for name, c := range contracts {
			cp[name] = c
		}
		out[k] = cp
	}
	return out
}

func ctx() context.Context { return context.Background() }

var testRun = model.Run{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Status: model.StatusQueued, CreatedAt: time.Unix(1000, 0).UTC()}

var testJob = model.Job{ID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", RunID: testRun.ID, Key: "build", Status: model.StatusQueued, CreatedAt: time.Unix(1001, 0).UTC()}

var testRunner = model.Runner{ID: "cccccccccccccccccccccccccccccccc", Capacity: 2, ActiveJobs: []string{}}

var testSchedule = Schedule{ID: "11111111111111111111111111111111", Repository: "https://example.com/repo.git", Spec: "@daily", Enabled: true, CreatedAt: time.Unix(1010, 0).UTC()}

var testDeployment = model.Deployment{ID: "22222222222222222222222222222222", RunID: testRun.ID, JobID: testJob.ID, Repository: "https://example.com/repo.git", Environment: "staging", Status: model.StatusRunning, CreatedAt: time.Unix(1011, 0).UTC()}

var testSnapshot = model.SnapshotRecord{ID: "33333333333333333333333333333333", RunID: testRun.ID, JobID: testJob.ID, JobKey: "build", Size: 10, SHA256: "abc", Version: 1, RootSHA256: "root", CreatedAt: time.Unix(1012, 0).UTC()}

var testContracts = map[string]ArtifactContract{
	"bundle": {Name: "bundle", Paths: []string{"dist/"}, Required: true, Retention: 24 * time.Hour, MaxSize: 4096, SHA256: "sha"},
}

var testDownstreamLink = DownstreamLink{
	ParentJobID: testJob.ID,
	TargetRepo:  "acme/child",
	TargetRef:   "refs/heads/main",
	LaunchToken: "tok",
	CreatedAt:   time.Unix(1014, 0).UTC(),
}

func seedRunAndJob(m *memStore) {
	_ = m.InsertRun(ctx(), testRun)
	_ = m.InsertJob(ctx(), testJob)
}

func seedRunningJob(m *memStore) {
	seedRunAndJob(m)
	exp := time.Unix(2000, 0).UTC()
	_, _ = m.AcquireLease(ctx(), testJob.ID, testRunner.ID, []byte("hash"), 1, exp)
}

func seedRunner(m *memStore) {
	_ = m.UpsertRunner(ctx(), testRunner)
}

// opCase describes one mutating store operation for fault-injection
// coverage: a setup function seeds the minimum durable state the operation
// needs, and call executes the operation against the store under test.
// enqueueStageFault, when > 0, additionally arms the inner store's
// mid-enqueue fault hook at failAfter=0 so the harness also covers a failure
// INSIDE the atomic enqueue transaction (after that many staged writes)
// rather than only before the call.
type opCase struct {
	name              string
	setup             func(*memStore)
	call              func(Store) error
	enqueueStageFault int
}

func faultOps() []opCase {
	return []opCase{
		{
			name:  "InsertRun",
			setup: func(m *memStore) {},
			call:  func(s Store) error { return s.InsertRun(ctx(), testRun) },
		},
		{
			name:  "InsertJob",
			setup: seedRunAndJob,
			call: func(s Store) error {
				job := testJob
				job.ID = "ffffffffffffffffffffffffffffffff"
				job.Key = "second"
				return s.InsertJob(ctx(), job)
			},
		},
		{
			name:  "AcquireLease",
			setup: seedRunAndJob,
			call: func(s Store) error {
				_, err := s.AcquireLease(ctx(), testJob.ID, testRunner.ID, []byte("hash"), 1, time.Unix(2000, 0).UTC())
				return err
			},
		},
		{
			name:  "HeartbeatLease",
			setup: func(m *memStore) { seedRunningJob(m); seedRunner(m) },
			call: func(s Store) error {
				return s.HeartbeatLease(ctx(), testJob.ID, testRunner.ID, 1, time.Unix(3000, 0).UTC())
			},
		},
		{
			name:  "CompleteJob",
			setup: func(m *memStore) { seedRunningJob(m); seedRunner(m) },
			call: func(s Store) error {
				return s.CompleteJob(ctx(), testJob.ID, 1, testRunner.ID, model.StatusSuccess, "", map[string]string{"o": "1"}, model.CompletionReceipt{JobID: testJob.ID, Generation: 1, RunnerID: testRunner.ID, ResultHash: "h"})
			},
		},
		{
			name:  "CancelRunJobs",
			setup: seedRunAndJob,
			call: func(s Store) error {
				_, err := s.CancelRunJobs(ctx(), testRun.ID, "fault test")
				return err
			},
		},
		{
			name:  "UpsertRunner",
			setup: func(m *memStore) { seedRunner(m) },
			call: func(s Store) error {
				runner := testRunner
				runner.Capacity = 7
				runner.LastSeen = time.Unix(5000, 0).UTC()
				return s.UpsertRunner(ctx(), runner)
			},
		},
		{
			name:  "InsertArtifact",
			setup: seedRunAndJob,
			call: func(s Store) error {
				return s.InsertArtifact(ctx(), model.ArtifactRecord{ID: "dddddddddddddddddddddddddddddddd", RunID: testRun.ID, JobID: testJob.ID, Name: "bin", SHA256: "e", CreatedAt: time.Unix(1002, 0).UTC()})
			},
		},
		{
			name:  "AppendLog",
			setup: seedRunAndJob,
			call: func(s Store) error {
				return s.AppendLog(ctx(), model.LogEntry{Seq: 1, RunID: testRun.ID, JobID: testJob.ID, Line: "hello", CreatedAt: time.Unix(1003, 0).UTC()})
			},
		},
		{
			name:  "AppendAudit",
			setup: seedRunAndJob,
			call: func(s Store) error {
				return s.AppendAudit(ctx(), model.AuditEvent{ID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", Action: "test", CreatedAt: time.Unix(1004, 0).UTC()})
			},
		},
		{
			name:  "InsertCompletionReceipt",
			setup: seedRunAndJob,
			call: func(s Store) error {
				return s.InsertCompletionReceipt(ctx(), model.CompletionReceipt{JobID: testJob.ID, Generation: 1, RunnerID: testRunner.ID, ResultHash: "h"})
			},
		},
		{
			name:  "OutboxAppend",
			setup: func(m *memStore) {},
			call: func(s Store) error {
				return s.(OutboxStore).OutboxAppend(ctx(), OutboxItem{ID: "44444444444444444444444444444444", Kind: "github_check", Payload: []byte(`{"sha":"abc"}`), CreatedAt: time.Unix(1013, 0).UTC()})
			},
		},
		{
			name: "OutboxAck",
			setup: func(m *memStore) {
				_ = m.OutboxAppend(ctx(), OutboxItem{ID: "44444444444444444444444444444444", Kind: "github_check", Payload: []byte(`{"sha":"abc"}`), CreatedAt: time.Unix(1013, 0).UTC()})
			},
			call: func(s Store) error {
				return s.(OutboxStore).OutboxAck(ctx(), "44444444444444444444444444444444")
			},
		},
		{
			name:  "UpsertSchedule",
			setup: func(m *memStore) { _ = m.UpsertSchedule(ctx(), testSchedule) },
			call: func(s Store) error {
				sc := testSchedule
				sc.Spec = "@hourly"
				return s.(ScheduleStore).UpsertSchedule(ctx(), sc)
			},
		},
		{
			name:  "ClaimScheduleOccurrence",
			setup: func(m *memStore) { _ = m.UpsertSchedule(ctx(), testSchedule) },
			call: func(s Store) error {
				_, err := s.(ScheduleStore).ClaimScheduleOccurrence(ctx(), testSchedule.ID, time.Unix(20000, 0).UTC(), testRun.ID)
				return err
			},
		},
		{
			name:  "InsertDeployment",
			setup: seedRunAndJob,
			call: func(s Store) error {
				return s.(DeploymentStore).InsertDeployment(ctx(), testDeployment)
			},
		},
		{
			name: "UpdateDeploymentStatus",
			setup: func(m *memStore) {
				seedRunAndJob(m)
				_ = m.InsertDeployment(ctx(), testDeployment)
			},
			call: func(s Store) error {
				fin := time.Unix(20001, 0).UTC()
				return s.(DeploymentStore).UpdateDeploymentStatus(ctx(), testDeployment.ID, model.StatusSuccess, &fin)
			},
		},
		{
			name:  "InsertSnapshotRecord",
			setup: seedRunAndJob,
			call: func(s Store) error {
				return s.(SnapshotStore).InsertSnapshotRecord(ctx(), testSnapshot)
			},
		},
		{
			name:  "InsertJobContracts",
			setup: seedRunAndJob,
			call: func(s Store) error {
				return s.(ArtifactContractStore).InsertJobContracts(ctx(), testJob.ID, testContracts)
			},
		},
		{
			name:  "ClaimSecretDelivery",
			setup: seedRunAndJob,
			call: func(s Store) error {
				_, err := s.(SecretClaimStore).ClaimSecretDelivery(ctx(), testJob.ID, 1, "tok")
				return err
			},
		},
		{
			name: "ReleaseSecretDelivery",
			setup: func(m *memStore) {
				seedRunAndJob(m)
				_, _ = m.ClaimSecretDelivery(ctx(), testJob.ID, 1, "tok")
			},
			call: func(s Store) error {
				return s.(SecretClaimReleaser).ReleaseSecretDelivery(ctx(), testJob.ID, 1, "tok")
			},
		},
		{
			name:  "SetQueueReasons",
			setup: seedRunAndJob,
			call: func(s Store) error {
				return s.(QueueReasonStore).SetQueueReasons(ctx(), map[string]string{testJob.ID: "WAITING_DEPENDENCY"})
			},
		},
		{
			name: "InsertGeneratedJobs",
			setup: func(m *memStore) {
				seedRunAndJob(m)
			},
			call: func(s Store) error {
				child := testJob
				child.ID = "ffffffffffffffffffffffffffffffff"
				child.Key = "generated"
				child.DynamicDepth = 1
				return s.(DynamicStore).InsertGeneratedJobs(ctx(), testJob.ID, 1, map[string]model.Job{child.ID: child}, map[string][]string{child.ID: nil})
			},
		},
		{
			name: "InsertDownstreamLink",
			setup: func(m *memStore) {
				seedRunAndJob(m)
			},
			call: func(s Store) error {
				return s.(DownstreamStore).InsertDownstreamLink(ctx(), testDownstreamLink)
			},
		},
		{
			name: "MarkDownstreamLaunched",
			setup: func(m *memStore) {
				seedRunAndJob(m)
				_ = m.InsertDownstreamLink(ctx(), testDownstreamLink)
			},
			call: func(s Store) error {
				return s.(DownstreamStore).MarkDownstreamLaunched(ctx(), testDownstreamLink.ParentJobID, testDownstreamLink.TargetRepo, testDownstreamLink.TargetRef, testRun.ID)
			},
		},
		{
			name: "AppendDownstreamRun",
			setup: func(m *memStore) {
				seedRunAndJob(m)
			},
			call: func(s Store) error {
				return s.(RunDownstreamStore).AppendDownstreamRun(ctx(), testRun.ID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab")
			},
		},
		{
			name: "ReopenRunForChildren",
			setup: func(m *memStore) {
				_ = m.InsertRun(ctx(), model.Run{ID: testRun.ID, Status: model.StatusSuccess, CreatedAt: time.Unix(1000, 0).UTC()})
			},
			call: func(s Store) error {
				return s.(RunDownstreamStore).ReopenRunForChildren(ctx(), testRun.ID)
			},
		},
		{
			name: "InsertCompiledRun",
			setup: func(m *memStore) {
				// A queued predecessor job that the enqueue supersedes.
				_ = m.InsertRun(ctx(), testRun)
				old := testJob
				old.ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"
				old.Status = model.StatusQueued
				old.RepoURL = "https://github.com/o/r.git"
				_ = m.InsertJob(ctx(), old)
			},
			call: func(s Store) error {
				return s.(RunEnqueueStore).InsertCompiledRun(ctx(), InsertCompiledRunRequest{
					Run:            model.Run{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", Repo: "https://github.com/o/r.git", Status: model.StatusQueued, ConcurrencyGroup: "grp", CreatedAt: time.Unix(2000, 0).UTC()},
					Jobs:           map[string]model.Job{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae": {ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", RunID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", Key: "new", RepoURL: "https://github.com/o/r.git", Status: model.StatusQueued, CreatedAt: time.Unix(2001, 0).UTC()}},
					CancelPrevious: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"},
					WebhookClaim:   &WebhookClaim{Forge: "github", DeliveryID: "del-1", RunID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad"},
					Quota:          &QuotaReservation{RepoKey: "https://github.com/o/r.git", JobCount: 1},
				})
			},
		},
		{
			// The mid-enqueue stage fault: a failure on the 7th of 8 job
			// writes (plus the supersede cancellation) must leave ZERO rows
			// behind — no run, no jobs, no delivery claim, no quota
			// reservation.
			name: "InsertCompiledRunMidEnqueueFault",
			setup: func(m *memStore) {
				_ = m.InsertRun(ctx(), testRun)
				old := testJob
				old.ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"
				old.Status = model.StatusQueued
				old.RepoURL = "https://github.com/o/r.git"
				_ = m.InsertJob(ctx(), old)
			},
			enqueueStageFault: 8,
			call: func(s Store) error {
				jobs := map[string]model.Job{}
				for i := 0; i < 8; i++ {
					id := fmt.Sprintf("%032d", i)
					jobs[id] = model.Job{ID: id, RunID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", Key: fmt.Sprintf("j%d", i), RepoURL: "https://github.com/o/r.git", Status: model.StatusQueued, CreatedAt: time.Unix(2000+int64(i), 0).UTC()}
				}
				return s.(RunEnqueueStore).InsertCompiledRun(ctx(), InsertCompiledRunRequest{
					Run:          model.Run{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", Repo: "https://github.com/o/r.git", Status: model.StatusQueued, ConcurrencyGroup: "grp", CreatedAt: time.Unix(2000, 0).UTC()},
					Jobs:         jobs,
					Supersede:    &SupersedePolicy{Repo: "https://github.com/o/r.git", ConcurrencyGroup: "grp"},
					WebhookClaim: &WebhookClaim{Forge: "github", DeliveryID: "del-stage", RunID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad"},
					Quota:        &QuotaReservation{RepoKey: "https://github.com/o/r.git", JobCount: 8},
				})
			},
		},
		{
			name:  "AcquireLeaseAtomic",
			setup: func(m *memStore) { seedRunAndJob(m); seedRunner(m) },
			call: func(s Store) error {
				_, err := s.(AtomicLeaseStore).AcquireLeaseAtomic(ctx(), LeaseClaim{JobID: testJob.ID, RunnerID: testRunner.ID, TokenHash: []byte("hash"), Generation: 1, ExpiresAt: time.Unix(2000, 0).UTC(), RunnerCapacity: 2})
				return err
			},
		},
		{
			name: "AdjustQuotaCounter",
			setup: func(m *memStore) {
				_ = m.AdjustQuotaCounter(ctx(), "repo", "team", 2, 3)
			},
			call: func(s Store) error {
				return s.(QuotaCounterStore).AdjustQuotaCounter(ctx(), "repo", "team", -1, 1)
			},
		},
		{
			name: "InsertGeneratedFragmentTx",
			setup: func(m *memStore) {
				seedRunAndJob(m)
			},
			call: func(s Store) error {
				child := testJob
				child.ID = "ffffffffffffffffffffffffffffffff"
				child.Key = "generated"
				child.DynamicDepth = 1
				_, _, err := s.(DynamicStoreTx).InsertGeneratedFragmentTx(ctx(), GeneratedFragmentRequest{
					ParentJobID: testJob.ID, Depth: 1, FragmentID: "frag-fault",
					Jobs: map[string]model.Job{child.ID: child}, Deps: map[string][]string{child.ID: nil},
					Contracts: map[string]map[string]ArtifactContract{child.ID: {"dist": {Name: "dist"}}},
					Children:  []GeneratedFragmentChild{{Key: child.Key, ID: child.ID}},
				}, func(parent model.Job, count int) error {
					if count != 1 {
						return fmt.Errorf("unexpected run job count %d", count)
					}
					return nil
				})
				return err
			},
		},
		{
			name:  "InsertArtifactOnce",
			setup: seedRunAndJob,
			call: func(s Store) error {
				_, _, err := s.(ArtifactIdempotentStore).InsertArtifactOnce(ctx(), model.ArtifactRecord{ID: "dddddddddddddddddddddddddddddddd", RunID: testRun.ID, JobID: testJob.ID, Name: "bin", SHA256: "e", CreatedAt: time.Unix(1002, 0).UTC()})
				return err
			},
		},
		{
			name: "ClaimOutbox",
			setup: func(m *memStore) {
				_ = m.OutboxAppend(ctx(), OutboxItem{ID: "44444444444444444444444444444444", Kind: "github_check", Payload: []byte(`{"sha":"abc"}`), CreatedAt: time.Unix(1013, 0).UTC()})
			},
			call: func(s Store) error {
				_, err := s.(OutboxStore).ClaimOutbox(ctx(), "flusher-a", 4)
				return err
			},
		},
		{
			name: "ReleaseOutboxClaim",
			setup: func(m *memStore) {
				_ = m.OutboxAppend(ctx(), OutboxItem{ID: "44444444444444444444444444444444", Kind: "github_check", Payload: []byte(`{"sha":"abc"}`), CreatedAt: time.Unix(1013, 0).UTC()})
				_, _ = m.ClaimOutbox(ctx(), "flusher-a", 1)
			},
			call: func(s Store) error {
				return s.(OutboxStore).ReleaseOutboxClaim(ctx(), "44444444444444444444444444444444", "flusher-a")
			},
		},
		{
			name:  "UpdateRunStatus",
			setup: seedRunAndJob,
			call: func(s Store) error {
				fin := time.Unix(25000, 0).UTC()
				return s.UpdateRunStatus(ctx(), testRun.ID, model.StatusSuccess, nil, &fin)
			},
		},
		{
			name:  "UpdateJob",
			setup: seedRunAndJob,
			call: func(s Store) error {
				j, err := s.GetJob(ctx(), testJob.ID)
				if err != nil {
					return err
				}
				j.QueueReason = "NO_COMPATIBLE_RUNNER"
				return s.UpdateJob(ctx(), j)
			},
		},
		{
			name:  "ReleaseRunnerJob",
			setup: func(m *memStore) { seedRunningJob(m); seedRunner(m) },
			call: func(s Store) error {
				return s.ReleaseRunnerJob(ctx(), testRunner.ID, testJob.ID, model.StatusFailure)
			},
		},
		{
			name:  "UpsertDelivery",
			setup: seedRunAndJob,
			call: func(s Store) error {
				return s.UpsertDelivery(ctx(), "github", "del-1", testRun.ID, "digest-1")
			},
		},
		{
			name: "SetArtifactSidecars",
			setup: func(m *memStore) {
				seedRunAndJob(m)
				_, _, _ = m.InsertArtifactOnce(ctx(), model.ArtifactRecord{ID: "dddddddddddddddddddddddddddddddd", RunID: testRun.ID, JobID: testJob.ID, Name: "bin", SHA256: "e", CreatedAt: time.Unix(1002, 0).UTC()})
			},
			call: func(s Store) error {
				return s.(ArtifactSidecarStore).SetArtifactSidecars(ctx(), "dddddddddddddddddddddddddddddddd", "sbom.json", "sbom-hash", "sig.json", "sig-hash")
			},
		},
		{
			name:  "RememberPendingSidecar",
			setup: seedRunAndJob,
			call: func(s Store) error {
				return s.(ArtifactSidecarStore).RememberPendingSidecar(ctx(), testJob.ID, "bin", ArtifactSidecarKindSBOM, strings.Repeat("c", 64))
			},
		},
		{
			name: "ConsumePendingSidecar",
			setup: func(m *memStore) {
				seedRunAndJob(m)
				_ = m.RememberPendingSidecar(ctx(), testJob.ID, "bin", ArtifactSidecarKindSBOM, strings.Repeat("c", 64))
			},
			call: func(s Store) error {
				return s.(ArtifactSidecarStore).ConsumePendingSidecar(ctx(), testJob.ID, "bin", ArtifactSidecarKindSBOM, strings.Repeat("c", 64))
			},
		},
		{
			name: "DeletePendingSidecars",
			setup: func(m *memStore) {
				seedRunAndJob(m)
				_ = m.RememberPendingSidecar(ctx(), testJob.ID, "bin", ArtifactSidecarKindSigstore, strings.Repeat("d", 64))
			},
			call: func(s Store) error {
				return s.(ArtifactSidecarStore).DeletePendingSidecars(ctx(), testJob.ID)
			},
		},
		{
			name: "PrunePendingSidecars",
			setup: func(m *memStore) {
				seedRunAndJob(m)
				_ = m.RememberPendingSidecar(ctx(), testJob.ID, "bin", ArtifactSidecarKindSBOM, strings.Repeat("c", 64))
			},
			call: func(s Store) error {
				_, err := s.(ArtifactSidecarStore).PrunePendingSidecars(ctx(), time.Now().UTC().Add(time.Hour))
				return err
			},
		},
		{
			name: "ReserveDownstreamLaunch",
			setup: func(m *memStore) {
				seedRunAndJob(m)
				_ = m.InsertDownstreamLink(ctx(), testDownstreamLink)
			},
			call: func(s Store) error {
				_, err := s.(DownstreamStore).ReserveDownstreamLaunch(ctx(), testDownstreamLink.ParentJobID, testDownstreamLink.TargetRepo, testDownstreamLink.TargetRef, "tok")
				return err
			},
		},
		{
			name: "ReleaseDownstreamReservation",
			setup: func(m *memStore) {
				seedRunAndJob(m)
				_ = m.InsertDownstreamLink(ctx(), testDownstreamLink)
				_, _ = m.ReserveDownstreamLaunch(ctx(), testDownstreamLink.ParentJobID, testDownstreamLink.TargetRepo, testDownstreamLink.TargetRef, "tok")
			},
			call: func(s Store) error {
				return s.(DownstreamStore).ReleaseDownstreamReservation(ctx(), testDownstreamLink.ParentJobID, testDownstreamLink.TargetRepo, testDownstreamLink.TargetRef)
			},
		},
		{
			name: "ExpireDownstreamReservations",
			setup: func(m *memStore) {
				seedRunAndJob(m)
				_ = m.InsertDownstreamLink(ctx(), testDownstreamLink)
				_, _ = m.ReserveDownstreamLaunch(ctx(), testDownstreamLink.ParentJobID, testDownstreamLink.TargetRepo, testDownstreamLink.TargetRef, "tok")
			},
			call: func(s Store) error {
				_, err := s.(DownstreamStore).ExpireDownstreamReservations(ctx(), time.Now().UTC().Add(time.Hour))
				return err
			},
		},
		{
			name:  "PutCacheManifest",
			setup: func(m *memStore) {},
			call: func(s Store) error {
				return s.(CacheManifestStore).PutCacheManifest(ctx(), CacheManifestRecord{
					Repo: "o/r", TrustDomain: "trusted", LogicalKey: strings.Repeat("a", 64), BlobSHA256: strings.Repeat("b", 64), BlobSize: 3,
				})
			},
		},
	}
}

// TestFaultInjectionEveryMutationEveryPoint injects a failure at every
// failure point of every mutating store operation and asserts the failed
// operation returned the injected error without leaving any partial write
// behind in the underlying store. Operations carrying an enqueueStageFault
// are additionally driven through the mid-enqueue hook at failAfter=0: a
// failure INSIDE the atomic enqueue transaction must also leave zero rows.
func TestFaultInjectionEveryMutationEveryPoint(t *testing.T) {
	for _, op := range faultOps() {
		for failAfter := 0; failAfter <= 3; failAfter++ {
			t.Run(fmt.Sprintf("%s/failAfter=%d", op.name, failAfter), func(t *testing.T) {
				inner := newMemStore()
				op.setup(inner)
				baseline := inner.snapshot()
				if op.enqueueStageFault > 0 && failAfter == 0 {
					inner.enqueueFaultOps = op.enqueueStageFault
					inner.enqueueFaultErr = errBoom
				}

				fs := &FaultyStore{Inner: inner, FailAfter: failAfter, Err: errBoom}
				err := op.call(fs)
				after := inner.snapshot()

				// Each operation faults either before the call (FailAfter
				// == 1) or, for stage-fault ops, on the Nth write inside the
				// transaction (failAfter == 0 with the hook armed).
				expectFault := failAfter == 1 || (op.enqueueStageFault > 0 && failAfter == 0)
				if expectFault {
					if !errors.Is(err, errBoom) {
						t.Fatalf("expected injected error, got %v", err)
					}
					if !reflect.DeepEqual(after, baseline) {
						t.Fatalf("faulted %s leaked a partial write into the store:\n before: %+v\n after:  %+v", op.name, baseline, after)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error at failAfter=%d: %v", failAfter, err)
				}
				if reflect.DeepEqual(after, baseline) {
					t.Fatalf("successful %s at failAfter=%d must commit durably", op.name, failAfter)
				}
			})
		}
	}
}

// TestFaultInjectionAtomicEnqueueNoPartialLeak drives the atomic enqueue
// through a faulted store and proves the durable state is all-or-nothing: a
// failure injected before the transaction leaves zero rows, a fully
// successful enqueue commits the run, every job and the webhook claim
// exactly once — never a partial prefix like the removed sequential
// InsertRun/InsertJob shape.
func TestFaultInjectionAtomicEnqueueNoPartialLeak(t *testing.T) {
	const jobCount = 8
	jobs := map[string]model.Job{}
	deps := map[string][]string{}
	for i := 0; i < jobCount; i++ {
		id := fmt.Sprintf("%032d", i)
		jobs[id] = model.Job{ID: id, RunID: testRun.ID, Key: fmt.Sprintf("job%d", i), Status: model.StatusQueued, CreatedAt: time.Unix(2000+int64(i), 0).UTC()}
	}
	req := InsertCompiledRunRequest{
		Run:          testRun,
		Jobs:         jobs,
		Deps:         deps,
		WebhookClaim: &WebhookClaim{Forge: "github", DeliveryID: "del-atomic", RunID: testRun.ID},
		Quota:        &QuotaReservation{RepoKey: "https://github.com/o/r.git", JobCount: jobCount},
	}
	for failAfter := 1; failAfter <= 3; failAfter++ {
		t.Run(fmt.Sprintf("failAfter=%d", failAfter), func(t *testing.T) {
			inner := newMemStore()
			fs := &FaultyStore{Inner: inner, FailAfter: failAfter, Err: errBoom}
			err := fs.InsertCompiledRun(ctx(), req)
			if failAfter == 1 {
				if !errors.Is(err, errBoom) {
					t.Fatalf("expected injected error, got %v", err)
				}
				if len(inner.snapshot().runs) != 0 || len(inner.snapshot().jobs) != 0 {
					t.Fatalf("faulted atomic enqueue leaked rows: %d runs, %d jobs", len(inner.runs), len(inner.jobs))
				}
				if _, ok := inner.deliveries["github/del-atomic"]; ok {
					t.Fatal("faulted atomic enqueue leaked the delivery claim")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error at failAfter=%d: %v", failAfter, err)
			}
			if len(inner.runs) != 1 {
				t.Fatalf("successful enqueue stored %d runs, want exactly 1", len(inner.runs))
			}
			if len(inner.jobs) != jobCount {
				t.Fatalf("successful enqueue stored %d jobs, want exactly %d", len(inner.jobs), jobCount)
			}
			if _, ok := inner.deliveries["github/del-atomic"]; !ok {
				t.Fatal("successful enqueue lost the delivery claim")
			}
		})
	}
}

// TestFaultInjectionAtomicEnqueueEveryStage sweeps the mid-enqueue stage
// hook across every write of a superseding atomic enqueue (the supersede
// cancellation plus 8 job rows plus the reservations): a failure after ANY
// staged write must leave the store byte-for-byte unchanged — the old run
// untouched, the new run absent, no audit rows, no quota movement — and only
// a fault beyond the last write lets the whole request commit.
func TestFaultInjectionAtomicEnqueueEveryStage(t *testing.T) {
	repo := "https://github.com/o/r.git"
	const jobCount = 8
	build := func() InsertCompiledRunRequest {
		jobs := map[string]model.Job{}
		for i := 0; i < jobCount; i++ {
			id := fmt.Sprintf("%032d", i)
			jobs[id] = model.Job{ID: id, RunID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", Key: fmt.Sprintf("job%d", i), RepoURL: repo, Status: model.StatusQueued, CreatedAt: time.Unix(2000+int64(i), 0).UTC()}
		}
		return InsertCompiledRunRequest{
			Run:          model.Run{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", Repo: repo, Status: model.StatusQueued, ConcurrencyGroup: "grp", CreatedAt: time.Unix(2000, 0).UTC()},
			Jobs:         jobs,
			Supersede:    &SupersedePolicy{Repo: repo, ConcurrencyGroup: "grp"},
			WebhookClaim: &WebhookClaim{Forge: "github", DeliveryID: "del-stage", RunID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad"},
			Quota:        &QuotaReservation{RepoKey: repo, JobCount: jobCount},
		}
	}
	seed := func(m *memStore) {
		old := compiledRunRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac", repo)
		old.Quota = &QuotaReservation{RepoKey: repo, JobCount: 1}
		if err := m.InsertCompiledRun(ctx(), old); err != nil {
			t.Fatal(err)
		}
		m.runs["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"] = model.Run{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", Repo: repo, ConcurrencyGroup: "grp", Status: model.StatusRunning, CreatedAt: time.Unix(1000, 0).UTC()}
	}
	// 1 supersede cancellation + 8 jobs = 9 staged writes.
	for stage := 1; stage <= jobCount+1; stage++ {
		t.Run(fmt.Sprintf("stage=%d", stage), func(t *testing.T) {
			inner := newMemStore()
			seed(inner)
			baseline := inner.snapshot()
			inner.enqueueFaultOps = stage
			inner.enqueueFaultErr = errBoom
			err := inner.InsertCompiledRun(ctx(), build())
			if !errors.Is(err, errBoom) {
				t.Fatalf("stage %d = %v, want injected error", stage, err)
			}
			if after := inner.snapshot(); !reflect.DeepEqual(after, baseline) {
				t.Fatalf("stage %d left partial state:\n before: %+v\n after:  %+v", stage, baseline, after)
			}
		})
	}
	// Without supersession the staged writes are exactly the job rows: a
	// failure on the 7th of 8 jobs must leave no run and no jobs — the
	// literal mid-enqueue case.
	t.Run("job7", func(t *testing.T) {
		inner := newMemStore()
		req := build()
		req.Supersede = nil
		inner.enqueueFaultOps = 7
		inner.enqueueFaultErr = errBoom
		if err := inner.InsertCompiledRun(ctx(), req); !errors.Is(err, errBoom) {
			t.Fatalf("mid-enqueue failure = %v, want injected error", err)
		}
		if len(inner.runs) != 0 || len(inner.jobs) != 0 {
			t.Fatalf("mid-enqueue failure leaked %d runs and %d jobs", len(inner.runs), len(inner.jobs))
		}
		if _, ok := inner.deliveries["github/del-stage"]; ok {
			t.Fatal("mid-enqueue failure leaked the webhook delivery claim")
		}
		if running, queued, _ := inner.QuotaCounts(ctx(), repo, ""); running != 0 || queued != 0 {
			t.Fatalf("mid-enqueue failure leaked quota counters %d/%d", running, queued)
		}
	})
	// A fault armed beyond the last write never fires: the request commits
	// completely and exactly once.
	inner := newMemStore()
	seed(inner)
	inner.enqueueFaultOps = jobCount + 2
	inner.enqueueFaultErr = errBoom
	if err := inner.InsertCompiledRun(ctx(), build()); err != nil {
		t.Fatalf("unfired stage fault failed the enqueue: %v", err)
	}
	if len(inner.jobs) != jobCount+1 {
		t.Fatalf("committed jobs = %d, want %d (old + new)", len(inner.jobs), jobCount+1)
	}
	if newRun, ok := inner.runs["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad"]; !ok || newRun.Status != model.StatusQueued {
		t.Fatalf("new run not committed: %+v ok=%v", newRun, ok)
	}
	old, _ := inner.GetJob(ctx(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac")
	if old.Status != model.StatusCancelled {
		t.Fatalf("superseded job status = %s, want cancelled", old.Status)
	}
	if prev, _ := inner.GetRun(ctx(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"); prev.Status != model.StatusCancelled {
		t.Fatalf("superseded run status = %s, want cancelled", prev.Status)
	}
}

// TestFaultInjectionReadsUnaffected proves injected faults never disturb
// read paths: reads pass through and report the same durable state.
func TestFaultInjectionReadsUnaffected(t *testing.T) {
	inner := newMemStore()
	seedRunAndJob(inner)
	fs := &FaultyStore{Inner: inner, FailAfter: 1, Err: errBoom}
	got, err := fs.GetRun(ctx(), testRun.ID)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.ID != testRun.ID {
		t.Fatalf("GetRun returned %q", got.ID)
	}
	jobs, err := fs.ListJobsByRun(ctx(), testRun.ID)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("ListJobsByRun: %v, %d jobs", err, len(jobs))
	}
	if _, ok, err := fs.HasCompletionReceipt(ctx(), testJob.ID, 1, testRunner.ID); err != nil || ok {
		t.Fatalf("HasCompletionReceipt: ok=%v err=%v", ok, err)
	}
	cost, energy, err := fs.RecentUsage(ctx(), time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("RecentUsage: %v", err)
	}
	if cost != 0 || energy != 0 {
		t.Fatalf("RecentUsage on empty store = %g/%g", cost, energy)
	}
	if _, ok, err := fs.GetDownstreamLink(ctx(), testJob.ID, "acme/child", "refs/heads/main"); err != nil || ok {
		t.Fatalf("GetDownstreamLink: ok=%v err=%v", ok, err)
	}
	if _, err := fs.GetArtifact(ctx(), "dddddddddddddddddddddddddddddddd"); err == nil {
		t.Fatal("GetArtifact on empty store must not succeed")
	}
	if digest, ok, err := fs.PendingSidecar(ctx(), testJob.ID, "bin", ArtifactSidecarKindSBOM); err != nil || ok || digest != "" {
		t.Fatalf("PendingSidecar on empty store = %q ok=%v err=%v", digest, ok, err)
	}
}
