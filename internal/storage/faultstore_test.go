package storage

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

var errBoom = errors.New("injected storage failure")

// memSnapshot is a comparable picture of every durable collection in a
// memStore, used to prove a faulted operation left no partial write.
type memSnapshot struct {
	runs         map[string]model.Run
	jobs         map[string]model.Job
	runners      map[string]model.Runner
	receipts     map[string]model.CompletionReceipt
	auditLen     int
	logsLen      int
	artifactsLen int
	reportsLen   int
	deliveries   map[string]string
	outbox       []OutboxItem
	schedules    map[string]Schedule
	occurrences  map[string]map[time.Time]string
	deployments  []model.Deployment
	snapshots    []model.SnapshotRecord
	jobContracts map[string]map[string]ArtifactContract
}

func (m *memStore) snapshot() memSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return memSnapshot{
		runs:         cloneRuns(m.runs),
		jobs:         cloneJobs(m.jobs),
		runners:      cloneRunners(m.runners),
		receipts:     cloneReceipts(m.receipts),
		auditLen:     len(m.audit),
		logsLen:      len(m.logs),
		artifactsLen: len(m.artifacts),
		reportsLen:   len(m.reports),
		deliveries:   cloneDeliveries(m.deliveries),
		outbox:       append([]OutboxItem(nil), m.outbox...),
		schedules:    cloneSchedules(m.schedules),
		occurrences:  cloneOccurrences(m.occurrences),
		deployments:  append([]model.Deployment(nil), m.deployments...),
		snapshots:    append([]model.SnapshotRecord(nil), m.snapshots...),
		jobContracts: cloneJobContracts(m.contracts),
	}
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
type opCase struct {
	name  string
	setup func(*memStore)
	call  func(Store) error
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
			name:  "SetQueueReasons",
			setup: seedRunAndJob,
			call: func(s Store) error {
				return s.(QueueReasonStore).SetQueueReasons(ctx(), map[string]string{testJob.ID: "WAITING_DEPENDENCY"})
			},
		},
	}
}

// TestFaultInjectionEveryMutationEveryPoint injects a failure at every
// failure point of every mutating store operation and asserts the failed
// operation returned the injected error without leaving any partial write
// behind in the underlying store.
func TestFaultInjectionEveryMutationEveryPoint(t *testing.T) {
	for _, op := range faultOps() {
		for failAfter := 0; failAfter <= 3; failAfter++ {
			t.Run(fmt.Sprintf("%s/failAfter=%d", op.name, failAfter), func(t *testing.T) {
				inner := newMemStore()
				op.setup(inner)
				baseline := inner.snapshot()

				fs := &FaultyStore{Inner: inner, FailAfter: failAfter, Err: errBoom}
				err := op.call(fs)
				after := inner.snapshot()

				// Each operation is a single mutating call, so it faults
				// exactly when FailAfter == 1.
				if failAfter == 1 {
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

// TestFaultInjectionSequenceNoPartialLeak replays the scheduler enqueue
// shape (InsertRun + one InsertJob per job) through a faulted store and
// checks that every failure point yields exactly the durable prefix of
// successful calls — memory never diverges from what was committed.
func TestFaultInjectionSequenceNoPartialLeak(t *testing.T) {
	const jobCount = 3
	jobs := make([]model.Job, jobCount)
	for i := range jobs {
		jobs[i] = model.Job{ID: fmt.Sprintf("j%d", i), RunID: testRun.ID, Key: fmt.Sprintf("job%d", i), Status: model.StatusQueued, CreatedAt: time.Unix(2000+int64(i), 0).UTC()}
	}
	enqueueShape := func(s Store) error {
		if err := s.InsertRun(ctx(), testRun); err != nil {
			return err
		}
		for _, j := range jobs {
			if err := s.InsertJob(ctx(), j); err != nil {
				return err
			}
		}
		return nil
	}
	for failAfter := 1; failAfter <= jobCount+2; failAfter++ {
		t.Run(fmt.Sprintf("failAfter=%d", failAfter), func(t *testing.T) {
			inner := newMemStore()
			fs := &FaultyStore{Inner: inner, FailAfter: failAfter, Err: errBoom}
			err := enqueueShape(fs)

			// Replay the successful prefix on a pristine store: the
			// faulted store's memory must match it exactly.
			// Replay only the successful prefix (calls 1..failAfter-1).
			control := newMemStore()
			for i := 1; i < failAfter && i <= jobCount+1; i++ {
				switch i {
				case 1:
					_ = control.InsertRun(ctx(), testRun)
				default:
					_ = control.InsertJob(ctx(), jobs[i-2])
				}
			}
			got := inner.snapshot()
			want := control.snapshot()
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("faulted store memory diverges from the durable prefix:\n got:  %+v\n want: %+v", got, want)
			}
			if failAfter >= 1 && failAfter <= jobCount+1 {
				if !errors.Is(err, errBoom) {
					t.Fatalf("expected injected error at call %d, got %v", failAfter, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
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
}
