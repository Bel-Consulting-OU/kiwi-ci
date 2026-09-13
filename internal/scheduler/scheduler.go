// Package scheduler implements the PostgreSQL-backed control plane. It
// operates on the storage.Store contract: the durable SQL rows are the source
// of truth, while the server keeps its in-memory maps only for dev mode.
//
// Leader semantics: exactly one instance may lease jobs or recover expired
// leases. Leadership is a session-level Postgres advisory lock held by the
// store on a dedicated connection; TryAcquireLeadership renews the claim and
// reports ownership, so a standby can observe promotion by polling IsLeader.
package scheduler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/kiwici/kiwi/internal/model"
	"github.com/kiwici/kiwi/internal/storage"
)

// ErrNotLeader is returned by leader-only operations when this instance does
// not hold the leadership advisory lock (a standby serving reads).
var ErrNotLeader = errors.New("scheduler: not leader")

// ErrNoJobs is returned by Lease when no job is currently available for the
// requesting runner.
var ErrNoJobs = errors.New("scheduler: no jobs available")

const (
	// DefaultLeaseDuration is the lease lifetime used when none is configured.
	DefaultLeaseDuration = 45 * time.Second
	// DefaultLeaderTTL is the soft renewal window for the leadership claim.
	DefaultLeaderTTL = 15 * time.Second
	// DefaultLeaderKey names the leadership lock slot shared by every
	// instance of the same control plane.
	DefaultLeaderKey = "kiwi-scheduler"
)

// Scheduler is the control-plane scheduling contract. Implementations operate
// on a storage.Store and must be safe for concurrent use.
type Scheduler interface {
	Enqueue(ctx context.Context, run model.Run, jobs map[string]model.Job, deps map[string][]string, cancelInProgress bool) error
	Lease(ctx context.Context, runnerID string, now time.Time) (*model.Job, string /*raw token*/, time.Time /*expires*/, error)
	Heartbeat(ctx context.Context, jobID, runnerID string, tokenHash []byte, generation int64, expiresAt time.Time) (bool /*cancelled*/, error)
	Complete(ctx context.Context, jobID string, generation int64, runnerID string, status model.Status, errMsg string, outputs map[string]string, resultHash string) error
	CancelRun(ctx context.Context, runID, reason string) error
	RecoverExpired(ctx context.Context, now time.Time) error
}

// DBScheduler schedules against a storage.Store. The token generator and
// hash are injectable so tests can assert exact token handling; production
// uses a crypto/rand hex token hashed with SHA-256 (the server layer HMACs it
// with its lease key before persisting).
type DBScheduler struct {
	Store         storage.Store
	LeaseDuration time.Duration
	NewToken      func() (string, error)
	HashToken     func(raw string) []byte

	// LeaderKey names the leadership advisory-lock slot shared by all
	// instances of this control plane.
	LeaderKey string
	// LeaderTTL is the soft renewal window for the leadership claim.
	LeaderTTL time.Duration

	// leader is true while this instance holds the leadership claim.
	leader bool
	// initErr records a leadership acquisition failure at construction.
	initErr error
}

// NewDB constructs a DBScheduler backed by store and attempts to acquire the
// leadership claim once. A hard store failure is recorded in InitErr; losing
// the claim to another live leader is not an error — the instance starts as a
// standby and can be promoted later (Server.Maintain polls IsLeader).
func NewDB(store storage.Store, leaseDur time.Duration, newToken func() (string, error), hashToken func(raw string) []byte) *DBScheduler {
	if leaseDur <= 0 {
		leaseDur = DefaultLeaseDuration
	}
	if newToken == nil {
		newToken = defaultToken
	}
	if hashToken == nil {
		hashToken = func(raw string) []byte {
			sum := sha256.Sum256([]byte(raw))
			return sum[:]
		}
	}
	s := &DBScheduler{
		Store:         store,
		LeaseDuration: leaseDur,
		NewToken:      newToken,
		HashToken:     hashToken,
		LeaderKey:     DefaultLeaderKey,
		LeaderTTL:     DefaultLeaderTTL,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := store.TryAcquireLeadership(ctx, s.LeaderKey, s.LeaderTTL)
	if err != nil {
		s.initErr = err
	} else {
		s.leader = got
	}
	return s
}

// InitErr reports a leadership acquisition failure at construction time.
// Callers should refuse to start on a hard store failure but may continue as
// a standby when the claim was simply lost to another live leader.
func (s *DBScheduler) InitErr() error { return s.initErr }

// IsLeader renews (or takes) the leadership claim and reports whether this
// instance currently holds it. A false result means another instance is the
// leader; a store error is logged and reported as not-leader.
func (s *DBScheduler) IsLeader(ctx context.Context) bool {
	if s.Store == nil {
		return false
	}
	got, err := s.Store.TryAcquireLeadership(ctx, s.LeaderKey, s.LeaderTTL)
	if err != nil {
		log.Printf("scheduler: leadership check failed: %v", err)
		return false
	}
	s.leader = got
	return got
}

// Enqueue inserts a run and its compiled jobs, then applies concurrency-group
// supersession when requested: non-terminal runs sharing the same repository
// and concurrency group are cancelled the same way the in-memory scheduler's
// cancelRunLocked does. deps carries the same dependency edges already
// embedded in each job's Needs field.
func (s *DBScheduler) Enqueue(ctx context.Context, run model.Run, jobs map[string]model.Job, deps map[string][]string, cancelInProgress bool) error {
	if err := s.Store.InsertRun(ctx, run); err != nil {
		return fmt.Errorf("scheduler: insert run: %w", err)
	}
	for id, j := range jobs {
		if err := s.Store.InsertJob(ctx, j); err != nil {
			return fmt.Errorf("scheduler: insert job %s: %w", id, err)
		}
	}
	if cancelInProgress && run.ConcurrencyGroup != "" {
		runs, err := s.Store.ListRuns(ctx, 10000)
		if err != nil {
			return fmt.Errorf("scheduler: list runs for supersession: %w", err)
		}
		for _, old := range runs {
			if old.ID == run.ID || old.Repo != run.Repo || old.ConcurrencyGroup != run.ConcurrencyGroup || old.Status.Terminal() {
				continue
			}
			if _, err := s.Store.CancelRunJobs(ctx, old.ID, "superseded by run "+run.ID); err != nil {
				log.Printf("scheduler: supersede run %s: %v", old.ID, err)
			}
		}
	}
	return nil
}

// Lease claims the best available queued job for runnerID. It is leader-only.
// Candidate selection mirrors the in-memory next(): dependency readiness and
// conditions via DependencyOutcome/ConditionAllows, label matching,
// environment concurrency, then priority (downstream depth) and age. The raw
// lease token is returned exactly once; only its hash is persisted.
func (s *DBScheduler) Lease(ctx context.Context, runnerID string, now time.Time) (*model.Job, string, time.Time, error) {
	if !s.IsLeader(ctx) {
		return nil, "", time.Time{}, ErrNotLeader
	}
	ri, err := s.Store.GetRunner(ctx, runnerID)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	if ri.Capacity < 1 {
		ri.Capacity = 1
	}
	if len(ri.ActiveJobs) >= ri.Capacity {
		return nil, "", time.Time{}, ErrNoJobs
	}
	queued, err := s.Store.ListQueuedJobs(ctx)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	sort.Slice(queued, func(i, j int) bool {
		if queued[i].Priority != queued[j].Priority {
			return queued[i].Priority > queued[j].Priority
		}
		return queued[i].CreatedAt.Before(queued[j].CreatedAt)
	})
	runJobs := map[string]map[string]model.Job{}
	for _, candidate := range queued {
		if !satisfiesLabels(ri.Labels, candidate.RequiredLabels) {
			continue
		}
		jobs, ok := runJobs[candidate.RunID]
		if !ok {
			all, err := s.Store.ListJobsByRun(ctx, candidate.RunID)
			if err != nil {
				return nil, "", time.Time{}, err
			}
			jobs = make(map[string]model.Job, len(all))
			for _, j := range all {
				jobs[j.ID] = j
			}
			runJobs[candidate.RunID] = jobs
		}
		if EnvironmentAtCapacity(candidate, jobs) {
			continue
		}
		ready, outcome := DependencyOutcome(candidate.Needs, nil, func(id string) (model.Status, bool) {
			d, ok := jobs[id]
			return d.Status, ok
		})
		if !ready || (outcome != model.StatusSuccess && !ConditionAllows(candidate.Condition, outcome)) {
			continue
		}
		raw, err := s.NewToken()
		if err != nil {
			return nil, "", time.Time{}, err
		}
		expires := LeaseExpiry(now, s.LeaseDuration)
		generation := candidate.LeaseGeneration + 1
		j, err := s.Store.AcquireLease(ctx, candidate.ID, runnerID, s.HashToken(raw), generation, expires)
		if errors.Is(err, storage.ErrLeaseConflict) {
			// Another leader raced us (or the row moved); try the next candidate.
			continue
		}
		if err != nil {
			return nil, "", time.Time{}, err
		}
		j.NeedsOutputs = CollectNeedsOutputs(candidate, jobs)
		ri.ActiveJobs = appendUnique(ri.ActiveJobs, j.ID)
		ri.Busy = len(ri.ActiveJobs) >= ri.Capacity
		ri.CurrentJob = ""
		if len(ri.ActiveJobs) > 0 {
			ri.CurrentJob = ri.ActiveJobs[0]
		}
		ri.LastSeen = now
		if err := s.Store.UpsertRunner(ctx, ri); err != nil {
			// The lease is already durably held; a runner bookkeeping failure
			// must not strand the job.
			log.Printf("scheduler: update runner %s after lease: %v", runnerID, err)
		}
		return &j, raw, expires, nil
	}
	return nil, "", time.Time{}, ErrNoJobs
}

// Heartbeat extends the job's lease and reports whether the job was
// cancelled while running. The token hash is carried for contract symmetry;
// lease authorization (runner + generation) is enforced by the store.
func (s *DBScheduler) Heartbeat(ctx context.Context, jobID, runnerID string, tokenHash []byte, generation int64, expiresAt time.Time) (bool, error) {
	_ = tokenHash
	j, err := s.Store.GetJob(ctx, jobID)
	if err != nil {
		return false, err
	}
	if j.Status == model.StatusCancelled {
		return true, nil
	}
	if err := s.Store.HeartbeatLease(ctx, jobID, runnerID, generation, expiresAt); err != nil {
		if errors.Is(err, storage.ErrLeaseConflict) {
			// A conflict can mean a concurrent cancellation: surface it so the
			// runner stops instead of retrying the lease.
			if cur, gerr := s.Store.GetJob(ctx, jobID); gerr == nil && cur.Status == model.StatusCancelled {
				return true, nil
			}
		}
		return false, err
	}
	if ri, rerr := s.Store.GetRunner(ctx, runnerID); rerr == nil {
		ri.LastSeen = time.Now().UTC()
		_ = s.Store.UpsertRunner(ctx, ri)
	}
	return false, nil
}

// Complete applies a runner completion through the store's transactional
// CompleteJob, passing the canonical completion receipt for idempotent replay.
func (s *DBScheduler) Complete(ctx context.Context, jobID string, generation int64, runnerID string, status model.Status, errMsg string, outputs map[string]string, resultHash string) error {
	receipt := model.CompletionReceipt{JobID: jobID, Generation: generation, RunnerID: runnerID, ResultHash: resultHash}
	return s.Store.CompleteJob(ctx, jobID, generation, runnerID, status, errMsg, outputs, receipt)
}

// CancelRun cancels every non-terminal job of the run and the run itself via
// the store's transactional CancelRunJobs. The audit event is emitted by the
// server's audit funnel, which routes to the same store in DB mode.
func (s *DBScheduler) CancelRun(ctx context.Context, runID, reason string) error {
	if _, err := s.Store.CancelRunJobs(ctx, runID, reason); err != nil {
		return err
	}
	return nil
}

// RecoverExpired requeues or fails jobs whose leases expired, mirrors the
// in-memory recoverLeasesLocked (infrastructure retry budget respected),
// re-evaluates dependents, and recomputes run statuses. Leader-only.
func (s *DBScheduler) RecoverExpired(ctx context.Context, now time.Time) error {
	if !s.IsLeader(ctx) {
		return ErrNotLeader
	}
	runs, err := s.Store.ListRuns(ctx, 10000)
	if err != nil {
		return fmt.Errorf("scheduler: list runs: %w", err)
	}
	for _, run := range runs {
		all, err := s.Store.ListJobsByRun(ctx, run.ID)
		if err != nil {
			log.Printf("scheduler: recover run %s: %v", run.ID, err)
			continue
		}
		jobs := make(map[string]model.Job, len(all))
		for _, j := range all {
			jobs[j.ID] = j
		}
		changed := false
		for _, j := range all {
			if j.Status != model.StatusRunning {
				continue
			}
			if j.LeaseExpiresAt != nil && j.LeaseExpiresAt.After(now) {
				continue
			}
			runnerID := j.LeaseRunnerID
			if j.Attempts <= j.MaxInfraRetries {
				j.Status = model.StatusQueued
				j.Error = "runner lease expired; retrying"
				s.appendAudit(ctx, "job.lease_expired", "scheduler", j.RunID, j.ID, "job requeued after lost runner", map[string]string{"job": j.Key})
			} else {
				fin := now
				j.Status = model.StatusFailure
				j.Error = "runner lease expired and infrastructure retry budget exhausted"
				j.FinishedAt = &fin
				s.appendAudit(ctx, "job.lost_runner", "scheduler", j.RunID, j.ID, j.Error, map[string]string{"job": j.Key})
			}
			j.LeaseRunnerID = ""
			j.LeaseTokenHash = nil
			j.LeaseExpiresAt = nil
			if err := s.Store.UpdateJob(ctx, j); err != nil {
				log.Printf("scheduler: recover job %s: %v", j.ID, err)
				continue
			}
			if err := s.Store.ReleaseRunnerJob(ctx, runnerID, j.ID, model.StatusFailure); err != nil && !errors.Is(err, storage.ErrNotFound) {
				log.Printf("scheduler: release runner %s after recovery: %v", runnerID, err)
			}
			jobs[j.ID] = j
			changed = true
		}
		if changed {
			s.recomputeDependents(ctx, jobs)
			s.recomputeRun(ctx, run, jobs)
		}
	}
	return nil
}

// recomputeDependents re-evaluates dependency outcomes for non-terminal jobs
// after a recovery changed an upstream state, mirroring scheduleStateLocked's
// dependency and blocking pass.
func (s *DBScheduler) recomputeDependents(ctx context.Context, jobs map[string]model.Job) {
	for _, j := range jobs {
		if j.Status != model.StatusQueued && j.Status != model.StatusWaitingApproval {
			continue
		}
		ready, outcome := DependencyOutcome(j.Needs, nil, func(id string) (model.Status, bool) {
			d, ok := jobs[id]
			return d.Status, ok
		})
		if !ready || j.DependencyStatus == outcome {
			continue
		}
		j.DependencyStatus = outcome
		if outcome != model.StatusSuccess && !ConditionAllows(j.Condition, outcome) {
			fin := time.Now().UTC()
			j.Status = model.StatusBlocked
			j.Error = "dependency failed"
			j.FinishedAt = &fin
			s.appendAudit(ctx, "job.blocked", "scheduler", j.RunID, j.ID, "dependency failed", map[string]string{"job": j.Key})
		}
		if err := s.Store.UpdateJob(ctx, j); err != nil {
			log.Printf("scheduler: recompute dependent %s: %v", j.ID, err)
		}
	}
}

// recomputeRun mirrors refreshRunLocked from the job states of one run.
func (s *DBScheduler) recomputeRun(ctx context.Context, run model.Run, jobs map[string]model.Job) {
	if run.Status == model.StatusCancelled {
		return
	}
	var total, terminal int
	var anyRunning, anyFailure, anyCancelled, anyWaiting bool
	var firstStart, lastFinish *time.Time
	for _, j := range jobs {
		total++
		if j.StartedAt != nil && (firstStart == nil || j.StartedAt.Before(*firstStart)) {
			t := *j.StartedAt
			firstStart = &t
		}
		if j.Status.Terminal() {
			terminal++
			if j.FinishedAt != nil && (lastFinish == nil || j.FinishedAt.After(*lastFinish)) {
				t := *j.FinishedAt
				lastFinish = &t
			}
		}
		switch j.Status {
		case model.StatusRunning:
			anyRunning = true
		case model.StatusFailure, model.StatusBlocked:
			anyFailure = true
		case model.StatusCancelled:
			anyCancelled = true
		case model.StatusWaitingApproval:
			anyWaiting = true
		}
	}
	if total == 0 {
		return
	}
	switch {
	case terminal == total:
		switch {
		case anyFailure:
			run.Status = model.StatusFailure
		case anyCancelled:
			run.Status = model.StatusCancelled
		default:
			run.Status = model.StatusSuccess
		}
		run.FinishedAt = lastFinish
		if run.FinishedAt == nil {
			n := time.Now().UTC()
			run.FinishedAt = &n
		}
	case anyRunning:
		run.Status = model.StatusRunning
	case anyWaiting:
		run.Status = model.StatusWaitingApproval
	default:
		run.Status = model.StatusQueued
	}
	if run.StartedAt == nil && firstStart != nil {
		run.StartedAt = firstStart
	}
	if err := s.Store.UpdateRunStatus(ctx, run.ID, run.Status, run.StartedAt, run.FinishedAt); err != nil {
		log.Printf("scheduler: recompute run %s: %v", run.ID, err)
	}
}

// appendAudit writes one audit event through the store. Failures are logged,
// never silently dropped, per the DB-mode audit policy.
func (s *DBScheduler) appendAudit(ctx context.Context, action, actor, runID, jobID, msg string, meta map[string]string) {
	id, err := newID()
	if err != nil {
		log.Printf("scheduler: dropping %q audit event: %v", action, err)
		return
	}
	e := model.AuditEvent{ID: id, Action: action, Actor: actor, RunID: runID, JobID: jobID, Message: msg, Metadata: meta, CreatedAt: time.Now().UTC()}
	if err := s.Store.AppendAudit(ctx, e); err != nil {
		log.Printf("scheduler: audit %q failed: %v", action, err)
	}
}

// satisfiesLabels reports whether every required label is present.
func satisfiesLabels(have, need []string) bool {
	m := map[string]bool{}
	for _, x := range have {
		m[x] = true
	}
	for _, x := range need {
		if !m[x] {
			return false
		}
	}
	return true
}

func appendUnique(in []string, v string) []string {
	for _, x := range in {
		if x == v {
			return in
		}
	}
	return append(in, v)
}

// defaultToken generates a 256-bit crypto/rand token, hex encoded.
func defaultToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// newID returns a 128-bit crypto/rand identifier hex-encoded, matching the
// canonical control-plane identifier format.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
