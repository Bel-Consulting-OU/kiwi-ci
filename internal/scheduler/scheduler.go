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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
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

	// Quota limits (0 = unlimited) are enforced INSIDE the atomic lease's
	// queued->running transition, so a lease can never push the running
	// count past the configured concurrency. The server installs them
	// through SetQuotaLimits after wiring the store (config is applied
	// after SwitchToDB) and re-applies them on every lease.
	quotaMu         sync.Mutex
	repoConcurrency float64
	teamConcurrency float64

	// leader is true while this instance holds the leadership claim.
	// Access is atomic: Lease and IsLeader can run concurrently from
	// runner poll goroutines.
	leader atomic.Bool
	// initErr records a leadership acquisition failure at construction.
	initErr error
}

// SetQuotaLimits installs the repo/team concurrency limits enforced by the
// atomic lease's conditional queued->running transition (0 = unlimited).
// Safe for concurrent use with Lease.
func (s *DBScheduler) SetQuotaLimits(repo, team float64) {
	s.quotaMu.Lock()
	s.repoConcurrency = repo
	s.teamConcurrency = team
	s.quotaMu.Unlock()
}

// quotaLimits returns the current repo/team concurrency limits.
func (s *DBScheduler) quotaLimits() (repo, team float64) {
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	return s.repoConcurrency, s.teamConcurrency
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
		s.leader.Store(got)
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
	s.leader.Store(got)
	return got
}

// Enqueue inserts a run, its compiled jobs and their dependency edges
// through the store's ONE atomic enqueue transaction
// (storage.InsertCompiledRun): the run row, every job row, the dependency
// edges, the supersession cancellations and their dependent/run
// recomputation commit together or not at all.
//
// Supersession is NOT applied as a follow-up pass: when cancelInProgress is
// set the request carries an in-transaction storage.SupersedePolicy, so the
// store resolves the conflicting non-terminal runs of the same repository
// and concurrency group inside the transaction and cancels them — jobs
// terminal-cancelled with leases cleared, runner slots and quota released,
// dependents recomputed — in the same commit that publishes the new run.
// Concurrent superseding enqueues therefore serialize on the store's
// per-(repository, group) transaction lock: exactly one run survives
// non-terminal and no partial state is ever observable. A store without the
// atomic contract fails closed instead of falling back to the sequential
// run/job inserts.
//
// Queue deadlines are materialized here: a job whose QueueDeadline is unset
// but whose compiled payload declares a queue_timeout gets its deadline
// (CreatedAt + timeout) persisted with the insert, so the deadline is set at
// enqueue for every DB-mode job.
func (s *DBScheduler) Enqueue(ctx context.Context, run model.Run, jobs map[string]model.Job, deps map[string][]string, cancelInProgress bool) error {
	rs, ok := s.Store.(storage.RunEnqueueStore)
	if !ok {
		return errors.New("scheduler: store does not support the atomic enqueue transaction")
	}
	for id, j := range jobs {
		if j.QueueDeadline == nil {
			if to := queueTimeoutFromPayload(j); to > 0 {
				dl := j.CreatedAt.Add(to)
				j.QueueDeadline = &dl
			}
		}
		jobs[id] = j
	}
	req := storage.InsertCompiledRunRequest{
		Run:  run,
		Jobs: jobs,
		Deps: deps,
	}
	// The supersede policy carries the CANONICAL repository identity of the
	// run (stored RepoID, legacy URL + full-name fallback), not the clone
	// URL: HTTPS and SSH submissions of one repository must supersede, and
	// the SQL store's advisory lock and prior-run selection key on the same
	// canonical value.
	if cancelInProgress {
		if repoID := storage.RepoIDForRun(run); repoID != "" && run.ConcurrencyGroup != "" {
			req.Supersede = &storage.SupersedePolicy{RepoID: repoID, ConcurrencyGroup: run.ConcurrencyGroup}
		}
	}
	return rs.InsertCompiledRun(ctx, req)
}

// Lease claims the best available queued job for runnerID. It is leader-only.
// Candidate selection uses the ONE shared lease predicate
// (storage.LeasePredicate): admission state, labels, canonical repository
// ACL, runtime capability, the enforced-policy runtime grant, placement
// regions and environment concurrency. Dependency readiness and queue
// deadlines are evaluated on top, then priority (downstream depth) and age.
// The raw lease token is returned exactly once; only its hash is persisted.
//
// Every scheduling attribute is resolved LIVE: when the runner has a linked
// profile the profile's current labels/region/repo ACL/capabilities/capacity/
// rates are used, not the registration snapshot.
func (s *DBScheduler) Lease(ctx context.Context, runnerID string, now time.Time) (*model.Job, string, time.Time, error) {
	if !s.IsLeader(ctx) {
		return nil, "", time.Time{}, ErrNotLeader
	}
	ri, err := s.Store.GetRunner(ctx, runnerID)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	// Profile semantics: capacity 0 means the runner takes no work (a
	// runner without a linked profile registers capacity 0). The legacy
	// clamp to 1 is gone — zero is meaningful now.
	eff := s.effectiveRunner(ctx, ri)
	if eff.Capacity <= 0 {
		return nil, "", time.Time{}, ErrNoJobs
	}
	if len(eff.ActiveJobs) >= eff.Capacity {
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
	repoConcurrency, teamConcurrency := s.quotaLimits()
	runJobs := map[string]map[string]model.Job{}
	envJobs := map[string][]model.Job{}
	for _, candidate := range queued {
		// Queue-timeout expiry: a candidate whose queue deadline has passed
		// is never leased; RecoverExpired cancels it. Both the atomic-lease
		// and the plain-lease branches below share this gate.
		if dl := QueueDeadlineFor(candidate); dl != nil && !dl.After(now) {
			continue
		}
		// The shared predicate is the same decision the SQL claim and the
		// in-memory stores apply: admission state (disabled/draining,
		// capacity), labels, canonical repo ACL, runtime capability,
		// enforced-policy runtime grant, placement regions and environment
		// concurrency.
		envRunning := 0
		if candidate.Environment != "" && candidate.EnvironmentConcurrency > 0 {
			// The environment concurrency key is the CANONICAL repository
			// identity plus the environment name (LeaseClaim.EnvKey): the
			// same repository submitted via HTTPS and via SSH shares one
			// slot pool, and a same-named environment on another repository
			// never shares it.
			repoID := storage.RepoIDForJob(candidate)
			key := repoID + "\x00" + candidate.Environment
			active, ok := envJobs[key]
			if !ok {
				all, err := s.Store.ListJobsByEnvironment(ctx, repoID, candidate.Environment)
				if err != nil {
					return nil, "", time.Time{}, err
				}
				envJobs[key] = all
				active = all
			}
			for _, other := range active {
				if other.ID != candidate.ID && other.Status == model.StatusRunning {
					envRunning++
				}
			}
		}
		policyRuntimes, policyEnforced := storage.LeasePolicyRuntimes(candidate)
		if !(storage.LeasePredicate{
			Runner:         eff,
			Job:            candidate,
			EnvRunning:     envRunning,
			PolicyEnforced: policyEnforced,
			PolicyRuntimes: policyRuntimes,
		}).Allows() {
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
		claim := storage.LeaseClaim{
			JobID:                  candidate.ID,
			RunnerID:               runnerID,
			TokenHash:              s.HashToken(raw),
			Generation:             generation,
			ExpiresAt:              expires,
			RunnerCapacity:         eff.Capacity,
			Runtime:                storage.JobRuntime(candidate),
			CanonRepoID:            storage.RepoIDForJob(candidate),
			RepoFullName:           candidate.RepoFullName,
			RequiredLabels:         candidate.RequiredLabels,
			PlacementRegions:       candidate.PlacementRegions,
			Environment:            candidate.Environment,
			EnvironmentConcurrency: candidate.EnvironmentConcurrency,
			RepoConcurrency:        repoConcurrency,
			TeamConcurrency:        teamConcurrency,
		}
		// Capacity-atomic lease: the job claim, every predicate above and
		// the runner's active-jobs append happen in ONE transaction, so two
		// concurrent leases can never exceed the runner's capacity, bypass
		// a concurrent disable/drain or overrun environment/quota limits.
		// The separate UpsertRunner afterwards is skipped because the store
		// already updated the runner row.
		if as, ok := s.Store.(storage.AtomicLeaseStore); ok {
			j, err := as.AcquireLeaseAtomic(ctx, claim)
			switch {
			case err == nil:
				j.NeedsOutputs = CollectNeedsOutputs(candidate, jobs)
				return &j, raw, expires, nil
			case errors.Is(err, storage.ErrLeaseConflict):
				continue
			case errors.Is(err, storage.ErrNoCapacity),
				errors.Is(err, storage.ErrEnvConcurrency),
				errors.Is(err, storage.ErrQuotaExceeded):
				// A predicate lost a race (filled capacity slot, taken
				// environment slot, exhausted quota) or this candidate is
				// not eligible for this runner: try the next candidate.
				continue
			default:
				return nil, "", time.Time{}, err
			}
		}
		j, err := s.Store.AcquireLease(ctx, candidate.ID, runnerID, s.HashToken(raw), generation, expires)
		if errors.Is(err, storage.ErrLeaseConflict) {
			// Another leader raced us (or the row moved); try the next candidate.
			continue
		}
		if err != nil {
			return nil, "", time.Time{}, err
		}
		// The plain-lease fallback persists no rates (its signature has no
		// rate source): freeze the live rates on the returned job and
		// persist them so completion accounting stays identical to the
		// atomic path.
		j.CostRate = eff.CostPerHour
		j.PowerWatts = eff.PowerWatts
		if j.StartedAt == nil {
			j.StartedAt = &now
		}
		j.NeedsOutputs = CollectNeedsOutputs(candidate, jobs)
		if err := s.Store.UpdateJob(ctx, j); err != nil {
			log.Printf("scheduler: persist frozen rates for %s: %v", j.ID, err)
		}
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

// effectiveRunner resolves the runner's LIVE scheduling view at lease time:
// when a profile is linked to the runner's certificate serial, the profile's
// current labels/region/repo ACL/capabilities/capacity/rates replace the
// registration snapshot, so a profile edit takes effect on the next lease.
// Stores without a profile contract (or an unlinked runner) return the
// snapshot unchanged; the atomic claim independently fails closed on a
// linked-but-missing profile.
func (s *DBScheduler) effectiveRunner(ctx context.Context, ri model.Runner) model.Runner {
	ps, ok := s.Store.(storage.ProfileStore)
	if !ok || strings.TrimSpace(ri.CertSerial) == "" {
		return ri
	}
	p, found, err := ps.ProfileForSerial(ctx, ri.CertSerial)
	if err != nil || !found {
		return ri
	}
	return storage.ResolveRunnerProfile(ri, p, true)
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

// CancelJobsByRunner is the runner disable kill switch: it invalidates every
// active lease the runner holds in one pass. Each running job either
// requeues (the infrastructure retry budget still available) or cancels;
// lease fields are cleared so a stale lease token is dead, the runner's
// counters are released, dependent jobs and run statuses are recomputed, and
// audit events are emitted through the store. It returns the number of
// invalidated leases.
//
// The requeue/exhaustion decision consumes the SAME attempt count as
// RecoverExpired: attempts increment exactly once per lease (see
// storage.AcquireLeaseAtomic / AcquireLease), so a lease recovered here is
// not charged a second attempt — the budget compares the job's attempt
// count, it does not manufacture a new one.
func (s *DBScheduler) CancelJobsByRunner(ctx context.Context, runnerID, reason string) (int, error) {
	if runnerID == "" {
		return 0, fmt.Errorf("scheduler: cancel jobs by runner: empty runner id")
	}
	rj, ok := s.Store.(storage.RunnerJobStore)
	if !ok {
		return 0, fmt.Errorf("scheduler: store does not support listing jobs by runner")
	}
	jobs, err := rj.ListJobsByRunner(ctx, runnerID)
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	affected := map[string]map[string]model.Job{}
	count := 0
	var firstErr error
	for _, j := range jobs {
		if j.Status != model.StatusRunning {
			continue
		}
		// Same decision RecoverExpired makes from the lease-time increment:
		// no extra attempts++ here, attempts stay equal to leases/executions.
		if j.Attempts <= j.MaxInfraRetries {
			j.Status = model.StatusQueued
			j.Error = reason + "; retrying"
			s.appendAudit(ctx, "job.runner_disabled_requeued", "admin", j.RunID, j.ID, reason, map[string]string{"job": j.Key, "runner": runnerID})
		} else {
			fin := now
			j.Status = model.StatusCancelled
			j.Error = reason
			j.FinishedAt = &fin
			s.appendAudit(ctx, "job.runner_disabled_cancelled", "admin", j.RunID, j.ID, reason, map[string]string{"job": j.Key, "runner": runnerID})
		}
		j.LeaseRunnerID = ""
		j.LeaseTokenHash = nil
		j.LeaseExpiresAt = nil
		if err := s.Store.UpdateJob(ctx, j); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			log.Printf("scheduler: kill switch: update job %s: %v", j.ID, err)
			continue
		}
		if err := s.Store.ReleaseRunnerJob(ctx, runnerID, j.ID, model.StatusFailure); err != nil && !errors.Is(err, storage.ErrNotFound) {
			log.Printf("scheduler: kill switch: release runner %s job %s: %v", runnerID, j.ID, err)
		}
		count++
		if affected[j.RunID] == nil {
			affected[j.RunID] = map[string]model.Job{}
		}
		affected[j.RunID][j.ID] = j
	}
	for runID := range affected {
		all, err := s.Store.ListJobsByRun(ctx, runID)
		if err != nil {
			log.Printf("scheduler: kill switch: list run %s jobs: %v", runID, err)
			continue
		}
		jobs := make(map[string]model.Job, len(all))
		for _, j := range all {
			jobs[j.ID] = j
		}
		s.recomputeDependents(ctx, jobs)
		if run, err := s.Store.GetRun(ctx, runID); err == nil {
			s.recomputeRun(ctx, run, jobs)
		}
	}
	return count, firstErr
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
			// Queue-timeout expiry: a queued (or approval-waiting) job past
			// its queue deadline is cancelled terminally, independent of its
			// attempt count, and dependents are recomputed below. The job's
			// reserved queued quota slot is released in the same pass: a
			// timed-out job never runs, so leaving the reservation behind
			// would permanently shrink the repository/team queue depth.
			if j.Status == model.StatusQueued || j.Status == model.StatusWaitingApproval {
				dl := QueueDeadlineFor(j)
				if dl == nil || dl.After(now) {
					continue
				}
				fin := now
				j.Status = model.StatusCancelled
				j.Error = "queue timeout"
				j.FinishedAt = &fin
				j.LeaseRunnerID = ""
				j.LeaseTokenHash = nil
				j.LeaseExpiresAt = nil
				s.appendAudit(ctx, "job.queue_timeout", "scheduler", j.RunID, j.ID, "job cancelled after queue deadline", map[string]string{"job": j.Key})
				if err := s.Store.UpdateJob(ctx, j); err != nil {
					log.Printf("scheduler: expire queue deadline for job %s: %v", j.ID, err)
					continue
				}
				s.releaseQueuedQuota(ctx, j)
				jobs[j.ID] = j
				changed = true
				continue
			}
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

// releaseQueuedQuota returns a queue-timeout-cancelled job's reserved queued
// slot to the repository/team quota counters, using the SAME key derivation
// the enqueue reservation used. Stores without the counter contract (legacy
// fakes) are tolerated. Failures are logged: the job is already cancelled and
// the next counter adjustment path cannot repair it, so this is best effort.
func (s *DBScheduler) releaseQueuedQuota(ctx context.Context, j model.Job) {
	qs, ok := s.Store.(storage.QuotaCounterStore)
	if !ok {
		return
	}
	repoID := storage.RepoIDForJob(j)
	if err := qs.AdjustQuotaCounter(ctx, repoID, storage.RepoTeamKey(repoID), 0, -1); err != nil {
		log.Printf("scheduler: release queued quota for job %s: %v", j.ID, err)
	}
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

// jobRuntimeCapability extracts the job's runtime capability
// (container/tart/native) from the persisted compiled payload.
func jobRuntimeCapability(j model.Job) string {
	return storage.JobRuntime(j)
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

// QueueDeadlineFor returns the job's queue deadline: the persisted
// QueueDeadline field when present, otherwise the deadline derived from the
// compiled payload's queue_timeout (CreatedAt + timeout). Jobs without
// either have no deadline and never expire. The payload fallback keeps
// rows persisted before the QueueDeadline field existed expiring correctly.
// It is exported so every lease/recovery path (including the server's
// in-memory mode) applies one queue-timeout rule.
func QueueDeadlineFor(j model.Job) *time.Time {
	if j.QueueDeadline != nil {
		return j.QueueDeadline
	}
	to := queueTimeoutFromPayload(j)
	if to <= 0 {
		return nil
	}
	dl := j.CreatedAt.Add(to)
	return &dl
}

// queueTimeoutFromPayload extracts the compiled job's queue_timeout from
// the stored compiled payload (CompiledJobPayload.EffectiveJob), so queue
// deadlines are payload-based and need no dedicated storage column.
func queueTimeoutFromPayload(j model.Job) time.Duration {
	if j.CompiledJobPayload == nil || j.CompiledJobPayload.EffectiveJob == nil {
		return 0
	}
	var b []byte
	switch v := j.CompiledJobPayload.EffectiveJob.(type) {
	case json.RawMessage:
		b = v
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		var err error
		if b, err = json.Marshal(v); err != nil {
			return 0
		}
	}
	var cj pipeline.CompiledJob
	if err := json.Unmarshal(b, &cj); err != nil {
		return 0
	}
	if cj.Job.QueueTimeout.Duration <= 0 {
		return 0
	}
	return cj.Job.QueueTimeout.Duration
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
