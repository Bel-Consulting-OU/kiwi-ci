// Package scheduler implements the PostgreSQL-backed control plane. It
// operates on the storage.Store contract: the durable SQL rows are the source
// of truth, while the server keeps its in-memory maps only for dev mode.
//
// Leader semantics: exactly one instance may lease jobs or recover expired
// leases. Leadership is a session-level Postgres advisory lock held by the
// store on a dedicated connection; TryAcquireLeadership renews the claim and
// reports ownership, so a standby can observe promotion by polling IsLeader.
// Because a cached renewal may briefly report true after the lock session
// died, leadership is enforced by a monotonic EPOCH (migration 0025), not by
// the check alone: the store publishes a new epoch on acquisition, retains it
// while it holds the claim, and every leader-only mutation re-validates it
// inside its own transaction. A replica whose cached claim outlived its
// session is rejected with storage.ErrStaleLeader and mutates nothing.
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
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
//
// A true result can be served from the store's throttled cached proof (no
// round-trip), so it may briefly survive the loss of the advisory-lock
// session. That window is closed by the store's leadership EPOCH, not by this
// check: every leader-only mutation validates the epoch inside its own
// transaction and fails with storage.ErrStaleLeader when the claim is stale,
// so a cached true can hand out no work that mutates shared state.
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
			// The canonical helper derives CreatedAt + queue_timeout from the
			// compiled payload when the deadline field is unset.
			if dl := storage.QueueDeadlineFor(j); dl != nil {
				j.QueueDeadline = dl
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
// RESOURCE ADMISSION: a candidate whose TOTAL request (its own
// CPU/memory/disk/PIDs plus the aggregate service envelope,
// model.Job.ReservedResources) does not fit the runner's REMAINING resource
// capacity is skipped, so it waits (or is leased to another runner with room)
// instead of oversubscribing this one. The check here is a pre-filter over the
// live reservation sum; the authoritative check-and-reserve happens inside the
// claim transaction (storage.AcquireLeaseAtomic), which fails with
// storage.ErrResourceCapacity when a concurrent lease won the remaining
// capacity first — that error is treated exactly like a lost capacity race
// (try the next candidate). A runner without configured capacities (all
// dimensions zero, the documented default) admits every candidate: only the
// job-count capacity applies.
//
// Deliberately NOT epoch-fenced, unlike the leader-only housekeeping
// mutations: the lease claim is itself a single atomic conditional
// transaction (AcquireLeaseAtomic / AcquireLease) whose mutual exclusion comes
// from the row state — the queued->running transition, the lease generation
// and the runner capacity/environment/quota predicates are checked under the
// job row lock, so a stale leader cannot double-lease or corrupt a claim; its
// worst case is handing out a job the current leader would also have handed
// out. Leadership orders this work, it is not the safety boundary for it.
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
	// The runner's live resource reservations, read ONCE per lease attempt
	// (the pre-filter below evaluates every candidate against the same
	// snapshot; the claim transaction re-reads them under the runner row
	// lock). A store without the reservation contract reports zero, which
	// makes the pre-filter vacuous.
	reserved := s.reservedResources(ctx, runnerID)
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
		// Resource admission pre-filter: a candidate that cannot fit the
		// runner's remaining resource capacity waits for room on this
		// runner (or a lease on another one) instead of being claimed and
		// rolling back. The requested total is the job's OWN request plus
		// its aggregate service envelope (model.Job.ReservedResources) —
		// the same total the claim transaction and the fs/dev path charge.
		if !(storage.ResourceAdmission{
			Capacity:  eff.ResourceCapacity,
			Reserved:  reserved,
			Requested: candidate.ReservedResources(),
		}).Allows() {
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
			CPURequest:             candidate.CPURequest,
			MemoryRequest:          candidate.MemoryRequest,
			DiskRequest:            candidate.DiskRequest,
			PIDsRequest:            candidate.PIDsRequest,
			// The aggregate service envelope rides the claim so the claim
			// transaction reserves job request + envelope in the ONE
			// ledger row (LeaseClaim.RequestedResources).
			ServiceEnvelopeRequest: candidate.ServiceEnvelopeRequest,
		}
		// Capacity-atomic lease: the job claim, every predicate above, the
		// resource reservation and the runner's active-jobs append happen in
		// ONE transaction, so two concurrent leases can never exceed the
		// runner's capacity — count or resources — bypass a concurrent
		// disable/drain or overrun environment/quota limits.
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
				errors.Is(err, storage.ErrResourceCapacity),
				errors.Is(err, storage.ErrQuotaExceeded):
				// A predicate lost a race (filled capacity slot, taken
				// environment slot, exhausted resource capacity or quota) or
				// this candidate is not eligible for this runner: try the
				// next candidate.
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

// effectiveRunner resolves the runner's LIVE scheduling view at lease time
// through the ONE shared live-profile precedence (storage.ResolveLiveProfileBinding):
// an explicit certificate-serial binding wins when the runner presents a
// registered serial, otherwise the runner-ID binding (runner_profile_links)
// applies, otherwise the registration snapshot is used unchanged. A profile
// edit therefore takes effect on the next lease for mTLS AND per-runner
// bearer identities.
//
// A dangling binding fails the lease closed ([LiveProfileResolution.
// DeniesLease]) and is presented here as a zero-capacity runner (the claim
// fails it closed with ErrNoCapacity), so the prefilter never proposes
// candidates the claim will reject. Stores without the resolver contract fall
// back to composing the same precedence from their profile read contracts
// (without dangling detection, since those report only found/not-found); the
// claim transaction remains the authoritative decision.
func (s *DBScheduler) effectiveRunner(ctx context.Context, ri model.Runner) model.Runner {
	if lr, ok := s.Store.(storage.LiveProfileResolver); ok {
		resolution, err := lr.ResolveLiveRunnerProfile(ctx, ri.ID, ri.CertSerial)
		if err != nil {
			// The prefilter is best-effort: a read failure falls back to the
			// snapshot and the claim (which re-reads inside its transaction)
			// decides with its own error.
			log.Printf("scheduler: resolve live profile for runner %s: %v", ri.ID, err)
			return ri
		}
		return applyLiveResolution(ri, resolution)
	}
	var runnerLookup storage.ProfileBindingLookup
	if ls, ok := s.Store.(storage.RunnerProfileLinkStore); ok {
		runnerLookup = func() (model.RunnerProfile, bool, bool, error) {
			p, found, err := ls.ProfileForRunnerID(ctx, ri.ID)
			return p, found, found, err
		}
	}
	var certLookup storage.ProfileBindingLookup
	if ps, ok := s.Store.(storage.ProfileStore); ok {
		certLookup = func() (model.RunnerProfile, bool, bool, error) {
			p, found, err := ps.ProfileForSerial(ctx, ri.CertSerial)
			return p, found, found, err
		}
	}
	resolution, err := storage.ResolveLiveProfileBinding(ri.CertSerial, certLookup, runnerLookup)
	if err != nil {
		log.Printf("scheduler: resolve live profile for runner %s: %v", ri.ID, err)
		return ri
	}
	return applyLiveResolution(ri, resolution)
}

// applyLiveResolution overlays one live-profile resolution on the runner's
// registration snapshot: a dangling binding presents the runner as
// zero-capacity (the claim fails it closed), a found profile replaces the
// snapshot attributes, and no binding keeps the snapshot unchanged. It is the
// ONE overlay body the per-runner and the batched entry points share, so the
// two paths cannot diverge.
func applyLiveResolution(ri model.Runner, resolution storage.LiveProfileResolution) model.Runner {
	switch {
	case resolution.DeniesLease():
		ri.Capacity = 0
		return ri
	case resolution.Applies():
		return storage.ResolveRunnerProfile(ri, resolution.Profile, true)
	default:
		return ri
	}
}

// EffectiveRunner exposes the LIVE scheduling view of one runner (profile
// overlay included) to the server's queue-reason explainer, so the reasons it
// reports use the same effective capacity the lease decision uses. Stores
// without a profile contract return the runner unchanged.
func (s *DBScheduler) EffectiveRunner(ctx context.Context, ri model.Runner) model.Runner {
	return s.effectiveRunner(ctx, ri)
}

// EffectiveRunnerBatch resolves the LIVE scheduling view of every runner in
// ONE set-based read when the store implements storage.FleetRunnerViewStore:
// the batched binding rows are resolved through the SAME shared precedence
// the per-runner path uses (storage.FleetRunnerBinding.Resolve ->
// ResolveLiveProfileBinding) and overlaid by the SAME body, so a batched view
// always equals EffectiveRunner's answer for the same runner.
//
// ok=false means the caller must use the per-runner entry point: the store
// has no batch contract, or the batch read failed (logged; the claim remains
// authoritative). Even on ok=true a runner the batch did not return (it
// raced the listing) is resolved per-runner, so the map is complete for every
// input runner.
func (s *DBScheduler) EffectiveRunnerBatch(ctx context.Context, runners []model.Runner) (map[string]model.Runner, bool) {
	vs, ok := s.Store.(storage.FleetRunnerViewStore)
	if !ok {
		return nil, false
	}
	bindings, err := vs.FleetRunnerProfileBindings(ctx)
	if err != nil {
		log.Printf("scheduler: batch resolve live profiles: %v", err)
		return nil, false
	}
	out := make(map[string]model.Runner, len(runners))
	for _, ri := range runners {
		binding, found := bindings[ri.ID]
		if !found {
			out[ri.ID] = s.effectiveRunner(ctx, ri)
			continue
		}
		out[ri.ID] = applyLiveResolution(ri, binding.Resolve(ri.CertSerial))
	}
	return out, true
}

// ReservedResources exposes the runner's live resource reservation sum to the
// queue-reason explainer. A store without the ledger contract reports zero,
// which makes the resource reasons vacuous.
func (s *DBScheduler) ReservedResources(ctx context.Context, runnerID string) model.ResourceCapacity {
	return s.reservedResources(ctx, runnerID)
}

// ReservedResourcesBatch returns every runner's live reservation sum from ONE
// GROUP BY runner_id read when the store implements
// storage.FleetRunnerViewStore, byte-for-byte the quantities the per-runner
// ReservedResources returns. ok=false means the caller falls back to the
// per-runner reads (the store has no batch contract, or the batch read failed
// and was logged).
func (s *DBScheduler) ReservedResourcesBatch(ctx context.Context) (map[string]model.ResourceCapacity, bool) {
	vs, ok := s.Store.(storage.FleetRunnerViewStore)
	if !ok {
		return nil, false
	}
	sums, err := vs.RunnerReservationSums(ctx)
	if err != nil {
		log.Printf("scheduler: batch read reserved resources: %v", err)
		return nil, false
	}
	return sums, true
}

// reservedResources reads the runner's live resource reservations when the
// store keeps the ledger. A store without the contract reports zero, which
// makes the resource pre-filter vacuous (the claim's own transaction still
// decides).
func (s *DBScheduler) reservedResources(ctx context.Context, runnerID string) model.ResourceCapacity {
	rs, ok := s.Store.(storage.ResourceReservationStore)
	if !ok {
		return model.ResourceCapacity{}
	}
	reserved, err := rs.RunnerReservedResources(ctx, runnerID)
	if err != nil {
		log.Printf("scheduler: read reserved resources for runner %s: %v", runnerID, err)
		return model.ResourceCapacity{}
	}
	return reserved
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

// recoveryPageSize bounds every recovery-discovery page. Candidate discovery
// is keyset-paged in job-id order, so this constant bounds memory and
// round-trip size per page, not how many candidates a sweep can reach: the
// loop keeps requesting the next page until a short page arrives, which means
// every expired/elapsed candidate is eventually visited regardless of how
// many newer runs exist. It is a var only so tests can shrink the page and
// prove paging determinism over a candidate set larger than one page.
var recoveryPageSize = 256

// RecoverExpired requeues or fails jobs whose leases expired and cancels
// queued jobs past their queue deadline, mirroring the in-memory
// recoverLeasesLocked (infrastructure retry budget respected). Every job
// transition is ONE transactional store operation that also releases the
// runner slot / quota reservation and recomputes dependents and the run, so
// no later best-effort pass can be lost to a crash. Leader-only, and every
// transition is EPOCH-FENCED inside the store transaction: a replica whose
// cached claim outlived its advisory-lock session gets
// storage.ErrStaleLeader, mutates nothing, and is demoted here immediately
// instead of sweeping on.
//
// Discovery is DIRECT and bounded: the store's id-paged candidate queries
// (storage.RecoveryScanStore) return lightweight candidates built from the
// authoritative relational columns (id, lease_generation, queue_deadline) for
// expired running leases and elapsed queue deadlines. ListRuns-style
// enumeration is deliberately gone: a newest-N window permanently orphans an
// old non-terminal job once N newer runs exist. Each page advances the id
// cursor past EVERY returned candidate, including candidates whose applier
// fails (logged, not fatal), so one bad row can never stall the candidates
// behind it; a later sweep revisits the failure from the start. Page query
// errors abort the sweep with an error, exactly as a ListRuns error did.
// Candidates are never decoded here, so a corrupt row is still swept: the
// fenced applier applies the forced recovery that releases its capacity.
func (s *DBScheduler) RecoverExpired(ctx context.Context, now time.Time) error {
	if !s.IsLeader(ctx) {
		return ErrNotLeader
	}
	scanner, ok := s.Store.(storage.RecoveryScanStore)
	if !ok {
		return fmt.Errorf("scheduler: store does not support paged recovery discovery")
	}
	// Expired running leases, in deterministic id order so the keyset cursor
	// is a total order.
	afterID := ""
	for {
		page, err := scanner.ListExpiredRunningJobs(ctx, now, afterID, recoveryPageSize)
		if err != nil {
			return fmt.Errorf("scheduler: list expired running jobs: %w", err)
		}
		for _, c := range page {
			// The expected generation makes the recovery idempotent and
			// race-safe: a lease replaced by a concurrent re-lease is left
			// untouched.
			if err := scanner.RecoverExpiredLease(ctx, c.ID, c.LeaseGeneration, now); err != nil {
				if errors.Is(err, storage.ErrStaleLeader) {
					return s.staleLeader("recover expired lease", err)
				}
				log.Printf("scheduler: recover job %s: %v", c.ID, err)
			}
			afterID = c.ID
		}
		if len(page) < recoveryPageSize {
			break
		}
	}
	// Queue-timeout expiry: a queued (or approval-waiting) job past its
	// queue deadline is cancelled terminally, independent of its attempt
	// count, and its reserved queued quota slot is released in the SAME
	// transaction. The candidate carries the persisted queue_deadline column
	// (zero for legacy payload-only rows); the applier re-derives the
	// effective deadline under its own row lock, so the query's superset
	// (legacy payload deadlines) is filtered inside the transaction.
	afterID = ""
	for {
		page, err := scanner.ListQueueTimedOutJobs(ctx, now, afterID, recoveryPageSize)
		if err != nil {
			return fmt.Errorf("scheduler: list queue-timed-out jobs: %w", err)
		}
		for _, c := range page {
			// The candidate carries the persisted queue_deadline column; a
			// nil deadline means the row is a legacy payload-only candidate,
			// signalled to the applier as the zero time.
			observed := time.Time{}
			if c.QueueDeadline != nil {
				observed = *c.QueueDeadline
			}
			if err := scanner.ExpireQueuedJob(ctx, c.ID, observed); err != nil {
				if errors.Is(err, storage.ErrStaleLeader) {
					return s.staleLeader("expire queue deadline", err)
				}
				log.Printf("scheduler: expire queue deadline for job %s: %v", c.ID, err)
			}
			afterID = c.ID
		}
		if len(page) < recoveryPageSize {
			break
		}
	}
	return nil
}

// staleLeader marks this scheduler not-leader after a store mutation rejected
// its leadership epoch and aborts the sweep. Every remaining candidate would
// be rejected the same way (the store already cleared its retained epoch), so
// continuing would be pure no-op work. The next IsLeader call either
// re-acquires (publishing a fresh epoch) or stays a standby.
func (s *DBScheduler) staleLeader(op string, err error) error {
	s.leader.Store(false)
	log.Printf("scheduler: %s rejected by the leadership fence; demoting to standby: %v", op, err)
	return fmt.Errorf("scheduler: %s: %w", op, err)
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

// QueueDeadlineFor returns the job's queue deadline. It delegates to the
// canonical storage helper so the scheduler's lease gate, the recovery
// transaction and the server's in-memory mode all apply one queue-timeout
// rule (persisted QueueDeadline first, compiled-payload queue_timeout second).
func QueueDeadlineFor(j model.Job) *time.Time {
	return storage.QueueDeadlineFor(j)
}
