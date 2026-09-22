package server

import (
	"context"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/queue"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/scheduler"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// Fleet-global queue reasoning.
//
// A persisted queue reason is a FLEET-level diagnostic: it is shown to
// operators and drives the queue metrics, and it is written on any runner's
// lease miss, so it must not depend on which runner happened to poll. The
// removed per-runner explainer could persist NO_COMPATIBLE_RUNNER while
// another runner in the fleet satisfied the job — visible for labels/regions,
// and made sharp by resource capacity, where a job above one runner's
// remaining capacity is perfectly leasable elsewhere.
//
// Every pass therefore evaluates the job against ALL ACTIVE effective runner
// profiles (disabled/draining runners and zero-capacity profile-less runners
// take no work and are excluded), using the same dimensions the lease paths
// decide on: dependency readiness, labels, placement regions, environment
// concurrency and resource capacity (configured, remaining, and job-count
// slots). A per-poll failure (the polling runner cannot take the job, or even
// a fleet listing failure) can therefore never overwrite a fleet-level
// diagnostic with a runner-local one.

// queueRunnerView is one active runner's effective view for the fleet-global
// queue-reason decision: the live profile overlay is already applied by the
// caller, exactly like the lease path's eff runner.
type queueRunnerView struct {
	labels   []string
	region   string
	slots    int                    // job-count capacity (>= 1 for active runners)
	active   int                    // jobs the runner currently holds
	capacity model.ResourceCapacity // configured capacities (zero = unconstrained)
	reserved model.ResourceCapacity // live reservations of its running jobs
}

// queueReasonForJob returns the fleet-global reason a queued job waits, or
// queue.None when at least one active runner can lease it right now.
//
// Precedence (each step is decided across the whole fleet):
//
//  1. a job-unready dependency gate wins: WAITING_DEPENDENCY (job-scoped);
//  2. no active runner matches the required labels: NO_COMPATIBLE_RUNNER;
//  3. no label-matching runner matches the placement regions:
//     REGION_UNAVAILABLE;
//  4. no label+region-matching runner's CONFIGURED capacity can ever fit the
//     request: NO_COMPATIBLE_RUNNER (the existing "no runner can take this"
//     semantics, so an unsatisfiable job never looks like an infinite
//     capacity wait);
//  5. the environment concurrency limit is reached: ENVIRONMENT_LOCKED;
//  6. some compatible runner has a free slot and remaining resource
//     capacity: queue.None;
//  7. otherwise every compatible runner is at capacity (slots or remaining
//     resources): RUNNER_CAPACITY.
func queueReasonForJob(j model.Job, fleet []queueRunnerView, depsReady, envLocked bool) queue.ReasonCode {
	if !depsReady {
		return queue.WaitingDependency
	}
	labelMatch := false
	regionMatch := false
	everFits := false
	fitsNow := false
	// The evaluated request is the job's TOTAL reservation (own request plus
	// the aggregate service envelope), the same total the lease pre-filter,
	// the claim transaction and the ledger charge, so the explainer can never
	// report RUNNER_CAPACITY for a job whose aggregate is permanently above a
	// runner's configured capacity.
	request := j.ReservedResources()
	for _, r := range fleet {
		if !labelsSatisfied(r.labels, j.RequiredLabels) {
			continue
		}
		labelMatch = true
		if !regionSatisfied(r.region, j.PlacementRegions) {
			continue
		}
		regionMatch = true
		admission := storage.ResourceAdmission{Capacity: r.capacity, Reserved: r.reserved, Requested: request}
		if !admission.EverSatisfiable() {
			continue
		}
		everFits = true
		if admission.Allows() && r.active < r.slots {
			fitsNow = true
		}
	}
	switch {
	case !labelMatch:
		return queue.NoCompatibleRunner
	case !regionMatch:
		return queue.RegionUnavailable
	case !everFits:
		return queue.NoCompatibleRunner
	case envLocked:
		return queue.EnvironmentLocked
	case fitsNow:
		return queue.None
	default:
		return queue.RunnerCapacity
	}
}

// applyQueueReasonsDB recomputes the queue reasons for every leasable
// candidate and persists them through QueueReasonStore. It runs on a DB
// lease miss so the SQL store's queue_reason column stays populated without
// rewriting whole job payloads.
//
// The evaluation is fleet-global: ALL active effective runner profiles are
// considered (see queueReasonForJob), and the polling runner contributes its
// view too (it is normally part of the listing; adding it keeps the pass
// correct when the caller raced a registration). A runner listing failure
// degrades to the polling runner's own view but may only persist JOB-scoped
// reasons (dependencies/environment/approval): a fleet-scoped diagnostic is
// never overwritten from a single runner we could not compare against the
// rest of the fleet.
func (s *Server) applyQueueReasonsDB(ctx context.Context, ri model.Runner) {
	qs, ok := s.DB.(storage.QueueReasonStore)
	if !ok {
		return
	}
	jobs, err := s.DB.ListQueuedJobs(ctx)
	if err != nil {
		return
	}
	fleet, fleetComplete := s.fleetQueueRunnerViewsDB(ctx, ri)
	reasons := map[string]string{}
	for _, j := range jobs {
		if j.Status != model.StatusQueued {
			continue
		}
		reason := queueReasonForJob(j, fleet, s.depsReadyDB(ctx, j), s.environmentAtCapacityDB(ctx, j))
		if !fleetComplete && !jobScopedQueueReason(reason) {
			// Unknown fleet: do not replace a fleet-level diagnostic with a
			// runner-local one (the next successful pass will).
			continue
		}
		if j.QueueReason != string(reason) {
			reasons[j.ID] = string(reason)
		}
	}
	if len(reasons) == 0 {
		return
	}
	if err := qs.SetQueueReasons(ctx, reasons); err != nil {
		s.logError("queue reasons: persist failed", "error", err.Error())
	}
}

// jobScopedQueueReason reports whether the reason is decided by the JOB's own
// state alone (dependencies, environment concurrency, approval) as opposed to
// the runner fleet's compatibility (labels/region/capacity). Only job-scoped
// reasons may be persisted from a degraded single-runner fleet view.
func jobScopedQueueReason(reason queue.ReasonCode) bool {
	switch reason {
	case queue.WaitingDependency, queue.EnvironmentLocked, queue.WaitingApproval:
		return true
	default:
		return false
	}
}

// fleetQueueRunnerViewsDB resolves every active runner's effective scheduling
// view (live profile overlay included) plus its live reservation sum. It
// returns the views and whether the fleet listing succeeded: on a listing
// failure only the polling runner is known, and the caller must not persist
// fleet-scoped reasons from that partial view.
func (s *Server) fleetQueueRunnerViewsDB(ctx context.Context, ri model.Runner) ([]queueRunnerView, bool) {
	fleet := make([]queueRunnerView, 0, 8)
	seen := map[string]bool{}
	add := func(r model.Runner) {
		if r.ID == "" || seen[r.ID] {
			return
		}
		seen[r.ID] = true
		eff := r
		if s.Sched != nil {
			eff = s.Sched.EffectiveRunner(ctx, r)
		}
		// A disabled/draining runner cannot take new work, so it is not part
		// of the fleet's compatibility answer. A zero-capacity runner (e.g. a
		// profile that sets no max_capacity) still participates in the
		// label/region/configured-capacity evaluation — its presence is what
		// keeps a compatible job from being mislabelled NO_COMPATIBLE_RUNNER —
		// but it contributes zero slots, so it never "fits right now".
		if eff.Disabled || eff.Draining {
			return
		}
		var reserved model.ResourceCapacity
		if s.Sched != nil {
			reserved = s.Sched.ReservedResources(ctx, eff.ID)
		}
		fleet = append(fleet, queueRunnerView{
			labels:   eff.Labels,
			region:   eff.Region,
			slots:    eff.Capacity,
			active:   len(eff.ActiveJobs),
			capacity: eff.ResourceCapacity,
			reserved: reserved,
		})
	}
	complete := true
	if s.DB != nil {
		runners, err := s.DB.ListRunners(ctx)
		if err != nil {
			// Degraded fleet view: keep the pass running for job-scoped
			// reasons, but never claim fleet incompatibility from it.
			s.logError("queue reasons: list runners", "error", err.Error())
			complete = false
		} else {
			for _, r := range runners {
				add(r)
			}
		}
	}
	add(ri)
	return fleet, complete
}

// applyQueueReasonsMemoryLocked is the fs/memory-mode mirror of
// applyQueueReasonsDB: the fleet is the in-memory runner map with each
// runner's live profile applied, and each runner's reservations are derived
// from the running jobs it holds (the memory ledger). The caller holds s.mu.
func (s *Server) applyQueueReasonsMemoryLocked(ri model.Runner) {
	fleet := s.fleetQueueRunnerViewsLocked(ri)
	for id, j := range s.jobs {
		reason := queue.None
		switch j.Status {
		case model.StatusWaitingApproval:
			reason = queue.WaitingApproval
		case model.StatusQueued:
			reason = queueReasonForJob(j, fleet, depsReadyLocked(j, s.jobs), environmentAtCapacityScoped(j, s.jobs))
		}
		if j.QueueReason != string(reason) {
			j.QueueReason = string(reason)
			s.jobs[id] = j
		}
	}
}

// fleetQueueRunnerViewsLocked builds the memory-mode fleet view. Reservations
// are summed per runner in ONE pass over the job map: a reservation exists
// exactly while the job is running, so this is the memory ledger the fs lease
// path charges against (and every terminal path releases by construction).
func (s *Server) fleetQueueRunnerViewsLocked(ri model.Runner) []queueRunnerView {
	reserved := map[string]model.ResourceCapacity{}
	for _, j := range s.jobs {
		if j.Status != model.StatusRunning || j.LeaseRunnerID == "" {
			continue
		}
		// The memory ledger charges the job's TOTAL reservation (own request
		// plus aggregate service envelope), exactly like the SQL ledger the
		// DB-mode fleet view reads, so both explainers agree.
		reserved[j.LeaseRunnerID] = model.AddResourceCapacity(reserved[j.LeaseRunnerID], j.ReservedResources())
	}
	fleet := make([]queueRunnerView, 0, len(s.runners)+1)
	seen := map[string]bool{}
	add := func(r model.Runner) {
		if r.ID == "" || seen[r.ID] {
			return
		}
		seen[r.ID] = true
		r, linked := s.liveRunnerLocked(r)
		if r.Disabled || r.Draining {
			return
		}
		if r.Capacity < 1 && !s.RequireProfiles && !linked {
			// The legacy clamp applies only to the self-reported dev-mode
			// registration; a profile-linked zero-capacity runner keeps zero
			// slots (it receives nothing) but still participates in the
			// fleet's label/region/capacity compatibility answer, exactly
			// like the DB path.
			r.Capacity = 1
		}
		fleet = append(fleet, queueRunnerView{
			labels:   r.Labels,
			region:   r.Region,
			slots:    r.Capacity,
			active:   len(r.ActiveJobs),
			capacity: r.ResourceCapacity,
			reserved: reserved[r.ID],
		})
	}
	for _, r := range s.runners {
		add(r)
	}
	// The polling runner is always part of its own fleet evaluation, even if
	// a concurrent registration changed the map under this pass.
	add(ri)
	return fleet
}

// depsReadyDB evaluates a queued job's dependency gate against the SQL
// store using the same unified condition evaluator as the in-memory path.
func (s *Server) depsReadyDB(ctx context.Context, j model.Job) bool {
	ready, status := scheduler.DependencyOutcome(j.Needs, nil, func(id string) (model.Status, bool) {
		d, err := s.DB.GetJob(ctx, id)
		if err != nil {
			return "", false
		}
		return d.Status, true
	})
	return ready && (status == model.StatusSuccess || scheduler.ConditionAllows(j.Condition, status))
}

// environmentAtCapacityDB mirrors environmentAtCapacityScoped against the
// SQL store's per-environment job listing: the listing is keyed by the
// SCHEDULING identity of the checkout repository (storage.RepoIDForJob:
// stored RepoID with the legacy URL + full-name fallback), never the clone
// URL and never the authorization-side PolicyRepoID. The DB and memory modes
// therefore make the same repo-scoped decision for one candidate.
func (s *Server) environmentAtCapacityDB(ctx context.Context, j model.Job) bool {
	if j.Environment == "" || j.EnvironmentConcurrency <= 0 {
		return false
	}
	others, err := s.DB.ListJobsByEnvironment(ctx, storage.RepoIDForJob(j), j.Environment)
	if err != nil {
		return false
	}
	active := 0
	for _, other := range others {
		if other.ID == j.ID || other.Status != model.StatusRunning {
			continue
		}
		active++
		if active >= j.EnvironmentConcurrency {
			return true
		}
	}
	return false
}
