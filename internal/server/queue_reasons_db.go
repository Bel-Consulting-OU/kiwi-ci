package server

import (
	"context"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/queue"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/scheduler"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// applyQueueReasonsDB recomputes the queue reasons for every leasable
// candidate and persists them through QueueReasonStore. It runs on a DB
// lease miss so the SQL store's queue_reason column stays populated without
// rewriting whole job payloads.
//
// Resource admission participates in the explanation: a candidate whose
// request exceeds the runner's configured capacity for good is reported as
// NO_COMPATIBLE_RUNNER (the existing "no runner can take this" semantics, so
// an unsatisfiable job does not look like an infinite capacity wait), and a
// candidate that merely does not fit the runner's REMAINING capacity now is
// reported as RUNNER_CAPACITY (it will be leased when one of the runner's
// jobs finishes, or by another runner with room).
func (s *Server) applyQueueReasonsDB(ctx context.Context, ri model.Runner) {
	qs, ok := s.DB.(storage.QueueReasonStore)
	if !ok {
		return
	}
	jobs, err := s.DB.ListQueuedJobs(ctx)
	if err != nil {
		return
	}
	// The runner's LIVE effective capacity and current reservations are
	// resolved once per pass (mirroring the lease path's live resolution).
	eff := ri
	if s.Sched != nil {
		eff = s.Sched.EffectiveRunner(ctx, ri)
	}
	var reserved model.ResourceCapacity
	if s.Sched != nil {
		reserved = s.Sched.ReservedResources(ctx, eff.ID)
	}
	reasons := map[string]string{}
	for _, j := range jobs {
		if j.Status != model.StatusQueued {
			continue
		}
		reason := queue.None
		switch {
		case !s.depsReadyDB(ctx, j):
			reason = queue.WaitingDependency
		case !labelsSatisfied(eff.Labels, j.RequiredLabels):
			reason = queue.NoCompatibleRunner
		case !regionSatisfied(eff.Region, j.PlacementRegions):
			reason = queue.RegionUnavailable
		case s.environmentAtCapacityDB(ctx, j):
			reason = queue.EnvironmentLocked
		case !(storage.ResourceAdmission{Capacity: eff.ResourceCapacity, Reserved: reserved, Requested: j.ResourceRequest()}).EverSatisfiable():
			// No amount of waiting frees this runner for the job: the job
			// is incompatible with its configured capacity.
			reason = queue.NoCompatibleRunner
		case !(storage.ResourceAdmission{Capacity: eff.ResourceCapacity, Reserved: reserved, Requested: j.ResourceRequest()}).Allows():
			// The job fits the runner in principle but not in what is left
			// right now.
			reason = queue.RunnerCapacity
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
