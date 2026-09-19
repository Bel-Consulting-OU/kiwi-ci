package server

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// reconcileCompletionEffects runs every INTERNAL post-completion effect for
// jobID: downstream launch recording, deployment finishing, usage
// accounting and run aggregation. Each effect checks its own durable marker
// (downstream link row, deployment finished_at, job usage_recorded flag,
// recomputed run aggregation) before acting, so at-least-once dispatch can
// never double-account. A job that no longer exists is treated as already
// reconciled.
//
// Forge publication is deliberately NOT part of this chain: it lives in the
// separate OutboxKindForgeDelivery intent, which may back off and dead-letter
// per its own policy without ever retiring this internal consistency row.
func (s *Server) reconcileCompletionEffects(ctx context.Context, jobID string) error {
	j, err := s.jobForLease(ctx, jobID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.effectDownstreamCheck(ctx, j); err != nil {
		return err
	}
	if err := s.effectDeploymentFinish(ctx, j); err != nil {
		return err
	}
	if err := s.effectUsageAccount(ctx, j); err != nil {
		return err
	}
	return s.effectRunAggregate(ctx, j)
}

// dispatchForgeDelivery runs the external publication for one completed job
// (the forge_delivery intent): resolve the job's run and mirror its terminal
// state to the forge. Retries/dead-letters are the outbox's per-intent
// policy, independent of the internal completion_reconcile row.
func (s *Server) dispatchForgeDelivery(ctx context.Context, jobID string) error {
	j, err := s.jobForLease(ctx, jobID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.effectForgeStatus(ctx, j)
}

// effectDownstreamCheck records the downstream launch intents of a
// successfully completed job. Marker: an existing downstream link row means
// the intents were already recorded (recordDownstreamIntents would only
// re-enqueue the dispatch intent otherwise).
func (s *Server) effectDownstreamCheck(ctx context.Context, j model.Job) error {
	if j.Status != model.StatusSuccess {
		return nil
	}
	cj, ok := compileJobFromPipeline(j)
	if !ok {
		return nil
	}
	if strings.TrimSpace(cj.Job.Downstream.Repository) == "" {
		return nil
	}
	// NO "link exists => success" shortcut: the crash window is exactly
	// "link committed, durable intent missing", and recordDownstreamIntents
	// is written as the IDEMPOTENT repair path (it reuses the link's stored
	// token, checks the DETERMINISTIC durable outbox ID, and re-appends
	// only when that row is absent). Returning early here would ACK the
	// effect and permanently suppress the launch.
	return s.recordDownstreamIntentsForCompleted(ctx, j.ID)
}

// deploymentForJob resolves the deployment record bound to a job: the
// in-memory mirror first, then the durable DeploymentStore in DB mode.
func (s *Server) deploymentForJob(ctx context.Context, j model.Job) (model.Deployment, bool, error) {
	s.mu.Lock()
	d, ok := s.deployments[j.ID]
	s.mu.Unlock()
	if ok {
		return d, true, nil
	}
	if s.DB != nil {
		if ds, isDS := s.DB.(storage.DeploymentStore); isDS {
			recs, err := ds.ListDeploymentsByRun(ctx, j.RunID)
			if err != nil {
				return model.Deployment{}, false, err
			}
			for _, rec := range recs {
				if rec.JobID == j.ID {
					return rec, true, nil
				}
			}
		}
	}
	return model.Deployment{}, false, nil
}

// persistDeploymentFinishState is a test seam over the fs-mode state write
// used by the deployment-finish effect: production calls
// s.persistCheckedErrLocked, tests inject a failure to prove the marker rolls
// back and the effect is retried instead of reporting success without
// durable state.
var persistDeploymentFinishState = func(s *Server) error { return s.persistCheckedErrLocked("job.deployment_finish") }

// effectDeploymentFinish marks the deployment record of a completed
// environment job with its terminal status, creating the record when a
// failed create left it absent. Marker: a non-nil finished_at (or a job
// without an environment) means there is nothing left to finish.
//
// Persistence failures are returned, never swallowed: in DB mode the record
// is inserted/updated durably before anything is mirrored or audited, so the
// completion outbox keeps the effect pending and retries it; in fs/memory
// mode a failed state write rolls the in-memory marker back, so the retry
// re-attempts it instead of reporting a success that durable state does not
// contain.
func (s *Server) effectDeploymentFinish(ctx context.Context, j model.Job) error {
	if j.Environment == "" {
		return nil
	}
	finished := time.Now().UTC()
	if j.FinishedAt != nil {
		finished = *j.FinishedAt
	}
	if s.DB != nil {
		return s.finishDeploymentDB(ctx, j, j.Status, finished)
	}
	d, found, err := s.deploymentForJob(ctx, j)
	if err != nil {
		return err
	}
	if !found || d.ID == "" || d.FinishedAt != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.deployments[j.ID]
	if !ok || cur.FinishedAt != nil {
		return nil
	}
	prev := cur
	cur.Status = j.Status
	cur.FinishedAt = &finished
	s.deployments[j.ID] = cur
	if err := persistDeploymentFinishState(s); err != nil {
		// Durability first: the marker must not survive a failed write, or
		// the retry would treat the effect as already done.
		s.deployments[j.ID] = prev
		return err
	}
	s.auditLocked("deployment.completed", "scheduler", j.RunID, j.ID, "deployment finished", map[string]string{"environment": j.Environment, "status": string(j.Status)})
	return nil
}

// effectUsageAccount computes and persists the completed job's cost/energy
// usage. Marker: the job's usage_recorded flag — once set (with cost/energy
// persisted on the job row), replays skip the computation so metrics and
// budgets are never double-accounted.
//
// DB mode arbitrates through UsageOnceStore.RecordUsageOnce FIRST and moves
// process metrics only when this call won the exactly-once transition: a
// retry (or a second replica) that loses the race increments nothing. A store
// without the contract fails closed rather than falling back to a
// read-modify-write with last-writer-wins semantics.
func (s *Server) effectUsageAccount(ctx context.Context, j model.Job) error {
	if j.UsageRecorded {
		return nil
	}
	finished := time.Now().UTC()
	if j.FinishedAt != nil {
		finished = *j.FinishedAt
	}
	cost, energy, computed := computeJobUsage(&j, finished)
	if s.DB != nil {
		us, ok := s.DB.(storage.UsageOnceStore)
		if !ok {
			// Fail closed: without the exactly-once transition a retry or a
			// second replica could double-account. Every shipped store
			// implements the contract (PostgresStore, memStore, FaultyStore),
			// so this is a programming-error guard, not a supported mode.
			return errors.New("server: usage store lacks the exactly-once usage contract")
		}
		won, err := us.RecordUsageOnce(ctx, j.ID, cost, energy)
		if err != nil {
			// Nothing was recorded; the marker and the metrics stay
			// untouched so the retry converges on exactly one winner.
			return err
		}
		if !won {
			// Another attempt (or replica) already recorded this job's
			// usage: never move process metrics for a lost race.
			return nil
		}
		if computed {
			s.metricAdd("kiwi_usage_cost_total", cost, nil)
			s.metricAdd("kiwi_usage_energy_total", energy, nil)
			s.metricObserve("kiwi_job_duration_seconds", finished.Sub(*j.StartedAt).Seconds(), nil)
		}
		return nil
	}
	// The marker check above ran without s.mu; re-check it against the live
	// job inside the same critical section that records. The outbox
	// serializer is not the arbiter of the record — a direct reconcile can
	// race a flush — so a second caller that slipped past the unlocked check
	// must lose here instead of re-adding the metrics and the trailing
	// window entry.
	s.mu.Lock()
	defer s.mu.Unlock()
	live, ok := s.jobs[j.ID]
	if !ok {
		return nil
	}
	if live.UsageRecorded {
		return nil
	}
	// Persist the live row (the effect's copy may predate unrelated state
	// changes made while this effect computed) carrying the usage amounts
	// this effect computed. Durability first, exactly like
	// effectDeploymentFinish: a failed snapshot write must roll the marker
	// and the amounts back, or the retry would short-circuit on the leaked
	// marker and the usage would never reach disk (the effect would be
	// ACKed from a state the snapshot does not contain).
	prev := live
	live.UsageRecorded = true
	if computed {
		live.Cost = cost
		live.EnergyWh = energy
	}
	s.jobs[j.ID] = live
	if err := s.persistCheckedErrLocked("job.usage_account"); err != nil {
		s.jobs[j.ID] = prev
		return err
	}
	if computed {
		// Metrics and the trailing window move only after the amounts are
		// durable: a failed attempt must not claim usage the snapshot
		// cannot reconstruct.
		s.accountJobUsageMetrics(cost, energy, finished)
	}
	return nil
}

// effectRunAggregate re-aggregates the completed job's run and every parent
// run that waits on it (wait=true downstream children). The recomputation is
// a pure function of durable state, so it is idempotent by construction.
func (s *Server) effectRunAggregate(ctx context.Context, j model.Job) error {
	if s.DB != nil {
		if err := s.adjustRunForChildrenDB(ctx, j.RunID); err != nil {
			return err
		}
		return s.refreshDownstreamParentsDB(ctx, j.RunID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[j.RunID]; !ok {
		return nil
	}
	s.refreshRunLocked(j.RunID)
	s.refreshDownstreamParentsLocked(j.RunID)
	return s.persistCheckedErrLocked("job.run_aggregate")
}

// effectForgeStatus mirrors the run's terminal state to the forge. The
// publish only queues durable forge intents, and forge status updates are
// idempotent at the forge, so the terminal-status check is the marker.
func (s *Server) effectForgeStatus(ctx context.Context, j model.Job) error {
	run, err := s.runForJob(ctx, j.RunID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if run.Status.Terminal() {
		return s.publishForgeStatus(ctx, run)
	}
	return nil
}

// runForJob resolves the run a job belongs to.
func (s *Server) runForJob(ctx context.Context, runID string) (model.Run, error) {
	if s.DB != nil {
		return s.DB.GetRun(ctx, runID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[runID]
	if !ok {
		return model.Run{}, storage.ErrNotFound
	}
	return run, nil
}

// enqueueCompletionEffects durably queues the completion effect intents
// (memory/fs mode: persisted to outbox.jsonl when a store is attached). The
// inline completion pass already applied the effects; the queued intents
// become no-ops via their markers unless a crash lost the inline pass, in
// which case the flush performs them. TWO intents are queued:
// completion_reconcile (internal consistency, unbounded retries) and
// forge_delivery (external publication, bounded retries + dead-letter).
//
// ctx is the completion request/reconciliation context and reaches the
// durable enqueue: a canceled request leaves no half-persisted intent, and
// the caller's idempotent replay (repairCompletionIntents) re-runs the whole
// recording. IDs are DETERMINISTIC (storage.CompletionEffectID over job +
// lease generation + kind), exactly like the DB-mode rows the completion
// transaction commits: a replayed completion (receipt match) re-runs this
// idempotently and converges on the same two intents instead of duplicating
// them, which is what makes the fs replay path able to repair a crash between
// the durable completion and the outbox append (FA-1).
func (s *Server) enqueueCompletionEffects(ctx context.Context, j model.Job, run model.Run) error {
	return s.enqueueCompletionEffectIntents(ctx, j.ID, run.ID, j.LeaseGeneration)
}

// enqueueCompletionEffectIntents queues the two deterministic completion
// effect intents for one (job, lease generation). The caller supplies the
// generation explicitly so a receipt-replayed completion converges on the
// ORIGINAL generation's intent IDs even when the live job has since been
// re-leased under a newer one. ctx reaches the durable enqueue per intent.
func (s *Server) enqueueCompletionEffectIntents(ctx context.Context, jobID, runID string, generation int64) error {
	payload, err := jsonMarshal(storage.CompletionEffectsPayload{JobID: jobID, RunID: runID})
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, kind := range storage.NewCompletionEffectKinds() {
		if err := s.outbox.Enqueue(ctx, forge.OutboxItem{
			ID:        storage.CompletionEffectID(jobID, generation, kind),
			Kind:      kind,
			Payload:   payload,
			CreatedAt: now,
		}); err != nil {
			return err
		}
	}
	return nil
}

// repairCompletionIntents re-ensures the deterministic completion effect
// intents exist in the outbox for a receipt-replayed completion in
// fs/memory mode. The fs outbox is a SEPARATE journal from the snapshot: a
// crash (or a failed append) between the durable completion and
// enqueueCompletionEffects leaves the terminal forge_delivery intent
// unrecorded, and the replay path would otherwise only reconcile internal
// effects, losing the terminal forge publication forever. Enqueue is
// idempotent by deterministic ID and skips already-delivered IDs, so a
// replay after a successful completion is a no-op. A job that no longer
// exists is treated as already reconciled.
//
// ctx is the replay request's context: it reaches the durable enqueue, so a
// canceled replay aborts before persisting and the caller answers 503
// WITHOUT acknowledging the completion; the runner's retry re-runs the
// repair.
func (s *Server) repairCompletionIntents(ctx context.Context, jobID string, generation int64) error {
	s.mu.Lock()
	j, ok := s.jobs[jobID]
	s.mu.Unlock()
	if !ok {
		return nil
	}
	return s.enqueueCompletionEffectIntents(ctx, jobID, j.RunID, generation)
}

// enqueueCompletionEffectsLocal queues in-memory-only copies of the effect
// intents for a committed DB-mode completion. The durable rows already exist
// inside the completion transaction under the deterministic effect IDs; the
// local copies let this instance's flush loop dispatch and ack them.
func (s *Server) enqueueCompletionEffectsLocal(jobID, runID string, generation int64) {
	payload, err := jsonMarshal(storage.CompletionEffectsPayload{JobID: jobID, RunID: runID})
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, kind := range storage.NewCompletionEffectKinds() {
		s.outbox.EnqueueLocal(forge.OutboxItem{
			ID:        storage.CompletionEffectID(jobID, generation, kind),
			Kind:      kind,
			Payload:   payload,
			CreatedAt: now,
		})
	}
}
