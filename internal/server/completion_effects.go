package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// reconcileCompletionEffects runs every post-completion effect for jobID.
// It is the idempotent reconciliation behind the completion outbox flush and
// the defensive receipt replay: each effect checks its own durable marker
// (downstream link row, deployment finished_at, job usage_recorded flag,
// recomputed run aggregation, terminal run forge publish) before acting, so
// at-least-once dispatch can never double-account. A job that no longer
// exists is treated as already reconciled.
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
	if err := s.effectRunAggregate(ctx, j); err != nil {
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
	targetRepo := strings.TrimSpace(cj.Job.Downstream.Repository)
	if targetRepo == "" {
		return nil
	}
	targetRef := strings.TrimSpace(cj.Job.Downstream.Ref)
	if targetRef == "" {
		run, err := s.runForJob(ctx, j.RunID)
		if err != nil {
			return err
		}
		targetRef = run.Ref
	}
	if link, ok, err := s.getDownstreamLink(ctx, j.ID, targetRepo, targetRef); err != nil {
		return err
	} else if ok && link.ParentJobID != "" {
		return nil
	}
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

// effectDeploymentFinish marks the deployment record of a completed
// environment job with its terminal status. Marker: a non-nil finished_at
// (or a missing deployment record) means there is nothing left to finish.
func (s *Server) effectDeploymentFinish(ctx context.Context, j model.Job) error {
	if j.Environment == "" {
		return nil
	}
	d, found, err := s.deploymentForJob(ctx, j)
	if err != nil {
		return err
	}
	if !found || d.ID == "" {
		return nil
	}
	if d.FinishedAt != nil {
		return nil
	}
	finished := time.Now().UTC()
	if j.FinishedAt != nil {
		finished = *j.FinishedAt
	}
	if s.DB != nil {
		s.finishDeploymentDB(ctx, j, j.Status, finished)
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.deployments[j.ID]; ok {
		cur.Status = j.Status
		cur.FinishedAt = &finished
		s.deployments[j.ID] = cur
	}
	return s.persistLocked()
}

// effectUsageAccount computes and persists the completed job's cost/energy
// usage. Marker: the job's usage_recorded flag — once set (with cost/energy
// persisted on the job row), replays skip the computation so metrics and
// budgets are never double-accounted.
func (s *Server) effectUsageAccount(ctx context.Context, j model.Job) error {
	if j.UsageRecorded {
		return nil
	}
	if j.StartedAt != nil {
		finished := time.Now().UTC()
		if j.FinishedAt != nil {
			finished = *j.FinishedAt
		}
		s.recordJobUsage(&j, finished)
		s.metricObserve("kiwi_job_duration_seconds", finished.Sub(*j.StartedAt).Seconds(), nil)
	}
	j.UsageRecorded = true
	if s.DB != nil {
		return s.DB.UpdateJob(ctx, j)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.jobs[j.ID]; !ok {
		return nil
	}
	s.jobs[j.ID] = j
	return s.persistLocked()
}

// effectRunAggregate re-aggregates the completed job's run and every parent
// run that waits on it (wait=true downstream children). The recomputation is
// a pure function of durable state, so it is idempotent by construction.
func (s *Server) effectRunAggregate(ctx context.Context, j model.Job) error {
	if s.DB != nil {
		s.adjustRunForChildrenDB(ctx, j.RunID)
		s.refreshDownstreamParentsDB(ctx, j.RunID)
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[j.RunID]; !ok {
		return nil
	}
	s.refreshRunLocked(j.RunID)
	s.refreshDownstreamParentsLocked(j.RunID)
	return s.persistLocked()
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
		s.publishGitHubStatus(run)
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
// (memory/fs mode: random IDs, persisted to outbox.jsonl when a store is
// attached). The inline completion pass already applied the effects; the
// queued intents become no-ops via their markers unless a crash lost the
// inline pass, in which case the flush performs them.
func (s *Server) enqueueCompletionEffects(j model.Job, run model.Run) error {
	payload, err := json.Marshal(storage.CompletionEffectsPayload{JobID: j.ID, RunID: run.ID})
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, kind := range storage.CompletionEffectKinds() {
		if err := s.outbox.Enqueue(forge.OutboxItem{Kind: kind, Payload: payload, CreatedAt: now}); err != nil {
			return err
		}
	}
	return nil
}

// enqueueCompletionEffectsLocal queues in-memory-only copies of the effect
// intents for a committed DB-mode completion. The durable rows already exist
// inside the completion transaction under the deterministic effect IDs; the
// local copies let this instance's flush loop dispatch and ack them.
func (s *Server) enqueueCompletionEffectsLocal(jobID, runID string, generation int64) {
	payload, err := json.Marshal(storage.CompletionEffectsPayload{JobID: jobID, RunID: runID})
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, kind := range storage.CompletionEffectKinds() {
		s.outbox.EnqueueLocal(forge.OutboxItem{
			ID:        storage.CompletionEffectID(jobID, generation, kind),
			Kind:      kind,
			Payload:   payload,
			CreatedAt: now,
		})
	}
}
