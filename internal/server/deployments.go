package server

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/deploy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// errDeploymentStoreUnsupported is defense in depth: SwitchToDB already
// refuses a store without the deployment contract at startup, so DB mode
// cannot silently degrade deployment state to the process-local mirror.
var errDeploymentStoreUnsupported = errors.New("server: deployment store unavailable")

// recordDeploymentLocked creates the deployment record for a job starting
// its environment deployment, if one does not exist yet. Idempotent per
// job. Called under s.mu (memory mode scheduling path).
func (s *Server) recordDeploymentLocked(j model.Job, startedAt time.Time) model.Deployment {
	if d, ok := s.deployments[j.ID]; ok {
		return d
	}
	if j.StartedAt != nil {
		// The job carries the authoritative first-start instant: a retried
		// lease must not re-stamp the deployment with a later attempt's
		// clock.
		startedAt = *j.StartedAt
	}
	// ApprovedAt is nil: the job tracks ApprovedBy but not the approval
	// timestamp.
	d := deploy.NewDeployment(j, j.ApprovedBy, nil, &startedAt)
	s.deployments[j.ID] = d
	s.auditLocked("deployment.started", "scheduler", j.RunID, j.ID, "deployment started", map[string]string{"environment": j.Environment})
	return d
}

// installDeploymentMirror caches the canonical durable deployment record for
// one job unless a concurrent writer already installed a record. Writers
// persist durably BEFORE touching the mirror, so a record that arrived while
// our durable store call was in flight is at least as new as ours (the
// completion effect can finish the row between our insert and this call):
// the mirror must never regress to an older snapshot. It returns the record
// the mirror holds after the call.
func (s *Server) installDeploymentMirror(jobID string, rec model.Deployment) model.Deployment {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.deployments[jobID]; ok {
		return cur
	}
	s.deployments[jobID] = rec
	return rec
}

// recordDeploymentDB creates the deployment record in DB mode. The durable
// insert and its deployment.started audit commit in ONE transaction
// (StartDeployment), so a created record can never exist without its audit
// and a deterministic-ID replay (created=false) can never duplicate it; the
// local mirror always caches the STORED canonical record. Persistence failure
// leaves no marker behind and the caller can retry (or the completion
// deployment effect can rebuild the record).
func (s *Server) recordDeploymentDB(ctx context.Context, j model.Job, startedAt time.Time) (model.Deployment, error) {
	s.mu.Lock()
	if d, ok := s.deployments[j.ID]; ok {
		s.mu.Unlock()
		return d, nil
	}
	s.mu.Unlock()
	ds, ok := s.DB.(storage.DeploymentStore)
	if !ok {
		// SwitchToDB refuses stores without the contract; this is defense in
		// depth for direct wiring.
		return model.Deployment{}, errDeploymentStoreUnsupported
	}
	if j.StartedAt != nil {
		// The job row is the authority on when the work actually started:
		// the claim transaction stamped started_at with the database clock,
		// so the deployment can never disagree with the job (or float with
		// the calling replica's clock).
		startedAt = *j.StartedAt
	}
	auditID, err := newID()
	if err != nil {
		return model.Deployment{}, err
	}
	audit := model.AuditEvent{
		ID: auditID, Action: "deployment.started", Actor: "scheduler",
		RunID: j.RunID, JobID: j.ID, Message: "deployment started",
		Metadata: map[string]string{"environment": j.Environment},
	}
	d, _, err := ds.StartDeployment(ctx, deploy.NewDeployment(j, j.ApprovedBy, nil, &startedAt), audit)
	if err != nil {
		return model.Deployment{}, err
	}
	// Install the canonical record without regressing a newer state that a
	// concurrent writer (for example the completion effect finishing the
	// row just created) committed while the insert was in flight.
	return s.installDeploymentMirror(j.ID, d), nil
}

// recordDeployment is POST /api/v1/jobs/{id}/deployments: it creates (or
// returns the existing) deployment record for an environment job that is
// ACTUALLY RUNNING. The scheduling path calls
// recordDeploymentLocked/recordDeploymentDB automatically when such a job is
// leased; this endpoint exists for explicit record creation and DB-mode
// parity. It refuses any non-running job (queued, waiting approval, blocked,
// terminal): a deployment cannot start before its job does, and
// StartedAt is derived from the authoritative job (never the request time),
// so administrative API usage cannot fabricate a running deployment.
func (s *Server) recordDeployment(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	if s.DB != nil {
		j, err := s.DB.GetJob(r.Context(), jobID)
		if err == storage.ErrNotFound {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			s.internalError(w, r, err, "")
			return
		}
		if j.Environment == "" {
			http.Error(w, "job has no environment", http.StatusConflict)
			return
		}
		if j.Status != model.StatusRunning || j.StartedAt == nil {
			http.Error(w, "deployment can only be recorded for a running job", http.StatusConflict)
			return
		}
		d, err := s.recordDeploymentDB(r.Context(), j, *j.StartedAt)
		if err != nil {
			// Fail closed: a deployment record that is not durable must not
			// be acknowledged (no in-memory marker, no audit).
			s.internalError(w, r, err, "")
			return
		}
		writeJSON(w, http.StatusCreated, d)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if j.Environment == "" {
		http.Error(w, "job has no environment", http.StatusConflict)
		return
	}
	if j.Status != model.StatusRunning || j.StartedAt == nil {
		http.Error(w, "deployment can only be recorded for a running job", http.StatusConflict)
		return
	}
	prev, had := s.deployments[jobID]
	d := s.recordDeploymentLocked(j, *j.StartedAt)
	if perr := s.persistCheckedErrLocked("deployment.record"); perr != nil {
		// The record never became durable: restore the pre-mutation mirror
		// (or remove the fresh entry) and fail closed, exactly like the DB
		// path. A later successful persist must not commit a 201 the
		// client was told failed.
		if had {
			s.deployments[jobID] = prev
		} else {
			delete(s.deployments, jobID)
		}
		http.Error(w, "deployment record not durable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusCreated, d)
}

// listDeployments is GET /api/v1/runs/{id}/deployments.
func (s *Server) listDeployments(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	if s.DB != nil {
		run, err := s.DB.GetRun(r.Context(), runID)
		if err == storage.ErrNotFound {
			http.NotFound(w, r)
			return
		} else if err != nil {
			s.internalError(w, r, err, "")
			return
		}
		if !s.requireRunRead(w, r, run) {
			return
		}
		out := []model.Deployment{}
		if ds, ok := s.DB.(storage.DeploymentStore); ok {
			recs, err := ds.ListDeploymentsByRun(r.Context(), runID)
			if err != nil {
				s.internalError(w, r, err, "")
				return
			}
			out = append(out, recs...)
		}
		s.mu.Lock()
		seen := map[string]bool{}
		for _, d := range out {
			seen[d.ID] = true
		}
		for _, d := range s.deployments {
			if d.RunID == runID && !seen[d.ID] {
				out = append(out, d)
			}
		}
		s.mu.Unlock()
		sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
		writeJSON(w, http.StatusOK, out)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[runID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !s.requireRunRead(w, r, run) {
		return
	}
	out := []model.Deployment{}
	for _, d := range s.deployments {
		if d.RunID == runID {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	writeJSON(w, http.StatusOK, out)
}

// finishDeploymentDB marks the deployment for a completed environment job
// with the job's terminal status, creating the record when the create path
// never managed to persist one (a lease-time insert failure that the
// completion effect now converges after the store recovers). A deployment
// whose finished_at is already set is the idempotency marker for the
// completion deployment_finish effect: replays skip it instead of
// re-auditing or overwriting the record.
//
// Durability contract: every DeploymentStore write happens BEFORE the
// in-memory mirror and the deployment.completed audit event are touched. A
// returned error leaves the marker unset and the completion outbox retries
// the whole effect; the record is rebuilt from the job on the retry.
func (s *Server) finishDeploymentDB(ctx context.Context, j model.Job, status model.Status, finishedAt time.Time) error {
	if j.Environment == "" {
		return nil
	}
	ds, hasStore := s.DB.(storage.DeploymentStore)
	d, found, err := s.deploymentForJob(ctx, j)
	if err != nil {
		return err
	}
	if !found || d.ID == "" {
		if !hasStore {
			// No durable deployment store to converge: DB-less servers use
			// the in-memory effect path.
			return nil
		}
		started := finishedAt
		if j.StartedAt != nil {
			started = *j.StartedAt
		}
		stored, _, err := ds.InsertDeploymentOnce(ctx, deploy.NewDeployment(j, j.ApprovedBy, nil, &started))
		if err != nil {
			return err
		}
		// Use the canonical stored record: another replica may have created
		// it (with its own finish state) between our read and this insert.
		d = stored
	}
	if d.FinishedAt != nil {
		return nil
	}
	if hasStore {
		// The finish marker and the deployment.completed audit commit in ONE
		// transaction: an audit failure rolls the marker back, so the finish
		// stays retryable and the exactly-once audit is not lost. changed is
		// false when another replica finished the row first: it owns the
		// audit, and this caller must not append a second one.
		auditID, err := newID()
		if err != nil {
			return err
		}
		audit := model.AuditEvent{
			ID: auditID, Action: "deployment.completed", Actor: "scheduler",
			RunID: j.RunID, JobID: j.ID, Message: "deployment finished",
			Metadata: map[string]string{"environment": j.Environment, "status": string(status)},
		}
		changed, err := ds.FinishDeploymentOnce(ctx, d.ID, status, finishedAt, audit)
		if err != nil {
			return err
		}
		d.Status = status
		fin := finishedAt.UTC()
		d.FinishedAt = &fin
		s.mu.Lock()
		s.deployments[j.ID] = d
		s.mu.Unlock()
		if !changed {
			return nil
		}
		return nil
	}
	d.Status = status
	d.FinishedAt = &finishedAt
	s.mu.Lock()
	s.deployments[j.ID] = d
	s.mu.Unlock()
	s.auditLocked("deployment.completed", "scheduler", j.RunID, j.ID, "deployment finished", map[string]string{"environment": j.Environment, "status": string(status)})
	return nil
}
