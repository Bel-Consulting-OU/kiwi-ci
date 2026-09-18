package server

import (
	"context"
	"net/http"
	"sort"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/deploy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// recordDeploymentLocked creates the deployment record for a job starting
// its environment deployment, if one does not exist yet. Idempotent per
// job. Called under s.mu (memory mode scheduling path).
func (s *Server) recordDeploymentLocked(j model.Job, startedAt time.Time) model.Deployment {
	if d, ok := s.deployments[j.ID]; ok {
		return d
	}
	// ApprovedAt is nil: the job tracks ApprovedBy but not the approval
	// timestamp.
	d := deploy.NewDeployment(j, j.ApprovedBy, nil, &startedAt)
	s.deployments[j.ID] = d
	s.auditLocked("deployment.started", "scheduler", j.RunID, j.ID, "deployment started", map[string]string{"environment": j.Environment})
	return d
}

// recordDeploymentDB creates the deployment record in DB mode. The durable
// insert commits FIRST: the in-memory mirror and the deployment.started
// audit event are only written after DeploymentStore accepted the record, so
// a persistence failure leaves no marker behind and the caller can retry
// (or the completion deployment effect can rebuild the record). Idempotent
// per job ID.
func (s *Server) recordDeploymentDB(ctx context.Context, j model.Job, startedAt time.Time) (model.Deployment, error) {
	s.mu.Lock()
	if d, ok := s.deployments[j.ID]; ok {
		s.mu.Unlock()
		return d, nil
	}
	s.mu.Unlock()
	d := deploy.NewDeployment(j, j.ApprovedBy, nil, &startedAt)
	if ds, ok := s.DB.(storage.DeploymentStore); ok {
		if err := ds.InsertDeployment(ctx, d); err != nil {
			return model.Deployment{}, err
		}
	}
	s.mu.Lock()
	if cur, ok := s.deployments[j.ID]; ok {
		// A concurrent create won the race; the durable row is keyed by the
		// deterministic per-job deployment ID, so it is the same record.
		s.mu.Unlock()
		return cur, nil
	}
	s.deployments[j.ID] = d
	s.mu.Unlock()
	s.auditLocked("deployment.started", "scheduler", j.RunID, j.ID, "deployment started", map[string]string{"environment": j.Environment})
	return d, nil
}

// recordDeployment is POST /api/v1/jobs/{id}/deployments: it creates (or
// returns the existing) deployment record for an environment job. The
// scheduling path calls recordDeploymentLocked/recordDeploymentDB
// automatically when such a job is leased; this endpoint exists for
// explicit record creation and DB-mode parity.
func (s *Server) recordDeployment(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	if s.DB != nil {
		j, err := s.DB.GetJob(r.Context(), jobID)
		if err == storage.ErrNotFound {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if j.Environment == "" {
			http.Error(w, "job has no environment", http.StatusConflict)
			return
		}
		d, err := s.recordDeploymentDB(r.Context(), j, time.Now().UTC())
		if err != nil {
			// Fail closed: a deployment record that is not durable must not
			// be acknowledged (no in-memory marker, no audit).
			http.Error(w, err.Error(), 500)
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
	d := s.recordDeploymentLocked(j, time.Now().UTC())
	s.persistCheckedLocked("deployment.record")
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
			http.Error(w, err.Error(), 500)
			return
		}
		if !s.requireRunRead(w, r, run) {
			return
		}
		out := []model.Deployment{}
		if ds, ok := s.DB.(storage.DeploymentStore); ok {
			recs, err := ds.ListDeploymentsByRun(r.Context(), runID)
			if err != nil {
				http.Error(w, err.Error(), 500)
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
		d = deploy.NewDeployment(j, j.ApprovedBy, nil, &started)
		if err := ds.InsertDeployment(ctx, d); err != nil {
			return err
		}
	}
	if d.FinishedAt != nil {
		return nil
	}
	d.Status = status
	d.FinishedAt = &finishedAt
	if hasStore {
		if err := ds.UpdateDeploymentStatus(ctx, d.ID, status, &finishedAt); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.deployments[j.ID] = d
	s.mu.Unlock()
	s.auditLocked("deployment.completed", "scheduler", j.RunID, j.ID, "deployment finished", map[string]string{"environment": j.Environment, "status": string(status)})
	return nil
}
