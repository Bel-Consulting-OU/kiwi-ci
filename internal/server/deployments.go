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

// recordDeploymentDB creates the deployment record in DB mode: the record
// is persisted through DeploymentStore and mirrored in memory for the
// completion path's ID lookup.
func (s *Server) recordDeploymentDB(ctx context.Context, j model.Job, startedAt time.Time) model.Deployment {
	s.mu.Lock()
	d := s.recordDeploymentLocked(j, startedAt)
	s.mu.Unlock()
	if ds, ok := s.DB.(storage.DeploymentStore); ok {
		if err := ds.InsertDeployment(ctx, d); err != nil {
			s.logError("deployment record insert failed", "job", j.ID, "error", err.Error())
		}
	}
	return d
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
		d := s.recordDeploymentDB(r.Context(), j, time.Now().UTC())
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
	_ = s.persistLocked()
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
// with the job's terminal status.
func (s *Server) finishDeploymentDB(ctx context.Context, j model.Job, status model.Status, finishedAt time.Time) {
	if j.Environment == "" {
		return
	}
	s.mu.Lock()
	d, ok := s.deployments[j.ID]
	s.mu.Unlock()
	if !ok {
		if ds, isDS := s.DB.(storage.DeploymentStore); isDS {
			recs, err := ds.ListDeploymentsByRun(ctx, j.RunID)
			if err == nil {
				for _, rec := range recs {
					if rec.JobID == j.ID {
						d = rec
						break
					}
				}
			}
		}
	}
	if d.ID == "" {
		return
	}
	d.Status = status
	d.FinishedAt = &finishedAt
	s.mu.Lock()
	s.deployments[j.ID] = d
	s.mu.Unlock()
	if ds, ok := s.DB.(storage.DeploymentStore); ok {
		if err := ds.UpdateDeploymentStatus(ctx, d.ID, status, &finishedAt); err != nil {
			s.logError("deployment status update failed", "deployment", d.ID, "error", err.Error())
		}
	}
	s.auditLocked("deployment.completed", "scheduler", j.RunID, j.ID, "deployment finished", map[string]string{"environment": j.Environment, "status": string(status)})
}
