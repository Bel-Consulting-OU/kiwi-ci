package server

import (
	"net/http"
	"sort"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/deploy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// recordDeploymentLocked creates the deployment record for a job starting
// its environment deployment, if one does not exist yet. Idempotent per
// job. Called under s.mu; DB mode currently records deployments through the
// explicit endpoint only (memory-backed records are a v1 scaffold — see the
// deferred-items note).
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

// recordDeployment is POST /api/v1/jobs/{id}/deployments: it creates (or
// returns the existing) deployment record for an environment job. The
// scheduling path calls recordDeploymentLocked automatically when such a job
// is leased; this endpoint exists for explicit record creation and DB-mode
// parity.
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
		// DB mode keeps deployment records in memory for now (deferred
		// persistence); the same idempotent scaffold applies.
		s.mu.Lock()
		d := s.recordDeploymentLocked(j, time.Now().UTC())
		s.mu.Unlock()
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.DB != nil {
		if _, err := s.DB.GetRun(r.Context(), runID); err == storage.ErrNotFound {
			http.NotFound(w, r)
			return
		} else if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	} else if _, ok := s.runs[runID]; !ok {
		http.NotFound(w, r)
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
