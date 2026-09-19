package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// downloadDependency implements
// GET /api/v1/jobs/{id}/dependencies/{producer}/{artifact}: a leased job
// fetches an artifact produced by one of its dependency jobs. The consumer
// must declare a downloads entry for the artifact, the producer must be a
// direct dependency (job.Needs), and exactly one matching artifact must
// exist — ambiguous matches are rejected rather than silently picked.

func (s *Server) downloadDependency(w http.ResponseWriter, r *http.Request) {
	producer := r.PathValue("producer")
	artifact := cleanBlobName(r.PathValue("artifact"))
	if artifact == "" {
		http.Error(w, "invalid artifact name", http.StatusBadRequest)
		return
	}
	runnerID := r.Header.Get("X-Kiwi-Runner-ID")
	token := r.Header.Get("X-Kiwi-Lease-Token")
	gen, _ := strconv.ParseInt(r.Header.Get("X-Kiwi-Lease-Generation"), 10, 64)
	j, authErr := s.authorizeRunnerLease(r, runnerID, token, gen)
	if authErr != nil {
		s.writeLeaseAuthError(w, r, authErr)
		return
	}
	// The consumer must declare a download of this artifact from the
	// producer. Downloads live in the pipeline spec, so the job's pipeline
	// text is recompiled (downloads only).
	cj, ok := compileJobFromPipeline(j)
	if !ok {
		http.Error(w, "job pipeline unavailable", http.StatusInternalServerError)
		return
	}
	declared := false
	for _, d := range cj.Job.Downloads {
		if d.Name != artifact {
			continue
		}
		if d.From == producer {
			declared = true
			break
		}
	}
	if !declared {
		s.auditLocked("artifact.download_rejected", runnerID, j.RunID, j.ID, "consumer did not declare the download", map[string]string{"producer": producer, "artifact": artifact})
		http.Error(w, "job does not declare a download of this artifact from the producer", http.StatusForbidden)
		return
	}
	// The producer must be one of the consumer's direct dependencies, and
	// its key must match the requested variant (BaseKey == producer or
	// Key == producer for matrix-expanded variants).
	var producerJobs []model.Job
	producerIDs := map[string]bool{}
	for _, need := range j.Needs {
		producerIDs[need] = true
	}
	s.eachJobByRun(r.Context(), j.RunID, func(pj model.Job) {
		if !producerIDs[pj.ID] {
			return
		}
		if pj.Key == producer || pj.BaseKey == producer {
			producerJobs = append(producerJobs, pj)
		}
	})
	if len(producerJobs) == 0 {
		s.auditLocked("artifact.download_rejected", runnerID, j.RunID, j.ID, "producer is not a dependency", map[string]string{"producer": producer, "artifact": artifact})
		http.Error(w, "producer is not a dependency of this job", http.StatusForbidden)
		return
	}
	// The artifact name must match the producer's declared contract and
	// exactly one matching artifact record must exist.
	var matches []model.ArtifactRecord
	for _, pj := range producerJobs {
		contracts, cerr := s.contractsForJob(r.Context(), pj)
		if cerr != nil {
			continue
		}
		if _, _, ok := contractForUploadName(contracts, artifact); !ok {
			continue
		}
		recs, lerr := s.findArtifactByJobName(r.Context(), pj.RunID, pj.ID, artifact)
		if lerr != nil {
			s.internalError(w, r, lerr, "")
			return
		}
		matches = append(matches, recs...)
	}
	if len(matches) == 0 {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	}
	if len(matches) > 1 {
		s.auditLocked("artifact.download_rejected", runnerID, j.RunID, j.ID, "ambiguous artifact match", map[string]string{"producer": producer, "artifact": artifact})
		http.Error(w, "ambiguous artifact match across producer variants", http.StatusConflict)
		return
	}
	rec := matches[0]
	f, err := s.openArtifact(r.Context(), rec)
	if err != nil {
		http.Error(w, "artifact bytes missing", http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", rec.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.tar.gz"`, cleanBlobName(rec.Name)))
	w.Header().Set("X-Kiwi-Content-SHA256", rec.SHA256)
	w.Header().Set("X-Kiwi-Producer-Job", rec.JobKey)
	w.Header().Set("Content-Length", strconv.FormatInt(rec.Size, 10))
	s.metricAdd("kiwi_artifact_bytes_total", float64(rec.Size), nil)
	if _, err := io.Copy(w, f); err != nil {
		s.logf("dependency download: %v", err)
	}
}

// eachJobByRun iterates the jobs of one run: through the store in DB mode,
// over the memory map otherwise.
func (s *Server) eachJobByRun(ctx context.Context, runID string, fn func(model.Job)) {
	if s.DB != nil {
		jobs, err := s.DB.ListJobsByRun(ctx, runID)
		if err != nil {
			return
		}
		for _, j := range jobs {
			fn(j)
		}
		return
	}
	s.mu.Lock()
	js := make([]model.Job, 0)
	for _, j := range s.jobs {
		if j.RunID == runID {
			js = append(js, j)
		}
	}
	s.mu.Unlock()
	for _, j := range js {
		fn(j)
	}
}
