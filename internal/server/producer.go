package server

import (
	"context"
	"fmt"
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
	// exactly one matching artifact record must exist. The matching
	// contract's max_size is the producer-declared download bound.
	var matches []model.ArtifactRecord
	var contractMaxSize int64
	for _, pj := range producerJobs {
		contracts, cerr := s.contractsForJob(r.Context(), pj)
		if cerr != nil {
			continue
		}
		contract, _, ok := contractForUploadName(contracts, artifact)
		if !ok {
			continue
		}
		recs, lerr := s.findArtifactByJobName(r.Context(), pj.RunID, pj.ID, artifact)
		if lerr != nil {
			s.internalError(w, r, lerr, "")
			return
		}
		if len(recs) > 0 {
			contractMaxSize = contract.MaxSize
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
	// Bound the transfer by the producer's declared contract (never above the
	// global blob ceiling). The record's size was already clamped at upload,
	// but a tampered or legacy record must still never stream past the
	// declared limit.
	limit := dependencySizeLimit(contractMaxSize)
	if rec.Size < 0 || rec.Size > limit {
		s.auditLocked("artifact.download_rejected", runnerID, j.RunID, j.ID, "dependency artifact exceeds the declared size limit", map[string]string{"producer": producer, "artifact": artifact, "size": strconv.FormatInt(rec.Size, 10), "max": strconv.FormatInt(limit, 10)})
		s.metricAdd(metricDownloadIntegrityFailures, 1, map[string]string{"scope": "dependency", "kind": "size"})
		s.logError("download integrity failure: aborting dependency response", "scope", "dependency", "sha256", rec.SHA256, "kind", "size", "error", fmt.Sprintf("artifact is %d bytes, declared limit is %d", rec.Size, limit))
		http.Error(w, "dependency artifact exceeds the declared maximum size", http.StatusServiceUnavailable)
		return
	}
	f, err := s.openArtifact(r.Context(), rec)
	if err != nil {
		http.Error(w, "artifact bytes missing", http.StatusNotFound)
		return
	}
	// Strong integrity: the same path the artifact download uses preverifies
	// the exact length and digest before committing the response and aborts
	// (with the shared integrity metric) on any copy/size/digest failure. A
	// truncated or corrupt dependency can therefore never be served as a
	// successful download.
	s.metricAdd("kiwi_artifact_bytes_total", float64(rec.Size), nil)
	s.serveVerifiedDownload(w, r, "dependency", f, rec.Size, rec.SHA256, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", rec.ContentType)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.tar.gz"`, cleanBlobName(rec.Name)))
		w.Header().Set("X-Kiwi-Content-SHA256", rec.SHA256)
		w.Header().Set("X-Kiwi-Producer-Job", rec.JobKey)
		w.Header().Set("Content-Length", strconv.FormatInt(rec.Size, 10))
	})
}

// dependencySizeLimit is the effective download bound for one dependency
// artifact: the producer's declared contract max_size, never above the global
// blob ceiling. It mirrors the artifact upload limit (blobs.go) so a record
// that somehow exceeds its contract is refused rather than streamed.
func dependencySizeLimit(contractMaxSize int64) int64 {
	limit := maxBlobBytes
	if contractMaxSize > 0 && contractMaxSize < limit {
		limit = contractMaxSize
	}
	return limit
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
