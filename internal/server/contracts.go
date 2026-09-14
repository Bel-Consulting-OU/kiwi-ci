package server

import (
	"context"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"gopkg.in/yaml.v3"
)

// Artifact contracts: at enqueue the server persists the set of artifacts
// each job promises to produce. Uploads are then checked against the
// contract: undeclared names are rejected, the declared retention drives
// expiry, and idempotent re-uploads are scoped to (job, lease generation,
// name).

const (
	defaultRetention = 30 * 24 * time.Hour
	sbomSuffix       = ".sbom"
	sigstoreSuffix   = ".sigstore"
)

// buildJobContracts compiles the artifact contract map for one compiled
// job. Retention is resolved now (via pipeline.ParseRetention) so uploads
// never re-parse the pipeline, and required/SBOM/Sigstore declarations are
// frozen into the contract at compile time.
func buildJobContracts(cj pipeline.CompiledJob) map[string]storage.ArtifactContract {
	out := map[string]storage.ArtifactContract{}
	for _, a := range cj.Job.Artifacts {
		name := strings.TrimSpace(a.Name)
		if name == "" {
			continue
		}
		c := storage.ArtifactContract{
			Name:     name,
			Paths:    append([]string(nil), a.Paths...),
			Required: a.Required,
			MaxSize:  0,
			SBOM:     strings.TrimSpace(a.SBOM),
		}
		if a.Sigstore != nil {
			c.SigstoreRequired = a.Sigstore.Required
			c.SigstoreIssuer = a.Sigstore.Issuer
			c.SigstoreIdentity = a.Sigstore.Identity
		}
		if d, err := pipeline.ParseRetention(a.Retention); err == nil {
			c.Retention = d
		}
		out[name] = c
	}
	return out
}

// persistJobContracts stores the contract set for one job: through the
// ArtifactContractStore in DB mode, in the in-memory map otherwise.
func (s *Server) persistJobContracts(ctx context.Context, jobID string, contracts map[string]storage.ArtifactContract) {
	if len(contracts) == 0 {
		return
	}
	if s.DB != nil {
		if cs, ok := s.DB.(storage.ArtifactContractStore); ok {
			if err := cs.InsertJobContracts(ctx, jobID, contracts); err != nil {
				s.logError("artifact contract persistence failed", "job", jobID, "error", err.Error())
			}
			return
		}
	}
	s.mu.Lock()
	s.contracts[jobID] = contracts
	s.mu.Unlock()
}

// jobContracts returns the stored contract set for jobID. DB mode reads
// through the store; memory mode reads the map. A missing set means the
// job was enqueued before contracts existed — the caller falls back to
// rebuilding from the job's pipeline.
func (s *Server) jobContracts(ctx context.Context, jobID string) (map[string]storage.ArtifactContract, bool, error) {
	if s.DB != nil {
		if cs, ok := s.DB.(storage.ArtifactContractStore); ok {
			m, found, err := cs.GetJobContracts(ctx, jobID)
			return m, found, err
		}
		return nil, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.contracts[jobID]
	if !ok {
		return nil, false, nil
	}
	return m, true, nil
}

// contractsForJob resolves the effective contract set for a job, rebuilding
// it from the job's pipeline when no stored set exists (legacy jobs
// enqueued by an older control plane or a restart that predates contracts).
func (s *Server) contractsForJob(ctx context.Context, j model.Job) (map[string]storage.ArtifactContract, error) {
	m, ok, err := s.jobContracts(ctx, j.ID)
	if err != nil {
		return nil, err
	}
	if ok {
		return m, nil
	}
	built := map[string]storage.ArtifactContract{}
	if cj, ok := compileJobFromPipeline(j); ok {
		built = buildJobContracts(cj)
	} else if lenient, ok := lenientJobContracts(j); ok {
		built = lenient
	}
	// Persist the derived set so subsequent uploads hit the fast path.
	s.persistJobContracts(ctx, j.ID, built)
	return built, nil
}

// lenientJobContracts extracts artifact contract entries from the raw
// pipeline YAML when the strict schema does not yet admit all artifact
// fields. The strict compile path is always preferred.
func lenientJobContracts(j model.Job) (map[string]storage.ArtifactContract, bool) {
	var raw struct {
		Jobs map[string]struct {
			Artifacts []struct {
				Name      string   `yaml:"name"`
				Paths     []string `yaml:"paths"`
				Retention string   `yaml:"retention"`
			} `yaml:"artifacts"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(j.Pipeline), &raw); err != nil {
		return nil, false
	}
	keys := []string{j.Key}
	if j.BaseKey != "" && j.BaseKey != j.Key {
		keys = append(keys, j.BaseKey)
	}
	for _, key := range keys {
		job, ok := raw.Jobs[key]
		if !ok {
			continue
		}
		out := map[string]storage.ArtifactContract{}
		for _, a := range job.Artifacts {
			if strings.TrimSpace(a.Name) == "" {
				continue
			}
			c := storage.ArtifactContract{Name: a.Name, Paths: append([]string(nil), a.Paths...)}
			if d, err := pipeline.ParseRetention(a.Retention); err == nil {
				c.Retention = d
			}
			out[a.Name] = c
		}
		if len(out) > 0 {
			return out, true
		}
	}
	return nil, false
}

// contractForUploadName resolves the contract entry an upload name refers
// to, handling the conventional <name>.sbom and <name>.sigstore suffixes.
func contractForUploadName(contracts map[string]storage.ArtifactContract, name string) (storage.ArtifactContract, string, bool) {
	if c, ok := contracts[name]; ok {
		return c, "", true
	}
	if strings.HasSuffix(name, sbomSuffix) {
		base := strings.TrimSuffix(name, sbomSuffix)
		if c, ok := contracts[base]; ok {
			return c, "sbom", true
		}
	}
	if strings.HasSuffix(name, sigstoreSuffix) {
		base := strings.TrimSuffix(name, sigstoreSuffix)
		if c, ok := contracts[base]; ok {
			return c, "sigstore", true
		}
	}
	return storage.ArtifactContract{}, "", false
}

// compileJobFromPipeline recompiles one job from the persisted pipeline
// text. Used to derive per-job spec state (artifacts, downloads) that the
// model.Job does not carry as compiled fields.
func compileJobFromPipeline(j model.Job) (pipeline.CompiledJob, bool) {
	if j.Pipeline == "" {
		return pipeline.CompiledJob{}, false
	}
	spec, err := pipeline.Parse([]byte(j.Pipeline))
	if err != nil {
		return pipeline.CompiledJob{}, false
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		return pipeline.CompiledJob{}, false
	}
	cj, ok := g.Jobs[j.Key]
	return cj, ok
}

// jobArtifactSpec returns the pipeline.Artifact declaration for name on the
// job. The strict compile path (which handles matrix interpolation) is
// preferred; when the pipeline schema does not yet admit sbom/sigstore
// keys, a lenient raw-YAML parse of the job's artifact declarations is the
// fallback so the attestation gate works independently of schema rollout.
func jobArtifactSpec(j model.Job, name string) (pipeline.Artifact, bool) {
	if cj, ok := compileJobFromPipeline(j); ok {
		for _, a := range cj.Job.Artifacts {
			if a.Name == name {
				return a, true
			}
		}
		return pipeline.Artifact{}, false
	}
	var raw struct {
		Jobs map[string]struct {
			Artifacts []struct {
				Name     string                   `yaml:"name"`
				SBOM     string                   `yaml:"sbom"`
				Sigstore *pipeline.SigstoreConfig `yaml:"sigstore"`
			} `yaml:"artifacts"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(j.Pipeline), &raw); err != nil {
		return pipeline.Artifact{}, false
	}
	lookup := []string{j.Key}
	if j.BaseKey != "" && j.BaseKey != j.Key {
		lookup = append(lookup, j.BaseKey)
	}
	for _, key := range lookup {
		job, ok := raw.Jobs[key]
		if !ok {
			continue
		}
		for _, a := range job.Artifacts {
			if a.Name == name {
				return pipeline.Artifact{Name: a.Name, SBOM: a.SBOM, Sigstore: a.Sigstore}, true
			}
		}
	}
	return pipeline.Artifact{}, false
}

// contractRetention maps a contract retention onto the concrete expiry
// offset: 0 (unset) yields the platform default, negative means never
// expire, positive is used verbatim.
func contractRetention(d time.Duration) time.Duration {
	switch {
	case d > 0:
		return d
	case d < 0:
		return 0
	default:
		return defaultRetention
	}
}

// findArtifactByJobName returns every artifact record uploaded for a
// (job, name) pair. DB mode lists through the store; memory mode scans the
// in-memory map.
func (s *Server) findArtifactByJobName(ctx context.Context, runID, jobID, name string) ([]model.ArtifactRecord, error) {
	if s.DB != nil {
		out, err := s.DB.ListArtifacts(ctx, runID)
		if err != nil {
			return nil, err
		}
		var matches []model.ArtifactRecord
		for _, a := range out {
			if a.JobID == jobID && a.Name == name {
				matches = append(matches, a)
			}
		}
		return matches, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var matches []model.ArtifactRecord
	for _, a := range s.artifacts {
		if a.JobID == jobID && a.Name == name {
			matches = append(matches, a)
		}
	}
	return matches, nil
}

// existingArtifactForGeneration returns the artifact record already
// uploaded for (job, name) under the given lease generation, if any.
func existingArtifactForGeneration(records []model.ArtifactRecord, generation int64) (model.ArtifactRecord, bool) {
	for _, a := range records {
		if a.LeaseGeneration == generation {
			return a, true
		}
	}
	return model.ArtifactRecord{}, false
}

// rebuildArtifactContractsLocked re-derives the in-memory contract map for
// every loaded job from its persisted pipeline text. Called at NewPersistent
// time so fs-mode restarts recover contract enforcement without a separate
// contract store.
func (s *Server) rebuildArtifactContractsLocked() {
	for id, j := range s.jobs {
		if cj, ok := compileJobFromPipeline(j); ok {
			s.contracts[id] = buildJobContracts(cj)
		}
	}
}
