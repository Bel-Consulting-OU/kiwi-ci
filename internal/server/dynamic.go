package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/scheduler"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/version"
)

// subtleCompare compares two byte slices in constant time.
func subtleCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

const (
	// maxGeneratedFragmentBytes bounds one generated graph fragment upload.
	maxGeneratedFragmentBytes = 256 << 10
	// maxGeneratedJobsPerFragment bounds jobs per fragment.
	maxGeneratedJobsPerFragment = 128
	// maxJobsPerRun bounds the total job count of one run across all
	// dynamic generations.
	maxJobsPerRun = 4096
	// maxDynamicDepth bounds generation nesting (0 = compiled jobs).
	maxDynamicDepth = 2
)

// generatedFragment is the POST /api/v1/jobs/{id}/generated body: a runner
// uploads the child graph its generator produced. jobs maps the child key to
// its pipeline job spec; deps carries the fragment-internal dependency edges
// (both keys must reference fragment keys; the generating job is the
// implicit dependency of every child).
type generatedFragment struct {
	Jobs map[string]pipeline.Job `json:"jobs"`
	Deps map[string][]string     `json:"deps"`
}

// generatedResponse reports the admitted fragment.
type generatedResponse struct {
	ParentJobID string   `json:"parent_job_id"`
	RunID       string   `json:"run_id"`
	Depth       int      `json:"depth"`
	JobIDs      []string `json:"job_ids"`
	Keys        []string `json:"keys"`
}

// generateJobs implements POST /api/v1/jobs/{id}/generated. The caller must
// hold the parent job's active lease; every generated child is admitted
// under the parent's effective capabilities (children can only inherit or
// reduce trust), depth- and size-bounded, and inserted atomically.
func (s *Server) generateJobs(w http.ResponseWriter, r *http.Request) {
	parentID := r.PathValue("id")
	var in generatedFragment
	if !decodeLimit(w, r, &in, maxGeneratedFragmentBytes) {
		return
	}
	runnerID := r.Header.Get("X-Kiwi-Runner-ID")
	token := r.Header.Get("X-Kiwi-Lease-Token")
	gen, _ := strconv.ParseInt(r.Header.Get("X-Kiwi-Lease-Generation"), 10, 64)
	if !s.verifyRunnerIdentity(r, runnerID) {
		http.Error(w, "runner identity mismatch", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	parent, err := s.jobForLease(ctx, parentID)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !s.validActiveLease(parent, runnerID, token, gen, time.Now().UTC()) {
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	res, aerr := s.processGeneratedFragment(ctx, parent, in)
	if aerr != nil {
		s.auditLocked("generate.rejected", runnerID, parent.RunID, parent.ID, aerr.Error(), map[string]string{"job": parent.Key})
		s.metricAdd("kiwi_dynamic_jobs_rejected_total", 1, nil)
		var adm *admissionError
		if errors.As(aerr, &adm) {
			http.Error(w, adm.Error(), adm.Status)
			return
		}
		http.Error(w, aerr.Error(), http.StatusBadRequest)
		return
	}
	s.auditLocked("generate.admitted", runnerID, parent.RunID, parent.ID, fmt.Sprintf("generated %d child jobs", len(res.JobIDs)), map[string]string{"job": parent.Key, "depth": strconv.Itoa(res.Depth)})
	s.metricAdd("kiwi_dynamic_jobs_generated_total", float64(len(res.JobIDs)), nil)
	writeJSON(w, http.StatusCreated, res)
}

// processGeneratedFragment validates and inserts one generated fragment.
// It is the shared admission path for both storage modes.
func (s *Server) processGeneratedFragment(ctx context.Context, parent model.Job, in generatedFragment) (*generatedResponse, error) {
	if len(in.Jobs) == 0 {
		return nil, fmt.Errorf("generated fragment declares no jobs")
	}
	if len(in.Jobs) > maxGeneratedJobsPerFragment {
		return nil, fmt.Errorf("generated fragment declares %d jobs, limit is %d", len(in.Jobs), maxGeneratedJobsPerFragment)
	}
	// Depth: children inherit parent depth + 1 and never exceed the cap.
	childDepth := parent.DynamicDepth + 1
	if childDepth > maxDynamicDepth {
		return nil, fmt.Errorf("generation depth %d exceeds maximum %d", childDepth, maxDynamicDepth)
	}
	// Every dep edge must reference fragment keys; deps keys must exist.
	fragment := map[string]pipeline.Job{}
	for key, j := range in.Jobs {
		if len(j.Matrix) > 0 {
			return nil, fmt.Errorf("generated job %q must not declare a matrix (fragments are pre-expanded)", key)
		}
		j.Needs = nil
		fragment[key] = j
	}
	for key, deps := range in.Deps {
		if _, ok := fragment[key]; !ok {
			return nil, fmt.Errorf("deps references unknown generated job %q", key)
		}
		seen := map[string]bool{}
		for _, dep := range deps {
			if _, ok := fragment[dep]; !ok {
				return nil, fmt.Errorf("generated job %q depends on unknown fragment job %q", key, dep)
			}
			if dep == key {
				return nil, fmt.Errorf("generated job %q depends on itself", key)
			}
			if seen[dep] {
				return nil, fmt.Errorf("generated job %q lists dependency %q more than once", key, dep)
			}
			seen[dep] = true
		}
	}
	// The strict pipeline validation path: a synthetic Spec containing the
	// fragment (needs resolved from deps) is validated by pipeline.Validate.
	synth := &pipeline.Spec{Version: 1, Jobs: map[string]pipeline.Job{}}
	for key, j := range fragment {
		j.Needs = append([]string(nil), in.Deps[key]...)
		synth.Jobs[key] = j
	}
	if err := pipeline.Validate(synth); err != nil {
		return nil, fmt.Errorf("generated fragment validation: %w", err)
	}
	// Children inherit (or reduce) the parent's effective capabilities: the
	// parent's stored effective policy is the ceiling, narrowed by the
	// current policy file and the trust floor.
	childCaps := s.generatedChildCapabilities(parent)
	oidcAudiences := policy.OIDCFromCapabilities(childCaps).AllowedAudiences
	if err := policy.ValidateAdmissionWithCapabilities(synth, childCaps); err != nil {
		return nil, fmt.Errorf("generated fragment admission: %w", err)
	}
	// The parent's own capabilities must permit child graph generation.
	if !childCaps.GenerateChildGraph {
		return nil, policyDenied("parent job's capabilities do not permit generated child graphs")
	}
	// Total jobs per run bound (enforced against the existing run).
	existing := 0
	if s.DB != nil {
		jobs, err := s.DB.ListJobsByRun(ctx, parent.RunID)
		if err != nil {
			return nil, err
		}
		existing = len(jobs)
	} else {
		s.mu.Lock()
		for _, j := range s.jobs {
			if j.RunID == parent.RunID {
				existing++
			}
		}
		s.mu.Unlock()
	}
	if existing+len(in.Jobs) > maxJobsPerRun {
		return nil, fmt.Errorf("run would grow to %d jobs, limit is %d", existing+len(in.Jobs), maxJobsPerRun)
	}

	canonical, err := pipeline.CanonicalJSON(synth)
	if err != nil {
		return nil, err
	}
	strictSpec, err := pipeline.Parse(canonical)
	if err != nil {
		return nil, fmt.Errorf("generated fragment re-parse: %w", err)
	}
	g, err := pipeline.Compile(strictSpec)
	if err != nil {
		return nil, err
	}
	policyJSON, err := json.Marshal(childCaps)
	if err != nil {
		return nil, err
	}
	pipelineDigest, err := pipeline.PipelineDigest(strictSpec)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()

	// Two-pass ID allocation: EVERY fragment key gets its job ID first, and
	// only then are the jobs and their dependency edges built. Iterating the
	// compiled graph once would read keyIDs[dep] for dependencies whose IDs
	// the map iteration order has not allocated yet, producing empty
	// dependency IDs.
	keys := make([]string, 0, len(g.Jobs))
	for key := range g.Jobs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	keyIDs := make(map[string]string, len(keys))
	for _, key := range keys {
		id, idErr := newID()
		if idErr != nil {
			return nil, fmt.Errorf("generate job id: %w", idErr)
		}
		keyIDs[key] = id
	}
	created := make(map[string]model.Job, len(keys))
	jobContracts := map[string]map[string]storage.ArtifactContract{}
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		cj := g.Jobs[key]
		id := keyIDs[key]
		ids = append(ids, id)
		cjJSON, mErr := json.Marshal(cj)
		if mErr != nil {
			return nil, mErr
		}
		digestSum := sha256.Sum256(cjJSON)
		needs := []string{parent.ID}
		for _, dep := range in.Deps[key] {
			depID := keyIDs[dep]
			if depID == "" {
				return nil, fmt.Errorf("generated job %q depends on unresolved fragment job %q", key, dep)
			}
			needs = append(needs, depID)
		}
		env := cj.Job.Environment.Name
		infraRetries := cj.Job.InfraRetries
		if infraRetries <= 0 {
			infraRetries = 2
		}
		effectiveNetwork := cj.Job.Network
		if effectiveNetwork == "" {
			effectiveNetwork = "bridge"
		}
		if !parent.Trusted && cj.Job.Runtime == "container" {
			effectiveNetwork = "none"
		}
		created[id] = model.Job{
			ID: id, RunID: parent.RunID, Key: key, BaseKey: cj.BaseID, RepoURL: parent.RepoURL, RepoFullName: parent.RepoFullName, Ref: parent.Ref, SHA: parent.SHA,
			Event: parent.Event, Condition: cj.Job.If, DependencyStatus: model.StatusSuccess, Pipeline: string(canonical), Trusted: parent.Trusted, ChangedFiles: append([]string{}, parent.ChangedFiles...), Needs: needs,
			RequiredLabels: labelsForJob(cj.Job), Network: effectiveNetwork, Environment: env, ApprovalRequired: cj.Job.Environment.Approval, EnvironmentBranches: append([]string{}, cj.Job.Environment.Branches...), EnvironmentConcurrency: cj.Job.Environment.Concurrency, OIDCAllowed: cj.Job.Permissions.IDToken, OIDCAudiences: cloneStrings(oidcAudiences),
			DeclaredSecrets: declaredSecrets(strictSpec, cj.Job),
			Status:          model.StatusQueued, Priority: scheduler.DownstreamDepth(g, key), MaxInfraRetries: infraRetries, CreatedAt: now,
			DynamicDepth:     childDepth,
			PlacementRegions: append([]string{}, cj.Job.Placement.Regions...),
			CompiledJobPayload: &model.CompiledJobPayload{
				SchemaVersion:   1,
				CompilerVersion: version.Version,
				PipelineDigest:  pipelineDigest,
				JobDigest:       hex.EncodeToString(digestSum[:]),
				EffectiveJob:    json.RawMessage(cjJSON),
				EffectivePolicy: json.RawMessage(policyJSON),
			},
		}
		jobContracts[id] = buildJobContracts(cj)
	}

	if s.DB != nil {
		ds, ok := s.DB.(storage.DynamicStoreTx)
		if !ok {
			return nil, fmt.Errorf("store does not support transactional dynamic job insertion")
		}
		deps := make(map[string][]string, len(created))
		for id, j := range created {
			deps[id] = append([]string(nil), j.Needs...)
		}
		// Transactional recheck: the store locks the parent FOR UPDATE and
		// counts the run's jobs inside the transaction; the closure
		// re-validates {job, runner, generation, token, expiry} and the
		// max-jobs-per-run bound against that fresh state.
		verify := func(fresh model.Job, runJobCount int) error {
			if fresh.Status != model.StatusRunning || fresh.LeaseExpiresAt == nil || !fresh.LeaseExpiresAt.After(time.Now().UTC()) {
				return fmt.Errorf("parent lease expired during generation")
			}
			if fresh.LeaseRunnerID != parent.LeaseRunnerID || fresh.LeaseGeneration != parent.LeaseGeneration {
				return fmt.Errorf("parent lease changed during generation")
			}
			if !subtleCompare(fresh.LeaseTokenHash, parent.LeaseTokenHash) {
				return fmt.Errorf("parent lease token changed during generation")
			}
			if runJobCount+len(created) > maxJobsPerRun {
				return fmt.Errorf("run would grow to %d jobs, limit is %d", runJobCount+len(created), maxJobsPerRun)
			}
			return nil
		}
		if err := ds.InsertGeneratedJobsTx(ctx, parent.ID, childDepth, created, deps, verify); err != nil {
			return nil, err
		}
		return &generatedResponse{ParentJobID: parent.ID, RunID: parent.RunID, Depth: childDepth, JobIDs: ids, Keys: keys}, nil
	}

	// Memory mode: re-verify the lease under the lock, then insert the
	// whole fragment atomically with the in-memory maps.
	s.mu.Lock()
	current, still := s.jobs[parent.ID]
	if !still {
		s.mu.Unlock()
		return nil, fmt.Errorf("parent job disappeared")
	}
	leaseNow := time.Now().UTC()
	if current.Status != model.StatusRunning || current.LeaseExpiresAt == nil || !current.LeaseExpiresAt.After(leaseNow) {
		s.mu.Unlock()
		return nil, fmt.Errorf("parent lease expired during generation")
	}
	for id, j := range created {
		s.jobs[id] = j
		if contracts, ok := jobContracts[id]; ok {
			s.contracts[id] = contracts
		}
	}
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.mu.Unlock()
	return &generatedResponse{ParentJobID: parent.ID, RunID: parent.RunID, Depth: childDepth, JobIDs: ids, Keys: keys}, nil
}

// generatedChildCapabilities derives the capability ceiling for generated
// children: the parent's stored effective policy, narrowed by the current
// policy file and the trust floor. A parent without a stored policy falls
// back to the enqueue-time defaults for its trust level.
func (s *Server) generatedChildCapabilities(parent model.Job) policy.Capabilities {
	repo := parent.RepoFullName
	if repo == "" {
		repo = repoFullNameOf(parent)
	}
	caps := policy.DefaultUntrustedCapabilities()
	if parent.Trusted {
		caps = policy.DefaultTrustedCapabilities()
	}
	if stored, ok := effectiveCapsOf(parent); ok {
		caps = stored
	}
	if s.Policy != nil {
		caps = policy.Intersect(caps, s.Policy.CapabilitiesFor(repo))
		// Grant-gated capabilities must STILL be granted by the current
		// policy file: removing the grant narrows the child ceiling even
		// when the parent was admitted under a wider policy.
		grants := s.Policy.GrantsFor(repo)
		caps.Deployments = caps.Deployments && grants.Deployments
		caps.GenerateChildGraph = caps.GenerateChildGraph && grants.GenerateChildGraph
		caps.CrossRepoTrigger = caps.CrossRepoTrigger && grants.CrossRepoTrigger
	}
	return caps.Effective(parent.Trusted)
}

// repoFullNameOf reconstructs the parent job's repository full name for
// policy lookup: the RepoURL's host+path without the .git suffix.
func repoFullNameOf(j model.Job) string {
	u, err := url.Parse(strings.TrimSpace(j.RepoURL))
	if err != nil || u.Host == "" {
		return j.RepoURL
	}
	return u.Host + strings.TrimSuffix(u.Path, ".git")
}
