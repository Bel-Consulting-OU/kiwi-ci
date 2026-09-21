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

	v1 "github.com/Bel-Consulting-OU/kiwi-ci/internal/api/v1"
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
// implicit dependency of every child). The wire type is shared with the
// runner so fragment_id is derived from the identical parsed shape on both
// sides.
type generatedFragment = v1.GeneratedFragment

// generatedResponse reports the admitted fragment. Replayed marks a response
// served from the idempotency receipt: the SAME children the original
// admission created, returned with 200 instead of 201.
type generatedResponse struct {
	ParentJobID string   `json:"parent_job_id"`
	RunID       string   `json:"run_id"`
	Depth       int      `json:"depth"`
	JobIDs      []string `json:"job_ids"`
	Keys        []string `json:"keys"`
	Replayed    bool     `json:"replayed,omitempty"`
}

// generateJobs implements POST /api/v1/jobs/{id}/generated. The caller must
// hold the parent job's active lease; every generated child is admitted
// under the parent's effective capabilities (children can only inherit or
// reduce trust), depth- and size-bounded, and inserted atomically.
func (s *Server) generateJobs(w http.ResponseWriter, r *http.Request) {
	var in generatedFragment
	if !decodeLimit(w, r, &in, maxGeneratedFragmentBytes) {
		return
	}
	runnerID := r.Header.Get("X-Kiwi-Runner-ID")
	token := r.Header.Get("X-Kiwi-Lease-Token")
	gen, _ := strconv.ParseInt(r.Header.Get("X-Kiwi-Lease-Generation"), 10, 64)
	ctx := r.Context()
	parent, authErr := s.authorizeRunnerLease(r, runnerID, token, gen)
	if authErr != nil {
		s.writeLeaseAuthError(w, r, authErr)
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
		// A failed snapshot write is a server-side durability failure, not a
		// client error.
		var nd *stateNotDurableError
		if errors.As(aerr, &nd) {
			s.serverError(w, r, http.StatusServiceUnavailable, nd, "state not durable")
			return
		}
		http.Error(w, aerr.Error(), http.StatusBadRequest)
		return
	}
	if res.Replayed {
		s.auditLocked("generate.replayed", runnerID, parent.RunID, parent.ID, fmt.Sprintf("replayed fragment with %d children", len(res.JobIDs)), map[string]string{"job": parent.Key, "depth": strconv.Itoa(res.Depth)})
		writeJSON(w, http.StatusOK, res)
		return
	}
	s.auditLocked("generate.admitted", runnerID, parent.RunID, parent.ID, fmt.Sprintf("generated %d child jobs", len(res.JobIDs)), map[string]string{"job": parent.Key, "depth": strconv.Itoa(res.Depth)})
	s.metricAdd("kiwi_dynamic_jobs_generated_total", float64(len(res.JobIDs)), nil)
	writeJSON(w, http.StatusCreated, res)
}

// verifyGeneratedParentState is the single lease/state predicate applied at
// fragment insertion time in BOTH storage modes (the DB transaction verifier
// and the memory-mode critical section): the parent must still be running
// under the same runner, lease generation and token hash, with a live lease,
// and the run must stay within the max-jobs-per-run cap. snapshot is the
// authorized parent the handler admitted against; fresh is the current
// durable/in-memory state.
func verifyGeneratedParentState(snapshot, fresh model.Job, runJobCount, childCount int) error {
	if fresh.ID != snapshot.ID {
		return fmt.Errorf("parent job changed during generation")
	}
	if fresh.Status != model.StatusRunning || fresh.LeaseExpiresAt == nil || !fresh.LeaseExpiresAt.After(time.Now().UTC()) {
		return fmt.Errorf("parent lease expired during generation")
	}
	if fresh.LeaseRunnerID != snapshot.LeaseRunnerID || fresh.LeaseGeneration != snapshot.LeaseGeneration {
		return fmt.Errorf("parent lease changed during generation")
	}
	if len(fresh.LeaseTokenHash) == 0 || !subtleCompare(fresh.LeaseTokenHash, snapshot.LeaseTokenHash) {
		return fmt.Errorf("parent lease token changed during generation")
	}
	if runJobCount+childCount > maxJobsPerRun {
		return fmt.Errorf("run would grow to %d jobs, limit is %d", runJobCount+childCount, maxJobsPerRun)
	}
	return nil
}

// replayGeneratedResponse rebuilds the original admission response from a
// stored receipt: the same child IDs and keys, in the same order.
func replayGeneratedResponse(parent model.Job, depth int, rec storage.GeneratedFragmentReceipt) *generatedResponse {
	ids := make([]string, 0, len(rec.Children))
	keys := make([]string, 0, len(rec.Children))
	for _, c := range rec.Children {
		ids = append(ids, c.ID)
		keys = append(keys, c.Key)
	}
	return &generatedResponse{ParentJobID: parent.ID, RunID: parent.RunID, Depth: depth, JobIDs: ids, Keys: keys, Replayed: true}
}

// processGeneratedFragment validates and inserts one generated fragment.
// It is the shared admission path for both storage modes. The body must carry
// the deterministic fragment_id (sha256 hex of the canonical {jobs, deps});
// the server recomputes it and rejects a missing or mismatching id with 400.
// A fragment already admitted under the same (parent, lease generation,
// fragment id) is answered idempotently with the originally created children.
func (s *Server) processGeneratedFragment(ctx context.Context, parent model.Job, in generatedFragment) (*generatedResponse, error) {
	fragmentID, err := in.Digest()
	if err != nil {
		return nil, err
	}
	if in.FragmentID == "" {
		return nil, fmt.Errorf("generated fragment is missing fragment_id")
	}
	if in.FragmentID != fragmentID {
		return nil, fmt.Errorf("generated fragment_id does not match the fragment digest")
	}
	childDepth := parent.DynamicDepth + 1
	// Replay fast path: a committed receipt returns the original children
	// without re-running admission (a replay must survive policy edits and a
	// changed compiler exactly as the original admission did).
	if rec, found, rerr := s.generatedFragmentReceipt(ctx, parent.ID, parent.LeaseGeneration, fragmentID); rerr != nil {
		return nil, rerr
	} else if found {
		return replayGeneratedResponse(parent, childDepth, rec), nil
	}
	if len(in.Jobs) == 0 {
		return nil, fmt.Errorf("generated fragment declares no jobs")
	}
	if len(in.Jobs) > maxGeneratedJobsPerFragment {
		return nil, fmt.Errorf("generated fragment declares %d jobs, limit is %d", len(in.Jobs), maxGeneratedJobsPerFragment)
	}
	// Depth: children inherit parent depth + 1 and never exceed the cap.
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
	// The parent's own capabilities must permit child graph generation.
	if !childCaps.GenerateChildGraph {
		return nil, policyDenied("parent job's capabilities do not permit generated child graphs")
	}
	// Canonical admission: the FULL admission path (structural validation,
	// capability admission, downstream/generate declaration invariants,
	// and the org policy's host/region/digest restrictions) runs with the
	// child caps — generated fragments have no second-class path.
	if err := s.admitCompiledSpec(repoIdentityOfJob(parent), synth, childCaps); err != nil {
		return nil, fmt.Errorf("generated fragment admission: %w", err)
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
	policyJSON, err := jsonMarshal(childCaps)
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
	oidcAudiences := policy.OIDCFromCapabilities(childCaps).AllowedAudiences
	for _, key := range keys {
		cj := g.Jobs[key]
		id := keyIDs[key]
		ids = append(ids, id)
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
		// Untrusted children get the server-side resource ceilings just
		// like initial enqueues, BEFORE the compiled payload is marshaled:
		// an explicit request above a ceiling rejects the whole fragment.
		cj, err = s.applyUntrustedResourceCeilings(cj, parent.Trusted)
		if err != nil {
			return nil, err
		}
		cjJSON, mErr := jsonMarshal(cj)
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
		j := model.Job{
			ID: id, RunID: parent.RunID, Key: key, BaseKey: cj.BaseID, RepoID: parent.RepoID, PolicyRepoID: parent.PolicyRepoID, CheckoutRepoURL: parent.CheckoutRepoURL,
			RepoURL: parent.RepoURL, RepoFullName: parent.RepoFullName, Ref: parent.Ref, SHA: parent.SHA,
			Event: parent.Event, Condition: cj.Job.If, DependencyStatus: model.StatusSuccess, Pipeline: string(canonical), Trusted: parent.Trusted, ChangedFiles: append([]string{}, parent.ChangedFiles...), ChangedFilesKnown: parent.ChangedFilesKnown, Needs: needs,
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
		applyCompiledJobFields(&j, cj, now)
		created[id] = j
		jobContracts[id] = buildJobContracts(cj)
	}

	// Canonical children order: the response order (sorted compiled keys),
	// stored in the receipt so a replay reconstructs it exactly.
	children := make([]storage.GeneratedFragmentChild, 0, len(keys))
	for _, key := range keys {
		children = append(children, storage.GeneratedFragmentChild{Key: key, ID: keyIDs[key]})
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
		// Transactional recheck: the store locks the parent FOR UPDATE, counts
		// the run's jobs and records the idempotency receipt in the SAME
		// transaction; the closure re-validates {job, runner, generation,
		// token, expiry} and the max-jobs-per-run bound against that fresh
		// state. A concurrently committed duplicate returns the winner's
		// receipt instead of inserting a second fragment.
		verify := func(fresh model.Job, runJobCount int) error {
			return verifyGeneratedParentState(parent, fresh, runJobCount, len(created))
		}
		rec, replayed, err := ds.InsertGeneratedFragmentTx(ctx, storage.GeneratedFragmentRequest{
			ParentJobID:     parent.ID,
			Depth:           childDepth,
			LeaseGeneration: parent.LeaseGeneration,
			FragmentID:      fragmentID,
			Jobs:            created,
			Deps:            deps,
			Contracts:       jobContracts,
			Children:        children,
		}, verify)
		if err != nil {
			return nil, err
		}
		if replayed {
			return replayGeneratedResponse(parent, childDepth, rec), nil
		}
		return &generatedResponse{ParentJobID: parent.ID, RunID: parent.RunID, Depth: childDepth, JobIDs: ids, Keys: keys}, nil
	}

	// Memory mode: the IDENTICAL lease/state predicate runs inside the same
	// critical section as the job-count check and the insertion, so a
	// concurrent fragment can neither race the cap nor slip past a lease
	// that changed while this request was being admitted.
	s.mu.Lock()
	current, still := s.jobs[parent.ID]
	if !still {
		s.mu.Unlock()
		return nil, fmt.Errorf("parent job disappeared")
	}
	runJobCount := 0
	for _, j := range s.jobs {
		if j.RunID == parent.RunID {
			runJobCount++
		}
	}
	if verr := verifyGeneratedParentState(parent, current, runJobCount, len(created)); verr != nil {
		s.mu.Unlock()
		return nil, verr
	}
	if rec, found := s.memoryGeneratedFragment(parent.ID, parent.LeaseGeneration, fragmentID); found {
		s.mu.Unlock()
		return replayGeneratedResponse(parent, childDepth, rec), nil
	}
	rb := s.captureStateRollbackLocked()
	for id, j := range created {
		s.jobs[id] = j
		if contracts, ok := jobContracts[id]; ok {
			s.contracts[id] = contracts
		}
	}
	if perr := s.persistCheckedErrLocked("generated.fragment"); perr != nil {
		// The children never became durable: restore every map this path
		// touched and fail closed with a 5xx. The idempotency receipt is
		// recorded only AFTER the snapshot write, so a retry can never
		// replay an admission the disk does not contain.
		s.rollbackStateLocked(rb)
		s.mu.Unlock()
		return nil, notDurable(perr)
	}
	// The children are durable: record the in-memory idempotency receipt so
	// a retry returns the SAME children instead of re-admitting. The
	// receipt table is process-local fs state (a restart re-admits, the
	// documented pre-receipt behavior); it is only ever populated for an
	// admission whose children are already on disk.
	s.generatedFragments[generatedFragmentKey(parent.ID, parent.LeaseGeneration, fragmentID)] = storage.GeneratedFragmentReceipt{
		ParentJobID:     parent.ID,
		LeaseGeneration: parent.LeaseGeneration,
		FragmentID:      fragmentID,
		Children:        children,
		CreatedAt:       time.Now().UTC(),
	}
	s.mu.Unlock()
	return &generatedResponse{ParentJobID: parent.ID, RunID: parent.RunID, Depth: childDepth, JobIDs: ids, Keys: keys}, nil
}

// generatedFragmentKey is the in-memory primary key of the fragment
// receipts, mirroring the generated_fragments table key.
func generatedFragmentKey(parentJobID string, generation int64, fragmentID string) string {
	return parentJobID + "\x00" + strconv.FormatInt(generation, 10) + "\x00" + fragmentID
}

// generatedFragmentReceipt resolves the idempotency receipt of a fragment:
// from the durable store in DB mode (when it implements the receipt store),
// from the in-memory map otherwise.
func (s *Server) generatedFragmentReceipt(ctx context.Context, parentJobID string, generation int64, fragmentID string) (storage.GeneratedFragmentReceipt, bool, error) {
	if s.DB != nil {
		if gs, ok := s.DB.(storage.GeneratedFragmentStore); ok {
			return gs.GetGeneratedFragment(ctx, parentJobID, generation, fragmentID)
		}
		// Stores without the receipt read still dedupe inside
		// InsertGeneratedFragmentTx; the fast path is simply skipped.
		return storage.GeneratedFragmentReceipt{}, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.memoryGeneratedFragment(parentJobID, generation, fragmentID)
	return rec, ok, nil
}

// memoryGeneratedFragment reads the in-memory receipt map. The caller holds
// s.mu.
func (s *Server) memoryGeneratedFragment(parentJobID string, generation int64, fragmentID string) (storage.GeneratedFragmentReceipt, bool) {
	rec, ok := s.generatedFragments[generatedFragmentKey(parentJobID, generation, fragmentID)]
	return rec, ok
}

// generatedChildCapabilities derives the capability ceiling for generated
// children: the parent's stored effective policy, narrowed by the current
// policy file and the trust floor. A parent without a stored policy falls
// back to the enqueue-time defaults for its trust level. The policy lookup
// uses the parent's canonical RepoID (derived for legacy payloads), so a
// policy entry for github.com/acme/api never narrows a
// gitlab.company.com/acme/api child.
func (s *Server) generatedChildCapabilities(parent model.Job) policy.Capabilities {
	repo := repoIDForJob(parent)
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

// repoIdentityOfJob resolves the repository identity a job is admitted
// under: the canonical RepoID (derived for legacy payloads), its clone URL
// and its full name (reconstructed from the URL when the stored full name
// is empty).
func repoIdentityOfJob(j model.Job) repoIdentity {
	id := repoIdentity{RepoID: repoIDForJob(j), RepoURL: j.RepoURL, RepoFullName: j.RepoFullName}
	if id.RepoFullName == "" {
		id.RepoFullName = repoFullNameOf(j)
	}
	return id
}
