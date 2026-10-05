package executor

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/artifact"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
)

type Options struct {
	Workspace string
	// WorkspaceFor resolves the per-job workspace directory. When set,
	// runJob calls it once per job (after condition/path gating), defers
	// the returned cleanup until the job is finished, and uses the
	// returned directory for caches, artifacts, steps, and the runtime
	// workspace. A nil value keeps the single Workspace directory for
	// every job (historical behavior; distributed runners pass fresh
	// per-task clones instead).
	WorkspaceFor func(jobID string) (string, func(), error)
	RunID        string
	// RunnerID and InstanceID identify the owning runner process incarnation
	// so runtime resources can be reconciled after a crash: every container,
	// service container and network is labelled with both, and a restarted
	// runner reaps only resources carrying ITS stable RunnerID but a previous
	// InstanceID. Empty values keep the legacy unlabelled behavior.
	RunnerID   string
	InstanceID string
	// OnCgroupCreated, when set, receives the job-scoped cgroup path as soon
	// as it exists so the caller (the runner's runtime ledger) can reclaim it
	// after a hard crash.
	OnCgroupCreated func(parent string) error
	// OnCleanupDebt, when set, is called whenever ANY runtime cleanup
	// primitive cannot prove its resource removed: the main backend, a
	// service container, the service network, or the job-scoped cgroup. The
	// caller must treat every report uniformly: RETAIN the workspace, quota
	// and crash-recovery ledger entry AND stop accepting new leases until
	// reconciliation clears the debt (a bounded in-process pass may clear it;
	// otherwise the runner exits so startup reconciliation owns recovery).
	OnCleanupDebt func(CleanupDebt)
	MaxParallel   int
	OnlyJob       string
	// OnlyStep, when set, executes just the named step (by step ID or by
	// resolved name, including canary./verify./rollback. prefixes) of the
	// selected job. Used by `kiwi replay RUN JOB STEP`. Steps that do not
	// match are skipped without side effects; the matched step runs with
	// dependency outputs interpolated as in the full job.
	OnlyStep         string
	Event            string
	Branch           string
	ChangedFiles     []string
	SecretProvider   secrets.Provider
	Logs             logging.Sink
	Cache            *cache.Store
	Artifacts        *artifact.Store
	ArtifactCapture  *ArtifactCapture
	ArtifactReporter func(jobID, name, path string) error
	// LocalDownloads enables restoring declared dependency downloads from
	// this run's locally saved artifacts (kiwi run parity with the
	// distributed runner's restoreDownloads). Off for the distributed
	// runner (it restores through the control plane) and for replay (the
	// workspace snapshot already contains the restored files).
	LocalDownloads   bool
	DependencyStatus model.Status
	NeedsOutputs     map[string]map[string]string
	CacheNamespace   string
	// InheritEnv opts into inheriting the full host environment instead of
	// the minimal clean env. Local trusted runs only; distributed runners
	// must never set this.
	InheritEnv bool
	// PassEnv is an explicit allowlist of extra host env var names carried
	// into job environments. Together with the clean env, these are the only
	// host variables that reach remote jobs.
	PassEnv []string
	// RequireImmutableImages rejects container images and Tart VM references
	// that are not pinned by an @sha256: digest. The server enables this for
	// untrusted jobs.
	RequireImmutableImages bool
	// Untrusted marks the job as untrusted. Untrusted container jobs always
	// receive a workspace disk budget: the declared resources.disk when set,
	// otherwise UntrustedWorkspaceMaxBytes (or the documented
	// DefaultUntrustedWorkspaceMaxBytes). Trusted jobs without a declaration
	// keep the historical unbounded behavior. Untrusted jobs are also held to
	// the smaller pipeline.MaxUntrustedServicesPerJob service-count ceiling.
	Untrusted bool
	// UntrustedWorkspaceMaxBytes overrides DefaultUntrustedWorkspaceMaxBytes
	// for untrusted jobs whose pipeline does not declare resources.disk. Zero
	// selects the package default; this is the configuration seam for runners
	// that need a different budget.
	UntrustedWorkspaceMaxBytes int64
	// RequireUntrustedDiskQuota fails an untrusted container job closed when
	// no OS-level hard workspace bound (XFS project quota) can be established
	// for its workspace. The step-boundary resources.disk measurement is not a
	// security boundary, so production runners set this and let the operator
	// escape hatch (KIWI_ALLOW_UNQUOTAED_UNTRUSTED_DISK) cover trusted-only
	// self-hosted setups.
	RequireUntrustedDiskQuota bool
	// TartAgentPort overrides the guest kiwi-agent bootstrap port for Tart
	// jobs. Zero keeps the production default. Tests set an ephemeral port so
	// they never collide with an external process.
	TartAgentPort int
	// WorkspaceQuota carries the outcome of a hard workspace quota attempt
	// the caller already performed BEFORE the workspace was populated (the
	// distributed runner installs the bound before checkout, so an untrusted
	// repository can no longer fill the host disk during checkout). A
	// non-nil Hard outcome satisfies RequireUntrustedDiskQuota without a
	// second probe; a non-nil non-Hard outcome fails the gate closed with
	// the caller's probe reason. Nil means no caller attempt: the container
	// backend probes at StartJob itself (defense in depth / direct users).
	WorkspaceQuota *DiskQuotaStatus
	// CaptureSnapshot archives the job workspace after its steps ran (for
	// any status other than skipped/blocked) under the host temp dir.
	// Snapshot failures are logged as warnings and never change job status.
	CaptureSnapshot bool
	// WorkspaceMaxBytes rejects a job before execution when the filesystem
	// containing the workspace reports fewer free bytes than the quota, so
	// an oversized workspace never half-runs. Zero disables the check.
	WorkspaceMaxBytes int64

	// WorkspaceAvailabilityChecked records that the caller already ran the
	// free-space availability preflight on the EMPTY workspace, before
	// checkout (the runner does this immediately after installing the hard
	// quota). It suppresses the executor's own full-capacity re-check: a
	// project quota caps the project but reserves nothing, so the check
	// must happen before any checkout bytes exist, and re-running it after
	// checkout would silently require bound + checkout bytes of free space.
	WorkspaceAvailabilityChecked bool
	// LogMaxBytes caps the per-job log stream forwarded to Logs. Once the
	// quota is exhausted, further lines are dropped after a single terminal
	// "log quota exceeded" marker. Zero means unlimited.
	LogMaxBytes int64
	// LifecycleContext is the runner/process lifecycle context, distinct
	// from the job context. Post-deadline work that intentionally survives
	// the JOB context ending (cancellation cleanup steps, diagnostic
	// artifact capture) is detached from the job deadline but re-tied to
	// this context, so a runner shutdown aborts it immediately instead of
	// waiting out its own timeout past the drain grace. Nil falls back to
	// the context RunCompiledJob received (the local-CLI process context);
	// the distributed runner passes its runCtx explicitly.
	LifecycleContext context.Context
	// StepReporter, when set, is called once per executed step with the
	// step's wall time (including retries and backoff). Steps that were
	// skipped or never executed are not reported.
	StepReporter func(jobID, stepID string, d time.Duration)
	// GenerateUpload, when set, is called for a successful job that declares
	// generate.path, with the fragment's contents read through the job's
	// live backend session (ReadJobFile) while it is still running. Unless
	// the job's generate.optional is true, an upload error (server
	// rejection, non-2xx response, network failure) FAILS the job with a
	// "generated graph rejected" error: a generator that declares a graph
	// must not silently succeed without it. With generate.optional the error
	// stays a warning and the job succeeds. A read error always fails the
	// job. The distributed runner wires its fragment POST here; local runs
	// leave it nil and only validate the read.
	GenerateUpload func(jobID, path string, data []byte) error
}

// ArtifactCapture configures distributed artifact packaging. It replaces the
// persistent local artifact store's defaults with a temporary, budgeted
// publication path: each archive is bounded by min(capture.MaxBytes, the
// declaration's max_size), charged to the runner-wide staging budget through
// Reserve BEFORE the first byte is written, and removed (archive + sidecar
// manifest) as soon as delivery finishes, on success and failure alike. The
// archive therefore lives only through capture -> attest -> upload ->
// cleanup and never accumulates outside the job workspace quota. Nil keeps
// the local-CLI persistent-store behavior.
type ArtifactCapture struct {
	// Context bounds capture and delivery while the job context is alive
	// (the distributed runner passes the job context, so a job that exceeds
	// its declared lifetime stops publishing).
	Context context.Context
	// MaxBytes is the global per-artifact payload ceiling (the server's blob
	// maximum). <=0 means no global cap.
	MaxBytes int64
	// Reserve charges n bytes of aggregate staging capacity before an
	// archive is created and returns the finalize callback. The executor
	// invokes finalize(path) exactly once after delivery (or finalize("")
	// when no archive was produced); finalize MUST delete the archive (and
	// its manifest) and release the charge only once the bytes are
	// physically gone, converting a removal failure into retryable cleanup
	// debt instead of silently freeing accounting. Nil fails capture closed
	// (an unaccounted archive must never be created).
	Reserve func(ctx context.Context, n int64) (func(path string) error, error)
}

type Executor struct {
	Opt    Options
	Masker *secrets.Masker
	// sessions tracks the live per-job backend sessions so generate reads
	// (and other job-scoped file reads) resolve through the execution
	// backend instead of host-side path opens. It must stay a pointer: runJob
	// makes shallow copies of Executor for its log-quota scoping.
	sessions *sessionRegistry
	// artifacts records locally saved artifacts of THIS run (run/job/name →
	// archive path) so downstream jobs can restore their declared downloads
	// without a server round trip. Pointer for the same shallow-copy reason.
	artifacts *artifactRegistry
}

// artifactRegistry maps a locally saved artifact of THIS run to the archive
// path published by its job. Entries are keyed by the producer's compiled id
// plus the artifact name; every producer's base id is recorded so a consumer
// that declares `from: <base>` for a matrix producer resolves exactly like
// the control plane's dependency endpoint (BaseKey == producer or Key ==
// producer, then exactly one matching artifact record).
type artifactRegistry struct {
	mu    sync.Mutex
	paths map[string]string
	bases map[string]string
}

func newArtifactRegistry() *artifactRegistry {
	return &artifactRegistry{paths: map[string]string{}, bases: map[string]string{}}
}

func (r *artifactRegistry) record(jobID, baseID, name, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paths[jobID+"\x00"+name] = path
	if baseID != "" {
		r.bases[jobID] = baseID
	}
}

// lookup resolves a declared (producer, artifact name) pair against this
// run's recorded artifacts. The producer may be the compiled id or the base
// id of a matrix producer; ambiguity (several variants publishing the same
// name) is an error, matching the server's exactly-one contract.
func (r *artifactRegistry) lookup(producer, name string) (string, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.paths[producer+"\x00"+name]; ok {
		return p, true, nil
	}
	matches := make([]string, 0, 2)
	for key, p := range r.paths {
		id, n, ok := strings.Cut(key, "\x00")
		if !ok || n != name {
			continue
		}
		if r.bases[id] == producer {
			matches = append(matches, p)
		}
	}
	switch len(matches) {
	case 0:
		return "", false, nil
	case 1:
		return matches[0], true, nil
	default:
		return "", false, fmt.Errorf("dependency artifact %q from %q is ambiguous: %d matrix variants published it", name, producer, len(matches))
	}
}

// sessionRegistry maps job IDs to their live backend sessions. A session is
// registered once its backend is started and unregistered after the backend
// is closed, so reads outside that window fail closed.
type sessionRegistry struct {
	mu sync.Mutex
	m  map[string]Backend
}

func (r *sessionRegistry) put(jobID string, b Backend) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.m == nil {
		r.m = map[string]Backend{}
	}
	r.m[jobID] = b
	r.mu.Unlock()
}

func (r *sessionRegistry) get(jobID string) (Backend, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.m[jobID]
	return b, ok
}

func (r *sessionRegistry) delete(jobID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.m, jobID)
	r.mu.Unlock()
}

// ReadJobFile reads a file from a running job's live backend session. The
// job must currently be executing (its backend session registered): the
// backend performs the read inside the execution boundary — native reads
// are no-follow host reads, container reads run `docker exec cat`, tart
// reads go over ssh — so a symlink planted in the workspace can only
// resolve inside the sandbox, never to host content. maxBytes is a hard
// cap.
func (e *Executor) ReadJobFile(ctx context.Context, jobID, path string, maxBytes int64) ([]byte, error) {
	b, ok := e.sessions.get(jobID)
	if !ok {
		return nil, fmt.Errorf("no live backend session for job %q", jobID)
	}
	return b.ReadFile(ctx, path, maxBytes)
}

func (e *Executor) prepare() {
	if e.Opt.MaxParallel <= 0 {
		e.Opt.MaxParallel = max(1, runtime.NumCPU()/2)
	}
	if e.Opt.RunID == "" {
		e.Opt.RunID = fmt.Sprintf("local-%d", time.Now().Unix())
	}
	if e.Opt.Cache == nil {
		e.Opt.Cache = cache.Default()
	}
	if e.Opt.Artifacts == nil {
		e.Opt.Artifacts = artifact.Default()
	}
	if e.Masker == nil {
		e.Masker = &secrets.Masker{}
	}
	if e.sessions == nil {
		e.sessions = &sessionRegistry{}
	}
	if e.artifacts == nil {
		e.artifacts = newArtifactRegistry()
	}
}

// RunCompiledJob executes one already-compiled job without evaluating its DAG
// dependencies. Distributed runners use this after the control plane has
// atomically decided that dependencies and approvals are satisfied.
func (e *Executor) RunCompiledJob(ctx context.Context, spec *pipeline.Spec, job pipeline.CompiledJob) model.JobResult {
	e.prepare()
	status := e.Opt.DependencyStatus
	if status == "" {
		status = model.StatusSuccess
	}
	return e.runJob(ctx, spec, job, status, e.Opt.NeedsOutputs)
}

func (e *Executor) Run(ctx context.Context, g *pipeline.Graph) (map[string]model.JobResult, error) {
	e.prepare()
	statuses := map[string]model.Status{}
	results := map[string]model.JobResult{}
	pending := map[string]bool{}
	for id := range g.Jobs {
		pending[id] = true
	}
	type completion struct {
		id     string
		result model.JobResult
	}
	sem := make(chan struct{}, e.Opt.MaxParallel)
	done := make(chan completion, len(g.Jobs))
	running := 0
	for len(pending) > 0 || running > 0 {
		scheduled := false
		ids := make([]string, 0, len(pending))
		for id := range pending {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			cj := g.Jobs[id]
			if e.Opt.OnlyJob != "" && cj.BaseID != e.Opt.OnlyJob && cj.ID != e.Opt.OnlyJob {
				statuses[id] = model.StatusSkipped
				delete(pending, id)
				continue
			}
			ready, depStatus := depsOutcome(cj.Needs, statuses)
			if !ready {
				continue
			}
			if depStatus != model.StatusSuccess && !dependencyConditionAllows(cj.Job.If, depStatus) {
				statuses[id] = model.StatusBlocked
				results[id] = model.JobResult{JobID: id, Status: model.StatusBlocked, Error: "dependency failed"}
				delete(pending, id)
				continue
			}
			delete(pending, id)
			running++
			scheduled = true
			needsOutputs := collectNeedsOutputs(cj.Needs, g.Jobs, results)
			sem <- struct{}{}
			go func(cj pipeline.CompiledJob, depStatus model.Status, needsOutputs map[string]map[string]string) {
				res := e.runJob(ctx, g.Spec, cj, depStatus, needsOutputs)
				<-sem
				done <- completion{id: cj.ID, result: res}
			}(cj, depStatus, needsOutputs)
		}
		if running > 0 {
			c := <-done
			results[c.id] = c.result
			statuses[c.id] = c.result.Status
			running--
			continue
		}
		if !scheduled && len(pending) > 0 {
			return results, fmt.Errorf("scheduler deadlock")
		}
	}

	var errs []error
	for _, r := range results {
		if r.Status == model.StatusFailure {
			errs = append(errs, fmt.Errorf("%s: %s", r.JobID, r.Error))
		}
	}
	return results, errors.Join(errs...)
}

func (e *Executor) runJob(ctx context.Context, s *pipeline.Spec, cj pipeline.CompiledJob, dependencyStatus model.Status, needsOutputs map[string]map[string]string) model.JobResult {
	if e.Opt.LogMaxBytes > 0 {
		// The log quota is scoped per job: wrap the shared sink in a
		// counting sink on a shallow copy so concurrent jobs keep their own
		// counters and the shared Options stay untouched.
		scoped := *e
		scoped.Opt.Logs = limitedSink(e.Opt.Logs, e.Opt.LogMaxBytes)
		e = &scoped
	}
	start := time.Now()
	res := model.JobResult{JobID: cj.ID, Status: model.StatusRunning, StartedAt: start}
	cj.Job.If = pipeline.InterpolateOutputs(cj.Job.If, needsOutputs, nil)
	cj.Job.Env = pipeline.InterpolateOutputMap(cj.Job.Env, needsOutputs, nil)
	cj.Job.Image = pipeline.InterpolateOutputs(cj.Job.Image, needsOutputs, nil)
	cj.Job.VM = pipeline.InterpolateOutputs(cj.Job.VM, needsOutputs, nil)
	cond, err := pipeline.Eval(cj.Job.If, pipeline.EvalContext{Status: dependencyStatus, Env: cj.Job.Env, Event: e.Opt.Event, Branch: e.Opt.Branch})
	if err != nil {
		res.Status = model.StatusFailure
		res.Error = err.Error()
		return finish(res)
	}
	if !cond {
		res.Status = model.StatusSkipped
		return finish(res)
	}
	if (len(cj.Job.Paths) > 0 || len(cj.Job.PathsIgnore) > 0) && !pipeline.PathsMatch(e.Opt.ChangedFiles, cj.Job.Paths, cj.Job.PathsIgnore) {
		e.log(cj.ID, "scheduler", "skipped: changed paths do not match job filters")
		res.Status = model.StatusSkipped
		return finish(res)
	}
	// The context received here is the RUNNER/PROCESS context (for the
	// distributed runner it already carries the declared job deadline; for
	// local execution it is the process context). Keep it: post-deadline
	// work that must survive the JOB context (cleanup steps, diagnostic
	// artifact capture) detaches from the job deadline below. When the
	// caller supplied a separate lifecycle context (the distributed runner
	// passes its runCtx), that work is re-tied to it so a runner shutdown
	// aborts it; local callers that did not supply one keep the historical
	// behavior (a canceled process context does not veto cleanup steps).
	jobParent := ctx
	lifecycle := e.Opt.LifecycleContext
	// Shared resolution with the enqueue-time stamping
	// (pipeline.EffectiveJobTimeout): a job-level timeout, else the pipeline
	// defaults.timeout. The distributed runner has already started the same
	// deadline at the beginning of execute; this child context can only
	// shorten it.
	jobTimeout := pipeline.EffectiveJobTimeout(cj, s)
	if jobTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, jobTimeout)
		defer cancel()
	}
	workspace := e.Opt.Workspace
	if e.Opt.WorkspaceFor != nil {
		dir, cleanup, werr := e.Opt.WorkspaceFor(cj.ID)
		if werr != nil {
			res.Status = model.StatusFailure
			res.Error = werr.Error()
			return finish(res)
		}
		workspace = dir
		defer cleanup()
	}
	if e.Opt.WorkspaceMaxBytes > 0 && !e.Opt.WorkspaceAvailabilityChecked {
		if err := WorkspaceDiskAvailable(workspace, e.Opt.WorkspaceMaxBytes); err != nil {
			infra := &RunError{Kind: ErrorInfra, Err: fmt.Errorf("workspace quota: %v", err)}
			e.log(cj.ID, "workspace", infra.Error())
			res.Status = model.StatusFailure
			res.Error = infra.Error()
			return finish(res)
		}
	}
	baseEnv := cleanExecutionEnv()
	if e.Opt.InheritEnv {
		// Local trusted opt-in only; distributed runners must never set it.
		baseEnv = osEnvironMap()
	}
	for _, name := range e.Opt.PassEnv {
		if v, ok := os.LookupEnv(name); ok {
			baseEnv[name] = v
		}
	}
	jobEnv := mergeEnvMap(baseEnv, s.Env, cj.Job.Env)
	secretCache := map[string]string{}
	jobSecrets, secErr := e.resolveSecrets(ctx, s.Secrets, secretCache)
	if secErr != nil {
		res.Status = model.StatusFailure
		res.Error = secErr.Error()
		return finish(res)
	}
	for k, v := range jobSecrets {
		jobEnv[k] = v
	}
	jobEnv["KIWI"] = "true"
	jobEnv["KIWI_RUN_ID"] = e.Opt.RunID
	jobEnv["KIWI_JOB_ID"] = cj.ID
	// Cache-definition ceiling (defense in depth): an untrusted job can
	// reach the executor through paths that skipped enqueue admission
	// (generated fragments), and every entry is an independent archive/key,
	// so the trust-dependent bound is enforced here before any restore.
	if err := pipeline.ValidateCacheCount(cj.ID, cj.Job.Cache, e.Opt.Untrusted); err != nil {
		res.Status = model.StatusFailure
		res.Error = err.Error()
		return finish(res)
	}
	for _, c := range cj.Job.Cache {
		bases := append([]string{c.Key}, c.RestoreKeys...)
		restored := false
		for i, base := range bases {
			key, er := e.Opt.Cache.KeyContext(ctx, e.cacheBase(base)+"|"+runtime.GOOS+"|"+runtime.GOARCH+"|"+cj.Job.Runtime, workspace, c.HashFiles)
			if er != nil {
				e.log(cj.ID, "cache", "key warning: "+er.Error())
				break
			}
			hit, er := e.Opt.Cache.RestoreContext(ctx, key, workspace, c.Paths)
			if er != nil {
				e.log(cj.ID, "cache", "restore warning: "+er.Error())
				break
			}
			if hit {
				label := "primary"
				if i > 0 {
					label = "fallback"
				}
				e.log(cj.ID, "cache", fmt.Sprintf("restored %s via %s (%s)", cacheName(c), label, key[:12]))
				restored = true
				break
			}
		}
		if !restored {
			e.log(cj.ID, "cache", "miss "+cacheName(c))
		}
	}
	// Local downloads parity: declared dependency artifacts are restored
	// from this run's local artifact store before any step runs, exactly as
	// the distributed runner restores them through the control plane. A
	// declared artifact its producer did not publish is a hard failure (the
	// server answers the same download with 404).
	if cj.Job.Generate != (pipeline.GenerateSpec{}) && e.Opt.ArtifactCapture == nil {
		// Local runs execute the generator step (its output fragment is a
		// runtime artifact); expanding the fragment into child jobs is a
		// control-plane feature. Say so instead of silently running a
		// partial graph.
		e.log(cj.ID, "generate", "child job expansion is a control-plane feature; this local run executes the generator step only")
	}
	if e.Opt.LocalDownloads && len(cj.Job.Downloads) > 0 {
		if err := e.restoreLocalDownloads(cj.Job.Downloads, workspace); err != nil {
			res.Status = model.StatusFailure
			res.Error = err.Error()
			return finish(res)
		}
	}
	// Sandbox requirements must never be silently unenforced: native and tart
	// cannot pin the workload to a non-root uid, so a non_root requirement is
	// refused there before anything starts.
	if err := unsupportedSandboxRequirement(cj.Job.Runtime, cj.Job.Sandbox); err != nil {
		res.Status = model.StatusFailure
		res.Error = err.Error()
		return finish(res)
	}
	networkPolicy := cj.Job.Sandbox.Network
	if networkPolicy == pipeline.NetworkPolicyDefault && cj.Job.Network == "none" {
		networkPolicy = pipeline.NetworkPolicyNone
	}
	network := cj.Job.Network
	var cleanupServices func() error
	// sandbox.rootless is a promise about the daemon, not the container:
	// verify it before any service container or job container is started on
	// that daemon, so services never run on a rootful daemon for a job that
	// demanded rootless isolation.
	if cj.Job.Runtime == "container" && cj.Job.Sandbox.Rootless {
		docker, derr := exec.LookPath("docker")
		if derr != nil {
			res.Status = model.StatusFailure
			res.Error = (&RunError{Kind: ErrorInfra, Err: fmt.Errorf("docker not found: %w", derr)}).Error()
			return finish(res)
		}
		if rerr := requireRootlessDaemon(ctx, docker); rerr != nil {
			res.Status = model.StatusFailure
			res.Error = rerr.Error()
			return finish(res)
		}
	}
	// The trust-aware service-count ceiling is enforced before any service
	// container starts: untrusted jobs may declare at most
	// pipeline.MaxUntrustedServicesPerJob services, trusted jobs the
	// historical 32. A pipeline that slipped past spec admission can never
	// fan out more sidecars than the trust domain allows.
	if err := pipeline.ValidateServiceCount(cj.ID, cj.Job.Services, e.Opt.Untrusted); err != nil {
		res.Status = model.StatusFailure
		res.Error = err.Error()
		return finish(res)
	}
	// The job-scoped parent cgroup (when the host supports one) is shared by
	// the service containers started here and by the main container started
	// below.
	cgroupParent := ""
	if RuntimeRunsServices(cj.Job.Runtime) && len(cj.Job.Services) > 0 {
		// One job-scoped parent cgroup holds the main container AND every
		// service container, with the declared envelope applied to the
		// PARENT (see jobcgroup.go): the scheduler reserved the envelope
		// once, so the two groups must not be able to add up to twice it.
		// When the host genuinely cannot provide the parent cgroup, the
		// fallback keeps per-container caps plus the fair-split aggregate
		// service budget, and the aggregate the scheduler must additionally
		// reserve is logged (control-plane follow-up, see
		// ServiceEnvelopeRequest).
		cgStatus, cgCleanup := jobCgroupSetup(ctx, jobCgroupRequest{
			JobID:  cj.ID,
			CPU:    cj.Job.Resources.CPU,
			Memory: int64(cj.Job.Resources.Memory),
			PIDs:   cj.Job.Resources.PIDs,
		})
		if cgStatus.Enabled && cgCleanup != nil {
			cgroupParent = cgStatus.Parent
			if e.Opt.OnCgroupCreated != nil {
				if hookErr := e.Opt.OnCgroupCreated(cgStatus.Parent); hookErr != nil {
					// Ownership could not be durably recorded: remove the
					// just-created cgroup before anything can run in it and
					// fail the job (never keep an unowned external cgroup).
					if cerr := cgCleanup(); cerr != nil {
						e.log(cj.ID, "service", "job cgroup rollback after ownership failure: "+cerr.Error())
					}
					res.Status = model.StatusFailure
					res.Error = fmt.Sprintf("record job cgroup ownership: %v", hookErr)
					return finish(res)
				}
			}
			// Registered before the services/backend cleanup defers below,
			// so it runs AFTER the containers are gone (LIFO).
			defer func() {
				if cerr := cgCleanup(); cerr != nil {
					e.log(cj.ID, "service", "job cgroup cleanup warning: "+cerr.Error())
					e.reportCleanupDebt(CleanupCgroup, cgroupParent, cerr)
				}
			}()
			e.log(cj.ID, "service", "job resource cgroup: "+cgStatus.Detail)
		} else {
			e.log(cj.ID, "service", "job resource cgroup unavailable ("+cgStatus.Detail+"); per-container caps apply, and the aggregate service request ("+serviceEnvelopeSummary(cj.Job.Resources, cj.Job.Services)+") must be reserved by the scheduler to bound aggregate host usage")
		}
		isolated := networkPolicy == pipeline.NetworkPolicyNone || networkPolicy == pipeline.NetworkPolicyServicesOnly
		var er error
		network, cleanupServices, er = startContainerServicesOwned(ctx, e.Opt.RunID, cj.ID, runtimeOwner{RunnerID: e.Opt.RunnerID, InstanceID: e.Opt.InstanceID}, cj.Job.Services, cj.Job.Resources, isolated, e.Opt.RequireImmutableImages, cgroupParent, func(line string) { e.log(cj.ID, "service", line) })
		if er != nil {
			res.Status = model.StatusFailure
			res.Error = er.Error()
			return finish(res)
		}
		defer func() {
			if cerr := cleanupServices(); cerr != nil {
				// A service container or the service network could not be
				// proven removed: the job cgroup keeps hosting it, so the
				// runner must retain the workspace/quota/ledger and stop new
				// leases until reconciliation clears the debt.
				e.reportCleanupDebt(CleanupService, cj.ID, cerr)
			}
		}()
	} else if networkPolicy == pipeline.NetworkPolicyNone || networkPolicy == pipeline.NetworkPolicyServicesOnly {
		// No services to reach: fully disable networking. The container
		// backend honors network "none"; the tart backend fails closed.
		network = "none"
	}
	backend, err := BackendForNetwork(cj.Job.Runtime, cj.Job.Image, cj.Job.VM, network)
	if err != nil {
		res.Status = model.StatusFailure
		res.Error = err.Error()
		return finish(res)
	}
	switch b := backend.(type) {
	case *ContainerBackend:
		b.RequireImmutableImages = e.Opt.RequireImmutableImages
		b.Rootless = cj.Job.Sandbox.Rootless
		b.ReadOnlyRootFS = cj.Job.Sandbox.ReadOnlyRootFS
		b.NonRoot = cj.Job.Sandbox.NonRoot
		b.RunID = e.Opt.RunID
		b.JobID = cj.ID
		b.RunnerID = e.Opt.RunnerID
		b.InstanceID = e.Opt.InstanceID
		b.Resources = cj.Job.Resources
		b.Untrusted = e.Opt.Untrusted
		b.UntrustedDiskMaxBytes = e.Opt.UntrustedWorkspaceMaxBytes
		b.RequireDiskQuota = e.Opt.RequireUntrustedDiskQuota
		b.WorkspaceQuota = e.Opt.WorkspaceQuota
		b.CgroupParent = cgroupParent
	case *TartBackend:
		b.RunID = e.Opt.RunID
		b.JobID = cj.ID
		b.RunnerID = e.Opt.RunnerID
		b.InstanceID = e.Opt.InstanceID
		b.RequireImmutableImages = e.Opt.RequireImmutableImages
		if e.Opt.TartAgentPort > 0 {
			b.AgentPort = e.Opt.TartAgentPort
		}
		b.Resources = cj.Job.Resources
	case *NativeBackend:
		// The native runtime has no container boundary to apply resource
		// requests to: they are logged as advisory and never change job
		// status.
		for _, line := range nativeResourceAdvisory(cj.Job.Resources) {
			e.log(cj.ID, "resources", line)
		}
	}
	var closeJob func() error
	if lifecycle, ok := backend.(JobLifecycle); ok {
		if err := lifecycle.StartJob(ctx, workspace, func(line string) { e.log(cj.ID, "runtime", line) }); err != nil {
			res.Status = model.StatusFailure
			res.Error = err.Error()
			return finish(res)
		}
		closeJob = lifecycle.CloseJob
	}
	// Register the live backend session so job-scoped reads (generate.path)
	// resolve through the execution boundary. The session stays registered
	// until the backend is closed.
	e.sessions.put(cj.ID, backend)
	defer func() {
		if closeJob != nil {
			if err := closeJob(); err != nil {
				e.log(cj.ID, "runtime", "cleanup warning: "+err.Error())
				e.reportCleanupDebt(CleanupMainRuntime, cj.ID, err)
			}
		}
		e.sessions.delete(cj.ID)
	}()
	stepOutputs := map[string]map[string]string{}
	// currentStatus drives step condition evaluation. A hard step failure
	// does NOT abort the job: later steps whose conditions explicitly allow
	// the new status (always(), failure(), cancelled(), ...) still run.
	currentStatus := model.StatusSuccess
	var cleanupCtx context.Context
	matchedStep := false
	for i, st := range effectiveSteps(cj) {
		st.Name = pipeline.InterpolateOutputs(st.Name, needsOutputs, stepOutputs)
		st.Run = pipeline.InterpolateOutputs(st.Run, needsOutputs, stepOutputs)
		st.If = pipeline.InterpolateOutputs(st.If, needsOutputs, stepOutputs)
		st.WorkingDirectory = pipeline.InterpolateOutputs(st.WorkingDirectory, needsOutputs, stepOutputs)
		st.Env = pipeline.InterpolateOutputMap(st.Env, needsOutputs, stepOutputs)
		name := st.Name
		if name == "" {
			name = fmt.Sprintf("step-%d", i+1)
		}
		if e.Opt.OnlyStep != "" && st.ID != e.Opt.OnlyStep && name != e.Opt.OnlyStep {
			e.log(cj.ID, "replay", "skipped "+name+" (replaying only "+e.Opt.OnlyStep+")")
			continue
		}
		matchedStep = true
		ok, er := pipeline.Eval(defaultCondition(st.If), pipeline.EvalContext{Status: currentStatus, Env: cj.Job.Env, Event: e.Opt.Event, Branch: e.Opt.Branch})
		if er != nil {
			e.log(cj.ID, name, "condition error: "+er.Error())
			if currentStatus == model.StatusSuccess {
				currentStatus = model.StatusFailure
			}
			if res.Error == "" {
				res.Error = er.Error()
			}
			continue
		}
		if !ok {
			e.log(cj.ID, name, "skipped")
			continue
		}
		// Cancelled jobs may only run steps whose condition explicitly
		// admits the cancelled state, and those steps run under a bounded
		// cleanup context; every other step runs under the job's
		// execution context.
		stepCtx := ctx
		if currentStatus == model.StatusCancelled {
			stepCtx = cleanupCtx
		}
		shell := st.Shell
		if shell == "" {
			shell = cj.Job.Shell
		}
		if shell == "" {
			shell = s.Defaults.Shell
		}
		if shell == "" {
			shell = defaultShell(cj.Job.Runtime)
		}
		dir, dirErr := secureWorkingDir(workspace, st.WorkingDirectory)
		if dirErr != nil {
			e.log(cj.ID, name, "working directory: "+dirErr.Error())
			if currentStatus == model.StatusSuccess {
				currentStatus = model.StatusFailure
			}
			if res.Error == "" {
				res.Error = dirErr.Error()
			}
			continue
		}
		// Job/default timeout is a total job deadline. A step timeout, when set,
		// is an additional tighter deadline for this individual command.
		timeout := st.Timeout.Duration
		retry := effectiveStepRetry(st, cj.Job, s.Defaults)
		attempts := retry.Max + 1
		if attempts < 1 {
			attempts = 1
		}
		backoff := retry.Backoff.Duration
		if backoff <= 0 {
			backoff = time.Second
		}
		seed := retrySeed(e.Opt.RunID, cj.ID)
		stepEnvMap := mergeEnvMap(jobEnv, st.Env)
		// Step secret values live only in this step's env map; a fresh cache
		// per step means no step secret is retained in any map that outlives
		// the step.
		stepSecrets, secErr := e.resolveSecrets(stepCtx, st.Secrets, map[string]string{})
		if secErr != nil {
			e.log(cj.ID, name, "secrets: "+secErr.Error())
			if currentStatus == model.StatusSuccess {
				currentStatus = model.StatusFailure
			}
			if res.Error == "" {
				res.Error = secErr.Error()
			}
			continue
		}
		for k, v := range stepSecrets {
			stepEnvMap[k] = v
		}
		outputFile := filepath.Join(dir, fmt.Sprintf(".kiwi-output-%d", i+1))
		if _, isNative := backend.(*NativeBackend); isNative {
			// Only the native backend may touch the workspace on the host;
			// container/Tart output files are cleaned up inside the sandbox
			// or together with the workspace temp dir.
			_ = os.Remove(outputFile)
		}
		stepEnvMap["KIWI_OUTPUT"] = filepath.Base(outputFile)
		stepEnv := envSlice(stepEnvMap)
		stepStart := time.Now()
		var runErr error
		for attempt := 1; attempt <= attempts; attempt++ {
			if _, isNative := backend.(*NativeBackend); isNative {
				_ = os.Remove(outputFile)
			}
			res.Attempts++
			e.log(cj.ID, name, fmt.Sprintf("running on %s (attempt %d/%d)", backend.Name(), attempt, attempts))
			runErr = backend.Run(stepCtx, Command{Shell: shell, Script: st.Run, Dir: dir, Env: stepEnv, TimeoutSeconds: int64(timeout.Seconds())}, func(line string) { e.log(cj.ID, name, line) })
			if runErr == nil {
				break
			}
			if !retryAllows(retry, runErr) {
				break
			}
			if attempt < attempts {
				e.log(cj.ID, name, fmt.Sprintf("retrying after error: %v", runErr))
				select {
				case <-stepCtx.Done():
					runErr = stepCtx.Err()
					attempt = attempts
				case <-time.After(backoffFor(attempt, backoff, maxRetryBackoff, seed)):
				}
			}
		}
		if st.ID != "" {
			var (
				data   []byte
				outErr error
			)
			if _, isNative := backend.(*NativeBackend); isNative {
				// Native reads go through the workspace root descriptor so a
				// symlinked intermediate directory cannot redirect the read
				// outside the workspace; container/Tart resolve the path
				// inside their own sandbox.
				data, outErr = readFileWithinRoot(workspace, outputFile, 1<<20)
			} else {
				data, outErr = backend.ReadFile(stepCtx, outputFile, 1<<20)
			}
			switch {
			case errors.Is(outErr, os.ErrNotExist):
				// Step wrote no outputs; treat as empty.
				stepOutputs[st.ID] = map[string]string{}
			case outErr != nil:
				runErr = &RunError{Kind: ErrorFailure, Err: fmt.Errorf("step outputs: %w", outErr)}
			default:
				vals, parseErr := readOutputFile(data)
				if parseErr != nil {
					runErr = &RunError{Kind: ErrorFailure, Err: fmt.Errorf("step outputs: %w", parseErr)}
				} else {
					stepOutputs[st.ID] = vals
				}
			}
		}
		if _, isNative := backend.(*NativeBackend); isNative {
			_ = os.Remove(outputFile)
		}
		if e.Opt.StepReporter != nil {
			id := st.ID
			if id == "" {
				id = name
			}
			e.Opt.StepReporter(cj.ID, id, time.Since(stepStart))
		}
		if runErr != nil {
			if st.ContinueOnError {
				e.log(cj.ID, name, "failed but continue_on_error=true: "+runErr.Error())
				continue
			}
			if errorKind(runErr) == ErrorCancelled || ctx.Err() != nil {
				currentStatus = model.StatusCancelled
				if cleanupCtx == nil {
					var cleanupCancel context.CancelFunc
					// Survive the JOB deadline, never the runner lifecycle:
					// context.WithoutCancel(ctx) alone would strip BOTH, so
					// a user cleanup step could keep running for the whole
					// cleanup timeout after the runner was told to shut down
					// (longer than the runner's background drain grace).
					cleanupCtx, cleanupCancel = detachedJobContext(jobParent, lifecycle, cleanupTimeout)
					defer cleanupCancel()
				}
				if res.Error == "" {
					res.Error = runErr.Error()
				}
				continue
			}
			currentStatus = model.StatusFailure
			if res.Error == "" {
				res.Error = runErr.Error()
			}
		}
	}
	if e.Opt.OnlyStep != "" && !matchedStep {
		res.Status = model.StatusFailure
		res.Error = fmt.Sprintf("step %q not found in job", e.Opt.OnlyStep)
		return finish(res)
	}
	// generate.path handling runs while the backend session is alive (the
	// session is closed only by the deferred cleanup above). The fragment is
	// read through the backend with a hard cap, never host-side by name: a
	// fragment that cannot be safely read fails the job with a clear error.
	// A fragment that is read but rejected by the upload hook fails the job
	// too unless generate.optional downgraded it to a warning.
	if currentStatus == model.StatusSuccess && strings.TrimSpace(cj.Job.Generate.Path) != "" {
		genPath := strings.TrimSpace(cj.Job.Generate.Path)
		clean := filepath.Clean(genPath)
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			genErr := fmt.Errorf("generate.path %q escapes the workspace", genPath)
			e.log(cj.ID, "generate", genErr.Error())
			currentStatus = model.StatusFailure
			res.Error = genErr.Error()
		} else {
			var (
				data []byte
				gerr error
			)
			if _, isNative := backend.(*NativeBackend); isNative {
				// Root-anchored read: the fragment path is workspace-relative
				// (already cleaned above), so no symlinked component below the
				// workspace can redirect it to host content.
				data, gerr = readFileWithinRoot(workspace, filepath.Join(workspace, clean), maxGeneratedFragmentBytes)
			} else {
				data, gerr = e.ReadJobFile(ctx, cj.ID, filepath.Join(workspace, clean), maxGeneratedFragmentBytes)
			}
			if gerr != nil {
				genErr := fmt.Errorf("generate.path %q: %w", genPath, gerr)
				e.log(cj.ID, "generate", genErr.Error())
				currentStatus = model.StatusFailure
				res.Error = genErr.Error()
			} else if e.Opt.GenerateUpload != nil {
				if uerr := e.Opt.GenerateUpload(cj.ID, genPath, data); uerr != nil {
					if cj.Job.Generate.Optional {
						e.log(cj.ID, "generate", "fragment upload warning (generate.optional=true): "+uerr.Error())
					} else {
						// Default semantics: a declared generated graph that
						// the control plane rejects (or that cannot be
						// delivered) is a job failure, never a silent
						// success with missing children.
						genErr := fmt.Errorf("generated graph rejected: %w", uerr)
						e.log(cj.ID, "generate", genErr.Error())
						currentStatus = model.StatusFailure
						res.Error = genErr.Error()
					}
				}
			}
		}
	}
	// Phase gate: the declared job context ending before publication means
	// the job did not complete inside its lifetime. Mark it cancelled NOW,
	// before success-only publication can spend minutes hashing and
	// compressing the workspace under a dead deadline (the work would
	// otherwise run to completion and be discarded by the final status
	// correction). Artifact capture below still honors conditions that admit
	// the cancelled status, under the bounded capture context, so diagnostic
	// artifacts are preserved deliberately instead of as a side effect.
	if ctx.Err() != nil && currentStatus == model.StatusSuccess {
		currentStatus = model.StatusCancelled
		if res.Error == "" {
			res.Error = ctx.Err().Error()
		}
	}
	if currentStatus == model.StatusSuccess {
		for _, c := range cj.Job.Cache {
			key, er := e.Opt.Cache.KeyContext(ctx, e.cacheBase(c.Key)+"|"+runtime.GOOS+"|"+runtime.GOARCH+"|"+cj.Job.Runtime, workspace, c.HashFiles)
			if er == nil {
				// SaveContext, never Save: the legacy wrapper uses a
				// timeout-free background context, so a big archive would
				// ignore the job deadline entirely.
				if er = e.Opt.Cache.SaveContext(ctx, key, workspace, c.Paths); er != nil {
					e.log(cj.ID, "cache", "save warning: "+er.Error())
				} else {
					e.log(cj.ID, "cache", "saved "+cacheName(c)+" ("+key[:12]+")")
				}
			}
		}
	}
	if e.Opt.CaptureSnapshot && currentStatus != model.StatusSkipped && currentStatus != model.StatusBlocked {
		e.captureSnapshot(cj.ID, workspace)
	}
	res.Status = currentStatus
	res.Outputs = pipeline.InterpolateOutputMap(cj.Job.Outputs, needsOutputs, stepOutputs)
	// Taint gate: declared job outputs interpolate step outputs, so both
	// are checked before anything persists. An output that carries a
	// registered secret fails the job and drops the outputs entirely —
	// secret values never reach persisted job outputs.
	if err := e.Masker.TaintCheck(res.Outputs, stepOutputs); err != nil {
		e.log(cj.ID, "outputs", err.Error())
		res.Status = model.StatusFailure
		res.Error = err.Error()
		res.Outputs = nil
	}
	e.saveArtifacts(cj, workspace, res.Status, jobParent, lifecycle)
	// Artifact delivery is part of the declared job lifetime (the runner
	// wires ArtifactReporter to the job context), so a deadline or
	// cancellation that lands while artifacts are being published must not
	// leave a green job behind: the reporter surfaces the cancellation as a
	// warning only, and without this check res.Status would still be SUCCESS
	// even though the upload was cut off. This mirrors the canonical
	// statusForErr rule (a context that ended makes the outcome cancelled)
	// and the same check also catches a job whose deadline expired after the
	// steps but before this point.
	if cerr := ctx.Err(); cerr != nil {
		if res.Error == "" {
			res.Error = cerr.Error()
		}
		res.Status = model.StatusCancelled
	}
	return finish(res)
}

// absWorkspacePath is a test-only seam over filepath.Abs. Production behavior
// is unchanged; it lets the checked workspace-canonicalization failure
// branches be exercised. The underlying failure is real when the process
// working directory has been removed (getcwd ENOENT on Linux) but cannot be
// reproduced on darwin, where getcwd keeps resolving an unlinked directory.
var absWorkspacePath = filepath.Abs

// closeSnapshotFile is a test-only seam over os.File.Close. Production
// behavior is unchanged; it lets the checked snapshot-close failure branch be
// exercised.
var closeSnapshotFile = (*os.File).Close

// captureSnapshot archives the job workspace after its steps ran. It writes
// under the host temp dir (filepath.Join(os.TempDir(), "kiwi-snapshots",
// runID, jobID+".tar.gz")) using the snapshot package's own workspace scan.
// Any failure is logged as a warning; snapshot capture never changes job
// status.
func (e *Executor) captureSnapshot(jobID, workspace string) {
	dest := filepath.Join(os.TempDir(), "kiwi-snapshots", e.Opt.RunID, jobID+".tar.gz")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		e.log(jobID, "snapshot", "warning: "+err.Error())
		return
	}
	f, err := os.Create(dest)
	if err != nil {
		e.log(jobID, "snapshot", "warning: "+err.Error())
		return
	}
	if _, err := snapshot.Create(workspace, f); err != nil {
		_ = f.Close()
		e.log(jobID, "snapshot", "warning: "+err.Error())
		return
	}
	if err := closeSnapshotFile(f); err != nil {
		e.log(jobID, "snapshot", "warning: "+err.Error())
		return
	}
	e.log(jobID, "snapshot", "saved "+dest)
}

// defaultCondition supplies the implicit step condition: a step without an
// explicit `if` runs only while the job status still admits success().
func defaultCondition(cond string) string {
	if strings.TrimSpace(cond) == "" {
		return "success()"
	}
	return cond
}

// cleanupTimeout bounds the cleanup phase that runs after a job is
// cancelled: steps whose conditions admit the cancelled state execute under
// a fresh context with this budget because the job's own execution context
// is already dead. A var so tests can shrink it.
var cleanupTimeout = 60 * time.Second

// artifactCaptureTimeout bounds the cancellation-time artifact capture
// fallback (if: cancelled() diagnostics) once the job context has ended. A
// var so tests can shrink it.
var artifactCaptureTimeout = 60 * time.Second

// detachedJobContext returns a context for work that must survive the JOB
// context ending (the declared job deadline) while staying tied to the
// runner/process lifecycle: it drops parent's cancellation but re-cancels
// when lifecycle does, and it is always bounded by timeout. parent is the
// context received before the job deadline was applied; a nil lifecycle
// means the caller supplied no separate lifecycle, so only the timeout
// bounds the detached work (historical local behavior).
func detachedJobContext(parent, lifecycle context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), timeout)
	if lifecycle == nil {
		return ctx, cancel
	}
	if lifecycle.Err() != nil {
		// Already shut down: cancel synchronously. context.AfterFunc only
		// schedules the callback on a goroutine, so relying on it here would
		// race a caller's immediate Err() check.
		cancel()
		return ctx, func() { cancel() }
	}
	stop := context.AfterFunc(lifecycle, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// maxGeneratedFragmentBytes is the hard cap for one generated graph
// fragment read through the execution backend (mirrors the control plane's
// upload bound).
const maxGeneratedFragmentBytes = 256 << 10

func (e *Executor) saveArtifacts(cj pipeline.CompiledJob, workspace string, status model.Status, jobParent, lifecycle context.Context) {
	for _, a := range cj.Job.Artifacts {
		ok, err := pipeline.Eval(a.If, pipeline.EvalContext{Status: status})
		if err != nil || !ok {
			continue
		}
		e.saveArtifact(cj, a, workspace, jobParent, lifecycle)
	}
}

// saveArtifact captures, reports and (in capture mode) deletes one artifact.
// A capture failure is a warning: artifact delivery is best-effort
// intelligence, while the job's terminal status is decided by the phase gate
// and the final context check.
func (e *Executor) saveArtifact(cj pipeline.CompiledJob, a pipeline.Artifact, workspace string, jobParent, lifecycle context.Context) {
	ctx := context.Background()
	limit := int64(0)
	if e.Opt.Artifacts != nil {
		limit = e.Opt.Artifacts.MaxArtifactBytes
	}
	// The DECLARATION's own max_size applies on every path, the local store
	// included: a pipeline must never save an archive larger than it
	// declared (previously only the distributed capture path intersected it,
	// so a local run saved unbounded archives for a max_size: 1MiB entry).
	limit = artifactCaptureLimit(limit, a.MaxSize)
	capture := e.Opt.ArtifactCapture
	var finalize func(string) error
	if capture != nil {
		ctx = capture.Context
		if ctx == nil || ctx.Err() != nil {
			// The job context ended before this artifact was captured (an
			// `if: cancelled()` diagnostic capture on a timed-out job). Use
			// the bounded context that survives the JOB deadline but not the
			// runner lifecycle, so the diagnostic still happens deliberately
			// and remains bounded.
			fallbackCtx, fallbackCancel := detachedJobContext(jobParent, lifecycle, artifactCaptureTimeout)
			defer fallbackCancel()
			ctx = fallbackCtx
		}
		if cerr := ctx.Err(); cerr != nil {
			// The bounded fallback itself is done (runner shutdown, or the
			// capture window expired): skip the capture entirely instead of
			// reserving capacity for an archive that can never be delivered.
			e.log(cj.ID, "artifact", "capture skipped: "+cerr.Error())
			return
		}
		limit = artifactCaptureLimit(capture.MaxBytes, a.MaxSize)
		if capture.Reserve == nil {
			e.log(cj.ID, "artifact", "capture failed: artifact staging is not configured")
			return
		}
		fin, rerr := capture.Reserve(ctx, limit)
		if rerr != nil {
			e.log(cj.ID, "artifact", "capture failed: "+rerr.Error())
			return
		}
		finalize = fin
	}
	p, err := e.Opt.Artifacts.SaveContext(ctx, e.Opt.RunID, cj.ID, a.Name, workspace, a.Paths, limit)
	if err != nil {
		if finalize != nil {
			// p is non-empty whenever an archive was renamed into place
			// before the failure (a post-rename fsync/manifest error), so
			// the finalizer can charge cleanup debt for bytes that really
			// exist; an empty path means publication never happened and the
			// charge is simply released.
			if ferr := finalize(p); ferr != nil {
				e.log(cj.ID, "artifact", "cleanup warning: "+ferr.Error())
			}
		}
		e.log(cj.ID, "artifact", "save warning: "+err.Error())
		return
	}
	if finalize != nil {
		// The archive exists only through capture -> attest -> upload ->
		// cleanup, and the finalize callback owns BOTH the physical deletion
		// and the staging release: a failed removal stays charged as cleanup
		// debt instead of freeing accounting for bytes that still occupy
		// disk.
		defer func() {
			if ferr := finalize(p); ferr != nil {
				e.log(cj.ID, "artifact", "cleanup warning: "+ferr.Error())
			}
		}()
	}
	e.log(cj.ID, "artifact", "saved "+p)
	if capture == nil && e.artifacts != nil {
		// Local store mode: make the archive resolvable for downstream jobs'
		// declared downloads in this run.
		e.artifacts.record(cj.ID, cj.BaseID, a.Name, p)
	}
	if e.Opt.ArtifactReporter != nil {
		if err := e.Opt.ArtifactReporter(cj.ID, a.Name, p); err != nil {
			e.log(cj.ID, "artifact", "upload warning: "+err.Error())
		} else {
			e.log(cj.ID, "artifact", "uploaded "+a.Name)
		}
	}
}

// restoreLocalDownloads restores the job's declared dependency downloads from
// this run's locally saved artifacts. The workspace root is opened once
// (no-follow) and every destination is resolved beneath that held handle by
// artifact.Extract, so a symlink left by the checkout can never redirect an
// extraction outside the workspace. A missing producer artifact is an error:
// validation guarantees `from` is a needs dependency, so its absence means
// the producer did not publish what the consumer declared.
func (e *Executor) restoreLocalDownloads(inputs []pipeline.ArtifactInput, workspace string) error {
	wsRoot, err := safefs.OpenWorkspaceRoot(workspace)
	if err != nil {
		return fmt.Errorf("downloads: open workspace root: %w", err)
	}
	defer wsRoot.Close()
	for _, in := range inputs {
		rel, err := localDownloadDest(in.Path)
		if err != nil {
			return err
		}
		from := strings.TrimSpace(in.From)
		name := strings.TrimSpace(in.Name)
		if from == "" || name == "" {
			return fmt.Errorf("invalid download declaration (from=%q name=%q)", in.From, in.Name)
		}
		archive, ok, lookupErr := e.artifacts.lookup(from, name)
		if lookupErr != nil {
			return lookupErr
		}
		if !ok {
			return fmt.Errorf("dependency artifact %q from %q was not produced by this run", name, from)
		}
		if err := artifact.Extract(archive, wsRoot.Root, rel); err != nil {
			return fmt.Errorf("download %q from %q: %w", name, from, err)
		}
		e.log(wsRootID(workspace), "download", fmt.Sprintf("restored %s from %s", name, from))
	}
	return nil
}

// wsRootID renders a short workspace identity for download log lines (the
// job ID is not available in the download path).
func wsRootID(workspace string) string {
	base := filepath.Base(workspace)
	if len(base) > 16 {
		base = base[:16]
	}
	return base
}

// localDownloadDest validates a declared download destination for local
// runs: relative, confined, no backslashes (the portable-absolute check
// covers both separators).
func localDownloadDest(inPath string) (string, error) {
	if inPath == "" {
		return "", nil
	}
	clean := filepath.Clean(inPath)
	if pipeline.IsPortableAbsPath(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || strings.ContainsRune(clean, '\\') {
		return "", fmt.Errorf("unsafe download path %q", inPath)
	}
	if clean == "." {
		return "", nil
	}
	return filepath.ToSlash(clean), nil
}

// CleanupKind names the runtime subsystem whose removal could not be proven.
type CleanupKind string

const (
	CleanupMainRuntime CleanupKind = "main-runtime"
	CleanupService     CleanupKind = "service-container-or-network"
	CleanupCgroup      CleanupKind = "job-cgroup"
	CleanupXFSQuota    CleanupKind = "xfs-project-quota"
	// Runner-observed teardown failures (reported by the runner itself).
	CleanupWorkspaceQuota  CleanupKind = "workspace-quota-teardown"
	CleanupWorkspace       CleanupKind = "workspace-removal"
	CleanupArtifactScratch CleanupKind = "artifact-scratch-removal"
)

// CleanupDebt is one unproven-removal report: the durable recovery ledger
// must keep the coordinates and no new leases may be accepted until the debt
// is reconciled.
type CleanupDebt struct {
	Kind     CleanupKind
	Resource string
	Err      error
}

// reportCleanupDebt forwards one cleanup-debt report to the caller.
func (e *Executor) reportCleanupDebt(kind CleanupKind, resource string, err error) {
	if err == nil || e.Opt.OnCleanupDebt == nil {
		return
	}
	e.Opt.OnCleanupDebt(CleanupDebt{Kind: kind, Resource: resource, Err: err})
}

// artifactCaptureLimit intersects the global artifact payload ceiling with
// the declaration's max_size: the distributed runner must not spend disk,
// CPU and upload bandwidth on an archive the control plane is guaranteed to
// reject (either bound can be the smaller one). Zero means unbounded, which
// only a caller that configured no global ceiling at all can produce.
func artifactCaptureLimit(global int64, declared pipeline.ByteSize) int64 {
	limit := global
	if d := int64(declared); d > 0 && (limit <= 0 || d < limit) {
		limit = d
	}
	return limit
}
func (e *Executor) log(j, s, l string) {
	if e.Opt.Logs != nil {
		e.Opt.Logs.WriteLine(j, s, e.Masker.MaskMulti(l))
	}
}
func finish(r model.JobResult) model.JobResult {
	r.FinishedAt = time.Now()
	r.Duration = r.FinishedAt.Sub(r.StartedAt)
	return r
}
func depsOutcome(needs []string, statuses map[string]model.Status) (bool, model.Status) {
	outcome := model.StatusSuccess
	for _, d := range needs {
		st, ok := statuses[d]
		if !ok || !st.Terminal() {
			return false, model.StatusPending
		}
		switch st {
		case model.StatusFailure, model.StatusBlocked:
			outcome = model.StatusFailure
		case model.StatusCancelled:
			if outcome != model.StatusFailure {
				outcome = model.StatusCancelled
			}
		}
	}
	return true, outcome
}

func dependencyConditionAllows(expr string, status model.Status) bool {
	return pipeline.ConditionAllows(expr, status)
}

// secureWorkingDir resolves a step's working_directory against the workspace
// root and enforces containment on symlink-resolved (canonical) paths, so a
// symlinked component inside the workspace cannot redirect the step outside
// of it.
//
// The returned path is re-spelled under the caller's workspace root rather
// than under the canonical root: ContainerBackend and TartBackend compare
// the step directory against filepath.Abs(workspace) lexically (filepath.Rel)
// to derive the in-sandbox path, and when the workspace root itself lives
// under a symlink (macOS /var and /tmp, or a symlinked data dir) the
// canonical path would look like it escapes the mount. The relative path was
// verified against the canonical root, so joining it back to the original
// root keeps containment and never widens the workspace.
func secureWorkingDir(workspace, rel string) (string, error) {
	root, err := absWorkspacePath(workspace)
	if err != nil {
		return "", err
	}
	candidate := root
	if strings.TrimSpace(rel) != "" {
		if filepath.IsAbs(rel) {
			return "", fmt.Errorf("working_directory must be workspace-relative: %q", rel)
		}
		clean := filepath.Clean(rel)
		if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("working_directory escapes workspace: %q", rel)
		}
		candidate = filepath.Join(root, clean)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve workspace: %w", err)
	}
	realCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve working_directory %q: %w", rel, err)
	}
	relToRoot, err := filepath.Rel(realRoot, realCandidate)
	if err != nil || relToRoot == ".." || strings.HasPrefix(relToRoot, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("working_directory resolves outside workspace: %q", rel)
	}
	return filepath.Join(root, relToRoot), nil
}

func collectNeedsOutputs(needs []string, jobs map[string]pipeline.CompiledJob, results map[string]model.JobResult) map[string]map[string]string {
	out := map[string]map[string]string{}
	baseCount := map[string]int{}
	for _, id := range needs {
		if cj, ok := jobs[id]; ok {
			baseCount[cj.BaseID]++
		}
	}
	for _, id := range needs {
		res, ok := results[id]
		if !ok || len(res.Outputs) == 0 {
			continue
		}
		out[id] = cloneOutputs(res.Outputs)
		if cj, ok := jobs[id]; ok && baseCount[cj.BaseID] == 1 {
			out[cj.BaseID] = cloneOutputs(res.Outputs)
		}
	}
	return out
}

func cloneOutputs(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func secretEnvName(s string) string {
	return "KIWI_SECRET_" + strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(s))
}

// resolveSecrets fetches the named secrets (deduplicated via cache), registers
// their values with the masker, and returns them as KIWI_SECRET_* env pairs.
// Job-level secrets are resolved once into the job env (job-wide); step-level
// secrets are resolved into that step's env only, so a secret declared on one
// step never reaches other steps, and secret values never reach cache keys or
// persisted state. Masker registration is strict: a secret value the masker
// cannot hold (capacity or outside the masking window) fails the job closed —
// an unmaskable secret must never run.
func (e *Executor) resolveSecrets(ctx context.Context, names []string, cache map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for _, name := range names {
		v, ok := cache[name]
		if !ok {
			if e.Opt.SecretProvider == nil {
				continue
			}
			var er error
			v, er = e.Opt.SecretProvider.Get(ctx, name)
			if er != nil {
				return nil, er
			}
			if err := e.Masker.AddStrict(v); err != nil {
				return nil, &RunError{Kind: ErrorConfig, Err: fmt.Errorf("secret %q cannot be masked; refusing to run: %w", name, err)}
			}
			cache[name] = v
		}
		out[secretEnvName(name)] = v
	}
	return out, nil
}

// defaultShell is the final fallback for an unspecified shell, per runtime
// kind: containers run sh, Tart guests run bash, native hosts run pwsh on
// Windows and bash everywhere else. The full resolution order is
// step.Shell > job.Shell > spec.Defaults.Shell > defaultShell(runtime).
func defaultShell(runtimeKind string) string {
	switch runtimeKind {
	case "container":
		return "sh"
	case "tart":
		return "bash"
	default: // native, ""
		if runtime.GOOS == "windows" {
			return "pwsh"
		}
		return "bash"
	}
}

func (e *Executor) cacheBase(base string) string {
	ns := strings.TrimSpace(e.Opt.CacheNamespace)
	if ns == "" {
		ns = "local"
	}
	return ns + "|" + base
}

func cacheName(c pipeline.Cache) string {
	if c.Name != "" {
		return c.Name
	}
	if c.Key != "" {
		return c.Key
	}
	return "cache"
}
func retryAllows(r pipeline.Retry, err error) bool {
	if r.Max <= 0 {
		return false
	}
	kind := errorKind(err)
	class := failureClass(err)
	if class == CancelledFailure {
		return false
	}
	if len(r.On) == 0 {
		// Default policy: only transient failure classes retry; policy,
		// configuration, cancellation, and lost-runner failures never do.
		return retryableClass(class)
	}
	for _, x := range r.On {
		x = strings.ToLower(strings.TrimSpace(x))
		if x == kind || x == "any" || (x == "command" && kind == ErrorFailure) {
			return true
		}
	}
	return false
}

// retrySeed derives a per-job seed for the retry backoff jitter so jobs
// retrying at the same time do not retry in lockstep.
func retrySeed(parts ...string) uint64 {
	h := fnv.New64a()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return h.Sum64()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// effectiveStepRetry resolves a step's retry policy: a step's EXPLICIT retry
// (including max: 0, meaning zero retries) wins over the job's, which wins
// over the defaults. Programmatic retries with Max>0 count as set. The
// resolved value is clamped to the admission cap as defense in depth, so a
// persisted or programmatic policy can never drive unbounded (or
// integer-wrapping) attempt arithmetic.
func effectiveStepRetry(st pipeline.Step, job pipeline.Job, defaults pipeline.Defaults) pipeline.Retry {
	retry := st.Retry
	if !retry.MaxSet && retry.Max == 0 {
		retry = job.Retry
	}
	if !retry.MaxSet && retry.Max == 0 {
		retry = defaults.Retry
	}
	if retry.Max > pipeline.MaxStepRetries {
		retry.Max = pipeline.MaxStepRetries
	}
	return retry
}

// unsupportedSandboxRequirement refuses sandbox requirements the runtime
// cannot actually enforce. A security requirement accepted but silently
// unenforced is worse than a refusal.
func unsupportedSandboxRequirement(runtime string, sandbox pipeline.Sandbox) error {
	if sandbox.NonRoot && runtime != "container" {
		return fmt.Errorf("sandbox non_root cannot be enforced by the %s runtime", runtime)
	}
	return nil
}
