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
	MaxParallel  int
	OnlyJob      string
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
	ArtifactReporter func(jobID, name, path string) error
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
	// LogMaxBytes caps the per-job log stream forwarded to Logs. Once the
	// quota is exhausted, further lines are dropped after a single terminal
	// "log quota exceeded" marker. Zero means unlimited.
	LogMaxBytes int64
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

type Executor struct {
	Opt    Options
	Masker *secrets.Masker
	// sessions tracks the live per-job backend sessions so generate reads
	// (and other job-scoped file reads) resolve through the execution
	// backend instead of host-side path opens. It must stay a pointer: runJob
	// makes shallow copies of Executor for its log-quota scoping.
	sessions *sessionRegistry
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
	jobTimeout := cj.Job.Timeout.Duration
	if jobTimeout == 0 {
		jobTimeout = s.Defaults.Timeout.Duration
	}
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
	if e.Opt.WorkspaceMaxBytes > 0 {
		if err := safefs.FitsAvailable(workspace, e.Opt.WorkspaceMaxBytes); err != nil {
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
	for _, c := range cj.Job.Cache {
		bases := append([]string{c.Key}, c.RestoreKeys...)
		restored := false
		for i, base := range bases {
			key, er := e.Opt.Cache.Key(e.cacheBase(base)+"|"+runtime.GOOS+"|"+runtime.GOARCH+"|"+cj.Job.Runtime, workspace, c.HashFiles)
			if er != nil {
				e.log(cj.ID, "cache", "key warning: "+er.Error())
				break
			}
			hit, er := e.Opt.Cache.Restore(key, workspace, c.Paths)
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
	networkPolicy := cj.Job.Sandbox.Network
	if networkPolicy == pipeline.NetworkPolicyDefault && cj.Job.Network == "none" {
		networkPolicy = pipeline.NetworkPolicyNone
	}
	network := cj.Job.Network
	var cleanupServices func()
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
			// Registered before the services/backend cleanup defers below,
			// so it runs AFTER the containers are gone (LIFO).
			defer func() {
				if cerr := cgCleanup(); cerr != nil {
					e.log(cj.ID, "service", "job cgroup cleanup warning: "+cerr.Error())
				}
			}()
			e.log(cj.ID, "service", "job resource cgroup: "+cgStatus.Detail)
		} else {
			e.log(cj.ID, "service", "job resource cgroup unavailable ("+cgStatus.Detail+"); per-container caps apply, and the aggregate service request ("+serviceEnvelopeSummary(cj.Job.Resources, cj.Job.Services)+") must be reserved by the scheduler to bound aggregate host usage")
		}
		isolated := networkPolicy == pipeline.NetworkPolicyNone || networkPolicy == pipeline.NetworkPolicyServicesOnly
		var er error
		network, cleanupServices, er = startContainerServices(ctx, e.Opt.RunID, cj.ID, cj.Job.Services, cj.Job.Resources, isolated, e.Opt.RequireImmutableImages, cgroupParent, func(line string) { e.log(cj.ID, "service", line) })
		if er != nil {
			res.Status = model.StatusFailure
			res.Error = er.Error()
			return finish(res)
		}
		defer cleanupServices()
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
		b.RunID = e.Opt.RunID
		b.JobID = cj.ID
		b.Resources = cj.Job.Resources
		b.Untrusted = e.Opt.Untrusted
		b.UntrustedDiskMaxBytes = e.Opt.UntrustedWorkspaceMaxBytes
		b.RequireDiskQuota = e.Opt.RequireUntrustedDiskQuota
		b.WorkspaceQuota = e.Opt.WorkspaceQuota
		b.CgroupParent = cgroupParent
	case *TartBackend:
		b.RequireImmutableImages = e.Opt.RequireImmutableImages
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
		retry := st.Retry
		if retry.Max == 0 {
			retry = cj.Job.Retry
		}
		if retry.Max == 0 {
			retry = s.Defaults.Retry
		}
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
					cleanupCtx, cleanupCancel = context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
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
	if currentStatus == model.StatusSuccess {
		for _, c := range cj.Job.Cache {
			key, er := e.Opt.Cache.Key(e.cacheBase(c.Key)+"|"+runtime.GOOS+"|"+runtime.GOARCH+"|"+cj.Job.Runtime, workspace, c.HashFiles)
			if er == nil {
				if er = e.Opt.Cache.Save(key, workspace, c.Paths); er != nil {
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
	e.saveArtifacts(s, cj, workspace, res.Status)
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
// exercised (matching the runner's closeRunnerTempFile seam).
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
// is already dead.
const cleanupTimeout = 60 * time.Second

// maxGeneratedFragmentBytes is the hard cap for one generated graph
// fragment read through the execution backend (mirrors the control plane's
// upload bound).
const maxGeneratedFragmentBytes = 256 << 10

func (e *Executor) saveArtifacts(_ *pipeline.Spec, cj pipeline.CompiledJob, workspace string, status model.Status) {
	for _, a := range cj.Job.Artifacts {
		ok, err := pipeline.Eval(a.If, pipeline.EvalContext{Status: status})
		if err != nil || !ok {
			continue
		}
		p, err := e.Opt.Artifacts.Save(e.Opt.RunID, cj.ID, a.Name, workspace, a.Paths)
		if err != nil {
			e.log(cj.ID, "artifact", "save warning: "+err.Error())
			continue
		}
		e.log(cj.ID, "artifact", "saved "+p)
		if e.Opt.ArtifactReporter != nil {
			if err := e.Opt.ArtifactReporter(cj.ID, a.Name, p); err != nil {
				e.log(cj.ID, "artifact", "upload warning: "+err.Error())
			} else {
				e.log(cj.ID, "artifact", "uploaded "+a.Name)
			}
		}
	}
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
