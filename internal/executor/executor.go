package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/artifact"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

type Options struct {
	Workspace        string
	RunID            string
	MaxParallel      int
	OnlyJob          string
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
}

type Executor struct {
	Opt    Options
	Masker *secrets.Masker
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
			key, er := e.Opt.Cache.Key(e.cacheBase(base)+"|"+runtime.GOOS+"|"+runtime.GOARCH+"|"+cj.Job.Runtime, e.Opt.Workspace, c.HashFiles)
			if er != nil {
				e.log(cj.ID, "cache", "key warning: "+er.Error())
				break
			}
			hit, er := e.Opt.Cache.Restore(key, e.Opt.Workspace, c.Paths)
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
	cleanupServices := func() {}
	if cj.Job.Runtime == "container" && len(cj.Job.Services) > 0 {
		isolated := networkPolicy == pipeline.NetworkPolicyNone || networkPolicy == pipeline.NetworkPolicyServicesOnly
		var er error
		network, cleanupServices, er = startContainerServices(ctx, e.Opt.RunID, cj.ID, cj.Job.Services, isolated, func(line string) { e.log(cj.ID, "service", line) })
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
	case *TartBackend:
		b.RequireImmutableImages = e.Opt.RequireImmutableImages
	}
	if lifecycle, ok := backend.(JobLifecycle); ok {
		if err := lifecycle.StartJob(ctx, e.Opt.Workspace, func(line string) { e.log(cj.ID, "runtime", line) }); err != nil {
			res.Status = model.StatusFailure
			res.Error = err.Error()
			return finish(res)
		}
		defer func() {
			if err := lifecycle.CloseJob(); err != nil {
				e.log(cj.ID, "runtime", "cleanup warning: "+err.Error())
			}
		}()
	}
	stepOutputs := map[string]map[string]string{}
	for i, st := range cj.Job.Steps {
		st.Name = pipeline.InterpolateOutputs(st.Name, needsOutputs, stepOutputs)
		st.Run = pipeline.InterpolateOutputs(st.Run, needsOutputs, stepOutputs)
		st.If = pipeline.InterpolateOutputs(st.If, needsOutputs, stepOutputs)
		st.WorkingDirectory = pipeline.InterpolateOutputs(st.WorkingDirectory, needsOutputs, stepOutputs)
		st.Env = pipeline.InterpolateOutputMap(st.Env, needsOutputs, stepOutputs)
		name := st.Name
		if name == "" {
			name = fmt.Sprintf("step-%d", i+1)
		}
		ok, er := pipeline.Eval(st.If, pipeline.EvalContext{Status: res.Status, Env: cj.Job.Env, Event: e.Opt.Event, Branch: e.Opt.Branch})
		if er != nil {
			res.Status = model.StatusFailure
			res.Error = er.Error()
			return finish(res)
		}
		if !ok {
			e.log(cj.ID, name, "skipped")
			continue
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
		dir, dirErr := secureWorkingDir(e.Opt.Workspace, st.WorkingDirectory)
		if dirErr != nil {
			res.Status = model.StatusFailure
			res.Error = dirErr.Error()
			res.Outputs = pipeline.InterpolateOutputMap(cj.Job.Outputs, needsOutputs, stepOutputs)
			e.saveArtifacts(s, cj, res.Status)
			return finish(res)
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
		if backoff == 0 {
			backoff = time.Second
		}
		stepEnvMap := mergeEnvMap(jobEnv, st.Env)
		// Step secret values live only in this step's env map; a fresh cache
		// per step means no step secret is retained in any map that outlives
		// the step.
		stepSecrets, secErr := e.resolveSecrets(ctx, st.Secrets, map[string]string{})
		if secErr != nil {
			res.Status = model.StatusFailure
			res.Error = secErr.Error()
			res.Outputs = pipeline.InterpolateOutputMap(cj.Job.Outputs, needsOutputs, stepOutputs)
			e.saveArtifacts(s, cj, res.Status)
			return finish(res)
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
		var runErr error
		for attempt := 1; attempt <= attempts; attempt++ {
			if _, isNative := backend.(*NativeBackend); isNative {
				_ = os.Remove(outputFile)
			}
			res.Attempts++
			e.log(cj.ID, name, fmt.Sprintf("running on %s (attempt %d/%d)", backend.Name(), attempt, attempts))
			runErr = backend.Run(ctx, Command{Shell: shell, Script: st.Run, Dir: dir, Env: stepEnv, TimeoutSeconds: int64(timeout.Seconds())}, func(line string) { e.log(cj.ID, name, line) })
			if runErr == nil {
				break
			}
			if !retryAllows(retry, runErr) {
				break
			}
			if attempt < attempts {
				e.log(cj.ID, name, fmt.Sprintf("retrying after error: %v", runErr))
				select {
				case <-ctx.Done():
					runErr = ctx.Err()
					attempt = attempts
				case <-time.After(backoff):
				}
				backoff *= 2
			}
		}
		if st.ID != "" {
			data, outErr := backend.ReadFile(ctx, outputFile, 1<<20)
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
		if runErr != nil {
			if st.ContinueOnError {
				e.log(cj.ID, name, "failed but continue_on_error=true: "+runErr.Error())
				continue
			}
			if errorKind(runErr) == ErrorCancelled || errors.Is(ctx.Err(), context.Canceled) {
				res.Status = model.StatusCancelled
			} else {
				res.Status = model.StatusFailure
			}
			res.Error = runErr.Error()
			res.Outputs = pipeline.InterpolateOutputMap(cj.Job.Outputs, needsOutputs, stepOutputs)
			e.saveArtifacts(s, cj, res.Status)
			return finish(res)
		}
	}
	for _, c := range cj.Job.Cache {
		key, er := e.Opt.Cache.Key(e.cacheBase(c.Key)+"|"+runtime.GOOS+"|"+runtime.GOARCH+"|"+cj.Job.Runtime, e.Opt.Workspace, c.HashFiles)
		if er == nil {
			if er = e.Opt.Cache.Save(key, e.Opt.Workspace, c.Paths); er != nil {
				e.log(cj.ID, "cache", "save warning: "+er.Error())
			} else {
				e.log(cj.ID, "cache", "saved "+cacheName(c)+" ("+key[:12]+")")
			}
		}
	}
	res.Status = model.StatusSuccess
	res.Outputs = pipeline.InterpolateOutputMap(cj.Job.Outputs, needsOutputs, stepOutputs)
	e.saveArtifacts(s, cj, res.Status)
	return finish(res)
}

func (e *Executor) saveArtifacts(_ *pipeline.Spec, cj pipeline.CompiledJob, status model.Status) {
	for _, a := range cj.Job.Artifacts {
		ok, err := pipeline.Eval(a.If, pipeline.EvalContext{Status: status})
		if err != nil || !ok {
			continue
		}
		p, err := e.Opt.Artifacts.Save(e.Opt.RunID, cj.ID, a.Name, e.Opt.Workspace, a.Paths)
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
func secureWorkingDir(workspace, rel string) (string, error) {
	root, err := filepath.Abs(workspace)
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
	return realCandidate, nil
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
// persisted state.
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
			e.Masker.Add(v)
			cache[name] = v
		}
		out[secretEnvName(name)] = v
	}
	return out, nil
}
func defaultShell(runtimeKind string) string {
	if runtimeKind == "container" {
		return "sh"
	}
	if runtimeKind == "native" || runtimeKind == "" {
		if runtime.GOOS == "windows" {
			return "pwsh"
		}
	}
	return "bash"
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
	if kind == ErrorCancelled {
		return false
	}
	if len(r.On) == 0 {
		return true
	}
	for _, x := range r.On {
		x = strings.ToLower(strings.TrimSpace(x))
		if x == kind || x == "any" || (x == "command" && kind == ErrorFailure) {
			return true
		}
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
