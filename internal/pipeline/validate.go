package pipeline

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

const (
	maxDeclaredJobs   = 1024
	maxExpandedJobs   = 4096
	maxMatrixDims     = 12
	maxMatrixCombos   = 512
	maxStepsPerJob    = 512
	maxServicesPerJob = 32
	// maxSecretsPerJob is the per-job declared-secret-name cap. It is the
	// shared capacity agreement with the execution masker: a job that
	// passes admission can never silently lose secrets to masking because
	// the Masker holds exactly secrets.MaxSecretNames values.
	maxSecretsPerJob = secrets.MaxSecretNames
	maxEnvVarsPerJob = 1024
	maxCommandBytes  = 1 << 20 // 1 MiB
	maxEnvValueBytes = 64 << 10
	maxArtifactDefs  = 128
	maxOutputKeys    = 256
	maxShardsPerJob  = 1024
)

var (
	idRegexp      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
	envNameRegexp = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	labelRegexp   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:_-]{0,63}$`)
	// inputNameRegexp pins the input identifier grammar: a leading ASCII
	// letter or underscore followed by up to 63 letters, digits,
	// underscores or hyphens.
	inputNameRegexp = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)
	// secretNameRegexp pins the secret identifier grammar to the env-safe
	// canonical form: a leading ASCII letter or underscore followed by up
	// to 63 letters, digits or underscores — no hyphens, dots or other
	// punctuation. The executor projects secret names into
	// KIWI_SECRET_<NAME> environment variables by replacing punctuation
	// with "_", so names like foo-bar and foo.bar would collide with
	// foo_bar after projection. Rejecting punctuation at admission makes
	// collisions impossible for accepted names.
	secretNameRegexp = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

	shellNames = map[string]bool{
		"": true, "bash": true, "sh": true, "zsh": true, "pwsh": true,
		"powershell": true, "fish": true, "dash": true, "ksh": true, "python": true,
	}
	networkModes = map[string]bool{"": true, "bridge": true, "host": true, "none": true}
	// retryClasses is the executor's retry-class vocabulary. "cancelled" is
	// deliberately absent: the executor never retries cancellations, and a
	// pipeline that declares it fails validation instead of silently
	// relying on a semantic that never fires.
	retryClasses = map[string]bool{
		"any": true, "artifact": true, "cache": true, "command": true,
		"failure": true, "infra": true, "timeout": true,
	}
	interpContexts = map[string]bool{
		"matrix": true, "needs": true, "steps": true, "env": true, "github": true,
		"inputs": true, "vars": true, "secrets": true, "runner": true,
		"ref": true, "event": true, "sha": true, "repo": true, "branch": true,
		"git": true,
	}
)

// Validate performs full admission validation: hard resource limits, ID and
// reference checks, runtime/network/shell constraints, matrix shape checks,
// path confinement, duration and retry policy checks, and interpolation
// sanity. It preserves the historical error messages existing consumers and
// tests rely on.
func Validate(s *Spec) error {
	return validateSpec(s, false)
}

// validateSpec is Validate with the component resolution relaxation used by
// ParseWithComponents: when relaxComponentJobs is set, a job that declares
// `component:` may omit its own steps (the component fragment supplies
// them); every other rule applies unchanged.
func validateSpec(s *Spec, relaxComponentJobs bool) error {
	if s == nil {
		return fmt.Errorf("nil pipeline")
	}
	if err := ValidateLimits(s); err != nil {
		return err
	}
	if !shellNames[s.Defaults.Shell] {
		return fmt.Errorf("unsupported default shell %q", s.Defaults.Shell)
	}
	if err := validateDuration(s.Defaults.Timeout, "defaults.timeout"); err != nil {
		return err
	}
	if err := validateRetry(s.Defaults.Retry, "defaults.retry"); err != nil {
		return err
	}
	if err := checkInterpolation(s.Concurrency.Group, "concurrency.group"); err != nil {
		return err
	}
	for name, v := range s.Env {
		if len(v) > maxEnvValueBytes {
			return fmt.Errorf("env var %q exceeds %d byte limit", name, maxEnvValueBytes)
		}
	}
	for _, name := range s.Secrets {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("secret name cannot be empty")
		}
		if !secretNameRegexp.MatchString(name) {
			return fmt.Errorf("secret name %q is invalid (must match %s)", name, secretNameRegexp.String())
		}
	}
	if err := validateInputs(s); err != nil {
		return err
	}
	for id, j := range s.Jobs {
		if !idRegexp.MatchString(id) {
			return fmt.Errorf("invalid job id %q", id)
		}
		if len(j.Steps) == 0 && !(relaxComponentJobs && j.Component != "") {
			return fmt.Errorf("job %q has no steps", id)
		}
		seenDeps := map[string]bool{}
		for _, dep := range j.Needs {
			if _, ok := s.Jobs[dep]; !ok {
				return fmt.Errorf("job %q needs unknown job %q", id, dep)
			}
			if dep == id {
				return fmt.Errorf("job %q depends on itself", id)
			}
			if seenDeps[dep] {
				return fmt.Errorf("job %q lists dependency %q more than once", id, dep)
			}
			seenDeps[dep] = true
		}
		if err := validateJob(s, id, j); err != nil {
			return err
		}
	}
	if cyc := findCycle(s.Jobs); len(cyc) > 0 {
		return fmt.Errorf("dependency cycle: %s", strings.Join(cyc, " -> "))
	}
	return nil
}

// ValidateLimits enforces the hard resource limits independent of structural
// rules. It is invoked by Validate so every admission path gets the limits.
func ValidateLimits(s *Spec) error {
	if s == nil {
		return fmt.Errorf("nil pipeline")
	}
	if len(s.Jobs) > maxDeclaredJobs {
		return fmt.Errorf("pipeline declares %d jobs, limit is %d", len(s.Jobs), maxDeclaredJobs)
	}
	if len(s.Env) > maxEnvVarsPerJob {
		return fmt.Errorf("pipeline declares %d env vars, limit is %d", len(s.Env), maxEnvVarsPerJob)
	}
	totalExpanded := 0
	for id, j := range s.Jobs {
		totalSteps := len(j.Steps) + len(j.Deployment.Canary) + len(j.Deployment.Verify) + len(j.Deployment.Rollback)
		if totalSteps > maxStepsPerJob {
			return fmt.Errorf("job %q declares %d steps across steps and deployment phases, limit is %d", id, totalSteps, maxStepsPerJob)
		}
		if len(j.Services) > maxServicesPerJob {
			return fmt.Errorf("job %q declares %d services, limit is %d", id, len(j.Services), maxServicesPerJob)
		}
		if len(j.Artifacts) > maxArtifactDefs {
			return fmt.Errorf("job %q declares %d artifacts, limit is %d", id, len(j.Artifacts), maxArtifactDefs)
		}
		if len(j.Outputs) > maxOutputKeys {
			return fmt.Errorf("job %q declares %d output keys, limit is %d", id, len(j.Outputs), maxOutputKeys)
		}
		if len(j.Env) > maxEnvVarsPerJob {
			return fmt.Errorf("job %q declares %d env vars, limit is %d", id, len(j.Env), maxEnvVarsPerJob)
		}
		secretCount := len(s.Secrets)
		allSteps := make([]Step, 0, totalSteps)
		allSteps = append(allSteps, j.Steps...)
		allSteps = append(allSteps, j.Deployment.Canary...)
		allSteps = append(allSteps, j.Deployment.Verify...)
		allSteps = append(allSteps, j.Deployment.Rollback...)
		for _, st := range allSteps {
			if len(st.Run) > maxCommandBytes {
				return fmt.Errorf("job %q step %q command exceeds %d byte limit", id, st.ID, maxCommandBytes)
			}
			secretCount += len(st.Secrets)
			if len(st.Env) > maxEnvVarsPerJob {
				return fmt.Errorf("job %q step %q declares %d env vars, limit is %d", id, st.ID, len(st.Env), maxEnvVarsPerJob)
			}
		}
		if secretCount > maxSecretsPerJob {
			return fmt.Errorf("job %q declares %d secret names, limit is %d", id, secretCount, maxSecretsPerJob)
		}
		if len(j.Matrix) > maxMatrixDims {
			return fmt.Errorf("job %q matrix has %d dimensions, limit is %d", id, len(j.Matrix), maxMatrixDims)
		}
		combos := matrixComboCount(j.Matrix)
		if combos > maxMatrixCombos {
			return fmt.Errorf("job %q matrix expands to %d combinations, limit is %d", id, combos, maxMatrixCombos)
		}
		if combos == 0 {
			combos = 1
		}
		if j.Tests.Shards > maxShardsPerJob {
			return fmt.Errorf("job %q tests.shards %d exceeds the limit of %d", id, j.Tests.Shards, maxShardsPerJob)
		}
		shardCount := 1
		if j.Tests.Shards > 0 {
			shardCount = j.Tests.Shards
		}
		expanded := saturatingMul(combos, shardCount, maxExpandedJobs)
		if totalExpanded > maxExpandedJobs-expanded {
			return fmt.Errorf("pipeline expands to %d jobs, limit is %d", maxExpandedJobs+1, maxExpandedJobs)
		}
		totalExpanded += expanded
	}
	return nil
}

// saturatingMul multiplies n by factor without ever computing an unchecked
// product: when n already exceeds limit or n*factor would exceed it, the
// result saturates at limit+1 instead of wrapping, so callers can compare
// against limit and never observe an overflowed value. A non-positive
// operand yields 0 (the empty-product identity for the count callers).
func saturatingMul(n, factor, limit int) int {
	if n <= 0 || factor <= 0 {
		return 0
	}
	if n > limit/factor {
		return limit + 1
	}
	return n * factor
}

func matrixComboCount(m map[string][]any) int {
	n := 1
	for _, vals := range m {
		if len(vals) > 0 {
			n = saturatingMul(n, len(vals), maxMatrixCombos)
		}
	}
	return n
}

func validateJob(s *Spec, id string, j Job) error {
	switch j.Runtime {
	case "", "native", "container", "tart":
	default:
		return fmt.Errorf("job %q has unsupported runtime %q", id, j.Runtime)
	}
	switch {
	case (j.Runtime == "" || j.Runtime == "native") && (j.Image != "" || j.VM != ""):
		return fmt.Errorf("job %q: native runtime must not set image or vm", id)
	case j.Runtime == "tart" && j.VM == "":
		return fmt.Errorf("job %q: tart runtime requires a vm", id)
	}
	// Note: "container requires image" is deliberately not enforced here.
	// The server enqueue path (internal/server) submits container jobs
	// without images in its DB-mode tests, and this package must not break
	// those submissions. Backends resolve and fail such jobs at execution
	// time.
	if !networkModes[j.Network] {
		return fmt.Errorf("job %q has unsupported network %q (want one of bridge, host, none)", id, j.Network)
	}
	if j.Sandbox.Network < NetworkPolicyDefault || j.Sandbox.Network > NetworkPolicyInternet {
		return fmt.Errorf("job %q has invalid sandbox.network value %d", id, j.Sandbox.Network)
	}
	if !shellNames[j.Shell] {
		return fmt.Errorf("job %q has unsupported shell %q", id, j.Shell)
	}
	if err := validateDuration(j.Timeout, fmt.Sprintf("job %q timeout", id)); err != nil {
		return err
	}
	if err := validateDuration(j.QueueTimeout, fmt.Sprintf("job %q queue_timeout", id)); err != nil {
		return err
	}
	if err := validateRetry(j.Retry, fmt.Sprintf("job %q retry", id)); err != nil {
		return err
	}
	if j.InfraRetries < 0 {
		return fmt.Errorf("job %q has negative infra_retries", id)
	}
	if j.Environment.Name != "" && !envNameRegexp.MatchString(j.Environment.Name) {
		return fmt.Errorf("job %q has invalid environment name %q", id, j.Environment.Name)
	}
	if j.Environment.Concurrency < 0 {
		return fmt.Errorf("job %q environment concurrency must not be negative", id)
	}
	for _, label := range j.Runner {
		if !labelRegexp.MatchString(label) {
			return fmt.Errorf("job %q has invalid runner label %q", id, label)
		}
	}
	for _, region := range j.Placement.Regions {
		if !envNameRegexp.MatchString(region) {
			return fmt.Errorf("job %q has invalid placement region %q", id, region)
		}
	}
	for _, label := range j.Placement.Labels {
		if !labelRegexp.MatchString(label) {
			return fmt.Errorf("job %q has invalid placement label %q", id, label)
		}
	}
	if err := validateResources(fmt.Sprintf("job %q", id), j.Runtime, j.Resources); err != nil {
		return err
	}
	for name, v := range j.Env {
		if len(v) > maxEnvValueBytes {
			return fmt.Errorf("job %q env var %q exceeds %d byte limit", id, name, maxEnvValueBytes)
		}
		if err := checkInterpolation(v, fmt.Sprintf("job %q env %q", id, name)); err != nil {
			return err
		}
	}
	for key := range j.Outputs {
		if !idRegexp.MatchString(key) {
			return fmt.Errorf("job %q has invalid output identifier %q", id, key)
		}
	}
	for key, v := range j.Outputs {
		if err := checkInterpolation(v, fmt.Sprintf("job %q output %q", id, key)); err != nil {
			return err
		}
	}
	for _, f := range []struct {
		name  string
		value string
	}{
		{"name", j.Name}, {"if", j.If}, {"image", j.Image}, {"vm", j.VM},
		{"shell", j.Shell}, {"component", j.Component},
	} {
		if err := checkInterpolation(f.value, fmt.Sprintf("job %q %s", id, f.name)); err != nil {
			return err
		}
	}
	for key, v := range j.With {
		if err := checkInterpolation(v, fmt.Sprintf("job %q with.%s", id, key)); err != nil {
			return err
		}
	}
	if err := validateMatrix(fmt.Sprintf("job %q", id), j.Matrix); err != nil {
		return err
	}
	seenAliases := map[string]bool{}
	for i := range j.Services {
		if err := validateService(id, &j.Services[i]); err != nil {
			return err
		}
		if seenAliases[j.Services[i].Name] {
			return fmt.Errorf("job %q declares service alias %q more than once", id, j.Services[i].Name)
		}
		seenAliases[j.Services[i].Name] = true
	}
	seenStepIDs := map[string]bool{}
	for i := range j.Steps {
		if err := validateStep(id, i, &j.Steps[i], seenStepIDs); err != nil {
			return err
		}
	}
	for i := range j.Deployment.Canary {
		if err := validateStep(fmt.Sprintf("%s deployment.canary", id), i, &j.Deployment.Canary[i], map[string]bool{}); err != nil {
			return err
		}
	}
	for i := range j.Deployment.Verify {
		if err := validateStep(fmt.Sprintf("%s deployment.verify", id), i, &j.Deployment.Verify[i], map[string]bool{}); err != nil {
			return err
		}
	}
	for i := range j.Deployment.Rollback {
		if err := validateStep(fmt.Sprintf("%s deployment.rollback", id), i, &j.Deployment.Rollback[i], map[string]bool{}); err != nil {
			return err
		}
	}
	for i := range j.Cache {
		if err := checkRelPath(fmt.Sprintf("job %q cache %d", id, i), j.Cache[i].Paths...); err != nil {
			return err
		}
		if err := checkRelPath(fmt.Sprintf("job %q cache %d hash_files", id, i), j.Cache[i].HashFiles...); err != nil {
			return err
		}
		for _, v := range append(append([]string{}, j.Cache[i].Paths...), j.Cache[i].HashFiles...) {
			if err := checkInterpolation(v, fmt.Sprintf("job %q cache", id)); err != nil {
				return err
			}
		}
		for _, v := range append([]string{j.Cache[i].Name, j.Cache[i].Key}, j.Cache[i].RestoreKeys...) {
			if err := checkInterpolation(v, fmt.Sprintf("job %q cache", id)); err != nil {
				return err
			}
		}
	}
	seenArtifacts := map[string]bool{}
	for i := range j.Artifacts {
		a := &j.Artifacts[i]
		if strings.TrimSpace(a.Name) == "" {
			return fmt.Errorf("job %q artifact %d has empty name", id, i+1)
		}
		if seenArtifacts[a.Name] {
			return fmt.Errorf("job %q declares artifact %q more than once", id, a.Name)
		}
		seenArtifacts[a.Name] = true
		if err := checkRelPath(fmt.Sprintf("job %q artifact %q", id, a.Name), a.Paths...); err != nil {
			return err
		}
		if err := checkInterpolation(a.Name, fmt.Sprintf("job %q artifact name", id)); err != nil {
			return err
		}
		if err := checkInterpolation(a.If, fmt.Sprintf("job %q artifact %q if", id, a.Name)); err != nil {
			return err
		}
		for _, p := range a.Paths {
			if err := checkInterpolation(p, fmt.Sprintf("job %q artifact %q paths", id, a.Name)); err != nil {
				return err
			}
		}
		if r := strings.TrimSpace(a.Retention); r != "" {
			d, err := ParseRetention(r)
			if err != nil {
				return fmt.Errorf("job %q artifact %q has invalid retention %q: %w", id, a.Name, a.Retention, err)
			}
			if d == 0 {
				return fmt.Errorf("job %q artifact %q retention must be positive or \"forever\"", id, a.Name)
			}
		}
		switch a.SBOM {
		case "", "spdx-json", "cyclonedx-json":
		default:
			return fmt.Errorf("job %q artifact %q has invalid sbom format %q (want spdx-json or cyclonedx-json)", id, a.Name, a.SBOM)
		}
		if a.Sigstore != nil && a.Sigstore.Required && (strings.TrimSpace(a.Sigstore.Issuer) == "" || strings.TrimSpace(a.Sigstore.Identity) == "") {
			return fmt.Errorf("job %q artifact %q: sigstore.required demands both issuer and identity", id, a.Name)
		}
	}
	for i := range j.Downloads {
		d := &j.Downloads[i]
		if _, ok := s.Jobs[d.From]; !ok {
			return fmt.Errorf("job %q downloads from unknown job %q", id, d.From)
		}
		if d.From != id && !contains(j.Needs, d.From) {
			return fmt.Errorf("job %q downloads from %q which is not a declared dependency", id, d.From)
		}
		if err := checkRelPath(fmt.Sprintf("job %q downloads from %q", id, d.From), d.Path); err != nil {
			return err
		}
		if err := checkInterpolation(d.Name, fmt.Sprintf("job %q download name", id)); err != nil {
			return err
		}
		if err := checkInterpolation(d.Path, fmt.Sprintf("job %q download path", id)); err != nil {
			return err
		}
	}
	for _, p := range j.TestReports {
		if err := checkInterpolation(p, fmt.Sprintf("job %q test_reports", id)); err != nil {
			return err
		}
	}
	for _, p := range j.Environment.Branches {
		if err := checkInterpolation(p, fmt.Sprintf("job %q environment.branches", id)); err != nil {
			return err
		}
	}
	if j.Generate.Path != "" {
		if err := checkRelPath(fmt.Sprintf("job %q generate.path", id), j.Generate.Path); err != nil {
			return err
		}
		if err := checkInterpolation(j.Generate.Path, fmt.Sprintf("job %q generate.path", id)); err != nil {
			return err
		}
	}
	if j.Generate.MaxJobs < 0 || j.Generate.MaxDepth < 0 {
		return fmt.Errorf("job %q generate limits must not be negative", id)
	}
	if err := checkInterpolation(j.Downstream.Repository, fmt.Sprintf("job %q downstream.repository", id)); err != nil {
		return err
	}
	if err := checkInterpolation(j.Downstream.Ref, fmt.Sprintf("job %q downstream.ref", id)); err != nil {
		return err
	}
	if err := checkInterpolation(j.Downstream.Event, fmt.Sprintf("job %q downstream.event", id)); err != nil {
		return err
	}
	for k, v := range j.Downstream.Inputs {
		if err := checkInterpolation(v, fmt.Sprintf("job %q downstream.inputs.%s", id, k)); err != nil {
			return err
		}
	}
	if j.Tests.Shards < 0 || j.Tests.RetryFailed < 0 {
		return fmt.Errorf("job %q tests shards/retry_failed must not be negative", id)
	}
	if j.Tests.Shards > 0 {
		if _, reserved := j.Matrix["test_shard"]; reserved {
			return fmt.Errorf("job %q matrix dimension %q is reserved for tests.shards", id, "test_shard")
		}
	}
	if err := checkRelPath(fmt.Sprintf("job %q tests.manifest", id), j.Tests.Manifest); err != nil {
		return err
	}
	for name, pkg := range s.Packages {
		if err := checkRelPath(fmt.Sprintf("package %q", name), pkg.Paths...); err != nil {
			return err
		}
	}
	return nil
}

func validateService(jobID string, svc *Service) error {
	if strings.TrimSpace(svc.Name) == "" {
		return fmt.Errorf("job %q service has empty name", jobID)
	}
	if !envNameRegexp.MatchString(svc.Name) {
		return fmt.Errorf("job %q has invalid service alias %q", jobID, svc.Name)
	}
	if strings.TrimSpace(svc.Image) == "" {
		return fmt.Errorf("job %q service %q has empty image", jobID, svc.Name)
	}
	if err := validateDuration(svc.Interval, fmt.Sprintf("job %q service %q interval", jobID, svc.Name)); err != nil {
		return err
	}
	if err := validateDuration(svc.Timeout, fmt.Sprintf("job %q service %q timeout", jobID, svc.Name)); err != nil {
		return err
	}
	if svc.Retries < 0 {
		return fmt.Errorf("job %q service %q has negative retries", jobID, svc.Name)
	}
	for k, v := range svc.Env {
		if len(v) > maxEnvValueBytes {
			return fmt.Errorf("job %q service %q env var %q exceeds %d byte limit", jobID, svc.Name, k, maxEnvValueBytes)
		}
		if err := checkInterpolation(v, fmt.Sprintf("job %q service %q env %q", jobID, svc.Name, k)); err != nil {
			return err
		}
	}
	for _, v := range []string{svc.Image, svc.Healthcheck} {
		if err := checkInterpolation(v, fmt.Sprintf("job %q service %q", jobID, svc.Name)); err != nil {
			return err
		}
	}
	return nil
}

func validateStep(jobID string, idx int, st *Step, seenIDs map[string]bool) error {
	where := fmt.Sprintf("job %q step %d", jobID, idx+1)
	if st.ID != "" {
		if !idRegexp.MatchString(st.ID) {
			return fmt.Errorf("%s has invalid id %q", where, st.ID)
		}
		if seenIDs[st.ID] {
			return fmt.Errorf("job %q has duplicate step id %q", jobID, st.ID)
		}
		seenIDs[st.ID] = true
	}
	if strings.TrimSpace(st.Run) == "" {
		return fmt.Errorf("%s has empty run command", where)
	}
	if !shellNames[st.Shell] {
		return fmt.Errorf("%s has unsupported shell %q", where, st.Shell)
	}
	if err := validateDuration(st.Timeout, where+" timeout"); err != nil {
		return err
	}
	if err := validateRetry(st.Retry, where+" retry"); err != nil {
		return err
	}
	if st.WorkingDirectory != "" {
		if err := checkRelPath(where+" working_directory", st.WorkingDirectory); err != nil {
			return err
		}
	}
	seenSecrets := map[string]bool{}
	for _, name := range st.Secrets {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("%s has empty secret name", where)
		}
		if !secretNameRegexp.MatchString(name) {
			return fmt.Errorf("%s has invalid secret name %q (must match %s)", where, name, secretNameRegexp.String())
		}
		if seenSecrets[name] {
			return fmt.Errorf("%s lists secret %q more than once", where, name)
		}
		seenSecrets[name] = true
	}
	for k, v := range st.Env {
		if len(v) > maxEnvValueBytes {
			return fmt.Errorf("%s env var %q exceeds %d byte limit", where, k, maxEnvValueBytes)
		}
		if err := checkInterpolation(v, where+" env "+k); err != nil {
			return err
		}
	}
	for _, v := range []string{st.Name, st.Run, st.If, st.Shell, st.WorkingDirectory} {
		if err := checkInterpolation(v, where); err != nil {
			return err
		}
	}
	return nil
}

func validateMatrix(where string, m map[string][]any) error {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	projected := map[string]string{}
	for _, dim := range names {
		if !matrixNameRegexp.MatchString(dim) {
			return fmt.Errorf("%s matrix dimension %q is invalid (must match %s)", where, dim, matrixNameRegexp.String())
		}
		proj := ProjectInputName(dim)
		if prev, dup := projected[proj]; dup {
			return fmt.Errorf("%s matrix dimensions %q and %q both project to KIWI_MATRIX_%s", where, prev, dim, proj)
		}
		projected[proj] = dim
		vals := m[dim]
		if len(vals) == 0 {
			return fmt.Errorf("matrix dimension %q has no values", dim)
		}
		for _, v := range vals {
			switch v.(type) {
			case string, bool, int, int64, uint64, float64:
			default:
				return fmt.Errorf("%s matrix dimension %q has non-scalar value (only strings, numbers and booleans are allowed)", where, dim)
			}
		}
	}
	return nil
}

func validateDuration(d Duration, where string) error {
	if d.Set && d.Duration <= 0 {
		return fmt.Errorf("%s must be a positive duration", where)
	}
	if !d.Set && d.Duration < 0 {
		return fmt.Errorf("%s must be a positive duration", where)
	}
	return nil
}

// validateInputs enforces the input identifier grammar and the env
// projection contract: no two declared inputs may project to the same
// KIWI_INPUT_<NAME> environment variable under the canonical projection
// (pipeline.ProjectInputName). CompileWithInputs and the server's
// enqueue-time injection use the same projection, so a colliding spec
// would otherwise silently shadow an input value.
func validateInputs(s *Spec) error {
	names := make([]string, 0, len(s.Inputs))
	for name := range s.Inputs {
		names = append(names, name)
	}
	sort.Strings(names)
	return checkInputNames(names)
}

// checkInputNames validates each input name against the identifier grammar
// and rejects name sets that collide under the canonical env projection.
// Both declared inputs (Validate) and provided inputs (CompileWithInputs)
// go through this check.
func checkInputNames(names []string) error {
	seen := map[string]string{}
	for _, name := range names {
		if !inputNameRegexp.MatchString(name) {
			return fmt.Errorf("input name %q is invalid (must match %s)", name, inputNameRegexp.String())
		}
		proj := ProjectInputName(name)
		if prev, dup := seen[proj]; dup {
			return fmt.Errorf("inputs %q and %q both project to KIWI_INPUT_%s", prev, name, proj)
		}
		seen[proj] = name
	}
	return nil
}

func validateRetry(r Retry, where string) error {
	if r.Max < 0 {
		return fmt.Errorf("%s max must not be negative", where)
	}
	if r.Backoff.Set && r.Backoff.Duration <= 0 {
		return fmt.Errorf("%s backoff must be a positive duration", where)
	}
	for _, class := range r.On {
		if !retryClasses[strings.ToLower(strings.TrimSpace(class))] {
			return fmt.Errorf("%s has invalid retry class %q (want one of any, artifact, cache, command, failure, infra, timeout)", where, class)
		}
	}
	return nil
}

// IsPortableAbsPath reports whether p is absolute on ANY supported platform
// (POSIX root, Windows drive designator, or UNC/backslash root), so callers
// reject platform-dependent absolute paths regardless of the host OS.
func IsPortableAbsPath(p string) bool { return portableAbsPath(p) }

// portableAbsPath reports whether p is absolute on ANY supported platform:
// a POSIX root, a Windows drive designator (C:...), or a UNC/backslash
// root. Pipelines are portable artifacts, so a path that is absolute on a
// Windows runner must be rejected even while validating on unix.
func portableAbsPath(p string) bool {
	if filepath.IsAbs(p) {
		return true
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") {
		return true
	}
	if len(p) >= 2 && p[1] == ':' {
		c := p[0]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

// checkRelPath rejects absolute paths (on every platform) and any ".."
// component.
func checkRelPath(where string, paths ...string) error {
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if portableAbsPath(p) {
			return fmt.Errorf("%s: absolute path %q is not allowed", where, p)
		}
		for _, part := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
			if part == ".." {
				return fmt.Errorf("%s: path %q contains a .. component", where, p)
			}
		}
	}
	return nil
}

// checkInterpolation rejects unterminated ${{ ... }} expressions and unknown
// interpolation contexts. matrix/needs/steps are resolved by the compiler and
// executor; ref/event/sha by the server concurrency expansion; the remaining
// contexts are reserved for future or policy-managed use.
func checkInterpolation(s, where string) error {
	rest := s
	for {
		i := strings.Index(rest, "${{")
		if i < 0 {
			return nil
		}
		expr := rest[i+3:]
		j := strings.Index(expr, "}}")
		if j < 0 {
			return fmt.Errorf("unresolved interpolation in %s: missing closing }}", where)
		}
		body := strings.TrimSpace(expr[:j])
		if body == "" {
			return fmt.Errorf("empty interpolation in %s", where)
		}
		prefix := body
		if k := strings.IndexAny(prefix, " ."); k >= 0 {
			prefix = prefix[:k]
		}
		if !interpContexts[prefix] {
			return fmt.Errorf("unknown interpolation context %q in %s", prefix, where)
		}
		rest = expr[j+2:]
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func findCycle(jobs map[string]Job) []string {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	state := map[string]int{}
	stack := []string{}
	var visit func(string) []string
	visit = func(n string) []string {
		state[n] = gray
		stack = append(stack, n)
		for _, d := range jobs[n].Needs {
			if state[d] == gray {
				pos := 0
				for i, v := range stack {
					if v == d {
						pos = i
						break
					}
				}
				return append(append([]string{}, stack[pos:]...), d)
			}
			if state[d] == white {
				if c := visit(d); len(c) > 0 {
					return c
				}
			}
		}
		stack = stack[:len(stack)-1]
		state[n] = black
		return nil
	}
	keys := make([]string, 0, len(jobs))
	for k := range jobs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if state[k] == white {
			if c := visit(k); len(c) > 0 {
				return c
			}
		}
	}
	return nil
}
