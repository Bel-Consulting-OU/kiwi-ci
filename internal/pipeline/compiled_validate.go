package pipeline

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Hard ceilings for per-job resource requests. Requests within these
// ranges are admitted (negative/NaN values are rejected outright);
// backends that cannot honor a request reject it through the
// ResourceCapabilities check.
const (
	maxCPURequest    = 256.0
	maxMemoryRequest = 16 << 40 // 16 TiB
	maxDiskRequest   = 1 << 50  // 1 PiB
	maxPIDsRequest   = 1_000_000
	// maxMatrixSuffixBytes caps the raw rendered matrix ID suffix; longer
	// suffixes collapse to a SHA-256 prefix.
	maxMatrixSuffixBytes = 128
)

var (
	// matrixNameRegexp pins the matrix dimension identifier grammar: a
	// leading ASCII letter or underscore followed by up to 63 letters,
	// digits, underscores or hyphens. Matrix names feed compiled-job IDs
	// and the KIWI_MATRIX_<NAME> environment projection, so the grammar
	// must exclude the encoding marker and path separators.
	matrixNameRegexp = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)
	// compiledIDRegexp validates a fully compiled job ID: the base job ID
	// followed by an optional canonical matrix suffix. The suffix admits
	// literal values ([A-Za-z0-9._-]), the base64url escape marker "~", the
	// hash-fallback form "[~<hex>]", and the "=" / "," separators. Job IDs
	// never contain "[" so the suffix is unambiguous.
	compiledIDRegexp = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}(\[[A-Za-z0-9._~,=-]{0,128}\])?$`)
)

// ResourceCapabilities documents, per runtime, which resource requests the
// backend can actually enforce. The container backend enforces cpu, memory
// and pid limits (its disk request is advisory and produces no cgroup/docker
// limit); the tart backend enforces cpu and memory (disk is advisory and
// pid limits are unsupported); the native runtime (and any unknown runtime)
// is not container-isolated at all, so every declaration there is advisory
// and admission rejects it. validateResources uses this map to refuse
// declarations a backend cannot honor instead of silently accepting no-ops.
func ResourceCapabilities(runtime string) (cpu, memory, disk, pids bool) {
	switch runtime {
	case "container":
		return true, true, false, true
	case "tart":
		return true, true, false, false
	default:
		return false, false, false, false
	}
}

// ValidateCompiledJob performs full post-interpolation validation on one
// effective compiled job: the compiled ID encoding, step-count and
// deployment-phase caps, per-step env and command byte caps, path safety on
// every workspace-relative path AFTER interpolation, step/service
// identifiers and unique service aliases, runtime/image/VM rules, artifact
// and download declarations, output identifiers, resource ranges and
// backend capability admission, placement regexes and the sandbox enum.
// Compile and CompileWithInputs call it for every compiled job after shard
// expansion; the server's enqueue re-validation runs it through the same
// compile pass after component merge.
func ValidateCompiledJob(cj CompiledJob) error {
	where := fmt.Sprintf("compiled job %q", cj.ID)
	if !compiledIDRegexp.MatchString(cj.ID) {
		return fmt.Errorf("compiled job id %q is invalid (must match %s)", cj.ID, compiledIDRegexp.String())
	}
	if !idRegexp.MatchString(cj.BaseID) {
		return fmt.Errorf("compiled job %q has invalid base id %q", cj.ID, cj.BaseID)
	}
	j := cj.Job
	switch j.Runtime {
	case "", "native", "container", "tart":
	default:
		return fmt.Errorf("%s has unsupported runtime %q", where, j.Runtime)
	}
	switch {
	case (j.Runtime == "" || j.Runtime == "native") && (j.Image != "" || j.VM != ""):
		return fmt.Errorf("%s: native runtime must not set image or vm", where)
	case j.Runtime == "tart" && j.VM == "":
		return fmt.Errorf("%s: tart runtime requires a vm", where)
	}
	if !networkModes[j.Network] {
		return fmt.Errorf("%s has unsupported network %q (want one of bridge, host, none)", where, j.Network)
	}
	if j.Sandbox.Network < NetworkPolicyDefault || j.Sandbox.Network > NetworkPolicyInternet {
		return fmt.Errorf("%s has invalid sandbox.network value %d", where, j.Sandbox.Network)
	}
	if !shellNames[j.Shell] {
		return fmt.Errorf("%s has unsupported shell %q", where, j.Shell)
	}
	if err := validateDuration(j.Timeout, where+" timeout"); err != nil {
		return err
	}
	if err := validateDuration(j.QueueTimeout, where+" queue_timeout"); err != nil {
		return err
	}
	if err := validateRetry(j.Retry, where+" retry"); err != nil {
		return err
	}
	if j.InfraRetries < 0 {
		return fmt.Errorf("%s has negative infra_retries", where)
	}
	if j.Environment.Name != "" && !envNameRegexp.MatchString(j.Environment.Name) {
		return fmt.Errorf("%s has invalid environment name %q", where, j.Environment.Name)
	}
	if j.Environment.Concurrency < 0 {
		return fmt.Errorf("%s environment concurrency must not be negative", where)
	}
	for _, label := range j.Runner {
		if !labelRegexp.MatchString(label) {
			return fmt.Errorf("%s has invalid runner label %q", where, label)
		}
	}
	for _, region := range j.Placement.Regions {
		if !envNameRegexp.MatchString(region) {
			return fmt.Errorf("%s has invalid placement region %q", where, region)
		}
	}
	for _, label := range j.Placement.Labels {
		if !labelRegexp.MatchString(label) {
			return fmt.Errorf("%s has invalid placement label %q", where, label)
		}
	}
	if len(j.Env) > maxEnvVarsPerJob {
		return fmt.Errorf("%s declares %d env vars, limit is %d", where, len(j.Env), maxEnvVarsPerJob)
	}
	for name, v := range j.Env {
		if len(v) > maxEnvValueBytes {
			return fmt.Errorf("%s env var %q exceeds %d byte limit", where, name, maxEnvValueBytes)
		}
	}
	for key := range j.Outputs {
		if !idRegexp.MatchString(key) {
			return fmt.Errorf("%s has invalid output identifier %q", where, key)
		}
	}
	if err := validateResources(where, j.Runtime, j.Resources); err != nil {
		return err
	}
	seenAliases := map[string]string{}
	for i := range j.Services {
		svc := &j.Services[i]
		if strings.TrimSpace(svc.Name) == "" {
			return fmt.Errorf("%s service %d has empty name", where, i+1)
		}
		if !envNameRegexp.MatchString(svc.Name) {
			return fmt.Errorf("%s has invalid service alias %q", where, svc.Name)
		}
		// Duplicate detection is canonical, exactly like the raw admission
		// validator: docker network aliases resolve case-insensitively, so
		// "Redis" and "redis" are one runtime DNS name and must be rejected
		// together (CanonicalServiceAlias is the same function the executor
		// attaches aliases with).
		canon := CanonicalServiceAlias(svc.Name)
		if prev, dup := seenAliases[canon]; dup {
			if prev == svc.Name {
				return fmt.Errorf("%s declares service alias %q more than once", where, svc.Name)
			}
			return fmt.Errorf("%s declares service aliases %q and %q that both resolve to %q", where, prev, svc.Name, canon)
		}
		seenAliases[canon] = svc.Name
		if strings.TrimSpace(svc.Image) == "" {
			return fmt.Errorf("%s service %q has empty image", where, svc.Name)
		}
		if err := validateDuration(svc.Interval, where+" service "+svc.Name+" interval"); err != nil {
			return err
		}
		if err := validateDuration(svc.Timeout, where+" service "+svc.Name+" timeout"); err != nil {
			return err
		}
		if svc.Retries < 0 {
			return fmt.Errorf("%s service %q has negative retries", where, svc.Name)
		}
		for k, v := range svc.Env {
			if len(v) > maxEnvValueBytes {
				return fmt.Errorf("%s service %q env var %q exceeds %d byte limit", where, svc.Name, k, maxEnvValueBytes)
			}
		}
	}
	totalSteps := len(j.Steps) + len(j.Deployment.Canary) + len(j.Deployment.Verify) + len(j.Deployment.Rollback)
	if totalSteps > maxStepsPerJob {
		return fmt.Errorf("%s declares %d steps across steps and deployment phases, limit is %d", where, totalSteps, maxStepsPerJob)
	}
	seenIDs := map[string]bool{}
	for i := range j.Steps {
		if err := validateCompiledStep(where, "step", i+1, &j.Steps[i], seenIDs); err != nil {
			return err
		}
	}
	for i := range j.Deployment.Canary {
		if err := validateCompiledStep(where, "deployment.canary", i+1, &j.Deployment.Canary[i], map[string]bool{}); err != nil {
			return err
		}
	}
	for i := range j.Deployment.Verify {
		if err := validateCompiledStep(where, "deployment.verify", i+1, &j.Deployment.Verify[i], map[string]bool{}); err != nil {
			return err
		}
	}
	for i := range j.Deployment.Rollback {
		if err := validateCompiledStep(where, "deployment.rollback", i+1, &j.Deployment.Rollback[i], map[string]bool{}); err != nil {
			return err
		}
	}
	for i := range j.Cache {
		if err := checkRelPath(fmt.Sprintf("%s cache %d", where, i), j.Cache[i].Paths...); err != nil {
			return err
		}
		if err := checkRelPath(fmt.Sprintf("%s cache %d hash_files", where, i), j.Cache[i].HashFiles...); err != nil {
			return err
		}
	}
	seenArtifacts := map[string]bool{}
	for i := range j.Artifacts {
		a := &j.Artifacts[i]
		if strings.TrimSpace(a.Name) == "" {
			return fmt.Errorf("%s artifact %d has empty name", where, i+1)
		}
		if seenArtifacts[a.Name] {
			return fmt.Errorf("%s declares artifact %q more than once", where, a.Name)
		}
		seenArtifacts[a.Name] = true
		if err := checkRelPath(fmt.Sprintf("%s artifact %q", where, a.Name), a.Paths...); err != nil {
			return err
		}
		if r := strings.TrimSpace(a.Retention); r != "" {
			d, err := ParseRetention(r)
			if err != nil {
				return fmt.Errorf("%s artifact %q has invalid retention %q: %w", where, a.Name, a.Retention, err)
			}
			if d == 0 {
				return fmt.Errorf("%s artifact %q retention must be positive or \"forever\"", where, a.Name)
			}
		}
		switch a.SBOM {
		case "", "spdx-json", "cyclonedx-json":
		default:
			return fmt.Errorf("%s artifact %q has invalid sbom format %q (want spdx-json or cyclonedx-json)", where, a.Name, a.SBOM)
		}
		if a.Sigstore != nil && a.Sigstore.Required && (strings.TrimSpace(a.Sigstore.Issuer) == "" || strings.TrimSpace(a.Sigstore.Identity) == "") {
			return fmt.Errorf("%s artifact %q: sigstore.required demands both issuer and identity", where, a.Name)
		}
	}
	for i := range j.Downloads {
		d := &j.Downloads[i]
		if strings.TrimSpace(d.From) == "" {
			return fmt.Errorf("%s download %d has empty from job", where, i+1)
		}
		if strings.TrimSpace(d.Name) == "" {
			return fmt.Errorf("%s download %d has empty name", where, i+1)
		}
		if err := checkRelPath(fmt.Sprintf("%s downloads from %q", where, d.From), d.Path); err != nil {
			return err
		}
	}
	if err := checkRelPath(where+" tests.manifest", j.Tests.Manifest); err != nil {
		return err
	}
	if j.Generate.Path != "" {
		if err := checkRelPath(where+" generate.path", j.Generate.Path); err != nil {
			return err
		}
	}
	return nil
}

// validateCompiledStep validates one effective step (or deployment-phase
// step) after interpolation: ID grammar and uniqueness, command presence
// and byte cap, shell enum, duration/retry policy, working-directory path
// safety and per-step env caps.
func validateCompiledStep(jobWhere, phase string, idx int, st *Step, seenIDs map[string]bool) error {
	where := fmt.Sprintf("%s %s %d", jobWhere, phase, idx)
	if st.ID != "" {
		if !idRegexp.MatchString(st.ID) {
			return fmt.Errorf("%s has invalid id %q", where, st.ID)
		}
		if seenIDs[st.ID] {
			return fmt.Errorf("%s has duplicate step id %q", jobWhere, st.ID)
		}
		seenIDs[st.ID] = true
	}
	if strings.TrimSpace(st.Run) == "" {
		return fmt.Errorf("%s has empty run command", where)
	}
	if len(st.Run) > maxCommandBytes {
		return fmt.Errorf("%s command exceeds %d byte limit", where, maxCommandBytes)
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
	if len(st.Env) > maxEnvVarsPerJob {
		return fmt.Errorf("%s declares %d env vars, limit is %d", where, len(st.Env), maxEnvVarsPerJob)
	}
	for k, v := range st.Env {
		if len(v) > maxEnvValueBytes {
			return fmt.Errorf("%s env var %q exceeds %d byte limit", where, k, maxEnvValueBytes)
		}
	}
	for _, name := range st.Secrets {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("%s has empty secret name", where)
		}
	}
	return nil
}

// validateResources enforces the resource request ranges and the backend
// capability admission for the given runtime: negative or NaN values are
// rejected, requests beyond the hard ceilings are rejected, and
// declarations a backend cannot honor are rejected outright — the native
// runtime accepts no resource request at all (host-side, not
// container-isolated), tart rejects disk and pid requests, and container
// accepts all four (cpu/memory/pids enforced; its disk request stays
// advisory, matching ResourceCapabilities).
func validateResources(where, runtime string, r Resources) error {
	if math.IsNaN(r.CPU) || math.IsInf(r.CPU, 0) {
		return fmt.Errorf("%s resources.cpu must be a finite number", where)
	}
	if r.CPU < 0 {
		return fmt.Errorf("%s resources.cpu must not be negative", where)
	}
	if r.CPU > maxCPURequest {
		return fmt.Errorf("%s resources.cpu %v exceeds the limit of %v", where, r.CPU, maxCPURequest)
	}
	if r.Memory < 0 {
		return fmt.Errorf("%s resources.memory must not be negative", where)
	}
	if r.Memory > maxMemoryRequest {
		return fmt.Errorf("%s resources.memory %d exceeds the limit of %d", where, r.Memory, maxMemoryRequest)
	}
	if r.Disk < 0 {
		return fmt.Errorf("%s resources.disk must not be negative", where)
	}
	if r.Disk > maxDiskRequest {
		return fmt.Errorf("%s resources.disk %d exceeds the limit of %d", where, r.Disk, maxDiskRequest)
	}
	if r.PIDs < 0 {
		return fmt.Errorf("%s resources.pids must not be negative", where)
	}
	if r.PIDs > maxPIDsRequest {
		return fmt.Errorf("%s resources.pids %d exceeds the limit of %d", where, r.PIDs, maxPIDsRequest)
	}
	switch {
	case runtime == "" || runtime == "native":
		if r.CPU > 0 || r.Memory > 0 || r.Disk > 0 || r.PIDs > 0 {
			return fmt.Errorf("%s: native backend does not enforce resource requests", where)
		}
	case runtime == "tart":
		if r.Disk > 0 {
			return fmt.Errorf("%s: tart backend does not honor disk limits", where)
		}
		if r.PIDs > 0 {
			return fmt.Errorf("%s: tart backend does not honor pid limits", where)
		}
	}
	return nil
}
