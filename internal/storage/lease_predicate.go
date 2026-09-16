package storage

import (
	"encoding/json"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

// LeasePredicate is the single scheduling decision shared by every lease
// path: the PostgresStore claim, the in-memory stores, the DB scheduler's
// candidate pre-filter and the server's dev-mode next(). Keeping one
// predicate in one place is what makes memory and SQL lease decisions
// identical (the parity table tests pin the agreement).
//
// Runner carries the EFFECTIVE scheduling attributes: the caller resolves
// the live profile (see ResolveRunnerProfile) before building the predicate.
// EnvRunning is the number of OTHER running jobs holding the same
// (repository, environment) key.
type LeasePredicate struct {
	Runner         model.Runner
	Job            model.Job
	EnvRunning     int
	PolicyEnforced bool
	PolicyRuntimes []string
}

// Allows reports whether the runner may be leased the job under every
// scheduling predicate:
//
//   - admission state: disabled/draining runners take no work, capacity 0
//     means "take no work", and a full active set is at capacity;
//   - labels: every required label is declared;
//   - repository ACL: the canonical repo ID (or bare full name) is in the
//     runner's allowlist (empty = unrestricted);
//   - runtime capability: the job's runtime is declared (empty declared
//     list = vacuous);
//   - enforced policy runtime grant: when the job's effective policy is
//     Enforced and grants no runtime at all, no runner can take it; when it
//     grants a set, the job's runtime must be in it;
//   - placement regions: a region-constrained job only matches a runner
//     whose region is in the set (a regionless runner can never satisfy
//     one);
//   - environment concurrency: the candidate's (repo, environment) key must
//     still have a free slot.
func (p LeasePredicate) Allows() bool {
	r := p.Runner
	j := p.Job
	if r.Disabled || r.Draining {
		return false
	}
	if r.Capacity <= 0 || len(r.ActiveJobs) >= r.Capacity {
		return false
	}
	if !labelsSatisfy(r.Labels, j.RequiredLabels) {
		return false
	}
	if !RepoAllowed(r.AllowedRepositories, j.RepoURL, j.RepoFullName) {
		return false
	}
	runtime := JobRuntime(j)
	if !RuntimeAllowed(r.Capabilities, runtime) {
		return false
	}
	if !PolicyRuntimeAllowed(p.PolicyEnforced, p.PolicyRuntimes, runtime) {
		return false
	}
	if len(j.PlacementRegions) > 0 && !containsString(j.PlacementRegions, r.Region) {
		return false
	}
	if j.Environment != "" && j.EnvironmentConcurrency > 0 && p.EnvRunning >= j.EnvironmentConcurrency {
		return false
	}
	return true
}

// ResolveRunnerProfile overlays a linked profile's live scheduling
// attributes onto the runner's registration snapshot. linked=false (or a
// zero profile) returns the runner unchanged, so unlinked runners keep their
// registration attributes.
func ResolveRunnerProfile(r model.Runner, profile model.RunnerProfile, linked bool) model.Runner {
	if !linked {
		return r
	}
	r.Labels = append([]string(nil), profile.Labels...)
	r.Region = profile.Region
	r.AllowedRepositories = append([]string(nil), profile.Repositories...)
	r.Capabilities = append([]string(nil), profile.Capabilities...)
	r.Capacity = profile.MaxCapacity
	r.CostPerHour = profile.CostPerHour
	r.PowerWatts = profile.PowerWatts
	return r
}

// RepoAllowed reports whether the canonical repository (or its bare full
// name) is inside the allowlist. An empty allowlist imposes no restriction.
func RepoAllowed(allowed []string, repoURL, repoFullName string) bool {
	if len(allowed) == 0 {
		return true
	}
	canon := CanonicalRepoID(RepoHost(repoURL), repoFullName)
	for _, a := range allowed {
		if a == canon || (repoFullName != "" && a == repoFullName) {
			return true
		}
	}
	return false
}

// RuntimeAllowed reports whether the runtime is declared by the capability
// list. An empty declared list makes the check vacuous; an empty runtime
// cannot be constrained.
func RuntimeAllowed(capabilities []string, runtime string) bool {
	if len(capabilities) == 0 || runtime == "" {
		return true
	}
	return containsString(capabilities, runtime)
}

// PolicyRuntimeAllowed enforces an ENFORCED effective policy's runtime
// grant: an enforced policy that grants no runtime denies every runtime
// (fail closed); an enforced policy that grants a set only allows those
// runtimes for the job's runtime. A non-enforced policy imposes no
// restriction (legacy payloads).
func PolicyRuntimeAllowed(enforced bool, runtimes []string, jobRuntime string) bool {
	if !enforced {
		return true
	}
	if len(runtimes) == 0 {
		return false
	}
	if jobRuntime == "" {
		return true
	}
	return containsString(runtimes, jobRuntime)
}

// LeasePolicyRuntimes extracts the effective policy's runtime grant from a
// job's compiled payload. enforced reports whether the payload declares an
// ENFORCED capability set (see policy.Capabilities.Enforced); runtimes is
// the granted runtime set (empty means "no runtime granted"). Jobs without
// an effective policy are not enforced.
func LeasePolicyRuntimes(j model.Job) (runtimes []string, enforced bool) {
	if j.CompiledJobPayload == nil || j.CompiledJobPayload.EffectivePolicy == nil {
		return nil, false
	}
	var b []byte
	switch v := j.CompiledJobPayload.EffectivePolicy.(type) {
	case json.RawMessage:
		b = v
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		var err error
		if b, err = json.Marshal(v); err != nil {
			return nil, false
		}
	}
	var caps policy.Capabilities
	if err := json.Unmarshal(b, &caps); err != nil {
		return nil, false
	}
	if !capabilityEnforced(caps) {
		return nil, false
	}
	runtimes = make([]string, 0, 3)
	if caps.NativeExecution {
		runtimes = append(runtimes, "native")
	}
	if caps.Container {
		runtimes = append(runtimes, "container")
	}
	if caps.Tart {
		runtimes = append(runtimes, "tart")
	}
	return runtimes, true
}

// JobRuntime extracts the job's runtime capability
// (container/tart/native) from the persisted compiled payload. Jobs without
// a compiled payload (or with an unknown runtime) yield "".
func JobRuntime(j model.Job) string {
	if j.CompiledJobPayload == nil || j.CompiledJobPayload.EffectiveJob == nil {
		return ""
	}
	var b []byte
	switch v := j.CompiledJobPayload.EffectiveJob.(type) {
	case json.RawMessage:
		b = v
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		var err error
		if b, err = json.Marshal(v); err != nil {
			return ""
		}
	}
	var cj pipeline.CompiledJob
	if err := json.Unmarshal(b, &cj); err != nil {
		return ""
	}
	switch cj.Job.Runtime {
	case "container", "tart", "native":
		return cj.Job.Runtime
	default:
		return ""
	}
}

// RepoHost extracts the forge host from a repository URL in the common forms
// (https://host/owner/repo, ssh://git@host/owner/repo and the scp-like
// git@host:owner/repo), mirroring the server's host derivation so canonical
// repo IDs agree across packages.
func RepoHost(repoURL string) string {
	u := strings.TrimSpace(repoURL)
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if at := strings.Index(u, "@"); at >= 0 {
		u = u[at+1:]
	}
	slash := strings.Index(u, "/")
	colon := strings.Index(u, ":")
	switch {
	case slash < 0 && colon < 0:
		return u
	case slash < 0:
		return u[:colon]
	case colon >= 0 && colon < slash:
		return u[:colon]
	default:
		return u[:slash]
	}
}

// CanonicalRepoID is the canonical "<host>/<owner>/<name>" identity used by
// repository allowlists. It mirrors auth.CanonicalRepoID without importing
// the auth package, so storage stays independent of the server identity
// layer.
func CanonicalRepoID(host, fullName string) string {
	host = strings.TrimSpace(host)
	fullName = strings.TrimSpace(fullName)
	if fullName == "" {
		return host
	}
	if host == "" {
		return fullName
	}
	return host + "/" + fullName
}

func labelsSatisfy(have, need []string) bool {
	if len(need) == 0 {
		return true
	}
	m := map[string]bool{}
	for _, x := range have {
		m[x] = true
	}
	for _, x := range need {
		if !m[x] {
			return false
		}
	}
	return true
}

// capabilityEnforced reports whether an effective capability set declares
// that its grants are ENFORCED (as opposed to a legacy/zero-value set that
// scheduling must not interpret as deny-all). It reads the policy package's
// Enforced marker.
func capabilityEnforced(caps policy.Capabilities) bool {
	return caps.Enforced
}
