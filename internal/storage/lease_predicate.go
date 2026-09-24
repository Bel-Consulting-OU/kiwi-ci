package storage

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
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
	if !RepoAllowed(r.AllowedRepositories, j) {
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
// registration attributes. The profile's resource capacities (migration
// 0030) replace the snapshot's the same way; a zero profile dimension is
// unconstrained.
func ResolveRunnerProfile(r model.Runner, profile model.RunnerProfile, linked bool) model.Runner {
	if !linked {
		return r
	}
	r.Labels = append([]string(nil), profile.Labels...)
	r.Region = profile.Region
	r.AllowedRepositories = append([]string(nil), profile.Repositories...)
	r.Capabilities = append([]string(nil), profile.Capabilities...)
	r.Capacity = profile.MaxCapacity
	r.ResourceCapacity = model.ResourceCapacityFromProfile(profile)
	r.CostPerHour = profile.CostPerHour
	r.PowerWatts = profile.PowerWatts
	return r
}

// ClaimAllowsRunner evaluates the shared, TYPED scheduling predicates for one
// candidate claim against a runner's EFFECTIVE scheduling view. The caller
// resolves the live profile first (see ResolveRunnerProfile) for linked
// runners; for unlinked runners the registration snapshot is used unchanged.
//
// It exists so the SQL claim and the in-memory claim make the SAME decision
// for the runner-side predicates (admission state, capacity, labels,
// canonical repository ACL, runtime capability and placement regions): the
// previous SQL claim compared raw strings and skipped every predicate for an
// unlinked runner, so a cross-forge allowlist entry, an "r1:" identity spelling
// or a snapshot capability could admit a job the in-memory store denied.
//
// Environment concurrency and the enforced-policy runtime grant are NOT part
// of this helper: the SQL claim reserves the environment slot under the
// per-key advisory lock using the claim's environment fields, and the
// enforced-policy grant is applied by the scheduler prefilter and the
// in-memory predicate.
func ClaimAllowsRunner(r model.Runner, c LeaseClaim) bool {
	if r.Disabled || r.Draining {
		return false
	}
	if r.Capacity <= 0 || len(r.ActiveJobs) >= r.Capacity {
		return false
	}
	if !labelsSatisfy(r.Labels, c.RequiredLabels) {
		return false
	}
	if !RepoAllowed(r.AllowedRepositories, claimRepoIdentity(c)) {
		return false
	}
	if !RuntimeAllowed(r.Capabilities, c.Runtime) {
		return false
	}
	if len(c.PlacementRegions) > 0 && !containsString(c.PlacementRegions, r.Region) {
		return false
	}
	return true
}

// claimRepoIdentity renders a claim's repository identity as a job value so
// the ONE typed allowlist predicate (RepoAllowed) can evaluate it: the
// canonical RepoID is authoritative (RepoIDForJob precedence), with the bare
// full name as its legacy alias.
func claimRepoIdentity(c LeaseClaim) model.Job {
	return model.Job{PolicyRepoID: c.CanonRepoID, RepoFullName: c.RepoFullName}
}

// RepoAllowed reports whether the job's repository is inside the runner's
// allowlist. An empty allowlist imposes no restriction. Both sides are parsed
// into typed values with the documented positional rule
// (auth.ParseStoredRepoID): an allowlist entry is a canonical identity when
// its first segment is the host (three or more path segments, dotted OR
// dotless) and a bare alias otherwise, and a job's identity is its canonical
// repository ID (RepoIDForJob) with the bare full name as a legacy alias.
//
// Matching is deliberately narrower than byte equality on the two strings:
//
//   - a canonical entry matches the SAME canonical identity (canonically
//     equivalent host spellings included);
//   - a bare entry matches the same bare full name, and falls back to a
//     canonical job identity with that full name (a bare alias addresses
//     every forge presenting the name);
//   - a canonical entry NEVER matches a job whose identity is a different
//     forge, and never matches a bare full name by string equality. The
//     legacy "entry == RepoFullName" comparison is gone: an allowlist entry
//     for dotless host "gitlab" plus full name "acme/widget" can no longer
//     admit a job on another forge that merely presents the same nested
//     name.
//
// An entry that cannot be parsed fails closed (it matches nothing).
func RepoAllowed(allowed []string, j model.Job) bool {
	if len(allowed) == 0 {
		return true
	}
	jobGrant, err := auth.ParseStoredRepoID(RepoIDForJob(j))
	if err != nil {
		return false
	}
	for _, a := range allowed {
		entry, err := auth.ParseStoredRepoID(a)
		if err != nil {
			continue
		}
		if repoEntryMatchesJob(entry, jobGrant) {
			return true
		}
	}
	return false
}

// repoEntryMatchesJob is the typed allowlist membership test.
func repoEntryMatchesJob(entry, job auth.RepoGrant) bool {
	switch {
	case entry.IsIdentity() && job.IsIdentity():
		e, _ := entry.Identity()
		j, _ := job.Identity()
		return e.Host == j.Host && e.FullName == j.FullName
	case entry.IsIdentity():
		// A canonical entry never matches a host-less job alias: the job's
		// host is unknown, so no canonical identity is known to match.
		return false
	case job.IsIdentity():
		e, _ := entry.Alias()
		j, _ := job.Identity()
		return e.FullName == j.FullName
	default:
		e, _ := entry.Alias()
		j, _ := job.Alias()
		return e.FullName == j.FullName
	}
}

// RepoIDFor resolves the canonical repository identity from an optional
// stored RepoID plus the clone URL and full name: the stored RepoID is
// authoritative and returned verbatim when set; otherwise the identity is
// derived from the forge host of the clone URL plus the full name (itself
// recovered from the URL path when the record carries no full name, so
// URL-only legacy submissions keep a host-scoped identity). It is the ONE
// fallback derivation the scheduler, the stores and the server's repoIDFor
// helper all agree on.
func RepoIDFor(repoID, repoURL, repoFullName string) string {
	if id := strings.TrimSpace(repoID); id != "" {
		return id
	}
	fullName := strings.TrimSpace(repoFullName)
	if fullName == "" {
		fullName = RepoFullNameFromURL(repoURL)
	}
	return CanonicalRepoID(RepoHost(repoURL), fullName)
}

// RepoFullNameFromURL extracts the forge-native owner/name (or nested group
// path) from a clone URL, dropping the scheme, host, credentials and the
// ".git" suffix. It returns "" when the input names no repository path
// (empty, bare owner/name, or unparseable).
func RepoFullNameFromURL(repoURL string) string {
	u := strings.TrimSpace(repoURL)
	if i := strings.Index(u, "://"); i >= 0 {
		parsed, err := url.Parse(u)
		if err != nil || parsed.Host == "" {
			return ""
		}
		return strings.Trim(strings.TrimSuffix(parsed.Path, ".git"), "/")
	}
	// scp-like git@host:owner/name
	if at := strings.Index(u, "@"); at >= 0 {
		if colon := strings.Index(u[at:], ":"); colon >= 0 {
			return strings.Trim(strings.TrimSuffix(u[at+colon+1:], ".git"), "/")
		}
	}
	return ""
}

// RepoIDForJob resolves the canonical repository identity of a job: the
// immutable PolicyRepoID when present (the BASE repository of a fork PR,
// which every authorization/quota/cache decision uses), otherwise the stored
// RepoID, otherwise derived from RepoURL + RepoFullName (legacy records).
func RepoIDForJob(j model.Job) string {
	if id := strings.TrimSpace(j.PolicyRepoID); id != "" {
		return id
	}
	return RepoIDFor(j.RepoID, j.RepoURL, j.RepoFullName)
}

// RepoIDForRun resolves the canonical repository identity of a run with the
// same PolicyRepoID-first fallback as RepoIDForJob.
func RepoIDForRun(r model.Run) string {
	if id := strings.TrimSpace(r.PolicyRepoID); id != "" {
		return id
	}
	return RepoIDFor(r.RepoID, r.Repo, r.RepoFullName)
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

// RepoHost extracts and CANONICALIZES the forge host from a repository URL
// in the common forms (https://host/owner/repo, ssh://git@host/owner/repo
// and the scp-like git@host:owner/repo), delegating to auth.CanonicalHost so
// every package derives the same host. The host is lowercased with ONE
// trailing dot stripped and the default port of the scheme dropped (443
// https, 80 http, 22 ssh); a non-default port stays part of the identity, and
// scp-like forms never carry a port.
func RepoHost(repoURL string) string {
	return auth.CanonicalHost(repoURL)
}

// CanonicalRepoID is the canonical "<host>/<owner>/<name>" identity used by
// repository allowlists, quota counters and the SQL canonical-identity
// expressions. It delegates to auth.CanonicalRepoID — the SINGLE
// canonicalization entry point — so storage and the authorization layer can
// never drift. The forge host is canonicalized first and a full name that
// already carries a canonically equivalent spelling of that KNOWN host is
// reduced to its owner/name remainder (idempotent); a name embedding a
// DIFFERENT host keeps the authoritative host prefix, so identities stay
// host-scoped. The host is never inferred from the name: with no known host
// the trimmed full name is returned unchanged; an empty full name stays
// empty. The output string is the exact value persisted in repository IDs and
// compared by the storage SQL; the typed r1: form is the ACL spelling
// (auth.RepoIdentity.Serialized).
func CanonicalRepoID(host, fullName string) string {
	return auth.CanonicalRepoID(host, fullName)
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
