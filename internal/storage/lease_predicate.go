package storage

import (
	"encoding/json"
	"net/url"
	"strconv"
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

// RepoAllowed reports whether the job's canonical repository identity (or,
// as an explicitly configured alias, its bare full name) is inside the
// allowlist. An empty allowlist imposes no restriction. The canonical
// identity is read from the job's immutable RepoID, falling back to the
// RepoURL + RepoFullName derivation for legacy payloads.
func RepoAllowed(allowed []string, j model.Job) bool {
	if len(allowed) == 0 {
		return true
	}
	canon := RepoIDForJob(j)
	for _, a := range allowed {
		if a == canon || (j.RepoFullName != "" && a == j.RepoFullName) {
			return true
		}
	}
	return false
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
// and the scp-like git@host:owner/repo), mirroring the server's host
// derivation so canonical repo IDs agree across packages. The host is
// lowercased with ONE trailing dot stripped and the default port of the
// scheme dropped (443 https, 80 http, 22 ssh); a non-default port stays part
// of the identity, and scp-like forms never carry a port.
func RepoHost(repoURL string) string {
	return canonicalHost(repoURL)
}

// canonicalHost normalizes a forge host spelling onto ONE canonical form so
// equivalent spellings of the same forge derive the same repository identity
// and the same quota/ACL keys: lowercase, ONE trailing dot stripped,
// userinfo stripped, and the scheme's default port dropped (443 https, 80
// http, 22 ssh; with no scheme the well-known default ports 443/80/22 are
// dropped). Non-default ports stay part of the identity. It mirrors
// auth.CanonicalHost and the server's canonicalHost; the pinning tests keep
// the three implementations identical.
func canonicalHost(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		scheme := strings.ToLower(strings.TrimSpace(s[:i]))
		rest := s[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		return canonicalHostPort(scheme, rest)
	}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		rest := s[at+1:]
		if colon := scpHostColon(rest); colon >= 0 {
			tail := rest[colon+1:]
			if tail == "" || strings.Contains(tail, "/") {
				return canonicalHostPort("ssh", rest[:colon])
			}
		}
		return canonicalHostPort("", rest)
	}
	if j := strings.IndexAny(s, "/?#"); j >= 0 {
		s = s[:j]
	}
	// A bracketed IPv6 literal is host material, never the legacy
	// "host:path" spelling: its internal colons must not split it (the
	// legacy rule below would otherwise canonicalize "[::1]:8443" to the
	// bare "[" and collapse every distinct literal onto one identity key).
	// canonicalHostPort's bracket parser handles both well-formed and
	// truncated literals; a truncated one is preserved verbatim.
	if strings.HasPrefix(s, "[") {
		return canonicalHostPort("", s)
	}
	if colon := strings.Index(s, ":"); colon > 0 && !strings.Contains(s[:colon], ":") {
		if _, err := strconv.Atoi(s[colon+1:]); err != nil {
			// Legacy "host:path" spelling with no scp user and no numeric
			// port: the colon separates the host from a path, not a port.
			s = s[:colon]
		}
	}
	return canonicalHostPort("", s)
}

// scpHostColon mirrors auth.scpHostColon: the first colon AFTER a bracketed
// IPv6 literal's closing bracket, the first colon otherwise, or -1 when no
// colon separates a host from a tail.
func scpHostColon(s string) int {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return -1
		}
		if colon := strings.Index(s[end+1:], ":"); colon >= 0 {
			return end + 1 + colon
		}
		return -1
	}
	return strings.Index(s, ":")
}

// canonicalHostPort lowercases hostPort and drops its default port for
// scheme.
func canonicalHostPort(scheme, hostPort string) string {
	hostPort = strings.TrimSpace(hostPort)
	if hostPort == "" {
		return ""
	}
	if at := strings.LastIndex(hostPort, "@"); at >= 0 {
		hostPort = hostPort[at+1:]
	}
	host, port := splitCanonHostPort(hostPort)
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return ""
	}
	if port != "" && isDefaultHostPort(scheme, port) {
		port = ""
	}
	if port != "" {
		return host + ":" + port
	}
	return host
}

func splitCanonHostPort(hostPort string) (host, port string) {
	if strings.HasPrefix(hostPort, "[") {
		if end := strings.Index(hostPort, "]"); end > 0 {
			host = hostPort[1:end]
			if rest := hostPort[end+1:]; strings.HasPrefix(rest, ":") {
				port = rest[1:]
			}
			return host, port
		}
		return hostPort, ""
	}
	if colon := strings.LastIndex(hostPort, ":"); colon > 0 && !strings.Contains(hostPort[:colon], ":") {
		if _, err := strconv.Atoi(hostPort[colon+1:]); err == nil {
			return hostPort[:colon], hostPort[colon+1:]
		}
	}
	return hostPort, ""
}

func isDefaultHostPort(scheme, port string) bool {
	switch scheme {
	case "https":
		return port == "443"
	case "http":
		return port == "80"
	case "ssh":
		return port == "22"
	default:
		return port == "443" || port == "80" || port == "22"
	}
}

// splitHostLike splits "host/rest" when the first segment is host-like
// (contains a dot) and the remainder itself contains a slash, so a GitLab
// group with a dot in its name ("acme.co/service") is never mistaken for a
// host. It mirrors auth's splitHostLike.
func splitHostLike(key string) (first, rest string, ok bool) {
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 || !strings.Contains(parts[0], ".") || !strings.Contains(parts[1], "/") {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// CanonicalRepoID is the canonical "<host>/<owner>/<name>" identity used by
// repository allowlists and quota counters. It mirrors auth.CanonicalRepoID
// without importing the auth package, so storage stays independent of the
// server identity layer; the two derivations MUST stay identical. The forge
// host is canonicalized first (see canonicalHost) and a full name that
// already carries a canonically equivalent spelling of that host is reduced
// to its owner/name remainder (idempotent); a name embedding a DIFFERENT
// host is re-prefixed with the authoritative host. With no known host the
// trimmed full name is returned unchanged; an empty full name stays empty.
func CanonicalRepoID(host, fullName string) string {
	fullName = strings.TrimSpace(fullName)
	if fullName == "" {
		return ""
	}
	host = canonicalHost(host)
	if first, rest, ok := splitHostLike(fullName); ok {
		canonFirst := canonicalHost(first)
		if host == "" || canonFirst == host {
			if host == "" {
				host = canonFirst
			}
			fullName = rest
		}
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
