package server

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// parseCloneURL is the STRICT clone-URL parser every non-webhook ingress
// uses to derive the repository identity. It accepts exactly the clone URL
// forms a git client accepts for a forge:
//
//   - https://host/owner/repo(.git)
//   - ssh://git@host/owner/repo(.git) (user "git", no password)
//   - scp-like git@host:owner/repo(.git)
//   - http://host/owner/repo(.git) only for loopback hosts
//
// It returns the canonical forge host (lowercase, one trailing dot
// stripped, the scheme's default port dropped, no userinfo) and the forge
// repository path: owner/repo (nested groups allowed), with no host, no
// ".git" suffix, no leading/trailing slash, no query, no fragment and no
// userinfo. Anything malformed, empty, ambiguous or credential-bearing is
// rejected: a clone URL that cannot be parsed must never silently become a
// different repository identity.
func parseCloneURL(raw string) (host, forgePath string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", errors.New("clone URL is empty")
	}
	if i := strings.Index(s, "://"); i >= 0 {
		scheme := strings.ToLower(strings.TrimSpace(s[:i]))
		switch scheme {
		case "https", "ssh", "http":
		default:
			return "", "", fmt.Errorf("unsupported clone URL scheme %q", scheme)
		}
		u, uerr := url.Parse(s)
		if uerr != nil {
			return "", "", fmt.Errorf("malformed clone URL: %w", uerr)
		}
		if u.Host == "" {
			return "", "", errors.New("clone URL names no host")
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return "", "", errors.New("clone URL must not carry a query or fragment")
		}
		if u.User != nil {
			username := u.User.Username()
			_, hasPassword := u.User.Password()
			if scheme != "ssh" || username != "git" || hasPassword {
				return "", "", errors.New("clone URL must not carry credentials (userinfo)")
			}
		}
		if scheme == "http" && !loopbackCloneHost(u.Hostname()) {
			return "", "", errors.New("http clone URLs are only allowed for loopback hosts")
		}
		path, perr := cleanClonePath(u.Path)
		if perr != nil {
			return "", "", perr
		}
		h := canonicalHost(u.Host)
		if h == "" {
			return "", "", errors.New("clone URL names no host")
		}
		return h, path, nil
	}
	// scp-like git@host:path
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return "", "", errors.New("clone URL must be an absolute URL or an scp-style git@host:path")
	}
	if user := s[:at]; user != "git" {
		return "", "", errors.New("scp-style clone URL must use the git user")
	}
	rest := s[at+1:]
	colon := strings.Index(rest, ":")
	if colon <= 0 {
		return "", "", errors.New("malformed scp-style clone URL")
	}
	hostRaw, pathRaw := rest[:colon], rest[colon+1:]
	if strings.ContainsAny(hostRaw, "/?#") {
		return "", "", errors.New("malformed scp-style clone URL host")
	}
	if strings.ContainsAny(pathRaw, "?#") {
		return "", "", errors.New("clone URL must not carry a query or fragment")
	}
	path, perr := cleanClonePath(pathRaw)
	if perr != nil {
		return "", "", perr
	}
	h := canonicalHost(hostRaw)
	if h == "" {
		return "", "", errors.New("clone URL names no host")
	}
	return h, path, nil
}

// cleanClonePath normalizes a clone URL's repository path: at most one
// leading slash and one trailing slash are stripped, plus ONE trailing
// ".git" suffix. The path must name at least one non-empty segment with no
// "."/".." traversal and no empty (double-slash) segments: empty, slash-only
// and ambiguous paths are rejected.
func cleanClonePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if strings.HasPrefix(p, "//") {
		return "", fmt.Errorf("clone URL repository path %q is malformed", p)
	}
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return "", errors.New("clone URL names no repository path")
	}
	if len(p) > 4 && strings.EqualFold(p[len(p)-4:], ".git") {
		p = p[:len(p)-4]
		p = strings.TrimSuffix(p, "/")
	}
	if p == "" {
		return "", errors.New("clone URL names no repository path")
	}
	segs := strings.Split(p, "/")
	for _, seg := range segs {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("clone URL repository path %q is malformed", p)
		}
	}
	return strings.Join(segs, "/"), nil
}

// loopbackCloneHost reports whether host is a loopback name/address. Plain
// http is only admitted for loopback so a credential-less plaintext clone
// can never be steered at an arbitrary network host through the parser.
func loopbackCloneHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	switch h {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return strings.HasPrefix(h, "127.")
}

// canonicalHost normalizes a forge host spelling onto one canonical form,
// using net/url for scheme-prefixed inputs and manual handling for the
// scp-like git@host:path form: lowercase hostname, ONE trailing dot
// stripped, userinfo stripped, and the default port of the scheme dropped
// (443 https, 80 http, 22 ssh; with no scheme the well-known defaults
// 443/80/22 are dropped). Non-default ports stay part of the identity
// (github.com:8443 is distinct). It agrees with auth.CanonicalHost, which
// the RBAC/policy layers canonicalize with; the pinning test asserts it.
func canonicalHost(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		scheme := strings.ToLower(strings.TrimSpace(s[:i]))
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			return canonHostPort(scheme, u.Host)
		}
		rest := s[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		return canonHostPort(scheme, rest)
	}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		rest := s[at+1:]
		if colon := strings.Index(rest, ":"); colon >= 0 {
			tail := rest[colon+1:]
			if tail == "" || strings.Contains(tail, "/") {
				return canonHostPort("ssh", rest[:colon])
			}
		}
		return canonHostPort("", rest)
	}
	if j := strings.IndexAny(s, "/?#"); j >= 0 {
		s = s[:j]
	}
	if colon := strings.Index(s, ":"); colon > 0 && !strings.Contains(s[:colon], ":") {
		if _, err := strconv.Atoi(s[colon+1:]); err != nil {
			// Legacy "host:path" spelling with no scp user and no numeric
			// port: the colon separates the host from a path, not a port.
			s = s[:colon]
		}
	}
	return canonHostPort("", s)
}

func canonHostPort(scheme, hostPort string) string {
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

// forgePathFromFullName normalizes a submitted repo_full_name / schedule
// Repository value to a forge repository path for the binding check. A
// URL-shaped input is reduced through the strict clone-URL parser; a bare
// owner/name is trimmed, ".git"-stripped and validated. It reports ok=false
// for anything that cannot name a repository path.
func forgePathFromFullName(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	if strings.Contains(s, "://") || strings.Contains(s, "@") {
		_, p, err := parseCloneURL(s)
		if err != nil {
			return "", false
		}
		return p, true
	}
	p, err := cleanClonePath(s)
	if err != nil {
		return "", false
	}
	return p, true
}

// bindSubmissionRepoIdentity resolves and validates the repository identity
// of a NON-webhook submission BEFORE any authorization decision:
//
//   - repo_url is authoritative: the canonical identity is derived from the
//     URL's host + repository path through the strict parser, never from a
//     free-standing repo_full_name;
//   - a supplied repo_full_name must be canonically equal to the URL's
//     repository path (case-insensitive owner/repo, ".git" stripped): the
//     audit example repo_url=https://github.com/acme/other.git with
//     repo_full_name=acme/allowed is rejected outright so it can never
//     authorize as acme/allowed;
//   - repo_url with a malformed/empty/ambiguous path is rejected;
//   - a URL-less legacy submission keeps the bare full-name identity.
//
// On success RepoID, PolicyRepoID and CheckoutRepoURL are set consistently.
func bindSubmissionRepoIdentity(in *SubmitRun) error {
	raw := strings.TrimSpace(in.RepoURL)
	full := strings.TrimSpace(in.RepoFullName)
	if raw == "" {
		if full == "" {
			return &admissionError{Status: 400, Reason: "repo_identity_required", Msg: "repo_url or repo_full_name is required"}
		}
		p, ok := forgePathFromFullName(full)
		if !ok {
			return &admissionError{Status: 400, Reason: "repo_full_name_invalid", Msg: "repo_full_name names no repository path"}
		}
		in.RepoID = auth.CanonicalRepoID("", p)
		in.PolicyRepoID = in.RepoID
		return nil
	}
	host, path, err := parseCloneURL(raw)
	if err != nil {
		return &admissionError{Status: 400, Reason: "repo_url_invalid", Msg: "invalid repo_url: " + err.Error()}
	}
	if full != "" {
		fullPath, ok := forgePathFromFullName(full)
		if !ok {
			return &admissionError{Status: 400, Reason: "repo_full_name_invalid", Msg: "repo_full_name names no repository path"}
		}
		if !strings.EqualFold(fullPath, path) {
			return &admissionError{
				Status: 400,
				Reason: "repo_identity_mismatch",
				Msg:    fmt.Sprintf("repo_full_name %q does not match the repository path %q of repo_url", full, path),
			}
		}
	}
	in.RepoID = auth.CanonicalRepoID(host, path)
	in.PolicyRepoID = in.RepoID
	if strings.TrimSpace(in.CheckoutRepoURL) == "" {
		in.CheckoutRepoURL = raw
	}
	return nil
}

// bindPublicSubmissionRepoIdentity is the PUBLIC API contract: POST
// /api/v1/runs must carry repo_url, because a URL-less submission has no
// checkout repository and can only fail later on the runner. Internal
// ingresses that legitimately know a bare identity (legacy state, tests)
// keep using bindSubmissionRepoIdentity directly.
func bindPublicSubmissionRepoIdentity(in *SubmitRun) error {
	if strings.TrimSpace(in.RepoURL) == "" {
		return &admissionError{Status: 400, Reason: "repo_url_required", Msg: "repo_url is required for API submissions"}
	}
	return bindSubmissionRepoIdentity(in)
}

// submittedPolicyRepoID resolves the policy/authorization identity of a
// submission: the explicit PolicyRepoID when set, otherwise the immutable
// RepoID. Internal ingresses set both; legacy payloads carry only RepoID.
func submittedPolicyRepoID(in SubmitRun) string {
	if id := strings.TrimSpace(in.PolicyRepoID); id != "" {
		return id
	}
	return strings.TrimSpace(in.RepoID)
}

// submittedCheckoutURL resolves the clone URL the run's jobs check out: the
// explicit CheckoutRepoURL when set, otherwise the display/legacy RepoURL.
func submittedCheckoutURL(in SubmitRun) string {
	if u := strings.TrimSpace(in.CheckoutRepoURL); u != "" {
		return u
	}
	return strings.TrimSpace(in.RepoURL)
}

// checkoutURLForRun resolves a run's checkout clone URL for a rerun copy.
func checkoutURLForRun(run model.Run) string {
	if u := strings.TrimSpace(run.CheckoutRepoURL); u != "" {
		return u
	}
	return strings.TrimSpace(run.Repo)
}

// Repository identity is derived exactly ONCE per ingress and then carried
// immutably on the run and its jobs as model.RepoID. The derivation helper
// below is THE server-side derivation: every ingress (API submit, forge
// webhooks, dispatch, schedules, downstream children, reruns) resolves the
// identity through it, and every consumer reads the stored RepoID with the
// SAME legacy fallback. There is no second helper: repoHost /
// forgeInstanceHost only supply the host component, auth.CanonicalRepoID
// only joins it with the forge-native full name.

// repoIDFor is the ONE repository identity resolver: the stored immutable
// RepoID when present, otherwise derived from the forge host of the clone
// URL plus the full name (recovered from the URL path when the record
// carries no full name, so URL-only submissions stay host-scoped). The
// fallback exists for records persisted before RepoID (payloads without
// repo_id); it derives the SAME value the ingress derivation produced for
// the same URL + full name.
func repoIDFor(storedID, repoURL, repoFullName string) string {
	if id := strings.TrimSpace(storedID); id != "" {
		return id
	}
	fullName := strings.TrimSpace(repoFullName)
	if fullName == "" {
		fullName = storage.RepoFullNameFromURL(repoURL)
	}
	return auth.CanonicalRepoID(repoHost(repoURL), fullName)
}

// repoIDForRun resolves a run's canonical repository identity. PolicyRepoID
// is authoritative for every AUTHORIZATION decision (it is the BASE
// repository of a fork PR); a legacy record without one falls back to the
// immutable RepoID and then to the URL + full-name derivation.
func repoIDForRun(run model.Run) string {
	if id := strings.TrimSpace(run.PolicyRepoID); id != "" {
		return id
	}
	return repoIDFor(run.RepoID, run.Repo, run.RepoFullName)
}

// repoIDForJob resolves a job's canonical repository identity, with the same
// PolicyRepoID-first fallback as repoIDForRun.
func repoIDForJob(j model.Job) string {
	if id := strings.TrimSpace(j.PolicyRepoID); id != "" {
		return id
	}
	return repoIDFor(j.RepoID, j.RepoURL, j.RepoFullName)
}

// repoIDForSubmit resolves a submission's canonical repository identity: the
// POLICY identity (PolicyRepoID) an ingress already derived, otherwise the
// stored RepoID, otherwise derived from repo_url + repo_full_name. Direct API
// submissions never carry a client-supplied RepoID (the field is not
// decoded), and their repo_full_name is bound to the repo_url path before
// this ever runs (see bindSubmissionRepoIdentity).
func repoIDForSubmit(in SubmitRun) string {
	if id := submittedPolicyRepoID(in); id != "" {
		return id
	}
	return repoIDFor("", in.RepoURL, in.RepoFullName)
}

// repoHost extracts and CANONICALIZES the forge host from a repo URL in the
// common forms: https://host/owner/repo(.git), ssh://git@host/owner/repo and
// the scp-like git@host:owner/repo. It is the ONE host extractor for
// server-side identity derivation (host allowlists use it too). The host is
// lowercased with one trailing dot stripped and the scheme's default port
// dropped (443 https, 80 http, 22 ssh); a non-default port (host:8443) stays
// part of the identity; scp-like forms never carry a port.
func repoHost(repoURL string) string {
	return canonicalHost(repoURL)
}

// repoFullNameFromCloneURL extracts the forge-native owner/name (or nested
// group path) from a clone URL, dropping the scheme, host, credentials and
// the ".git" suffix. A non-URL input (a bare owner/name, the legacy schedule
// identity form) is returned unchanged; a URL-shaped input with no
// repository path yields "".
func repoFullNameFromCloneURL(repoURL string) string {
	trimmed := strings.TrimSpace(repoURL)
	if strings.Contains(trimmed, "://") || strings.Contains(trimmed, "@") {
		return storage.RepoFullNameFromURL(trimmed)
	}
	return trimmed
}

// forgeInstanceHost resolves the forge instance host for a webhook delivery:
// the host the forge itself reported in the clone URL comes first (the
// authoritative instance the delivery came from), then the configured
// enterprise/self-hosted API base host, then the forge's public host. The
// GitHub public API host (api.github.com) normalizes to github.com, the web
// host that appears in clone URLs and canonical IDs.
func (s *Server) forgeInstanceHost(forgeKind, cloneURL string) string {
	if h := repoHost(cloneURL); h != "" {
		return h
	}
	if h := s.configuredForgeHost(forgeKind); h != "" {
		return h
	}
	return publicForgeHost(forgeKind)
}

// configuredForgeHost returns the host of the configured API base URL for a
// forge kind, normalized to the forge's web host, or "" when no base URL is
// configured.
func (s *Server) configuredForgeHost(forgeKind string) string {
	host := repoHost(s.forgeBaseURL(forgeKind))
	if host == "api.github.com" {
		return "github.com"
	}
	return host
}

// publicForgeHost is the public instance host of a forge kind, used when
// neither configuration nor the delivery names a host.
func publicForgeHost(forgeKind string) string {
	switch forgeKind {
	case "gitlab":
		return "gitlab.com"
	case "forgejo":
		return "codeberg.org"
	default:
		return "github.com"
	}
}

// forgeRepoID derives the canonical repository identity of one webhook
// repository coordinate: the forge instance host plus the forge-native full
// name (GitHub/GitHub Enterprise full_name, GitLab path_with_namespace,
// Forgejo full_name). It runs at webhook ingress, before any policy, RBAC,
// quota or scheduling decision.
func (s *Server) forgeRepoID(forgeKind string, repo forge.Repository) string {
	return auth.CanonicalRepoID(s.forgeInstanceHost(forgeKind, repo.CloneURL), repo.FullName)
}

// webhookRepoCoordinate returns the event's BASE repository (the canonical
// policy coordinate, never the fork head) with the clone URL the delivery
// reported; the head repository's URL is the fallback when the base section
// omits one, so the derived host still comes from the delivery.
func webhookRepoCoordinate(ec forge.EventContext) forge.Repository {
	repo := ec.Repository
	if strings.TrimSpace(repo.CloneURL) == "" {
		repo.CloneURL = ec.HeadRepository.CloneURL
	}
	return repo
}

// checkoutCloneURL returns the clone URL a webhook run's jobs must check out:
// the HEAD repository's URL (a fork on cross-repo PRs), falling back to the
// base repository's URL when the delivery names none. The POLICY identity of
// the run stays the base repository (see PolicyRepoID); the checkout URL is
// what the runner clones.
func checkoutCloneURL(ec forge.EventContext) string {
	if u := strings.TrimSpace(ec.HeadRepository.CloneURL); u != "" {
		return u
	}
	return strings.TrimSpace(ec.Repository.CloneURL)
}

// repoTeamKey returns the quota team key of a canonical repository identity:
// the forge host plus the owner segment. It delegates to the storage
// derivation so every counter mutation uses the same key.
func repoTeamKey(repoID string) string {
	return storage.RepoTeamKey(repoID)
}
