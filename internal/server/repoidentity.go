package server

import (
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

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

// repoIDForRun resolves a run's canonical repository identity.
func repoIDForRun(run model.Run) string {
	return repoIDFor(run.RepoID, run.Repo, run.RepoFullName)
}

// repoIDForJob resolves a job's canonical repository identity.
func repoIDForJob(j model.Job) string {
	return repoIDFor(j.RepoID, j.RepoURL, j.RepoFullName)
}

// repoIDForSubmit resolves a submission's canonical repository identity:
// the identity an ingress already derived when it set SubmitRun.RepoID,
// otherwise derived from repo_url + repo_full_name. Direct API submissions
// never carry a client-supplied RepoID (the field is not decoded), so this
// is the API's host-from-repo_url derivation.
func repoIDForSubmit(in SubmitRun) string {
	return repoIDFor(in.RepoID, in.RepoURL, in.RepoFullName)
}

// repoHost extracts the forge host from a repo URL in the common forms:
// https://host/owner/repo(.git), ssh://git@host/owner/repo and the scp-like
// git@host:owner/repo. It is the ONE host extractor for server-side
// identity derivation (host allowlists use it too). Scheme URLs keep a
// non-default port (host:port is part of the identity); scp-like forms never
// do.
func repoHost(repoURL string) string {
	u := strings.TrimSpace(repoURL)
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		if slash := strings.Index(rest, "/"); slash >= 0 {
			return rest[:slash]
		}
		return rest
	}
	if at := strings.LastIndex(u, "@"); at >= 0 {
		u = u[at+1:]
	}
	if colon := strings.Index(u, ":"); colon >= 0 {
		return u[:colon]
	}
	if slash := strings.Index(u, "/"); slash >= 0 {
		return u[:slash]
	}
	return u
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

// repoTeamKey returns the quota team key of a canonical repository identity:
// the forge host plus the owner segment. It delegates to the storage
// derivation so every counter mutation uses the same key.
func repoTeamKey(repoID string) string {
	return storage.RepoTeamKey(repoID)
}
