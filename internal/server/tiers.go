package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// routeTier classifies a request for auth(): public routes need no bearer
// token, runner routes require the runner token (or a store principal in
// store mode), RBAC routes require an authenticated principal and are
// authorized per action by requireAction, and admin routes keep the blanket
// admin gate.
type routeTier int

const (
	tierPublic routeTier = iota
	tierEnroll
	tierRunner
	tierRBAC
	tierAdmin
)

// publicPath reports whether the request is public (no bearer token
// required). It delegates to the shared auth.PublicRoute classifier so the
// auth middleware and the tier gate can never drift; enrollment is carved
// out because it needs its own tier gate (the enrollment token/grant) even
// though the middleware treats it as public.
func publicPath(r *http.Request) bool {
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/runners/enroll" {
		return false
	}
	return auth.PublicRoute(r.Method, r.URL.Path)
}

// runnerPath reports whether the route is runner-tier: the bearer must be
// the runner token and the handler performs lease/identity verification.
func runnerPath(method, path string) bool {
	if method == http.MethodPost && path == "/api/v1/runners/register" {
		return true
	}
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) < 4 || segs[0] != "api" || segs[1] != "v1" {
		return false
	}
	switch {
	case len(segs) == 5 && segs[2] == "runners" && method == http.MethodPost && segs[4] == "next":
		return true
	case segs[2] == "jobs":
		if len(segs) == 5 && method == http.MethodPost {
			switch segs[4] {
			case "heartbeat", "log", "complete", "generated", "secrets", "tests", "snapshots":
				return true
			}
		}
		if len(segs) == 5 && segs[4] == "test-shards" && method == http.MethodGet {
			return true
		}
		if len(segs) == 6 && segs[4] == "artifacts" && method == http.MethodPut {
			return true
		}
		if len(segs) == 7 && segs[4] == "dependencies" && method == http.MethodGet {
			return true
		}
		if len(segs) == 6 && segs[4] == "cache" && (method == http.MethodGet || method == http.MethodPut) {
			return true
		}
	}
	return false
}

// classifyRoute returns the auth tier for a request.
func classifyRoute(r *http.Request) routeTier {
	if publicPath(r) {
		return tierPublic
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/runners/enroll" {
		return tierEnroll
	}
	if runnerPath(r.Method, r.URL.Path) {
		return tierRunner
	}
	if _, _, handled := auth.ActionFor(r.Method, r.URL.Path); handled {
		return tierRBAC
	}
	return tierAdmin
}

// visibleRepos returns the set of repository identities a principal may
// read. ok=false means the request has no principal-based restriction
// (legacy mode, admin principal, or a principal without a repository map:
// role-granted read covers everything). The set contains exactly the
// DECLARED map keys: canonical IDs ("forge-host/owner/name") and explicitly
// configured bare aliases. Bare forms are never derived implicitly from
// canonical keys — a principal keyed for github.com/acme/service grants
// nothing for gitlab.example/acme/service.
func (s *Server) visibleRepos(r *http.Request) (map[string]bool, bool) {
	p, ok := auth.PrincipalFrom(r)
	if !ok || p.Has(auth.RoleAdmin) || len(p.Repositories) == 0 {
		return nil, false
	}
	allowed := map[string]bool{}
	for key := range p.Repositories {
		allowed[key] = true
	}
	return allowed, true
}

// splitCanonicalKey splits "host/owner/name" into host and bare "owner/name".
// The remainder after the dotted host must itself contain a slash: a
// canonical identity always carries owner/name, so a two-segment
// "acme.co/service" (a GitLab group containing a dot) must NOT be read as
// host "acme.co" + bare "service" — that would let an unrelated bare alias
// "service" match it.
func splitCanonicalKey(key string) (host, bare string, hasHost bool) {
	parts := strings.SplitN(key, "/", 2)
	if len(parts) == 2 && strings.Contains(parts[0], ".") && strings.Contains(parts[1], "/") {
		return parts[0], parts[1], true
	}
	return "", key, false
}

// repoVisible reports whether a run's repository is visible to the request's
// principal. It is used by the scoped list endpoints. Resolution is
// STRICTLY canonical: the run's identity is forge-host/owner/name. A
// declared canonical key matches only its exact identity; a bare key in
// the principal map is honored as an EXPLICITLY configured alias (it
// matches the run's bare full name across forges) — aliases are never
// derived implicitly.
func (s *Server) repoVisible(r *http.Request, run model.Run) bool {
	allowed, restricted := s.visibleRepos(r)
	if !restricted {
		return true
	}
	canon := repoIDForRun(run)
	if allowed[canon] || allowed[run.RepoFullName] {
		return true
	}
	if _, bare, hasHost := splitCanonicalKey(canon); hasHost && allowed[bare] {
		return true
	}
	return false
}

// repoVisibleByName reports whether a repository full name is visible to the
// request's principal (used by endpoints addressed by repo name instead of
// run ID). A declared canonical key matches its exact identity or its bare
// full name; a declared bare alias matches the bare full name. Nothing is
// derived implicitly.
func (s *Server) repoVisibleByName(r *http.Request, fullName string) bool {
	allowed, restricted := s.visibleRepos(r)
	if !restricted {
		return true
	}
	if allowed[fullName] {
		return true
	}
	canon := auth.CanonicalRepoID("", fullName)
	if canon != fullName && allowed[canon] {
		return true
	}
	if _, bare, hasHost := splitCanonicalKey(canon); hasHost && allowed[bare] {
		return true
	}
	return false
}

// authorizeRepo is the canonical-only repository authorization gate. The
// repo entry is resolved STRICTLY by the exact canonical identity; a bare
// key in the principal map is honored only as an explicitly configured
// alias (matching the bare full name across forges) — it is never derived
// implicitly, so gitlab.example/acme/service and github.com/acme/service
// never share authorization unless a bare alias is literally declared.
// Non-repo-scoped actions and the role fallback mirror auth.Authorize.
func authorizeRepo(p auth.Principal, action auth.Action, repo string, trusted bool) bool {
	if p.Has(auth.RoleAdmin) {
		return true
	}
	if repo != "" {
		if perm, ok := p.Repositories[repo]; ok {
			return repoPermAllows(perm, action, trusted)
		}
		if _, bare, hasHost := splitCanonicalKey(repo); hasHost {
			if perm, ok := p.Repositories[bare]; ok {
				return repoPermAllows(perm, action, trusted)
			}
		}
	}
	switch action {
	case auth.ActionRead:
		return p.Has(auth.RoleRead)
	case auth.ActionRun:
		if trusted {
			return p.Has(auth.RoleTrustedRun)
		}
		return p.Has(auth.RoleRun)
	case auth.ActionTrustedRun:
		return p.Has(auth.RoleTrustedRun)
	case auth.ActionApprove:
		return p.Has(auth.RoleApprove)
	case auth.ActionCancel:
		return p.Has(auth.RoleCancel)
	case auth.ActionRerun:
		return p.Has(auth.RoleRerun)
	case auth.ActionArtifactRead:
		return p.Has(auth.RoleArtifactRead)
	case auth.ActionRunnerManage:
		return p.Has(auth.RoleRunnerManage)
	case auth.ActionPolicyManage:
		return p.Has(auth.RolePolicyManage)
	}
	return false
}

// repoPermAllows maps a repo-specific permission set onto one repo-scoped
// action (the trusted_run resolution for ActionRun mirrors auth.Authorize).
func repoPermAllows(perm auth.RepositoryPermission, action auth.Action, trusted bool) bool {
	switch action {
	case auth.ActionRead:
		return perm.Read
	case auth.ActionRun:
		if trusted {
			return perm.TrustedRun
		}
		return perm.Run
	case auth.ActionTrustedRun:
		return perm.TrustedRun
	case auth.ActionApprove:
		return perm.Approve
	case auth.ActionCancel:
		return perm.Cancel
	case auth.ActionRerun:
		return perm.Rerun
	case auth.ActionArtifactRead:
		return perm.ArtifactRead
	}
	return false
}

// runForAuth resolves the run addressed by id (store in DB mode, memory map
// otherwise) for per-route authorization.
func (s *Server) runForAuth(ctx context.Context, id string) (model.Run, error) {
	if s.DB != nil {
		return s.DB.GetRun(ctx, id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return model.Run{}, storage.ErrNotFound
	}
	return run, nil
}

// requireRunRead enforces the read action plus repository-scope visibility
// for a per-run read route.
func (s *Server) requireRunRead(w http.ResponseWriter, r *http.Request, run model.Run) bool {
	if !s.requireAction(w, r, auth.ActionRead, repoIDForRun(run), false) {
		return false
	}
	if !s.repoVisible(r, run) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// requireRunArtifactRead enforces the artifact-read action plus repository
// visibility for a per-run artifact route.
func (s *Server) requireRunArtifactRead(w http.ResponseWriter, r *http.Request, run model.Run) bool {
	if !s.requireAction(w, r, auth.ActionArtifactRead, repoIDForRun(run), false) {
		return false
	}
	if !s.repoVisible(r, run) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// requireArtifactRead enforces the artifact-read action for one artifact
// record, resolving the repository scope from the owning run. When the run
// cannot be resolved the request is denied rather than silently scoped
// away.
func (s *Server) requireArtifactRead(w http.ResponseWriter, r *http.Request, rec model.ArtifactRecord) bool {
	run, err := s.runForAuth(r.Context(), rec.RunID)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return s.requireRunArtifactRead(w, r, run)
}
