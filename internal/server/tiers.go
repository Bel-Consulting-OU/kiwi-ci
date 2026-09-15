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

// canonicalRepoForRun resolves the run's canonical repository identity
// ("<forgeHost>/<fullName>"). The forge host is derived from the run's repo
// URL when the stored full name does not already carry one.
func canonicalRepoForRun(run model.Run) string {
	return auth.CanonicalRepoID(repoHost(run.Repo), run.RepoFullName)
}

// repoHost extracts the forge host from a repo URL in the common forms:
// https://host/owner/repo(.git), ssh://git@host/owner/repo and the scp-like
// git@host:owner/repo.
func repoHost(repoURL string) string {
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

// visibleRepos returns the set of repository identities a principal may
// read. ok=false means the request has no principal-based restriction
// (legacy mode, admin principal, or a principal without a repository map:
// role-granted read covers everything). The set contains both the raw map
// keys and their canonicalized forms so either keying convention matches.
func (s *Server) visibleRepos(r *http.Request) (map[string]bool, bool) {
	p, ok := auth.PrincipalFrom(r)
	if !ok || p.Has(auth.RoleAdmin) || len(p.Repositories) == 0 {
		return nil, false
	}
	allowed := map[string]bool{}
	for key := range p.Repositories {
		allowed[key] = true
		allowed[auth.CanonicalRepoID("", key)] = true
		if _, bare, hasHost := splitCanonicalKey(key); hasHost {
			allowed[bare] = true
		}
	}
	return allowed, true
}

// splitCanonicalKey splits "host/owner/name" into host and bare "owner/name".
func splitCanonicalKey(key string) (host, bare string, hasHost bool) {
	parts := strings.SplitN(key, "/", 2)
	if len(parts) == 2 && strings.Contains(parts[0], ".") {
		return parts[0], parts[1], true
	}
	return "", key, false
}

// repoVisible reports whether a run's repository is visible to the request's
// principal. It is used by the scoped list endpoints.
func (s *Server) repoVisible(r *http.Request, run model.Run) bool {
	allowed, restricted := s.visibleRepos(r)
	if !restricted {
		return true
	}
	canon := canonicalRepoForRun(run)
	return allowed[canon] || allowed[run.RepoFullName] || allowed[auth.CanonicalRepoID("", run.RepoFullName)]
}

// repoVisibleByName reports whether a repository full name is visible to the
// request's principal (used by endpoints addressed by repo name instead of
// run ID).
func (s *Server) repoVisibleByName(r *http.Request, fullName string) bool {
	allowed, restricted := s.visibleRepos(r)
	if !restricted {
		return true
	}
	return allowed[fullName] || allowed[auth.CanonicalRepoID("", fullName)]
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

// canonicalRepoForJob resolves the canonical repository identity of a job.
func canonicalRepoForJob(j model.Job) string {
	return auth.CanonicalRepoID(repoHost(j.RepoURL), j.RepoFullName)
}

// requireRunRead enforces the read action plus repository-scope visibility
// for a per-run read route.
func (s *Server) requireRunRead(w http.ResponseWriter, r *http.Request, run model.Run) bool {
	if !s.requireAction(w, r, auth.ActionRead, canonicalRepoForRun(run), false) {
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
	if !s.requireAction(w, r, auth.ActionArtifactRead, canonicalRepoForRun(run), false) {
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
