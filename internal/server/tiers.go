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
		if len(segs) == 6 && segs[4] == "log" && segs[5] == "batch" && method == http.MethodPost {
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

// canReadRepo reports whether the request's principal may read repoID. The
// resolution is delegated to auth.CanReadRepo, the single repository-grant
// entry point, so host case, default ports, bare aliases and the ambiguity
// fail-closed behavior are identical on every endpoint. When no principal is
// present (legacy mode or the web-session path, both already tier-gated by
// auth()) the outer tier decides, so the answer is true. Scoped collection
// endpoints call this per candidate; the coarse per-request gate is
// requireReadAny.
func (s *Server) canReadRepo(r *http.Request, repoID string) bool {
	p, ok := auth.PrincipalFrom(r)
	if !ok {
		return true
	}
	return auth.CanReadRepo(p, repoID)
}

// requireReadAny enforces the coarse read gate of the collection endpoints
// that span repositories (GET /api/v1/runs and GET /api/v1/runners/serving):
// global read/admin OR at least one repository read grant. The capability
// resolution lives in auth.CanReadAnyRepo, never in server-side map
// inspection, and it is NOT the authorization decision for any candidate —
// every run/job is still filtered individually through canReadRepo. Without
// the coarse gate a repository-only reader would be denied outright before
// its grant is evaluated; with it, a principal holding no read capability is
// answered 403 rather than an empty 200.
func (s *Server) requireReadAny(w http.ResponseWriter, r *http.Request) bool {
	p, ok := auth.PrincipalFrom(r)
	if !ok {
		return true
	}
	if auth.CanReadAnyRepo(p) {
		return true
	}
	http.Error(w, "forbidden", http.StatusForbidden)
	return false
}

// repoVisibleByName reports whether the request's principal may read the
// repository named by fullName (a repository addressed by name instead of by
// run ID, e.g. the test-intelligence query parameter). It resolves through
// the same single auth entry point as canReadRepo, so the query form — full
// name, canonical ID or bare alias, in any canonical host spelling — agrees
// with the per-run routes and the collections.
func (s *Server) repoVisibleByName(r *http.Request, fullName string) bool {
	return s.canReadRepo(r, auth.CanonicalRepoID("", strings.TrimSpace(fullName)))
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

// requireRunRead enforces the read action for a per-run read route, scoped
// by the run's canonical policy identity. The repository decision goes
// through canReadRepo (auth.CanReadRepo), the same entry point the
// collections filter with, so the per-run endpoint and the collection can
// never disagree about a repository.
func (s *Server) requireRunRead(w http.ResponseWriter, r *http.Request, run model.Run) bool {
	if !s.canReadRepo(r, repoIDForRun(run)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// requireRunArtifactRead enforces the artifact-read action for a per-run
// artifact route, scoped by the run's canonical policy identity. The
// repository-scoped permission set resolves inside auth.Authorize: a
// repository entry is authoritative for artifact_read, and a plain read
// grant does not imply artifact access.
func (s *Server) requireRunArtifactRead(w http.ResponseWriter, r *http.Request, run model.Run) bool {
	return s.requireAction(w, r, auth.ActionArtifactRead, repoIDForRun(run), false)
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
