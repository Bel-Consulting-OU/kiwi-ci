package server

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// routeTier classifies a request for auth(): public routes need no bearer
// token, runner routes require the runner token (or a store principal in
// store mode), RBAC routes require an authenticated principal and are
// authorized per action by requireAction, capability routes require an
// authenticated controller principal carrying the addressed capability (or
// admin), and admin routes keep the blanket admin gate.
type routeTier int

const (
	tierPublic routeTier = iota
	tierEnroll
	tierRunner
	tierRBAC
	tierCapability
	tierAdmin
)

// capabilityScope names the repository scope a capability route declares.
type capabilityScope int

const (
	// capabilityScopeGlobal: the route addresses no repository (audit); the
	// capability must be held globally (or admin).
	capabilityScopeGlobal capabilityScope = iota
	// capabilityScopeRun: the route addresses one run; the handler resolves
	// the run's canonical repository identity (repoIDForRun) and authorizes
	// the capability there.
	capabilityScopeRun
	// capabilityScopeRepo: the route addresses a repository directly (the
	// repo_id query parameter, or a run window resolved to one repository);
	// the handler authorizes the capability against that repository.
	capabilityScopeRepo
)

// capabilityRoute is one entry of the capability route table: the
// method+path pattern, the capability the route consumes, and the scope in
// which the handler enforces it. The table is consulted by classifyRoute
// BEFORE the auth.ActionFor RBAC table and before the admin fallback, so a
// capability route is never classified as tierRBAC/tierAdmin (or worse,
// unclassified).
type capabilityRoute struct {
	method     string
	pattern    string
	capability auth.Capability
	scope      capabilityScope
	// readFallback admits a principal with ANY repository read capability at
	// the TIER gate (never instead of the handler decision): the run-scoped
	// execution event reads may be satisfied by read access to the addressed
	// run's repository, so a repository reader must reach the handler that
	// resolves run_id. The handler still requires read access to THAT run's
	// repository (or the capability globally), so the tier gate can never
	// widen what the handler allows.
	readFallback bool
}

// capabilityRoutes is the explicit, pinned inventory of controller
// capability routes. Every entry is enforced twice: the tier gate
// (tierCapability in auth()) only screens that the principal carries the
// capability somewhere, and the handler resolves the actual repository scope.
// Runs cancel is deliberately NOT here: it stays on the RBAC tier action
// table (auth.ActionFor maps it to ActionCancel) and the cancel handlers
// additionally accept the runs:cancel capability.
var capabilityRoutes = []capabilityRoute{
	// The canonical execution event stream: admin gates were too broad for
	// external controllers consuming execution history. A run_id-scoped read
	// is covered by the capability for that run's repository or by read
	// access to it; a repo_id-scoped read by the capability for the addressed
	// repository or read access to it; the unscoped cursor read requires a
	// GLOBAL capability.
	{method: http.MethodGet, pattern: "/api/v1/events", capability: auth.CapExecutionEventsRead, scope: capabilityScopeRun, readFallback: true},
	{method: http.MethodGet, pattern: "/api/v1/events/stream", capability: auth.CapExecutionEventsRead, scope: capabilityScopeRun, readFallback: true},
	// The atomic bootstrap snapshot mirrors the event stream's visibility: a
	// repo_id-scoped request is authorized exactly like a repo-scoped event
	// read (capability for the repository or read access to it); the
	// unscoped form spans every repository, so only a GLOBAL
	// execution.events:read (or admin) may read it.
	{method: http.MethodGet, pattern: "/api/v1/execution-snapshot", capability: auth.CapExecutionEventsRead, scope: capabilityScopeRepo, readFallback: true},
	// The audit trail is repository-less: evidence:read must be global.
	{method: http.MethodGet, pattern: "/api/v1/audit", capability: auth.CapEvidenceRead, scope: capabilityScopeGlobal},
	// Workspace snapshot listing and archive download: the record carries the
	// workspace manifest, so checkpoints:read (run-scoped) is the controller
	// grant; the admin action still satisfies both handlers.
	{method: http.MethodGet, pattern: "/api/v1/runs/{id}/snapshots", capability: auth.CapCheckpointsRead, scope: capabilityScopeRun},
	{method: http.MethodGet, pattern: "/api/v1/runs/{id}/snapshots/{sid}", capability: auth.CapCheckpointsRead, scope: capabilityScopeRun},
	// The exact-replay pipeline/payload export serves replay MATERIAL
	// (evidence) recorded at enqueue time, so it consumes evidence:read, the
	// same capability class as the audit trail, not checkpoints:read (which
	// governs workspace archives).
	{method: http.MethodGet, pattern: "/api/v1/runs/{id}/jobs/{job}/pipeline", capability: auth.CapEvidenceRead, scope: capabilityScopeRun},
	// The final signed execution attestation of one job attempt is durable
	// completion evidence: evidence:read scoped to the addressed job's run
	// (or admin). The handler resolves the run and enforces the run-scoped
	// decision; a 404 for an unattested job is answered after authorization.
	{method: http.MethodGet, pattern: "/api/v1/jobs/{id}/attestation", capability: auth.CapEvidenceRead, scope: capabilityScopeRun},
}

// capabilityRouteFor resolves the capability route entry for a method+path,
// or reports false. Matching is segment-exact: literal segments must equal,
// "{name}" placeholders match one non-empty segment, and the segment count
// must match, so a near-miss path can never inherit a capability route.
func capabilityRouteFor(method, path string) (capabilityRoute, bool) {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for _, rt := range capabilityRoutes {
		if rt.method == method && matchRouteSegments(rt.pattern, segs) {
			return rt, true
		}
	}
	return capabilityRoute{}, false
}

// matchRouteSegments reports whether the concrete path segments match the
// registered pattern. A placeholder matches exactly one non-empty segment.
func matchRouteSegments(pattern string, segs []string) bool {
	pat := strings.Split(strings.Trim(pattern, "/"), "/")
	if len(pat) != len(segs) {
		return false
	}
	for i, p := range pat {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			if segs[i] == "" {
				return false
			}
			continue
		}
		if p != segs[i] {
			return false
		}
	}
	return true
}

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

// classifyRoute returns the auth tier for a request. The capability table is
// consulted BEFORE the RBAC action table and the admin fallback: the
// capability tier owns the controller endpoints that used to be admin-only
// (events, audit, pipeline export) and the snapshot routes that ActionFor
// alone would classify as hard ActionAdmin.
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
	// The verification substrate (/api/v1/verifications/*) is an
	// authenticated principal surface: the tier gate admits any store
	// principal (or admin / legacy open mode) and the Service's Authorizer
	// makes the subject-level decision. Fail closed lives in the Service,
	// not in a blanket admin gate.
	if strings.HasPrefix(r.URL.Path, verificationPrefix) {
		return tierRBAC
	}
	if _, ok := capabilityRouteFor(r.Method, r.URL.Path); ok {
		return tierCapability
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

// maskedRunNotFound is the SINGLE tenancy existence-masking response: the same
// status, headers and body bytes answer "no such run" and "a run the caller
// may not see", so a principal that cannot read a run's repository can never
// distinguish another repository's run from an unknown id through the
// run-scoped endpoints. The body deliberately carries no id, repository,
// reason or timing hint.
var maskedRunNotFound = map[string]string{"error": "not found"}

// writeMaskedRunNotFound writes the shared existence-masking 404. Every
// pre-visibility not-found answer on a run-scoped endpoint must use it (also
// when the address is a job or artifact id whose run has not been resolved),
// so the masked case and the genuinely-missing case are byte-identical.
func (s *Server) writeMaskedRunNotFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, maskedRunNotFound)
}

// visibilityGrant is one positive endpoint grant that keeps a run's existence
// visible in ADDITION to repository READ access (the baseline every
// run-scoped route shares). A principal holding the grant the addressed
// endpoint consumes is authorized on the run's repository, so masking the run
// from it would refuse a legitimate caller; exactly one field is set.
type visibilityGrant struct {
	capability auth.Capability
	action     auth.Action
}

// endpointVisibilityGrants returns the endpoint-specific grants whose holders
// must keep seeing the addressed run. The table mirrors the handler
// decisions: a controller capability route (snapshots/pipeline/attestation/
// events) contributes its capability, the artifact surfaces contribute
// artifact_read, and cancel/rerun contribute the capability (cancel) or
// action the handler accepts. Paths without an entry are read-only endpoints:
// repository read access alone decides visibility.
//
// The returned set is a visibility SUPERSET of the endpoint's final decision
// on purpose: a principal that reaches visibility but fails the narrower
// capability check is answered the existing 403 (capability denial is not an
// existence leak once the caller provably holds SOME grant on that
// repository). A principal holding no grant for the repository at all never
// reaches the final decision — it gets the masked 404.
func endpointVisibilityGrants(method, path string) []visibilityGrant {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) < 3 || segs[0] != "api" || segs[1] != "v1" {
		return nil
	}
	if rt, ok := capabilityRouteFor(method, path); ok && rt.scope == capabilityScopeRun {
		return []visibilityGrant{{capability: rt.capability}}
	}
	switch segs[2] {
	case "runs":
		if len(segs) == 5 && method == http.MethodPost {
			switch segs[4] {
			case "cancel":
				return []visibilityGrant{{capability: auth.CapRunsCancel}, {action: auth.ActionCancel}}
			case "rerun":
				return []visibilityGrant{{action: auth.ActionRerun}}
			}
		}
		if len(segs) == 5 && segs[4] == "artifacts" && method == http.MethodGet {
			return []visibilityGrant{{action: auth.ActionArtifactRead}}
		}
	case "artifacts":
		if method == http.MethodGet && (len(segs) == 4 || (len(segs) == 5 && segs[4] == "provenance")) {
			return []visibilityGrant{{action: auth.ActionArtifactRead}}
		}
	}
	return nil
}

// runVisibleTo reports whether the request's principal may learn that run
// exists through the addressed endpoint: no principal (legacy/web-session,
// already tier-gated) and the admin role see every run, repository read
// access (auth.CanReadRepo, the same single repository-grant entry point
// every read route resolves through) sees its repositories' runs, and the
// endpoint's own positive grants (endpointVisibilityGrants) see the runs they
// are authorized on.
func (s *Server) runVisibleTo(r *http.Request, run model.Run) bool {
	p, ok := auth.PrincipalFrom(r)
	if !ok {
		return true
	}
	repo := repoIDForRun(run)
	if auth.Authorize(p, auth.ActionAdmin, repo, false) || auth.CanReadRepo(p, repo) {
		return true
	}
	for _, g := range endpointVisibilityGrants(r.Method, r.URL.Path) {
		if g.capability != "" && auth.AuthorizeCapability(p, g.capability, repo) {
			return true
		}
		if g.action != "" && auth.Authorize(p, g.action, repo, false) {
			return true
		}
	}
	return false
}

// requireRunVisible is THE existence-masking primitive of the run-scoped
// endpoints. It loads the addressed run and, when it does not exist OR the
// principal cannot see its repository, writes the SAME masked 404
// (writeMaskedRunNotFound) and returns false, so "exists in another
// repository" and "does not exist" are indistinguishable through status,
// body or headers. A visible run is returned so the caller can run its
// narrower decision (capability/artifact/action) AFTER visibility; a
// capability denial for a visible run keeps the existing 403.
//
// A store failure that is not ErrNotFound stays a 500: it is not an
// attacker-controllable existence oracle and operators must keep seeing real
// backend failures.
func (s *Server) requireRunVisible(w http.ResponseWriter, r *http.Request, runID string) (model.Run, bool) {
	run, err := s.runForAuth(r.Context(), runID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			s.writeMaskedRunNotFound(w)
		} else {
			s.internalError(w, r, err, "")
		}
		return model.Run{}, false
	}
	if !s.runVisibleTo(r, run) {
		s.writeMaskedRunNotFound(w)
		return model.Run{}, false
	}
	return run, true
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

// requireRunCapability enforces a run-scoped controller capability: it
// resolves the run addressed by runID, scopes the decision to the run's
// canonical repository identity (repoIDForRun), and accepts the admin action
// (the same decision requireRunAdmin makes) OR the capability authorized by
// auth.AuthorizeCapability. Requests without a principal are legacy open mode
// and pass, exactly like requireAction; an authenticated principal without
// either grant is answered 403 with the standard body. An unresolved run
// fails closed (403): the repository scope cannot be established, so no
// repository-scoped grant may be guessed.
//
// Handlers call requireRunVisible FIRST: an unknown or invisible run is the
// masked 404, so this helper only decides for runs whose existence the caller
// may already know; its 403 is the capability denial of a visible run.
func (s *Server) requireRunCapability(w http.ResponseWriter, r *http.Request, capability auth.Capability, runID string) bool {
	p, ok := auth.PrincipalFrom(r)
	if !ok {
		return true
	}
	run, err := s.runForAuth(r.Context(), runID)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	repo := repoIDForRun(run)
	if auth.Authorize(p, auth.ActionAdmin, repo, false) || auth.AuthorizeCapability(p, capability, repo) {
		return true
	}
	http.Error(w, "forbidden", http.StatusForbidden)
	return false
}

// requireRunActionOrCapability enforces an either/or decision on a run: the
// named Action (the existing RBAC behavior, unchanged) OR the controller
// capability, both resolved against the run's canonical repository identity.
// The cancel handlers use it with ActionCancel / runs:cancel.
func (s *Server) requireRunActionOrCapability(w http.ResponseWriter, r *http.Request, action auth.Action, capability auth.Capability, run model.Run) bool {
	p, ok := auth.PrincipalFrom(r)
	if !ok {
		return true
	}
	repo := repoIDForRun(run)
	if auth.Authorize(p, action, repo, false) || auth.AuthorizeCapability(p, capability, repo) {
		return true
	}
	http.Error(w, "forbidden", http.StatusForbidden)
	return false
}

// requireGlobalCapability enforces a repository-less capability (audit):
// only a global capability grant (or the admin role) satisfies it. A
// repository-scoped-only grant is answered 403 here; the tier gate admits it
// so the decision stays in one place.
func (s *Server) requireGlobalCapability(w http.ResponseWriter, r *http.Request, capability auth.Capability) bool {
	p, ok := auth.PrincipalFrom(r)
	if !ok {
		return true
	}
	if auth.AuthorizeCapability(p, capability, "") {
		return true
	}
	http.Error(w, "forbidden", http.StatusForbidden)
	return false
}
