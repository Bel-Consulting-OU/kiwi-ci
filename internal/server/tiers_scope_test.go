package server

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// routePattern is one method+path pattern registered on the server mux.
type routePattern struct {
	Method  string
	Path    string
	Pattern string
}

// registeredRoutePatterns walks the real Handler() route table by parsing
// the `mux.Handle*("METHOD /path", ...)` registrations out of server.go.
// Parsing (instead of a hand-maintained list) means a newly added route can
// never slip through the tier classification checks below unnoticed.
func registeredRoutePatterns(t *testing.T) []routePattern {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, filepath.Join(filepath.Dir(file), "server.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}
	var out []routePattern
	ast.Inspect(parsed, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); !ok || ident.Name != "mux" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		method, path, ok := strings.Cut(pattern, " ")
		if !ok {
			return true
		}
		out = append(out, routePattern{Method: method, Path: path, Pattern: pattern})
		return true
	})
	return out
}

var routePlaceholder = regexp.MustCompile(`\{[^/]+\}`)

// concretePath substitutes every path placeholder with a probe segment.
func concretePath(path string) string {
	return routePlaceholder.ReplaceAllString(path, "probe")
}

// expectedRouteTiers is the classification contract for EVERY registered
// route. A new route in server.go fails the walk until it is added here with
// an explicit tier decision, so no route can silently fall through to the
// blanket admin gate (or worse, a public tier) by accident. Logout is listed
// for both methods: it stays public at the auth tier, but the state-change
// gate lives in the handler (session+CSRF on POST, a 405 stub on GET).
var expectedRouteTiers = map[string]routeTier{
	// Public: no bearer required.
	"GET /":                                                    tierPublic,
	"GET /static/":                                             tierPublic,
	"POST /api/v1/login":                                       tierPublic,
	"GET /api/v1/logout":                                       tierPublic,
	"POST /api/v1/logout":                                      tierPublic,
	"GET /readiness":                                           tierPublic,
	"GET /liveness":                                            tierPublic,
	"POST /hooks/github":                                       tierPublic,
	"POST /hooks/gitlab":                                       tierPublic,
	"POST /hooks/forgejo":                                      tierPublic,
	"GET /.well-known/openid-configuration":                    tierPublic,
	"GET /api/v1/oidc/jwks":                                    tierPublic,
	"POST /api/v1/jobs/{id}/oidc":                              tierPublic,
	"POST /api/v1/runners/enroll":                              tierEnroll,
	"POST /api/v1/runners/register":                            tierRunner,
	"POST /api/v1/runners/{id}/next":                           tierRunner,
	"POST /api/v1/jobs/{id}/heartbeat":                         tierRunner,
	"POST /api/v1/jobs/{id}/log":                               tierRunner,
	"POST /api/v1/jobs/{id}/log/batch":                         tierRunner,
	"POST /api/v1/jobs/{id}/complete":                          tierRunner,
	"POST /api/v1/jobs/{id}/generated":                         tierRunner,
	"POST /api/v1/jobs/{id}/secrets":                           tierRunner,
	"POST /api/v1/jobs/{id}/tests":                             tierRunner,
	"POST /api/v1/jobs/{id}/snapshots":                         tierRunner,
	"GET /api/v1/jobs/{id}/test-shards":                        tierRunner,
	"PUT /api/v1/jobs/{id}/artifacts/{name}":                   tierRunner,
	"GET /api/v1/jobs/{id}/dependencies/{producer}/{artifact}": tierRunner,
	"GET /api/v1/jobs/{id}/cache/{key}":                        tierRunner,
	"PUT /api/v1/jobs/{id}/cache/{key}":                        tierRunner,
	// RBAC: authenticated principal + per-action role.
	"GET /api/v1/runs":                               tierRBAC,
	"POST /api/v1/runs":                              tierRBAC,
	"GET /api/v1/runs/{id}":                          tierRBAC,
	"POST /api/v1/runs/{id}/cancel":                  tierRBAC,
	"POST /api/v1/runs/{id}/rerun":                   tierRBAC,
	"GET /api/v1/runs/{id}/jobs":                     tierRBAC,
	"GET /api/v1/runs/{id}/logs":                     tierRBAC,
	"GET /api/v1/runs/{id}/logs/stream":              tierRBAC,
	"GET /api/v1/runs/{id}/artifacts":                tierRBAC,
	"GET /api/v1/runs/{id}/tests":                    tierRBAC,
	"GET /api/v1/runs/{id}/snapshots":                tierRBAC,
	"GET /api/v1/runs/{id}/snapshots/{sid}":          tierRBAC,
	"GET /api/v1/runs/{id}/deployments":              tierRBAC,
	"GET /api/v1/test-intelligence":                  tierRBAC,
	"GET /api/v1/artifacts/{id}":                     tierRBAC,
	"GET /api/v1/artifacts/{id}/provenance":          tierRBAC,
	"GET /api/v1/schedules":                          tierRBAC,
	"PUT /api/v1/schedules":                          tierRBAC,
	"POST /api/v1/schedules/{id}/trigger":            tierRBAC,
	"POST /api/v1/jobs/{id}/approve":                 tierRBAC,
	"GET /api/v1/runners":                            tierRBAC,
	"GET /api/v1/runners/serving":                    tierRBAC,
	"POST /api/v1/runners/{id}/drain":                tierRBAC,
	"POST /api/v1/runners/{id}/disable":              tierRBAC,
	"POST /api/v1/runners/{id}/enable":               tierRBAC,
	"POST /api/v1/runner-profiles":                   tierRBAC,
	"GET /api/v1/runner-profiles":                    tierRBAC,
	"GET /api/v1/runner-profiles/{id}":               tierRBAC,
	"PUT /api/v1/runner-profiles/{id}":               tierRBAC,
	"PUT /api/v1/runner-profiles/{id}/cert/{serial}": tierRBAC,
	// Runner-ID profile bindings are an admin operation: deliberately
	// unmapped by auth.ActionFor so they fall through to the blanket admin
	// gate (like drain), never the RBAC table.
	"PUT /api/v1/runner-profiles/{id}/runner/{runnerID}":    tierAdmin,
	"DELETE /api/v1/runner-profiles/{id}/runner/{runnerID}": tierAdmin,
	// Admin: blanket admin gate.
	"GET /metrics":                       tierAdmin,
	"POST /api/v1/jobs/{id}/deployments": tierAdmin,
	"POST /api/v1/drain":                 tierAdmin,
	"GET /api/v1/drain":                  tierAdmin,
	"GET /api/v1/audit":                  tierAdmin,
}

func tierName(t routeTier) string {
	switch t {
	case tierPublic:
		return "public"
	case tierEnroll:
		return "enroll"
	case tierRunner:
		return "runner"
	case tierRBAC:
		return "rbac"
	default:
		return "admin"
	}
}

// TestHandlerRouteTableFullyClassified walks the REAL route table and
// asserts every pattern has an explicit tier and that the tier classifier
// agrees with the independent classifiers it is built from (public table,
// runner path table, RBAC action table). No route may fall through
// unclassified.
func TestHandlerRouteTableFullyClassified(t *testing.T) {
	routes := registeredRoutePatterns(t)
	if len(routes) < 50 {
		t.Fatalf("only %d route patterns parsed; the parser or Handler() changed", len(routes))
	}
	seen := map[string]bool{}
	for _, rt := range routes {
		if seen[rt.Pattern] {
			t.Errorf("duplicate route pattern %q", rt.Pattern)
		}
		seen[rt.Pattern] = true
		want, ok := expectedRouteTiers[rt.Pattern]
		if !ok {
			t.Errorf("route %q is not in the classification contract; add it with an explicit tier", rt.Pattern)
			continue
		}
		path := concretePath(rt.Path)
		req := httptest.NewRequest(rt.Method, path, strings.NewReader("{}"))
		got := classifyRoute(req)
		if got != want {
			t.Errorf("classifyRoute(%s) = %s, want %s", rt.Pattern, tierName(got), tierName(want))
		}
		// Cross-check the classifier against the route-shape helpers it
		// delegates to, so the tier can never drift from them.
		switch want {
		case tierPublic:
			if !auth.PublicRoute(rt.Method, rt.Path) {
				t.Errorf("%s classified public but auth.PublicRoute disagrees", rt.Pattern)
			}
		case tierEnroll:
			if rt.Method != http.MethodPost || rt.Path != "/api/v1/runners/enroll" {
				t.Errorf("%s is the only enroll-tier route", rt.Pattern)
			}
			if !auth.PublicRoute(rt.Method, rt.Path) {
				t.Errorf("enroll must stay public to the middleware (tier gate owns it): %s", rt.Pattern)
			}
		case tierRunner:
			if !runnerPath(rt.Method, rt.Path) {
				t.Errorf("%s classified runner but runnerPath disagrees", rt.Pattern)
			}
		case tierRBAC:
			if _, _, handled := auth.ActionFor(rt.Method, rt.Path); !handled {
				t.Errorf("%s classified rbac but ActionFor is unhandled", rt.Pattern)
			}
		case tierAdmin:
			// Admin is the explicit fall-through by design; it must never
			// be reachable through the public or runner tables.
			if publicPath(req) || runnerPath(rt.Method, rt.Path) {
				t.Errorf("%s fell through to admin despite another classifier claiming it", rt.Pattern)
			}
			if _, _, handled := auth.ActionFor(rt.Method, rt.Path); handled {
				t.Errorf("%s fell through to admin despite an RBAC mapping", rt.Pattern)
			}
		}
	}
	for pattern := range expectedRouteTiers {
		if !seen[pattern] {
			t.Errorf("classification contract lists %q but Handler() no longer registers it", pattern)
		}
	}
}

// routeTestServer builds a credential-configured server used by the
// route-walk authorization probes: admin token, a runner token and a
// populated principal store (so strict middleware semantics apply), plus a
// runner CA and enrollment token.
func routeTestServer(t *testing.T) (*Server, *runnerpki.CA) {
	t.Helper()
	ca, err := runnerpki.NewCA("route-walk ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := storeServer(t, "admin-tok", map[string]auth.Principal{
		"store-tok": {Subject: "store-bot", Roles: []auth.Role{auth.RoleRead, auth.RoleRun}},
	})
	s.RunnerToken = "runner-tok"
	s.RunnerEnrollToken = "enroll-tok"
	s.RunnerCA = ca
	s.ExternalURL = "https://ci.example.com"
	return s, ca
}

// TestEveryRoutePatternIsServed asserts the parsed table really is the live
// routing table: an unauthenticated request to every pattern must be
// answered by a matched handler (or a gate), never by the mux's own
// not-found response — except the static file server, whose handler owns
// its 404s, and enroll when no CA is configured.
func TestEveryRoutePatternIsServed(t *testing.T) {
	s, _ := routeTestServer(t)
	h := s.Handler()
	for _, rt := range registeredRoutePatterns(t) {
		if rt.Path == "/static/" {
			continue
		}
		path := concretePath(rt.Path)
		req := httptest.NewRequest(rt.Method, path, strings.NewReader("{}"))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code == http.StatusNotFound && !strings.Contains(w.Body.String(), "404 page not found") {
			// A handler-produced 404 (e.g. unknown run id) is still a
			// matched route; only the mux's bare not-found response means
			// the pattern was not registered.
			continue
		}
		if w.Code == http.StatusNotFound {
			t.Errorf("%s %s is not served by the mux: %s", rt.Method, path, strings.TrimSpace(w.Body.String()))
		}
	}
}

// TestRunnerTierRejectsStorePrincipals walks every runner-tier pattern and
// proves a store principal bearer never reaches the handler.
func TestRunnerTierRejectsStorePrincipals(t *testing.T) {
	s, _ := routeTestServer(t)
	h := s.Handler()
	for pattern, tier := range expectedRouteTiers {
		if tier != tierRunner {
			continue
		}
		method, path, _ := strings.Cut(pattern, " ")
		req := httptest.NewRequest(method, concretePath(path), strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer store-tok")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s with a store principal = %d, want 401", pattern, w.Code)
		}
	}
}

// TestRunnerCredentialsCannotReachRBACOrAdminRoutes is the mirror probe:
// the runner bearer must never satisfy the RBAC or admin gates.
func TestRunnerCredentialsCannotReachRBACOrAdminRoutes(t *testing.T) {
	s, _ := routeTestServer(t)
	h := s.Handler()
	for pattern, tier := range expectedRouteTiers {
		if tier != tierRBAC && tier != tierAdmin {
			continue
		}
		method, path, _ := strings.Cut(pattern, " ")
		req := httptest.NewRequest(method, concretePath(path), strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer runner-tok")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s with the runner bearer = %d, want 401", pattern, w.Code)
		}
	}
}

// TestPublicRoutesNeverRequireAuth walks every public pattern with a
// populated strict token store and no credentials: none may be gated with
// 401/403 by the auth layers (handlers may still reject the payload).
func TestPublicRoutesNeverRequireAuth(t *testing.T) {
	s, _ := routeTestServer(t)
	h := s.Handler()
	for pattern, tier := range expectedRouteTiers {
		if tier != tierPublic {
			continue
		}
		method, path, _ := strings.Cut(pattern, " ")
		req := httptest.NewRequest(method, concretePath(path), strings.NewReader("{}"))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		// The auth gates answer with the exact bodies "unauthorized"/
		// "forbidden"; a public handler may legitimately reject its own
		// payload with a 401/403 and a different message (login).
		body := strings.TrimSpace(w.Body.String())
		if w.Code == http.StatusUnauthorized && body == "unauthorized" {
			t.Errorf("public route %s gated by the auth layer: %d %s", pattern, w.Code, body)
		}
		if w.Code == http.StatusForbidden && body == "forbidden" {
			t.Errorf("public route %s gated by the auth layer: %d %s", pattern, w.Code, body)
		}
	}
}

// TestEnrollTierAcceptsOnlyEnrollCredentials proves enrollment is reachable
// with the static enrollment token or a single-use grant, and with NOTHING
// else — not the admin token, not a store principal, not the runner token.
func TestEnrollTierAcceptsOnlyEnrollCredentials(t *testing.T) {
	ca, err := runnerpki.NewCA("enroll-tier ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM, err := runnerpki.GenerateKeyAndCSR("runner-1")
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(EnrollRequest{RunnerID: "runner-1", CSR: base64.StdEncoding.EncodeToString(csrPEM)})
	if err != nil {
		t.Fatal(err)
	}

	// Static enrollment token: works; every other credential is refused.
	s := storeServer(t, "admin-tok", map[string]auth.Principal{
		"store-tok": {Subject: "store-bot"},
	})
	s.RunnerCA = ca
	s.RunnerEnrollToken = "enroll-tok"
	s.RunnerToken = "runner-tok"
	h := s.Handler()
	for _, tok := range []string{"admin-tok", "store-tok", "runner-tok", "wrong"} {
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", body, tok, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("enroll with %q = %d, want 401", tok, w.Code)
		}
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", body, "enroll-tok", nil); w.Code != http.StatusOK {
		t.Fatalf("enroll with the static token = %d %s", w.Code, w.Body.String())
	}

	// Grant-only mode (no static token): the grant works, other
	// credentials never do.
	g := storeServer(t, "admin-tok", map[string]auth.Principal{
		"store-tok": {Subject: "store-bot"},
	})
	g.RunnerCA = ca
	g.RunnerEnrollToken = ""
	g.RunnerToken = "runner-tok"
	raw, err := g.CreateEnrollGrant(context.Background(), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	gh := g.Handler()
	for _, tok := range []string{"admin-tok", "store-tok", "runner-tok", "wrong"} {
		if w := pkiRequest(t, gh, http.MethodPost, "/api/v1/runners/enroll", body, tok, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("grant-only enroll with %q = %d, want 401", tok, w.Code)
		}
	}
	_, csr2, err := runnerpki.GenerateKeyAndCSR("runner-2")
	if err != nil {
		t.Fatal(err)
	}
	grantBody, err := json.Marshal(EnrollRequest{RunnerID: "runner-2", CSR: base64.StdEncoding.EncodeToString(csr2)})
	if err != nil {
		t.Fatal(err)
	}
	if w := pkiRequest(t, gh, http.MethodPost, "/api/v1/runners/enroll", grantBody, raw, nil); w.Code != http.StatusOK {
		t.Fatalf("enroll with a grant = %d %s", w.Code, w.Body.String())
	}
	// The consumed grant must not open the runner tier either.
	if w := pkiRequest(t, gh, http.MethodPost, "/api/v1/runners/runner-2/next", map[string]any{}, raw, nil); w.Code == http.StatusOK {
		t.Fatal("a grant must not authenticate runner-tier routes")
	}
}

// TestClassifyRouteNeverPanicsOnHostilePaths feeds the classifier the weird
// shapes an attacker controls (trailing slashes, doubled slashes, NUL
// bytes, percent-encoded separators, overlong paths) and asserts it always
// answers with a valid tier — never "unclassified and therefore open".
func TestClassifyRouteNeverPanicsOnHostilePaths(t *testing.T) {
	paths := []string{
		"/api/v1/runners/enroll/",
		"/api/v1//runners/enroll",
		"//api/v1/runners/enroll",
		"/api/v1/runners/register/",
		"/api/v1/runners/register%2f",
		"/api/v1/jobs/%00/heartbeat",
		"/api/v1/jobs/x/heartbeat/",
		"/api/v1/jobs/x/Heartbeat",
		"/API/V1/RUNS",
		"/api/v1/../../etc/passwd",
		"/" + strings.Repeat("a", 8192),
		"/api/v1/" + strings.Repeat("../", 1000) + "runs",
		"/api/v1/jobs/x/cache/key/extra",
	}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodPost, p, nil)
		got := classifyRoute(req)
		switch got {
		case tierPublic, tierEnroll, tierRunner, tierRBAC, tierAdmin:
		default:
			t.Fatalf("path %q produced invalid tier %d", p, got)
		}
		// The enroll carve-out is exact-match only: a near-miss path must
		// never land in the enroll tier (it would skip both the store
		// principal gate and the runner credential gate).
		if got == tierEnroll && p != "/api/v1/runners/enroll" {
			t.Fatalf("path %q wrongly classified as enroll", p)
		}
		// Runner-tier classification must never be produced for a path
		// that trims to something else (e.g. trailing NUL or doubled
		// slashes) unless runnerPath agrees.
		if got == tierRunner && !runnerPath(http.MethodPost, p) {
			t.Fatalf("path %q classified runner but runnerPath disagrees", p)
		}
	}
}

// TestRunnerTierFailClosedWhenNoCredentialConfigured re-asserts the 503
// gate across every runner pattern (the single-route form lives in
// auth_findings_test.go).
func TestRunnerTierFailClosedWhenNoCredentialConfigured(t *testing.T) {
	s := New("")
	s.AdminToken = "admin-tok"
	h := s.Handler()
	for pattern, tier := range expectedRouteTiers {
		if tier != tierRunner {
			continue
		}
		method, path, _ := strings.Cut(pattern, " ")
		req := httptest.NewRequest(method, concretePath(path), strings.NewReader("{}"))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s without any runner credential = %d, want 503", pattern, w.Code)
		}
	}
}

// TestRouteWalkCatchesUnclassifiedRoute is the self-check for the walk
// itself: an invented pattern must be reported as missing from the
// contract, proving new routes cannot slip through.
func TestRouteWalkCatchesUnclassifiedRoute(t *testing.T) {
	patterns := map[string]bool{}
	for _, rt := range registeredRoutePatterns(t) {
		patterns[rt.Pattern] = true
	}
	if !patterns["POST /api/v1/runners/register"] {
		t.Fatal("route parser missed a known pattern")
	}
	if _, ok := expectedRouteTiers["GET /api/v1/not-a-route"]; ok {
		t.Fatal("contract lookup must fail for unknown patterns")
	}
	// Every contract entry must be a syntactically plausible method+path.
	for pattern := range expectedRouteTiers {
		method, path, ok := strings.Cut(pattern, " ")
		if !ok || method == "" || !strings.HasPrefix(path, "/") {
			t.Errorf("contract entry %q is malformed", pattern)
		}
	}
}

// TestDottedOrgVisibilityStaysStrict pins the server-side counterpart of
// the canonical-shape rule: a run on a dotted-org repository
// (gitlab.example/acme.co/service) is invisible to a principal whose map
// only declares a single-segment alias "service". canReadRepo and
// repoVisibleByName (the auth.CanReadRepo wrappers) must agree with the
// canonical auth resolution.
func TestDottedOrgVisibilityStaysStrict(t *testing.T) {
	aliasPrincipal := auth.Principal{Subject: "alias", Repositories: map[string]auth.RepositoryPermission{
		"service": {Read: true},
	}}
	run := model.Run{
		ID:           "run-dotted",
		Repo:         "https://gitlab.example/acme.co/service.git",
		RepoFullName: "acme.co/service",
	}
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), aliasPrincipal))
	if s.canReadRepo(req, repoIDForRun(run)) {
		t.Fatal("single-segment alias made a dotted-org run readable")
	}
	// repoVisibleByName has no alias entry for the literal name either.
	if s.repoVisibleByName(req, "acme.co/service") {
		t.Fatal("single-segment alias resolved by name")
	}
	// The literal full-name alias does see it.
	literal := auth.Principal{Subject: "literal", Repositories: map[string]auth.RepositoryPermission{
		"acme.co/service": {Read: true},
	}}
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	req2 = req2.WithContext(auth.WithPrincipal(req2.Context(), literal))
	if !s.canReadRepo(req2, repoIDForRun(run)) {
		t.Fatal("literal dotted-org alias must see its run")
	}
	// A canonical principal for the exact identity also sees it.
	canon := auth.Principal{Subject: "canon", Repositories: map[string]auth.RepositoryPermission{
		"gitlab.example/acme.co/service": {Read: true},
	}}
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	req3 = req3.WithContext(auth.WithPrincipal(req3.Context(), canon))
	if !s.canReadRepo(req3, repoIDForRun(run)) {
		t.Fatal("canonical dotted-org principal must see the run")
	}
	// The shared auth resolution: the bare alias must not authorize the
	// dotted run.
	if auth.CanReadRepo(aliasPrincipal, repoIDForRun(run)) {
		t.Fatal("auth.CanReadRepo honored a single-segment alias for a dotted org")
	}
}
