package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// floorStore overrides the fake store's schema floor (and read error) for
// gate tests.
type floorStore struct {
	*dbFakeStore
	floor int
	err   error
}

func (f *floorStore) SchemaCompatibilityFloor(context.Context) (int, error) {
	return f.floor, f.err
}

func testClientWithFloor(t *testing.T, floor int, ferr error) (*Server, *testClient) {
	t.Helper()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(&floorStore{dbFakeStore: newDBFakeStore(), floor: floor, err: ferr}); err != nil {
		t.Fatal(err)
	}
	return s, &testClient{t: t, h: s.Handler()}
}

func submitBody() map[string]any {
	return map[string]any{"repo_url": "https://github.com/o/r.git", "repo_full_name": "o/r",
		"ref": "refs/heads/main", "pipeline": "version: 1\njobs:\n  a:\n    steps:\n      - run: echo hi\n"}
}

// TestSchemaFloorMutationFence: every DB mutation surface refuses while the
// floor is incompatible — readiness-based LB removal is not a boundary.
func TestSchemaFloorMutationFence(t *testing.T) {
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	s, c := testClientWithFloor(t, maxV+1, nil)
	s.GitHubWebhookSecret = "hunter2"
	auth := map[string]string{"Authorization": "Bearer token"}
	for name, req := range map[string]struct {
		method, path string
		body         any
	}{
		"submit":      {http.MethodPost, "/api/v1/runs", submitBody()},
		"schedule":    {http.MethodPost, "/api/v1/schedules/x/trigger", map[string]any{}},
		"login":       {http.MethodPost, "/api/v1/login", map[string]any{"token": "token"}},
		"runner next": {http.MethodPost, "/api/v1/runners/ghost/next", map[string]any{}},
	} {
		w := c.do(req.method, req.path, req.body, auth)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s = %d, want 503 (schema fence): %s", name, w.Code, w.Body.String())
		}
		if w.Header().Get("X-Kiwi-State") != "schema-incompatible" {
			t.Fatalf("%s missing schema-incompatible state header", name)
		}
	}
	// A webhook with no valid HMAC is rejected by its own authentication
	// BEFORE the fence (see the deferred-auth tests below): it must not be a
	// 503 here.
	if w := c.do(http.MethodPost, "/hooks/github", map[string]any{}, nil); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("unsigned webhook = %d, want 401/403 before the schema fence", w.Code)
	}
	// Reads stay reachable so orchestration can observe the state.
	if w := c.do(http.MethodGet, "/api/v1/runs", nil, auth); w.Code == http.StatusServiceUnavailable {
		t.Fatalf("reads must not be fenced: %d", w.Code)
	}
}

// TestSchemaFloorReadFailureFailsClosed: an unreadable floor is NOT
// "compatible": readiness 503 and every mutation refused.
func TestSchemaFloorReadFailureFailsClosed(t *testing.T) {
	s, c := testClientWithFloor(t, 0, errors.New("permission denied for column compatible_from"))
	_ = s
	if w := c.do(http.MethodGet, "/readiness", nil, nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness with an unreadable floor = %d, want 503", w.Code)
	}
	auth := map[string]string{"Authorization": "Bearer token"}
	if w := c.do(http.MethodPost, "/api/v1/runs", submitBody(), auth); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("submit with an unreadable floor = %d, want 503", w.Code)
	}
	if w := c.do(http.MethodPost, "/api/v1/runners/ghost/next", map[string]any{}, auth); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("next with an unreadable floor = %d, want 503", w.Code)
	}
}

// TestCompatibleFloorIsNeverCachedAcrossAnIncompatibleMigration: a replica
// that observed the pre-migration floor must refuse immediately after the
// floor advances — no positive cache window.
func TestCompatibleFloorIsNeverCachedAcrossAnIncompatibleMigration(t *testing.T) {
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	fs := &floorStore{dbFakeStore: newDBFakeStore(), floor: maxV}
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(fs); err != nil {
		t.Fatal(err)
	}
	c := &testClient{t: t, h: s.Handler()}
	auth := map[string]string{"Authorization": "Bearer token"}
	if w := c.do(http.MethodGet, "/readiness", nil, nil); w.Code != http.StatusOK {
		t.Fatalf("pre-migration readiness = %d", w.Code)
	}
	// The newer replica commits its migration.
	fs.floor = maxV + 1
	// The very next mutation must be refused.
	if w := c.do(http.MethodPost, "/api/v1/runs", submitBody(), auth); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("submit after the floor advanced = %d, want 503 (positive cache window)", w.Code)
	}
	if w := c.do(http.MethodGet, "/readiness", nil, nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness after the floor advanced = %d, want 503", w.Code)
	}
}

// countingFloorStore counts compatibility-floor reads.
type countingFloorStore struct {
	*floorStore
	reads atomic.Int32
}

func (c *countingFloorStore) SchemaCompatibilityFloor(ctx context.Context) (int, error) {
	c.reads.Add(1)
	return c.floorStore.SchemaCompatibilityFloor(ctx)
}

// TestSchemaFenceRunsAfterAuth: an unauthenticated mutation must be rejected
// by authentication BEFORE the fence can issue a database compatibility
// query — otherwise the fence is an anonymous DB-amplification endpoint.
func TestSchemaFenceRunsAfterAuth(t *testing.T) {
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	fs := &countingFloorStore{floorStore: &floorStore{dbFakeStore: newDBFakeStore(), floor: maxV}}
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(fs); err != nil {
		t.Fatal(err)
	}
	c := &testClient{t: t, h: s.Handler()}
	w := c.do(http.MethodPost, "/api/v1/runs", submitBody(), map[string]string{"Authorization": "Bearer wrong-token"})
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("invalid bearer = %d, want 401/403", w.Code)
	}
	if fs.reads.Load() != 0 {
		t.Fatalf("unauthenticated request triggered %d schema floor read(s)", fs.reads.Load())
	}
	// A valid mutation does read the floor (and passes). The pipeline must be
	// untrusted-admissible, so use a digest-pinned container job.
	container := map[string]any{"repo_url": "https://github.com/o/r.git", "repo_full_name": "o/r",
		"ref": "refs/heads/main",
		"pipeline": "version: 1\njobs:\n  a:\n    runtime: container\n" +
			"    image: alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc\n" +
			"    steps:\n      - run: echo hi\n"}
	w = c.do(http.MethodPost, "/api/v1/runs", container, map[string]string{"Authorization": "Bearer token"})
	if w.Code != http.StatusAccepted {
		t.Fatalf("valid submit = %d: %s", w.Code, w.Body.String())
	}
	if fs.reads.Load() == 0 {
		t.Fatal("authenticated mutation did not verify schema compatibility")
	}
}

// countingFloorServer builds a server whose compatibility-floor store counts
// every read, plus its test client.
func countingFloorServer(t *testing.T, floor int) (*Server, *countingFloorStore, *testClient) {
	t.Helper()
	fs := &countingFloorStore{floorStore: &floorStore{dbFakeStore: newDBFakeStore(), floor: floor}}
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(fs); err != nil {
		t.Fatal(err)
	}
	return s, fs, &testClient{t: t, h: s.Handler()}
}

// TestSchemaFloorDeferredAuthPathsSkipFenceReads: the tierPublic routes whose
// authentication lives in the handler (webhook HMAC, job lease token, session
// cookie) must reject invalid credentials WITHOUT a compatibility-floor read;
// the middleware defers to the handler's post-auth requireSchemaCompatible.
func TestSchemaFloorDeferredAuthPathsSkipFenceReads(t *testing.T) {
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	s, fs, c := countingFloorServer(t, maxV+1)
	s.GitHubWebhookSecret = "hunter2"
	s.ExternalURL = "https://ci.example.com"

	// Invalid HMAC webhook: 401 before any floor read.
	w := c.do(http.MethodPost, "/hooks/github", []byte(`{"zen":"ok"}`), map[string]string{
		"X-Hub-Signature-256": "sha256=" + strings.Repeat("0", 64),
		"X-GitHub-Event":      "ping",
	})
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("invalid HMAC webhook = %d, want 401/403", w.Code)
	}
	if fs.reads.Load() != 0 {
		t.Fatalf("invalid HMAC webhook triggered %d schema floor read(s)", fs.reads.Load())
	}

	// Missing lease token on the job OIDC route: 401, no floor read.
	w = c.do(http.MethodPost, "/api/v1/jobs/"+pgJobID(t)+"/oidc", map[string]any{"audience": "aud"}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("OIDC without a lease token = %d, want 401: %s", w.Code, w.Body.String())
	}
	if fs.reads.Load() != 0 {
		t.Fatalf("OIDC without a lease token triggered %d schema floor read(s)", fs.reads.Load())
	}
	// A syntactically invalid lease token for an unknown job: 404/401, and
	// still no floor read.
	w = c.do(http.MethodPost, "/api/v1/jobs/"+pgJobID(t)+"/oidc", map[string]any{"audience": "aud"},
		map[string]string{"Authorization": "Bearer not-a-lease-token"})
	if w.Code != http.StatusNotFound && w.Code != http.StatusUnauthorized {
		t.Fatalf("OIDC with an invalid lease = %d, want 401/404: %s", w.Code, w.Body.String())
	}
	if fs.reads.Load() != 0 {
		t.Fatalf("OIDC with an invalid lease triggered %d schema floor read(s)", fs.reads.Load())
	}

	// Logout without a session cookie: 403, no floor read.
	w = c.do(http.MethodPost, "/api/v1/logout", map[string]any{}, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("logout without a session = %d, want 403", w.Code)
	}
	if fs.reads.Load() != 0 {
		t.Fatalf("logout without a session triggered %d schema floor read(s)", fs.reads.Load())
	}

	// Login with a wrong admin token: 401, no floor read.
	w = c.do(http.MethodPost, "/api/v1/login", map[string]any{"token": "wrong"}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("login with a wrong token = %d, want 401", w.Code)
	}
	if fs.reads.Load() != 0 {
		t.Fatalf("failed login triggered %d schema floor read(s)", fs.reads.Load())
	}
}

// pgJobID returns a job-shaped synthetic ID for route probes.
func pgJobID(t *testing.T) string {
	t.Helper()
	return strings.Repeat("a", 32)
}

// TestSchemaFloorValidWebhookSignatureRunsFence: a valid HMAC passes the
// handler's authentication and THEN runs the compatibility gate (the read
// happens) before the request proceeds.
func TestSchemaFloorValidWebhookSignatureRunsFence(t *testing.T) {
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	s, fs, c := countingFloorServer(t, maxV)
	s.GitHubWebhookSecret = "hunter2"
	body := []byte(`{"zen":"ok"}`)
	w := c.do(http.MethodPost, "/hooks/github", body, map[string]string{
		"X-Hub-Signature-256": signGitHubPayload("hunter2", body),
		"X-GitHub-Event":      "ping",
	})
	if w.Code != http.StatusNoContent {
		t.Fatalf("valid signed ping = %d, want 204: %s", w.Code, w.Body.String())
	}
	if fs.reads.Load() == 0 {
		t.Fatal("authenticated webhook did not verify schema compatibility")
	}
}

// TestSchemaFloorValidLoginRunsFence: a valid admin-token login passes the
// constant-time compare and THEN runs the compatibility gate, which refuses
// with the shared 503 when the floor is incompatible.
func TestSchemaFloorValidLoginRunsFence(t *testing.T) {
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	s, fs, c := countingFloorServer(t, maxV+1)
	_ = s
	w := c.do(http.MethodPost, "/api/v1/login", map[string]any{"token": "token"}, nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("valid login with an incompatible floor = %d, want 503: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Kiwi-State"); got != "schema-incompatible" {
		t.Fatalf("login refusal missing schema-incompatible state header: %q", got)
	}
	if fs.reads.Load() == 0 {
		t.Fatal("authenticated login did not verify schema compatibility")
	}
}

// TestSchemaFloorAuthenticatedMutationStillFenced: the deferred-path split
// must not disable the fence for ordinary authenticated mutations.
func TestSchemaFloorAuthenticatedMutationStillFenced(t *testing.T) {
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	_, _, c := countingFloorServer(t, maxV+1)
	w := c.do(http.MethodPost, "/api/v1/runs", submitBody(), map[string]string{"Authorization": "Bearer token"})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("authenticated submit with an incompatible floor = %d, want 503: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Kiwi-State"); got != "schema-incompatible" {
		t.Fatalf("submit refusal missing schema-incompatible state header: %q", got)
	}
}

// TestSchemaFenceDeferredPathExactRouteShapes pins the shared predicate: only
// the exact tierPublic deferred-auth route shapes are exempt, never a
// lookalike path that merely shares a suffix or prefix.
func TestSchemaFenceDeferredPathExactRouteShapes(t *testing.T) {
	cases := []struct {
		method, path string
		want         bool
	}{
		{http.MethodPost, "/hooks/github", true},
		{http.MethodPost, "/hooks/gitlab", true},
		{http.MethodPost, "/hooks/forgejo", true},
		{http.MethodPost, "/api/v1/login", true},
		{http.MethodPost, "/api/v1/logout", true},
		{http.MethodPost, "/api/v1/jobs/abc123/oidc", true},
		{http.MethodPost, "/api/v1/jobs/job-with-dashes/oidc", true},
		{http.MethodGet, "/api/v1/jobs/abc123/oidc", false},
		{http.MethodPut, "/api/v1/jobs/abc123/oidc", false},
		{http.MethodPost, "/api/v1/jobs/abc123/oidc/", false},
		{http.MethodPost, "/api/v1/jobs/a/b/oidc", false},
		{http.MethodPost, "/api/v1/jobs//oidc", false},
		{http.MethodPost, "/api/v1/admin/foo/oidc", false},
		{http.MethodPost, "/api/v1/oidc", false},
		{http.MethodPost, "/api/v1/runners/enroll", false},
		{http.MethodPost, "/api/v1/not-login", false},
		{http.MethodGet, "/hooks/github", false},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		if got := schemaFenceDeferredPath(req); got != tc.want {
			t.Errorf("schemaFenceDeferredPath(%s %s) = %v, want %v", tc.method, tc.path, got, tc.want)
		}
		// Cross-check the auth layer's public classifier: every deferred path
		// must still be a public (no store-principal) route, so the two route
		// sets cannot drift apart silently.
		if tc.want && !auth.PublicRoute(tc.method, tc.path) {
			t.Errorf("%s %s is deferred by the schema fence but auth.PublicRoute disagrees", tc.method, tc.path)
		}
	}
}
