package auth

// E5-G: the public-route classifier must match the EXACT job OIDC issuance
// route shape POST /api/v1/jobs/{id}/oidc, never any path that merely ends in
// /oidc. A suffix match would silently exempt a future route such as
// /api/v1/admin/foo/oidc from store-principal authentication.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestE5OIDCPublicRouteExactShape(t *testing.T) {
	public := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/jobs/abc123/oidc"},
		{http.MethodPost, "/api/v1/jobs/job-with-dashes/oidc"},
	}
	for _, tc := range public {
		if !PublicRoute(tc.method, tc.path) {
			t.Fatalf("PublicRoute(%s, %s) = false, want the real issuance route public", tc.method, tc.path)
		}
	}
	notPublic := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/admin/foo/oidc"},
		{http.MethodPost, "/api/v1/oidc"},
		{http.MethodPost, "/oidc"},
		{http.MethodPost, "/api/v1/jobs/a/b/oidc"},
		{http.MethodPost, "/api/v1/jobs//oidc"},
		{http.MethodPost, "/api/v1/jobs/abc123/oidc/"},
		{http.MethodGet, "/api/v1/jobs/abc123/oidc"},
		{http.MethodPut, "/api/v1/jobs/abc123/oidc"},
	}
	for _, tc := range notPublic {
		if PublicRoute(tc.method, tc.path) {
			t.Fatalf("PublicRoute(%s, %s) = true, want it to require authentication", tc.method, tc.path)
		}
	}
}

// TestE5OIDCRouteShapeThroughMiddleware proves the classifier decision reaches
// the request path: with a non-empty token store, the admin lookalike route is
// rejected 401 while the real issuance route passes through to the server's
// tier gate.
func TestE5OIDCRouteShapeThroughMiddleware(t *testing.T) {
	store := NewTokenStore()
	if err := store.AddToken("tok", Principal{Subject: "alice", Roles: []Role{RoleRead}}); err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	mw := Middleware(store, "", next, nil)

	serve := func(method, path string) int {
		req := httptest.NewRequest(method, path, nil)
		w := httptest.NewRecorder()
		mw.ServeHTTP(w, req)
		return w.Code
	}
	if got := serve(http.MethodPost, "/api/v1/jobs/job-1/oidc"); got != http.StatusTeapot {
		t.Fatalf("real issuance route = %d, want it to pass the middleware (418)", got)
	}
	if got := serve(http.MethodPost, "/api/v1/admin/foo/oidc"); got != http.StatusUnauthorized {
		t.Fatalf("lookalike /oidc route = %d, want 401 (never public)", got)
	}
}
