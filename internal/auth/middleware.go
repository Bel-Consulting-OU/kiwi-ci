package auth

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
)

type principalContextKey struct{}

// WithPrincipal returns a context carrying the authenticated principal.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}

// PrincipalFrom returns the principal bound by Middleware, if any.
func PrincipalFrom(r *http.Request) (Principal, bool) {
	p, ok := r.Context().Value(principalContextKey{}).(Principal)
	return p, ok
}

// AdminPrincipal is the identity used for the legacy admin-token mode: a
// request whose bearer matches the admin token acts as subject "admin"
// with the admin role.
func AdminPrincipal() Principal {
	return Principal{Subject: "admin", Roles: []Role{RoleAdmin}}
}

// Middleware authenticates bearer tokens and binds the resulting principal
// to the request context. It deliberately does not decide authorization for
// routes (the server's auth() classifies routes and requireAction enforces
// per-action roles); its only gate is authentication strictness:
//
//   - a valid store token yields the stored principal;
//   - a valid admin-token bearer yields AdminPrincipal (both when a store
//     is configured and in legacy token-only mode);
//   - when the store has tokens, requests without a valid token or admin
//     bearer are rejected with 401 and logged;
//   - with no store tokens configured (legacy mode) requests pass through
//     without a principal; the server's auth() enforces the bearer check.
//
// The request ID survives untouched; 401s are logged with it for
// correlation.
func Middleware(store *TokenStore, adminToken string, next http.Handler, logger func(string, ...any)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r) {
			next.ServeHTTP(w, r)
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token != "" && store != nil {
			if p, ok := store.Authenticate(token); ok {
				next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
				return
			}
		}
		if adminToken != "" && token != "" && tokenMatches(token, adminToken) {
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), AdminPrincipal())))
			return
		}
		if store != nil && !store.Empty() {
			if logger != nil {
				logger("auth: unauthorized method=%s path=%s request_id=%s", r.Method, r.URL.Path, requestIDFrom(r))
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// PublicRoute is the single route classifier shared by the auth middleware
// and the server's tier classification (internal/server/tiers.go): it
// reports whether a request needs no bearer-token/store-principal
// authentication at the auth layer. The shared table covers webhook intake,
// the dashboard and its assets, login/logout, OIDC discovery/JWKS/token
// issuance, the health endpoints, and runner enrollment (which
// authenticates with the enrollment token/grant inside the server's own
// tier gate instead of a store principal). /metrics stays admin-tier:
// operational state is not public.
func PublicRoute(method, path string) bool {
	if strings.HasPrefix(path, "/hooks/") ||
		path == "/" ||
		strings.HasPrefix(path, "/static/") ||
		path == "/api/v1/login" ||
		path == "/api/v1/logout" ||
		path == "/readiness" ||
		path == "/liveness" ||
		path == "/.well-known/openid-configuration" ||
		path == "/api/v1/oidc/jwks" {
		return true
	}
	// The job OIDC issuance endpoint is public at the auth layer because it
	// authenticates with the lease token embedded in the body.
	if method == http.MethodPost && strings.HasSuffix(path, "/oidc") {
		return true
	}
	// Runner enrollment is public to the middleware (the enrollment
	// token/grant is not a store principal); the server's auth() tier gate
	// authenticates it.
	if method == http.MethodPost && path == "/api/v1/runners/enroll" {
		return true
	}
	return false
}

// isPublicPath delegates to the shared PublicRoute classifier so strict
// token-store mode does not lock out forge webhooks, the dashboard, health
// probes or enrollment. Authorization for these paths is enforced by the
// server's auth() chain.
func isPublicPath(r *http.Request) bool {
	return PublicRoute(r.Method, r.URL.Path)
}

func tokenMatches(got, want string) bool {
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func requestIDFrom(r *http.Request) string {
	if id := r.Header.Get("X-Kiwi-Request-ID"); id != "" {
		return id
	}
	return "-"
}
