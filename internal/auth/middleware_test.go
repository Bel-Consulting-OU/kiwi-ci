package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMiddlewareNoTokenUnauthorized(t *testing.T) {
	store := NewTokenStore()
	if err := store.AddToken("store-token", Principal{Subject: "bot", Roles: []Role{RoleRun}}); err != nil {
		t.Fatal(err)
	}
	called := false
	h := Middleware(store, "admin-token", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runs", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401 got %d", w.Code)
	}
	if called {
		t.Fatal("handler must not run for unauthenticated request")
	}
}

func TestMiddlewareBadTokenUnauthorized(t *testing.T) {
	store := NewTokenStore()
	if err := store.AddToken("store-token", Principal{Subject: "bot", Roles: []Role{RoleRun}}); err != nil {
		t.Fatal(err)
	}
	called := false
	h := Middleware(store, "admin-token", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runs", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: want 401 got %d", w.Code)
	}
	if called {
		t.Fatal("handler must not run for bad token")
	}
}

func TestMiddlewareValidTokenSetsPrincipal(t *testing.T) {
	store := NewTokenStore()
	want := Principal{Subject: "ci-bot", Roles: []Role{RoleRun}}
	if err := store.AddToken("store-token", want); err != nil {
		t.Fatal(err)
	}
	var got Principal
	var ok bool
	h := Middleware(store, "admin-token", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok = PrincipalFrom(r)
	}), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runs", nil)
	req.Header.Set("Authorization", "Bearer store-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("valid token: want 200 got %d", w.Code)
	}
	if !ok || got.Subject != "ci-bot" || !got.Has(RoleRun) {
		t.Fatalf("principal not bound: ok=%v %+v", ok, got)
	}
}

func TestMiddlewareAdminTokenFallback(t *testing.T) {
	store := NewTokenStore()
	var got Principal
	var ok bool
	h := Middleware(store, "admin-token", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok = PrincipalFrom(r)
	}), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("admin bearer: want 200 got %d", w.Code)
	}
	if !ok || got.Subject != "admin" || !got.Has(RoleAdmin) {
		t.Fatalf("admin fallback principal wrong: ok=%v %+v", ok, got)
	}
}

func TestMiddlewareStoreMatchWinsOverAdminToken(t *testing.T) {
	store := NewTokenStore()
	if err := store.AddToken("shared-token", Principal{Subject: "bot", Roles: []Role{RoleRun}}); err != nil {
		t.Fatal(err)
	}
	// A store token with the same value as the admin token yields the store
	// principal: store authentication is attempted first.
	if err := store.AddToken("admin-token", Principal{Subject: "bot2", Roles: []Role{RoleRun}}); err != nil {
		t.Fatal(err)
	}
	var got Principal
	h := Middleware(store, "admin-token", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = PrincipalFrom(r)
	}), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || got.Subject != "bot2" {
		t.Fatalf("store match must yield the stored principal: %d %+v", w.Code, got)
	}
}

func TestMiddlewareLegacyModePassthrough(t *testing.T) {
	// Empty store + no admin token: requests pass through with no
	// principal; the server's auth() is the gate in this mode.
	store := NewTokenStore()
	var got Principal
	var ok bool
	h := Middleware(store, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok = PrincipalFrom(r)
	}), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("legacy passthrough: want 200 got %d", w.Code)
	}
	if ok {
		t.Fatalf("no principal expected, got %+v", got)
	}
}

func TestMiddlewareLogsRequestIDOn401(t *testing.T) {
	store := NewTokenStore()
	if err := store.AddToken("store-token", Principal{Subject: "bot"}); err != nil {
		t.Fatal(err)
	}
	var logged []string
	h := Middleware(store, "admin-token", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) })
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	req.Header.Set("X-Kiwi-Request-ID", "req-abc-123")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 got %d", w.Code)
	}
	found := false
	for _, line := range logged {
		if strings.Contains(line, "req-abc-123") {
			found = true
		}
	}
	if !found {
		t.Fatalf("401 not logged with request id: %v", logged)
	}
}
