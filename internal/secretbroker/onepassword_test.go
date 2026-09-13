package secretbroker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOnePasswordResolve(t *testing.T) {
	var gotPath, gotAuth, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"abc","title":"CI","fields":[{"id":"password","label":"password","value":"op-secret"}]}`))
	}))
	defer srv.Close()

	c := &OnePasswordClient{Host: srv.URL, Token: "op-token", VaultID: "vault-1"}
	v, err := c.Resolve(context.Background(), "ci item", SecretScope{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "op-secret" {
		t.Fatalf("got %q", v)
	}
	if gotPath != "/v1/vaults/vault-1/items/ci item" {
		t.Fatalf("path %q", gotPath)
	}
	if gotAuth != "Bearer op-token" {
		t.Fatalf("auth %q", gotAuth)
	}
	if gotQuery != "fields=password" {
		t.Fatalf("query %q", gotQuery)
	}
}

func TestOnePasswordResolveEmptyFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"id":"abc","fields":[]}`))
	}))
	defer srv.Close()

	c := &OnePasswordClient{Host: srv.URL, Token: "t", VaultID: "v"}
	if _, err := c.Resolve(context.Background(), "item", SecretScope{}); err == nil {
		t.Fatal("expected error for empty fields")
	}
}

func TestOnePasswordResolveErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := &OnePasswordClient{Host: srv.URL, Token: "bad", VaultID: "v"}
	if _, err := c.Resolve(context.Background(), "item", SecretScope{}); err == nil {
		t.Fatal("expected 401 error")
	}
}

func TestOnePasswordResolveSingleValueFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"value":"plain-value"}`))
	}))
	defer srv.Close()

	c := &OnePasswordClient{Host: srv.URL, Token: "t", VaultID: "v"}
	v, err := c.Resolve(context.Background(), "item", SecretScope{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "plain-value" {
		t.Fatalf("got %q", v)
	}
}
