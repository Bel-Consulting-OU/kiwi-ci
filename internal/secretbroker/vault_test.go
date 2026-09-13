package secretbroker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVaultResolve(t *testing.T) {
	var gotPath, gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotToken = r.Header.Get("X-Vault-Token")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"data":{"value":"vault-secret"}}}`))
	}))
	defer srv.Close()

	c := &VaultClient{Address: srv.URL, Token: "s.token"}
	v, err := c.Resolve(context.Background(), "ci/token", SecretScope{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "vault-secret" {
		t.Fatalf("got %q", v)
	}
	if gotPath != "/v1/secret/data/ci/token" {
		t.Fatalf("path %q", gotPath)
	}
	if gotToken != "s.token" {
		t.Fatalf("token header %q", gotToken)
	}
}

func TestVaultResolveFallsBackToFirstKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"data":{"password":"first-key-value","other":"x"}}}`))
	}))
	defer srv.Close()

	c := &VaultClient{Address: srv.URL}
	v, err := c.Resolve(context.Background(), "db", SecretScope{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "first-key-value" {
		t.Fatalf("got %q", v)
	}
}

func TestVaultResolveEmptyData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"data":{}}}`))
	}))
	defer srv.Close()

	c := &VaultClient{Address: srv.URL}
	if _, err := c.Resolve(context.Background(), "db", SecretScope{}); err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestVaultRejectsRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/redirect") {
			http.Redirect(w, r, "/real", http.StatusFound)
			return
		}
		w.Write([]byte(`{"data":{"data":{"value":"x"}}}`))
	}))
	defer srv.Close()

	c := &VaultClient{Address: srv.URL}
	if _, err := c.Resolve(context.Background(), "redirect", SecretScope{}); err == nil {
		t.Fatal("expected redirect rejection")
	} else if !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVaultRejectsNonLoopbackHTTP(t *testing.T) {
	c := &VaultClient{Address: "http://vault.example.com:8200"}
	if _, err := c.Resolve(context.Background(), "x", SecretScope{}); err == nil {
		t.Fatal("expected rejection of non-loopback http address")
	} else if !strings.Contains(err.Error(), "insecure") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVaultAllowsLoopbackHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"data":{"value":"ok"}}}`))
	}))
	defer srv.Close()

	c := &VaultClient{Address: srv.URL}
	v, err := c.Resolve(context.Background(), "x", SecretScope{})
	if err != nil {
		t.Fatalf("loopback http should be allowed: %v", err)
	}
	if v != "ok" {
		t.Fatalf("got %q", v)
	}
}

func TestVaultRejectsBadScheme(t *testing.T) {
	c := &VaultClient{Address: "ftp://vault.example.com"}
	if _, err := c.Resolve(context.Background(), "x", SecretScope{}); err == nil {
		t.Fatal("expected scheme rejection")
	}
}

func TestVaultErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "permission denied", http.StatusForbidden)
	}))
	defer srv.Close()

	c := &VaultClient{Address: srv.URL}
	if _, err := c.Resolve(context.Background(), "x", SecretScope{}); err == nil {
		t.Fatal("expected error for 403")
	}
}
