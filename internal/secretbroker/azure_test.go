package secretbroker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAzureResolve(t *testing.T) {
	var tokenForm urlValues
	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		tokenForm = urlValues{
			grantType:    r.PostForm.Get("grant_type"),
			clientID:     r.PostForm.Get("client_id"),
			clientSecret: r.PostForm.Get("client_secret"),
			scope:        r.PostForm.Get("scope"),
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"az-token","token_type":"Bearer"}`))
	}))
	defer oauth.Close()

	var gotAuth, gotQuery string
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotQuery = r.URL.RawQuery
		if r.URL.Path != "/secrets/db-password" {
			t.Errorf("path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"value":"azure-secret"}`))
	}))
	defer vault.Close()

	c := &AzureClient{
		TenantID:     "tenant-1",
		ClientID:     "client-1",
		ClientSecret: "client-secret-1",
		VaultURL:     vault.URL,
		TokenURL:     oauth.URL,
	}
	v, err := c.Resolve(context.Background(), "db-password", SecretScope{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "azure-secret" {
		t.Fatalf("got %q", v)
	}
	if gotAuth != "Bearer az-token" {
		t.Fatalf("vault auth %q", gotAuth)
	}
	if gotQuery != "api-version=7.4" {
		t.Fatalf("query %q", gotQuery)
	}
	if tokenForm.grantType != "client_credentials" ||
		tokenForm.clientID != "client-1" ||
		tokenForm.clientSecret != "client-secret-1" ||
		tokenForm.scope != "https://vault.azure.net/.default" {
		t.Fatalf("token form %+v", tokenForm)
	}
}

type urlValues struct {
	grantType    string
	clientID     string
	clientSecret string
	scope        string
}

func TestAzureResolveDefaultTokenURL(t *testing.T) {
	c := &AzureClient{TenantID: "t", ClientID: "c", ClientSecret: "s", VaultURL: "https://vault.example.com"}
	if got := c.tokenURL(); got != "https://login.microsoftonline.com/t/oauth2/v2.0/token" {
		t.Fatalf("token URL %q", got)
	}
}

func TestAzureResolveTokenErrorStatus(t *testing.T) {
	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
	}))
	defer oauth.Close()

	c := &AzureClient{
		TenantID:     "t",
		ClientID:     "c",
		ClientSecret: "s",
		VaultURL:     "https://vault.example.com",
		TokenURL:     oauth.URL,
	}
	if _, err := c.Resolve(context.Background(), "x", SecretScope{}); err == nil {
		t.Fatal("expected token error")
	} else if !strings.Contains(err.Error(), "token status") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAzureResolveVaultErrorStatus(t *testing.T) {
	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"t"}`))
	}))
	defer oauth.Close()
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer vault.Close()

	c := &AzureClient{
		TenantID: "t", ClientID: "c", ClientSecret: "s",
		VaultURL: vault.URL, TokenURL: oauth.URL,
	}
	if _, err := c.Resolve(context.Background(), "x", SecretScope{}); err == nil {
		t.Fatal("expected vault error")
	}
}

func TestAzureResolveEmptyValue(t *testing.T) {
	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"t"}`))
	}))
	defer oauth.Close()
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer vault.Close()

	c := &AzureClient{
		TenantID: "t", ClientID: "c", ClientSecret: "s",
		VaultURL: vault.URL, TokenURL: oauth.URL,
	}
	if _, err := c.Resolve(context.Background(), "x", SecretScope{}); err == nil {
		t.Fatal("expected empty value error")
	}
}
