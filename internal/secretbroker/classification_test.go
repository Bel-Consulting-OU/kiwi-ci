package secretbroker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func assertClass(t *testing.T, err error, want error, label string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: err = %v, want %v", label, err, want)
	}
}

// TestVaultStatusClassification pins the Vault HTTP-status mapping, the
// permission-marker upgrade on 400, malformed bodies, redirects, and body
// redaction.
func TestVaultStatusClassification(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusNotFound, `{"errors":["missing provider-body-marker"]}`, ErrSecretNotFound},
		{http.StatusUnauthorized, `{"errors":["invalid token provider-body-marker"]}`, ErrUnauthorized},
		{http.StatusForbidden, `{"errors":["permission denied provider-body-marker"]}`, ErrForbidden},
		{http.StatusTooManyRequests, `{"errors":["too many requests provider-body-marker"]}`, ErrUnavailable},
		{http.StatusInternalServerError, `{"errors":["internal provider-body-marker"]}`, ErrUnavailable},
		{http.StatusServiceUnavailable, `provider-body-marker`, ErrUnavailable},
		{http.StatusBadRequest, `{"errors":["permission denied provider-body-marker"]}`, ErrForbidden},
		{http.StatusBadRequest, `{"errors":["invalid token provider-body-marker"]}`, ErrUnauthorized},
		{http.StatusBadRequest, `{"errors":["bad request provider-body-marker"]}`, ErrUnavailable},
	}
	for _, tc := range cases {
		srv := vaultServer(t, tc.status, tc.body)
		c := &VaultClient{Address: srv.URL, Token: "t"}
		_, err := c.Resolve(context.Background(), "x", SecretScope{})
		assertClass(t, err, tc.want, fmt.Sprintf("vault status %d", tc.status))
		if strings.Contains(err.Error(), "provider-body-marker") {
			t.Fatalf("vault status %d: provider body leaked into error: %v", tc.status, err)
		}
	}

	t.Run("error list on 200", func(t *testing.T) {
		srv := vaultServer(t, http.StatusOK, `{"errors":["permission denied provider-body-marker"]}`)
		c := &VaultClient{Address: srv.URL}
		_, err := c.Resolve(context.Background(), "x", SecretScope{})
		assertClass(t, err, ErrForbidden, "vault error list")
		if strings.Contains(err.Error(), "provider-body-marker") {
			t.Fatalf("vault error list: provider body leaked: %v", err)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		srv := vaultServer(t, http.StatusOK, "not json")
		c := &VaultClient{Address: srv.URL}
		_, err := c.Resolve(context.Background(), "x", SecretScope{})
		assertClass(t, err, ErrMalformedResponse, "vault undecodable")
	})

	t.Run("structurally unusable", func(t *testing.T) {
		srv := vaultServer(t, http.StatusOK, `{"data":{"data":{}}}`)
		c := &VaultClient{Address: srv.URL}
		_, err := c.Resolve(context.Background(), "x", SecretScope{})
		assertClass(t, err, ErrMalformedResponse, "vault empty data")
	})

	t.Run("redirect", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}))
		t.Cleanup(srv.Close)
		c := &VaultClient{Address: srv.URL}
		_, err := c.Resolve(context.Background(), "x", SecretScope{})
		assertClass(t, err, ErrUnavailable, "vault redirect")
		if !strings.Contains(err.Error(), "redirect") {
			t.Fatalf("vault redirect error = %v, want redirect annotation", err)
		}
	})
}

// TestAWSStatusAndCodeClassification pins the Secrets Manager mapping:
// AWS answers most failures with HTTP 400, so the sanitized error code wins.
func TestAWSStatusAndCodeClassification(t *testing.T) {
	cases := []struct {
		label  string
		status int
		header string
		body   string
		want   error
	}{
		{"resource not found", http.StatusBadRequest, "", `{"__type":"com.amazonaws.secretsmanager#ResourceNotFoundException","message":"provider-body-marker"}`, ErrSecretNotFound},
		{"access denied", http.StatusBadRequest, "", `{"__type":"AccessDeniedException","message":"provider-body-marker"}`, ErrForbidden},
		{"kms access denied", http.StatusBadRequest, "", `{"__type":"KMSAccessDeniedException","message":"provider-body-marker"}`, ErrForbidden},
		{"unrecognized client", http.StatusBadRequest, "", `{"__type":"UnrecognizedClientException","message":"provider-body-marker"}`, ErrUnauthorized},
		{"expired token", http.StatusBadRequest, "", `{"__type":"ExpiredTokenException","message":"provider-body-marker"}`, ErrUnauthorized},
		{"signature mismatch", http.StatusBadRequest, "", `{"__type":"SignatureDoesNotMatch","message":"provider-body-marker"}`, ErrUnauthorized},
		{"throttling", http.StatusBadRequest, "", `{"__type":"ThrottlingException","message":"provider-body-marker"}`, ErrUnavailable},
		{"unknown code", http.StatusBadRequest, "", `{"__type":"WeirdException","message":"provider-body-marker"}`, ErrUnavailable},
		{"errortype header", http.StatusBadRequest, "AccessDeniedException", "provider-body-marker", ErrForbidden},
		{"server error", http.StatusInternalServerError, "", "provider-body-marker", ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			status, header, body := tc.status, tc.header, tc.body
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if header != "" {
					w.Header().Set("x-amzn-errortype", header)
				}
				w.WriteHeader(status)
				_, _ = w.Write([]byte(body))
			}))
			t.Cleanup(srv.Close)
			c := &SecretsManagerClient{Region: "us-east-1", AccessKeyID: "a", SecretAccessKey: "s", Endpoint: srv.URL}
			_, err := c.Resolve(context.Background(), "x", SecretScope{})
			assertClass(t, err, tc.want, "aws "+tc.label)
			if strings.Contains(err.Error(), "provider-body-marker") {
				t.Fatalf("aws %s: provider body leaked into error: %v", tc.label, err)
			}
		})
	}
}

// TestGCPTokenAndFetchClassification pins GCP token invalid_grant as
// Unauthorized (expired credentials arrive as HTTP 400) and the secret-fetch
// status mapping.
func TestGCPTokenAndFetchClassification(t *testing.T) {
	pem := rsaPEM(testRSAKey(t))
	ctx := context.Background()

	t.Run("token invalid_grant", func(t *testing.T) {
		oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"provider-body-marker"}`))
		}))
		t.Cleanup(oauth.Close)
		c := &GCPClient{Project: "p", ClientEmail: "e", PrivateKeyPEM: pem, TokenURL: oauth.URL}
		_, err := c.Resolve(ctx, "x", SecretScope{})
		assertClass(t, err, ErrUnauthorized, "gcp invalid_grant")
		if strings.Contains(err.Error(), "provider-body-marker") {
			t.Fatalf("gcp invalid_grant leaked body: %v", err)
		}
	})

	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"tok"}`))
	}))
	t.Cleanup(oauth.Close)

	cases := []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusNotFound, `provider-body-marker`, ErrSecretNotFound},
		{http.StatusUnauthorized, `provider-body-marker`, ErrUnauthorized},
		{http.StatusForbidden, `provider-body-marker`, ErrForbidden},
		{http.StatusInternalServerError, `provider-body-marker`, ErrUnavailable},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		t.Cleanup(srv.Close)
		c := &GCPClient{Project: "p", ClientEmail: "e", PrivateKeyPEM: pem, TokenURL: oauth.URL, SecretManagerURL: srv.URL}
		_, err := c.Resolve(ctx, "x", SecretScope{})
		assertClass(t, err, tc.want, fmt.Sprintf("gcp fetch status %d", tc.status))
		if strings.Contains(err.Error(), "provider-body-marker") {
			t.Fatalf("gcp fetch status %d leaked body: %v", tc.status, err)
		}
	}

	for label, body := range map[string]string{
		"undecodable":   "not json",
		"empty payload": `{}`,
		"bad base64":    `{"payload":{"data":"!!!"}}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		c := &GCPClient{Project: "p", ClientEmail: "e", PrivateKeyPEM: pem, TokenURL: oauth.URL, SecretManagerURL: srv.URL}
		_, err := c.Resolve(ctx, "x", SecretScope{})
		assertClass(t, err, ErrMalformedResponse, "gcp "+label)
	}
}

// TestAzureTokenAndFetchClassification pins Azure's invalid_client token
// error as Unauthorized and the Key Vault fetch status mapping.
func TestAzureTokenAndFetchClassification(t *testing.T) {
	ctx := context.Background()

	t.Run("token invalid_client", func(t *testing.T) {
		oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"provider-body-marker"}`))
		}))
		t.Cleanup(oauth.Close)
		c := &AzureClient{TenantID: "t", ClientID: "c", ClientSecret: "s", VaultURL: "https://kv.test", TokenURL: oauth.URL}
		_, err := c.Resolve(ctx, "x", SecretScope{})
		assertClass(t, err, ErrUnauthorized, "azure invalid_client")
		if strings.Contains(err.Error(), "provider-body-marker") {
			t.Fatalf("azure invalid_client leaked body: %v", err)
		}
	})

	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"tok"}`))
	}))
	t.Cleanup(oauth.Close)

	cases := []struct {
		status int
		want   error
	}{
		{http.StatusNotFound, ErrSecretNotFound},
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusForbidden, ErrForbidden},
		{http.StatusInternalServerError, ErrUnavailable},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte("provider-body-marker"))
		}))
		t.Cleanup(srv.Close)
		c := &AzureClient{TenantID: "t", ClientID: "c", ClientSecret: "s", VaultURL: srv.URL, TokenURL: oauth.URL}
		_, err := c.Resolve(ctx, "x", SecretScope{})
		assertClass(t, err, tc.want, fmt.Sprintf("azure fetch status %d", tc.status))
		if strings.Contains(err.Error(), "provider-body-marker") {
			t.Fatalf("azure fetch status %d leaked body: %v", tc.status, err)
		}
	}
}

// TestOnePasswordStatusClassification pins the Connect server mapping.
func TestOnePasswordStatusClassification(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusNotFound, "provider-body-marker", ErrSecretNotFound},
		{http.StatusUnauthorized, "provider-body-marker", ErrUnauthorized},
		{http.StatusForbidden, "provider-body-marker", ErrForbidden},
		{http.StatusInternalServerError, "provider-body-marker", ErrUnavailable},
		{http.StatusOK, "not json", ErrMalformedResponse},
		{http.StatusOK, `{}`, ErrMalformedResponse},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		t.Cleanup(srv.Close)
		c := &OnePasswordClient{Host: srv.URL, Token: "t", VaultID: "v"}
		_, err := c.Resolve(context.Background(), "x", SecretScope{})
		assertClass(t, err, tc.want, fmt.Sprintf("onepassword status %d", tc.status))
		if strings.Contains(err.Error(), "provider-body-marker") {
			t.Fatalf("onepassword status %d leaked body: %v", tc.status, err)
		}
	}
}

// TestRemoteProviderClassificationAndRedaction pins the runner-side control
// plane delivery mapping and proves the response body never reaches the
// error (it would otherwise travel into runner/job error surfaces).
func TestRemoteProviderClassificationAndRedaction(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusUnauthorized, "provider-body-marker", ErrUnauthorized},
		{http.StatusForbidden, "provider-body-marker", ErrForbidden},
		{http.StatusInternalServerError, "provider-body-marker", ErrUnavailable},
		{http.StatusOK, "not json", ErrMalformedResponse},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		t.Cleanup(srv.Close)
		p := &RemoteProvider{Server: srv.URL, JobID: "j", LeaseToken: "l", LeaseGeneration: 1, RunnerID: "r"}
		_, err := p.Get(context.Background(), "K")
		assertClass(t, err, tc.want, fmt.Sprintf("remote status %d", tc.status))
		if strings.Contains(err.Error(), "provider-body-marker") {
			t.Fatalf("remote status %d leaked response body: %v", tc.status, err)
		}
	}
}

// TestProviderCancellationClassification pins that a canceled context is
// Unavailable (never fallback-able by default) and that the ctx error stays
// matchable.
func TestProviderCancellationClassification(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	vault := &VaultClient{Address: "https://vault.test"}
	if _, err := vault.Resolve(ctx, "x", SecretScope{}); !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("vault cancellation = %v, want ErrUnavailable wrapping context.Canceled", err)
	}

	remote := &RemoteProvider{Server: "https://cp.test", JobID: "j", RunnerID: "r"}
	if _, err := remote.Get(ctx, "K"); !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("remote cancellation = %v, want ErrUnavailable wrapping context.Canceled", err)
	}
}
