package secretbroker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestMain enables the explicit cleartext-loopback escape hatch for the
// package's provider tests: they point clients at httptest servers on
// 127.0.0.1 over http. The endpoint-validation tests clear the variable with
// t.Setenv to exercise the production posture, so the hatch stays test-only.
func TestMain(m *testing.M) {
	_ = os.Setenv(devAllowLoopbackHTTPEnv, "1")
	os.Exit(m.Run())
}

// TestHardenedClientBoundsAndRefusesRedirects pins the factory contract: a
// finite total timeout, bounded transport phases, and redirect refusal.
func TestHardenedClientBoundsAndRefusesRedirects(t *testing.T) {
	c := hardenedClient()
	if c.Timeout != hardenedTotalTimeout {
		t.Fatalf("total timeout = %v, want %v", c.Timeout, hardenedTotalTimeout)
	}
	if c.CheckRedirect == nil || c.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("hardened client must refuse redirects")
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", c.Transport)
	}
	if tr.TLSHandshakeTimeout != hardenedTLSHandshakeTimeout {
		t.Fatalf("TLS handshake timeout = %v", tr.TLSHandshakeTimeout)
	}
	if tr.ResponseHeaderTimeout != hardenedResponseHeaderTimeout {
		t.Fatalf("response header timeout = %v", tr.ResponseHeaderTimeout)
	}
	if tr.IdleConnTimeout != hardenedIdleConnTimeout {
		t.Fatalf("idle conn timeout = %v", tr.IdleConnTimeout)
	}
	if tr.DialContext == nil {
		t.Fatal("transport must bound dialing")
	}
	if hardenedDialer.Timeout != hardenedDialTimeout {
		t.Fatalf("dial timeout = %v, want %v", hardenedDialer.Timeout, hardenedDialTimeout)
	}
}

// TestProviderClientConfiguredBounds proves an injected client keeps its
// transport but gains redirect refusal and the hardened default timeout.
func TestProviderClientConfiguredBounds(t *testing.T) {
	custom := &http.Client{Transport: &http.Transport{}}
	got := providerClient(custom)
	if got == custom {
		t.Fatal("configured client must be copied, not mutated in place")
	}
	if got.Transport != custom.Transport {
		t.Fatal("configured transport must be preserved")
	}
	if got.Timeout != hardenedTotalTimeout {
		t.Fatalf("zero configured timeout = %v, want %v", got.Timeout, hardenedTotalTimeout)
	}
	if got.CheckRedirect == nil || got.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("configured client must refuse redirects")
	}
	if custom.CheckRedirect != nil {
		t.Fatal("the configured client was mutated")
	}
	custom2 := &http.Client{Timeout: 5 * time.Second}
	if got := providerClient(custom2); got.Timeout != 5*time.Second {
		t.Fatalf("configured timeout overridden: %v", got.Timeout)
	}
}

// TestValidateProviderEndpointMatrix pins the accepted/rejected endpoint
// classes shared by every provider.
func TestValidateProviderEndpointMatrix(t *testing.T) {
	t.Setenv(devAllowLoopbackHTTPEnv, "1")
	cases := []struct {
		name    string
		url     string
		allow   bool
		wantErr bool
	}{
		{"https bare", "https://vault.example.com", true, false},
		{"https with port and path", "https://vault.example.com:8200/v1/", true, false},
		{"https benign query", "https://vault.azure.net?api-version=7.4", true, false},
		{"loopback ipv4", "http://127.0.0.1:8200", true, false},
		{"loopback localhost", "http://localhost:8200", true, false},
		{"loopback ipv6", "http://[::1]:8200", true, false},
		{"empty", "", true, true},
		{"unparsable", "://bad", true, true},
		{"unsupported scheme", "ftp://vault.example.com", true, true},
		{"hostless https", "https://", true, true},
		{"non-loopback http", "http://vault.example.com", true, true},
		{"non-exact loopback http", "http://127.0.0.2:8200", true, true},
		{"loopback http not opted in", "http://127.0.0.1:8200", false, true},
		{"userinfo", "https://user:pass@vault.example.com", true, true},
		{"userinfo no password", "https://evil.example@good.example", true, true},
		{"fragment", "https://vault.example.com/#frag", true, true},
		{"fragment spoofed host", "https://good.example#@evil.example", true, true},
		{"credential query token", "https://vault.example.com/?token=abc", true, true},
		{"credential query signature", "https://vault.example.com/?X-Amz-Signature=abc", true, true},
		{"credential query api_key", "https://vault.example.com/?api_key=abc", true, true},
		{"credential query password", "https://vault.example.com/?password=abc", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProviderEndpoint(tc.url, tc.allow)
			if tc.wantErr && err == nil {
				t.Fatalf("validateProviderEndpoint(%q, %v) = nil, want error", tc.url, tc.allow)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateProviderEndpoint(%q, %v) = %v", tc.url, tc.allow, err)
			}
		})
	}
}

// TestValidateProviderEndpointEscapeHatch pins the production posture: the
// process-wide env override is required in addition to the caller opt-in.
func TestValidateProviderEndpointEscapeHatch(t *testing.T) {
	t.Setenv(devAllowLoopbackHTTPEnv, "")
	if err := validateProviderEndpoint("http://127.0.0.1:8200", true); err == nil {
		t.Fatal("loopback http must be rejected without the env escape hatch")
	}
	t.Setenv(devAllowLoopbackHTTPEnv, "1")
	if err := validateProviderEndpoint("http://127.0.0.1:8200", false); err == nil {
		t.Fatal("loopback http must be rejected when the caller does not opt in")
	}
}

// TestProviderEndpointValidationPerProvider proves each provider applies
// the shared validation to its own endpoint fields.
func TestProviderEndpointValidationPerProvider(t *testing.T) {
	ctx := context.Background()
	okClient := &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return canned(http.StatusOK, `{"data":{"data":{"value":"v"}}}`), nil
	}}}

	t.Run("vault", func(t *testing.T) {
		c := &VaultClient{Address: "http://vault.example.com", Token: "t", HTTPClient: okClient}
		if _, err := c.Resolve(ctx, "x", SecretScope{}); err == nil || !strings.Contains(err.Error(), "insecure") {
			t.Fatalf("vault non-loopback http = %v", err)
		}
		if _, err := (&VaultClient{Address: "https://vault.example.com", HTTPClient: okClient}).baseURL(); err != nil {
			t.Fatalf("vault https rejected: %v", err)
		}
		if _, err := (&VaultClient{Address: "https://user:pass@vault.example.com"}).baseURL(); err == nil {
			t.Fatal("vault userinfo must be rejected")
		}
	})

	t.Run("azure", func(t *testing.T) {
		tokenClient := &http.Client{Transport: routeTripper{fn: func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/token") {
				return canned(http.StatusOK, `{"access_token":"tok"}`), nil
			}
			return canned(http.StatusOK, `{"value":"v"}`), nil
		}}}
		c := &AzureClient{TenantID: "t", ClientID: "c", ClientSecret: "s", VaultURL: "http://vault.example.com", TokenURL: "https://login.example.com/token", HTTPClient: tokenClient}
		if _, err := c.Resolve(ctx, "x", SecretScope{}); err == nil || !strings.Contains(err.Error(), "insecure") {
			t.Fatalf("azure vault non-loopback http = %v", err)
		}
		bad := &AzureClient{TenantID: "t", ClientID: "c", ClientSecret: "s", VaultURL: "https://vault.example.com", TokenURL: "ftp://login.example.com", HTTPClient: tokenClient}
		if _, err := bad.Resolve(ctx, "x", SecretScope{}); err == nil || !strings.Contains(err.Error(), "unsupported scheme") {
			t.Fatalf("azure token scheme = %v", err)
		}
	})

	t.Run("onepassword", func(t *testing.T) {
		c := &OnePasswordClient{Host: "http://op.example.com", Token: "t", VaultID: "v", HTTPClient: okClient}
		if _, err := c.Resolve(ctx, "x", SecretScope{}); err == nil || !strings.Contains(err.Error(), "insecure") {
			t.Fatalf("onepassword non-loopback http = %v", err)
		}
		if _, err := (&OnePasswordClient{Host: "https://op.example.com", HTTPClient: okClient}).Resolve(ctx, "x", SecretScope{}); err == nil {
			t.Fatal("https endpoint must reach the transport (decode failure expected)")
		}
	})

	t.Run("aws", func(t *testing.T) {
		c := &SecretsManagerClient{Region: "us-east-1", AccessKeyID: "a", SecretAccessKey: "s", Endpoint: "http://sm.example.com", HTTPClient: okClient}
		if _, err := c.Resolve(ctx, "x", SecretScope{}); err == nil || !strings.Contains(err.Error(), "insecure") {
			t.Fatalf("aws non-loopback http = %v", err)
		}
		if _, err := (&SecretsManagerClient{Region: "us-east-1", Endpoint: "https://sm.example.com", HTTPClient: okClient}).Resolve(ctx, "x", SecretScope{}); err == nil {
			t.Fatal("https endpoint must reach the transport (decode failure expected)")
		}
	})

	t.Run("gcp", func(t *testing.T) {
		key := testRSAKey(t)
		oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"access_token":"ya29.fake"}`))
		}))
		defer oauth.Close()
		c := &GCPClient{Project: "p", ClientEmail: "e", PrivateKeyPEM: rsaPEM(key), TokenURL: oauth.URL, SecretManagerURL: "http://sm.example.com"}
		if _, err := c.Resolve(ctx, "x", SecretScope{}); err == nil || !strings.Contains(err.Error(), "insecure") {
			t.Fatalf("gcp non-loopback http = %v", err)
		}
		bad := &GCPClient{Project: "p", ClientEmail: "e", PrivateKeyPEM: rsaPEM(key), TokenURL: oauth.URL, SecretManagerURL: "ftp://sm.example.com"}
		if _, err := bad.Resolve(ctx, "x", SecretScope{}); err == nil || !strings.Contains(err.Error(), "unsupported scheme") {
			t.Fatalf("gcp scheme = %v", err)
		}
	})
}

// TestProvidersDoNotForwardCredentialsAcrossRedirects pins the second half
// of the hardening: a redirecting endpoint gets no credential, because the
// hardened clients surface the 3xx response instead of following it.
func TestProvidersDoNotForwardCredentialsAcrossRedirects(t *testing.T) {
	var leaks int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&leaks, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL+"/stolen", http.StatusFound)
	}))
	defer origin.Close()
	ctx := context.Background()

	check := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: a redirect must surface as an error", name)
		}
		if n := atomic.LoadInt32(&leaks); n != 0 {
			t.Fatalf("%s: %d request(s) leaked to the redirect target", name, n)
		}
	}

	if _, err := (&VaultClient{Address: origin.URL, Token: "vault-token"}).Resolve(ctx, "x", SecretScope{}); err != nil {
		check("vault", err)
	} else {
		t.Fatal("vault: redirect must surface as an error")
	}

	if _, err := (&OnePasswordClient{Host: origin.URL, Token: "op-token", VaultID: "v"}).Resolve(ctx, "x", SecretScope{}); err != nil {
		check("onepassword", err)
	} else {
		t.Fatal("onepassword: redirect must surface as an error")
	}

	if _, err := (&SecretsManagerClient{Endpoint: origin.URL, Region: "us-east-1", AccessKeyID: "a", SecretAccessKey: "s"}).Resolve(ctx, "x", SecretScope{}); err != nil {
		check("aws", err)
	} else {
		t.Fatal("aws: redirect must surface as an error")
	}

	azureToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"tok"}`))
	}))
	defer azureToken.Close()
	if _, err := (&AzureClient{TenantID: "t", ClientID: "c", ClientSecret: "s", VaultURL: origin.URL, TokenURL: azureToken.URL}).Resolve(ctx, "x", SecretScope{}); err != nil {
		check("azure", err)
	} else {
		t.Fatal("azure: redirect must surface as an error")
	}

	gcpToken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"tok"}`))
	}))
	defer gcpToken.Close()
	gcp := &GCPClient{Project: "p", ClientEmail: "e", PrivateKeyPEM: rsaPEM(testRSAKey(t)), TokenURL: gcpToken.URL, SecretManagerURL: origin.URL}
	if _, err := gcp.Resolve(ctx, "x", SecretScope{}); err != nil {
		check("gcp", err)
	} else {
		t.Fatal("gcp: redirect must surface as an error")
	}

	remote := &RemoteProvider{Server: origin.URL, Token: "runner-token", JobID: "job", LeaseToken: "lease", LeaseGeneration: 1, RunnerID: "runner"}
	if _, err := remote.Get(ctx, "x"); err != nil {
		check("remote", err)
	} else {
		t.Fatal("remote: redirect must surface as an error")
	}
}
