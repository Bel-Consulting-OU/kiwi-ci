package secretbroker

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type failTripper struct{ err error }

func (f failTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

type routeTripper struct {
	fn func(*http.Request) (*http.Response, error)
}

func (r routeTripper) RoundTrip(req *http.Request) (*http.Response, error) { return r.fn(req) }

type failingBody struct{ err error }

func (f failingBody) Read([]byte) (int, error) { return 0, f.err }
func (f failingBody) Close() error             { return nil }

func canned(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
}

// TestProviderClientFactories proves each provider adopts the hardened
// client factory: a configured client's transport is preserved (on a copy),
// while redirect refusal and a finite total timeout are always enforced; a
// provider without a configured client never falls back to the unbounded
// http.DefaultClient.
func TestProviderClientFactories(t *testing.T) {
	custom := &http.Client{Timeout: time.Second, Transport: &http.Transport{}}
	checkConfigured := func(name string, got *http.Client) {
		t.Helper()
		if got == custom {
			t.Fatalf("%s: configured client must be copied, not returned as-is", name)
		}
		if got.Transport != custom.Transport {
			t.Fatalf("%s: configured transport ignored", name)
		}
		if got.Timeout != time.Second {
			t.Fatalf("%s: configured timeout = %v", name, got.Timeout)
		}
		if got.CheckRedirect == nil || got.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
			t.Fatalf("%s: configured client must refuse redirects", name)
		}
	}
	checkDefault := func(name string, got *http.Client) {
		t.Helper()
		if got == http.DefaultClient {
			t.Fatalf("%s: default client must be the hardened one, not http.DefaultClient", name)
		}
		if got.Timeout != hardenedTotalTimeout {
			t.Fatalf("%s: default timeout = %v, want %v", name, got.Timeout, hardenedTotalTimeout)
		}
		if got.CheckRedirect == nil || got.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
			t.Fatalf("%s: default client must refuse redirects", name)
		}
	}
	checkConfigured("aws", (&SecretsManagerClient{HTTPClient: custom}).client())
	checkDefault("aws default", (&SecretsManagerClient{}).client())
	checkConfigured("azure", (&AzureClient{HTTPClient: custom}).client())
	checkDefault("azure default", (&AzureClient{}).client())
	checkConfigured("gcp", (&GCPClient{HTTPClient: custom}).client())
	checkDefault("gcp default", (&GCPClient{}).client())
	checkConfigured("onepassword", (&OnePasswordClient{HTTPClient: custom}).client())
	checkDefault("onepassword default", (&OnePasswordClient{}).client())
	checkConfigured("vault", (&VaultClient{HTTPClient: custom}).client())
	checkDefault("vault default", (&VaultClient{}).client())
	checkConfigured("remote", (&RemoteProvider{Client: custom}).client())
	checkDefault("remote default", (&RemoteProvider{}).client())
}

// TestAWSSecretsManagerErrorMatrix proves every failure branch of the
// Secrets Manager client plus the session-token request shape.
func TestAWSSecretsManagerErrorMatrix(t *testing.T) {
	ctx := context.Background()

	if _, err := (&SecretsManagerClient{Endpoint: "http://[::1"}).Resolve(ctx, "x", SecretScope{}); err == nil {
		t.Fatal("unparsable endpoint must fail")
	}

	boom := errors.New("connection refused")
	c := &SecretsManagerClient{Endpoint: "https://sm.test", HTTPClient: &http.Client{Transport: failTripper{err: boom}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); !errors.Is(err, boom) {
		t.Fatalf("transport failure = %v", err)
	}

	readErr := errors.New("read broke")
	c = &SecretsManagerClient{Endpoint: "https://sm.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: failingBody{err: readErr}, Header: http.Header{}}, nil
	}}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); !errors.Is(err, readErr) {
		t.Fatalf("read failure = %v", err)
	}

	c = &SecretsManagerClient{Endpoint: "https://sm.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return canned(http.StatusOK, "not json"), nil
	}}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); err == nil {
		t.Fatal("undecodable body must fail")
	}

	c = &SecretsManagerClient{Endpoint: "https://sm.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return canned(http.StatusOK, `{}`), nil
	}}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); err == nil || !strings.Contains(err.Error(), "SecretString") {
		t.Fatalf("missing SecretString = %v", err)
	}

	// Session token: header must be sent and echoed back in the value.
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("x-amz-security-token")
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"SecretString":"session-secret"}`))
	}))
	t.Cleanup(srv.Close)
	c = &SecretsManagerClient{Endpoint: srv.URL, Region: "us-east-1", SessionToken: "sess", HTTPClient: srv.Client()}
	v, err := c.Resolve(ctx, "db/password", SecretScope{})
	if err != nil || v != "session-secret" {
		t.Fatalf("session resolve = (%q, %v)", v, err)
	}
	if gotToken != "sess" {
		t.Fatalf("session token header = %q", gotToken)
	}

	if got := (&SecretsManagerClient{Region: "eu-west-1"}).endpoint(); got != "https://secretsmanager.eu-west-1.amazonaws.com" {
		t.Fatalf("default endpoint = %q", got)
	}
}

// TestAzureErrorMatrix proves every failure branch of the Azure client.
func TestAzureErrorMatrix(t *testing.T) {
	ctx := context.Background()

	// Token request construction failure.
	if _, err := (&AzureClient{TokenURL: "://bad", VaultURL: "https://vault.test"}).Resolve(ctx, "x", SecretScope{}); err == nil {
		t.Fatal("unparsable token URL must fail")
	}

	boom := errors.New("token refused")
	c := &AzureClient{TokenURL: "https://login.test/token", VaultURL: "https://vault.test", HTTPClient: &http.Client{Transport: failTripper{err: boom}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); !errors.Is(err, boom) {
		t.Fatalf("token transport failure = %v", err)
	}

	readErr := errors.New("token read broke")
	c = &AzureClient{TokenURL: "https://login.test/token", VaultURL: "https://vault.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: failingBody{err: readErr}, Header: http.Header{}}, nil
	}}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); !errors.Is(err, readErr) {
		t.Fatalf("token read failure = %v", err)
	}

	c = &AzureClient{TokenURL: "https://login.test/token", VaultURL: "https://vault.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return canned(http.StatusOK, "not json"), nil
	}}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); err == nil {
		t.Fatal("undecodable token body must fail")
	}

	c = &AzureClient{TokenURL: "https://login.test/token", VaultURL: "https://vault.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return canned(http.StatusOK, `{}`), nil
	}}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); err == nil || !strings.Contains(err.Error(), "empty access token") {
		t.Fatalf("empty token = %v", err)
	}

	// Token succeeds; the vault request construction fails.
	tokenOnly := &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return canned(http.StatusOK, `{"access_token":"tok"}`), nil
	}}}
	if _, err := (&AzureClient{TokenURL: "https://login.test/token", VaultURL: "://bad", HTTPClient: tokenOnly}).Resolve(ctx, "x", SecretScope{}); err == nil {
		t.Fatal("unparsable vault URL must fail")
	}

	// Token succeeds; the vault request fails at the transport.
	vaultErr := errors.New("vault refused")
	c = &AzureClient{TokenURL: "https://login.test/token", VaultURL: "https://vault.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Host, "login") {
			return canned(http.StatusOK, `{"access_token":"tok"}`), nil
		}
		return nil, vaultErr
	}}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); !errors.Is(err, vaultErr) {
		t.Fatalf("vault transport failure = %v", err)
	}

	// Vault body read failure.
	c = &AzureClient{TokenURL: "https://login.test/token", VaultURL: "https://vault.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Host, "login") {
			return canned(http.StatusOK, `{"access_token":"tok"}`), nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: failingBody{err: readErr}, Header: http.Header{}}, nil
	}}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); !errors.Is(err, readErr) {
		t.Fatalf("vault read failure = %v", err)
	}

	// Vault response decode failure.
	c = &AzureClient{TokenURL: "https://login.test/token", VaultURL: "https://vault.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Host, "login") {
			return canned(http.StatusOK, `{"access_token":"tok"}`), nil
		}
		return canned(http.StatusOK, "not json"), nil
	}}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); err == nil {
		t.Fatal("undecodable vault body must fail")
	}
}

// TestGCPDefaultsAndKeyParsing proves the default URLs/scope/clock and the
// key parser's rejections.
func TestGCPDefaultsAndKeyParsing(t *testing.T) {
	c := &GCPClient{}
	if c.tokenURL() != "https://oauth2.googleapis.com/token" {
		t.Fatalf("default token URL = %q", c.tokenURL())
	}
	if c.secretManagerURL() != "https://secretmanager.googleapis.com" {
		t.Fatalf("default secret manager URL = %q", c.secretManagerURL())
	}
	if c.scope() != "https://www.googleapis.com/auth/cloud-platform" {
		t.Fatalf("default scope = %q", c.scope())
	}
	now := time.Now()
	c.Now = func() time.Time { return now }
	if !c.now().Equal(now) {
		t.Fatal("custom clock ignored")
	}
	c.TokenURL = "https://custom/token"
	c.SecretManagerURL = "https://custom/sm"
	c.Scope = "custom-scope"
	if c.tokenURL() != "https://custom/token" || c.secretManagerURL() != "https://custom/sm" || c.scope() != "custom-scope" {
		t.Fatal("custom values ignored")
	}

	// PEM block with garbage DER.
	badDER := &GCPClient{PrivateKeyPEM: pemBlockBytes("PRIVATE KEY", []byte("not der"))}
	if _, err := badDER.privateKey(); err == nil {
		t.Fatal("garbage PKCS8 must fail")
	}
	// Non-PEM input.
	if _, err := (&GCPClient{PrivateKeyPEM: []byte("garbage")}).privateKey(); err == nil {
		t.Fatal("non-PEM key must fail")
	}
}

func pemBlockBytes(typ string, der []byte) []byte {
	return []byte("-----BEGIN " + typ + "-----\n" + base64.StdEncoding.EncodeToString(der) + "\n-----END " + typ + "-----\n")
}

// TestMustJSONPanics proves the marshal helper panics on unencodable values.
func TestMustJSONPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("mustJSON did not panic on an unencodable value")
		}
	}()
	mustJSON(make(chan int))
}

// tinyRSAKeyPEM crafts a structurally valid but far-too-small RSA key: the
// DER parses, but rsa.SignPKCS1v15 refuses it, which drives the JWT signing
// failure branch.
func tinyRSAKeyPEM(t *testing.T) []byte {
	t.Helper()
	p := big.NewInt(61)
	q := big.NewInt(53)
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
	d := new(big.Int).ModInverse(big.NewInt(17), phi)
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: 17},
		D:         d,
		Primes:    []*big.Int{p, q},
	}
	if err := key.Validate(); err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// TestGCPTinyKeySigningFailure proves a parseable but insecure key fails JWT
// signing instead of being used.
func TestGCPTinyKeySigningFailure(t *testing.T) {
	c := &GCPClient{ClientEmail: "sa@x", PrivateKeyPEM: tinyRSAKeyPEM(t), TokenURL: "https://oauth.test/token"}
	if _, err := c.accessToken(context.Background()); err == nil || !strings.Contains(err.Error(), "sign jwt") {
		t.Fatalf("tiny key signing = %v, want sign-jwt error", err)
	}
}

// TestGCPErrorMatrix proves every failure branch of the GCP client.
func TestGCPErrorMatrix(t *testing.T) {
	ctx := context.Background()
	key := testRSAKey(t)
	pem := rsaPEM(key)

	// Invalid private key surfaces from accessToken.
	badKey := &GCPClient{ClientEmail: "sa@x", PrivateKeyPEM: []byte("not pem"), TokenURL: "https://oauth.test/token"}
	if _, err := badKey.accessToken(ctx); err == nil {
		t.Fatal("invalid key must fail the token request")
	}

	// Token request construction failure.
	badURL := &GCPClient{ClientEmail: "sa@x", PrivateKeyPEM: pem, TokenURL: "://bad"}
	if _, err := badURL.accessToken(ctx); err == nil {
		t.Fatal("unparsable token URL must fail")
	}

	boom := errors.New("token refused")
	c := &GCPClient{ClientEmail: "sa@x", PrivateKeyPEM: pem, TokenURL: "https://oauth.test/token", HTTPClient: &http.Client{Transport: failTripper{err: boom}}}
	if _, err := c.accessToken(ctx); !errors.Is(err, boom) {
		t.Fatalf("token transport failure = %v", err)
	}

	readErr := errors.New("token read broke")
	c = &GCPClient{ClientEmail: "sa@x", PrivateKeyPEM: pem, TokenURL: "https://oauth.test/token", HTTPClient: &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: failingBody{err: readErr}, Header: http.Header{}}, nil
	}}}}
	if _, err := c.accessToken(ctx); !errors.Is(err, readErr) {
		t.Fatalf("token read failure = %v", err)
	}

	c = &GCPClient{ClientEmail: "sa@x", PrivateKeyPEM: pem, TokenURL: "https://oauth.test/token", HTTPClient: &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return canned(http.StatusBadRequest, "bad"), nil
	}}}}
	if _, err := c.accessToken(ctx); err == nil || !strings.Contains(err.Error(), "token status") {
		t.Fatalf("token status = %v", err)
	}

	c = &GCPClient{ClientEmail: "sa@x", PrivateKeyPEM: pem, TokenURL: "https://oauth.test/token", HTTPClient: &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return canned(http.StatusOK, "not json"), nil
	}}}}
	if _, err := c.accessToken(ctx); err == nil {
		t.Fatal("undecodable token body must fail")
	}

	c = &GCPClient{ClientEmail: "sa@x", PrivateKeyPEM: pem, TokenURL: "https://oauth.test/token", HTTPClient: &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return canned(http.StatusOK, `{}`), nil
	}}}}
	if _, err := c.accessToken(ctx); err == nil || !strings.Contains(err.Error(), "empty access token") {
		t.Fatalf("empty token = %v", err)
	}

	// Resolve: token failure (invalid key).
	if _, err := (&GCPClient{ClientEmail: "sa@x", PrivateKeyPEM: []byte("bad"), TokenURL: "https://oauth.test/token"}).Resolve(ctx, "x", SecretScope{}); err == nil {
		t.Fatal("invalid key must fail Resolve")
	}

	// Resolve: secret manager URL is unparsable after a successful token.
	tokenTripper := routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return canned(http.StatusOK, `{"access_token":"tok"}`), nil
	}}
	if _, err := (&GCPClient{ClientEmail: "sa@x", PrivateKeyPEM: pem, TokenURL: "https://oauth.test/token", SecretManagerURL: "://bad", HTTPClient: &http.Client{Transport: tokenTripper}}).Resolve(ctx, "x", SecretScope{}); err == nil {
		t.Fatal("unparsable secret manager URL must fail")
	}

	// Resolve: transport failure on the secret fetch.
	smErr := errors.New("secret manager refused")
	c = &GCPClient{ClientEmail: "sa@x", PrivateKeyPEM: pem, TokenURL: "https://oauth.test/token", SecretManagerURL: "https://sm.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Host, "oauth") {
			return canned(http.StatusOK, `{"access_token":"tok"}`), nil
		}
		return nil, smErr
	}}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); !errors.Is(err, smErr) {
		t.Fatalf("secret transport failure = %v", err)
	}

	// Resolve: read failure.
	readTripper := routeTripper{fn: func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Host, "oauth") {
			return canned(http.StatusOK, `{"access_token":"tok"}`), nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: failingBody{err: readErr}, Header: http.Header{}}, nil
	}}
	c = &GCPClient{ClientEmail: "sa@x", PrivateKeyPEM: pem, TokenURL: "https://oauth.test/token", SecretManagerURL: "https://sm.test", HTTPClient: &http.Client{Transport: readTripper}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); !errors.Is(err, readErr) {
		t.Fatalf("secret read failure = %v", err)
	}

	// Resolve: non-200 status.
	statusTripper := routeTripper{fn: func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Host, "oauth") {
			return canned(http.StatusOK, `{"access_token":"tok"}`), nil
		}
		return canned(http.StatusForbidden, "denied"), nil
	}}
	c = &GCPClient{ClientEmail: "sa@x", PrivateKeyPEM: pem, TokenURL: "https://oauth.test/token", SecretManagerURL: "https://sm.test", HTTPClient: &http.Client{Transport: statusTripper}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("secret status = %v", err)
	}

	// Resolve: decode failure, empty payload, and bad base64 payload.
	for label, payload := range map[string]string{
		"decode":     "not json",
		"empty":      `{"payload":{"data":""}}`,
		"bad base64": `{"payload":{"data":"!!!"}}`,
	} {
		body := payload
		c = &GCPClient{ClientEmail: "sa@x", PrivateKeyPEM: pem, TokenURL: "https://oauth.test/token", SecretManagerURL: "https://sm.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.Host, "oauth") {
				return canned(http.StatusOK, `{"access_token":"tok"}`), nil
			}
			return canned(http.StatusOK, body), nil
		}}}}
		if _, err := c.Resolve(ctx, "x", SecretScope{}); err == nil {
			t.Fatalf("%s: Resolve succeeded, want error", label)
		}
	}

	// Resolve: happy path.
	c = &GCPClient{ClientEmail: "sa@x", PrivateKeyPEM: pem, TokenURL: "https://oauth.test/token", SecretManagerURL: "https://sm.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Host, "oauth") {
			return canned(http.StatusOK, `{"access_token":"tok"}`), nil
		}
		return canned(http.StatusOK, `{"payload":{"data":"`+base64.StdEncoding.EncodeToString([]byte("gcp-secret"))+`"}}`), nil
	}}}}
	v, err := c.Resolve(ctx, "x", SecretScope{})
	if err != nil || v != "gcp-secret" {
		t.Fatalf("happy path = (%q, %v)", v, err)
	}
}

// TestOnePasswordErrorMatrix proves every failure branch of the 1Password
// client.
func TestOnePasswordErrorMatrix(t *testing.T) {
	ctx := context.Background()
	if _, err := (&OnePasswordClient{Host: "://bad"}).Resolve(ctx, "x", SecretScope{}); err == nil {
		t.Fatal("unparsable host must fail")
	}
	boom := errors.New("connect refused")
	c := &OnePasswordClient{Host: "https://op.test", HTTPClient: &http.Client{Transport: failTripper{err: boom}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); !errors.Is(err, boom) {
		t.Fatalf("transport failure = %v", err)
	}
	readErr := errors.New("read broke")
	c = &OnePasswordClient{Host: "https://op.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: failingBody{err: readErr}, Header: http.Header{}}, nil
	}}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); !errors.Is(err, readErr) {
		t.Fatalf("read failure = %v", err)
	}
	c = &OnePasswordClient{Host: "https://op.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return canned(http.StatusOK, "not json"), nil
	}}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); err == nil {
		t.Fatal("undecodable body must fail")
	}
}

// TestVaultBaseURLErrors proves address parsing and scheme/host validation.
func TestVaultBaseURLErrors(t *testing.T) {
	if _, err := (&VaultClient{Address: "://bad"}).baseURL(); err == nil {
		t.Fatal("unparsable address must fail")
	}
	if _, err := (&VaultClient{Address: "https://"}).baseURL(); err == nil || !strings.Contains(err.Error(), "no host") {
		t.Fatalf("hostless address = %v", err)
	}
	if _, err := (&VaultClient{Address: "ftp://vault.example"}).baseURL(); err == nil {
		t.Fatal("unsupported scheme must fail")
	}
	if _, err := (&VaultClient{Address: "http://vault.example"}).baseURL(); err == nil {
		t.Fatal("non-loopback http must fail")
	}
	if !isLoopbackHost("localhost") || !isLoopbackHost("127.0.0.1") || isLoopbackHost("vault.example") {
		t.Fatal("loopback classification wrong")
	}
	// A localhost address is accepted.
	if _, err := (&VaultClient{Address: "http://localhost:8200"}).baseURL(); err != nil {
		t.Fatalf("localhost http rejected: %v", err)
	}
}

// TestFirstVaultValueErrorMatrix proves the data decoder's rejection paths.
func TestFirstVaultValueErrorMatrix(t *testing.T) {
	cases := map[string]json.RawMessage{
		"not json":      json.RawMessage(`not json`),
		"not an object": json.RawMessage(`[1,2]`),
		"key error":     json.RawMessage(`{"a":"b","`),
		"bad value":     json.RawMessage(`{"a":123}`),
	}
	for label, data := range cases {
		if _, err := firstVaultValue(data); err == nil {
			t.Errorf("%s: accepted, want error", label)
		}
	}
}

// TestVaultResolveErrorMatrix proves the transport, decode, and error-list
// branches of Resolve.
func TestVaultResolveErrorMatrix(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("connect refused")
	c := &VaultClient{Address: "https://vault.test", HTTPClient: &http.Client{Transport: failTripper{err: boom}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); !errors.Is(err, boom) {
		t.Fatalf("transport failure = %v", err)
	}
	readErr := errors.New("read broke")
	c = &VaultClient{Address: "https://vault.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: failingBody{err: readErr}, Header: http.Header{}}, nil
	}}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); !errors.Is(err, readErr) {
		t.Fatalf("read failure = %v", err)
	}
	c = &VaultClient{Address: "https://vault.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return canned(http.StatusOK, "not json"), nil
	}}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); err == nil {
		t.Fatal("undecodable body must fail")
	}
	c = &VaultClient{Address: "https://vault.test", HTTPClient: &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return canned(http.StatusOK, `{"errors":["permission denied","bad token"]}`), nil
	}}}}
	if _, err := c.Resolve(ctx, "x", SecretScope{}); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("error list = %v", err)
	}
}

// TestBrokerRandFailures proves entropy failures in sealing and remote
// ephemeral-key generation are surfaced (via the test seams).
func TestBrokerRandFailures(t *testing.T) {
	origReader := randReader
	origKey := generateX25519Key
	defer func() { randReader = origReader; generateX25519Key = origKey }()

	var peer [32]byte
	copy(peer[:], bytes.Repeat([]byte{9}, 32))

	// Ephemeral key generation fails.
	generateX25519Key = func() (*ecdh.PrivateKey, error) { return nil, errors.New("no entropy") }
	if _, err := SealEnvelope([]byte("secret"), peer, nil); err == nil {
		t.Fatal("key generation failure must surface")
	}

	// Key generation succeeds but nonce entropy fails.
	generateX25519Key = origKey
	randReader = failingBody{err: errors.New("no nonce entropy")}
	if _, err := SealEnvelope([]byte("secret"), peer, nil); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("nonce failure = %v, want nonce error", err)
	}
	randReader = origReader
	generateX25519Key = func() (*ecdh.PrivateKey, error) { return nil, errors.New("no entropy") }
	// Remote provider: ephemeral key generation fails.
	p := &RemoteProvider{Server: "https://cp.test", JobID: "j", RunnerID: "r"}
	if _, err := p.Get(context.Background(), "NAME"); err == nil {
		t.Fatal("remote ephemeral key failure must surface")
	}
}

// TestOpenEnvelopeMalformedEphemeralKey proves wrong-length and low-order
// ephemeral public keys are rejected.
func TestOpenEnvelopeMalformedEphemeralKey(t *testing.T) {
	var own [32]byte
	if _, err := OpenEnvelope(EncryptedDelivery{EphemeralPublic: []byte{1, 2, 3}}, own, nil); err == nil || !strings.Contains(err.Error(), "ephemeral public key") {
		t.Fatalf("short ephemeral key = %v", err)
	}
	// A 32-byte all-zero point is accepted by NewPublicKey but rejected by
	// ECDH as a low-order point.
	var own2 [32]byte
	copy(own2[:], bytes.Repeat([]byte{7}, 32))
	if _, err := OpenEnvelope(EncryptedDelivery{EphemeralPublic: make([]byte, 32)}, own2, nil); err == nil || !strings.Contains(err.Error(), "ecdh") {
		t.Fatalf("low-order point = %v", err)
	}
}

// TestChainBrokerSkipsNil proves a nil broker in the chain is skipped.
func TestChainBrokerSkipsNil(t *testing.T) {
	chain := ChainBroker{nil, StaticBroker{"a": "1"}}
	v, err := chain.Resolve(context.Background(), "a", SecretScope{})
	if err != nil || v != "1" {
		t.Fatalf("chain = (%q, %v)", v, err)
	}
}

// TestRemoteProviderErrorMatrix proves the remote provider's validation,
// transport, size, decode, and envelope-parse failures.
func TestRemoteProviderErrorMatrix(t *testing.T) {
	ctx := context.Background()

	// Empty name.
	if _, err := (&RemoteProvider{Server: "https://cp.test", JobID: "j"}).Get(ctx, "  "); err == nil {
		t.Fatal("empty name must fail")
	}

	// Unparsable server URL.
	if _, err := (&RemoteProvider{Server: "http://[::1", JobID: "j", RunnerID: "r"}).Get(ctx, "N"); err == nil {
		t.Fatal("unparsable server must fail")
	}

	// Transport failure.
	boom := errors.New("connect refused")
	p := &RemoteProvider{Server: "https://cp.test", JobID: "j", RunnerID: "r", Client: &http.Client{Transport: failTripper{err: boom}}}
	if _, err := p.Get(ctx, "N"); !errors.Is(err, boom) {
		t.Fatalf("transport failure = %v", err)
	}

	// Read failure.
	p = &RemoteProvider{Server: "https://cp.test", JobID: "j", RunnerID: "r", Client: &http.Client{Transport: routeTripper{fn: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: failingBody{err: errors.New("read broke")}, Header: http.Header{}}, nil
	}}}}
	if _, err := p.Get(ctx, "N"); err == nil {
		t.Fatal("read failure must surface")
	}

	// Oversize delivery.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("a", maxSecretDeliveryBytes+2))
	}))
	t.Cleanup(srv.Close)
	if _, err := testProvider(srv).Get(ctx, "N"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize delivery = %v", err)
	}

	// Decode failures and bad base64 fields, plus the token header.
	var gotAuth string
	body := ""
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv2.Close)

	cases := []struct {
		label string
		body  string
	}{
		{"undecodable delivery", "not json"},
		{"bad ciphertext", `{"ciphertext":"!!!","ephemeral_public":"","nonce":"","lease_generation":3}`},
		{"bad ephemeral public", `{"ciphertext":"` + base64.StdEncoding.EncodeToString([]byte("x")) + `","ephemeral_public":"!!!","nonce":"","lease_generation":3}`},
		{"bad nonce", `{"ciphertext":"` + base64.StdEncoding.EncodeToString([]byte("x")) + `","ephemeral_public":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)) + `","nonce":"!!!","lease_generation":3}`},
	}
	for _, tc := range cases {
		body = tc.body
		pp := testProvider(srv2)
		pp.Token = "tok"
		if _, err := pp.Get(ctx, "N"); err == nil {
			t.Errorf("%s: Get succeeded, want error", tc.label)
		}
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("authorization header = %q", gotAuth)
	}
}

// TestRemoteProviderNameInRequestPath proves the delivery name is carried in
// the request body only and the URL stays the job route.
func TestRemoteProviderNameInRequestPath(t *testing.T) {
	var got secretRequest
	var path string
	fsrv := &fakeSecretServer{plaintext: "v"}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/jobs/{id}/secrets", func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		fsrv.handler().ServeHTTP(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	v, err := testProvider(srv).Get(context.Background(), "API_TOKEN")
	if err != nil || v != "v" {
		t.Fatalf("Get = (%q, %v)", v, err)
	}
	if path != "/api/v1/jobs/job-1/secrets" {
		t.Fatalf("request path = %q", path)
	}
	if got.Name != "API_TOKEN" || got.RunnerID != "runner-1" || got.LeaseToken != "lease-token" || got.LeaseGeneration != 3 {
		t.Fatalf("request body = %+v", got)
	}
	if _, err := base64.StdEncoding.DecodeString(got.EphemeralPublic); err != nil {
		t.Fatalf("ephemeral public not base64: %v", err)
	}
}

// TestSecretDeliveryAADLayout pins the authenticated-data layout.
func TestSecretDeliveryAADLayout(t *testing.T) {
	got := string(secretDeliveryAAD("runner", "job", 7, "NAME"))
	want := remoteSecretAADPrefix + "runner\x00job\x007\x00NAME"
	if got != want {
		t.Fatalf("AAD = %q, want %q", got, want)
	}
	// A fresh ephemeral key is generated per request and differs.
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		seen[string(priv.PublicKey().Bytes())] = true
	}
	if len(seen) != 2 {
		t.Fatal("ephemeral keys are not distinct")
	}
}
