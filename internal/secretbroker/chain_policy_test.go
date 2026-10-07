package secretbroker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// callCountBroker counts resolutions and returns a fixed value or error.
type callCountBroker struct {
	value string
	err   error
	calls atomic.Int64
}

func (b *callCountBroker) Resolve(context.Context, string, SecretScope) (string, error) {
	b.calls.Add(1)
	if b.err != nil {
		return "", b.err
	}
	return b.value, nil
}

// vaultServer serves one fixed status/body for every Vault request.
func vaultServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestChainVaultForbiddenFailsClosed pins the P1 fix: an authoritative 403
// from Vault must NOT fall through to the static broker, even when the static
// broker holds the requested key.
func TestChainVaultForbiddenFailsClosed(t *testing.T) {
	srv := vaultServer(t, http.StatusForbidden, `{"errors":["permission denied"],"marker":"provider-body-marker"}`)
	static := &callCountBroker{value: "static-production-value"}
	chain := ChainBroker{Brokers: []Broker{&VaultClient{Address: srv.URL}, static}}

	v, err := chain.Resolve(context.Background(), "DEPLOY_KEY", SecretScope{})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if v != "" {
		t.Fatalf("secret delivered despite 403: %q", v)
	}
	if got := static.calls.Load(); got != 0 {
		t.Fatalf("static broker consulted %d time(s) after a 403", got)
	}
	if !strings.Contains(err.Error(), "vault") {
		t.Fatalf("error does not name the provider: %v", err)
	}
	if strings.Contains(err.Error(), "provider-body-marker") || strings.Contains(err.Error(), "static-production-value") {
		t.Fatalf("error leaks provider body or secret value: %v", err)
	}
}

// TestChainVaultUnauthorizedFailsClosed pins that expired/invalid credentials
// never trigger a fallback.
func TestChainVaultUnauthorizedFailsClosed(t *testing.T) {
	srv := vaultServer(t, http.StatusUnauthorized, `{"errors":["invalid token"],"marker":"provider-body-marker"}`)
	static := &callCountBroker{value: "static-production-value"}
	chain := ChainBroker{Brokers: []Broker{&VaultClient{Address: srv.URL}, static}}

	v, err := chain.Resolve(context.Background(), "DEPLOY_KEY", SecretScope{})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if v != "" || static.calls.Load() != 0 {
		t.Fatalf("fail-open after 401: value=%q static calls=%d", v, static.calls.Load())
	}
	if strings.Contains(err.Error(), "provider-body-marker") {
		t.Fatalf("error leaks provider body: %v", err)
	}
}

// TestChainVaultUnavailableFailsClosedByDefault pins that transport, TLS and
// timeout failures are Unavailable and do NOT fall through under the default
// policy.
func TestChainVaultUnavailableFailsClosedByDefault(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		boom := errors.New("connection refused")
		vault := &VaultClient{Address: "https://vault.test", HTTPClient: &http.Client{Transport: failTripper{err: boom}}}
		static := &callCountBroker{value: "fallback"}
		_, err := (&ChainBroker{Brokers: []Broker{vault, static}}).Resolve(context.Background(), "K", SecretScope{})
		if !errors.Is(err, ErrUnavailable) || !errors.Is(err, boom) {
			t.Fatalf("err = %v, want ErrUnavailable wrapping the transport cause", err)
		}
		if static.calls.Load() != 0 {
			t.Fatal("static broker consulted after a transport failure")
		}
	})
	t.Run("tls", func(t *testing.T) {
		// The test server's certificate is not trusted by the hardened
		// default client, producing a real TLS verification failure.
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"data":{"data":{"value":"never-delivered"}}}`))
		}))
		t.Cleanup(srv.Close)
		static := &callCountBroker{value: "fallback"}
		chain := ChainBroker{Brokers: []Broker{&VaultClient{Address: srv.URL}, static}}
		v, err := chain.Resolve(context.Background(), "K", SecretScope{})
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("TLS failure = %v, want ErrUnavailable", err)
		}
		if v != "" || static.calls.Load() != 0 {
			t.Fatalf("fail-open after TLS failure: value=%q static calls=%d", v, static.calls.Load())
		}
	})
	t.Run("timeout", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		t.Cleanup(srv.Close)
		static := &callCountBroker{value: "fallback"}
		chain := ChainBroker{Brokers: []Broker{&VaultClient{Address: srv.URL}, static}}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		v, err := chain.Resolve(ctx, "K", SecretScope{})
		if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("timeout = %v, want ErrUnavailable wrapping the deadline", err)
		}
		if v != "" || static.calls.Load() != 0 {
			t.Fatalf("fail-open after timeout: value=%q static calls=%d", v, static.calls.Load())
		}
	})
}

// TestChainVaultNotFoundAdvancesByDefault pins the one permitted fallback.
func TestChainVaultNotFoundAdvancesByDefault(t *testing.T) {
	srv := vaultServer(t, http.StatusNotFound, `{"errors":["missing"],"marker":"provider-body-marker"}`)
	static := &callCountBroker{value: "fallback-value"}
	chain := ChainBroker{Brokers: []Broker{&VaultClient{Address: srv.URL}, static}}

	v, err := chain.Resolve(context.Background(), "K", SecretScope{})
	if err != nil {
		t.Fatalf("not_found must advance the default chain: %v", err)
	}
	if v != "fallback-value" || static.calls.Load() != 1 {
		t.Fatalf("got value=%q static calls=%d, want the static fallback once", v, static.calls.Load())
	}
}

// TestChainFallbackOnUnavailable pins the opt-in policy: an outage falls
// through, but a 403 still fails closed even when the policy names
// unavailable.
func TestChainFallbackOnUnavailable(t *testing.T) {
	policy := []string{FallbackClassNotFound, FallbackClassUnavailable}

	t.Run("outage falls through", func(t *testing.T) {
		srv := vaultServer(t, http.StatusInternalServerError, "provider-body-marker")
		static := &callCountBroker{value: "fallback-value"}
		chain := ChainBroker{Brokers: []Broker{&VaultClient{Address: srv.URL}, static}, FallbackOn: policy}
		v, err := chain.Resolve(context.Background(), "K", SecretScope{})
		if err != nil || v != "fallback-value" {
			t.Fatalf("outage with fallback_on unavailable = (%q, %v)", v, err)
		}
		if static.calls.Load() != 1 {
			t.Fatalf("static calls = %d, want 1", static.calls.Load())
		}
	})

	t.Run("forbidden still fails closed", func(t *testing.T) {
		srv := vaultServer(t, http.StatusForbidden, `{"errors":["permission denied"]}`)
		static := &callCountBroker{value: "fallback-value"}
		chain := ChainBroker{Brokers: []Broker{&VaultClient{Address: srv.URL}, static}, FallbackOn: policy}
		v, err := chain.Resolve(context.Background(), "K", SecretScope{})
		if !errors.Is(err, ErrForbidden) {
			t.Fatalf("403 with fallback_on unavailable = %v, want ErrForbidden", err)
		}
		if v != "" || static.calls.Load() != 0 {
			t.Fatalf("fail-open after 403: value=%q static calls=%d", v, static.calls.Load())
		}
	})

	t.Run("unavailable policy is not needed for not_found", func(t *testing.T) {
		// A 404 must still advance when only not_found is configured.
		srv := vaultServer(t, http.StatusNotFound, `{"errors":["missing"]}`)
		static := &callCountBroker{value: "fallback-value"}
		chain := ChainBroker{Brokers: []Broker{&VaultClient{Address: srv.URL}, static}, FallbackOn: DefaultFallbackOn}
		v, err := chain.Resolve(context.Background(), "K", SecretScope{})
		if err != nil || v != "fallback-value" {
			t.Fatalf("not_found = (%q, %v)", v, err)
		}
	})
}

// TestChainMalformedResponseFailsClosed pins that an undecodable or
// structurally unusable response never falls through.
func TestChainMalformedResponseFailsClosed(t *testing.T) {
	cases := map[string]string{
		"undecodable": `not json`,
		"no data":     `{"data":{"data":{}}}`,
	}
	for label, body := range cases {
		t.Run(label, func(t *testing.T) {
			srv := vaultServer(t, http.StatusOK, body)
			static := &callCountBroker{value: "fallback-value"}
			chain := ChainBroker{Brokers: []Broker{&VaultClient{Address: srv.URL}, static}}
			v, err := chain.Resolve(context.Background(), "K", SecretScope{})
			if !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("err = %v, want ErrMalformedResponse", err)
			}
			if v != "" || static.calls.Load() != 0 {
				t.Fatalf("fail-open after malformed response: value=%q static calls=%d", v, static.calls.Load())
			}
		})
	}
}

// contextWaitBroker blocks until its context is canceled, then returns the
// ctx error classified as Unavailable.
type contextWaitBroker struct{ calls atomic.Int64 }

func (b *contextWaitBroker) Resolve(ctx context.Context, _ string, _ SecretScope) (string, error) {
	b.calls.Add(1)
	<-ctx.Done()
	return "", transportError("test", "request failed", ctx.Err())
}

// TestChainCancellationNeverFallsBack pins that a canceled context stops the
// chain immediately, preserves the ctx error, and never consults a later
// broker even when the policy includes unavailable.
func TestChainCancellationNeverFallsBack(t *testing.T) {
	policy := []string{FallbackClassNotFound, FallbackClassUnavailable}

	t.Run("already canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		first := &callCountBroker{value: "first"}
		static := &callCountBroker{value: "fallback-value"}
		chain := ChainBroker{Brokers: []Broker{first, static}, FallbackOn: policy}
		v, err := chain.Resolve(ctx, "K", SecretScope{})
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("err = %v, want context.Canceled classified Unavailable", err)
		}
		if v != "" || first.calls.Load() != 0 || static.calls.Load() != 0 {
			t.Fatalf("brokers consulted after cancellation: first=%d static=%d value=%q",
				first.calls.Load(), static.calls.Load(), v)
		}
	})

	t.Run("canceled during resolve", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		blocker := &contextWaitBroker{}
		static := &callCountBroker{value: "fallback-value"}
		chain := ChainBroker{Brokers: []Broker{blocker, static}, FallbackOn: policy}

		type result struct {
			value string
			err   error
		}
		done := make(chan result, 1)
		go func() {
			v, err := chain.Resolve(ctx, "K", SecretScope{})
			done <- result{v, err}
		}()
		deadline := time.Now().Add(2 * time.Second)
		for blocker.calls.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if blocker.calls.Load() != 1 {
			t.Fatal("blocking broker was never consulted")
		}
		cancel()
		got := <-done
		if !errors.Is(got.err, context.Canceled) || !errors.Is(got.err, ErrUnavailable) {
			t.Fatalf("err = %v, want context.Canceled classified Unavailable", got.err)
		}
		if got.value != "" || static.calls.Load() != 0 {
			t.Fatalf("fail-open after cancellation: value=%q static calls=%d", got.value, static.calls.Load())
		}
	})
}

// TestChainNeverConsultsLaterBrokerForNonFallbackClass proves with call
// counters that only the configured classes advance the chain.
func TestChainNeverConsultsLaterBrokerForNonFallbackClass(t *testing.T) {
	cases := []struct {
		label   string
		class   error
		plain   bool
		advance bool
	}{
		{"not_found advances", ErrSecretNotFound, false, true},
		{"unauthorized fails closed", ErrUnauthorized, false, false},
		{"forbidden fails closed", ErrForbidden, false, false},
		{"malformed fails closed", ErrMalformedResponse, false, false},
		{"unavailable fails closed by default", ErrUnavailable, false, false},
		{"unclassified fails closed", nil, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			var first *callCountBroker
			if tc.plain {
				first = &callCountBroker{err: errors.New("raw provider failure")}
			} else {
				first = &callCountBroker{err: classError("test", tc.class, "injected failure", nil)}
			}
			later := &callCountBroker{value: "later-value"}
			chain := ChainBroker{Brokers: []Broker{first, later}}

			v, err := chain.Resolve(context.Background(), "K", SecretScope{})
			if tc.advance {
				if err != nil || v != "later-value" {
					t.Fatalf("class must advance: (%q, %v)", v, err)
				}
				if later.calls.Load() != 1 {
					t.Fatalf("later broker calls = %d, want 1", later.calls.Load())
				}
				return
			}
			if err == nil {
				t.Fatalf("class must fail closed, got value %q", v)
			}
			if v != "" || later.calls.Load() != 0 {
				t.Fatalf("later broker consulted for a non-fallback class: value=%q calls=%d", v, later.calls.Load())
			}
			if !strings.Contains(err.Error(), "chain stopped") {
				t.Fatalf("chain did not annotate the stopping class: %v", err)
			}
			if tc.class != nil && !errors.Is(err, tc.class) {
				t.Fatalf("err = %v, want class %v", err, tc.class)
			}
		})
	}

	t.Run("empty explicit policy never advances", func(t *testing.T) {
		first := &callCountBroker{err: classError("test", ErrSecretNotFound, "missing", nil)}
		later := &callCountBroker{value: "later-value"}
		chain := ChainBroker{Brokers: []Broker{first, later}, FallbackOn: []string{}}
		v, err := chain.Resolve(context.Background(), "K", SecretScope{})
		if !errors.Is(err, ErrSecretNotFound) || v != "" || later.calls.Load() != 0 {
			t.Fatalf("empty policy = (%q, %v), later calls=%d", v, err, later.calls.Load())
		}
	})
}
