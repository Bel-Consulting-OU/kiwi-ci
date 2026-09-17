package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
)

// TestSecretAADContextBinding proves the sealed envelope is bound to the
// exact delivery context via authenticated data: opening with a different
// runner, job, generation or name must fail, while the exact tuple opens.
func TestSecretAADContextBinding(t *testing.T) {
	const value = "aad-bound-value"
	s := New("secret")
	s.SecretBroker = secretbroker.StaticBroker{"tok": value}
	c := newTestClient(t, s.Handler(), "secret")
	jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
	priv, pubB64 := ephemeralKey(t)
	w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64})
	if w.Code != http.StatusOK {
		t.Fatalf("issue: %d %s", w.Code, w.Body.String())
	}
	var out SecretResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	ct, err := base64.StdEncoding.DecodeString(out.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := base64.StdEncoding.DecodeString(out.EphemeralPublic)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.StdEncoding.DecodeString(out.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	env := secretbroker.EncryptedDelivery{Ciphertext: ct, EphemeralPublic: ep, Nonce: nonce}
	// Exact context opens.
	plain, err := secretbroker.OpenEnvelope(env, priv, secretAAD(runnerID, jobID, gen, "tok"))
	if err != nil || string(plain) != value {
		t.Fatalf("exact AAD must open: %v %q", err, plain)
	}
	// Every single-field substitution must fail authentication.
	wrong := []struct {
		name       string
		runner, id string
		gen        int64
		secret     string
	}{
		{"wrong runner", "other-runner", jobID, gen, "tok"},
		{"runner prefix", runnerID + "x", jobID, gen, "tok"},
		{"wrong job", runnerID, "other-job", gen, "tok"},
		{"job suffix", runnerID, jobID + "x", gen, "tok"},
		{"wrong generation", runnerID, jobID, gen + 1, "tok"},
		{"generation zero", runnerID, jobID, 0, "tok"},
		{"wrong name", runnerID, jobID, gen, "other"},
		{"name suffix", runnerID, jobID, gen, "tok "},
		{"empty name", runnerID, jobID, gen, ""},
		{"empty runner", "", jobID, gen, "tok"},
		{"empty job", runnerID, "", gen, "tok"},
	}
	for _, tc := range wrong {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := secretbroker.OpenEnvelope(env, priv, secretAAD(tc.runner, tc.id, tc.gen, tc.secret)); err == nil {
				t.Fatal("envelope opened under a wrong AAD context")
			}
		})
	}
	// A different recipient key must fail too (sealed to the ephemeral key).
	otherPriv, _ := ephemeralKey(t)
	if _, err := secretbroker.OpenEnvelope(env, otherPriv, secretAAD(runnerID, jobID, gen, "tok")); err == nil {
		t.Fatal("envelope opened with an unrelated private key")
	}
}

// TestIssueSecretClaimSingleUseAcrossReplicas proves the durable claim is
// shared: two live control-plane instances on the same store can deliver a
// given (job, generation, name) exactly once, even concurrently.
func TestIssueSecretClaimSingleUseAcrossReplicas(t *testing.T) {
	f := newDBFakeStore()
	s1 := dbSecretServer(t, f)
	s2 := dbSecretServer(t, f)
	c1 := newTestClient(t, s1.Handler(), "secret")
	c2 := newTestClient(t, s2.Handler(), "secret")
	jobID, runnerID, token, gen := seedDBSecretJob(t, f, s1, []string{"tok"})

	_, pub1 := ephemeralKey(t)
	_, pub2 := ephemeralKey(t)
	req1 := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pub1}
	req2 := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pub2}

	codes := make(chan int, 2)
	var wg sync.WaitGroup
	for _, tgt := range []struct {
		c   *testClient
		req SecretRequest
	}{{c1, req1}, {c2, req2}} {
		wg.Add(1)
		go func(c *testClient, req SecretRequest) {
			defer wg.Done()
			codes <- issue(t, c, jobID, req).Code
		}(tgt.c, tgt.req)
	}
	wg.Wait()
	close(codes)
	ok, conflict := 0, 0
	for code := range codes {
		switch code {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
			conflict++
		default:
			t.Fatalf("unexpected cross-replica status %d", code)
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("cross-replica delivery: %d ok, %d conflict; want exactly one each", ok, conflict)
	}
	// A third replica sees the same durable claim.
	s3 := dbSecretServer(t, f)
	c3 := newTestClient(t, s3.Handler(), "secret")
	_, pub3 := ephemeralKey(t)
	req3 := req1
	req3.EphemeralPublic = pub3
	if w := issue(t, c3, jobID, req3); w.Code != http.StatusConflict {
		t.Fatalf("third replica replay = %d, want 409", w.Code)
	}
}

// flakyBroker fails the first resolve and then delegates to the static
// broker, modelling a transient broker outage.
type flakyBroker struct {
	mu      sync.Mutex
	failed  bool
	values  secretbroker.StaticBroker
	failErr error
}

func (b *flakyBroker) Resolve(ctx context.Context, name string, scope secretbroker.SecretScope) (string, error) {
	b.mu.Lock()
	if !b.failed {
		b.failed = true
		b.mu.Unlock()
		if b.failErr != nil {
			return "", b.failErr
		}
		return "", errors.New("broker: transient outage")
	}
	b.mu.Unlock()
	return b.values.Resolve(ctx, name, scope)
}

// TestBrokerFailureReleasesClaimAndAllowsRetry proves a failed broker
// resolution does not consume the once-only delivery in either mode: the
// retry after recovery succeeds.
func TestBrokerFailureReleasesClaimAndAllowsRetry(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		s := New("secret")
		broker := &flakyBroker{values: secretbroker.StaticBroker{"tok": "v"}}
		s.SecretBroker = broker
		c := newTestClient(t, s.Handler(), "secret")
		jobID, runnerID, token, gen := seedJob(t, s, true, []string{"tok"})
		_, pubB64 := ephemeralKey(t)
		req := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64}
		w := issue(t, c, jobID, req)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("broker outage = %d, want 500: %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "ciphertext") {
			t.Fatal("envelope leaked on broker failure")
		}
		// Receipt must have been released: the retry after recovery works.
		s.mu.Lock()
		_, still := s.secretReceipts[secretReceiptKey(jobID, gen, "tok")]
		s.mu.Unlock()
		if still {
			t.Fatal("failed resolution kept the memory receipt")
		}
		_, pubB64 = ephemeralKey(t)
		req.EphemeralPublic = pubB64
		if w := issue(t, c, jobID, req); w.Code != http.StatusOK {
			t.Fatalf("retry after broker recovery = %d, want 200: %s", w.Code, w.Body.String())
		}
	})
	t.Run("db", func(t *testing.T) {
		f := newDBFakeStore()
		s := dbSecretServer(t, f)
		s.SecretBroker = &flakyBroker{values: secretbroker.StaticBroker{"tok": "v"}}
		c := newTestClient(t, s.Handler(), "secret")
		jobID, runnerID, token, gen := seedDBSecretJob(t, f, s, []string{"tok"})
		_, pubB64 := ephemeralKey(t)
		req := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64}
		if w := issue(t, c, jobID, req); w.Code != http.StatusInternalServerError {
			t.Fatalf("broker outage = %d, want 500", w.Code)
		}
		f.mu.Lock()
		claims := len(f.secretClaims)
		f.mu.Unlock()
		if claims != 0 {
			t.Fatalf("failed resolution kept %d durable claims", claims)
		}
		_, pubB64 = ephemeralKey(t)
		req.EphemeralPublic = pubB64
		if w := issue(t, c, jobID, req); w.Code != http.StatusOK {
			t.Fatalf("retry after broker recovery = %d, want 200: %s", w.Code, w.Body.String())
		}
	})
}

// TestInvalidEphemeralKeyReleasesClaim covers the post-claim validation
// failure: a malformed ephemeral key must not consume the delivery.
func TestInvalidEphemeralKeyReleasesClaim(t *testing.T) {
	for _, mode := range []string{"memory", "db"} {
		t.Run(mode, func(t *testing.T) {
			var s *Server
			var jobID, runnerID, token string
			var gen int64
			var f *dbFakeStore
			if mode == "db" {
				f = newDBFakeStore()
				s = dbSecretServer(t, f)
				jobID, runnerID, token, gen = seedDBSecretJob(t, f, s, []string{"tok"})
			} else {
				s = New("secret")
				s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
				jobID, runnerID, token, gen = seedJob(t, s, true, []string{"tok"})
			}
			c := newTestClient(t, s.Handler(), "secret")
			bad := []string{"", "!!!", base64.StdEncoding.EncodeToString([]byte("short")), base64.StdEncoding.EncodeToString(make([]byte, 33))}
			for _, pub := range bad {
				w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pub})
				if w.Code != http.StatusBadRequest {
					t.Fatalf("bad ephemeral key %q = %d, want 400", pub, w.Code)
				}
			}
			// After all those failures the delivery is still available.
			_, pub := ephemeralKey(t)
			if w := issue(t, c, jobID, SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pub}); w.Code != http.StatusOK {
				t.Fatalf("delivery burned by invalid keys: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
