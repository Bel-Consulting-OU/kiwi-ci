package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
)

// ctxAwareSecretStore refuses a release on a cancelled context: only a
// compensation that runs on its OWN live context can release the claim, so
// the test proves the release does not ride the (cancelled) request
// context.
type ctxAwareSecretStore struct {
	*dbFakeStore
}

func (c ctxAwareSecretStore) ReleaseSecretDelivery(ctx context.Context, jobID string, generation int64, secretName string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("secret release context cancelled: %w", err)
	}
	return c.dbFakeStore.ReleaseSecretDelivery(ctx, jobID, generation, secretName)
}

// failingBroker always fails resolution, modelling a post-claim broker
// failure: the claim must be compensated.
type failingBroker struct{ err error }

func (b failingBroker) Resolve(ctx context.Context, name string, scope secretbroker.SecretScope) (string, error) {
	return "", b.err
}

// TestSecretClaimReleaseOutlivesRequestCancellation pins P2-12: the request
// context is cancelled (client disconnect) at the post-claim failure point;
// the compensation must still release the durable claim, so a retry on a
// fresh request succeeds instead of being answered 409 by a stranded claim.
func TestSecretClaimReleaseOutlivesRequestCancellation(t *testing.T) {
	f := newDBFakeStore()
	s := New("secret")
	if err := s.SwitchToDB(ctxAwareSecretStore{dbFakeStore: f}); err != nil {
		t.Fatal(err)
	}
	s.SecretBroker = failingBroker{err: errors.New("broker down")}
	jobID, runnerID, token, gen := seedDBSecretJob(t, f, s, []string{"tok"})
	_, pubB64 := ephemeralKey(t)
	req := SecretRequest{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Name: "tok", EphemeralPublic: pubB64}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	// The request context is cancelled BEFORE the handler runs, modelling a
	// client disconnect at the failure point.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+jobID+"/secrets", bytes.NewReader(body))
	r = r.WithContext(ctx)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("broker failure = %d, want 500: %s", w.Code, w.Body.String())
	}

	// The compensation ran on its own context: the claim is released.
	f.mu.Lock()
	claims := len(f.secretClaims)
	f.mu.Unlock()
	if claims != 0 {
		t.Fatalf("stranded claims after cancelled request = %d, want 0", claims)
	}

	// A fresh request with a healthy broker delivers the secret.
	s.SecretBroker = secretbroker.StaticBroker{"tok": "v"}
	c := newTestClient(t, s.Handler(), "secret")
	_, pubB64 = ephemeralKey(t)
	req.EphemeralPublic = pubB64
	if w := issue(t, c, jobID, req); w.Code != http.StatusOK {
		t.Fatalf("retry after released claim = %d, want 200: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	claimed := len(f.secretClaims)
	f.mu.Unlock()
	if claimed != 1 {
		t.Fatalf("claims after successful retry = %d, want 1", claimed)
	}
}
