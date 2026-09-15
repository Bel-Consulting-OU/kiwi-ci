package secretbroker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeSecretServer implements the control plane's secret delivery contract
// with a real SealEnvelope call so the provider round-trips against the same
// crypto the server uses.
type fakeSecretServer struct {
	plaintext string
	aadName   string // override the AAD name to simulate a context mismatch
	// generationDelta shifts the sealed/returned lease generation to
	// simulate a delivery minted under a different (stale) lease.
	generationDelta int64
	delivered       int32 // number of successful deliveries issued
}

type secretRequest struct {
	RunnerID        string `json:"runner_id"`
	LeaseToken      string `json:"lease_token"`
	LeaseGeneration int64  `json:"lease_generation"`
	Name            string `json:"name"`
	EphemeralPublic string `json:"ephemeral_public"`
}

type secretResponse struct {
	Ciphertext      string `json:"ciphertext"`
	EphemeralPublic string `json:"ephemeral_public"`
	Nonce           string `json:"nonce"`
	LeaseGeneration int64  `json:"lease_generation"`
}

func (f *fakeSecretServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/jobs/{id}/secrets", func(w http.ResponseWriter, r *http.Request) {
		var in secretRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if atomic.AddInt32(&f.delivered, 1) > 1 {
			http.Error(w, "secret already delivered for this lease generation", http.StatusConflict)
			return
		}
		pubRaw, err := base64.StdEncoding.DecodeString(in.EphemeralPublic)
		if err != nil || len(pubRaw) != 32 {
			http.Error(w, "invalid ephemeral_public", http.StatusBadRequest)
			return
		}
		var pub [32]byte
		copy(pub[:], pubRaw)
		name := in.Name
		if f.aadName != "" {
			name = f.aadName
		}
		aad := secretDeliveryAAD(in.RunnerID, r.PathValue("id"), in.LeaseGeneration+f.generationDelta, name)
		enc, err := SealEnvelope([]byte(f.plaintext), pub, aad)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(secretResponse{
			Ciphertext:      base64.StdEncoding.EncodeToString(enc.Ciphertext),
			EphemeralPublic: base64.StdEncoding.EncodeToString(enc.EphemeralPublic),
			Nonce:           base64.StdEncoding.EncodeToString(enc.Nonce),
			LeaseGeneration: in.LeaseGeneration + f.generationDelta,
		})
	})
	return mux
}

func testProvider(ts *httptest.Server, opts ...func(*RemoteProvider)) *RemoteProvider {
	p := &RemoteProvider{
		Server:          ts.URL,
		JobID:           "job-1",
		LeaseToken:      "lease-token",
		LeaseGeneration: 3,
		RunnerID:        "runner-1",
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func TestRemoteProviderDeliversSealedSecret(t *testing.T) {
	fsrv := &fakeSecretServer{plaintext: "hunter2-value"}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	got, err := testProvider(ts).Get(context.Background(), "API_TOKEN")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "hunter2-value" {
		t.Fatalf("plaintext = %q, want %q", got, "hunter2-value")
	}
}

func TestRemoteProviderAADMismatchFails(t *testing.T) {
	fsrv := &fakeSecretServer{plaintext: "hunter2-value", aadName: "OTHER_SECRET"}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	_, err := testProvider(ts).Get(context.Background(), "API_TOKEN")
	if err == nil {
		t.Fatal("expected AAD mismatch to fail the open")
	}
	if !strings.Contains(err.Error(), "open") {
		t.Fatalf("error = %q, want envelope open failure", err)
	}
}

func TestRemoteProviderSecondDeliveryConflictPropagates(t *testing.T) {
	fsrv := &fakeSecretServer{plaintext: "hunter2-value"}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	p := testProvider(ts)
	if _, err := p.Get(context.Background(), "API_TOKEN"); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	_, err := p.Get(context.Background(), "API_TOKEN")
	if err == nil {
		t.Fatal("expected the second delivery conflict to propagate")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Fatalf("error = %q, want 409 conflict surfaced", err)
	}
}

func TestRemoteProviderNeverFollowsRedirects(t *testing.T) {
	fsrv := &fakeSecretServer{plaintext: "hunter2-value"}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	// The redirect target would satisfy the request; the provider must
	// surface the redirect itself as an error instead of following it.
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ts.URL+"/api/v1/jobs/job-1/secrets", http.StatusFound)
	}))
	defer redirector.Close()

	p := testProvider(redirector)
	if _, err := p.Get(context.Background(), "API_TOKEN"); err == nil {
		t.Fatal("expected redirect refusal")
	} else if !strings.Contains(err.Error(), "302") {
		t.Fatalf("error = %q, want the 302 surfaced", err)
	}
	if got := atomic.LoadInt32(&fsrv.delivered); got != 0 {
		t.Fatalf("redirect was followed: target issued %d deliveries", got)
	}
}

func TestRemoteProviderRejectsWrongGeneration(t *testing.T) {
	fsrv := &fakeSecretServer{plaintext: "hunter2-value", generationDelta: 1}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	// The envelope itself opens (the server sealed it under the shifted
	// generation the response advertises); only the explicit generation
	// check must refuse the delivery.
	_, err := testProvider(ts).Get(context.Background(), "API_TOKEN")
	if err == nil || !strings.Contains(err.Error(), "lease generation") {
		t.Fatalf("error = %v, want lease generation mismatch", err)
	}
}
