package secretbroker

// Dropped-response regressions for the runner's remote secret client: a
// committed delivery whose response was lost must be recoverable by a retry
// that presents the SAME ephemeral public key. The provider caches the
// keypair per (job, generation, secret) until the delivery opens, so the
// control plane can replay the exact committed envelope; a successful open
// clears the cache, and a generation change mints a new keypair.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// replaySecretServer models the control plane's retry-stable delivery
// contract: the first request for an identity commits (optionally dropping
// its response, modelling a lost acknowledgement), a retry presenting the
// SAME ephemeral public key gets the stored envelope verbatim, and any other
// key stays 409.
type replaySecretServer struct {
	dropFirst bool
	mu        sync.Mutex
	attempts  []string
	storedPub string
	envelope  secretResponse
	commits   int
}

func (s *replaySecretServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/jobs/{id}/secrets", func(w http.ResponseWriter, r *http.Request) {
		var in secretRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		s.attempts = append(s.attempts, in.EphemeralPublic)
		if s.storedPub != "" {
			stored, resp := s.storedPub, s.envelope
			s.mu.Unlock()
			if in.EphemeralPublic != stored {
				http.Error(w, "secret already delivered for this lease generation", http.StatusConflict)
				return
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		pubRaw, err := base64.StdEncoding.DecodeString(in.EphemeralPublic)
		if err != nil || len(pubRaw) != 32 {
			s.mu.Unlock()
			http.Error(w, "invalid ephemeral_public", http.StatusBadRequest)
			return
		}
		var pub [32]byte
		copy(pub[:], pubRaw)
		enc, err := SealEnvelope([]byte("replay-value"), pub, secretDeliveryAAD(in.RunnerID, "job-1", in.LeaseGeneration, in.Name))
		if err != nil {
			s.mu.Unlock()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.storedPub = in.EphemeralPublic
		s.envelope = secretResponse{
			Ciphertext:      base64.StdEncoding.EncodeToString(enc.Ciphertext),
			EphemeralPublic: base64.StdEncoding.EncodeToString(enc.EphemeralPublic),
			Nonce:           base64.StdEncoding.EncodeToString(enc.Nonce),
			LeaseGeneration: in.LeaseGeneration,
		}
		s.commits++
		drop := s.dropFirst
		s.mu.Unlock()
		if drop {
			// The commit is durable; the acknowledgement never reaches the
			// runner.
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, herr := hj.Hijack(); herr == nil {
					_ = conn.Close()
				}
			}
			return
		}
		_ = json.NewEncoder(w).Encode(s.envelope)
	})
	return mux
}

func (s *replaySecretServer) snapshot() (attempts []string, commits int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.attempts...), s.commits
}

// TestRemoteProviderTransportRetryReusesEphemeralKeyAndReplays is the dropped-
// response regression: the first delivery commits and the connection dies;
// the retry must present the SAME ephemeral public key, receive the stored
// envelope, and open it, with exactly one commit on the control plane.
func TestRemoteProviderTransportRetryReusesEphemeralKeyAndReplays(t *testing.T) {
	fsrv := &replaySecretServer{dropFirst: true}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	p := testProvider(ts)
	if _, err := p.Get(context.Background(), "API_TOKEN"); err == nil {
		t.Fatal("a dropped delivery response was not surfaced as a transport error")
	}
	got, err := p.Get(context.Background(), "API_TOKEN")
	if err != nil {
		t.Fatalf("retry with the cached key: %v", err)
	}
	if got != "replay-value" {
		t.Fatalf("replayed plaintext = %q, want %q", got, "replay-value")
	}
	attempts, commits := fsrv.snapshot()
	if len(attempts) != 2 {
		t.Fatalf("requests = %d, want 2 (first + retry)", len(attempts))
	}
	if attempts[0] != attempts[1] {
		t.Fatalf("retry minted a new ephemeral key: %s -> %s", attempts[0], attempts[1])
	}
	if commits != 1 {
		t.Fatalf("commits = %d, want exactly 1 (the retry must replay)", commits)
	}
}

// TestRemoteProviderSuccessClearsRetryKey proves the cache exists only for
// unacknowledged deliveries: after a successful open the next request mints a
// fresh keypair, so the control plane sees a different key and refuses 409.
func TestRemoteProviderSuccessClearsRetryKey(t *testing.T) {
	fsrv := &replaySecretServer{} // first delivery acknowledged normally
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	p := testProvider(ts)
	if _, err := p.Get(context.Background(), "API_TOKEN"); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	_, err := p.Get(context.Background(), "API_TOKEN")
	if err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("second delivery error = %v, want the 409 conflict", err)
	}
	attempts, _ := fsrv.snapshot()
	if len(attempts) != 2 {
		t.Fatalf("requests = %d, want 2", len(attempts))
	}
	if attempts[0] == attempts[1] {
		t.Fatal("successful delivery left its keypair cached; the next request reused it")
	}
}

// TestRemoteProviderGenerationChangeMintsNewKey proves a cached keypair is
// never reused across lease generations: advancing the provider generation
// drops old entries and the next request presents a new key.
func TestRemoteProviderGenerationChangeMintsNewKey(t *testing.T) {
	fsrv := &replaySecretServer{dropFirst: true}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	p := testProvider(ts)
	if _, err := p.Get(context.Background(), "API_TOKEN"); err == nil {
		t.Fatal("a dropped delivery response was not surfaced as a transport error")
	}
	p.LeaseGeneration++
	if _, err := p.Get(context.Background(), "API_TOKEN"); err == nil {
		t.Fatal("a new generation must not replay the old generation's delivery")
	}
	attempts, _ := fsrv.snapshot()
	if len(attempts) != 2 {
		t.Fatalf("requests = %d, want 2", len(attempts))
	}
	if attempts[0] == attempts[1] {
		t.Fatal("cached key was reused across a lease generation change")
	}
}
