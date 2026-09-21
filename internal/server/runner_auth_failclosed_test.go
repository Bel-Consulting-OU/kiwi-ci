package server

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestRunnerTierAuthFailsClosedOnStoreError proves the fail-open defect is
// gone: when the per-runner credential store errors, the runner tier answers
// 503 and NEVER falls back to the weaker shared runner token — not even when
// the presented bearer IS the shared token.
func TestRunnerTierAuthFailsClosedOnStoreError(t *testing.T) {
	s, err := NewPersistent("shared-token", "admin-token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.DB = errTokenStore{dbFakeStore: f, hasErr: errors.New("runner token table unavailable")}
	s.runnerTokensDBAt = time.Time{}

	for _, bearer := range []string{"shared-token", "some-other-token", ""} {
		w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", bearer, `{}`)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("bearer %q with a failing token store = %d, want 503 (no shared-token fallback)", bearer, w.Code)
		}
	}
}

// TestRunnerTierAuthFailsClosedOnLookupError covers the second store call:
// per-runner credentials are known to exist (existence check cached), but
// resolving the presented digest fails. The request must fail closed. A
// store that does not even carry the RunnerTokenStore surface cannot hold
// per-runner credentials, so the dev shared-token path is unchanged there
// (production refuses that shape at startup).
func TestRunnerTierAuthFailsClosedOnLookupError(t *testing.T) {
	s, err := NewPersistent("shared-token", "admin-token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	f.runnerTokens[auth.TokenDigest("per-runner-token")] = "runner-a"
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	// Existence check succeeds (tokens exist), the digest lookup fails.
	s.DB = errTokenStore{dbFakeStore: f, lookupErr: errors.New("runner token lookup unavailable")}
	s.runnerTokensDBAt = time.Time{}

	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "per-runner-token", `{}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("failing digest lookup = %d, want 503", w.Code)
	}
	// A store without the RunnerTokenStore surface is a STATIC shape, not a
	// store error: it cannot hold per-runner credentials at all, so the
	// dev/bootstrap shared token path is unchanged (production refuses this
	// shape at startup).
	s.DB = struct{ storage.Store }{Store: f}
	s.runnerTokensDBAt = time.Time{}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "shared-token", `{}`)
	if w.Code == http.StatusUnauthorized || w.Code == http.StatusServiceUnavailable {
		t.Fatalf("store without the token surface = %d, want the dev shared-token path", w.Code)
	}
}

// TestRunnerSharedTokenDevBootstrapUnchanged pins the dev/bootstrap path: a
// memory-mode server with no per-runner credentials authenticates with the
// shared token, and stops accepting it the moment per-runner credentials are
// loaded.
func TestRunnerSharedTokenDevBootstrapUnchanged(t *testing.T) {
	s, err := NewPersistent("shared-token", "admin-token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "shared-token", `{}`); w.Code == http.StatusUnauthorized || w.Code == http.StatusServiceUnavailable {
		t.Fatalf("shared token in dev/bootstrap mode = %d, want the shared path to authenticate", w.Code)
	}
	s.LoadRunnerTokens(map[string]string{"runner-a": auth.TokenDigest("per-runner-token")})
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "shared-token", `{}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("shared token with per-runner credentials loaded = %d, want 401", w.Code)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "per-runner-token", `{}`); w.Code == http.StatusUnauthorized || w.Code == http.StatusServiceUnavailable {
		t.Fatalf("per-runner token = %d, want the per-runner path to authenticate", w.Code)
	}
}

// TestRunnerProductionModeRejectsSharedTokenDeterministically models the
// production wiring (which clears RunnerToken at startup once the per-runner
// contract holds): the shared token can no longer authenticate, per-runner
// bearer credentials still do, and a production server with no mechanism at
// all refuses runner traffic with 503.
func TestRunnerProductionModeRejectsSharedTokenDeterministically(t *testing.T) {
	s, err := NewPersistent("shared-token", "admin-token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.RunnerToken = "" // production startup policy
	s.LoadRunnerTokens(map[string]string{"runner-a": auth.TokenDigest("per-runner-token")})
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "shared-token", `{}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("shared token in production identity mode = %d, want 401", w.Code)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "per-runner-token", `{}`); w.Code == http.StatusUnauthorized || w.Code == http.StatusServiceUnavailable {
		t.Fatalf("per-runner token in production identity mode = %d, want it to authenticate", w.Code)
	}

	bare, err := NewPersistent("shared-token", "admin-token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bare.RunnerToken = ""
	if w := doJSON(t, bare, http.MethodPost, "/api/v1/runners/register", "shared-token", `{}`); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("production identity mode without any mechanism = %d, want 503", w.Code)
	}
}
