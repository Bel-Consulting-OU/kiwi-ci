package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// withOIDCBeforeCommitHook installs fn as the pre-commit test seam so a test
// can interleave a concurrent cancel/complete/revoke/audience change between
// the preliminary authentication (read + token check + JWT signing) and the
// final commit-time issuance transaction.
func withOIDCBeforeCommitHook(t *testing.T, fn func()) {
	t.Helper()
	prev := oidcBeforeCommitHook
	oidcBeforeCommitHook = fn
	t.Cleanup(func() { oidcBeforeCommitHook = prev })
}

// issueOIDCForStatus issues one job id_token request with the given bearer
// header value and returns the recorder.
func issueOIDCForStatus(t *testing.T, s *Server, authHeader, audience string) *httptest.ResponseRecorder {
	t.Helper()
	headers := map[string]string{}
	if authHeader != "" {
		headers["Authorization"] = authHeader
	}
	return newTestClient(t, s.Handler(), "").do(http.MethodPost, "/api/v1/jobs/job-oidc/oidc", map[string]any{"audience": audience}, headers)
}

// requireNoToken fails a test whenever a denied issuance leaked a credential.
func requireNoToken(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if strings.Contains(w.Body.String(), `"value"`) {
		t.Fatalf("credential leaked on a denied issuance: %s", w.Body.String())
	}
}

// TestOIDCIssuanceRevokedBetweenAuthAndCommitReturns409 is the P1 regression:
// a cancellation/lease clearance that lands between the preliminary lease
// authentication and the final issuance commit must refuse the issuance with
// 409. The already-signed JWT is discarded; no credential may be returned.
func TestOIDCIssuanceRevokedBetweenAuthAndCommitReturns409(t *testing.T) {
	for _, mode := range []string{"memory", "db"} {
		t.Run(mode, func(t *testing.T) {
			s, mutate := oidcScopeServer(t, mode == "db")
			withOIDCBeforeCommitHook(t, func() {
				mutate(func(j *model.Job) {
					j.Status = model.StatusCancelled
					j.LeaseExpiresAt = nil
					j.LeaseTokenHash = nil
					j.LeaseRunnerID = ""
				})
			})
			w := issueOIDCForStatus(t, s, "Bearer lease1", "https://aud.example.com")
			if w.Code != http.StatusConflict {
				t.Fatalf("revocation between auth and commit = %d, want 409: %s", w.Code, w.Body.String())
			}
			requireNoToken(t, w)
		})
	}
}

// TestOIDCIssuanceCompletedBetweenAuthAndCommitReturns409 pins the same window
// for a job completing (or otherwise leaving running) instead of being
// cancelled.
func TestOIDCIssuanceCompletedBetweenAuthAndCommitReturns409(t *testing.T) {
	for _, mode := range []string{"memory", "db"} {
		t.Run(mode, func(t *testing.T) {
			s, mutate := oidcScopeServer(t, mode == "db")
			withOIDCBeforeCommitHook(t, func() {
				mutate(func(j *model.Job) {
					j.Status = model.StatusSuccess
					j.LeaseExpiresAt = nil
					j.LeaseTokenHash = nil
					j.LeaseRunnerID = ""
				})
			})
			w := issueOIDCForStatus(t, s, "Bearer lease1", "https://aud.example.com")
			if w.Code != http.StatusConflict {
				t.Fatalf("completion between auth and commit = %d, want 409: %s", w.Code, w.Body.String())
			}
			requireNoToken(t, w)
		})
	}
}

// TestOIDCIssuanceGenerationChangedBeforeCommitReturns409 pins the generation
// fence: a replacement lease (new generation) acquired between auth and commit
// invalidates the credential built from the old lease.
func TestOIDCIssuanceGenerationChangedBeforeCommitReturns409(t *testing.T) {
	for _, mode := range []string{"memory", "db"} {
		t.Run(mode, func(t *testing.T) {
			s, mutate := oidcScopeServer(t, mode == "db")
			withOIDCBeforeCommitHook(t, func() {
				mutate(func(j *model.Job) {
					j.LeaseGeneration++
				})
			})
			w := issueOIDCForStatus(t, s, "Bearer lease1", "https://aud.example.com")
			if w.Code != http.StatusConflict {
				t.Fatalf("generation change between auth and commit = %d, want 409: %s", w.Code, w.Body.String())
			}
			requireNoToken(t, w)
		})
	}
}

// TestOIDCIssuanceLeaseExpiresDuringCommitStallReturns409 is the W2-A
// regression: the handler authenticates a still-live lease, the signer/
// key-ring work (played by the pre-commit hook) stalls until the wall clock
// has passed the lease expiry, and the final transaction must then refuse at
// the STORAGE commit clock. The pre-fix commit judged the lease against the
// handler-captured IssuedAt, so it would have returned a token here.
func TestOIDCIssuanceLeaseExpiresDuringCommitStallReturns409(t *testing.T) {
	for _, mode := range []string{"memory", "db"} {
		t.Run(mode, func(t *testing.T) {
			s, mutate := oidcScopeServer(t, mode == "db")
			expiry := time.Now().UTC().Add(250 * time.Millisecond)
			mutate(func(j *model.Job) { j.LeaseExpiresAt = &expiry })
			withOIDCBeforeCommitHook(t, func() {
				deadline := expiry.Add(20 * time.Millisecond)
				for !time.Now().UTC().After(deadline) {
					time.Sleep(5 * time.Millisecond)
				}
			})
			w := issueOIDCForStatus(t, s, "Bearer lease1", "https://aud.example.com")
			if w.Code != http.StatusConflict {
				t.Fatalf("lease expiring during the commit stall = %d, want 409: %s", w.Code, w.Body.String())
			}
			requireNoToken(t, w)
		})
	}
}

// oidcTokenClaims decodes the claim set of a test-issued JWT.
func oidcTokenClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed jwt %q", token)
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(cb, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// TestOIDCIssuanceClaimsDerivedFromLockedIdentity is the W2-B happy path: the
// token returned in both storage modes carries the LOCKED job's value for
// every identity-bearing claim (revision and environment included), proving
// no claim is candidate-supplied or stale.
func TestOIDCIssuanceClaimsDerivedFromLockedIdentity(t *testing.T) {
	for _, mode := range []string{"memory", "db"} {
		t.Run(mode, func(t *testing.T) {
			s, mutate := oidcScopeServer(t, mode == "db")
			// An empty mutation snapshots the authoritative job under the
			// same lock the store uses.
			var locked model.Job
			mutate(func(j *model.Job) { locked = *j })
			tok := issueOIDCToken(t, s, "job-oidc", "lease1", "https://aud.example.com")
			claims := oidcTokenClaims(t, tok)
			want := map[string]any{
				"sub":           "repo:" + repoIDForJob(locked) + ":ref:" + locked.Ref + ":job:" + locked.Key,
				"repository":    locked.RepoFullName,
				"repository_id": repoIDForJob(locked),
				"ref":           locked.Ref,
				"sha":           locked.SHA,
				"event":         locked.Event,
				"run_id":        locked.RunID,
				"job_id":        locked.ID,
				"job":           locked.Key,
				"environment":   locked.Environment,
				"trusted":       locked.Trusted,
				"aud":           "https://aud.example.com",
			}
			for key, v := range want {
				if claims[key] != v {
					t.Fatalf("claim %q = %v, want the locked value %v", key, claims[key], v)
				}
			}
		})
	}
}

// TestOIDCIssuanceIdentityChangedBetweenAuthAndCommitReturns409 is the W2-B
// regression matrix: a job key, ref, sha, event or environment that changes
// between the preliminary read and the final transaction makes the commit
// refuse with 409 in BOTH storage modes, and the token is never built.
func TestOIDCIssuanceIdentityChangedBetweenAuthAndCommitReturns409(t *testing.T) {
	fields := []struct {
		name   string
		mutate func(*model.Job)
	}{
		{"job key", func(j *model.Job) { j.Key = "other" }},
		{"ref", func(j *model.Job) { j.Ref = "refs/heads/other" }},
		{"sha", func(j *model.Job) { j.SHA = "ffff" }},
		{"event", func(j *model.Job) { j.Event = "schedule" }},
		{"environment", func(j *model.Job) { j.Environment = "staging" }},
	}
	for _, mode := range []string{"memory", "db"} {
		for _, f := range fields {
			t.Run(mode+"/"+f.name, func(t *testing.T) {
				s, mutate := oidcScopeServer(t, mode == "db")
				withOIDCBeforeCommitHook(t, func() { mutate(f.mutate) })
				w := issueOIDCForStatus(t, s, "Bearer lease1", "https://aud.example.com")
				if w.Code != http.StatusConflict {
					t.Fatalf("%s changing between auth and commit = %d, want 409: %s", f.name, w.Code, w.Body.String())
				}
				requireNoToken(t, w)
			})
		}
	}
}

// TestOIDCIssuanceAudienceChangedBeforeCommitReturns403 pins the audience
// allowlist at commit time: narrowing the locked job's audiences after the
// preliminary check refuses the issuance with 403.
func TestOIDCIssuanceAudienceChangedBeforeCommitReturns403(t *testing.T) {
	for _, mode := range []string{"memory", "db"} {
		t.Run(mode, func(t *testing.T) {
			s, mutate := oidcScopeServer(t, mode == "db")
			withOIDCBeforeCommitHook(t, func() {
				mutate(func(j *model.Job) {
					j.OIDCAudiences = []string{"https://other.example.com"}
				})
			})
			w := issueOIDCForStatus(t, s, "Bearer lease1", "https://aud.example.com")
			if w.Code != http.StatusForbidden {
				t.Fatalf("audience change between auth and commit = %d, want 403: %s", w.Code, w.Body.String())
			}
			requireNoToken(t, w)
		})
	}
}

// countOIDCIssuedAudits counts the oidc.issued events in a slice.
func countOIDCIssuedAudits(events []model.AuditEvent) int {
	n := 0
	for _, e := range events {
		if e.Action == "oidc.issued" {
			n++
		}
	}
	return n
}

// TestOIDCIssuanceNeverReturnsJWTWithoutDurableAudit proves the invariant the
// commit refactor exists to enforce: a token is only ever returned after the
// oidc.issued audit row is durably committed in the same transaction. When the
// audit sink fails, the issuance answers 500 with no credential; once it
// recovers, the same issuance commits exactly one audit row and returns a
// token.
func TestOIDCIssuanceNeverReturnsJWTWithoutDurableAudit(t *testing.T) {
	t.Run("db mode", func(t *testing.T) {
		f := newDBFakeStore()
		s := New("secret")
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		s.ExternalURL = "https://ci.example.com"
		seedDBOIDCJob(t, f, s, "lease1")

		f.mu.Lock()
		f.auditErr = errors.New("audit: injected failure")
		f.mu.Unlock()
		w := issueOIDCForStatus(t, s, "Bearer lease1", "https://aud.example.com")
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("issuance with a failing audit sink = %d, want 500: %s", w.Code, w.Body.String())
		}
		requireNoToken(t, w)
		f.mu.Lock()
		before := countOIDCIssuedAudits(f.audit)
		f.mu.Unlock()
		if before != 0 {
			t.Fatalf("audit rows written despite the injected failure: %d", before)
		}

		// Recovery: the same request must now commit the audit and mint.
		f.mu.Lock()
		f.auditErr = nil
		f.mu.Unlock()
		issueOIDCToken(t, s, "job-oidc", "lease1", "https://aud.example.com")
		f.mu.Lock()
		after := countOIDCIssuedAudits(f.audit)
		f.mu.Unlock()
		if after != 1 {
			t.Fatalf("oidc.issued audit rows after recovery = %d, want 1", after)
		}
	})

	t.Run("fs mode", func(t *testing.T) {
		s := NewPersistentServerForTest(t)
		s.ExternalURL = "https://ci.example.com"
		_, jobID := seedOIDCJob(t, s, "lease1")

		blocker := filepath.Join(t.TempDir(), "audit-blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		prevRoot := s.store.Root
		s.store.Root = blocker
		w := newTestClient(t, s.Handler(), "lease1").do(http.MethodPost, "/api/v1/jobs/"+jobID+"/oidc", map[string]any{"audience": "https://aud.example.com"}, nil)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("fs issuance with a failing audit sink = %d, want 500: %s", w.Code, w.Body.String())
		}
		requireNoToken(t, w)

		s.store.Root = prevRoot
		issueOIDCToken(t, s, jobID, "lease1", "https://aud.example.com")
		raw, err := os.ReadFile(filepath.Join(s.store.Root, "audit.jsonl"))
		if err != nil {
			t.Fatalf("read audit trail: %v", err)
		}
		if !strings.Contains(string(raw), `"action":"oidc.issued"`) {
			t.Fatalf("durable audit trail lacks oidc.issued: %.400s", string(raw))
		}
	})
}

// TestOIDCIssuanceBearerSchemeIsRequired pins the strict bearer grammar at the
// issuance endpoint: a header that IS the raw lease token (no scheme) or any
// other malformed scheme must be refused, never treated as the credential.
func TestOIDCIssuanceBearerSchemeIsRequired(t *testing.T) {
	cases := []struct {
		name   string
		header string
	}{
		{"raw token without scheme", "lease1"},
		{"lowercase scheme", "bearer lease1"},
		{"no space after scheme", "Bearerlease1"},
		{"whitespace inside token", "Bearer le ase1"},
		{"comma inside token", "Bearer lease1,x"},
		{"empty token", "Bearer "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newOIDCTestServer(t, false)
			seedOIDCJob(t, s, "lease1")
			w := issueOIDCForStatus(t, s, tc.header, "https://aud.example.com")
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("issuance with Authorization %q = %d, want 401: %s", tc.header, w.Code, w.Body.String())
			}
			requireNoToken(t, w)
		})
	}
}
