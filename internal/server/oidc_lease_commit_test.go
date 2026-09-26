package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
