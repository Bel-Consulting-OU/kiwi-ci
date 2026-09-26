package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestOIDCIssuanceRefusalMapping pins the HTTP contract of every typed
// commit-time refusal: a vanished job is 404, authorization-shaped refusals
// are 403, every lease/identity refusal is 409, an unsupported store is 503
// and an audit failure is a 500 that never carries a token.
func TestOIDCIssuanceRefusalMapping(t *testing.T) {
	s := New("secret")
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"missing job", storage.ErrNotFound, http.StatusNotFound},
		{"untrusted", storage.ErrOIDCIssuanceUntrusted, http.StatusForbidden},
		{"not allowed", storage.ErrOIDCIssuanceNotAllowed, http.StatusForbidden},
		{"audience", storage.ErrOIDCIssuanceAudience, http.StatusForbidden},
		{"revoked", storage.ErrOIDCIssuanceRevoked, http.StatusConflict},
		{"runner replaced", storage.ErrOIDCIssuanceRunner, http.StatusConflict},
		{"generation replaced", storage.ErrOIDCIssuanceGeneration, http.StatusConflict},
		{"token changed", storage.ErrOIDCIssuanceToken, http.StatusConflict},
		{"expired", storage.ErrOIDCIssuanceExpired, http.StatusConflict},
		{"identity", storage.ErrOIDCIssuanceIdentity, http.StatusConflict},
		{"store unsupported", errOIDCIssuanceStoreUnsupported, http.StatusServiceUnavailable},
		{"audit failed", errOIDCIssuanceAudit, http.StatusInternalServerError},
		{"unknown", errors.New("boom"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-oidc/oidc", nil)
			w := httptest.NewRecorder()
			s.oidcIssuanceRefusal(w, r, tc.err)
			if w.Code != tc.want {
				t.Fatalf("refusal mapping = %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
			if strings.Contains(w.Body.String(), `"value"`) {
				t.Fatal("refusal leaked a credential")
			}
		})
	}
}

// TestOIDCIssuanceCommitRefusals covers the handler-level refusals that only
// exist at the final commit: a job that vanishes between the preliminary
// authentication and the commit is 404, a trust or permission revocation in
// that window is 403, and a DB store without the transactional issuance
// capability is 503 — never a token.
func TestOIDCIssuanceCommitRefusals(t *testing.T) {
	t.Run("job vanished", func(t *testing.T) {
		s := newOIDCTestServer(t, false)
		seedOIDCJob(t, s, "lease1")
		withOIDCBeforeCommitHook(t, func() {
			s.mu.Lock()
			delete(s.jobs, "job-oidc")
			s.mu.Unlock()
		})
		w := issueOIDCForStatus(t, s, "Bearer lease1", "https://aud.example.com")
		if w.Code != http.StatusNotFound {
			t.Fatalf("vanished job = %d, want 404: %s", w.Code, w.Body.String())
		}
		requireNoToken(t, w)
	})

	t.Run("trust revoked", func(t *testing.T) {
		s, mutate := oidcScopeServer(t, false)
		withOIDCBeforeCommitHook(t, func() { mutate(func(j *model.Job) { j.Trusted = false }) })
		w := issueOIDCForStatus(t, s, "Bearer lease1", "https://aud.example.com")
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "untrusted") {
			t.Fatalf("trust revocation at commit = %d: %s", w.Code, w.Body.String())
		}
		requireNoToken(t, w)
	})

	t.Run("permission revoked", func(t *testing.T) {
		s, mutate := oidcScopeServer(t, false)
		withOIDCBeforeCommitHook(t, func() { mutate(func(j *model.Job) { j.OIDCAllowed = false }) })
		w := issueOIDCForStatus(t, s, "Bearer lease1", "https://aud.example.com")
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "permissions.id_token") {
			t.Fatalf("permission revocation at commit = %d: %s", w.Code, w.Body.String())
		}
		requireNoToken(t, w)
	})

	t.Run("store without issuance capability", func(t *testing.T) {
		f := newDBFakeStore()
		s := New("secret")
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		s.ExternalURL = "https://ci.example.com"
		seedDBOIDCJob(t, f, s, "lease1")
		s.DB = fenceOnlyStore{Store: f, fence: f}
		w := issueOIDCForStatus(t, s, "Bearer lease1", "https://aud.example.com")
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("store without LeaseOIDCIssueStore = %d, want 503: %s", w.Code, w.Body.String())
		}
		requireNoToken(t, w)
	})
}

// TestCommitOIDCIssuanceLockedRejectsMalformedRequest pins the memory-mode
// authority's input contract: a request that cannot address an issuance (no
// job id) is refused before the lock and before any audit append.
func TestCommitOIDCIssuanceLockedRejectsMalformedRequest(t *testing.T) {
	s := New("secret")
	if _, err := s.commitOIDCIssuanceLocked(storage.OIDCIssuance{}); err == nil {
		t.Fatal("empty issuance request accepted")
	}
}

// TestAuditOIDCIssuanceFailsClosedOnIDFailure proves the fs-mode audit append
// cannot degrade into a silent success: when the audit event id cannot be
// minted, issuance reports the failure so the caller refuses to return a
// credential.
func TestAuditOIDCIssuanceFailsClosedOnIDFailure(t *testing.T) {
	s := NewPersistentServerForTest(t)
	restore := seamRand(t, &fcErrReader{})
	defer restore()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-oidc/oidc", nil)
	if err := s.auditOIDCIssuance(r, "runner-1", "run-oidc", "job-oidc", "kid", "build", "aud"); err == nil {
		t.Fatal("audit append with a failing id source reported success")
	}
}
