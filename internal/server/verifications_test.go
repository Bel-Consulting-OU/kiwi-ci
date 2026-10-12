package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/verifyapi"
)

// verificationFixture builds a Server with an in-memory Service, a stub
// evidence verifier and a ScopeAuthorizer, plus the principal scopes used
// by the tests.
type verificationFixture struct {
	svc   *verifyapi.Service
	store *verifyapi.MemoryStore
}

func mustSubject(t *testing.T, ns, tenant, project, repo string) verifyapi.SubjectRef {
	t.Helper()
	return verifyapi.SubjectRef{
		AuthorityNamespace: ns,
		TenantID:           tenant,
		ProjectID:          project,
		RepositoryID:       repo,
	}
}

func testDigest(seed string) verifyapi.Digest {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 64)
	for i := range out {
		out[i] = hexDigits[(int(seed[i%len(seed)])+i)%16]
	}
	return verifyapi.Digest(out)
}

func newVerificationServer(t *testing.T) *Server {
	t.Helper()
	now := time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	st := verifyapi.NewMemoryStore(clock)
	root := testDigest("evidence-root")
	verifier := &verifyapi.FuncEvidenceVerifier{
		Identity: "server-test-verifier/v1",
		Clock:    clock,
		Resolve: func(context.Context, string) (verifyapi.ResolvedAttestation, error) {
			return verifyapi.ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      root,
				AttestationDigest: testDigest("att-digest"),
				Status:            string(model.StatusSuccess),
				Facts:             &model.ExecutionFacts{FilesystemIsolated: true},
			}, nil
		},
	}
	svc, err := verifyapi.NewService(st, verifier, verifyapi.ScopeAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	svc.Clock = clock
	s := &Server{
		AdminToken:   "admin-tok",
		Verification: svc,
		VerificationScopes: map[string]verifyapi.SubjectRef{
			"svc-a": mustSubject(t, "github.com", "tenant-a", "proj", "github.com/acme/service"),
			"svc-b": mustSubject(t, "github.com", "tenant-b", "proj", "github.com/acme/service"),
		},
		AuthStore: auth.NewTokenStore(),
	}
	if err := s.AuthStore.AddToken("tok-a", auth.Principal{Subject: "svc-a"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AuthStore.AddToken("tok-b", auth.Principal{Subject: "svc-b"}); err != nil {
		t.Fatal(err)
	}
	return s
}

func verificationBody(t *testing.T, ob verifyapi.VerificationObligation) *strings.Reader {
	t.Helper()
	raw, err := verifyapi.MarshalObligation(ob)
	if err != nil {
		t.Fatal(err)
	}
	return strings.NewReader(string(raw))
}

func baseVOb(t *testing.T, id string, subject verifyapi.SubjectRef) verifyapi.VerificationObligation {
	t.Helper()
	return verifyapi.VerificationObligation{
		ObligationID:               id,
		Subject:                    id,
		SubjectRef:                 &subject,
		ImmutableCandidateDigest:   testDigest("candidate-" + id),
		SourceSnapshotDigest:       testDigest("snapshot-" + id),
		VerificationContractDigest: testDigest("contract-" + id),
		RequiredChecks:             []string{verifyapi.CheckJobStatusSuccess, verifyapi.CheckEvidenceRoot},
		RequiredAssurance:          "no_injected_credentials",
		Freshness:                  verifyapi.FreshnessPolicy{MaxAgeSeconds: 3600},
		IssuedAt:                   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

// TestVerificationsMountedOnlyWhenConfigured: without a Service the subtree
// is absent (the verification substrate is opt-in).
func TestVerificationsMountedOnlyWhenConfigured(t *testing.T) {
	s := &Server{AdminToken: "admin-tok"}
	h := s.Handler()
	req := httptest.NewRequest("GET", "/api/v1/verifications/obligations/ob-1", nil)
	req.Header.Set("Authorization", "Bearer admin-tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("unconfigured verification surface answered 200: %s", rec.Body.String())
	}
}

// TestVerificationsFailClosedWithoutAuth: a configured service still
// refuses unauthenticated requests before any store work.
func TestVerificationsFailClosedWithoutAuth(t *testing.T) {
	s := newVerificationServer(t)
	h := s.Handler()
	req := httptest.NewRequest("GET", "/api/v1/verifications/obligations/ob-1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated verification read = %d %s, want 401", rec.Code, rec.Body.String())
	}
}

// TestVerificationsSubjectIsolationOverIdenticalContent: byte-identical
// candidates under tenant A vs tenant B do not share authorization over the
// HTTP surface. Tenant B cannot read tenant A's sealed outcome.
func TestVerificationsSubjectIsolationOverIdenticalContent(t *testing.T) {
	s := newVerificationServer(t)
	h := s.Handler()

	// Tenant A submits an obligation and verifies a sealed outcome.
	ob := baseVOb(t, "ob-a", s.VerificationScopes["svc-a"])
	req := httptest.NewRequest("POST", "/api/v1/verifications/obligations", verificationBody(t, ob))
	req.Header.Set("Authorization", "Bearer tok-a")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("submit as tenant A = %d %s", rec.Code, rec.Body.String())
	}

	d := testDigest
	claim := verifyapi.VerificationOutcome{
		VerificationID:   "ver-a",
		ObligationID:     ob.ObligationID,
		CandidateDigest:  ob.ImmutableCandidateDigest,
		SnapshotDigest:   ob.SourceSnapshotDigest,
		ContractDigest:   ob.VerificationContractDigest,
		Outcome:          verifyapi.OutcomePass,
		AssuranceProfile: ob.RequiredAssurance,
		CompletedChecks:  append([]string(nil), ob.RequiredChecks...),
		ExecutionIDs:     []string{"exec-1"},
		EvidenceRoot:     d("evidence-x"),
		Resources: verifyapi.ResourceFacts{
			QueueLatencyNS: 1, ExecutionLatencyNS: 2, RunnerClass: "standard",
		},
		StartedAt:      ob.IssuedAt.Add(time.Second),
		CompletedAt:    ob.IssuedAt.Add(2 * time.Second),
		ProvenanceRefs: []string{"att-1"},
	}
	claimRaw, err := verifyapi.MarshalOutcome(claim)
	if err != nil {
		t.Fatal(err)
	}

	// POST /outcomes is a CLAIM only — never merge/deploy authority.
	req = httptest.NewRequest("POST", "/api/v1/verifications/outcomes", strings.NewReader(string(claimRaw)))
	req.Header.Set("Authorization", "Bearer tok-a")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("record claim = %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"proven_pass":true`) {
		t.Fatalf("claim response must not carry proven_pass: %s", rec.Body.String())
	}
	// The claim view is not proof.
	req = httptest.NewRequest("GET", "/api/v1/verifications/outcomes/"+claim.VerificationID+"/verified", nil)
	req.Header.Set("Authorization", "Bearer tok-a")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("claim answered as verified: %s", rec.Body.String())
	}

	// Verify-and-record derives the sealed outcome.
	req = httptest.NewRequest("POST", "/api/v1/verifications/outcomes/verify", strings.NewReader(string(claimRaw)))
	req.Header.Set("Authorization", "Bearer tok-a")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("verify-and-record = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"proven_pass":true`) {
		t.Fatalf("sealed response missing proven_pass: %s", rec.Body.String())
	}

	// Tenant A may read the sealed record.
	req = httptest.NewRequest("GET", "/api/v1/verifications/outcomes/"+claim.VerificationID+"/verified", nil)
	req.Header.Set("Authorization", "Bearer tok-a")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant A query = %d %s", rec.Code, rec.Body.String())
	}

	// Tenant B is refused on tenant A's record — same content digests, other
	// subject, no shared authorization.
	req = httptest.NewRequest("GET", "/api/v1/verifications/outcomes/"+claim.VerificationID+"/verified", nil)
	req.Header.Set("Authorization", "Bearer tok-b")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant B query of tenant A outcome = %d %s, want 403", rec.Code, rec.Body.String())
	}

	// Admin break-glass still goes through the Authorizer and is allowed.
	req = httptest.NewRequest("GET", "/api/v1/verifications/outcomes/"+claim.VerificationID+"/verified", nil)
	req.Header.Set("Authorization", "Bearer admin-tok")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin query = %d %s", rec.Code, rec.Body.String())
	}
	var sealed struct {
		ProvenPass bool `json:"proven_pass"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sealed); err != nil {
		t.Fatal(err)
	}
	if !sealed.ProvenPass {
		t.Fatal("admin read of sealed record must report proven_pass")
	}
}

// TestVerificationsCrossTenantSubmitDenied: a tenant B principal cannot
// submit an obligation whose SubjectRef names tenant A.
func TestVerificationsCrossTenantSubmitDenied(t *testing.T) {
	s := newVerificationServer(t)
	h := s.Handler()
	ob := baseVOb(t, "ob-x", s.VerificationScopes["svc-a"])
	req := httptest.NewRequest("POST", "/api/v1/verifications/obligations", verificationBody(t, ob))
	req.Header.Set("Authorization", "Bearer tok-b")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant submit = %d %s, want 403", rec.Code, rec.Body.String())
	}
}

// TestSetVerificationScopesRejectsMalformedHierarchy: loading verification
// scopes from config refuses every malformed partial shape (tenant-only,
// namespace/project, ...) and installs nothing on failure. A tenant-only
// scope must never be able to authorize across namespaces.
func TestSetVerificationScopesRejectsMalformedHierarchy(t *testing.T) {
	s := newVerificationServer(t)
	keep := s.VerificationScopes
	for name, bad := range map[string]verifyapi.SubjectRef{
		"tenant-only":       {TenantID: "acme"},
		"project-only":      {ProjectID: "payments"},
		"namespace/project": {AuthorityNamespace: "github.com", ProjectID: "payments"},
		"namespace/repo":    {AuthorityNamespace: "github.com", RepositoryID: "github.com/acme/service"},
		"zero":              {},
	} {
		err := s.SetVerificationScopes(map[string]verifyapi.SubjectRef{"svc-a": bad})
		if err == nil {
			t.Fatalf("%s scope accepted at load", name)
		}
		// Previous map must remain installed (never partially replaced).
		if len(s.VerificationScopes) != len(keep) {
			t.Fatalf("%s load replaced the scope map", name)
		}
		for k, v := range keep {
			if !s.VerificationScopes[k].Equal(v) {
				t.Fatalf("%s load mutated existing scopes", name)
			}
		}
	}
	// A malformed scope on a principal grants nothing: tenant-only cannot
	// authorize another namespace even if it were hand-built.
	principal := verifyapi.Principal{Subject: "x", Capabilities: []verifyapi.Capability{
		{Action: verifyapi.ActionProofRead, Scope: verifyapi.SubjectRef{TenantID: "acme"}},
	}}
	if principal.Allows(verifyapi.ActionProofRead, verifyapi.SubjectRef{AuthorityNamespace: "evil", TenantID: "acme"}) {
		t.Fatal("tenant-only capability must not authorize another namespace")
	}
	// Valid load replaces the map.
	ns := verifyapi.SubjectRef{AuthorityNamespace: "github.com"}
	if err := s.SetVerificationScopes(map[string]verifyapi.SubjectRef{"svc-a": ns}); err != nil {
		t.Fatalf("valid scope load = %v", err)
	}
	if !s.VerificationScopes["svc-a"].Equal(ns) {
		t.Fatalf("loaded scope = %v, want %v", s.VerificationScopes["svc-a"], ns)
	}
}

// TestVerificationAdminIsExplicitNotZeroRef: admin break-glass is only the
// explicit GlobalVerificationAdmin capability. A principal with no
// capabilities (including one whose scope is the zero ref) is never admin.
func TestVerificationAdminIsExplicitNotZeroRef(t *testing.T) {
	s := newVerificationServer(t)
	// Admin token maps to the explicit capability, not a zero-ref wildcard.
	req := httptest.NewRequest("GET", "/api/v1/verifications/obligations/ob-a", nil)
	req.Header.Set("Authorization", "Bearer admin-tok")
	p, ok := s.verificationPrincipal(req)
	if !ok {
		t.Fatal("admin token must authenticate")
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("admin principal malformed: %v", err)
	}
	if !p.Allows(verifyapi.ActionProofRead, verifyapi.SubjectRef{AuthorityNamespace: "any", TenantID: "any"}) {
		t.Fatal("explicit GlobalVerificationAdmin must span subjects")
	}
	// An unlisted store subject gets no capabilities and is not admin.
	req = httptest.NewRequest("GET", "/api/v1/verifications/obligations/ob-a", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "svc-c"}))
	p, ok = s.verificationPrincipal(req)
	if !ok {
		t.Fatal("svc-c must authenticate")
	}
	if p.Allows(verifyapi.ActionProofRead, verifyapi.SubjectRef{}) {
		t.Fatal("unlisted subject must not hold authority, even on the zero subject")
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("svc-c principal malformed: %v", err)
	}
}
