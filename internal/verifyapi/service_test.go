package verifyapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// serviceFixture builds a Service over a MemoryStore with a real
// FuncEvidenceVerifier (injected resolver) and a ScopeAuthorizer.
type serviceFixture struct {
	svc      *Service
	store    *MemoryStore
	clock    func() time.Time
	tenantA  Principal
	tenantB  Principal
	admin    Principal
	verifier *FuncEvidenceVerifier
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	now := time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	st := NewMemoryStore(clock)
	root := mustDigest(t, "evidence")
	execID := "exec-1"
	v := &FuncEvidenceVerifier{
		Identity: "service-test-verifier/v1",
		Clock:    clock,
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       execID,
				EvidenceRoot:      root,
				AttestationDigest: mustDigest(t, "att-digest"),
				// Signed job status + assurance facts: the derived verifier
				// only trusts what the attestation proves.
				Status:   string(model.StatusSuccess),
				Attested: trustedWindow(),
				Facts: &model.ExecutionFacts{
					FilesystemIsolated: true,
				},
			}, nil
		},
	}
	svc, err := NewService(st, v, ScopeAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	svc.Clock = clock
	return &serviceFixture{
		svc:      svc,
		store:    st,
		clock:    clock,
		tenantA:  Principal{Subject: "svc-a", Capabilities: CapabilitiesIn(tenantRef("tenant-a"))},
		tenantB:  Principal{Subject: "svc-b", Capabilities: CapabilitiesIn(tenantRef("tenant-b"))},
		admin:    Principal{Subject: "root", Capabilities: []Capability{GlobalVerificationAdmin}},
		verifier: v,
	}
}

func (f *serviceFixture) obligation(t *testing.T, id, tenant string) VerificationObligation {
	t.Helper()
	ob := baseObligation(t)
	ob.ObligationID = id
	ref := tenantRef(tenant)
	ob.SubjectRef = &ref
	// RequiredChecks / RequiredAssurance must be the derived vocabulary the
	// evidence verifier can actually prove (Model A).
	ob.RequiredChecks = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	ob.RequiredAssurance = "no_injected_credentials"
	return ob
}

func (f *serviceFixture) claim(t *testing.T, ob VerificationObligation) VerificationOutcome {
	t.Helper()
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "evidence")
	v.ProvenanceRefs = []string{"att-1"}
	// The injected resolver binds exactly one execution id; the claim may
	// only name ids the attestations prove.
	v.ExecutionIDs = []string{"exec-1"}
	// A pass claim must cover the obligation's required checks (Bind rule).
	v.CompletedChecks = append([]string(nil), ob.RequiredChecks...)
	v.AssuranceProfile = ob.RequiredAssurance
	return v
}

// TestNewServiceFailsClosedOnMissingSeams: construction refuses a nil
// store, verifier or authorizer rather than deferring the failure.
func TestNewServiceFailsClosedOnMissingSeams(t *testing.T) {
	st := NewMemoryStore(nil)
	v := &FuncEvidenceVerifier{Identity: "x", Resolve: func(context.Context, string) (ResolvedAttestation, error) {
		return ResolvedAttestation{}, errors.New("unused")
	}}
	if _, err := NewService(nil, v, ScopeAuthorizer{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil store = %v, want ErrInvalid", err)
	}
	if _, err := NewService(st, nil, ScopeAuthorizer{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil verifier = %v, want ErrInvalid", err)
	}
	if _, err := NewService(st, v, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil authz = %v, want ErrInvalid", err)
	}
	// A nil Authorizer on an existing service denies every call.
	svc := &Service{Store: st, Verifier: v}
	err := svc.SubmitObligation(context.Background(), Principal{}, baseObligation(t))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("nil Authz SubmitObligation = %v, want ErrUnauthorized", err)
	}
}

// TestServiceAuthorizeDenied is the authorization-refusal half: a tenant B
// principal cannot act on tenant A's obligation — submit, claim, verify and
// query are all refused with ErrUnauthorized and nothing is recorded.
func TestServiceAuthorizeDenied(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	obA := f.obligation(t, "ob-a", "tenant-a")

	if err := f.svc.SubmitObligation(ctx, f.tenantA, obA); err != nil {
		t.Fatalf("tenant A submit = %v", err)
	}
	// Tenant B cannot submit into tenant A's scope.
	obA2 := obA
	obA2.ObligationID = "ob-a2"
	if err := f.svc.SubmitObligation(ctx, f.tenantB, obA2); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-tenant submit = %v, want ErrUnauthorized", err)
	}
	// Tenant B cannot claim against tenant A's obligation.
	v := f.claim(t, obA)
	if err := f.svc.RecordClaim(ctx, f.tenantB, v); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-tenant RecordClaim = %v, want ErrUnauthorized", err)
	}
	if _, err := f.svc.VerifyAndRecord(ctx, f.tenantB, v); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-tenant VerifyAndRecord = %v, want ErrUnauthorized", err)
	}
	// Tenant A records the claim; tenant B still cannot read it.
	if err := f.svc.RecordClaim(ctx, f.tenantA, v); err != nil {
		t.Fatalf("tenant A RecordClaim = %v", err)
	}
	if _, err := f.svc.QueryOutcome(ctx, f.tenantB, v.VerificationID); !errors.Is(err, ErrUnverified) {
		// QueryOutcome reads the sealed record first; a claim-only id is
		// ErrUnverified even before subject authorization.
		t.Fatalf("tenant B QueryOutcome(claim) = %v, want ErrUnverified", err)
	}
	// DenyAll refuses everything, including admin-shaped principals.
	deny, err := NewService(f.store, f.verifier, DenyAllAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := deny.SubmitObligation(ctx, f.admin, obA); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("DenyAll admin submit = %v, want ErrUnauthorized", err)
	}
}

// TestServiceVerifyAndRecordDerivesSealed is the positive discharge path:
// VerifyAndRecord runs the verifier and stores a sealed record; QueryOutcome
// returns it with ProvenPass, and the measured facts are substrate-derived.
func TestServiceVerifyAndRecordDerivesSealed(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	ob := f.obligation(t, "ob-sealed", "tenant-a")
	if err := f.svc.SubmitObligation(ctx, f.tenantA, ob); err != nil {
		t.Fatal(err)
	}
	v := f.claim(t, ob)

	seal, err := f.svc.VerifyAndRecord(ctx, f.tenantA, v)
	if err != nil {
		t.Fatalf("VerifyAndRecord = %v", err)
	}
	if !seal.Sealed() {
		t.Fatal("VerifyAndRecord returned an unsealed record")
	}
	if !ProvenPass(seal) {
		t.Fatalf("ProvenPass = false, want true for sealed pass")
	}
	if seal.Evidence.VerifierIdentity != "service-test-verifier/v1" {
		t.Fatalf("verifier identity = %q", seal.Evidence.VerifierIdentity)
	}
	// Measured facts are derived at record time, never caller-asserted.
	if seal.Outcome.Resources.Measured == nil {
		t.Fatal("Measured is nil on the sealed record")
	}
	wantNS := v.CompletedAt.Sub(v.StartedAt).Nanoseconds()
	if seal.Outcome.Resources.Measured.DurationNS != wantNS {
		t.Fatalf("DurationNS = %d, want %d", seal.Outcome.Resources.Measured.DurationNS, wantNS)
	}
	// QueryOutcome returns the same sealed pass.
	got, err := f.svc.QueryOutcome(ctx, f.tenantA, v.VerificationID)
	if err != nil {
		t.Fatalf("QueryOutcome = %v", err)
	}
	if !got.ProvenPass() {
		t.Fatal("QueryOutcome record is not a proven pass")
	}
	// A POSTed claim alone never discharges: RecordClaim + QueryOutcome is
	// still ErrUnverified. Merge/deploy must use the sealed path only.
	other := f.claim(t, ob)
	other.VerificationID = "ver-claim-only"
	if err := f.svc.RecordClaim(ctx, f.tenantA, other); err != nil {
		t.Fatalf("RecordClaim = %v", err)
	}
	if _, err := f.svc.QueryOutcome(ctx, f.tenantA, other.VerificationID); !errors.Is(err, ErrUnverified) {
		t.Fatalf("QueryOutcome(claim) = %v, want ErrUnverified", err)
	}
	if ProvenPass(VerifiedOutcome{}) {
		t.Fatal("zero VerifiedOutcome must not be a proven pass")
	}
}

// TestServiceTenantIsolationOverIdenticalContent: byte-identical candidates
// under tenant A vs tenant B do not share authorization. The same
// verification id space is per-obligation; the subject of the STORED
// obligation decides who may read the sealed outcome.
func TestServiceTenantIsolationOverIdenticalContent(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	obA := f.obligation(t, "ob-iso-a", "tenant-a")
	obB := f.obligation(t, "ob-iso-b", "tenant-b")
	// Byte-identical content digests: only the subject differs.
	if obA.ImmutableCandidateDigest != obB.ImmutableCandidateDigest {
		t.Fatal("fixture digests must match")
	}
	if err := f.svc.SubmitObligation(ctx, f.tenantA, obA); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.SubmitObligation(ctx, f.tenantB, obB); err != nil {
		t.Fatal(err)
	}
	dA, err := CanonicalObligationDigest(obA)
	if err != nil {
		t.Fatal(err)
	}
	dB, err := CanonicalObligationDigest(obB)
	if err != nil {
		t.Fatal(err)
	}
	if dA == dB {
		t.Fatal("identical content under different tenants must not share a canonical digest")
	}

	vA := f.claim(t, obA)
	vA.VerificationID = "ver-iso-a"
	vB := f.claim(t, obB)
	vB.VerificationID = "ver-iso-b"
	sealA, err := f.svc.VerifyAndRecord(ctx, f.tenantA, vA)
	if err != nil {
		t.Fatalf("verify A = %v", err)
	}
	sealB, err := f.svc.VerifyAndRecord(ctx, f.tenantB, vB)
	if err != nil {
		t.Fatalf("verify B = %v", err)
	}

	// Tenant A reads its own sealed outcome; tenant B is refused on it.
	if _, err := f.svc.QueryOutcome(ctx, f.tenantA, sealA.Outcome.VerificationID); err != nil {
		t.Fatalf("tenant A reads own outcome: %v", err)
	}
	if _, err := f.svc.QueryOutcome(ctx, f.tenantB, sealA.Outcome.VerificationID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("tenant B reads tenant A outcome = %v, want ErrUnauthorized", err)
	}
	// And the reverse.
	if _, err := f.svc.QueryOutcome(ctx, f.tenantB, sealB.Outcome.VerificationID); err != nil {
		t.Fatalf("tenant B reads own outcome: %v", err)
	}
	if _, err := f.svc.QueryOutcome(ctx, f.tenantA, sealB.Outcome.VerificationID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("tenant A reads tenant B outcome = %v, want ErrUnauthorized", err)
	}
	// Admin may read both (cross-subject break-glass, still via Authorizer).
	if _, err := f.svc.QueryOutcome(ctx, f.admin, sealA.Outcome.VerificationID); err != nil {
		t.Fatalf("admin reads A: %v", err)
	}
	if _, err := f.svc.QueryOutcome(ctx, f.admin, sealB.Outcome.VerificationID); err != nil {
		t.Fatalf("admin reads B: %v", err)
	}
}

// TestServiceQueryOutcomeRestartSafe proves authority survives a process
// restart: the durable store hands back the persisted triple plus the
// acceptance record, and RestoreVerifiedOutcome rehydrates the seal through
// the MAC-checked acceptance path. QueryOutcome on the restored record is
// still a proven pass — the seal cannot be serialized, so acceptance+restore
// is the only way it crosses a restart (the PostgresStore read path calls
// exactly this).
func TestServiceQueryOutcomeRestartSafe(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	ob := f.obligation(t, "ob-restart", "tenant-a")
	if err := f.svc.SubmitObligation(ctx, f.tenantA, ob); err != nil {
		t.Fatal(err)
	}
	v := f.claim(t, ob)
	seal, err := f.svc.VerifyAndRecord(ctx, f.tenantA, v)
	if err != nil {
		t.Fatalf("VerifyAndRecord = %v", err)
	}

	// Persist-time acceptance (what a durable store computes before write).
	key, err := NewHMACAcceptanceKey("acc-1", []byte("restart-test-secret-32bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := Accept(ob, seal, key, f.clock())
	if err != nil {
		t.Fatalf("Accept = %v", err)
	}
	persisted := PersistedVerified{
		Obligation:     ob,
		SubmittedClaim: seal.SubmittedClaim,
		Outcome:        seal.Outcome,
		Evidence:       seal.Evidence,
		Acceptance:     rec,
	}

	// Load-time restore: the MAC must verify and the digests re-check.
	restored, err := RestoreVerifiedOutcome(persisted, key)
	if err != nil {
		t.Fatalf("RestoreVerifiedOutcome = %v", err)
	}
	if !restored.ProvenPass() {
		t.Fatal("restored record is not a proven pass")
	}

	// Simulate a full restart: a fresh store, rehydrate through Accept/Restore
	// and record the restored sealed row.
	st2 := NewMemoryStore(f.clock)
	svc2, err := NewService(st2, f.verifier, ScopeAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	svc2.Clock = f.clock
	if err := st2.SubmitObligation(ctx, ob); err != nil {
		t.Fatal(err)
	}
	if err := st2.RecordVerifiedOutcome(ctx, restored); err != nil {
		t.Fatalf("re-record restored = %v", err)
	}
	got, err := svc2.QueryOutcome(ctx, f.tenantA, v.VerificationID)
	if err != nil {
		t.Fatalf("QueryOutcome after restart = %v", err)
	}
	if !got.ProvenPass() {
		t.Fatal("restarted QueryOutcome is not a proven pass")
	}
	if got.Evidence.VerifierIdentity != seal.Evidence.VerifierIdentity {
		t.Fatalf("verifier identity after restart = %q, want %q", got.Evidence.VerifierIdentity, seal.Evidence.VerifierIdentity)
	}
	// A tampered evidence set cannot be restored into authority.
	tampered := persisted
	tampered.Evidence.AttestationDigests = append([]Digest(nil), persisted.Evidence.AttestationDigests...)
	tampered.Evidence.AttestationDigests[0] = mustDigest(t, "tampered")
	if _, err := RestoreVerifiedOutcome(tampered, key); err == nil {
		t.Fatal("RestoreVerifiedOutcome(tampered) must fail")
	}
	// A truncated evidence set is refused as incomplete.
	partial := persisted
	partial.Evidence.AttestationDigests = nil
	if _, err := RestoreVerifiedOutcome(partial, key); err == nil {
		t.Fatal("RestoreVerifiedOutcome(truncated) must fail")
	}
}

// TestServiceCompareGroupAuthorizesSubjects: a group comparison that spans
// two tenants is refused for a single-tenant principal; admin may compare.
func TestServiceCompareGroupAuthorizesSubjects(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	obA := f.obligation(t, "ob-g-a", "tenant-a")
	obB := f.obligation(t, "ob-g-b", "tenant-b")
	for _, ob := range []VerificationObligation{obA, obB} {
		p := f.tenantA
		if ob.SubjectReference().TenantID == "tenant-b" {
			p = f.tenantB
		}
		if err := f.svc.SubmitObligation(ctx, p, ob); err != nil {
			t.Fatal(err)
		}
	}
	g := SpeculativeGroup{
		VerificationGroupID: "grp-1",
		BaseSnapshotDigest:  obA.SourceSnapshotDigest,
		CandidateDigests: map[string]Digest{
			"cand-a": obA.ImmutableCandidateDigest,
			"cand-b": obB.ImmutableCandidateDigest,
		},
	}
	if err := f.store.RegisterGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	mk := func(ob VerificationObligation, id, cand string) VerificationOutcome {
		v := f.claim(t, ob)
		v.VerificationID = id
		v.Resources.Speculative = true
		v.Resources.VerificationGroupID = g.VerificationGroupID
		v.Resources.CandidateID = cand
		return v
	}
	if err := f.svc.RecordClaim(ctx, f.tenantA, mk(obA, "ver-g-a", "cand-a")); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.RecordClaim(ctx, f.tenantB, mk(obB, "ver-g-b", "cand-b")); err != nil {
		t.Fatal(err)
	}
	// Tenant A alone cannot compare a group that includes tenant B rows.
	if _, err := f.svc.CompareGroup(ctx, f.tenantA, g.VerificationGroupID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-tenant CompareGroup = %v, want ErrUnauthorized", err)
	}
	// Admin may compare the mixed group.
	cmp, err := f.svc.CompareGroup(ctx, f.admin, g.VerificationGroupID)
	if err != nil {
		t.Fatalf("admin CompareGroup = %v", err)
	}
	if len(cmp.Candidates) != 2 {
		t.Fatalf("candidates = %d, want 2", len(cmp.Candidates))
	}
}

// TestScopeAuthorizerZeroScope: a principal with no capabilities is refused
// on any subject, including the zero subject. Admin authority is only the
// explicit GlobalVerificationAdmin capability — never a zero SubjectRef.
func TestScopeAuthorizerZeroScope(t *testing.T) {
	var a ScopeAuthorizer
	ctx := context.Background()
	p := Principal{Subject: "anon"}
	if err := a.Authorize(ctx, p, ActionProofRead, tenantRef("tenant-a")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("capability-less principal over named subject = %v, want ErrUnauthorized", err)
	}
	if err := a.Authorize(ctx, p, ActionProofRead, SubjectRef{}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("capability-less principal over zero subject = %v, want ErrUnauthorized", err)
	}
	// The zero SubjectRef is not a wildcard: a capability scoped to it
	// grants nothing.
	zeroScoped := Principal{Subject: "zero-scoped", Capabilities: []Capability{
		{Action: ActionProofRead, Scope: SubjectRef{}},
	}}
	if err := a.Authorize(ctx, zeroScoped, ActionProofRead, tenantRef("tenant-a")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("zero-scope capability over named subject = %v, want ErrUnauthorized", err)
	}
	if err := a.Authorize(ctx, zeroScoped, ActionProofRead, SubjectRef{}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("zero-scope capability over zero subject = %v, want ErrUnauthorized", err)
	}
	// Admin is explicit, not a zero ref.
	if err := a.Authorize(ctx, Principal{Subject: "root", Capabilities: []Capability{GlobalVerificationAdmin}}, ActionProofRead, tenantRef("tenant-a")); err != nil {
		t.Fatalf("explicit GlobalVerificationAdmin over named subject = %v, want nil", err)
	}
}

// TestSubjectHierarchyEnforcement is the P1 authorization rule: scopes are
// strict prefix hierarchies. A tenant-only or project-only ref is a
// malformed scope and authorizes nothing; it can never cross namespaces or
// tenants even when the trailing dimensions collide.
func TestSubjectHierarchyEnforcement(t *testing.T) {
	var a ScopeAuthorizer
	ctx := context.Background()

	// Malformed partial hierarchies are refused as scopes (and as
	// principal capabilities).
	for name, bad := range map[string]SubjectRef{
		"tenant-only":       {TenantID: "acme"},
		"project-only":      {ProjectID: "payments"},
		"repository-only":   {RepositoryID: "github.com/acme/service"},
		"namespace/project": {AuthorityNamespace: "github.com", ProjectID: "payments"},
		"namespace/repo":    {AuthorityNamespace: "github.com", RepositoryID: "github.com/acme/service"},
		"tenant/repo":       {TenantID: "acme", RepositoryID: "github.com/acme/service"},
		"namespace/tenant/repo": {
			AuthorityNamespace: "github.com", TenantID: "acme", RepositoryID: "github.com/acme/service",
		},
	} {
		if err := bad.ValidateHierarchy(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s ValidateHierarchy = %v, want ErrInvalid", name, err)
		}
		p := Principal{Subject: name, Capabilities: CapabilitiesIn(bad)}
		if len(p.Capabilities) != 0 {
			t.Fatalf("%s: CapabilitiesIn must refuse a malformed scope, got %v", name, p.Capabilities)
		}
		// A hand-built capability with a malformed scope authorizes nothing.
		p = Principal{Subject: name, Capabilities: []Capability{
			{Action: ActionProofRead, Scope: bad},
		}}
		if err := a.Authorize(ctx, p, ActionProofRead, tenantRef("acme")); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("%s scope authorized a subject: %v", name, err)
		}
		if err := p.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s principal Validate = %v, want ErrInvalid", name, err)
		}
	}

	// {tenant:acme} cannot authorize other namespaces (it is not a scope).
	acme := SubjectRef{TenantID: "acme"}
	otherNS := SubjectRef{AuthorityNamespace: "evil.example", TenantID: "acme"}
	if acme.Includes(otherNS) || acme.Includes(tenantRef("acme")) {
		t.Fatal("tenant-only ref must not authorize any namespace")
	}

	// {project:payments} cannot cross tenants.
	payments := SubjectRef{ProjectID: "payments"}
	ta := SubjectRef{AuthorityNamespace: "github.com", TenantID: "tenant-a", ProjectID: "payments"}
	tb := SubjectRef{AuthorityNamespace: "github.com", TenantID: "tenant-b", ProjectID: "payments"}
	if payments.Includes(ta) || payments.Includes(tb) {
		t.Fatal("project-only ref must not cross tenants")
	}

	// Valid hierarchy: namespace scope is trailing-wildcard over its
	// tenants, but never another namespace.
	ns := SubjectRef{AuthorityNamespace: "github.com"}
	if !ns.Includes(ta) || !ns.Includes(tb) {
		t.Fatal("namespace scope must cover its own tenants")
	}
	if ns.Includes(otherNS) {
		t.Fatal("namespace scope must not cover another namespace")
	}

	// A tenant scope covers its own projects/repositories but not a
	// namespace-level obligation (the scope must not extend upward).
	tScope := SubjectRef{AuthorityNamespace: "github.com", TenantID: "tenant-a"}
	if !tScope.Includes(ta) {
		t.Fatal("tenant scope must cover its project")
	}
	if tScope.Includes(ns) {
		t.Fatal("tenant scope must not cover a namespace-level subject")
	}

	// Admin is explicit, not a zero ref: a zero SubjectRef covers nothing,
	// and only GlobalVerificationAdmin spans subjects.
	if (SubjectRef{}).Includes(ta) || (SubjectRef{}).Includes(SubjectRef{}) {
		t.Fatal("zero SubjectRef must not cover anything")
	}
	if err := a.Authorize(ctx, Principal{Subject: "root", Capabilities: []Capability{GlobalVerificationAdmin}}, ActionProofRead, ta); err != nil {
		t.Fatalf("explicit admin = %v, want nil", err)
	}
	// A zero-SubjectRef-shaped "admin" principal is NOT admin.
	if err := a.Authorize(ctx, Principal{Subject: "root"}, ActionProofRead, ta); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("zero-ref principal must not be admin: %v", err)
	}
}

// TestCapabilityAuthorizerIsActionScoped: a capability for one action does
// not grant another; the admin capability grants every action.
func TestCapabilityAuthorizerIsActionScoped(t *testing.T) {
	var a ScopeAuthorizer
	ctx := context.Background()
	scope := tenantRef("tenant-a")
	readOnly := Principal{Subject: "reader", Capabilities: []Capability{
		{Action: ActionProofRead, Scope: scope},
	}}
	if err := a.Authorize(ctx, readOnly, ActionProofRead, scope); err != nil {
		t.Fatalf("scoped read = %v", err)
	}
	if err := a.Authorize(ctx, readOnly, ActionObligationCreate, scope); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("read capability must not create obligations: %v", err)
	}
	if err := a.Authorize(ctx, readOnly, ActionClaimSubmit, scope); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("read capability must not submit claims: %v", err)
	}
	// GlobalVerificationAdmin is every action on every subject.
	admin := Principal{Subject: "root", Capabilities: []Capability{GlobalVerificationAdmin}}
	for _, act := range []Action{ActionObligationCreate, ActionClaimSubmit, ActionProofVerify, ActionProofRead, ActionGroupCompare} {
		if err := a.Authorize(ctx, admin, act, scope); err != nil {
			t.Fatalf("admin %s = %v, want nil", act, err)
		}
		if err := a.Authorize(ctx, admin, act, SubjectRef{}); err != nil {
			t.Fatalf("admin %s on zero subject = %v, want nil", act, err)
		}
	}
}
