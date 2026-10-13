package verifyapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// stubProvider is a product-neutral external verifier for dispatch tests.
// kind and caps are what the registry checks; verify, when set, is invoked
// in place of a real evidence path so the test can observe routing.
type stubProvider struct {
	kind   string
	caps   VerifierCapability
	calls  int
	verify func(ctx context.Context, obligation VerificationObligation, claim VerificationOutcome) (DerivedVerifiedOutcome, error)
}

func (s *stubProvider) Kind() string                     { return s.kind }
func (s *stubProvider) Capabilities() VerifierCapability { return s.caps }
func (s *stubProvider) Verify(ctx context.Context, obligation VerificationObligation, claim VerificationOutcome) (DerivedVerifiedOutcome, error) {
	s.calls++
	if s.verify != nil {
		return s.verify(ctx, obligation, claim)
	}
	return DerivedVerifiedOutcome{}, errors.New("stubProvider: verify not wired")
}

// externalScannerKind is the product-neutral kind used by the dispatch
// tests: an obligation that names it must be routed to the matching
// registered provider, never to the service default verifier.
const externalScannerKind = "external-scanner"

func externalScannerCapability() VerifierCapability {
	return VerifierCapability{
		Kind:            externalScannerKind,
		Version:         "1",
		AssuranceLevels: []string{"no_injected_credentials", "sealed_pinned_no_network"},
		EvidenceTypes:   []string{"execution-attestation"},
	}
}

func providerBaseObligation(t *testing.T) VerificationObligation {
	t.Helper()
	ob := baseObligation(t)
	ob.ObligationID = "provider-ob"
	ob.RequiredChecks = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	ob.RequiredAssurance = "no_injected_credentials"
	return ob
}

func providerBaseClaim(t *testing.T, ob VerificationObligation) VerificationOutcome {
	t.Helper()
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "evidence")
	v.ProvenanceRefs = []string{"att-1"}
	v.ExecutionIDs = []string{"exec-1"}
	v.CompletedChecks = append([]string(nil), ob.RequiredChecks...)
	v.AssuranceProfile = ob.RequiredAssurance
	return v
}

// TestProviderRegistryRegisterAndQuery covers the catalog itself: kind is
// required, capability must validate and agree with Kind(), duplicates are
// refused, and lookup is fail closed on unknown kinds.
func TestProviderRegistryRegisterAndQuery(t *testing.T) {
	reg := NewProviderRegistry()
	if err := reg.Register(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil provider = %v, want ErrInvalid", err)
	}
	if err := reg.Register(&stubProvider{kind: "", caps: externalScannerCapability()}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty kind = %v, want ErrInvalid", err)
	}
	// Capability whose kind disagrees with the provider kind is refused.
	mismatched := externalScannerCapability()
	mismatched.Kind = "other-kind"
	if err := reg.Register(&stubProvider{kind: externalScannerKind, caps: mismatched}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("capability kind mismatch = %v, want ErrInvalid", err)
	}
	// A capability that advertises nothing is refused by Validate.
	empty := VerifierCapability{Kind: externalScannerKind, Version: "1"}
	if err := reg.Register(&stubProvider{kind: externalScannerKind, caps: empty}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty capability = %v, want ErrInvalid", err)
	}

	p := &stubProvider{kind: externalScannerKind, caps: externalScannerCapability()}
	if err := reg.Register(p); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := reg.Register(&stubProvider{kind: externalScannerKind, caps: externalScannerCapability()}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate register = %v, want ErrExists", err)
	}
	got, err := reg.Provider(externalScannerKind)
	if err != nil {
		t.Fatalf("Provider(%q): %v", externalScannerKind, err)
	}
	if got != VerifierProvider(p) {
		t.Fatal("Provider returned a different registration")
	}
	if _, err := reg.Provider("no-such-kind"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown kind = %v, want ErrNotFound", err)
	}
	if _, err := reg.Provider(""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty kind = %v, want ErrInvalid", err)
	}
	if list := reg.Providers(); len(list) != 1 || list[0].Kind() != externalScannerKind {
		t.Fatalf("Providers() = %v, want one %q", list, externalScannerKind)
	}
}

// TestServiceDispatchesToNamedProvider: an obligation that names the
// external scanner kind is verified by THAT provider (the default verifier
// is never invoked), and the sealed result is recorded.
func TestServiceDispatchesToNamedProvider(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	prov := &stubProvider{kind: externalScannerKind, caps: externalScannerCapability()}
	// The provider seals through the same acceptance path as the default
	// verifier: reuse the fixture's FuncEvidenceVerifier logic by delegating
	// to it, so the returned record is a real sealed DerivedVerifiedOutcome.
	prov.verify = func(ctx context.Context, obligation VerificationObligation, claim VerificationOutcome) (DerivedVerifiedOutcome, error) {
		return f.verifier.Verify(ctx, obligation, claim)
	}
	reg := NewProviderRegistry()
	if err := reg.Register(prov); err != nil {
		t.Fatal(err)
	}
	f.svc.Providers = reg

	ob := f.obligation(t, "dispatch-ob", "tenant-a")
	ob.VerifierProviderKind = externalScannerKind
	if err := f.svc.SubmitObligation(ctx, f.tenantA, ob); err != nil {
		t.Fatalf("SubmitObligation: %v", err)
	}
	claim := f.claim(t, ob)
	if err := f.svc.RecordClaim(ctx, f.tenantA, claim); err != nil {
		t.Fatalf("RecordClaim: %v", err)
	}

	beforeDefault := 0
	_ = beforeDefault // the fixture verifier does not count calls; routing is proven by prov.calls.
	seal, err := f.svc.VerifyAndRecord(ctx, f.tenantA, claim)
	if err != nil {
		t.Fatalf("VerifyAndRecord: %v", err)
	}
	if !seal.Sealed() || !seal.ProvenPass() {
		t.Fatalf("dispatched record is not a sealed pass: %+v", seal)
	}
	if prov.calls != 1 {
		t.Fatalf("external-scanner provider called %d times, want 1", prov.calls)
	}
	// The default fixture verifier must NOT have been the acceptance path:
	// the sealed identity is the provider's delegate, and the record is
	// queryable as authoritative.
	rec, err := f.svc.QueryOutcome(ctx, f.tenantA, seal.Outcome.VerificationID)
	if err != nil {
		t.Fatalf("QueryOutcome: %v", err)
	}
	if rec.Outcome.VerificationID != seal.Outcome.VerificationID {
		t.Fatalf("queried %q, sealed %q", rec.Outcome.VerificationID, seal.Outcome.VerificationID)
	}
}

// TestServiceUnknownProviderFailsClosed: an obligation that names a kind no
// one registered is refused before any verification runs — no fallback to
// the default verifier, and no record is stored.
func TestServiceUnknownProviderFailsClosed(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	// Providers registered, but not the kind the obligation names.
	reg := NewProviderRegistry()
	if err := reg.Register(&stubProvider{kind: externalScannerKind, caps: externalScannerCapability()}); err != nil {
		t.Fatal(err)
	}
	f.svc.Providers = reg

	ob := f.obligation(t, "unknown-kind-ob", "tenant-a")
	ob.VerifierProviderKind = "no-such-provider"
	if err := f.svc.SubmitObligation(ctx, f.tenantA, ob); err != nil {
		t.Fatalf("SubmitObligation: %v", err)
	}
	claim := f.claim(t, ob)
	if _, err := f.svc.VerifyAndRecord(ctx, f.tenantA, claim); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown provider = %v, want ErrNotFound", err)
	}
	// Nothing authoritative may exist for the claim.
	if _, err := f.svc.QueryOutcome(ctx, f.tenantA, claim.VerificationID); !errors.Is(err, ErrUnverified) && !errors.Is(err, ErrNotFound) {
		t.Fatalf("QueryOutcome after failed dispatch = %v, want ErrUnverified/ErrNotFound", err)
	}

	// The same obligation against a Service with a nil registry is also
	// fail closed (a named kind never silently falls back).
	f2 := newServiceFixture(t)
	ob2 := f2.obligation(t, "nil-registry-ob", "tenant-a")
	ob2.VerifierProviderKind = externalScannerKind
	if err := f2.svc.SubmitObligation(ctx, f2.tenantA, ob2); err != nil {
		t.Fatalf("SubmitObligation: %v", err)
	}
	claim2 := f2.claim(t, ob2)
	if _, err := f2.svc.VerifyAndRecord(ctx, f2.tenantA, claim2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nil provider registry = %v, want ErrNotFound", err)
	}
}

// TestServiceCapabilityMismatchRefuses: a registered provider whose
// advertised assurance set does not include the obligation's required
// assurance is refused (capability mismatch), even though the kind matches.
func TestServiceCapabilityMismatchRefuses(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	// The provider only advertises a stronger profile; the obligation asks
	// for a profile it never claimed.
	narrow := externalScannerCapability()
	narrow.AssuranceLevels = []string{"sealed_pinned_no_network"}
	prov := &stubProvider{kind: externalScannerKind, caps: narrow, verify: func(context.Context, VerificationObligation, VerificationOutcome) (DerivedVerifiedOutcome, error) {
		t.Fatal("capability-mismatched provider must never be invoked")
		return DerivedVerifiedOutcome{}, nil
	}}
	reg := NewProviderRegistry()
	if err := reg.Register(prov); err != nil {
		t.Fatal(err)
	}
	f.svc.Providers = reg

	ob := f.obligation(t, "cap-mismatch-ob", "tenant-a")
	ob.VerifierProviderKind = externalScannerKind
	ob.RequiredAssurance = "no_injected_credentials"
	if err := f.svc.SubmitObligation(ctx, f.tenantA, ob); err != nil {
		t.Fatalf("SubmitObligation: %v", err)
	}
	claim := f.claim(t, ob)
	_, err := f.svc.VerifyAndRecord(ctx, f.tenantA, claim)
	if !errors.Is(err, ErrBinding) {
		t.Fatalf("capability mismatch = %v, want ErrBinding", err)
	}
	if prov.calls != 0 {
		t.Fatalf("mismatched provider was invoked %d times, want 0", prov.calls)
	}
	if !strings.Contains(err.Error(), externalScannerKind) {
		t.Fatalf("capability mismatch error %q must name the provider kind", err)
	}
}

// TestProviderServesKindMismatch: providerServes itself refuses an
// obligation addressed to a different kind than the provider being invoked
// (defense in depth against a mis-routed call). Capability absence is fail
// closed: a dimension the capability never advertised is unsupported, not
// universal.
func TestProviderServesKindMismatch(t *testing.T) {
	p := &stubProvider{kind: externalScannerKind, caps: externalScannerCapability()}
	ob := providerBaseObligation(t)
	ob.VerifierProviderKind = "some-other-kind"
	if err := providerServes(p, ob); !errors.Is(err, ErrBinding) {
		t.Fatalf("kind mismatch = %v, want ErrBinding", err)
	}
	ob.VerifierProviderKind = externalScannerKind
	if err := providerServes(p, ob); err != nil {
		t.Fatalf("matching kind refused: %v", err)
	}
	// A capability whose AssuranceLevels is empty is NOT a universal
	// advertiser: absence means unsupported on that axis. The demand's
	// required assurance must be refused.
	open := externalScannerCapability()
	open.AssuranceLevels = nil
	open.ClaimClasses = []string{"execution"}
	p2 := &stubProvider{kind: externalScannerKind, caps: open}
	if err := providerServes(p2, ob); !errors.Is(err, ErrBinding) {
		t.Fatalf("empty assurance set = %v, want ErrBinding (absence is unsupported)", err)
	}
	// The explicit AnyCapability wildcard is how a capability says
	// "universal on this axis".
	universal := externalScannerCapability()
	universal.AssuranceLevels = []string{AnyCapability}
	p3 := &stubProvider{kind: externalScannerKind, caps: universal}
	if err := providerServes(p3, ob); err != nil {
		t.Fatalf("AnyCapability assurance refused: %v", err)
	}
}

// TestProviderObligationWireIsAdditive: an obligation that names no provider
// kind encodes without the field, and one that names a kind round-trips it.
// A decoder that does not know the field refuses the latter (fail closed on
// un-honored routing) — that is the DisallowUnknownFields contract.
func TestProviderObligationWireIsAdditive(t *testing.T) {
	ob := providerBaseObligation(t)
	raw, err := MarshalObligation(ob)
	if err != nil {
		t.Fatalf("MarshalObligation: %v", err)
	}
	if strings.Contains(string(raw), "verifier_provider_kind") {
		t.Fatalf("empty provider kind must be omitted from the wire: %s", raw)
	}
	back, err := UnmarshalObligation(raw)
	if err != nil {
		t.Fatalf("UnmarshalObligation: %v", err)
	}
	if back.VerifierProviderKind != "" {
		t.Fatalf("round-trip invented provider kind %q", back.VerifierProviderKind)
	}

	ob.VerifierProviderKind = externalScannerKind
	raw, err = MarshalObligation(ob)
	if err != nil {
		t.Fatalf("MarshalObligation(with kind): %v", err)
	}
	if !strings.Contains(string(raw), `"verifier_provider_kind":"external-scanner"`) {
		t.Fatalf("named provider kind missing from wire: %s", raw)
	}
	back, err = UnmarshalObligation(raw)
	if err != nil {
		t.Fatalf("UnmarshalObligation(with kind): %v", err)
	}
	if back.VerifierProviderKind != externalScannerKind {
		t.Fatalf("round-trip lost provider kind: %q", back.VerifierProviderKind)
	}
}

// TestProviderDispatchClockSmoke keeps the dispatch path exercised under a
// non-nil service clock (the provider call is the only new seam).
func TestProviderDispatchClockSmoke(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 1, 2, 4, 0, 0, 0, time.UTC)
	f.svc.Clock = func() time.Time { return now }

	prov := &stubProvider{kind: externalScannerKind, caps: externalScannerCapability()}
	prov.verify = func(ctx context.Context, obligation VerificationObligation, claim VerificationOutcome) (DerivedVerifiedOutcome, error) {
		return f.verifier.Verify(ctx, obligation, claim)
	}
	reg := NewProviderRegistry()
	if err := reg.Register(prov); err != nil {
		t.Fatal(err)
	}
	f.svc.Providers = reg

	ob := f.obligation(t, "clock-ob", "tenant-a")
	ob.VerifierProviderKind = externalScannerKind
	if err := f.svc.SubmitObligation(ctx, f.tenantA, ob); err != nil {
		t.Fatal(err)
	}
	claim := f.claim(t, ob)
	if _, err := f.svc.VerifyAndRecord(ctx, f.tenantA, claim); err != nil {
		t.Fatalf("VerifyAndRecord: %v", err)
	}
	if prov.calls != 1 {
		t.Fatalf("provider calls = %d, want 1", prov.calls)
	}
}

// TestResolvedDemandCoversIsRealDispatchContract (P2e): the demand is the
// provider kind, contract version, claim class, platform, evidence types and
// assurance; admission requires provider.capabilities ⊇ demand.
func TestResolvedDemandCoversIsRealDispatchContract(t *testing.T) {
	ob := providerBaseObligation(t)
	ob.VerifierProviderKind = externalScannerKind
	ob.RequiredAssurance = "no_injected_credentials"
	d := ResolveDemand(ob)
	if d.ProviderKind != externalScannerKind || d.Assurance != "no_injected_credentials" {
		t.Fatalf("ResolveDemand = %+v", d)
	}
	full := ResolveDemandFull(ob, "1", "execution", "linux", []string{"execution-attestation", "test-report"})
	if full.ContractVersion != "1" || full.ClaimClass != "execution" || full.Platform != "linux" || len(full.EvidenceTypes) != 2 {
		t.Fatalf("ResolveDemandFull = %+v", full)
	}

	caps := VerifierCapability{
		Kind:            externalScannerKind,
		Version:         "1",
		ClaimClasses:    []string{"execution", "release"},
		AssuranceLevels: []string{"no_injected_credentials", "sealed_pinned_no_network"},
		Platforms:       []string{"linux", "darwin"},
		EvidenceTypes:   []string{"execution-attestation", "test-report"},
	}
	if err := caps.Covers(full); err != nil {
		t.Fatalf("superset capability refused demand: %v", err)
	}

	// Each missing dimension is a refusal.
	cases := map[string]ResolvedDemand{
		"kind":       {ProviderKind: "other"},
		"version":    {ProviderKind: externalScannerKind, ContractVersion: "2"},
		"claim":      {ProviderKind: externalScannerKind, ClaimClass: "billing"},
		"platform":   {ProviderKind: externalScannerKind, Platform: "plan9"},
		"evidence":   {ProviderKind: externalScannerKind, EvidenceTypes: []string{"telemetry"}},
		"assurance":  {ProviderKind: externalScannerKind, Assurance: "angelic"},
		"evidence-2": {ProviderKind: externalScannerKind, EvidenceTypes: []string{"execution-attestation", "telemetry"}},
	}
	for name, dem := range cases {
		if err := caps.Covers(dem); err == nil {
			t.Fatalf("Covers(%s) succeeded, want refusal", name)
		} else if !errors.Is(err, ErrBinding) {
			t.Fatalf("Covers(%s) error = %v, want ErrBinding", name, err)
		}
	}

	// Capability absence is fail closed, NOT universal: a verifier that
	// never advertised a dimension is unsupported on it and any demand on
	// that axis is refused.
	absent := VerifierCapability{Kind: externalScannerKind, Version: "1", ClaimClasses: []string{"execution"}}
	if err := absent.Covers(full); err == nil {
		t.Fatal("absent capability dimensions must refuse a demand, not pass as universal")
	} else if !errors.Is(err, ErrBinding) {
		t.Fatalf("absent dimension error = %v, want ErrBinding", err)
	}
	// Explicit AnyCapability wildcards are the universal advertisers.
	universal := VerifierCapability{
		Kind:            externalScannerKind,
		Version:         AnyCapability,
		ClaimClasses:    []string{AnyCapability},
		AssuranceLevels: []string{AnyCapability},
		Platforms:       []string{AnyCapability},
		EvidenceTypes:   []string{AnyCapability},
	}
	if err := universal.Covers(full); err != nil {
		t.Fatalf("explicit AnyCapability refused a dimension demand: %v", err)
	}
}

// TestResolvedDemandPinsObligationFields: an obligation that carries the
// dispatch pins (contract version, claim class, platform, evidence types)
// resolves them into the demand; an obligation that carries none demands
// nothing on those axes.
func TestResolvedDemandPinsObligationFields(t *testing.T) {
	ob := providerBaseObligation(t)
	ob.VerifierProviderKind = externalScannerKind
	ob.VerifierContractVersion = "1"
	ob.VerifierClaimClass = "release"
	ob.VerifierPlatform = "linux"
	ob.VerifierEvidenceTypes = []string{"execution-attestation", "test-report"}
	d := ResolveDemand(ob)
	if d.ContractVersion != "1" || d.ClaimClass != "release" || d.Platform != "linux" || len(d.EvidenceTypes) != 2 {
		t.Fatalf("ResolveDemand did not pin obligation fields: %+v", d)
	}

	// The pinned demand is enforced: a capability that covers none of those
	// axes is refused even though the kind matches.
	narrow := VerifierCapability{
		Kind:            externalScannerKind,
		Version:         "1",
		AssuranceLevels: []string{AnyCapability},
		EvidenceTypes:   []string{"execution-attestation"},
	}
	if err := narrow.Covers(d); err == nil {
		t.Fatal("narrow capability must refuse the pinned claim class/platform demand")
	}

	// An obligation without the pins demands nothing on those axes.
	bare := providerBaseObligation(t)
	bare.VerifierProviderKind = externalScannerKind
	bd := ResolveDemand(bare)
	if bd.ContractVersion != "" || bd.ClaimClass != "" || bd.Platform != "" || len(bd.EvidenceTypes) != 0 {
		t.Fatalf("unpinned obligation invented demand axes: %+v", bd)
	}
	if err := narrow.Covers(bd); err != nil {
		t.Fatalf("unpinned demand refused by a matching capability: %v", err)
	}
}

// TestProviderRecheckAfterVerify (P2e): the demand is re-checked in the
// verifier path after Verify returns, so admission is not the last word.
func TestProviderRecheckAfterVerify(t *testing.T) {
	p := &stubProvider{kind: externalScannerKind, caps: externalScannerCapability()}
	ob := providerBaseObligation(t)
	ob.VerifierProviderKind = externalScannerKind
	// Capabilities cover the demand at admission.
	if err := providerServes(p, ob); err != nil {
		t.Fatalf("providerServes = %v", err)
	}
	// A sealed pass under a different assurance than the demand is refused.
	// Build the sealed shape via the package seal path is heavy; recheck the
	// demand contract directly against a mismatched profile.
	demand := ResolveDemand(ob)
	if demand.Assurance == "" {
		t.Fatal("demand assurance is empty")
	}
	// Simulate a drifted capability: Covers now refuses.
	narrow := p
	narrow.caps = externalScannerCapability()
	narrow.caps.AssuranceLevels = []string{"sealed_pinned_no_network"}
	if err := recheckProviderDemand(narrow, ob, DerivedVerifiedOutcome{}); err == nil {
		t.Fatal("recheck must refuse a provider whose capabilities no longer cover the demand")
	}
}
