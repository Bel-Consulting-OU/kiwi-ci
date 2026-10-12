package verifyapi

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func tenantRef(id string) SubjectRef {
	return SubjectRef{
		AuthorityNamespace: "github.com",
		TenantID:           id,
		ProjectID:          "proj",
		RepositoryID:       "github.com/acme/service",
	}
}

// TestSubjectRefValidate: zero is structurally valid; set dimensions must
// be clean identifiers; whitespace and control characters are refused.
func TestSubjectRefValidate(t *testing.T) {
	if err := (SubjectRef{}).Validate(); err != nil {
		t.Fatalf("zero SubjectRef refused: %v", err)
	}
	if err := tenantRef("a").Validate(); err != nil {
		t.Fatalf("valid SubjectRef refused: %v", err)
	}
	bad := tenantRef("a")
	bad.TenantID = " a"
	if err := bad.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("whitespace tenant = %v, want ErrInvalid", err)
	}
	bad = tenantRef("a")
	bad.RepositoryID = "repo\nname"
	if err := bad.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("control-char repo = %v, want ErrInvalid", err)
	}
}

// TestSubjectRefValidateHierarchy: only the strict prefix shapes are valid
// scopes — namespace, namespace/tenant, namespace/tenant/project,
// namespace/tenant/project/repository. Every hole in the chain and the zero
// ref are refused (the zero ref is not a scope; admin is explicit).
func TestSubjectRefValidateHierarchy(t *testing.T) {
	valid := map[string]SubjectRef{
		"namespace":  {AuthorityNamespace: "github.com"},
		"tenant":     {AuthorityNamespace: "github.com", TenantID: "acme"},
		"project":    {AuthorityNamespace: "github.com", TenantID: "acme", ProjectID: "payments"},
		"repository": tenantRef("acme"),
	}
	for name, s := range valid {
		if err := s.ValidateHierarchy(); err != nil {
			t.Fatalf("valid shape %q refused: %v", name, err)
		}
	}
	invalid := map[string]SubjectRef{
		"zero":               {},
		"tenant-only":        {TenantID: "acme"},
		"project-only":       {ProjectID: "payments"},
		"repository-only":    {RepositoryID: "github.com/acme/service"},
		"tenant/project":     {TenantID: "acme", ProjectID: "payments"},
		"tenant/repository":  {TenantID: "acme", RepositoryID: "github.com/acme/service"},
		"namespace/project":  {AuthorityNamespace: "github.com", ProjectID: "payments"},
		"namespace/repository": {
			AuthorityNamespace: "github.com", RepositoryID: "github.com/acme/service",
		},
		"namespace/tenant/repository": {
			AuthorityNamespace: "github.com", TenantID: "acme", RepositoryID: "github.com/acme/service",
		},
		"project/repository": {ProjectID: "payments", RepositoryID: "github.com/acme/service"},
	}
	for name, s := range invalid {
		if err := s.ValidateHierarchy(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid shape %q accepted: %v", name, err)
		}
	}
}

// TestSubjectRefIncludesIsFailClosed: a scope covers only its own
// hierarchy; malformed partial scopes and the zero ref cover nothing.
func TestSubjectRefIncludesIsFailClosed(t *testing.T) {
	a := tenantRef("tenant-a")
	if !a.Includes(a) {
		t.Fatal("scope must include itself")
	}
	narrow := SubjectRef{AuthorityNamespace: "github.com", TenantID: "tenant-a", ProjectID: "proj"}
	if !narrow.Includes(a) {
		t.Fatal("project scope must include its repository")
	}
	b := tenantRef("tenant-b")
	if narrow.Includes(b) {
		t.Fatal("tenant-a project scope must not cover tenant-b")
	}
	if (SubjectRef{}).Includes(a) {
		t.Fatal("zero scope must not cover a named subject")
	}
	if (SubjectRef{}).Includes(SubjectRef{}) {
		t.Fatal("zero scope is not a wildcard — it covers nothing")
	}
	// Same repository id under different tenants is NOT the same authority.
	clone := tenantRef("tenant-b")
	clone.RepositoryID = a.RepositoryID
	if a.Includes(clone) {
		t.Fatal("byte-identical repository under another tenant must not be covered")
	}
	// Trailing wildcards only: a namespace scope spans its tenants, a
	// holey scope spans nothing.
	ns := SubjectRef{AuthorityNamespace: "github.com"}
	if !ns.Includes(a) || !ns.Includes(b) {
		t.Fatal("namespace scope must cover its tenants")
	}
	otherNS := tenantRef("tenant-a")
	otherNS.AuthorityNamespace = "evil.example"
	if ns.Includes(otherNS) {
		t.Fatal("namespace scope must not cover another namespace")
	}
	// {tenant:acme} is a holey shape: it authorizes nothing, including
	// subjects that share the tenant id.
	acme := SubjectRef{TenantID: "acme"}
	sameTenant := SubjectRef{AuthorityNamespace: "github.com", TenantID: "acme", ProjectID: "p"}
	if acme.Includes(sameTenant) {
		t.Fatal("tenant-only ref must not authorize any subject")
	}
	// {project:payments} cannot cross tenants.
	payments := SubjectRef{ProjectID: "payments"}
	pa := SubjectRef{AuthorityNamespace: "github.com", TenantID: "a", ProjectID: "payments"}
	pb := SubjectRef{AuthorityNamespace: "github.com", TenantID: "b", ProjectID: "payments"}
	if payments.Includes(pa) || payments.Includes(pb) {
		t.Fatal("project-only ref must not cross tenants")
	}
}

// TestValidateScopes: loading a scope map refuses any malformed entry and
// accepts the four valid hierarchy shapes.
func TestValidateScopes(t *testing.T) {
	good := map[string]SubjectRef{
		"ns":   {AuthorityNamespace: "github.com"},
		"ten":  {AuthorityNamespace: "github.com", TenantID: "acme"},
		"proj": {AuthorityNamespace: "github.com", TenantID: "acme", ProjectID: "payments"},
		"repo": tenantRef("acme"),
	}
	if err := ValidateScopes(good); err != nil {
		t.Fatalf("valid scopes refused: %v", err)
	}
	if err := ValidateScopes(nil); err != nil {
		t.Fatalf("empty scopes refused: %v", err)
	}
	bad := map[string]SubjectRef{
		"tenant-only": {TenantID: "acme"},
	}
	if err := ValidateScopes(bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed scope loaded = %v, want ErrInvalid", err)
	}
}

// TestObligationValidateRequiresHierarchy: an obligation's SubjectRef must
// be a strict prefix hierarchy. Malformed partial shapes are refused at
// obligation validation (and therefore at decode, submit and digest).
func TestObligationValidateRequiresHierarchy(t *testing.T) {
	ob := baseObligation(t)
	nsOnly := SubjectRef{AuthorityNamespace: "github.com"}
	ob.SubjectRef = &nsOnly
	if err := ob.Validate(); err != nil {
		t.Fatalf("namespace-only subject refused: %v", err)
	}
	if _, err := CanonicalObligationDigest(ob); err != nil {
		t.Fatalf("namespace-only digest = %v", err)
	}
	for name, bad := range map[string]SubjectRef{
		"zero":               {},
		"tenant-only":        {TenantID: "acme"},
		"namespace/project":  {AuthorityNamespace: "github.com", ProjectID: "payments"},
		"namespace/repo":     {AuthorityNamespace: "github.com", RepositoryID: "github.com/acme/service"},
		"namespace/tenant/repo": {
			AuthorityNamespace: "github.com", TenantID: "acme", RepositoryID: "github.com/acme/service",
		},
	} {
		bad := bad
		ob.SubjectRef = &bad
		if err := ob.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("obligation with %s subject accepted: %v", name, err)
		}
		if _, err := CanonicalObligationDigest(ob); !errors.Is(err, ErrInvalid) {
			t.Fatalf("digest of %s subject = %v, want ErrInvalid", name, err)
		}
	}
}

// TestCanonicalObligationDigestSeparatesSubjects is the core identity rule:
// byte-identical content digests under tenant A vs tenant B are different
// obligations (different canonical digests), so they are never
// interchangeable authority.
func TestCanonicalObligationDigestSeparatesSubjects(t *testing.T) {
	obA := baseObligation(t)
	refA := tenantRef("tenant-a")
	obA.SubjectRef = &refA
	obB := obA
	refB := tenantRef("tenant-b")
	obB.SubjectRef = &refB

	dA, err := CanonicalObligationDigest(obA)
	if err != nil {
		t.Fatalf("digest A = %v", err)
	}
	dB, err := CanonicalObligationDigest(obB)
	if err != nil {
		t.Fatalf("digest B = %v", err)
	}
	if dA == dB {
		t.Fatalf("identical digests across tenants: %s — subject must separate obligations", dA)
	}
	if len(dA) != digestLen {
		t.Fatalf("digest length = %d, want %d", len(dA), digestLen)
	}
	// Same subject + same content is stable.
	dA2, err := CanonicalObligationDigest(obA)
	if err != nil {
		t.Fatal(err)
	}
	if dA != dA2 {
		t.Fatalf("digest unstable: %s vs %s", dA, dA2)
	}
	// UTC location tags do not change identity.
	loc := time.FixedZone("UTC+2", 2*3600)
	obC := obA
	obC.IssuedAt = obA.IssuedAt.In(loc)
	dC, err := CanonicalObligationDigest(obC)
	if err != nil {
		t.Fatal(err)
	}
	if dC != dA {
		t.Fatalf("UTC normalization changed digest: %s vs %s", dC, dA)
	}
}

// TestSubjectsEqualAndBinding: subject participates in obligation identity.
// An outcome bound to tenant A's obligation never discharges tenant B's
// obligation even when the content digests are byte-identical — Bind keys
// on ObligationID, and the canonical digests (store idempotency identity)
// already differ by subject.
func TestSubjectsEqualAndBinding(t *testing.T) {
	obA := baseObligation(t)
	refA := tenantRef("tenant-a")
	obA.SubjectRef = &refA
	obB := obA
	obB.ObligationID = "ob-tenant-b"
	refB := tenantRef("tenant-b")
	obB.SubjectRef = &refB

	if SubjectsEqual(obA, obB) {
		t.Fatal("tenant A and tenant B obligations must not be subject-equal")
	}
	if !SubjectsEqual(obA, obA) {
		t.Fatal("same obligation must be subject-equal")
	}

	// Byte-identical outcome, different obligation ids: Bind refuses.
	out := baseOutcome(t, obA)
	outB := out
	outB.ObligationID = obB.ObligationID
	now := obA.IssuedAt.Add(2 * time.Second)
	if err := Bind(obA, out, now); err != nil {
		t.Fatalf("same-subject bind = %v", err)
	}
	if err := Bind(obB, out, now); !errors.Is(err, ErrBinding) {
		t.Fatalf("cross-subject bind (tenant A outcome vs tenant B obligation) = %v, want ErrBinding", err)
	}
	// Even with the outcome re-pointed at B's id, the claim is a different
	// obligation's record: it may bind structurally, but the canonical
	// obligation digests differ so the store keeps them distinct rows.
	if err := Bind(obB, outB, now); err != nil {
		t.Fatalf("tenant B bind of its own outcome = %v", err)
	}
	dA, _ := CanonicalObligationDigest(obA)
	dB, _ := CanonicalObligationDigest(obB)
	if dA == dB {
		t.Fatal("canonical obligation digests must differ across subjects")
	}
}

// TestObligationWireCarriesSubjectRef: the codec round-trips SubjectRef
// with omitempty (a nil ref stays absent), and Unmarshal refuses a
// malformed ref.
func TestObligationWireCarriesSubjectRef(t *testing.T) {
	ob := baseObligation(t)
	raw, err := MarshalObligation(ob)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "subject_ref") {
		t.Fatalf("nil SubjectRef must be omitted from the wire: %s", raw)
	}
	ref := tenantRef("tenant-a")
	ob.SubjectRef = &ref
	raw, err = MarshalObligation(ob)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"subject_ref"`) {
		t.Fatalf("set SubjectRef must appear on the wire: %s", raw)
	}
	got, err := UnmarshalObligation(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SubjectReference().Equal(ref) {
		t.Fatalf("round-trip subject = %v, want %v", got.SubjectReference(), ref)
	}
	// Malformed subject is refused at decode.
	bad := tenantRef("a")
	bad.TenantID = " x"
	ob.SubjectRef = &bad
	raw, err = MarshalObligation(ob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalObligation(raw); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed subject_ref decoded = %v, want ErrInvalid", err)
	}
}

// TestCloneObligationCopiesSubjectRef: registry clones must not share the
// pointer, so a mutation through one handle cannot rewrite another.
func TestCloneObligationCopiesSubjectRef(t *testing.T) {
	ob := baseObligation(t)
	ref := tenantRef("tenant-a")
	ob.SubjectRef = &ref
	c := cloneObligation(ob)
	if c.SubjectRef == ob.SubjectRef {
		t.Fatal("clone shares SubjectRef pointer with the original")
	}
	if !c.SubjectReference().Equal(ref) {
		t.Fatalf("clone subject = %v, want %v", c.SubjectReference(), ref)
	}
}
