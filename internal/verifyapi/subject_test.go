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

// TestSubjectRefValidate: zero is valid; set dimensions must be clean
// identifiers; whitespace and control characters are refused.
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

// TestSubjectRefIncludesIsFailClosed: a scope covers only its own
// dimensions; a zero scope never covers a named subject.
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
	if !(SubjectRef{}).Includes(SubjectRef{}) {
		t.Fatal("zero scope must include the zero subject")
	}
	// Same repository id under different tenants is NOT the same authority.
	clone := tenantRef("tenant-b")
	clone.RepositoryID = a.RepositoryID
	if a.Includes(clone) {
		t.Fatal("byte-identical repository under another tenant must not be covered")
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
