package verifyapi

import (
	"errors"
	"testing"
)

func baseCapability() VerifierCapability {
	return VerifierCapability{
		Kind:            "execution-attestation",
		Version:         "v1",
		ClaimClasses:    []string{"build-output", "test-run"},
		AssuranceLevels: []string{"attested-v1", "attested-v2"},
		Platforms:       []string{"linux/amd64", "linux/arm64"},
		EvidenceTypes:   []string{"dsse-envelope"},
	}
}

func TestVerifierCapabilityValidate(t *testing.T) {
	if err := baseCapability().Validate(); err != nil {
		t.Fatalf("valid capability refused: %v", err)
	}

	noKind := baseCapability()
	noKind.Kind = ""
	if err := noKind.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing kind = %v, want ErrInvalid", err)
	}

	noVersion := baseCapability()
	noVersion.Version = ""
	if err := noVersion.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing version = %v, want ErrInvalid", err)
	}

	empty := VerifierCapability{Kind: "k", Version: "v"}
	if err := empty.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("advertising nothing = %v, want ErrInvalid", err)
	}

	blank := baseCapability()
	blank.Platforms = []string{""}
	if err := blank.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty platform entry = %v, want ErrInvalid", err)
	}
}

func TestRegistryRegisterAndQueryCapabilities(t *testing.T) {
	reg := NewRegistry(nil)

	c1 := baseCapability()
	c2 := VerifierCapability{
		Kind:            "policy-audit",
		Version:         "v2",
		ClaimClasses:    []string{"policy"},
		AssuranceLevels: []string{"basic"},
		Platforms:       []string{"any"},
		EvidenceTypes:   []string{"json-report"},
	}
	if err := reg.RegisterCapability(c1); err != nil {
		t.Fatalf("RegisterCapability c1 = %v", err)
	}
	if err := reg.RegisterCapability(c2); err != nil {
		t.Fatalf("RegisterCapability c2 = %v", err)
	}
	if err := reg.RegisterCapability(c1); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate capability = %v, want ErrExists", err)
	}

	all := reg.QueryCapabilities(CapabilityQuery{})
	if len(all) != 2 {
		t.Fatalf("zero query = %d rows, want 2", len(all))
	}
	// Deterministic order: kind ascending.
	if all[0].Kind != "execution-attestation" || all[1].Kind != "policy-audit" {
		t.Fatalf("query order = %q, %q", all[0].Kind, all[1].Kind)
	}

	byKind := reg.QueryCapabilities(CapabilityQuery{Kind: "policy-audit"})
	if len(byKind) != 1 || byKind[0].Version != "v2" {
		t.Fatalf("by kind = %+v", byKind)
	}

	byClaim := reg.QueryCapabilities(CapabilityQuery{ClaimClass: "test-run"})
	if len(byClaim) != 1 || byClaim[0].Kind != "execution-attestation" {
		t.Fatalf("by claim class = %+v", byClaim)
	}

	byPlatform := reg.QueryCapabilities(CapabilityQuery{Platform: "linux/arm64"})
	if len(byPlatform) != 1 {
		t.Fatalf("by platform = %+v", byPlatform)
	}

	byEvidence := reg.QueryCapabilities(CapabilityQuery{EvidenceType: "json-report"})
	if len(byEvidence) != 1 || byEvidence[0].Kind != "policy-audit" {
		t.Fatalf("by evidence type = %+v", byEvidence)
	}

	none := reg.QueryCapabilities(CapabilityQuery{ClaimClass: "nope"})
	if len(none) != 0 {
		t.Fatalf("no-match query = %+v, want empty", none)
	}

	// AND across dimensions: kind matches both rows, claim class only one.
	and := reg.QueryCapabilities(CapabilityQuery{Kind: "execution-attestation", AssuranceLevel: "attested-v2"})
	if len(and) != 1 {
		t.Fatalf("AND query = %+v, want 1 row", and)
	}
}

func TestMemoryStoreCapabilities(t *testing.T) {
	st := NewMemoryStore(nil)
	if err := st.RegisterCapability(baseCapability()); err != nil {
		t.Fatalf("RegisterCapability = %v", err)
	}
	got := st.QueryCapabilities(CapabilityQuery{Kind: "execution-attestation"})
	if len(got) != 1 {
		t.Fatalf("QueryCapabilities = %+v", got)
	}
}
