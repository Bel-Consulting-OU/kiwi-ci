package verifyapi

import "fmt"

// VerifierCapability declares what one evidence verifier can actually check:
// which claim kind and version it implements, which claim classes and
// assurance levels it understands, which platforms it can attest over, and
// which evidence types it can cryptographically resolve. Capabilities are
// advertising, not enforcement: the Registry stores and serves them so a
// caller can discover a fit verifier, while the binding rule and the
// EvidenceVerifier remain the only acceptance boundary.
//
// All class/level/platform/evidence values are opaque strings defined by the
// verification contract ecosystem, not by this package — the substrate stays
// product-neutral.
type VerifierCapability struct {
	// Kind names the verifier family (e.g. "execution-attestation").
	Kind string `json:"kind"`
	// Version is the capability schema version of that family.
	Version string `json:"version"`
	// ClaimClasses are the claim classes this verifier can verify.
	ClaimClasses []string `json:"claim_classes,omitempty"`
	// AssuranceLevels are the assurance profiles this verifier can confirm.
	AssuranceLevels []string `json:"assurance_levels,omitempty"`
	// Platforms are the execution platforms this verifier covers.
	Platforms []string `json:"platforms,omitempty"`
	// EvidenceTypes are the evidence encodings this verifier can resolve.
	EvidenceTypes []string `json:"evidence_types,omitempty"`
}

// Validate reports whether the capability is structurally sound: a kind, a
// version, and at least one advertised dimension so an empty row cannot
// masquerade as a universal verifier.
func (c VerifierCapability) Validate() error {
	if c.Kind == "" {
		return fmt.Errorf("%w: capability kind is required", ErrInvalid)
	}
	if c.Version == "" {
		return fmt.Errorf("%w: capability version is required", ErrInvalid)
	}
	if len(c.ClaimClasses) == 0 && len(c.AssuranceLevels) == 0 &&
		len(c.Platforms) == 0 && len(c.EvidenceTypes) == 0 {
		return fmt.Errorf("%w: capability %s/%s advertises nothing", ErrInvalid, c.Kind, c.Version)
	}
	for label, list := range map[string][]string{
		"claim_classes":    c.ClaimClasses,
		"assurance_levels": c.AssuranceLevels,
		"platforms":        c.Platforms,
		"evidence_types":   c.EvidenceTypes,
	} {
		for i, v := range list {
			if v == "" {
				return fmt.Errorf("%w: capability %s/%s has empty %s[%d]", ErrInvalid, c.Kind, c.Version, label, i)
			}
		}
	}
	return nil
}

// CapabilityQuery filters registered capabilities. Zero fields match all;
// non-empty fields must all match (AND across dimensions, OR within one).
type CapabilityQuery struct {
	Kind           string
	Version        string
	ClaimClass     string
	AssuranceLevel string
	Platform       string
	EvidenceType   string
}

// matches reports whether c satisfies every non-empty query dimension.
func (q CapabilityQuery) matches(c VerifierCapability) bool {
	if q.Kind != "" && c.Kind != q.Kind {
		return false
	}
	if q.Version != "" && c.Version != q.Version {
		return false
	}
	if q.ClaimClass != "" && !containsString(c.ClaimClasses, q.ClaimClass) {
		return false
	}
	if q.AssuranceLevel != "" && !containsString(c.AssuranceLevels, q.AssuranceLevel) {
		return false
	}
	if q.Platform != "" && !containsString(c.Platforms, q.Platform) {
		return false
	}
	if q.EvidenceType != "" && !containsString(c.EvidenceTypes, q.EvidenceType) {
		return false
	}
	return true
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func capabilityKey(c VerifierCapability) string {
	return c.Kind + "\x00" + c.Version
}
