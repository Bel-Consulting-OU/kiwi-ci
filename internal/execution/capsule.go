package execution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// materializedCapsuleVersion is part of the materialized capsule digest
// preimage: the tag names the exact field set and canonical encoding, and ANY
// change to the EffectiveExecution fields (adding, removing or reordering)
// must bump this version so digests from different encodings can never
// collide. The v1 compilation capsule (provenance.CapsuleDigest) deliberately
// stays unchanged: it binds the admitted computation record, while this v2
// digest binds the FINAL EFFECTIVE EXECUTION (the persisted resource/trust
// overlays, the effective network and the sandbox requirements that actually
// ran).
const materializedCapsuleVersion = "kiwi-ci/execution-capsule/v1"

// MaterializedCapsuleDigest returns the canonical, versioned SHA-256 digest
// over ALL execution-affecting values of e: a length-prefixed encoding of
// every EffectiveExecution field in stable declaration order, with structured
// values canonicalized as JSON (encoding/json emits map keys sorted and
// struct fields in declaration order, so the encoding is canonical).
//
// The digest closes the gap the v1 capsule left open: two payloads with an
// identical CompiledJobPayload but different persisted resource
// envelopes/network/sandbox materialize to different effective executions and
// therefore to different digest values.
func MaterializedCapsuleDigest(e EffectiveExecution) (string, error) {
	h := sha256.New()
	field := func(label string, value any) error {
		payload, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("execution capsule: canonicalize %s: %w", label, err)
		}
		fmt.Fprintf(h, "%d:%s=%d:", len(label), label, len(payload))
		_, _ = h.Write(payload)
		return nil
	}
	// Field order is the EffectiveExecution declaration order; see the
	// version tag contract above.
	fields := []struct {
		label string
		value any
	}{
		{"materializedCapsuleVersion", materializedCapsuleVersion},
		{"compiledJob", e.CompiledJob},
		{"trusted", e.Trusted},
		{"untrusted", e.Untrusted},
		{"policyPresent", e.PolicyPresent},
		{"capabilities", e.Capabilities},
		{"requestedNetwork", int(e.RequestedNetwork)},
		{"network", int(e.Network)},
		{"sandbox", e.Sandbox},
		{"resources", e.Resources},
		{"declaredDiskBytes", e.DeclaredDiskBytes},
		{"workspaceMaxBytes", e.WorkspaceMaxBytes},
		{"workspaceQuotaLimit", e.WorkspaceQuotaLimit},
		{"serviceEnvelope", e.ServiceEnvelope},
		{"requireImmutableImages", e.RequireImmutableImages},
	}
	for _, f := range fields {
		if err := field(f.label, f.value); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
