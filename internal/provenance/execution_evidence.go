package provenance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// ExecutionAssuranceEvidence is the signed form of the execution-assurance
// classification of one attempt: the AUTHORITATIVE control-fact vector plus
// the DERIVED profile label (numeric level and stable public name). The facts
// are the decision surface; the label is a convenience view. Both are bound
// by the signature, and a verifier recomputes the label from the facts so a
// signed profile can never disagree with its signed facts.
//
// Facts is a pointer so schema-v4 statements (which carried only level+name)
// keep their exact canonical JSON shape and still verify: an omitted pointer
// marshals as no field.
type ExecutionAssuranceEvidence struct {
	Level int                   `json:"level"`
	Name  string                `json:"name"`
	Facts *model.ExecutionFacts `json:"facts,omitempty"`
}

// NewExecutionAssuranceEvidence renders an authoritative fact vector into its
// signed form, deriving the profile label with the single shared rule
// (model.DeriveAssuranceProfile). An invalid vector is refused rather than
// signed.
func NewExecutionAssuranceEvidence(facts model.ExecutionFacts) (ExecutionAssuranceEvidence, error) {
	if !facts.Valid() {
		return ExecutionAssuranceEvidence{}, fmt.Errorf("provenance: invalid execution facts")
	}
	level := model.DeriveAssuranceProfile(facts)
	f := facts
	return ExecutionAssuranceEvidence{Level: int(level), Name: level.Name(), Facts: &f}, nil
}

// legacyAssuranceNamesV4 is the frozen name map of attestation schema v4,
// retained so previously issued v4 statements keep verifying. It is
// verification-only: new evidence is always built under the current schema.
var legacyAssuranceNamesV4 = map[int]string{
	0: "uncontrolled",
	1: "isolated_filesystem",
	2: "no_ambient_credentials",
	3: "network_denied",
	4: "kiwi_mediated_authority",
	5: "hermetic",
}

// effectivePolicyDigestVersion tags the canonical effective-policy digest
// encoding: any change to the encoding bumps the tag so digests from
// different encodings can never collide.
const effectivePolicyDigestVersion = "kiwi-ci/effective-policy-digest/v1"

// EffectivePolicyDigest returns the canonical, versioned SHA-256 digest of
// the persisted payload's effective policy: the same length-prefixed field
// encoding CapsuleDigest uses over the canonical JSON of EffectivePolicy
// (encoding/json emits map keys sorted, so the encoding is canonical). An
// absent payload or policy yields the empty string: the field is omitted from
// evidence rather than fabricated.
func EffectivePolicyDigest(p *model.CompiledJobPayload) (string, error) {
	if p == nil || p.EffectivePolicy == nil {
		return "", nil
	}
	h := sha256.New()
	field := func(label, value string) {
		fmt.Fprintf(h, "%d:%s=%d:", len(label), label, len(value))
		_, _ = io.WriteString(h, value)
	}
	field("effectivePolicyDigestVersion", effectivePolicyDigestVersion)
	raw, err := canonicalPolicyJSON(p.EffectivePolicy)
	if err != nil {
		return "", fmt.Errorf("provenance: canonicalize effective policy: %w", err)
	}
	if raw == nil {
		return "", nil
	}
	field("effectivePolicy", string(raw))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// canonicalPolicyJSON canonicalizes a persisted policy value: it is marshaled,
// re-decoded with json.Number (numeric literals preserved verbatim) and
// re-encoded with encoding/json, which sorts object keys. Two semantically
// identical policy documents therefore produce identical bytes regardless of
// their persisted key order, while any value change changes the bytes. A nil
// or empty value canonicalizes to nil (no field preimage).
func canonicalPolicyJSON(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	switch raw := v.(type) {
	case json.RawMessage:
		if len(raw) == 0 {
			return nil, nil
		}
	case []byte:
		if len(raw) == 0 {
			return nil, nil
		}
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

// graphFingerprintVersion tags the canonical graph-fingerprint encoding.
const graphFingerprintVersion = "kiwi-ci/graph-fingerprint/v1"

// GraphFingerprint returns the canonical SHA-256 of a run's job graph: a
// length-prefixed encoding over the jobs sorted by run-scoped logical key
// (ID as the deterministic tie-break), carrying each job's key and its
// dependency needs as a sorted set. It binds the SHAPE of the graph (which
// nodes exist and how they depend on each other), not job status, identity or
// store row order, so two runs with the same graph topology fingerprint
// identically while any added, removed or rewired node changes the value.
//
// The fingerprint is derived from the durable job records at emission time;
// an empty list yields the well-defined empty-graph fingerprint (it is never
// an empty string).
func GraphFingerprint(jobs []model.Job) string {
	sorted := append([]model.Job(nil), jobs...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Key != sorted[j].Key {
			return sorted[i].Key < sorted[j].Key
		}
		return sorted[i].ID < sorted[j].ID
	})
	h := sha256.New()
	field := func(label, value string) {
		fmt.Fprintf(h, "%d:%s=%d:", len(label), label, len(value))
		_, _ = io.WriteString(h, value)
	}
	field("graphFingerprintVersion", graphFingerprintVersion)
	field("jobCount", strconv.Itoa(len(sorted)))
	for _, j := range sorted {
		field("jobKey", j.Key)
		needs := append([]string(nil), j.Needs...)
		sort.Strings(needs)
		field("needCount", strconv.Itoa(len(needs)))
		for _, need := range needs {
			field("need", need)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
