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
// classification of one attempt: the numeric level and its stable public name
// (model.ExecutionAssurance.Name). Both are bound by the signature so a
// consumer reads one unambiguous claim; a verifier rejects a block whose name
// does not match its level.
type ExecutionAssuranceEvidence struct {
	Level int    `json:"level"`
	Name  string `json:"name"`
}

// NewExecutionAssuranceEvidence renders a derived level into its signed form.
func NewExecutionAssuranceEvidence(level model.ExecutionAssurance) ExecutionAssuranceEvidence {
	return ExecutionAssuranceEvidence{Level: int(level), Name: level.Name()}
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
