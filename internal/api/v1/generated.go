package v1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// GeneratedFragment is the wire body of POST /api/v1/jobs/{id}/generated: a
// runner uploads the child graph its generator produced. Jobs maps the child
// key to its pipeline job spec; deps carries the fragment-internal dependency
// edges (both keys must reference fragment keys; the generating job is the
// implicit dependency of every child).
//
// FragmentID is the deterministic idempotency key of {jobs, deps}: the runner
// computes it with Digest and sends it, the control plane recomputes it from
// the parsed body and rejects a mismatch (400). The id is deliberately NOT
// part of the digest, so re-sending the same fragment always derives the same
// key.
//
// ExternalContext is optional caller-supplied correlation data the generator
// attaches to the mutation (for example a PR number, a trace id or the digest
// of an external planning document). It is bounded opaque data: at most 256
// bytes, printable UTF-8, no control characters (ValidateExternalContext); it
// is never interpreted by Kiwi and must never carry secrets. It is
// deliberately NOT part of Digest: the graph identity is {jobs, deps}, and a
// deterministic retry that re-sends the same graph under a different (or no)
// context still maps to the same mutation. The children admitted by the
// original mutation keep the context the original admission carried.
type GeneratedFragment struct {
	FragmentID      string                  `json:"fragment_id,omitempty"`
	Jobs            map[string]pipeline.Job `json:"jobs"`
	Deps            map[string][]string     `json:"deps"`
	ExternalContext string                  `json:"external_context,omitempty"`
}

// MaxExternalContextBytes bounds ExternalContext. The bound is on the wire
// bytes of the string, so a malformed request cannot grow durable job records
// without limit.
const MaxExternalContextBytes = 256

// ValidateExternalContext enforces the external-context grammar: empty is
// allowed (no context attached); otherwise the value must be valid UTF-8,
// at most MaxExternalContextBytes bytes, and every rune must be printable
// (unicode.IsPrint), which excludes every control character including newlines
// and tabs. The value is opaque correlation data and is never interpreted.
func ValidateExternalContext(s string) error {
	if s == "" {
		return nil
	}
	if len(s) > MaxExternalContextBytes {
		return fmt.Errorf("external_context exceeds %d bytes", MaxExternalContextBytes)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("external_context is not valid UTF-8")
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("external_context contains a non-printable character")
		}
	}
	return nil
}

// Digest returns the fragment id: sha256 hex of the canonical JSON form of the
// parsed {jobs, deps} pair. Encoding/json renders map keys in sorted order and
// struct fields in declaration order, so the same parsed fragment always yields
// the same digest on the runner and on every control-plane replica. A nil Jobs
// map marshals as an empty object so an absurd fragment still has a stable id.
func (f GeneratedFragment) Digest() (string, error) {
	jobs := f.Jobs
	if jobs == nil {
		jobs = map[string]pipeline.Job{}
	}
	deps := f.Deps
	if deps == nil {
		deps = map[string][]string{}
	}
	b, err := json.Marshal(struct {
		Jobs map[string]pipeline.Job `json:"jobs"`
		Deps map[string][]string     `json:"deps"`
	}{Jobs: jobs, Deps: deps})
	if err != nil {
		return "", fmt.Errorf("fragment digest: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
