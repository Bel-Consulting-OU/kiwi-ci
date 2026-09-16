package v1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

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
type GeneratedFragment struct {
	FragmentID string                  `json:"fragment_id,omitempty"`
	Jobs       map[string]pipeline.Job `json:"jobs"`
	Deps       map[string][]string     `json:"deps"`
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
