package dogfood

import (
	"fmt"
	"math/rand"
	"time"
)

// Seed is the captured reproducibility record of one dogfood invocation: the
// deterministic scenario seed plus the run metadata needed to re-materialize
// the exact environment later. Chaos failures are only actionable if the
// invocation that produced them can be replayed, so the seed is captured
// BEFORE any scenario runs and is copied into every ScenarioResult.
type Seed struct {
	// Value is the deterministic scenario seed (math/rand source seed).
	Value int64 `json:"value"`
	// CapturedAt is when the harness locked the seed.
	CapturedAt time.Time `json:"captured_at"`
	// Metadata is the run identity the scenarios execute under.
	Metadata RunMetadata `json:"metadata"`
}

// RunMetadata identifies what was under test: the commit, the component
// versions, the executor backend and the effective policy digest the runs
// are admitted against. All of it is copied into scenario results so a
// failure report says WHICH engine and policy produced it.
type RunMetadata struct {
	// Commit is the Kiwi commit under test.
	Commit string `json:"commit"`
	// Versions are the component versions under test.
	Versions VersionInfo `json:"versions"`
	// Executor names the execution backend (docker, tart, fake, ...).
	Executor string `json:"executor"`
	// PolicyDigest is the canonical digest of the effective policy the
	// seeded runs are admitted against (provenance.EffectivePolicyDigest).
	PolicyDigest string `json:"policy_digest"`
}

// VersionInfo records the versions of the components under test. Protocol is
// the runner protocol / execution-semantics version so a downgrade scenario
// has a concrete floor to violate.
type VersionInfo struct {
	Server   string `json:"server"`
	Runner   string `json:"runner"`
	Protocol string `json:"protocol"`
}

// NewSeed locks a reproducibility seed. A caller that wants a fresh random
// invocation passes time.Now() and a freshly generated value; a chaos replay
// passes the captured Seed.Value and Seed.Metadata verbatim.
func NewSeed(value int64, now time.Time, meta RunMetadata) Seed {
	return Seed{Value: value, CapturedAt: now.UTC(), Metadata: meta}
}

// Source returns the deterministic scenario RNG for this seed. Scenario
// choices (branch names, fault timings, hostile mode selection) must draw
// from this source and never from crypto/rand, so a reported failure is
// replayable byte-for-byte.
func (s Seed) Source() *rand.Rand {
	return rand.New(rand.NewSource(s.Value)) //nolint:gosec // deterministic chaos replay, not a security boundary
}

// Valid reports whether the seed carries enough identity to replay a run.
func (s Seed) Valid() bool {
	return s.Metadata.Commit != "" && s.Metadata.Versions.Protocol != ""
}

// Validate refuses an incomplete seed record before any scenario runs: a
// failure under an unknown commit cannot be attributed.
func (s Seed) Validate() error {
	if s.Value == 0 && s.Metadata.Commit == "" {
		return fmt.Errorf("dogfood: seed is empty")
	}
	if !s.Valid() {
		return fmt.Errorf("dogfood: seed metadata incomplete (commit=%q protocol=%q)", s.Metadata.Commit, s.Metadata.Versions.Protocol)
	}
	return nil
}
