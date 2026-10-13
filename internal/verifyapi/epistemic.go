package verifyapi

// Epistemic levels for key facts (P10).
//
// Every quantity a verification surface carries is known at some epistemic
// level: how the value became known, not how important it is. The ladder is
// ordered; a fact at a higher level is stronger evidence about the world than
// the same claim at a lower one. Existing FactSource values map onto the
// ladder (see EpistemicLevelOf), so callers that already tag facts with a
// FactSource stay valid.

// EpistemicLevel is the provenance ladder of a fact.
type EpistemicLevel int

const (
	// EpistemicUnknown is the zero value: the level is not known or not
	// placeable on the ladder. It is NEVER a request/intent fact and is
	// invalid — Valid() reports false — so a new FactSource must be placed
	// deliberately rather than silently landing on a real rung.
	EpistemicUnknown EpistemicLevel = iota
	// EpistemicRequested: the value was asked for or declared as intent
	// (a requirement, a configured wish). It says nothing about what
	// actually happened.
	EpistemicRequested
	// EpistemicConfigured: the value is what a configuration or recipe
	// declares should hold. Still not an observation.
	EpistemicConfigured
	// EpistemicObserved: a runtime observer reported the value (executor
	// counters, runner assertions). Trustworthy only as far as the
	// observer is.
	EpistemicObserved
	// EpistemicAttested: a cryptographically resolved attestation binds
	// the value.
	EpistemicAttested
	// EpistemicDerived: the substrate computed the value itself from
	// fields it validates (so a caller cannot inflate it).
	EpistemicDerived
)

// String renders the level in its wire spelling.
func (e EpistemicLevel) String() string {
	switch e {
	case EpistemicUnknown:
		return "unknown"
	case EpistemicRequested:
		return "requested"
	case EpistemicConfigured:
		return "configured"
	case EpistemicObserved:
		return "observed"
	case EpistemicAttested:
		return "attested"
	case EpistemicDerived:
		return "derived"
	default:
		return "unknown"
	}
}

// Valid reports whether e is one of the defined ladder rungs. EpistemicUnknown
// is invalid: an unknown level is not a fact on the ladder and must never be
// treated as a request or any other rung.
func (e EpistemicLevel) Valid() bool {
	return e > EpistemicUnknown && e <= EpistemicDerived
}

// AtLeast reports whether e is at least as strong as min on the ladder. Fail
// closed: an unknown/invalid level on either side is never at least anything.
func (e EpistemicLevel) AtLeast(min EpistemicLevel) bool {
	if !e.Valid() || !min.Valid() {
		return false
	}
	return e >= min
}

// EpistemicLevelOf maps a FactSource onto the epistemic ladder. The
// reported source is an observer assertion, so it sits at observed. An
// unknown source yields (EpistemicUnknown, false) — never EpistemicRequested —
// so a new FactSource must be placed deliberately before it can claim a rung.
func EpistemicLevelOf(s FactSource) (EpistemicLevel, bool) {
	switch s {
	case FactSourceReported:
		return EpistemicObserved, true
	case FactSourceAttested:
		return EpistemicAttested, true
	case FactSourceDerived:
		return EpistemicDerived, true
	default:
		return EpistemicUnknown, false
	}
}

// Epistemic is a value tagged with the epistemic level at which it is known.
// Use it on new key facts so consumers can require a minimum rung
// (e.g. attested) without re-deriving provenance per field.
type Epistemic[T any] struct {
	Value T              `json:"value"`
	Level EpistemicLevel `json:"level"`
}

// Known reports whether the tagged value is known at least at min.
func (e Epistemic[T]) Known(min EpistemicLevel) bool {
	return e.Level.AtLeast(min)
}

// Requested tags v as mere request/intent.
func Requested[T any](v T) Epistemic[T] {
	return Epistemic[T]{Value: v, Level: EpistemicRequested}
}

// Configured tags v as configured/declared.
func Configured[T any](v T) Epistemic[T] {
	return Epistemic[T]{Value: v, Level: EpistemicConfigured}
}

// Observed tags v as an observer report.
func Observed[T any](v T) Epistemic[T] {
	return Epistemic[T]{Value: v, Level: EpistemicObserved}
}

// AttestedE tags v as attestation-bound.
func AttestedE[T any](v T) Epistemic[T] {
	return Epistemic[T]{Value: v, Level: EpistemicAttested}
}

// DerivedE tags v as substrate-derived.
func DerivedE[T any](v T) Epistemic[T] {
	return Epistemic[T]{Value: v, Level: EpistemicDerived}
}
