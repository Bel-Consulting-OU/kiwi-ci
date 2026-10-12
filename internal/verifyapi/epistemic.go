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
	// EpistemicRequested: the value was asked for or declared as intent
	// (a requirement, a configured wish). It says nothing about what
	// actually happened.
	EpistemicRequested EpistemicLevel = iota
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

// Valid reports whether e is one of the defined ladder rungs.
func (e EpistemicLevel) Valid() bool {
	return e >= EpistemicRequested && e <= EpistemicDerived
}

// AtLeast reports whether e is at least as strong as min on the ladder.
func (e EpistemicLevel) AtLeast(min EpistemicLevel) bool {
	return e >= min
}

// EpistemicLevelOf maps a FactSource onto the epistemic ladder. The
// reported source is an observer assertion, so it sits at observed; unknown
// sources yield the zero level with Valid() == false so a new FactSource must
// be placed deliberately.
func EpistemicLevelOf(s FactSource) EpistemicLevel {
	switch s {
	case FactSourceReported:
		return EpistemicObserved
	case FactSourceAttested:
		return EpistemicAttested
	case FactSourceDerived:
		return EpistemicDerived
	default:
		return EpistemicRequested
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
