package verifyapi

import (
	"fmt"
	"time"
)

// Execution-window authority (P1b).
//
// Freshness must never be satisfied by a caller-typed interval: the
// obligation's started_at/completed_at on a submitted claim are a PROPOSAL,
// not evidence of when the work ran. An execution window is therefore tagged
// with the source that established it, and every freshness judgment requires
// that source to clear a minimum authority level. A window with no trusted
// source is freshness UNKNOWN — which is NOT satisfied (fail closed) and
// surfaces as evidence_incomplete missing=attested_execution_window.

// WindowSource names how an execution window became known. The values form
// an authority ladder (see Authority): Attested > VerifiedObserver > Unknown.
type WindowSource string

const (
	// WindowSourceAttested: the window is the signed job started_at /
	// finished_at carried by a cryptographically resolved execution
	// attestation. This is the only source a RequireAttestedWindow
	// freshness demand accepts.
	WindowSourceAttested WindowSource = "attested"
	// WindowSourceVerifiedObserver: the window comes from a verified
	// observer report (a signature-checked observer statement), weaker
	// than the job's own attested window. It can satisfy a normal
	// freshness demand but never a RequireAttestedWindow one.
	WindowSourceVerifiedObserver WindowSource = "verified_observer"
	// WindowSourceUnknown: no trusted source established the window. A
	// caller-typed interval is always Unknown — the claim's started_at /
	// completed_at never become freshness authority. An Unknown window
	// never satisfies freshness.
	WindowSourceUnknown WindowSource = "unknown"
)

// Authority returns the ladder rung of the source: Unknown=0,
// VerifiedObserver=1, Attested=2. An unknown source is the zero rung.
func (s WindowSource) Authority() int {
	switch s {
	case WindowSourceAttested:
		return 2
	case WindowSourceVerifiedObserver:
		return 1
	default:
		return 0
	}
}

// Valid reports whether s is one of the closed source vocabulary values.
func (s WindowSource) Valid() bool {
	switch s {
	case WindowSourceAttested, WindowSourceVerifiedObserver, WindowSourceUnknown:
		return true
	}
	return false
}

// AtLeast reports whether s is at least as strong as min on the ladder.
func (s WindowSource) AtLeast(min WindowSource) bool {
	return s.Authority() >= min.Authority()
}

// ExecutionWindow is the authoritative execution interval of one
// verification, tagged with the source that established it. The times on an
// Unknown window are the claim's proposed interval, kept only so a record
// still has a structural bracket — they are never freshness authority.
type ExecutionWindow struct {
	StartedAt   time.Time    `json:"started_at"`
	CompletedAt time.Time    `json:"completed_at"`
	Source      WindowSource `json:"source"`
}

// Trusted reports whether the window comes from a non-caller source. An
// Unknown window is untrusted no matter what times it carries.
func (w ExecutionWindow) Trusted() bool {
	return w.Source == WindowSourceAttested || w.Source == WindowSourceVerifiedObserver
}

// SatisfiesFreshness reports whether this window may satisfy a freshness
// demand that requires at least min authority. An Unknown window never
// satisfies anything: there is no trusted window to measure freshness from.
func (w ExecutionWindow) SatisfiesFreshness(min WindowSource) bool {
	if !w.Trusted() {
		return false
	}
	return w.Source.AtLeast(min)
}

// MinWindowForRequireAttested maps Recipe.EvidenceMinimum.RequireAttestedWindow
// onto the window-authority floor: a recipe that demands an attested window
// raises the floor to WindowSourceAttested; otherwise any trusted window
// clears the floor.
func MinWindowForRequireAttested(requireAttestedWindow bool) WindowSource {
	if requireAttestedWindow {
		return WindowSourceAttested
	}
	return WindowSourceVerifiedObserver
}

// FreshnessStatus is the three-valued freshness judgment. Unknown means the
// window carries no trusted authority, so freshness cannot be decided — and
// is NOT satisfied (fail closed).
type FreshnessStatus string

const (
	// FreshnessSatisfied: a trusted window of sufficient authority lies
	// inside the freshness policy.
	FreshnessSatisfied FreshnessStatus = "satisfied"
	// FreshnessUnsatisfied: a trusted window of sufficient authority
	// violates the freshness policy.
	FreshnessUnsatisfied FreshnessStatus = "unsatisfied"
	// FreshnessUnknown: no trusted window of sufficient authority, so the
	// judgment cannot be made. Never counts as satisfied.
	FreshnessUnknown FreshnessStatus = "unknown"
)

// MissingAttestedExecutionWindow names the required evidence item whose
// absence leaves freshness UNKNOWN: an execution window bound by attestation
// (or, under a lower floor, by a verified observer). Used as the
// OutcomeStatus missing-item spelling.
const MissingAttestedExecutionWindow = "attested_execution_window"

// EvaluateFreshness judges the window against the freshness policy at the
// given minimum authority. An untrusted / under-authority window yields
// FreshnessUnknown — never satisfied — so a caller-typed interval can never
// pass. A window that clears the floor is judged against the policy itself.
func EvaluateFreshness(w ExecutionWindow, policy FreshnessPolicy, issuedAt, now time.Time, min WindowSource) FreshnessStatus {
	if !w.SatisfiesFreshness(min) {
		return FreshnessUnknown
	}
	probe := VerificationObligation{IssuedAt: issuedAt, Freshness: policy}
	if err := probe.CheckFreshness(now, w.StartedAt, w.CompletedAt); err != nil {
		return FreshnessUnsatisfied
	}
	return FreshnessSatisfied
}

// deriveWindow picks the authoritative execution window. The attested job
// window wins when the evidence carries one; a verified-observer window is
// next; anything else is Unknown. The claim's proposed window is NEVER a
// source — it is recorded as the times of an Unknown window only so a record
// keeps a structural bracket, and it never satisfies freshness.
func deriveWindow(claim VerificationOutcome, attested, observer *AttestedResourceFacts) ExecutionWindow {
	if attested != nil && !attested.StartedAt.IsZero() && !attested.FinishedAt.IsZero() {
		return ExecutionWindow{
			StartedAt:   attested.StartedAt,
			CompletedAt: attested.FinishedAt,
			Source:      WindowSourceAttested,
		}
	}
	if observer != nil && !observer.StartedAt.IsZero() && !observer.FinishedAt.IsZero() {
		return ExecutionWindow{
			StartedAt:   observer.StartedAt,
			CompletedAt: observer.FinishedAt,
			Source:      WindowSourceVerifiedObserver,
		}
	}
	return ExecutionWindow{
		StartedAt:   claim.StartedAt,
		CompletedAt: claim.CompletedAt,
		Source:      WindowSourceUnknown,
	}
}

// mergeObserver folds the observer-reported job windows of the resolved
// attestations into one window, with the same fail-closed rule as
// mergeAttested: a partial set (some attestations carry a window, others do
// not) or an inverted window drops the merged value entirely rather than
// reporting a half-observed interval as authority.
func mergeObserver(resolved []ResolvedAttestation) *AttestedResourceFacts {
	if len(resolved) == 0 {
		return nil
	}
	var merged *AttestedResourceFacts
	for _, att := range resolved {
		if att.ObserverWindow == nil {
			return nil
		}
		a := *att.ObserverWindow
		if a.StartedAt.IsZero() || a.FinishedAt.IsZero() || a.FinishedAt.Before(a.StartedAt) {
			return nil
		}
		if merged == nil {
			m := a
			merged = &m
			continue
		}
		if a.StartedAt.Before(merged.StartedAt) {
			merged.StartedAt = a.StartedAt
		}
		if a.FinishedAt.After(merged.FinishedAt) {
			merged.FinishedAt = a.FinishedAt
		}
	}
	return merged
}

// WindowSourceRequired renders the authority floor in error messages.
func windowSourceLabel(s WindowSource) string {
	if s == "" {
		return string(WindowSourceVerifiedObserver)
	}
	return string(s)
}

// errWindowAuthority is the refusal raised when a discharge needs a trusted
// window the evidence does not carry.
func errWindowAuthority(min WindowSource, got WindowSource) error {
	return fmt.Errorf("%w: freshness requires a %s execution window, got %s (missing=%s)",
		ErrFreshness, windowSourceLabel(min), windowSourceLabel(got), MissingAttestedExecutionWindow)
}
