package verifyapi

import "fmt"

// Evidence completeness and rich terminal states (P11).
//
// The coarse Outcome vocabulary (pass/fail/partial) is what existing
// consumers already understand. Richer surfaces need to say WHY a
// verification did not prove a pass: evidence was missing, invalid, the
// policy refused it, the clock expired, and so on. The types here are the
// richer layer; ProjectCoarse is the deterministic projection back onto
// Outcome so every rich state has exactly one coarse meaning.

// TerminalState is the rich terminal state of one verification attempt. It
// is closed: a terminal state is final for that attempt and never transitions.
type TerminalState string

const (
	// TerminalPassed: every required check passed under the required
	// assurance with complete, valid evidence.
	TerminalPassed TerminalState = "passed"
	// TerminalFailed: at least one required check failed.
	TerminalFailed TerminalState = "failed"
	// TerminalExecutionError: the execution itself errored (crash,
	// infrastructure fault) before a check verdict could be derived.
	TerminalExecutionError TerminalState = "execution_error"
	// TerminalPolicyDenied: a policy gate refused the outcome (scope,
	// assurance floor, capability) even though the run produced facts.
	TerminalPolicyDenied TerminalState = "policy_denied"
	// TerminalEvidenceIncomplete: required evidence is missing, so the
	// obligation cannot be discharged.
	TerminalEvidenceIncomplete TerminalState = "evidence_incomplete"
	// TerminalEvidenceInvalid: evidence was presented but failed
	// cryptographic or structural verification.
	TerminalEvidenceInvalid TerminalState = "evidence_invalid"
	// TerminalExpired: the obligation's freshness window closed before a
	// complete verdict landed (or the verdict is stale).
	TerminalExpired TerminalState = "expired"
	// TerminalCancelled: the attempt was cancelled mid-flight. A cancelled
	// attempt never discharges an obligation.
	TerminalCancelled TerminalState = "cancelled"
	// TerminalSuperseded: a later attempt replaced this one as the
	// candidate's canonical result. The historical record stands.
	TerminalSuperseded TerminalState = "superseded"
	// TerminalUnsupported: the recipe or contract requires a capability
	// this substrate does not implement; nothing was verified.
	TerminalUnsupported TerminalState = "unsupported"
)

// Valid reports whether s is one of the closed terminal-state values.
func (s TerminalState) Valid() bool {
	switch s {
	case TerminalPassed, TerminalFailed, TerminalExecutionError,
		TerminalPolicyDenied, TerminalEvidenceIncomplete, TerminalEvidenceInvalid,
		TerminalExpired, TerminalCancelled, TerminalSuperseded, TerminalUnsupported:
		return true
	default:
		return false
	}
}

// ProjectCoarse is the deterministic projection onto the coarse Outcome
// vocabulary. Only TerminalPassed projects to OutcomePass (the single
// discharge state). States that definitively refused a pass project to
// OutcomeFail; states that never completed a determination project to
// OutcomePartial. The mapping is total over valid states and is pinned by
// tests so a consumer can rely on it.
func (s TerminalState) ProjectCoarse() Outcome {
	switch s {
	case TerminalPassed:
		return OutcomePass
	case TerminalFailed, TerminalPolicyDenied, TerminalEvidenceInvalid,
		TerminalExpired, TerminalUnsupported:
		return OutcomeFail
	case TerminalExecutionError, TerminalEvidenceIncomplete,
		TerminalCancelled, TerminalSuperseded:
		return OutcomePartial
	default:
		return OutcomePartial
	}
}

// UnverifiedReason names why a verification is not a proven pass. It is set
// on every terminal state other than TerminalPassed, and empty on a pass.
type UnverifiedReason string

const (
	// ReasonMissingRequiredEvidence: required evidence items are absent.
	ReasonMissingRequiredEvidence UnverifiedReason = "missing_required_evidence"
	// ReasonInvalidEvidence: presented evidence failed verification.
	ReasonInvalidEvidence UnverifiedReason = "invalid_evidence"
	// ReasonChecksNotCovered: the execution ran but did not cover every
	// required check.
	ReasonChecksNotCovered UnverifiedReason = "checks_not_covered"
	// ReasonInsufficientAssurance: the achieved assurance is below the
	// required profile.
	ReasonInsufficientAssurance UnverifiedReason = "insufficient_assurance"
	// ReasonJobFailed: the attested job status is failure.
	ReasonJobFailed UnverifiedReason = "job_failed"
	// ReasonExecutionError: the execution errored before a verdict.
	ReasonExecutionError UnverifiedReason = "execution_error"
	// ReasonPolicyDenied: a policy gate refused the outcome.
	ReasonPolicyDenied UnverifiedReason = "policy_denied"
	// ReasonExpired: the freshness window closed first.
	ReasonExpired UnverifiedReason = "expired"
	// ReasonCancelled: the attempt was cancelled.
	ReasonCancelled UnverifiedReason = "cancelled"
	// ReasonSuperseded: a later attempt replaced this one.
	ReasonSuperseded UnverifiedReason = "superseded"
	// ReasonUnsupported: required capability is not implemented.
	ReasonUnsupported UnverifiedReason = "unsupported"
)

// EvidenceCompleteness counts the evidence items of one verification against
// what the recipe (or obligation) requires. The counters are computed, never
// caller-asserted, by the completeness constructor below.
type EvidenceCompleteness struct {
	// Required is how many evidence items the recipe demands.
	Required int `json:"required"`
	// Present is how many required items the submission cites.
	Present int `json:"present"`
	// Verified is how many cited required items cryptographically
	// verified.
	Verified int `json:"verified"`
	// Missing is required items that are not cited (set difference).
	Missing int `json:"missing"`
	// Invalid is required items that were cited but failed verification.
	Invalid int `json:"invalid"`
}

// ComputeEvidenceCompleteness derives the counter set from the required,
// cited, and verified item identities. Items are matched by identity string
// and duplicates collapse. The counters account for the REQUIRED set only:
// Present counts required items the submission cites, Verified counts those
// that also verified, Missing is required-but-not-cited, and Invalid is
// required-and-cited-but-not-verified. Cited or verified items outside the
// required set are ignored (they cannot back this claim).
func ComputeEvidenceCompleteness(required, present, verified []string) EvidenceCompleteness {
	req := stringSet(required)
	pres := stringSet(present)
	ver := stringSet(verified)
	c := EvidenceCompleteness{Required: len(req)}
	for id := range req {
		_, isPresent := pres[id]
		_, isVerified := ver[id]
		switch {
		case !isPresent:
			c.Missing++
		case !isVerified:
			c.Present++
			c.Invalid++
		default:
			c.Present++
			c.Verified++
		}
	}
	return c
}

// Complete reports whether every required item is present and verified, with
// nothing missing or invalid. An empty requirement set is not complete: a
// recipe that demands nothing can never discharge anything.
func (c EvidenceCompleteness) Complete() bool {
	return c.Required > 0 && c.Missing == 0 && c.Invalid == 0 && c.Verified == c.Required
}

// OutcomeStatus is the richer outcome view: the rich terminal state, the
// reason it is not a proven pass (when it is not), and the evidence
// completeness counters behind that judgment. Coarse is the projection for
// consumers still on the pass/fail/partial vocabulary.
type OutcomeStatus struct {
	Terminal TerminalState        `json:"terminal"`
	Reason   UnverifiedReason     `json:"reason,omitempty"`
	Evidence EvidenceCompleteness `json:"evidence"`
	Coarse   Outcome              `json:"coarse"`
}

// ProvenPass reports whether this status is a proven pass (the single
// discharge state).
func (s OutcomeStatus) ProvenPass() bool {
	return s.Terminal == TerminalPassed
}

// StatusFromCompleteness derives the OutcomeStatus of one attempt from its
// evidence completeness and the coarse verdict the verifier derived. The
// terminal state and reason are computed here so the same facts always
// produce the same status; a caller cannot mark an incomplete set as passed.
func StatusFromCompleteness(c EvidenceCompleteness, derived Outcome) OutcomeStatus {
	if c.Invalid > 0 {
		return OutcomeStatus{
			Terminal: TerminalEvidenceInvalid,
			Reason:   ReasonInvalidEvidence,
			Evidence: c,
			Coarse:   TerminalEvidenceInvalid.ProjectCoarse(),
		}
	}
	if c.Missing > 0 {
		return OutcomeStatus{
			Terminal: TerminalEvidenceIncomplete,
			Reason:   ReasonMissingRequiredEvidence,
			Evidence: c,
			Coarse:   TerminalEvidenceIncomplete.ProjectCoarse(),
		}
	}
	switch derived {
	case OutcomePass:
		if !c.Complete() {
			// A claimed pass without a complete evidence set is not a
			// pass; it is an incomplete attempt.
			return OutcomeStatus{
				Terminal: TerminalEvidenceIncomplete,
				Reason:   ReasonMissingRequiredEvidence,
				Evidence: c,
				Coarse:   TerminalEvidenceIncomplete.ProjectCoarse(),
			}
		}
		return OutcomeStatus{
			Terminal: TerminalPassed,
			Evidence: c,
			Coarse:   OutcomePass,
		}
	case OutcomeFail:
		return OutcomeStatus{
			Terminal: TerminalFailed,
			Reason:   ReasonJobFailed,
			Evidence: c,
			Coarse:   OutcomeFail,
		}
	default:
		return OutcomeStatus{
			Terminal: TerminalEvidenceIncomplete,
			Reason:   ReasonChecksNotCovered,
			Evidence: c,
			Coarse:   OutcomePartial,
		}
	}
}

// String renders the status as "terminal" or "terminal: reason".
func (s OutcomeStatus) String() string {
	if s.Reason == "" {
		return string(s.Terminal)
	}
	return fmt.Sprintf("%s: %s", s.Terminal, s.Reason)
}
