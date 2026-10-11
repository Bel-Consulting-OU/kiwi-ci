package hostile

import (
	"fmt"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Mode is one deterministic hostile-runner behavior. The names are stable
// so scenario IDs and result files can reference an exact adversary.
type Mode string

const (
	// ModeStaleGeneration completes with the lease generation the runner
	// held BEFORE a reassignment/reclaim — the classic stale-writer race.
	ModeStaleGeneration Mode = "stale-generation"
	// ModeDuplicateCompletion completes the same attempt twice.
	ModeDuplicateCompletion Mode = "duplicate-completion"
	// ModeWrongRuntimeReceipt reports an enforcement receipt whose runtime
	// contradicts the effective execution (e.g. native receipt on a
	// container job).
	ModeWrongRuntimeReceipt Mode = "wrong-runtime-receipt"
	// ModeContradictoryAssurance reports assurance facts that contradict
	// their own observed receipt (e.g. network denied + connected namespace).
	ModeContradictoryAssurance Mode = "contradictory-assurance"
	// ModeArtifactHashLiar claims an artifact hash that does not match the
	// collected bytes.
	ModeArtifactHashLiar Mode = "artifact-hash-liar"
	// ModeLateLogger posts log lines after the terminal completion.
	ModeLateLogger Mode = "late-logger"
	// ModeNeverHeartbeat never heartbeats during the attempt.
	ModeNeverHeartbeat Mode = "never-heartbeat"
	// ModeCompletionBeforeArtifact completes before its artifact is
	// uploaded — the finalize window the crash-recovery ledger owns.
	ModeCompletionBeforeArtifact Mode = "completion-before-artifact"
	// ModeWrongJob completes a different job's attempt id than the lease
	// names.
	ModeWrongJob Mode = "wrong-job"
	// ModeProtocolDowngrade completes under an older execution-semantics
	// version than the floor.
	ModeProtocolDowngrade Mode = "protocol-downgrade"
)

// AllModes is the closed hostile vocabulary.
var AllModes = []Mode{
	ModeStaleGeneration,
	ModeDuplicateCompletion,
	ModeWrongRuntimeReceipt,
	ModeContradictoryAssurance,
	ModeArtifactHashLiar,
	ModeLateLogger,
	ModeNeverHeartbeat,
	ModeCompletionBeforeArtifact,
	ModeWrongJob,
	ModeProtocolDowngrade,
}

// Attempt is the honest baseline one hostile mode mutates: the lease the
// runner currently holds and the completion it would legitimately send.
type Attempt struct {
	RunID      string
	JobID      string
	RunnerID   string
	Generation int64
	Status     string
	Protocol   string
	// ArtifactSHA256 is the hash of the artifact bytes the control plane
	// actually collected (the truth the liar contradicts).
	ArtifactSHA256 string
	// Receipt is the honest executor-observed enforcement receipt.
	Receipt *model.ExecutionControlReceipt
	// Competitor is the runner the lease will be (or was) reassigned to;
	// used by stale-generation to pick the pre-reassignment generation.
	Competitor string
}

// Traffic is the protocol traffic a hostile runner emits for one attempt.
// Completions are the terminal claims (possibly several, for duplicates);
// LogsAfterCompletion counts log lines posted after the terminal completion;
// Heartbeats is how many heartbeats the runner sent.
type Traffic struct {
	Mode                Mode
	Completions         []Completion
	LogsAfterCompletion int
	Heartbeats          int
	ArtifactUploaded    bool
}

// Completion is one terminal claim. It mirrors the fields the control-plane
// gate inspects; the harness translates it into its own gate input.
type Completion struct {
	RunID          string
	JobID          string
	AttemptID      string
	RunnerID       string
	Generation     int64
	Status         string
	Protocol       string
	ArtifactSHA256 string
	Receipt        *model.ExecutionControlReceipt
	// ContradictoryFacts, when non-nil, are the hostile assurance facts the
	// completion claims (used by ModeContradictoryAssurance).
	ContradictoryFacts *model.ExecutionFacts
}

// New builds the hostile traffic for mode against a baseline attempt. An
// unknown mode is refused so a scenario cannot silently fall through to an
// honest completion.
func New(mode Mode, base Attempt) (Traffic, error) {
	honest := Completion{
		RunID:          base.RunID,
		JobID:          base.JobID,
		AttemptID:      base.JobID,
		RunnerID:       base.RunnerID,
		Generation:     base.Generation,
		Status:         base.Status,
		Protocol:       base.Protocol,
		ArtifactSHA256: base.ArtifactSHA256,
		Receipt:        base.Receipt,
	}
	t := Traffic{Mode: mode, Heartbeats: 1, ArtifactUploaded: true}
	switch mode {
	case ModeStaleGeneration:
		c := honest
		if c.Generation > 1 {
			c.Generation--
		}
		t.Completions = []Completion{c}
	case ModeDuplicateCompletion:
		t.Completions = []Completion{honest, honest}
	case ModeWrongRuntimeReceipt:
		c := honest
		c.Receipt = &model.ExecutionControlReceipt{
			Runtime:         "native",
			SandboxStarted:  false,
			NetworkEnforced: model.ObservedNetworkHost,
		}
		t.Completions = []Completion{c}
	case ModeContradictoryAssurance:
		c := honest
		// The receipt says the container entered a connected namespace; the
		// facts claim effective network none — the exact contradiction
		// ValidateObservedConsistency must refuse. The receipt is attached
		// to the facts so the pair is validated as a unit, which is how the
		// evidence builder would see it.
		c.Receipt = &model.ExecutionControlReceipt{
			Runtime:         "docker",
			SandboxStarted:  true,
			NetworkEnforced: model.ObservedNetworkContainerNamespace,
		}
		facts := model.ExecutionFacts{
			Runtime:            model.RuntimeFactContainer,
			FilesystemIsolated: true,
			NetworkMode:        model.NetworkModeFactNone,
			Observed:           c.Receipt,
		}
		c.ContradictoryFacts = &facts
		t.Completions = []Completion{c}
	case ModeArtifactHashLiar:
		c := honest
		c.ArtifactSHA256 = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
		t.Completions = []Completion{c}
	case ModeLateLogger:
		t.Completions = []Completion{honest}
		t.LogsAfterCompletion = 3
	case ModeNeverHeartbeat:
		t.Heartbeats = 0
		t.Completions = []Completion{honest}
	case ModeCompletionBeforeArtifact:
		t.ArtifactUploaded = false
		t.Completions = []Completion{honest}
	case ModeWrongJob:
		c := honest
		c.AttemptID = base.JobID + "-other"
		t.Completions = []Completion{c}
	case ModeProtocolDowngrade:
		c := honest
		c.Protocol = "kiwi.execution.v1"
		t.Completions = []Completion{c}
	default:
		return Traffic{}, fmt.Errorf("hostile: unknown mode %q", mode)
	}
	return t, nil
}

// Expectation is what the control plane must do with this traffic for the
// scenario to be green. The hostile surface splits into three layers of
// defense, and a mode is graded against the layer that owns it:
//
//   - GateRejects: every completion is refused at the control-plane gate.
//   - AcceptsAtMostOne: only the first completion may land (duplicates).
//   - EvidenceMustFail: a completion that lands must still fail signing,
//     verification or the artifact-hash comparison — the evidence layer
//     must catch the lie the gate let through.
//
// Liveness is always required: after the hostile traffic the honest holder
// must still be able to complete and evidence must verify.
type Expectation struct {
	GateRejects        bool
	AcceptsAtMostOne   bool
	EvidenceMustFail   bool
	RequiresLiveHolder bool
}

// Expectation returns the defense-layer contract for the mode.
func (m Mode) Expectation() Expectation {
	switch m {
	case ModeStaleGeneration, ModeWrongJob, ModeProtocolDowngrade:
		return Expectation{GateRejects: true, RequiresLiveHolder: true}
	case ModeDuplicateCompletion:
		return Expectation{AcceptsAtMostOne: true, RequiresLiveHolder: true}
	case ModeWrongRuntimeReceipt, ModeContradictoryAssurance, ModeArtifactHashLiar:
		return Expectation{EvidenceMustFail: true, RequiresLiveHolder: true}
	default:
		// ModeLateLogger, ModeNeverHeartbeat, ModeCompletionBeforeArtifact:
		// the completion itself is legitimate; the surrounding discipline
		// is what the scenario flags.
		return Expectation{RequiresLiveHolder: true}
	}
}
