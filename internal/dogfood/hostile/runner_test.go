package hostile

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func testAttempt() Attempt {
	return Attempt{
		RunID: "run-1", JobID: "job-1", RunnerID: "runner-1", Generation: 3,
		Status: string(model.StatusSuccess), Protocol: model.ExecutionSemanticsVersion,
		ArtifactSHA256: strings.Repeat("a", 64),
		Receipt: &model.ExecutionControlReceipt{
			Runtime: "docker", SandboxStarted: true,
			NetworkEnforced: model.ObservedNetworkContainerNamespace,
		},
	}
}

// TestNewModeMatrix pins every hostile mode produces the traffic it
// promises — and nothing honest. A mode that silently degrades into a clean
// completion would let a scenario pass without exercising its adversary.
func TestNewModeMatrix(t *testing.T) {
	base := testAttempt()
	for _, mode := range AllModes {
		t.Run(string(mode), func(t *testing.T) {
			traffic, err := New(mode, base)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if len(traffic.Completions) == 0 && mode != ModeNeverHeartbeat {
				// Never-heartbeat still completes; every mode emits at
				// least one claim except when the behavior IS the absence.
				t.Fatal("mode produced no completions")
			}
			switch mode {
			case ModeStaleGeneration:
				c := traffic.Completions[0]
				if c.Generation >= base.Generation {
					t.Fatalf("stale-generation claim generation = %d, want < %d", c.Generation, base.Generation)
				}
			case ModeDuplicateCompletion:
				if len(traffic.Completions) != 2 {
					t.Fatalf("duplicate completions = %d, want 2", len(traffic.Completions))
				}
			case ModeWrongRuntimeReceipt:
				c := traffic.Completions[0]
				if c.Receipt == nil || c.Receipt.Runtime == base.Receipt.Runtime {
					t.Fatalf("wrong-runtime receipt not mutated: %+v", c.Receipt)
				}
				if !c.Receipt.Valid() {
					// The receipt must be a well-formed observation of a
					// DIFFERENT runtime; its contradiction with the job is
					// caught later, not by malformedness.
					t.Fatal("wrong-runtime receipt is malformed (want a valid native receipt)")
				}
			case ModeContradictoryAssurance:
				c := traffic.Completions[0]
				if c.ContradictoryFacts == nil {
					t.Fatal("contradictory-assurance carries no facts")
				}
				if err := c.ContradictoryFacts.ValidateObservedConsistency(); err == nil {
					t.Fatal("contradictory facts pass consistency")
				}
			case ModeArtifactHashLiar:
				c := traffic.Completions[0]
				if c.ArtifactSHA256 == base.ArtifactSHA256 {
					t.Fatal("artifact-hash-liar claimed the true hash")
				}
			case ModeLateLogger:
				if traffic.LogsAfterCompletion == 0 {
					t.Fatal("late-logger emitted no late logs")
				}
			case ModeNeverHeartbeat:
				if traffic.Heartbeats != 0 {
					t.Fatal("never-heartbeat heartbeated")
				}
			case ModeCompletionBeforeArtifact:
				if traffic.ArtifactUploaded {
					t.Fatal("completion-before-artifact uploaded the artifact")
				}
			case ModeWrongJob:
				c := traffic.Completions[0]
				if c.AttemptID == base.JobID {
					t.Fatal("wrong-job claim names the correct job")
				}
			case ModeProtocolDowngrade:
				c := traffic.Completions[0]
				if c.Protocol == base.Protocol {
					t.Fatal("protocol-downgrade kept the current protocol")
				}
			}
		})
	}
}

// TestExpectationsAreLayered pins the defense-layer contract: gate-rejected
// modes claim no liveness budget at the gate, evidence-layer modes must
// fail evidence, and every mode still requires the honest holder to be
// able to finish.
func TestExpectationsAreLayered(t *testing.T) {
	for _, mode := range AllModes {
		exp := mode.Expectation()
		if !exp.RequiresLiveHolder {
			t.Fatalf("%s drops the liveness requirement", mode)
		}
		if exp.GateRejects && exp.EvidenceMustFail {
			t.Fatalf("%s claims two exclusive defense layers", mode)
		}
		switch mode {
		case ModeStaleGeneration, ModeWrongJob, ModeProtocolDowngrade:
			if !exp.GateRejects {
				t.Fatalf("%s must be gate-rejected", mode)
			}
		case ModeDuplicateCompletion:
			if !exp.AcceptsAtMostOne {
				t.Fatal("duplicate-completion must be accept-at-most-one")
			}
		case ModeWrongRuntimeReceipt, ModeContradictoryAssurance, ModeArtifactHashLiar:
			if !exp.EvidenceMustFail {
				t.Fatalf("%s must fail at the evidence layer", mode)
			}
		}
	}
}

// TestUnknownModeRefused: a typo'd mode must error rather than silently
// produce an honest completion.
func TestUnknownModeRefused(t *testing.T) {
	if _, err := New(Mode("bogus"), testAttempt()); err == nil {
		t.Fatal("unknown mode produced traffic")
	}
}
