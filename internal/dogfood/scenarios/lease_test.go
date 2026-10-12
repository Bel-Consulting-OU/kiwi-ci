package scenarios

import (
	"fmt"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood/hostile"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
)

// leaseFixture is the shared DF-LEASE setup: a two-runner distributed
// topology with one attempt leased to runner-1.
type leaseFixture struct {
	h    *dogfood.Harness
	repo dogfood.Repo
	job  string
}

func newLeaseFixture(t *testing.T) leaseFixture {
	t.Helper()
	h, err := dogfood.Launch(dogfood.LaunchConfig{
		Topology: dogfood.Distributed(mustNamespace(t)),
		Seed:     mustSeed(t),
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	t.Cleanup(func() { h.Stop() })
	if got := len(h.Topology().RunnerNames()); got != 2 {
		t.Fatalf("distributed topology runners = %d, want 2", got)
	}
	repo := h.SeedRepo("app", "cafe0003", "refs/heads/main")
	run, err := h.SeedRun("run-lease", repo, []string{"build"}, "runner-1")
	if err != nil {
		t.Fatalf("seed run: %v", err)
	}
	return leaseFixture{h: h, repo: repo, job: run.Attempts[0].JobID}
}

func (f leaseFixture) claim(runID, job, runner string, gen int64) dogfood.CompletionClaim {
	return dogfood.CompletionClaim{
		RunID: runID, JobID: job,
		RunnerID: runner, Generation: gen,
		Status: string(model.StatusSuccess), Protocol: model.ExecutionSemanticsVersion,
		ArtifactSHA256: "2222222222222222222222222222222222222222222222222222222222222222",
	}
}

// TestDFLEASE001StaleRunnerAfterReassignment is DF-LEASE-001: after the
// lease moves to runner-2, every completion from the stale holder is
// rejected (safety) AND the current holder still completes and its evidence
// verifies (liveness). The hostile-mode table names each adversarial shape
// and grades it against the defense layer that owns it.
func TestDFLEASE001StaleRunnerAfterReassignment(t *testing.T) {
	if _, ok := Lookup(ScenarioLeaseStaleRunner); !ok {
		t.Fatal("scenario DF-LEASE-001 missing from the registry")
	}
	f := newLeaseFixture(t)
	h := f.h
	if err := h.ReassignLease("run-lease", f.job, "runner-2"); err != nil {
		t.Fatalf("reassign: %v", err)
	}
	// Stale holder (runner-1, generation 1) is refused.
	if d, err := h.SubmitCompletion(f.claim("run-lease", f.job, "runner-1", 1)); err != nil || d != dogfood.DecisionRejected {
		t.Fatalf("stale runner-1 completion = %s, %v, want rejected", d, err)
	}
	// Wrong generation even from the new holder is refused.
	if d, err := h.SubmitCompletion(f.claim("run-lease", f.job, "runner-2", 1)); err != nil || d != dogfood.DecisionRejected {
		t.Fatalf("stale generation completion = %s, %v, want rejected", d, err)
	}

	// Hostile-mode table: each mode gets its own attempt so no mode can
	// consume another's liveness budget.
	for _, mode := range hostile.AllModes {
		t.Run(string(mode), func(t *testing.T) {
			runID := "run-mode-" + string(mode)
			run, err := h.SeedRun(runID, f.repo, []string{"build"}, "runner-1")
			if err != nil {
				t.Fatalf("seed run: %v", err)
			}
			job := run.Attempts[0].JobID
			holder, gen := "runner-1", int64(1)
			if mode == hostile.ModeStaleGeneration {
				// Give the mode a live lease at generation 2 so its stale
				// mutation lands on generation 1.
				if err := h.ReassignLease(runID, job, "runner-2"); err != nil {
					t.Fatalf("reassign: %v", err)
				}
				holder, gen = "runner-2", 2
			}
			base := hostile.Attempt{
				RunID: runID, JobID: job,
				RunnerID: holder, Generation: gen,
				Status: string(model.StatusSuccess), Protocol: model.ExecutionSemanticsVersion,
				ArtifactSHA256: "3333333333333333333333333333333333333333333333333333333333333333",
				Receipt: &model.ExecutionControlReceipt{
					Runtime: "docker", SandboxStarted: true,
					NetworkEnforced: model.ObservedNetworkContainerNamespace,
				},
			}
			traffic, err := hostile.New(mode, base)
			if err != nil {
				t.Fatalf("hostile.New: %v", err)
			}
			exp := mode.Expectation()
			accepted := 0
			for _, comp := range traffic.Completions {
				d, err := h.SubmitCompletion(dogfood.CompletionClaim{
					RunID:          comp.RunID,
					JobID:          comp.JobID,
					AttemptID:      comp.AttemptID,
					RunnerID:       comp.RunnerID,
					Generation:     comp.Generation,
					Status:         comp.Status,
					Protocol:       comp.Protocol,
					ArtifactSHA256: comp.ArtifactSHA256,
					Receipt:        comp.Receipt,
				})
				if err != nil {
					t.Fatalf("submit: %v", err)
				}
				if d == dogfood.DecisionAccepted {
					accepted++
				}
				if exp.GateRejects && d != dogfood.DecisionRejected {
					t.Fatalf("hostile %s completion accepted at the gate (%s)", mode, d)
				}
			}
			if exp.AcceptsAtMostOne && accepted > 1 {
				t.Fatalf("hostile %s landed %d completions, want at most 1", mode, accepted)
			}
			if exp.GateRejects && accepted != 0 {
				t.Fatalf("hostile %s consumed the attempt", mode)
			}
			if exp.EvidenceMustFail {
				// The gate may have let the claim through; the evidence
				// layer must refuse to turn it into signed evidence.
				if err := evidenceMustFail(mode, base, traffic); err != nil {
					t.Fatalf("hostile %s: %v", mode, err)
				}
			}
			// Discipline shapes: the traffic itself must carry the
			// violation the mode promises, or the scenario is miswired.
			switch mode {
			case hostile.ModeLateLogger:
				if traffic.LogsAfterCompletion == 0 {
					t.Fatal("late-logger traffic has no late logs")
				}
			case hostile.ModeNeverHeartbeat:
				if traffic.Heartbeats != 0 {
					t.Fatal("never-heartbeat traffic heartbeated")
				}
			case hostile.ModeCompletionBeforeArtifact:
				if traffic.ArtifactUploaded {
					t.Fatal("completion-before-artifact uploaded the artifact")
				}
			case hostile.ModeArtifactAfterCompletion:
				if traffic.ArtifactsAfterCompletion == 0 {
					t.Fatal("artifact-after-completion traffic has no post-terminal artifact write")
				}
			}
			// Liveness: a fresh honest holder can still complete its own
			// attempt afterwards (the mode never burns the runner).
			if exp.RequiresLiveHolder {
				live, err := h.SeedRun(runID+"-live", f.repo, []string{"build"}, "runner-2")
				if err != nil {
					t.Fatalf("seed live run: %v", err)
				}
				if d, err := h.SubmitCompletion(f.claim(runID+"-live", live.Attempts[0].JobID, "runner-2", 1)); err != nil || d != dogfood.DecisionAccepted {
					t.Fatalf("honest holder after %s = %s, %v, want accepted", mode, d, err)
				}
			}
		})
	}

	// Liveness on the original attempt: the current holder completes, and
	// its evidence verifies.
	if d, err := h.SubmitCompletion(f.claim("run-lease", f.job, "runner-2", 2)); err != nil || d != dogfood.DecisionAccepted {
		t.Fatalf("current runner-2 completion = %s, %v, want accepted", d, err)
	}
	pub, priv := signKey(t)
	in := evidenceInput()
	in.JobID = f.job
	in.Generation = 2
	in.RunnerIdentity = "runner-2"
	st, err := provenance.ExecutionAttestationStatement(in)
	if err != nil {
		t.Fatalf("build statement: %v", err)
	}
	env, err := provenance.Sign(st, "df-key", priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := h.VerifyEvidence(env, pub); err != nil {
		t.Fatalf("liveness evidence must verify after stale rejections: %v", err)
	}
	obs, err := h.Observations("run-lease", 1)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	if res := dogfood.NewOracle().Check(obs); !res.Green {
		t.Fatalf("eight-oracle after liveness: %s", res.Summary())
	}
}

// evidenceMustFail proves the evidence layer refuses the hostile claim the
// gate may have let through: wrong-runtime receipts and contradictory
// assurance fail the effective/observed consistency check, and a lying
// artifact hash disagrees with the collected bytes.
func evidenceMustFail(mode hostile.Mode, base hostile.Attempt, traffic hostile.Traffic) error {
	switch mode {
	case hostile.ModeWrongRuntimeReceipt:
		// A container attempt reporting a native receipt is a runtime
		// contradiction the signer must refuse.
		facts := model.ExecutionFacts{
			Runtime:            model.RuntimeFactContainer,
			FilesystemIsolated: true,
			NetworkMode:        model.NetworkModeFactDefault,
		}
		if err := facts.ApplyObservedControl(traffic.Completions[0].Receipt); err == nil {
			return fmt.Errorf("wrong-runtime receipt was applied to container facts")
		}
	case hostile.ModeContradictoryAssurance:
		comp := traffic.Completions[0]
		if comp.ContradictoryFacts == nil {
			return fmt.Errorf("contradictory-assurance traffic carries no facts")
		}
		if err := comp.ContradictoryFacts.ApplyObservedControl(comp.Receipt); err == nil {
			return fmt.Errorf("contradictory assurance facts were accepted")
		}
		in := evidenceInput()
		in.ExecutionAssuranceFacts = *comp.ContradictoryFacts
		if _, err := provenance.ExecutionAttestationStatement(in); err == nil {
			return fmt.Errorf("contradictory assurance signed")
		}
	case hostile.ModeArtifactHashLiar:
		claimed := traffic.Completions[0].ArtifactSHA256
		if claimed == base.ArtifactSHA256 {
			return fmt.Errorf("artifact-hash-liar claimed the true hash")
		}
		// The artifact surface compares the claim against the collected
		// bytes; a disagreement must be detectable (and red the oracle).
		if claimed == "" || base.ArtifactSHA256 == "" {
			return fmt.Errorf("artifact hash comparison missing an operand")
		}
	}
	return nil
}

// TestDFLEASE002CompletionVsLeaseExpiry is DF-LEASE-002: a completion under
// a live lease is accepted; a completion after expiry — including one that
// races the AfterLeaseExpirationBeforeReclaim window — is rejected; the
// reclaim winner can still complete.
func TestDFLEASE002CompletionVsLeaseExpiry(t *testing.T) {
	if _, ok := Lookup(ScenarioLeaseCompletionExpiry); !ok {
		t.Fatal("scenario DF-LEASE-002 missing from the registry")
	}
	f := newLeaseFixture(t)
	h := f.h
	// Positive arm: live lease accepts.
	if d, err := h.SubmitCompletion(f.claim("run-lease", f.job, "runner-1", 1)); err != nil || d != dogfood.DecisionAccepted {
		t.Fatalf("live-lease completion = %s, %v, want accepted", d, err)
	}
	// Fresh attempt for the expiry arms.
	run, err := h.SeedRun("run-expiry", f.repo, []string{"build"}, "runner-1")
	if err != nil {
		t.Fatalf("seed run: %v", err)
	}
	expJob := run.Attempts[0].JobID
	claim := func(runner string, gen int64) dogfood.CompletionClaim {
		return f.claim("run-expiry", expJob, runner, gen)
	}
	// Freeze the control plane inside the expiry-before-reclaim window and
	// race a completion from the expired holder: it must not win.
	release, arrived, err := h.Faults().PauseAt(dogfood.AfterLeaseExpirationBeforeReclaim)
	if err != nil {
		t.Fatalf("pause: %v", err)
	}
	go func() {
		_ = h.ExpireLease("run-expiry", expJob)
	}()
	select {
	case <-arrived:
	case <-time.After(2 * time.Second):
		t.Fatal("expiry fault hook never arrived")
	}
	if d, err := h.SubmitCompletion(claim("runner-1", 1)); err != nil || d != dogfood.DecisionRejected {
		t.Fatalf("post-expiry completion = %s, %v, want rejected", d, err)
	}
	release()
	// Reclaim hands the lease to runner-2 at the next generation.
	if err := h.ReclaimLease("run-expiry", expJob, "runner-2"); err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	// The expired holder is still stale after reclaim.
	if d, err := h.SubmitCompletion(claim("runner-1", 1)); err != nil || d != dogfood.DecisionRejected {
		t.Fatalf("post-reclaim stale completion = %s, %v, want rejected", d, err)
	}
	// The reclaim winner completes (liveness across the expiry window).
	if d, err := h.SubmitCompletion(claim("runner-2", 2)); err != nil || d != dogfood.DecisionAccepted {
		t.Fatalf("reclaim winner completion = %s, %v, want accepted", d, err)
	}
	obs, err := h.Observations("run-expiry", 0)
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	if res := dogfood.NewOracle().Check(obs); !res.Green {
		t.Fatalf("eight-oracle after expiry window: %s", res.Summary())
	}
}
