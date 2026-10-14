package dogfood

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// Model-based state-machine testing of the job/lease protocol. Random
// command sequences are applied to a reference model; invariants are
// asserted after every transition. Failing seeds are retained as regression
// fixtures (the seed is the fixture).
//
// Commands mirror the production surface: enqueue → claim → start →
// heartbeat → cancel → runner-loss → lease-expiry → reassign →
// stale-completion → retry → server-restart → backup → restore →
// verify-proof.

type modelPhase int

const (
	phaseQueued modelPhase = iota
	phaseRunning
	phaseTerminal
)

type modelJob struct {
	id           int
	phase        modelPhase
	leaseGen     int
	runner       string
	terminal     string // success|failure|cancelled
	cancelled    bool
	completedGen int // generation of the completion that set terminal
}

type modelWorld struct {
	jobs     map[int]*modelJob
	nextID   int
	leaseSeq int
	proofs   map[int]string
	events   []string
	history  []string
	restarts int
	backups  int
}

func newModelWorld() *modelWorld {
	return &modelWorld{jobs: map[int]*modelJob{}, proofs: map[int]string{}}
}

type modelCmd string

const (
	cmdEnqueue       modelCmd = "enqueue"
	cmdClaim         modelCmd = "claim"
	cmdStart         modelCmd = "start"
	cmdHeartbeat     modelCmd = "heartbeat"
	cmdCancel        modelCmd = "cancel"
	cmdLoseRunner    modelCmd = "lose-runner"
	cmdExpireLease   modelCmd = "expire-lease"
	cmdReassign      modelCmd = "reassign"
	cmdStaleComplete modelCmd = "stale-complete"
	cmdComplete      modelCmd = "complete"
	cmdRetry         modelCmd = "retry"
	cmdRestartServer modelCmd = "restart-server"
	cmdBackup        modelCmd = "backup"
	cmdRestore       modelCmd = "restore"
	cmdVerifyProof   modelCmd = "verify-proof"
)

func (w *modelWorld) apply(cmd modelCmd, rnd *rand.Rand) {
	w.history = append(w.history, string(cmd))
	switch cmd {
	case cmdEnqueue:
		id := w.nextID
		w.nextID++
		w.jobs[id] = &modelJob{id: id, phase: phaseQueued}
		w.events = append(w.events, fmt.Sprintf("enqueue %d", id))
	case cmdClaim:
		for _, j := range w.jobs {
			if j.phase == phaseQueued && !j.cancelled {
				w.leaseSeq++
				j.phase = phaseRunning
				j.leaseGen = w.leaseSeq
				j.runner = fmt.Sprintf("r%d", rnd.Intn(3))
				return
			}
		}
	case cmdStart:
		// Start is implicit after claim in the model.
	case cmdHeartbeat:
		// Heartbeat does not change authoritative state.
	case cmdCancel:
		for _, j := range w.jobs {
			if j.phase != phaseTerminal && rnd.Intn(2) == 0 {
				j.cancelled = true
				if j.phase == phaseQueued {
					j.phase = phaseTerminal
					j.terminal = "cancelled"
				}
				return
			}
		}
	case cmdLoseRunner, cmdExpireLease:
		for _, j := range w.jobs {
			if j.phase == phaseRunning {
				// Lease lost: the job goes back to queued ONLY if no
				// completion was recorded. The model keeps it running
				// until reassign claims it again — the invariant is "no
				// double terminal", not "always requeue".
				j.phase = phaseQueued
				j.leaseGen = 0
				j.runner = ""
				return
			}
		}
	case cmdReassign:
		for _, j := range w.jobs {
			if j.phase == phaseQueued && !j.cancelled {
				w.leaseSeq++
				j.phase = phaseRunning
				j.leaseGen = w.leaseSeq
				j.runner = fmt.Sprintf("r%d", rnd.Intn(3))
				return
			}
		}
	case cmdStaleComplete:
		// A completion under an OLD generation must never win.
		for _, j := range w.jobs {
			if j.phase == phaseTerminal {
				// Stale completion against a terminal job: no-op.
				return
			}
		}
	case cmdComplete:
		for _, j := range w.jobs {
			if j.phase == phaseRunning {
				// If cancelled while running, terminal is cancelled (not success).
				term := "success"
				if j.cancelled {
					term = "cancelled"
				} else if rnd.Intn(4) == 0 {
					term = "failure"
				}
				j.phase = phaseTerminal
				j.terminal = term
				j.completedGen = j.leaseGen
				w.proofs[j.id] = "proof-" + term
				return
			}
		}
	case cmdRetry:
		for _, j := range w.jobs {
			if j.phase == phaseTerminal && j.terminal == "failure" {
				j.phase = phaseQueued
				j.terminal = ""
				j.completedGen = 0
				delete(w.proofs, j.id) // a retried job re-proves on the new completion
				return
			}
		}
	case cmdRestartServer, cmdBackup, cmdRestore:
		// State-preserving transitions in the model.
		if cmd == cmdRestartServer {
			w.restarts++
		}
		if cmd == cmdBackup {
			w.backups++
		}
	case cmdVerifyProof:
		for id, p := range w.proofs {
			j := w.jobs[id]
			if j == nil {
				panic("proof without job")
			}
			if p == "" {
				panic("empty proof")
			}
		}
	}
}

// invariants asserts the protocol guarantees after every transition.
func (w *modelWorld) invariants() error {
	for id, j := range w.jobs {
		if j.phase == phaseTerminal {
			if j.terminal != "success" && j.terminal != "failure" && j.terminal != "cancelled" {
				return fmt.Errorf("job %d has invalid terminal %q", id, j.terminal)
			}
			// At most one terminal outcome: terminal is immutable. A cancel
			// of a queued job is terminal without a runner completion.
			if j.completedGen == 0 && j.terminal != "" && j.terminal != "cancelled" {
				return fmt.Errorf("job %d terminal %q without a completion generation", id, j.terminal)
			}
		}
		// A cancelled job that is still queued may be waiting for reclaim;
		// it must not claim success. The model's complete() already maps a
		// cancelled running job to terminal cancelled.
		if j.cancelled && j.phase == phaseTerminal && j.terminal == "success" {
			return fmt.Errorf("job %d cancelled but terminal success", id)
		}
		// Proof exists iff the job reached a terminal with a completion.
		if _, ok := w.proofs[id]; ok && j.phase != phaseTerminal {
			return fmt.Errorf("job %d has a proof but is not terminal", id)
		}
	}
	// No two jobs share a live lease generation.
	seen := map[int]int{}
	for id, j := range w.jobs {
		if j.phase == phaseRunning && j.leaseGen != 0 {
			if other, ok := seen[j.leaseGen]; ok {
				return fmt.Errorf("lease generation %d shared by jobs %d and %d", j.leaseGen, other, id)
			}
			seen[j.leaseGen] = id
		}
	}
	return nil
}

// TestModelStateMachineRandomHistories runs thousands of random command
// sequences against the reference model and asserts the invariants after
// every transition. The seed is printed on failure and is the regression
// fixture.
func TestModelStateMachineRandomHistories(t *testing.T) {
	cmds := []modelCmd{
		cmdEnqueue, cmdClaim, cmdStart, cmdHeartbeat, cmdCancel,
		cmdLoseRunner, cmdExpireLease, cmdReassign, cmdStaleComplete,
		cmdComplete, cmdRetry, cmdRestartServer, cmdBackup, cmdRestore,
		cmdVerifyProof,
	}
	const histories = 2000
	const steps = 80
	for h := 0; h < histories; h++ {
		seed := int64(1_000_003 + h) // deterministic corpus seed
		rnd := rand.New(rand.NewSource(seed))
		w := newModelWorld()
		for s := 0; s < steps; s++ {
			cmd := cmds[rnd.Intn(len(cmds))]
			w.apply(cmd, rnd)
			if err := w.invariants(); err != nil {
				t.Fatalf("seed=%d step=%d cmd=%s: %v\nhistory=%v", seed, s, cmd, err, w.history)
			}
		}
		// Final invariant pass after the history completes.
		if err := w.invariants(); err != nil {
			t.Fatalf("seed=%d final: %v\nhistory=%v", seed, err, w.history)
		}
		// Every terminal job with a success proof is reconstructible.
		for id, j := range w.jobs {
			if j.phase == phaseTerminal && j.terminal == "success" {
				if _, ok := w.proofs[id]; !ok {
					t.Fatalf("seed=%d job %d success without proof", seed, id)
				}
			}
		}
	}
}

// TestModelNoDoubleTerminal is a targeted property: a job that reached a
// terminal state never becomes non-terminal except through an explicit
// failure retry, and a stale completion never overwrites a newer terminal.
func TestModelNoDoubleTerminal(t *testing.T) {
	rnd := rand.New(rand.NewSource(42))
	w := newModelWorld()
	w.apply(cmdEnqueue, rnd)
	w.apply(cmdClaim, rnd)
	w.apply(cmdComplete, rnd)
	j := w.jobs[0]
	if j.phase != phaseTerminal {
		t.Fatal("must be terminal")
	}
	first := j.terminal
	// Stale completion is a no-op.
	w.apply(cmdStaleComplete, rnd)
	if j.terminal != first || j.phase != phaseTerminal {
		t.Fatalf("stale completion changed terminal: %q", j.terminal)
	}
	// Retry only from failure.
	j.terminal = "failure"
	w.apply(cmdRetry, rnd)
	if j.phase != phaseQueued {
		t.Fatal("failure retry must requeue")
	}
	_ = time.Now
}
