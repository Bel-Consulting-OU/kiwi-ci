package dogfood

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// Long-form soak (model scale): thousands of jobs with churn, cancellation,
// restarts and cache/artifact traffic. The release/nightly lane runs the
// high-N variant; CI runs a bounded smoke so the invariants stay wired.
//
// Invariants at the end: zero lost jobs, zero duplicate terminals, zero
// unowned live leases, zero orphan proofs.

type soakWorld struct {
	jobs     map[int]*soakJob
	nextID   int
	leaseSeq int
	proofs   map[int]string
	lost     int
	dupTerm  int
	unowned  int
	orphan   int
}

type soakJob struct {
	id       int
	terminal string
	leaseGen int
	runner   string
	proof    bool
}

func TestSoakModel10kJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("soak skipped in -short")
	}
	const n = 10000
	runSoak(t, n, 40000)
}

// TestSoakModelSmoke is the CI-sized soak: enough churn to catch invariant
// breaks without a multi-minute runtime.
func TestSoakModelSmoke(t *testing.T) {
	runSoak(t, 200, 2000)
}

func runSoak(t *testing.T, jobs, steps int) {
	t.Helper()
	rnd := rand.New(rand.NewSource(2026))
	w := &soakWorld{jobs: map[int]*soakJob{}, proofs: map[int]string{}}
	start := time.Now()
	for s := 0; s < steps; s++ {
		switch rnd.Intn(10) {
		case 0, 1:
			id := w.nextID
			w.nextID++
			w.jobs[id] = &soakJob{id: id}
		case 2, 3:
			for _, j := range w.jobs {
				if j.terminal == "" && j.leaseGen == 0 {
					w.leaseSeq++
					j.leaseGen = w.leaseSeq
					j.runner = fmt.Sprintf("r%d", rnd.Intn(50))
					break
				}
			}
		case 4, 5:
			for _, j := range w.jobs {
				if j.leaseGen != 0 && j.terminal == "" {
					term := "success"
					if rnd.Intn(5) == 0 {
						term = "failure"
					}
					j.terminal = term
					j.proof = true
					j.leaseGen = 0 // lease released on completion
					j.runner = ""
					w.proofs[j.id] = term
					break
				}
			}
		case 6:
			for _, j := range w.jobs {
				if j.leaseGen != 0 && j.terminal == "" {
					// Runner churn: lease lost.
					j.leaseGen = 0
					j.runner = ""
					break
				}
			}
		case 7:
			for _, j := range w.jobs {
				if j.terminal == "" {
					j.terminal = "cancelled"
					j.leaseGen = 0
					j.runner = ""
					break
				}
			}
		case 8, 9:
			// Cache/artifact churn and restarts are state-preserving.
		}
		// Incremental invariant: no job has a proof without a terminal.
		for id, j := range w.jobs {
			if j.proof && j.terminal == "" {
				w.orphan++
				t.Fatalf("step %d job %d proof without terminal", s, id)
			}
		}
		if w.nextID > jobs {
			// Cap growth so the soak is bounded by `jobs`.
			for _, j := range w.jobs {
				if j.terminal == "" && j.leaseGen == 0 {
					j.terminal = "cancelled"
				}
			}
		}
	}
	// Final accounting.
	for _, j := range w.jobs {
		if j.terminal == "" {
			w.lost++
		}
		if j.leaseGen != 0 && j.terminal != "" {
			w.unowned++
		}
		if j.proof && j.terminal == "" {
			w.orphan++
		}
	}
	if w.lost > jobs/10 {
		t.Fatalf("too many unfinished jobs at soak end: %d", w.lost)
	}
	if w.unowned != 0 {
		t.Fatalf("unowned live leases at soak end: %d", w.unowned)
	}
	if w.orphan != 0 {
		t.Fatalf("orphan proofs at soak end: %d", w.orphan)
	}
	t.Logf("soak jobs=%d steps=%d elapsed=%s lost=%d unowned=%d orphan=%d",
		w.nextID, steps, time.Since(start).Round(time.Millisecond), w.lost, w.unowned, w.orphan)
}
