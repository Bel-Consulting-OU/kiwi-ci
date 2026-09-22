package server

// K4-B invariant under concurrency: the per-poll fs/dev reservation fold
// (runnerReservationSumsLocked) must equal a full re-derivation from the job
// map at every instant, while leases, completions and cancellations race the
// polls. The fold walks each runner's running-job index; this test proves the
// index and the ledger stay exact through the real lease/complete/cancel
// handlers (run with -race: every map access is inside s.mu, and any
// divergence is reported).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// fullRunnerReservationSumsLocked re-derives the reservation ledger from the
// job map (the pre-fix algorithm), for comparison with the folded map.
func fullRunnerReservationSumsLocked(jobs map[string]model.Job) map[string]model.ResourceCapacity {
	sums := map[string]model.ResourceCapacity{}
	for _, j := range jobs {
		if j.Status != model.StatusRunning || j.LeaseRunnerID == "" {
			continue
		}
		sums[j.LeaseRunnerID] = model.AddResourceCapacity(sums[j.LeaseRunnerID], j.ReservedResources())
	}
	return sums
}

func TestMemoryReservationLedgerConcurrentTransitions(t *testing.T) {
	s := New("token")
	now := time.Now().UTC()
	runnerIDs := []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01"}
	for _, id := range runnerIDs {
		s.runners[id] = model.Runner{ID: id, Name: id, Labels: []string{"container"}, Capacity: 8, ResourceCapacity: model.ResourceCapacity{CPU: 8, Memory: 16 << 30}}
	}
	const jobs = 60
	runIDs := make([]string, 0, jobs)
	for i := 0; i < jobs; i++ {
		runID := fmt.Sprintf("run-%04d", i)
		jobID := fmt.Sprintf("job-%04d", i)
		s.runs[runID] = model.Run{ID: runID, Status: model.StatusQueued}
		s.jobs[jobID] = model.Job{
			ID: jobID, RunID: runID, Key: "build", Status: model.StatusQueued, CreatedAt: now,
			CPURequest: 0.25, MemoryRequest: 64 << 20,
		}
		runIDs = append(runIDs, runID)
	}

	stop := make(chan struct{})
	errs := make(chan error, 16)
	report := func(format string, args ...any) {
		select {
		case errs <- fmt.Errorf(format, args...):
		default:
		}
	}
	var leases atomic.Int64
	var completions atomic.Int64
	var wg sync.WaitGroup
	for _, id := range runnerIDs {
		wg.Add(1)
		go func(runnerID string) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
				switch w.Code {
				case http.StatusOK:
					leases.Add(1)
					var task Task
					if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
						report("decode task: %v", err)
						return
					}
					body, _ := json.Marshal(map[string]any{
						"runner_id": runnerID, "lease_token": task.LeaseToken,
						"lease_generation": task.LeaseGeneration, "status": "success",
					})
					cw := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", string(body))
					// A concurrent cancellation legitimately wins the race.
					if cw.Code != http.StatusNoContent && cw.Code != http.StatusConflict {
						report("complete %s = %d %s", task.Job.ID, cw.Code, cw.Body.String())
						return
					}
					if cw.Code == http.StatusNoContent {
						completions.Add(1)
					}
				case http.StatusNoContent:
					// Lease miss: the poll folded the ledger and ran the
					// explainer.
				default:
					report("next %s = %d %s", runnerID, w.Code, w.Body.String())
					return
				}
			}
		}(id)
	}
	// The canceller walks every run once and then ends the workload.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(stop)
		for i, runID := range runIDs {
			if i%2 == 0 {
				cw := doJSON(t, s, http.MethodPost, "/api/v1/runs/"+runID+"/cancel", "token", "")
				if cw.Code != http.StatusOK && cw.Code != http.StatusNoContent {
					report("cancel %s = %d %s", runID, cw.Code, cw.Body.String())
					return
				}
			}
		}
	}()
	// The invariant checker observes every transition under s.mu.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			s.mu.Lock()
			folded := s.runnerReservationSumsLocked()
			full := fullRunnerReservationSumsLocked(s.jobs)
			for id := range s.runners {
				if folded[id] != full[id] {
					s.mu.Unlock()
					report("runner %s: folded ledger %+v, full re-derivation %+v", id, folded[id], full[id])
					return
				}
			}
			for id := range full {
				if _, ok := s.runners[id]; !ok {
					s.mu.Unlock()
					report("running job ledger key %s has no runner row", id)
					return
				}
			}
			s.mu.Unlock()
			runtime.Gosched()
		}
	}()
	wg.Wait()
	select {
	case err := <-errs:
		t.Fatal(err)
	default:
	}
	if leases.Load() == 0 || completions.Load() == 0 {
		t.Fatalf("workload did not exercise lease/release transitions: leases=%d completions=%d", leases.Load(), completions.Load())
	}

	// The final state must still satisfy the invariant, and the workload must
	// have moved real reservations through the fold.
	s.mu.Lock()
	folded := s.runnerReservationSumsLocked()
	full := fullRunnerReservationSumsLocked(s.jobs)
	s.mu.Unlock()
	for id := range full {
		if folded[id] != full[id] {
			t.Fatalf("final runner %s: folded ledger %+v, full re-derivation %+v", id, folded[id], full[id])
		}
	}
}
