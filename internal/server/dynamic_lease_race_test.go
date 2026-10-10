package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// fragmentLeaseRaceStore loses the parent lease exactly when the insertion
// transaction begins: the handler's request gate already authorized the live
// lease, so this reproduces the in-transaction race the commit-time predicate
// must map to the stale-lease 409 (previously the generic validator mapped it
// to 400).
type fragmentLeaseRaceStore struct {
	*dbFakeStore
	fired bool
}

func (f *fragmentLeaseRaceStore) InsertGeneratedFragmentTx(ctx context.Context, req storage.GeneratedFragmentRequest, verify storage.GeneratedJobVerifier) (storage.GeneratedFragmentReceipt, bool, error) {
	if !f.fired {
		f.fired = true
		f.mu.Lock()
		j := f.jobs[req.ParentJobID]
		j.LeaseGeneration++
		f.jobs[req.ParentJobID] = j
		f.mu.Unlock()
	}
	return f.dbFakeStore.InsertGeneratedFragmentTx(ctx, req, verify)
}

// TestGeneratedFragmentRacedLeaseLossMaps409Not400: a lease that is live at
// the request gate but superseded before the fragment transaction commits is
// a stale-lease refusal (409) with the fragment committed nowhere — never a
// 400 validation error.
func TestGeneratedFragmentRacedLeaseLossMaps409Not400(t *testing.T) {
	f := newDBFakeStore()
	s := trustedGenerateServerDB(t, f)
	runnerID, task := leaseRunJob(t, s)
	race := &fragmentLeaseRaceStore{dbFakeStore: f}
	s.DB = race
	path := "/api/v1/jobs/" + task.Job.ID + "/generated"
	w := doJSONHeaders(t, s, http.MethodPost, path, "token", fragmentBody(t, replayFragmentA), leaseHeaders(task, runnerID))
	if w.Code != http.StatusConflict {
		t.Fatalf("raced fragment = %d, want 409: %s", w.Code, w.Body.String())
	}
	if !race.fired {
		t.Fatal("race hook never ran: the request did not reach the insertion transaction")
	}
	// Nothing was inserted and no slot receipt was committed.
	f.mu.Lock()
	children := 0
	for _, j := range f.jobs {
		if j.RunID == task.Job.RunID && j.ID != task.Job.ID {
			children++
		}
	}
	fragments := len(f.fragments)
	f.mu.Unlock()
	if children != 0 || fragments != 0 {
		t.Fatalf("raced fragment left state: children=%d fragments=%d", children, fragments)
	}
}
