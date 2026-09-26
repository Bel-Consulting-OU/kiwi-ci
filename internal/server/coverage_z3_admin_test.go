package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestRestoreCompletionReceiptsPrunesSortsAndCaps pins the restart-time
// receipt rebuild: records without a job id or past the TTL are dropped, the
// survivors are ordered newest-first with a deterministic identity tie-break,
// and the table is trimmed to the hard cap.
func TestRestoreCompletionReceiptsPrunesSortsAndCaps(t *testing.T) {
	s := NewPersistentServerForTest(t)
	now := time.Now().UTC()
	expired := now.Add(-storage.CompletionReceiptTTL - time.Hour)
	rec := func(jobID, runnerID string, generation int64, at time.Time) storage.CompletionReceiptRecord {
		return storage.CompletionReceiptRecord{
			Receipt:   model.CompletionReceipt{JobID: jobID, Generation: generation, RunnerID: runnerID},
			CreatedAt: at,
		}
	}

	records := []storage.CompletionReceiptRecord{
		rec("", "r", 1, now),            // no job id: dropped
		rec("expired", "r", 1, expired), // past the TTL: dropped
		rec("zero", "r", 1, time.Time{}),
		rec("dup", "a", 1, now.Add(-time.Minute)),
		rec("dup", "a", 2, now.Add(-time.Minute)),
		rec("dup", "b", 2, now.Add(-time.Minute)),
		rec("fresh", "r", 1, now),
	}
	// Fill past the cap with equal timestamps so the trim and the identity
	// tie-break decide the survivors deterministically.
	for i := 0; len(records) < storage.MaxCompletionReceipts+8; i++ {
		records = append(records, rec(fmt.Sprintf("fill-%06d", i), "r", 1, now.Add(-time.Minute)))
	}
	s.restoreCompletionReceiptsLocked(records)

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.completions) != storage.MaxCompletionReceipts {
		t.Fatalf("restored receipts = %d, want the %d cap", len(s.completions), storage.MaxCompletionReceipts)
	}
	if _, ok := s.completions[completionReceiptKey("", 1, "r")]; ok {
		t.Fatal("record without a job id survived restore")
	}
	if _, ok := s.completions[completionReceiptKey("expired", 1, "r")]; ok {
		t.Fatal("expired record survived restore")
	}
	if _, ok := s.completions[completionReceiptKey("fresh", 1, "r")]; !ok {
		t.Fatal("newest record was trimmed")
	}
	if _, ok := s.completions[completionReceiptKey("zero", 1, "r")]; ok {
		t.Fatal("timestamp-less record outranked timestamped records")
	}

	// The empty snapshots and the zero-length call are no-ops.
	s2 := NewPersistentServerForTest(t)
	s2.restoreCompletionReceiptsLocked(nil)
	s2.mu.Lock()
	empty := len(s2.completions)
	s2.mu.Unlock()
	if empty != 0 {
		t.Fatalf("empty restore inserted %d receipts", empty)
	}
}

// disableNotFoundStore reports the runner as vanished from the atomic disable
// transaction after the handler's read succeeded, pinning the 404 mapping.
type disableNotFoundStore struct {
	*dbFakeStore
}

func (disableNotFoundStore) DisableRunnerAndRevokeCert(ctx context.Context, runnerID, certSerial, actor string) (int, error) {
	return 0, storage.ErrNotFound
}

// TestApproveJobFailureBranches covers the approval handler's refusals: a
// missing job is 404, a store without the transactional approval contract is
// 503, a job that does not need approval or is already terminal is 409, and a
// waiting job approves durably through the store.
func TestApproveJobFailureBranches(t *testing.T) {
	mem, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, mem, http.MethodPost, "/api/v1/jobs/missing/approve", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("memory approve of a missing job = %d, want 404: %s", w.Code, w.Body.String())
	}

	s, f, _, _ := cacheFixture(t)
	s.DB = fcPlainStore{f}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/job-a/approve", "admin-tok", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("approve without the transactional store = %d, want 503: %s", w.Code, w.Body.String())
	}

	s2, _, _, _ := cacheFixture(t)
	if w := doJSON(t, s2, http.MethodPost, "/api/v1/jobs/job-a/approve", "admin-tok", ""); w.Code != http.StatusConflict {
		t.Fatalf("approve of a non-gated job = %d, want 409: %s", w.Code, w.Body.String())
	}

	s3, f3, _, _ := cacheFixture(t)
	f3.mu.Lock()
	terminal := f3.jobs["job-a"]
	terminal.ApprovalRequired = true
	terminal.Status = model.StatusSuccess
	f3.jobs["job-a"] = terminal
	f3.mu.Unlock()
	if w := doJSON(t, s3, http.MethodPost, "/api/v1/jobs/job-a/approve", "admin-tok", ""); w.Code != http.StatusConflict {
		t.Fatalf("approve of a terminal job = %d, want 409: %s", w.Code, w.Body.String())
	}

	s4, f4, _, _ := cacheFixture(t)
	f4.mu.Lock()
	waiting := f4.jobs["job-a"]
	waiting.ApprovalRequired = true
	waiting.Status = model.StatusWaitingApproval
	since := time.Now().UTC().Add(-time.Minute)
	waiting.WaitingSince = &since
	f4.jobs["job-a"] = waiting
	f4.mu.Unlock()
	if w := doJSON(t, s4, http.MethodPost, "/api/v1/jobs/job-a/approve", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("approve of a waiting job = %d, want 200: %s", w.Code, w.Body.String())
	}
	f4.mu.Lock()
	approved := f4.jobs["job-a"]
	f4.mu.Unlock()
	if approved.ApprovedBy == "" || approved.Status != model.StatusQueued || approved.WaitingSince != nil {
		t.Fatalf("approved job = %+v, want actor/queued/cleared wait marker", approved)
	}
}

// TestRunnerAdminFailureBranches covers the admin runner endpoints'
// fail-closed refusals: an unwritable audit row blocks drain/enable/disable,
// a store without the atomic disable contract is refused, a vanished runner
// inside the disable transaction is 404, and the memory-mode disable installs
// the local CRL entry for a serial-bearing runner.
func TestRunnerAdminFailureBranches(t *testing.T) {
	t.Run("drain audit failure", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		f.mu.Lock()
		f.runners["r-drain"] = model.Runner{ID: "r-drain", Name: "r-drain", Capacity: 1}
		f.mu.Unlock()
		s.DB = &fcStore{dbFakeStore: f, appendAuditErr: errors.New("audit down")}
		if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r-drain/drain", "admin-tok", ""); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("drain with a failing audit sink = %d, want 503: %s", w.Code, w.Body.String())
		}
	})
	t.Run("enable audit failure", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		f.mu.Lock()
		f.runners["r-enable"] = model.Runner{ID: "r-enable", Name: "r-enable", Capacity: 1, Disabled: true}
		f.mu.Unlock()
		s.DB = &fcStore{dbFakeStore: f, appendAuditErr: errors.New("audit down")}
		if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r-enable/enable", "admin-tok", ""); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("enable with a failing audit sink = %d, want 503: %s", w.Code, w.Body.String())
		}
	})
	t.Run("disable without the atomic store", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		f.mu.Lock()
		f.runners["r-plain"] = model.Runner{ID: "r-plain", Name: "r-plain", Capacity: 1}
		f.mu.Unlock()
		s.DB = fcPlainStore{f}
		if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r-plain/disable", "admin-tok", ""); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("disable without the atomic store = %d, want 503: %s", w.Code, w.Body.String())
		}
	})
	t.Run("disable sees a vanished runner", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		f.mu.Lock()
		f.runners["r-gone"] = model.Runner{ID: "r-gone", Name: "r-gone", Capacity: 1}
		f.mu.Unlock()
		s.DB = disableNotFoundStore{dbFakeStore: f}
		if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r-gone/disable", "admin-tok", ""); w.Code != http.StatusNotFound {
			t.Fatalf("disable of a vanished runner = %d, want 404: %s", w.Code, w.Body.String())
		}
	})
	t.Run("memory disable installs the CRL entry", func(t *testing.T) {
		s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		s.runners["r-crl"] = model.Runner{ID: "r-crl", Name: "r-crl", Capacity: 1, CertSerial: "serial-1"}
		s.crl = nil
		s.mu.Unlock()
		if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r-crl/disable", "admin-tok", ""); w.Code != http.StatusOK {
			t.Fatalf("memory disable = %d, want 200: %s", w.Code, w.Body.String())
		}
		s.mu.Lock()
		owner, ok := s.crl["serial-1"]
		s.mu.Unlock()
		if !ok || owner != "r-crl" {
			t.Fatalf("local CRL entry = (%q, %v), want r-crl", owner, ok)
		}
	})
}

// TestWriteRunnerProfileDBLegacyFallbackPreservesLeaseFields pins the legacy
// store contract: without the guarded profile-update extension, the write
// carries forward the lease-owned fields of the row that was just read and
// re-derives the busy flag, so a stale read can never drop a reserved slot.
func TestWriteRunnerProfileDBLegacyFallbackPreservesLeaseFields(t *testing.T) {
	f := newDBFakeStore()
	s := New("tok")
	s.DB = fcPlainStore{f}
	old := model.Runner{ID: "r1", Name: "r1", Capacity: 1, ActiveJobs: []string{"j1"}, CurrentJob: "j1", Completed: 2, Failed: 1}
	profile := model.Runner{ID: "r1", Name: "r1", Capacity: 1, Draining: true}
	if err := s.writeRunnerProfileDB(context.Background(), profile, old, false); err != nil {
		t.Fatalf("legacy profile write: %v", err)
	}
	f.mu.Lock()
	stored, ok := f.runners["r1"]
	f.mu.Unlock()
	if !ok {
		t.Fatal("legacy profile write stored nothing")
	}
	if !stored.Draining || len(stored.ActiveJobs) != 1 || stored.ActiveJobs[0] != "j1" || stored.CurrentJob != "j1" || stored.Completed != 2 || stored.Failed != 1 || !stored.Busy {
		t.Fatalf("legacy profile write = %+v, want the lease-owned fields preserved and busy re-derived", stored)
	}
}

// TestRollbackCompletionLockedRestoresAllMirrors proves the completion
// rollback puts every mirror back exactly: job/run maps, the receipt table
// (including an evicted entry), the deployment mirror and the runner slot,
// and that the absence markers delete instead of resurrecting rows.
func TestRollbackCompletionLockedRestoresAllMirrors(t *testing.T) {
	s := New("tok")
	now := time.Now().UTC()

	rb := completionRollback{
		jobs:          map[string]model.Job{"j1": {ID: "j1", Status: model.StatusRunning}},
		runs:          map[string]model.Run{"run1": {ID: "run1", Status: model.StatusRunning}},
		jobID:         "j1",
		receiptKey:    "k1",
		receipt:       model.CompletionReceipt{JobID: "j1", RunnerID: "r1"},
		receiptAt:     now,
		hadReceipt:    true,
		evictedKey:    "k2",
		evicted:       model.CompletionReceipt{JobID: "j2", RunnerID: "r2"},
		evictedAt:     now,
		deployment:    model.Deployment{ID: "d1", JobID: "j1"},
		hadDeployment: true,
		runnerID:      "r1",
		runner:        model.Runner{ID: "r1", Capacity: 1},
		hadRunner:     true,
	}
	s.mu.Lock()
	s.rollbackCompletionLocked(rb)
	s.mu.Unlock()
	s.mu.Lock()
	_, jobOK := s.jobs["j1"]
	_, runOK := s.runs["run1"]
	got, receiptOK := s.completions["k1"]
	_, evictedOK := s.completions["k2"]
	dep, depOK := s.deployments["j1"]
	runner, runnerOK := s.runners["r1"]
	s.mu.Unlock()
	if !jobOK || !runOK || !receiptOK || got.RunnerID != "r1" || !evictedOK || !depOK || dep.ID != "d1" || !runnerOK || runner.ID != "r1" {
		t.Fatalf("rollback state = job=%v run=%v receipt=%v evicted=%v dep=%v runner=%v", jobOK, runOK, receiptOK, evictedOK, depOK, runnerOK)
	}

	// The absence markers delete the rows the failed attempt inserted.
	s.mu.Lock()
	s.jobs["j1"] = model.Job{ID: "j1"}
	s.runs["run1"] = model.Run{ID: "run1"}
	s.completions["k1"] = model.CompletionReceipt{JobID: "j1"}
	s.deployments["j1"] = model.Deployment{ID: "d1"}
	s.runners["r1"] = model.Runner{ID: "r1"}
	s.mu.Unlock()
	rb2 := completionRollback{
		jobs:       map[string]model.Job{},
		runs:       map[string]model.Run{},
		jobID:      "j1",
		receiptKey: "k1",
		runnerID:   "r1",
	}
	s.mu.Lock()
	s.rollbackCompletionLocked(rb2)
	s.mu.Unlock()
	s.mu.Lock()
	_, jobOK = s.jobs["j1"]
	_, runOK = s.runs["run1"]
	_, receiptOK = s.completions["k1"]
	_, depOK = s.deployments["j1"]
	_, runnerOK = s.runners["r1"]
	s.mu.Unlock()
	if jobOK || runOK || receiptOK || depOK || runnerOK {
		t.Fatalf("rollback with absence markers left state: job=%v run=%v receipt=%v dep=%v runner=%v", jobOK, runOK, receiptOK, depOK, runnerOK)
	}
}
