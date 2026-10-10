package server

// Coverage round: the DB-mode maintenance tick's promotion/boost arms. A
// wrapper over dbFakeStore implements the optional reconcile, recovery-scan
// and queued-boost contracts with injectable failures, so every leader and
// standby transition of maintainDB is driven deterministically.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// r17Store is a dbFakeStore with the optional storage contracts the
// maintenance tick type-asserts: resource reconciliation, paged recovery
// discovery and queued-boost promotion.
type r17Store struct {
	*dbFakeStore
	reconcileErr   error
	reconcileCalls int
	listExpiredErr error
	recoverErr     error
	boostErr       error
	boostCalls     int
	boosts         []int64
}

func (r *r17Store) ReconcileResourceReservations(context.Context) (storage.ResourceReconcileResult, error) {
	r.reconcileCalls++
	if r.reconcileErr != nil {
		return storage.ResourceReconcileResult{}, r.reconcileErr
	}
	return storage.ResourceReconcileResult{}, nil
}

func (r *r17Store) ListExpiredRunningJobs(context.Context, time.Time, string, int) ([]storage.RecoveryCandidate, error) {
	if r.listExpiredErr != nil {
		return nil, r.listExpiredErr
	}
	return nil, nil
}

func (r *r17Store) ListQueueTimedOutJobs(context.Context, time.Time, string, int) ([]storage.RecoveryCandidate, error) {
	return nil, nil
}

func (r *r17Store) RecoverExpiredLease(context.Context, string, int64, time.Time) error {
	return r.recoverErr
}

func (r *r17Store) PromoteQueuedJobBoosts(context.Context, time.Time, int) (int64, error) {
	r.boostCalls++
	if r.boostErr != nil {
		return 0, r.boostErr
	}
	if len(r.boosts) == 0 {
		return 0, nil
	}
	n := r.boosts[0]
	r.boosts = r.boosts[1:]
	return n, nil
}

func r17Server(t *testing.T, f *r17Store) *Server {
	t.Helper()
	s := New("t")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	// dbFakeStore starts as the accepted leader; every promotion test starts
	// from a standby so maintainDB takes the promotion branch.
	f.setLeader(false)
	s.mu.Lock()
	s.leader = false
	s.mu.Unlock()
	return s
}

// TestMaintainDBPromotionArms drives the promotion path's stale/non-stale
// reconcile and recovery failures plus the schedule-reload failure.
func TestMaintainDBPromotionArms(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("reconcile non-stale error keeps serving", func(t *testing.T) {
		f := &r17Store{dbFakeStore: newDBFakeStore(), reconcileErr: errors.New("ledger down")}
		s := r17Server(t, f)
		f.setLeader(true)
		s.maintainDB(ctx, now)
		if f.reconcileCalls != 1 {
			t.Fatalf("reconcile calls = %d, want 1", f.reconcileCalls)
		}
		s.mu.Lock()
		leader := s.leader
		s.mu.Unlock()
		if !leader {
			t.Fatal("a non-stale reconcile error demoted the leader")
		}
	})

	t.Run("reconcile stale leader demotes", func(t *testing.T) {
		f := &r17Store{dbFakeStore: newDBFakeStore(), reconcileErr: storage.ErrStaleLeader}
		s := r17Server(t, f)
		f.setLeader(true)
		s.maintainDB(ctx, now)
		s.mu.Lock()
		leader := s.leader
		s.mu.Unlock()
		if leader {
			t.Fatal("a stale reconcile fence left the replica leader")
		}
	})

	t.Run("recovery stale leader demotes", func(t *testing.T) {
		f := &r17Store{dbFakeStore: newDBFakeStore(), listExpiredErr: storage.ErrStaleLeader}
		s := r17Server(t, f)
		f.setLeader(true)
		s.maintainDB(ctx, now)
		s.mu.Lock()
		leader := s.leader
		s.mu.Unlock()
		if leader {
			t.Fatal("a stale recovery fence left the replica leader")
		}
	})

	t.Run("schedule reload error keeps the leader", func(t *testing.T) {
		f := &r17Store{dbFakeStore: newDBFakeStore()}
		s := r17Server(t, f)
		f.setLeader(true)
		f.mu.Lock()
		f.listSchedulesErr = errors.New("schedules down")
		f.mu.Unlock()
		s.maintainDB(ctx, now)
		s.mu.Lock()
		leader := s.leader
		s.mu.Unlock()
		if !leader {
			t.Fatal("a schedule reload error demoted the leader")
		}
	})
}

// TestMaintainDBLeaderTickArms drives the established-leader tick's stale
// recovery fence and demotion.
func TestMaintainDBLeaderTickArms(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("stale recovery fence demotes", func(t *testing.T) {
		f := &r17Store{dbFakeStore: newDBFakeStore(), listExpiredErr: storage.ErrStaleLeader}
		s := r17Server(t, f)
		f.setLeader(true)
		s.mu.Lock()
		s.leader = true
		s.mu.Unlock()
		s.maintainDB(ctx, now)
		s.mu.Lock()
		leader := s.leader
		s.mu.Unlock()
		if leader {
			t.Fatal("a stale recovery fence left the established leader in place")
		}
	})

	t.Run("lost leadership demotes", func(t *testing.T) {
		f := &r17Store{dbFakeStore: newDBFakeStore()}
		s := r17Server(t, f)
		f.setLeader(false)
		s.mu.Lock()
		s.leader = true
		s.mu.Unlock()
		s.maintainDB(ctx, now)
		s.mu.Lock()
		leader := s.leader
		s.mu.Unlock()
		if leader {
			t.Fatal("a lost leadership claim left the leader flag set")
		}
	})
}

// TestMaybePromoteQueuedBoostsArms drives the boost sweep: nil DB, a store
// without the promoter contract, the interval gate, the bounded multi-batch
// drain and the promoter failure.
func TestMaybePromoteQueuedBoostsArms(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("nil db", func(t *testing.T) {
		s := New("t")
		s.maybePromoteQueuedBoosts(ctx, now)
	})

	t.Run("no promoter contract", func(t *testing.T) {
		s := r17Server(t, &r17Store{dbFakeStore: newDBFakeStore()})
		s.DB = newDBFakeStore() // dbFakeStore itself has no promoter
		s.maybePromoteQueuedBoosts(ctx, now)
	})

	t.Run("bounded drain then interval gate", func(t *testing.T) {
		f := &r17Store{dbFakeStore: newDBFakeStore(), boosts: []int64{queuedBoostPromoteBatch, 7}}
		s := r17Server(t, f)
		s.maybePromoteQueuedBoosts(ctx, now)
		if f.boostCalls != 2 {
			t.Fatalf("boost calls = %d, want 2 (full batch then short page)", f.boostCalls)
		}
		s.maybePromoteQueuedBoosts(ctx, now.Add(queuedBoostPromoteInterval/2))
		if f.boostCalls != 2 {
			t.Fatalf("boost calls inside the interval = %d, want 2", f.boostCalls)
		}
	})

	t.Run("promoter failure stops the sweep", func(t *testing.T) {
		f := &r17Store{dbFakeStore: newDBFakeStore(), boostErr: errors.New("boost down")}
		s := r17Server(t, f)
		s.maybePromoteQueuedBoosts(ctx, now)
		if f.boostCalls != 1 {
			t.Fatalf("boost calls = %d, want 1", f.boostCalls)
		}
	})
}
