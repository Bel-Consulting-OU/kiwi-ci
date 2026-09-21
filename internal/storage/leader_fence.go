package storage

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
)

// ErrStaleLeader is returned by every leader-fenced store operation when the
// store's retained leadership epoch no longer matches the durable
// leader_fence row (or the store retains none). The operation's transaction is
// aborted and nothing is mutated: the caller is a replica whose cached
// leadership claim outlived the advisory lock (a split-brain window), and a
// new leader has already published a strictly greater epoch.
var ErrStaleLeader = errors.New("storage: stale leader epoch")

// LeaderFenceStore is the leadership-epoch contract behind the fenced
// leader-only operations. The store retains the epoch published by its own
// successful advisory-lock acquisition (TryAcquireLeadership, on the same
// dedicated session, in one transaction) and presents it to every fenced
// operation, which re-validates it against the durable row INSIDE the
// operation's transaction.
//
// SetLeaderEpoch(0) and ClearLeaderEpoch both clear the retained epoch, so
// every subsequent fenced operation fails closed with ErrStaleLeader until a
// fresh acquisition publishes one. ReadLeaderEpoch reads the durable current
// epoch (diagnostics and tests); it does not arm the store.
type LeaderFenceStore interface {
	// SetLeaderEpoch retains epoch as the value this store presents to
	// fenced operations. Non-positive values clear it.
	SetLeaderEpoch(epoch int64)
	// LeaderEpoch returns the retained epoch and whether one is retained.
	LeaderEpoch() (epoch int64, ok bool)
	// ClearLeaderEpoch drops the retained epoch: fenced operations then fail
	// closed until a new acquisition publishes one.
	ClearLeaderEpoch()
	// ReadLeaderEpoch reads the durable current epoch from leader_fence.
	ReadLeaderEpoch(ctx context.Context) (int64, error)
}

// leaderFenceSingletonID is the primary key of the single fence row migration
// 0025 seeds (and CHECK-constrains to exactly this value).
const leaderFenceSingletonID = "singleton"

// assertLeaderEpoch validates epoch against the durable leader_fence row
// INSIDE the caller's transaction. SELECT ... FOR SHARE takes a share lock on
// the singleton row, so a concurrent new leader's epoch-increment UPDATE
// either committed before this read (mismatch: ErrStaleLeader) or blocks
// until this transaction ends — the epoch check and the mutations that follow
// it are serialized against leadership hand-over. A missing row or a
// non-positive epoch is a mismatch (fail closed), never a pass.
func assertLeaderEpoch(ctx context.Context, tx pgx.Tx, epoch int64) error {
	if epoch <= 0 {
		return ErrStaleLeader
	}
	var current int64
	err := tx.QueryRow(ctx, `SELECT epoch FROM leader_fence WHERE id = '`+leaderFenceSingletonID+`' FOR SHARE`).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrStaleLeader
	}
	if err != nil {
		return err
	}
	if current != epoch {
		return ErrStaleLeader
	}
	return nil
}

// SetLeaderEpoch retains epoch (non-positive clears) as the value fenced
// operations present. Acquisition sets it from the published row; loss clears
// it.
func (s *PostgresStore) SetLeaderEpoch(epoch int64) { s.leaderEpoch.Store(epoch) }

// LeaderEpoch returns the retained epoch and whether one is retained.
func (s *PostgresStore) LeaderEpoch() (int64, bool) {
	e := s.leaderEpoch.Load()
	return e, e > 0
}

// ClearLeaderEpoch drops the retained epoch; every fenced operation then
// fails closed with ErrStaleLeader.
func (s *PostgresStore) ClearLeaderEpoch() { s.leaderEpoch.Store(0) }

// ReadLeaderEpoch reads the durable current epoch (leader_fence). It is a
// plain read and never arms the store: presenting an epoch is exclusively the
// acquisition path's job.
func (s *PostgresStore) ReadLeaderEpoch(ctx context.Context) (int64, error) {
	var epoch int64
	if err := s.pool.QueryRow(ctx, `SELECT epoch FROM leader_fence WHERE id = '`+leaderFenceSingletonID+`'`).Scan(&epoch); err != nil {
		return 0, err
	}
	return epoch, nil
}

// fenceLeaderTx validates the store's retained epoch inside tx. A mismatch
// clears the retained epoch (compare-and-swap, so a concurrent successful
// acquisition's fresh epoch is never clobbered): the proof is provably dead,
// and later fenced operations must fail fast rather than re-query a fence
// they cannot match. Errors other than ErrStaleLeader (a read failure) leave
// the retained epoch alone — they are not proof of anything.
func (s *PostgresStore) fenceLeaderTx(ctx context.Context, tx pgx.Tx) error {
	epoch, ok := s.LeaderEpoch()
	if !ok {
		return ErrStaleLeader
	}
	err := assertLeaderEpoch(ctx, tx, epoch)
	if errors.Is(err, ErrStaleLeader) {
		s.leaderEpoch.CompareAndSwap(epoch, 0)
	}
	return err
}

// beginFencedTx opens an operational transaction and fences it: the retained
// epoch must still match the durable one before any mutation in tx runs. The
// pool error keeps its own error contract (a closed/exhausted pool fails at
// Begin, exactly as before fencing); a fence failure rolls the transaction
// back and returns ErrStaleLeader with nothing mutated.
func (s *PostgresStore) beginFencedTx(ctx context.Context) (pgx.Tx, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.fenceLeaderTx(ctx, tx); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return tx, nil
}

// publishLeaderEpoch advances the durable leadership epoch on conn — THE SAME
// dedicated session that just took the leadership advisory lock — and returns
// the new value. Running the increment in a transaction on that session is
// the atomicity contract: if the connection dies before commit the increment
// is rolled back with it, no epoch is published, and the advisory lock died
// with the same session, so no other replica can be misled into thinking a
// leader exists that never published. The epoch is strictly monotonic
// (epoch + 1 under the row lock); it is never decremented, on release or
// anywhere else.
func (s *PostgresStore) publishLeaderEpoch(ctx context.Context, conn *pgx.Conn) (int64, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var epoch int64
	if err := tx.QueryRow(ctx, `INSERT INTO leader_fence (id, epoch, holder, updated_at)
		VALUES ('`+leaderFenceSingletonID+`', 1, $1, now())
		ON CONFLICT (id) DO UPDATE
			SET epoch = leader_fence.epoch + 1, holder = EXCLUDED.holder, updated_at = now()
		RETURNING epoch`, leaderHolderIdentity()).Scan(&epoch); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return epoch, nil
}

// leaderHolderIdentity is a best-effort human-readable holder label
// (host:pid) for the fence row. It is advisory metadata only: never compared,
// never a correctness input, and an empty value is harmless.
func leaderHolderIdentity() string {
	host, err := os.Hostname()
	if err != nil {
		host = ""
	}
	return fmt.Sprintf("%s:%d", host, os.Getpid())
}
