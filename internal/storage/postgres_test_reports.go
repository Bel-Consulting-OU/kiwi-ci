package storage

// Durable, idempotent test-report delivery (migration 0029).
//
// InsertTestReportWithHistory folds one report's cases into the repository's
// aggregates in ONE transaction, but it is keyed only by the report ID the
// server minted for the request. A runner whose request committed and whose
// response was lost has no way to replay without inserting a second report
// and folding its cases a second time. TestReportDeliveryStore closes that
// gap: the caller supplies the stable delivery identity of the upload — for
// runners that send one, the ID derived from the payload (job, lease
// generation, delivery ID); for legacy clients that send none, the
// server-synthesized deterministic identity (see
// internal/server/testintel.go, synthesizedReportDeliveryID) — plus the
// digest of the bytes it received; the store records that receipt and the
// report in the same transaction, so:
//
//   - a first delivery inserts the report, folds its cases once and bumps the
//     repository version;
//   - a replay of the SAME (delivery ID, content digest) is an idempotent
//     success that returns the originally committed report ID and changes
//     nothing else — no duplicate report, no re-fold;
//   - the same delivery ID with a DIFFERENT content digest is
//     ErrTestReportDeliveryConflict and leaves history untouched.
//
// The delivery receipt is written by the same transaction as the report and
// the fold, so a failure anywhere commits neither. Delivery rows are
// retained; test_report_deliveries_created_at_idx supports future pruning.
//
// Callers that own the delivery policy (the server) must never fall back to
// the non-idempotent entry points: a store that does not implement this
// contract cannot deduplicate a replay and must be refused. The empty-ID
// branch below exists only for InsertTestReportWithHistory, the legacy
// store-internal repair/import path; it is not a production upload path.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestReportDelivery is the stable identity of one report upload attempt.
// DeliveryID is opaque and client-supplied (the runner derives it from the
// job, lease generation and payload digest); ContentDigest is the
// server-computed hex digest of the report payload bytes actually received.
type TestReportDelivery struct {
	JobID           string
	LeaseGeneration int64
	DeliveryID      string
	ContentDigest   string
}

// TestReportInsertOutcome reports what one delivery did. Replay is true when
// the identical (delivery ID, content digest) had already committed: the
// stored ReportID is the original report and nothing was inserted or folded.
type TestReportInsertOutcome struct {
	Version  int64
	Replay   bool
	ReportID string
}

// ErrTestReportDeliveryConflict reports a delivery ID reused with a different
// payload digest. The conflicting upload is rejected and the repository's
// report rows and aggregates are untouched.
var ErrTestReportDeliveryConflict = errors.New("storage: test report delivery id reused with different content")

// TestReportDeliveryStore is the idempotent, delivery-keyed form of the
// incremental report upload. The in-memory and PostgreSQL stores implement
// it; callers that only hold TestHistoryAggregateStore keep the legacy
// (non-idempotent) contract.
type TestReportDeliveryStore interface {
	InsertTestReportWithHistoryDelivery(ctx context.Context, rep model.TestReport, repoID string, delivery TestReportDelivery) (TestReportInsertOutcome, error)
}

var _ TestReportDeliveryStore = (*PostgresStore)(nil)

// InsertTestReportWithHistoryDelivery is InsertTestReportWithHistory plus the
// durable delivery receipt: the report rows, the case rows, the aggregate
// fold and the (job, generation, delivery ID) receipt commit together. A
// non-empty delivery ID claims the receipt first; a replay of a committed
// receipt returns the original report ID without touching the transaction's
// other work. Empty delivery IDs (legacy callers) skip the receipt and
// behave exactly like InsertTestReportWithHistory.
func (s *PostgresStore) InsertTestReportWithHistoryDelivery(ctx context.Context, rep model.TestReport, repoID string, delivery TestReportDelivery) (TestReportInsertOutcome, error) {
	if err := ValidateID(rep.ID); err != nil {
		return TestReportInsertOutcome{}, err
	}
	if err := ValidateRunID(rep.RunID); err != nil {
		return TestReportInsertOutcome{}, err
	}
	if strings.TrimSpace(repoID) == "" {
		return TestReportInsertOutcome{}, fmt.Errorf("storage: test history repository identity is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return TestReportInsertOutcome{}, err
	}
	defer tx.Rollback(ctx)
	if delivery.DeliveryID != "" {
		claimed, existingID, err := claimTestReportDeliveryTx(ctx, tx, delivery, rep.ID)
		if err != nil {
			return TestReportInsertOutcome{}, err
		}
		if !claimed {
			// The identical delivery already committed: return its original
			// report ID and commit nothing (the rollback is a no-op).
			return TestReportInsertOutcome{Replay: true, ReportID: existingID}, nil
		}
	}
	version, err := lockTestHistoryRepoTx(ctx, tx, repoID)
	if err != nil {
		return TestReportInsertOutcome{}, err
	}
	if err := insertTestReportRowsTx(ctx, tx, rep); err != nil {
		return TestReportInsertOutcome{}, err
	}
	// Fold the new report in (created_at,id) order, rebuilding the repository
	// when the new report is not its canonical newest. The rebuild folds the
	// report too (it reads every durable report for the repository), so the
	// two branches are mutually exclusive and the resulting aggregates always
	// equal a rebuild.
	if err := foldOrRebuildTestReportTx(ctx, tx, repoID, version, rep); err != nil {
		return TestReportInsertOutcome{}, err
	}
	version, err = bumpTestHistoryVersionTx(ctx, tx, repoID)
	if err != nil {
		return TestReportInsertOutcome{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TestReportInsertOutcome{}, err
	}
	return TestReportInsertOutcome{Version: version, ReportID: rep.ID}, nil
}

// claimTestReportDeliveryTx attempts to claim one delivery receipt inside the
// caller's transaction. It reports claimed=true when this transaction owns
// the receipt (the report insert must follow), and claimed=false with the
// originally committed report ID when the IDENTICAL delivery had already
// committed. A reused delivery ID whose stored digest differs is
// ErrTestReportDeliveryConflict. The insert's ON CONFLICT DO NOTHING waits
// for a concurrent same-identity transaction, so two racing duplicates
// serialize on the primary key: exactly one claims, the other observes the
// committed receipt.
func claimTestReportDeliveryTx(ctx context.Context, tx pgx.Tx, delivery TestReportDelivery, reportID string) (claimed bool, existingReportID string, err error) {
	tag, err := tx.Exec(ctx, `INSERT INTO test_report_deliveries (job_id, lease_generation, delivery_id, content_digest, report_id) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (job_id, lease_generation, delivery_id) DO NOTHING`,
		delivery.JobID, delivery.LeaseGeneration, delivery.DeliveryID, delivery.ContentDigest, reportID)
	if err != nil {
		return false, "", err
	}
	if tag.RowsAffected() == 1 {
		return true, "", nil
	}
	var storedDigest, storedReportID string
	if err := tx.QueryRow(ctx, `SELECT content_digest, report_id FROM test_report_deliveries WHERE job_id=$1 AND lease_generation=$2 AND delivery_id=$3`,
		delivery.JobID, delivery.LeaseGeneration, delivery.DeliveryID).Scan(&storedDigest, &storedReportID); err != nil {
		return false, "", err
	}
	if storedDigest != delivery.ContentDigest {
		return false, "", fmt.Errorf("%w: job %s generation %d delivery %s", ErrTestReportDeliveryConflict, delivery.JobID, delivery.LeaseGeneration, delivery.DeliveryID)
	}
	return false, storedReportID, nil
}

// foldOrRebuildTestReportTx folds the just-inserted report into the
// repository's aggregates while preserving the (created_at,id) fold order the
// rebuild uses. version is the repository's locked history version observed
// before the insert (0 = pre-aggregate repository, so the durable reports
// were never folded). The report is folded incrementally only when it is the
// repository's canonical NEWEST report; otherwise (version 0, or an
// out-of-order commit whose created_at/id precedes an already-folded report)
// the repository is rebuilt from its durable reports in (created_at,id) order.
// Both branches read/replace the same rows, so an incremental history can no
// longer drift from a repaired or restarted one.
func foldOrRebuildTestReportTx(ctx context.Context, tx pgx.Tx, repoID string, version int64, rep model.TestReport) error {
	if version == 0 {
		return rebuildRepoTestHistoryTx(ctx, tx, repoID)
	}
	outOfOrder, err := hasNewerTestReportTx(ctx, tx, repoID, rep.CreatedAt, rep.ID)
	if err != nil {
		return err
	}
	if outOfOrder {
		return rebuildRepoTestHistoryTx(ctx, tx, repoID)
	}
	for _, c := range rep.Cases {
		// Skip policy (one rule for every fold path): a skipped case is NOT
		// a pass/fail observation. JUnit marks it Passed=false plus
		// Skipped=true, so folding it would record a failure the test never
		// had and poison Fails, LastFailure, the 16-outcome window and
		// FlakeProb. Skipped cases contribute nothing to the historical
		// counters; the report's own Tests/Failures/Errors/Skipped totals
		// still describe the run.
		if c.Skipped {
			continue
		}
		if err := foldTestHistoryTx(ctx, tx, repoID, TestHistoryEntry{
			Suite: rep.JobKey, Class: c.Class, Name: c.Name, Duration: c.Duration, Passed: c.Passed, When: rep.CreatedAt,
		}); err != nil {
			return err
		}
	}
	return nil
}

// hasNewerTestReportTx reports whether repoID already holds a durable report
// that sorts AFTER (createdAt, id) under the canonical (created_at,id) order
// the rebuild uses. Such a report proves the new one is out of order, so the
// incremental fold must fall back to a rebuild. The repository predicate is
// the SAME canonical policy-first identity expression the rebuild and every
// scoped read use, so a pre-RepoID report is compared too.
func hasNewerTestReportTx(ctx context.Context, tx pgx.Tx, repoID string, createdAt time.Time, id string) (bool, error) {
	var newer bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM test_results tr JOIN runs r ON r.id = tr.run_id WHERE `+canonicalPolicyRepoIDSQLExprOn("r.payload", "repo")+` = $1 AND (tr.created_at, tr.id) > ($2, $3))`,
		repoID, createdAt, id).Scan(&newer)
	return newer, err
}
