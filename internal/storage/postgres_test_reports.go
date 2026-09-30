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
// the identical (delivery ID, content digest) had already committed while the
// lease was live: the stored ReportID is the original report, CreatedAt is
// its canonical stored creation instant, and nothing was inserted or folded.
type TestReportInsertOutcome struct {
	Version   int64
	Replay    bool
	ReportID  string
	CreatedAt time.Time
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

// LeaseTestReportStore is the LEASE-FENCED test-report commit: the report
// receipt, the report rows, the history fold and the repository version bump
// commit only while the job still holds a live lease in the database clock
// domain.
//
// Test reports are not passive telemetry: the folded history drives future
// test-to-shard assignment, duration balancing, the test manifest and flaky
// classification (testShards -> TestHistoryManifest/Shard/Flaky). A report
// whose request passed the HTTP lease gate and then committed after the lease
// expired would let a superseded generation alter later execution behavior.
// The fenced transaction therefore locks the job row, validates
// runner/generation, samples clock_timestamp() after the lock, and refuses
// the whole delivery with ErrLeaseLost when the lease already expired. It
// also stamps the report's canonical (created_at,id) ordering instant from
// that database timestamp, so replica clock skew cannot reorder history.
type LeaseTestReportStore interface {
	// InsertTestReportWithHistoryDeliveryForLease inserts one test-report
	// delivery under (jobID, runnerID, generation) exactly like
	// InsertTestReportWithHistoryDelivery, but only while the lease is live
	// at the post-lock database clock. The report's job/run identity and the
	// delivery's (job, generation) identity must match the locked job, and
	// repoID (when non-empty) must equal the locked job's canonical
	// repository identity; a mismatch commits nothing and returns an error
	// wrapping ErrLeaseIdentityMismatch. rep.CreatedAt is overwritten with
	// the fence's database timestamp.
	//
	// REPLAY CONTRACT (chosen semantics): an identical (delivery ID, digest)
	// replay is idempotent ONLY while generation N still holds the live
	// lease: the receipt is examined after the lease fence, so the retry
	// returns the original report ID and canonical CreatedAt and commits
	// nothing. Once the lease has ended (expiry, completion, recovery), the
	// retry is refused with ErrLeaseLost like any other post-lease write.
	// That refusal is safe — the first commit is already durable and folded
	// exactly once, so nothing is duplicated — and it is the documented
	// contract: test-report delivery is an advisory, lease-bound upload, not
	// a post-lease acknowledgment channel.
	InsertTestReportWithHistoryDeliveryForLease(ctx context.Context, jobID, runnerID string, generation int64, rep model.TestReport, repoID string, delivery TestReportDelivery) (TestReportInsertOutcome, error)
}

var _ LeaseTestReportStore = (*PostgresStore)(nil)

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
	return commitTestReportDeliveryTx(ctx, tx, rep, repoID, delivery)
}

// InsertTestReportWithHistoryDeliveryForLease is the lease-fenced sibling of
// InsertTestReportWithHistoryDelivery (see LeaseTestReportStore): the same
// delivery/report/fold transaction, preceded by the shared post-lock
// job-lease predicate (lockedLeaseJobTx) and with rep.CreatedAt overwritten
// by the fence's own database timestamp (coords.DBNow).
func (s *PostgresStore) InsertTestReportWithHistoryDeliveryForLease(ctx context.Context, jobID, runnerID string, generation int64, rep model.TestReport, repoID string, delivery TestReportDelivery) (TestReportInsertOutcome, error) {
	if err := validateLeaseCommitKey(jobID, runnerID, generation); err != nil {
		return TestReportInsertOutcome{}, err
	}
	if err := ValidateID(rep.ID); err != nil {
		return TestReportInsertOutcome{}, err
	}
	if err := ValidateRunID(rep.RunID); err != nil {
		return TestReportInsertOutcome{}, err
	}
	// The delivery identity is bound to the verified lease: a caller cannot
	// attribute one lease's report to another job or generation.
	if delivery.JobID != jobID || delivery.LeaseGeneration != generation {
		return TestReportInsertOutcome{}, leaseIdentityErrorf("test report delivery (job %s, generation %d) does not match leased job %s generation %d", delivery.JobID, delivery.LeaseGeneration, jobID, generation)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return TestReportInsertOutcome{}, err
	}
	defer tx.Rollback(ctx)
	coords, held, err := s.lockedLeaseJobTx(ctx, tx, jobID, runnerID, generation)
	if err != nil {
		return TestReportInsertOutcome{}, err
	}
	if !held {
		return TestReportInsertOutcome{}, fmt.Errorf("%w: test report for job %s", ErrLeaseLost, jobID)
	}
	if rep.JobID != jobID || rep.RunID != coords.RunID {
		return TestReportInsertOutcome{}, leaseIdentityErrorf("test report %s (job %s, run %s) does not match leased job %s run %s", rep.ID, rep.JobID, rep.RunID, jobID, coords.RunID)
	}
	if rep.JobKey != "" && rep.JobKey != coords.JobKey {
		return TestReportInsertOutcome{}, leaseIdentityErrorf("test report %s job key %q does not match leased job key %q", rep.ID, rep.JobKey, coords.JobKey)
	}
	if rep.JobKey == "" {
		rep.JobKey = coords.JobKey
	}
	if repoID == "" {
		repoID = coords.RepoID
	}
	if repoID != coords.RepoID {
		return TestReportInsertOutcome{}, leaseIdentityErrorf("test report %s repository %q does not match leased job repository %q", rep.ID, repoID, coords.RepoID)
	}
	// Canonical history ordering is the (created_at,id) pair; reuse the very
	// instant the lease was validated against, so the ordering time IS the
	// fence time, never a second sample or the serving replica's clock.
	rep.CreatedAt = coords.DBNow
	return commitTestReportDeliveryTx(ctx, tx, rep, repoID, delivery)
}

// commitTestReportDeliveryTx applies one report delivery inside the caller's
// transaction: claim the delivery receipt, lock the repository's history
// version, insert the report rows, fold (or rebuild) the aggregates, bump the
// version, and commit. The lease-fenced and plain entry points share it so
// the two can never drift.
func commitTestReportDeliveryTx(ctx context.Context, tx pgx.Tx, rep model.TestReport, repoID string, delivery TestReportDelivery) (TestReportInsertOutcome, error) {
	if delivery.DeliveryID != "" {
		claimed, existingID, err := claimTestReportDeliveryTx(ctx, tx, delivery, rep.ID)
		if err != nil {
			return TestReportInsertOutcome{}, err
		}
		if !claimed {
			// The identical delivery already committed (while this
			// generation held a live lease): return the ORIGINAL canonical
			// report identity and instant, and commit nothing (the rollback
			// is a no-op).
			var createdAt time.Time
			if err := tx.QueryRow(ctx, `SELECT created_at FROM test_results WHERE id=$1`, existingID).Scan(&createdAt); err != nil {
				return TestReportInsertOutcome{}, err
			}
			return TestReportInsertOutcome{Replay: true, ReportID: existingID, CreatedAt: createdAt.UTC()}, nil
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
	return TestReportInsertOutcome{Version: version, ReportID: rep.ID, CreatedAt: rep.CreatedAt}, nil
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
