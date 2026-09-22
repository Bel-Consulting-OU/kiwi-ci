package storage

// L5-B parity proof for the durable report-delivery contract: the in-memory
// store and the real PostgreSQL store must behave IDENTICALLY for one
// delivery identity — including a server-synthesized legacy-client identity —
// so the server's fs/memory fallback and the DB path cannot drift: a resend
// is an idempotent replay (no duplicate report, no re-fold), and the same
// identity with different content is ErrTestReportDeliveryConflict.
//
// Gated on KIWI_TEST_POSTGRES_URL via the shared pgIT* helpers.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// synthesizedDeliveryFixture is the identity the server synthesizes for a
// legacy client: an opaque 64-hex name bound to (job, generation, digest).
// The store treats it exactly like a runner-derived delivery ID.
func synthesizedDeliveryFixture() TestReportDelivery {
	return TestReportDelivery{
		JobID:           testJob.ID,
		LeaseGeneration: 7,
		DeliveryID:      "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
		ContentDigest:   "d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c",
	}
}

func TestMemStoreReportDeliverySynthesizedIdentityConverges(t *testing.T) {
	repo := "github.com/o/synthed"
	m, insert := newDeliveryHistoryStore(t, repo)
	base := time.Now().UTC()
	d := synthesizedDeliveryFixture()
	rep := deliveryReport("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa61", base, model.TestResult{Name: "t", Passed: true})

	first, err := insert(rep, d)
	if err != nil || first.Replay || first.ReportID != rep.ID || first.Version != 1 {
		t.Fatalf("first delivery = %+v, %v; want fresh version 1", first, err)
	}
	replay, err := insert(rep, d)
	if err != nil || !replay.Replay || replay.ReportID != rep.ID {
		t.Fatalf("replay = %+v, %v; want the original report", replay, err)
	}
	if len(m.reports) != 1 {
		t.Fatalf("reports after replay = %d, want 1", len(m.reports))
	}
	if row := m.historyAggregates[repo][memHistoryKey("build", "", "t")]; row.Runs != 1 {
		t.Fatalf("aggregate after replay = %+v, want one fold", row)
	}
	if v := memHistoryVersion(m, repo); v != 1 {
		t.Fatalf("history version after replay = %d, want 1", v)
	}
	conflict := d
	conflict.ContentDigest = "other-digest"
	if _, err := insert(deliveryReport("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa62", base.Add(time.Second), model.TestResult{Name: "t", Passed: false}), conflict); !errors.Is(err, ErrTestReportDeliveryConflict) {
		t.Fatalf("conflict err = %v, want ErrTestReportDeliveryConflict", err)
	}
}

func TestPostgresIntegrationReportDeliverySynthesizedIdentityParity(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo, full := "github.com/kiwi-it/synth-parity", "kiwi-it/synth-parity"
	runID := pgITNewID(t)
	pgITHistoryRun(t, st, runID, pgITNewID(t), repo, full, time.Now().UTC())

	d := synthesizedDeliveryFixture()
	rep := pgITHistoryReport(runID, pgITNewID(t), time.Now().UTC(), model.TestResult{Name: "t", Passed: true})

	first, err := st.InsertTestReportWithHistoryDelivery(ctx, rep, repo, d)
	if err != nil || first.Replay || first.ReportID != rep.ID {
		t.Fatalf("first delivery = %+v, %v; want fresh", first, err)
	}
	replay, err := st.InsertTestReportWithHistoryDelivery(ctx, rep, repo, d)
	if err != nil || !replay.Replay || replay.ReportID != rep.ID {
		t.Fatalf("replay = %+v, %v; want the original report", replay, err)
	}
	if got := pgITHistoryReportCount(t, st, rep.ID); got != 1 {
		t.Fatalf("report rows after replay = %d, want 1", got)
	}
	if got := pgITHistoryStats(t, st, repo); len(got) != 1 {
		t.Fatalf("aggregate keys after replay = %d, want 1", len(got))
	}
	var runs int64
	if err := st.pool.QueryRow(ctx, `SELECT runs FROM test_history_aggregates WHERE repo_id=$1 AND suite=$2 AND test_class='' AND test_name=$3`, repo, "build", "t").Scan(&runs); err != nil {
		t.Fatalf("read aggregate: %v", err)
	}
	if runs != 1 {
		t.Fatalf("aggregate runs after replay = %d, want 1", runs)
	}
	conflict := d
	conflict.ContentDigest = "other-digest"
	if _, err := st.InsertTestReportWithHistoryDelivery(ctx, pgITHistoryReport(runID, pgITNewID(t), time.Now().UTC(), model.TestResult{Name: "t", Passed: false}), repo, conflict); !errors.Is(err, ErrTestReportDeliveryConflict) {
		t.Fatalf("conflict err = %v, want ErrTestReportDeliveryConflict", err)
	}
}
