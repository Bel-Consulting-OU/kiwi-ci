package storage

// Real-PostgreSQL regression for ClaimScheduleOccurrence's zero-row branch
// (Round-11 finding B3). Gated on KIWI_TEST_POSTGRES_URL like the other
// integration tests.
//
// A BEFORE INSERT trigger that returns NULL deterministically reproduces the
// unsound condition the audit found: the claim INSERT reports ZERO affected
// rows while the follow-up ownership read finds NO row (nothing was ever
// inserted, and nothing conflicting exists). The old code treated that as a
// win; the fixed code re-executes the claim and, still observing no row of its
// own, reports the claim as lost. The trigger is then disabled to prove a
// normal claim still wins with a durable row.

import (
	"context"
	"testing"
	"time"
)

func TestPostgresIntegrationClaimScheduleOccurrenceNeverReportsUnobservedWin(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	scheduleID := pgITNewID(t)
	nominal := time.Now().UTC().Truncate(time.Microsecond)
	runID := pgITNewID(t)
	if err := st.UpsertSchedule(ctx, Schedule{ID: scheduleID, Repository: "kiwi-it/repo", Spec: "@daily", Enabled: true, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("seed schedule: %v", err)
	}

	if _, err := st.pool.Exec(ctx, `CREATE TABLE occurrence_insert_gate (suppress boolean NOT NULL)`); err != nil {
		t.Fatalf("create gate table: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `INSERT INTO occurrence_insert_gate VALUES (TRUE)`); err != nil {
		t.Fatalf("arm gate: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `CREATE FUNCTION occurrence_insert_suppress() RETURNS trigger AS $$
		BEGIN
			IF (SELECT suppress FROM occurrence_insert_gate LIMIT 1) THEN
				RETURN NULL;
			END IF;
			RETURN NEW;
		END $$ LANGUAGE plpgsql`); err != nil {
		t.Fatalf("create suppress function: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `CREATE TRIGGER occurrence_insert_suppress BEFORE INSERT ON schedule_occurrences FOR EACH ROW EXECUTE FUNCTION occurrence_insert_suppress()`); err != nil {
		t.Fatalf("create suppress trigger: %v", err)
	}

	won, err := st.ClaimScheduleOccurrence(ctx, scheduleID, nominal, runID)
	if err != nil {
		t.Fatalf("suppressed ClaimScheduleOccurrence: %v", err)
	}
	if won {
		t.Fatal("claim reported won with no durable occurrence row (the zero-row INSERT had no observable owner)")
	}
	occ, err := st.ListOccurrences(ctx, scheduleID)
	if err != nil {
		t.Fatalf("ListOccurrences: %v", err)
	}
	if len(occ) != 0 {
		t.Fatalf("suppressed claim left %d occurrence rows, want 0", len(occ))
	}

	// Release the gate: the same claim now wins and its row is durable.
	if _, err := st.pool.Exec(ctx, `UPDATE occurrence_insert_gate SET suppress = FALSE`); err != nil {
		t.Fatalf("release gate: %v", err)
	}
	won, err = st.ClaimScheduleOccurrence(ctx, scheduleID, nominal, runID)
	if err != nil {
		t.Fatalf("released ClaimScheduleOccurrence: %v", err)
	}
	if !won {
		t.Fatal("claim lost after the insert gate was released")
	}
	occ, err = st.ListOccurrences(ctx, scheduleID)
	if err != nil {
		t.Fatalf("ListOccurrences after release: %v", err)
	}
	if len(occ) != 1 || occ[0].RunID != runID {
		t.Fatalf("occurrences after release = %+v, want exactly one owned by %s", occ, runID)
	}
}
