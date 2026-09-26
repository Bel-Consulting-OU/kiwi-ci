package storage

// Real-PostgreSQL coverage for the O(1) snapshot preflight count and the
// SQL-only refusal branches of the OIDC issuance commit. Gated on
// KIWI_TEST_POSTGRES_URL exactly like the other storage integration tests.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestIntegrationCountSnapshotsForJobPreflight pins the O(1) preflight count
// on PostgreSQL: it counts exactly the addressed (run, job) pair, never a
// sibling job's rows and never the legacy NULL-job rows on the same run, and
// a malformed run id is refused before the query.
func TestIntegrationCountSnapshotsForJobPreflight(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID, runnerID, gen := leaseCommitITJob(t, st, pgITRepo)

	if n, err := st.CountSnapshotsForJob(ctx, runID, jobID); err != nil || n != 0 {
		t.Fatalf("empty count = (%d, %v), want (0, nil)", n, err)
	}
	for i := 0; i < 2; i++ {
		rec := model.SnapshotRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, CreatedAt: time.Now().UTC()}
		if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, gen, 0, rec); err != nil {
			t.Fatalf("lease-fenced snapshot insert: %v", err)
		}
	}
	// A legacy NULL-job row on the SAME run and a sibling job's row are both
	// excluded from the addressed pair's count.
	if _, err := st.pool.Exec(ctx, `INSERT INTO workspace_snapshots (id, run_id, job_id, created_at, payload) VALUES ($1,$2,NULL,now(),'{}'::jsonb)`, pgITNewID(t), runID); err != nil {
		t.Fatal(err)
	}
	otherJob := pgITNewID(t)
	if _, err := st.pool.Exec(ctx, `INSERT INTO workspace_snapshots (id, run_id, job_id, created_at, payload) VALUES ($1,$2,$3,now(),'{}'::jsonb)`, pgITNewID(t), runID, otherJob); err != nil {
		t.Fatal(err)
	}

	if n, err := st.CountSnapshotsForJob(ctx, runID, jobID); err != nil || n != 2 {
		t.Fatalf("count for the locked pair = (%d, %v), want (2, nil)", n, err)
	}
	if n, err := st.CountSnapshotsForJob(ctx, runID, otherJob); err != nil || n != 1 {
		t.Fatalf("count for the sibling job = (%d, %v), want (1, nil)", n, err)
	}
	if _, err := st.CountSnapshotsForJob(ctx, "", jobID); err == nil {
		t.Fatal("malformed run id accepted by the preflight count")
	}
	if n, err := st.CountSnapshotsForJob(ctx, runID, ""); err != nil || n != 0 {
		t.Fatalf("NULL job address = (%d, %v), want (0, nil): an empty job id matches no row", n, err)
	}
}

// TestIntegrationOIDCIssuanceCommitMissingJobAndDecodeRefusals covers the two
// SQL-only refusals of the issuance commit: a row that vanished before the
// FOR UPDATE read maps to ErrNotFound (never a credential), and a malformed
// oidc_audiences column is a decode error, with no audit row appended for
// either.
func TestIntegrationOIDCIssuanceCommitMissingJobAndDecodeRefusals(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, _, j := oidcITLeasedJob(t, st)

	missing := oidcITRequest(j, oidcITAudience)
	missing.JobID = pgITNewID(t)
	if _, err := st.CommitOIDCIssuance(ctx, missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("issuance for a vanished job = %v, want ErrNotFound", err)
	}
	if n := oidcITIssuedAudits(t, st, jobID); n != 0 {
		t.Fatalf("refused missing-job issuance appended %d audit rows", n)
	}

	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload = payload || '{"oidc_audiences":"nope"}'::jsonb WHERE id=$1`, jobID); err != nil {
		t.Fatalf("corrupt audiences: %v", err)
	}
	_, err := st.CommitOIDCIssuance(ctx, oidcITRequest(j, oidcITAudience))
	if err == nil || !strings.Contains(err.Error(), "decode job oidc_audiences") {
		t.Fatalf("malformed audiences = %v, want a decode refusal", err)
	}
	if n := oidcITIssuedAudits(t, st, jobID); n != 0 {
		t.Fatalf("decode-refused issuance appended %d audit rows", n)
	}
}
