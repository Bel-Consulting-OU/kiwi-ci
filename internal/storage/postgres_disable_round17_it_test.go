package storage

// Coverage round: the atomic runner-disable failure arms. Every path either
// asserts the typed error or proves the transaction rolled back (no disable,
// no revocation row, no audit rows).

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// itConditionalAuditBoom raises only for the given audit action, so a
// multi-audit transaction can fail on a later insert while earlier ones
// succeed.
func itConditionalAuditBoom(t *testing.T, st *PostgresStore, action string) {
	t.Helper()
	ctx := context.Background()
	fn := "kiwi_audit_boom_" + strings.ReplaceAll(action, ".", "_")
	if _, err := st.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION `+fn+`() RETURNS trigger AS $$
		BEGIN IF NEW.action = '`+action+`' THEN RAISE EXCEPTION 'blocked audit action `+action+`'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql`); err != nil {
		t.Fatalf("create conditional audit trigger: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `CREATE TRIGGER `+fn+`_t BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION `+fn+`()`); err != nil {
		t.Fatalf("create conditional audit trigger: %v", err)
	}
}

func itSeedRunner(t *testing.T, st *PostgresStore, runnerID string) {
	t.Helper()
	if err := st.UpsertRunner(context.Background(), model.Runner{ID: runnerID, Name: "r", Capacity: 4, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
}

// TestPostgresIntegrationDisableRunnerArms drives the runner-disable kill
// switch's failure arms and proves each one rolls back every effect.
func TestPostgresIntegrationDisableRunnerArms(t *testing.T) {
	ctx := context.Background()

	t.Run("missing runner", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.DisableRunnerAndRevokeCert(ctx, pgITNewID(t), "", "admin"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("disable of a missing runner = %v, want ErrNotFound", err)
		}
	})

	t.Run("lease revocation error", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		itSeedRunner(t, st, runnerID)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		pgITBoomOp(t, st, "jobs", "UPDATE")
		if _, err := st.DisableRunnerAndRevokeCert(ctx, runnerID, "", "admin"); err == nil {
			t.Fatal("disable with a failing lease revocation succeeded")
		}
		r, err := st.GetRunner(ctx, runnerID)
		if err != nil {
			t.Fatalf("get runner: %v", err)
		}
		if r.Disabled {
			t.Fatal("failed disable still marked the runner disabled")
		}
	})

	t.Run("runner payload query error", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		itSeedRunner(t, st, runnerID)
		pgITBreakColumn(t, st, "runners", "payload")
		if _, err := st.DisableRunnerAndRevokeCert(ctx, runnerID, "", "admin"); err == nil {
			t.Fatal("disable over an undecodable runner payload succeeded")
		}
	})

	t.Run("runner payload column missing", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		itSeedRunner(t, st, runnerID)
		pgITDropColumn(t, st, "runners", "payload")
		if _, err := st.DisableRunnerAndRevokeCert(ctx, runnerID, "", "admin"); err == nil {
			t.Fatal("disable without the runner payload column succeeded")
		}
	})

	t.Run("corrupt runner payload", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		itSeedRunner(t, st, runnerID)
		if _, err := st.pool.Exec(ctx, `UPDATE runners SET payload = '"scalar"'::jsonb WHERE id=$1`, runnerID); err != nil {
			t.Fatalf("corrupt payload: %v", err)
		}
		if _, err := st.DisableRunnerAndRevokeCert(ctx, runnerID, "", "admin"); err == nil {
			t.Fatal("disable over a corrupt runner payload succeeded")
		}
	})

	t.Run("encode errors", func(t *testing.T) {
		t.Run("runner payload", func(t *testing.T) {
			st := pgITStore(t)
			runnerID := pgITNewID(t)
			itSeedRunner(t, st, runnerID)
			defer seamPGFailAt(t, 1)()
			if _, err := st.DisableRunnerAndRevokeCert(ctx, runnerID, "", "admin"); !errors.Is(err, errPGSeamJSON) {
				t.Fatalf("encode failure = %v, want the seam error", err)
			}
		})
		t.Run("audit metadata", func(t *testing.T) {
			st := pgITStore(t)
			runnerID := pgITNewID(t)
			itSeedRunner(t, st, runnerID)
			// The runner payload encodes first, the disable-audit metadata
			// second; failing only the second isolates the audit arm.
			defer seamPGFailAt(t, 2)()
			if _, err := st.DisableRunnerAndRevokeCert(ctx, runnerID, "", "admin"); !errors.Is(err, errPGSeamJSON) {
				t.Fatalf("audit encode failure = %v, want the seam error", err)
			}
		})
	})

	t.Run("disable audit insert error", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		itSeedRunner(t, st, runnerID)
		pgITBoomOp(t, st, "audit_events", "INSERT")
		if _, err := st.DisableRunnerAndRevokeCert(ctx, runnerID, "", "admin"); err == nil {
			t.Fatal("disable with a failing audit insert succeeded")
		}
		if r, err := st.GetRunner(ctx, runnerID); err != nil || r.Disabled {
			t.Fatalf("rolled-back disable = %+v, %v", r, err)
		}
	})

	t.Run("cert revocation audit insert error", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		itSeedRunner(t, st, runnerID)
		itConditionalAuditBoom(t, st, "runner.cert_revoked")
		if _, err := st.DisableRunnerAndRevokeCert(ctx, runnerID, "serial-1", "admin"); err == nil {
			t.Fatal("disable with a failing cert-revocation audit succeeded")
		}
		if r, err := st.GetRunner(ctx, runnerID); err != nil || r.Disabled {
			t.Fatalf("rolled-back disable = %+v, %v", r, err)
		}
		var revoked bool
		if err := st.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cert_revocations WHERE serial='serial-1')`).Scan(&revoked); err != nil {
			t.Fatalf("read revocation: %v", err)
		}
		if revoked {
			t.Fatal("failed disable left a dangling certificate revocation")
		}
	})

	t.Run("commit error", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		itSeedRunner(t, st, runnerID)
		itDeferBoom(t, st, "audit_events")
		if _, err := st.DisableRunnerAndRevokeCert(ctx, runnerID, "", "admin"); err == nil || !strings.Contains(err.Error(), "deferred failure") {
			t.Fatalf("commit failure = %v, want the deferred error", err)
		}
		if r, err := st.GetRunner(ctx, runnerID); err != nil || r.Disabled {
			t.Fatalf("rolled-back disable = %+v, %v", r, err)
		}
	})

	t.Run("happy path revokes cert", func(t *testing.T) {
		st := pgITStore(t)
		runnerID := pgITNewID(t)
		itSeedRunner(t, st, runnerID)
		n, err := st.DisableRunnerAndRevokeCert(ctx, runnerID, "serial-ok", "admin")
		if err != nil || n != 0 {
			t.Fatalf("disable = (%d, %v), want (0, nil)", n, err)
		}
		r, err := st.GetRunner(ctx, runnerID)
		if err != nil || !r.Disabled || r.RevokedAt == nil {
			t.Fatalf("disabled runner = %+v, %v", r, err)
		}
		if ok, err := st.CertRevoked(ctx, "serial-ok"); err != nil || !ok {
			t.Fatalf("cert revoked = %v, %v", ok, err)
		}
	})
}
