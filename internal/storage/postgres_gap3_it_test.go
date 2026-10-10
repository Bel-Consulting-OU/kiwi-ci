package storage

// Third coverage round for the Postgres store: branch-level integration tests
// for the lease claim, generated-fragment admission, completion receipts and
// the versioned outbox. Every case runs on its own throwaway database and uses
// the existing seam helpers (mistyped columns, BEFORE triggers, skip triggers)
// so exactly one statement of the helper under test fails while every earlier
// statement succeeds. All tests carry Integration in the name and are gated on
// KIWI_TEST_POSTGRES_URL.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// gapITLeaseObject claims jobID for runnerID through the legacy (non-atomic)
// claim, which every test in this file uses as the lease fixture: it needs no
// runner row and yields the token hash and generation the request structs
// must present.
func gapITLeaseObject(t *testing.T, st *PostgresStore, jobID, runnerID string) model.Job {
	t.Helper()
	leased, err := st.AcquireLease(context.Background(), jobID, runnerID, []byte("gap-lease-token"), 1, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("AcquireLease %s: %v", jobID, err)
	}
	return leased
}

// gapITFragmentRequest builds a valid generated-fragment request for a leased
// parent with exactly one child and one contract-free job.
func gapITFragmentRequest(t *testing.T, st *PostgresStore, runID, parentID, runnerID, fragmentID string) (GeneratedFragmentRequest, model.Job) {
	t.Helper()
	leased := gapITLeaseObject(t, st, parentID, runnerID)
	child := pgITJob(runID, pgITNewID(t), pgITRepo)
	req := GeneratedFragmentRequest{
		ParentJobID: parentID, RunnerID: runnerID, LeaseGeneration: leased.LeaseGeneration,
		LeaseTokenHash: leased.LeaseTokenHash, Depth: 1, FragmentID: fragmentID,
		Jobs:     map[string]model.Job{child.ID: child},
		Children: []GeneratedFragmentChild{{Key: child.Key, ID: child.ID}},
	}
	return req, child
}

// TestPostgresIntegrationAcquireLeaseAtomicClaimArms drives the claim's
// validation, decode, runner-write and semantic-event failure arms.
func TestPostgresIntegrationAcquireLeaseAtomicClaimArms(t *testing.T) {
	ctx := context.Background()

	t.Run("claimTextValidation", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		bad := "bad\x00value"
		cases := []struct {
			name  string
			claim LeaseClaim
		}{
			{"runtime", LeaseClaim{JobID: jobID, RunnerID: "r", Runtime: bad}},
			{"canonRepoID", LeaseClaim{JobID: jobID, RunnerID: "r", CanonRepoID: bad}},
			{"repoFullName", LeaseClaim{JobID: jobID, RunnerID: "r", RepoFullName: bad}},
			{"environment", LeaseClaim{JobID: jobID, RunnerID: "r", Environment: bad}},
			{"requiredLabel", LeaseClaim{JobID: jobID, RunnerID: "r", RequiredLabels: []string{bad}}},
			{"placementRegion", LeaseClaim{JobID: jobID, RunnerID: "r", PlacementRegions: []string{bad}}},
		}
		for _, tc := range cases {
			if _, err := st.AcquireLeaseAtomic(ctx, tc.claim); err == nil {
				t.Fatalf("%s with a NUL byte was expected to fail validation", tc.name)
			}
		}
	})

	t.Run("runnerPayloadDecode", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		runnerID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		if _, err := st.pool.Exec(ctx, `UPDATE runners SET payload='"scalar"'::jsonb WHERE id=$1`, runnerID); err != nil {
			t.Fatal(err)
		}
		_, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("t"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Minute)})
		if err == nil || !strings.Contains(err.Error(), "decode runner payload") {
			t.Fatalf("runner payload decode = %v, want decode failure", err)
		}
	})

	t.Run("runnerActiveJobsDecode", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		runnerID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		if _, err := st.pool.Exec(ctx, `UPDATE runners SET active_jobs='"scalar"'::jsonb WHERE id=$1`, runnerID); err != nil {
			t.Fatal(err)
		}
		_, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("t"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Minute)})
		if err == nil || !strings.Contains(err.Error(), "decode runner active jobs") {
			t.Fatalf("active jobs decode = %v, want decode failure", err)
		}
	})

	t.Run("runnerSlotUpdate", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		runnerID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		pgITBoomOp(t, st, "runners", "UPDATE")
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("t"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Minute)}); err == nil {
			t.Fatal("claim with a failing runner slot update succeeded")
		}
		if j, err := st.GetJob(ctx, jobID); err != nil || j.Status != model.StatusQueued {
			t.Fatalf("job after failed slot update = %+v, %v; want queued", j, err)
		}
	})

	t.Run("eventAppendRollsBack", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		runnerID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		pgITBoomOp(t, st, "execution_events", "INSERT")
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("t"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Minute)}); err == nil {
			t.Fatal("claim with a failing semantic event append succeeded")
		}
		if j, err := st.GetJob(ctx, jobID); err != nil || j.Status != model.StatusQueued {
			t.Fatalf("job after failed event append = %+v, %v; want queued", j, err)
		}
	})

	t.Run("claimDecode", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		runnerID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, jobID); err != nil {
			t.Fatal(err)
		}
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("t"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Minute)}); err == nil {
			t.Fatal("claim over an undecodable payload succeeded")
		}
	})
}

// TestPostgresIntegrationGeneratedFragmentTxArms drives the fragment
// transaction's write and decode failure arms.
func TestPostgresIntegrationGeneratedFragmentTxArms(t *testing.T) {
	ctx := context.Background()

	t.Run("emptyFragmentID", func(t *testing.T) {
		if _, _, err := (&PostgresStore{}).InsertGeneratedFragmentTx(ctx, GeneratedFragmentRequest{ParentJobID: pgITNewID(t)}, nil); err == nil {
			t.Fatal("empty fragment id was admitted")
		}
	})

	t.Run("parentScanFail", func(t *testing.T) {
		st := pgITStore(t)
		runID, parentID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, parentID, pgITRepo)
		req, _ := gapITFragmentRequest(t, st, runID, parentID, runnerID, "frag-scan")
		pgITBreakColumnToArray(t, st, "jobs", "key")
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
			t.Fatal("parent lock scan over a mistyped key succeeded")
		}
	})

	t.Run("childInvalidID", func(t *testing.T) {
		st := pgITStore(t)
		runID, parentID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, parentID, pgITRepo)
		req, child := gapITFragmentRequest(t, st, runID, parentID, runnerID, "frag-badid")
		child.ID = "not-a-valid-id"
		req.Jobs = map[string]model.Job{child.ID: child}
		req.Children = []GeneratedFragmentChild{{Key: child.Key, ID: child.ID}}
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
			t.Fatal("fragment with an invalid child id succeeded")
		}
	})

	t.Run("childInsertFail", func(t *testing.T) {
		st := pgITStore(t)
		runID, parentID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, parentID, pgITRepo)
		req, child := gapITFragmentRequest(t, st, runID, parentID, runnerID, "frag-insert")
		pgITBoomOp(t, st, "jobs", "INSERT")
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
			t.Fatal("fragment with a failing child insert succeeded")
		}
		if _, err := st.GetJob(ctx, child.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("failed fragment leaked a child row: %v", err)
		}
	})

	t.Run("dependenciesFail", func(t *testing.T) {
		st := pgITStore(t)
		runID, parentID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, parentID, pgITRepo)
		req, child := gapITFragmentRequest(t, st, runID, parentID, runnerID, "frag-deps")
		child.Needs = []string{parentID}
		req.Jobs = map[string]model.Job{child.ID: child}
		pgITBoomOp(t, st, "job_dependencies", "INSERT")
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
			t.Fatal("fragment with a failing dependency insert succeeded")
		}
	})

	t.Run("contractInvalidID", func(t *testing.T) {
		st := pgITStore(t)
		runID, parentID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, parentID, pgITRepo)
		req, _ := gapITFragmentRequest(t, st, runID, parentID, runnerID, "frag-contractid")
		req.Contracts = map[string]map[string]ArtifactContract{"bad-id": {"bin": {Name: "bin"}}}
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
			t.Fatal("fragment with an invalid contract job id succeeded")
		}
	})

	t.Run("contractUpdateFail", func(t *testing.T) {
		st := pgITStore(t)
		runID, parentID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, parentID, pgITRepo)
		req, child := gapITFragmentRequest(t, st, runID, parentID, runnerID, "frag-contractupd")
		req.Contracts = map[string]map[string]ArtifactContract{child.ID: {"bin": {Name: "bin"}}}
		if _, err := st.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION kiwi_boom_contract_update() RETURNS trigger AS $$ BEGIN IF NEW.payload->'artifact_contracts' IS NOT NULL THEN RAISE EXCEPTION 'injected contract update failure'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.pool.Exec(ctx, `CREATE TRIGGER kiwi_boom_contract_update_t BEFORE UPDATE ON jobs FOR EACH ROW EXECUTE FUNCTION kiwi_boom_contract_update()`); err != nil {
			t.Fatal(err)
		}
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
			t.Fatal("fragment with a failing contract update succeeded")
		}
	})

	t.Run("fragmentInsertFail", func(t *testing.T) {
		st := pgITStore(t)
		runID, parentID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, parentID, pgITRepo)
		req, _ := gapITFragmentRequest(t, st, runID, parentID, runnerID, "frag-receipt")
		pgITBoomOp(t, st, "generated_fragments", "INSERT")
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
			t.Fatal("fragment with a failing receipt insert succeeded")
		}
	})

	t.Run("eventAppendFail", func(t *testing.T) {
		st := pgITStore(t)
		runID, parentID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, parentID, pgITRepo)
		req, child := gapITFragmentRequest(t, st, runID, parentID, runnerID, "frag-event")
		pgITBoomOp(t, st, "execution_events", "INSERT")
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
			t.Fatal("fragment with a failing semantic event append succeeded")
		}
		if _, err := st.GetJob(ctx, child.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("rolled-back fragment leaked a child row: %v", err)
		}
	})

	t.Run("graphEventAppendFail", func(t *testing.T) {
		st := pgITStore(t)
		runID, parentID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, parentID, pgITRepo)
		req, child := gapITFragmentRequest(t, st, runID, parentID, runnerID, "frag-graphevent")
		if _, err := st.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION kiwi_boom_graph_event() RETURNS trigger AS $$ BEGIN IF NEW.event_type = 'graph.mutation_committed' THEN RAISE EXCEPTION 'injected graph event failure'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.pool.Exec(ctx, `CREATE TRIGGER kiwi_boom_graph_event_t BEFORE INSERT ON execution_events FOR EACH ROW EXECUTE FUNCTION kiwi_boom_graph_event()`); err != nil {
			t.Fatal(err)
		}
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
			t.Fatal("fragment with a failing graph event append succeeded")
		}
		if _, err := st.GetJob(ctx, child.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("rolled-back fragment leaked a child row: %v", err)
		}
	})

	t.Run("replayEventAppendFail", func(t *testing.T) {
		st := pgITStore(t)
		runID, parentID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, parentID, pgITRepo)
		req, _ := gapITFragmentRequest(t, st, runID, parentID, runnerID, "frag-replay")
		if _, replayed, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err != nil || replayed {
			t.Fatalf("seed fragment = replayed %v, %v", replayed, err)
		}
		pgITBoomOp(t, st, "execution_events", "INSERT")
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
			t.Fatal("replay with a failing semantic event append succeeded")
		}
	})
}

// TestPostgresIntegrationCompleteJobReceiptArms drives the completion
// transaction's resource-release, receipt replay and prune failure arms.
func TestPostgresIntegrationCompleteJobReceiptArms(t *testing.T) {
	ctx := context.Background()

	complete := func(t *testing.T, st *PostgresStore, jobID, runnerID string) error {
		t.Helper()
		return st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", map[string]string{"out": "v"},
			model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "gap-result-hash"}, nil)
	}

	t.Run("resourceReleaseFail", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		if _, err := st.pool.Exec(ctx, `INSERT INTO job_resource_reservations (job_id, runner_id) VALUES ($1,$2)`, jobID, runnerID); err != nil {
			t.Fatal(err)
		}
		pgITBoomOp(t, st, "job_resource_reservations", "DELETE")
		if err := complete(t, st, jobID, runnerID); err == nil {
			t.Fatal("completion with a failing resource release succeeded")
		}
		if j, err := st.GetJob(ctx, jobID); err != nil || j.Status != model.StatusRunning {
			t.Fatalf("job after failed resource release = %+v, %v; want running", j, err)
		}
	})

	t.Run("receiptAgedOutReinsert", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		if _, err := st.pool.Exec(ctx, `INSERT INTO completion_receipts (job_id, generation, runner_id, result_hash, result_hash_version, created_at) VALUES ($1,1,$2,'stale',1, now() - interval '30 days')`, jobID, runnerID); err != nil {
			t.Fatal(err)
		}
		if err := complete(t, st, jobID, runnerID); err != nil {
			t.Fatalf("completion over an aged-out receipt = %v", err)
		}
		if j, err := st.GetJob(ctx, jobID); err != nil || j.Status != model.StatusSuccess {
			t.Fatalf("job after aged-out receipt completion = %+v, %v", j, err)
		}
	})

	t.Run("receiptReinsertStillConflicts", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		if _, err := st.pool.Exec(ctx, `INSERT INTO completion_receipts (job_id, generation, runner_id, result_hash, result_hash_version, created_at) VALUES ($1,1,$2,'stale',1, now() - interval '30 days')`, jobID, runnerID); err != nil {
			t.Fatal(err)
		}
		// The insert is skipped while the delete is real: the receipt can
		// never be reoccupied inside the locked transaction, so the
		// completion must fail closed instead of acking an unverified result.
		pgITSkipWrites(t, st, "completion_receipts", "INSERT")
		if err := complete(t, st, jobID, runnerID); !errors.Is(err, ErrCompletionConflict) {
			t.Fatalf("skipped receipt reinsert = %v, want ErrCompletionConflict", err)
		}
		if j, err := st.GetJob(ctx, jobID); err != nil || j.Status != model.StatusRunning {
			t.Fatalf("job after skipped receipt reinsert = %+v, %v; want running", j, err)
		}
	})

	t.Run("pruneFail", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		if _, err := st.pool.Exec(ctx, `INSERT INTO completion_receipts (job_id, generation, runner_id, result_hash, result_hash_version, created_at) VALUES ($1,99,$2,'prunable',1, now() - interval '30 days')`, jobID, runnerID); err != nil {
			t.Fatal(err)
		}
		pgITBoomOp(t, st, "completion_receipts", "DELETE")
		if err := complete(t, st, jobID, runnerID); err == nil {
			t.Fatal("completion with a failing receipt prune succeeded")
		}
		if j, err := st.GetJob(ctx, jobID); err != nil || j.Status != model.StatusRunning {
			t.Fatalf("job after failed prune = %+v, %v; want running", j, err)
		}
	})

	t.Run("receiptIdentityMismatch", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		gapITLeaseObject(t, st, jobID, runnerID)
		err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil,
			model.CompletionReceipt{JobID: pgITNewID(t), Generation: 1, RunnerID: runnerID, ResultHash: "x"}, nil)
		if err == nil || !strings.Contains(err.Error(), "identity mismatch") {
			t.Fatalf("mismatched receipt = %v, want identity mismatch", err)
		}
	})
}

// TestPostgresIntegrationOutboxEnqueueVersionedArms drives the versioned
// enqueue's validation, defaults, scan and write failure arms.
func TestPostgresIntegrationOutboxEnqueueVersionedArms(t *testing.T) {
	ctx := context.Background()

	t.Run("validation", func(t *testing.T) {
		zero := &PostgresStore{}
		if _, err := zero.OutboxEnqueueVersioned(ctx, OutboxItem{StateVersion: 1}); err == nil {
			t.Fatal("missing logical key was admitted")
		}
		if _, err := zero.OutboxEnqueueVersioned(ctx, OutboxItem{LogicalKey: "lk", StateVersion: 0}); err == nil {
			t.Fatal("non-positive state version was admitted")
		}
	})

	t.Run("defaults", func(t *testing.T) {
		st := pgITStore(t)
		item := OutboxItem{ID: pgITNewID(t), Kind: "gap", LogicalKey: "gap-defaults", StateVersion: 1}
		outcome, err := st.OutboxEnqueueVersioned(ctx, item)
		if err != nil || outcome != VersionedEnqueued {
			t.Fatalf("defaults enqueue = %v, %v", outcome, err)
		}
		var payload string
		var createdSet bool
		if err := st.pool.QueryRow(ctx, `SELECT payload::text, created_at IS NOT NULL FROM outbox WHERE id=$1`, item.ID).Scan(&payload, &createdSet); err != nil {
			t.Fatal(err)
		}
		if payload != "{}" || !createdSet {
			t.Fatalf("defaults persisted payload=%q createdSet=%v, want {} and set", payload, createdSet)
		}
	})

	t.Run("beginFail", func(t *testing.T) {
		st := pgITStore(t)
		st.Close()
		if _, err := st.OutboxEnqueueVersioned(ctx, OutboxItem{ID: pgITNewID(t), Kind: "gap", LogicalKey: "gap-closed", StateVersion: 1}); err == nil {
			t.Fatal("enqueue over a closed pool succeeded")
		}
	})

	t.Run("deliveredScanFail", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.pool.Exec(ctx, `ALTER TABLE forge_check_state ALTER COLUMN delivered_version DROP DEFAULT`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.pool.Exec(ctx, `ALTER TABLE forge_check_state ALTER COLUMN delivered_version TYPE bytea USING '\x00'::bytea`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.OutboxEnqueueVersioned(ctx, OutboxItem{ID: pgITNewID(t), Kind: "gap", LogicalKey: "gap-delivered", StateVersion: 1}); err == nil {
			t.Fatal("enqueue with a mistyped delivered_version succeeded")
		}
	})

	t.Run("maxPendingScanFail", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.pool.Exec(ctx, `ALTER TABLE outbox ALTER COLUMN state_version DROP DEFAULT`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.pool.Exec(ctx, `ALTER TABLE outbox ALTER COLUMN state_version TYPE bytea USING '\x00'::bytea`); err != nil {
			t.Fatal(err)
		}
		if _, err := st.OutboxEnqueueVersioned(ctx, OutboxItem{ID: pgITNewID(t), Kind: "gap", LogicalKey: "gap-maxpending", StateVersion: 1}); err == nil {
			t.Fatal("enqueue with a mistyped state_version succeeded")
		}
	})

	t.Run("deleteFail", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.pool.Exec(ctx, `INSERT INTO outbox (id, kind, payload, created_at, logical_key, state_version) VALUES ($1,'gap','{}',now(),'gap-delete',1)`, pgITNewID(t)); err != nil {
			t.Fatal(err)
		}
		pgITBoomOp(t, st, "outbox", "DELETE")
		if _, err := st.OutboxEnqueueVersioned(ctx, OutboxItem{ID: pgITNewID(t), Kind: "gap", LogicalKey: "gap-delete", StateVersion: 2}); err == nil {
			t.Fatal("enqueue with a failing supersede delete succeeded")
		}
	})

	t.Run("insertFail", func(t *testing.T) {
		st := pgITStore(t)
		pgITBoomOp(t, st, "outbox", "INSERT")
		if _, err := st.OutboxEnqueueVersioned(ctx, OutboxItem{ID: pgITNewID(t), Kind: "gap", LogicalKey: "gap-insert", StateVersion: 1}); err == nil {
			t.Fatal("enqueue with a failing outbox insert succeeded")
		}
	})

	t.Run("idConflictDeadLetter", func(t *testing.T) {
		st := pgITStore(t)
		id := pgITNewID(t)
		if _, err := st.pool.Exec(ctx, `INSERT INTO outbox (id, kind, payload, created_at, logical_key, state_version, dead_lettered_at) VALUES ($1,'gap','{}',now(),'gap-conflict',5,now())`, id); err != nil {
			t.Fatal(err)
		}
		outcome, err := st.OutboxEnqueueVersioned(ctx, OutboxItem{ID: id, Kind: "gap", LogicalKey: "gap-conflict", StateVersion: 1})
		if err != nil || outcome != VersionedSuperseded {
			t.Fatalf("dead-letter id conflict = %v, %v; want superseded", outcome, err)
		}
	})
}
