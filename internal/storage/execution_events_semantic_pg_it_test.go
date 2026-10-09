package storage

// Semantic execution event integration coverage (findings 12/15) against a
// real PostgreSQL database. Every test owns a throwaway database
// (pgITStore), so seq/watermark assertions are exact.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITAllExecutionEvents lists the whole committed stream.
func pgITAllExecutionEvents(t *testing.T, st *PostgresStore) []model.ExecutionEvent {
	t.Helper()
	events, _, err := st.ListExecutionEvents(context.Background(), 0, MaxExecutionEventLimit, "")
	if err != nil {
		t.Fatalf("list all execution events: %v", err)
	}
	return events
}

// pgITEventByType returns the single event of typ (fails when absent or
// duplicated).
func pgITEventByType(t *testing.T, st *PostgresStore, typ string) model.ExecutionEvent {
	t.Helper()
	var found []model.ExecutionEvent
	for _, e := range pgITAllExecutionEvents(t, st) {
		if e.Type == typ {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("events of type %q = %d, want exactly 1: %+v", typ, len(found), found)
	}
	return found[0]
}

// TestPostgresIntegrationSemanticEventCatalogue proves every semantic event
// type is committed with the expected identity and a small, non-secret
// payload: attempt.created, graph.mutation_committed/replayed,
// artifact.published, checkpoint.published, approval.granted, secret.issued,
// oidc.issued and deployment.started/completed.
func TestPostgresIntegrationSemanticEventCatalogue(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	// Lease -> attempt.created, and the leased job carries the identity the
	// artifact/snapshot commits below need.
	runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	pgITSeedRunner(t, st, runnerID, 2, 0, 0)
	leased, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 2})
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	attempt := pgITEventByType(t, st, model.EventAttemptCreated)
	if attempt.Attempt != 1 || attempt.JobID != jobID || attempt.RunID != runID || attempt.Actor != runnerID {
		t.Fatalf("attempt.created = %+v", attempt)
	}
	if attempt.Payload["runner"] != runnerID || attempt.Payload["job"] != leased.Key {
		t.Fatalf("attempt.created payload = %+v", attempt.Payload)
	}

	// Artifact -> artifact.published (idempotent replay emits nothing).
	art := model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, JobKey: leased.Key, Name: "dist.tar.gz", Size: 42, SHA256: strings.Repeat("ab", 32), LeaseGeneration: 1, CreatedAt: time.Now().UTC()}
	if _, created, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, 1, art); err != nil || !created {
		t.Fatalf("artifact commit = created %v err %v", created, err)
	}
	published := pgITEventByType(t, st, model.EventArtifactPublished)
	if published.Payload["name"] != "dist.tar.gz" || published.Payload["sha256"] != art.SHA256 || published.Payload["size"] != "42" || published.Payload["generation"] != "1" {
		t.Fatalf("artifact.published = %+v", published)
	}
	if _, created, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, 1, art); err != nil || created {
		t.Fatalf("artifact replay = created %v err %v", created, err)
	}
	pgITEventByType(t, st, model.EventArtifactPublished) // still exactly one

	// Snapshot -> checkpoint.published.
	snap := model.SnapshotRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, JobKey: leased.Key, Size: 7, SHA256: strings.Repeat("cd", 32), Phase: "post_job", LeaseGeneration: 1, CreatedAt: time.Now().UTC()}
	if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, 1, 0, snap); err != nil {
		t.Fatalf("snapshot commit: %v", err)
	}
	checkpoint := pgITEventByType(t, st, model.EventCheckpointPublished)
	if checkpoint.Payload["snapshot"] != snap.ID || checkpoint.Payload["phase"] != "post_job" || checkpoint.Payload["sha256"] != snap.SHA256 || checkpoint.Payload["generation"] != "1" {
		t.Fatalf("checkpoint.published = %+v", checkpoint)
	}

	// Graph mutation: first commit, then the identical resubmission replay.
	fragRun, fragJob, fragRunner := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, fragRun, fragJob, pgITRepo)
	pgITSeedRunner(t, st, fragRunner, 1, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: fragJob, RunnerID: fragRunner, TokenHash: []byte("fh"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1}); err != nil {
		t.Fatalf("fragment parent lease: %v", err)
	}
	childID := pgITNewID(t)
	child := pgITJob(fragRun, childID, pgITRepo)
	child.Key = "child-" + childID
	fragReq := GeneratedFragmentRequest{
		ParentJobID: fragJob, RunnerID: fragRunner, LeaseGeneration: 1, LeaseTokenHash: []byte("fh"),
		MutationSlot: "slot-1", FragmentID: "fragment-sha",
		Jobs:     map[string]model.Job{childID: child},
		Children: []GeneratedFragmentChild{{Key: child.Key, ID: childID}},
	}
	if _, replayed, err := st.InsertGeneratedFragmentTx(ctx, fragReq, nil); err != nil || replayed {
		t.Fatalf("fragment commit = replayed %v err %v", replayed, err)
	}
	committed := pgITEventByType(t, st, model.EventGraphMutationCommitted)
	if committed.Payload["slot"] != "slot-1" || committed.Payload["fragment"] != "fragment-sha" || committed.Payload["children"] != "1" || committed.Attempt != 1 {
		t.Fatalf("graph.mutation_committed = %+v", committed)
	}
	if _, replayed, err := st.InsertGeneratedFragmentTx(ctx, fragReq, nil); err != nil || !replayed {
		t.Fatalf("fragment replay = replayed %v err %v", replayed, err)
	}
	replay := pgITEventByType(t, st, model.EventGraphMutationReplayed)
	if replay.Payload["slot"] != "slot-1" || replay.Payload["fragment"] != "fragment-sha" {
		t.Fatalf("graph.mutation_replayed = %+v", replay)
	}

	// Approval -> approval.granted.
	apprRun, apprJob := pgITNewID(t), pgITNewID(t)
	appr := pgITJob(apprRun, apprJob, pgITRepo)
	appr.ApprovalRequired = true
	appr.Status = model.StatusWaitingApproval
	appr.Environment = "production"
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  model.Run{ID: apprRun, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{apprJob: appr},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApproveJob(ctx, apprJob, "alice"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	approval := pgITEventByType(t, st, model.EventApprovalGranted)
	if approval.Actor != "alice" || approval.JobID != apprJob || approval.Payload["environment"] != "production" || approval.Payload["status"] != "queued" {
		t.Fatalf("approval.granted = %+v", approval)
	}

	// Secret issuance -> secret.issued (name/generation only; the replay
	// emits nothing).
	secRun, secJob, secRunner, secj := secretITLeasedJob(t, st)
	_ = secRun
	secReq := secretITRequest(secj, "TOKEN")
	if _, _, err := st.CommitSecretIssuance(ctx, secReq); err != nil {
		t.Fatalf("secret commit: %v", err)
	}
	secret := pgITEventByType(t, st, model.EventSecretIssued)
	if secret.JobID != secJob || secret.Attempt != 1 || secret.Actor != secRunner || len(secret.Payload) != 2 || secret.Payload["secret"] != "TOKEN" || secret.Payload["generation"] != "1" {
		t.Fatalf("secret.issued = %+v", secret)
	}
	if _, _, err := st.CommitSecretIssuance(ctx, secReq); err == nil {
		t.Fatal("bare duplicate secret must be refused")
	}
	pgITEventByType(t, st, model.EventSecretIssued)

	// OIDC issuance -> oidc.issued (no claim values).
	oidcRun, oidcJob, oidcRunner, oidcJobRec := oidcITLeasedJob(t, st)
	_ = oidcRun
	if _, err := st.CommitOIDCIssuance(ctx, oidcITRequest(oidcJobRec, oidcITAudience)); err != nil {
		t.Fatalf("OIDC commit: %v", err)
	}
	oidcEvent := pgITEventByType(t, st, model.EventOIDCIssued)
	if oidcEvent.JobID != oidcJob || oidcEvent.Attempt != 1 || oidcEvent.Actor != oidcRunner {
		t.Fatalf("oidc.issued identity = %+v", oidcEvent)
	}
	if len(oidcEvent.Payload) != 3 || oidcEvent.Payload["audience"] != oidcITAudience || oidcEvent.Payload["kid"] != "kid-1" {
		t.Fatalf("oidc.issued payload = %+v", oidcEvent.Payload)
	}
	if strings.Contains(oidcEvent.Payload["claims"], oidcJobRec.SHA) {
		t.Fatalf("oidc.issued leaked a claim value: %+v", oidcEvent.Payload)
	}

	// Deployment lifecycle -> started then completed (exactly once).
	depRun, depJob := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, depRun, depJob, pgITRepo)
	dep := model.Deployment{ID: pgITNewID(t), RunID: depRun, JobID: depJob, Environment: "staging", Status: model.StatusRunning, CreatedAt: time.Now().UTC()}
	if _, created, err := st.StartDeployment(ctx, dep, model.AuditEvent{ID: pgITNewID(t), Action: "deployment.started"}); err != nil || !created {
		t.Fatalf("deployment start = created %v err %v", created, err)
	}
	if _, created, err := st.StartDeployment(ctx, dep, model.AuditEvent{}); err != nil || created {
		t.Fatalf("deployment start replay = created %v err %v", created, err)
	}
	startedEvent := pgITEventByType(t, st, model.EventDeploymentStarted)
	if startedEvent.Payload["deployment"] != dep.ID || startedEvent.Payload["environment"] != "staging" {
		t.Fatalf("deployment.started = %+v", startedEvent)
	}
	if changed, err := st.FinishDeploymentOnce(ctx, dep.ID, model.StatusSuccess, time.Now().UTC(), model.AuditEvent{ID: pgITNewID(t), Action: "deployment.completed"}); err != nil || !changed {
		t.Fatalf("deployment finish = changed %v err %v", changed, err)
	}
	if changed, err := st.FinishDeploymentOnce(ctx, dep.ID, model.StatusSuccess, time.Now().UTC(), model.AuditEvent{}); err != nil || changed {
		t.Fatalf("deployment finish replay = changed %v err %v", changed, err)
	}
	completedEvent := pgITEventByType(t, st, model.EventDeploymentCompleted)
	if completedEvent.Payload["deployment"] != dep.ID || completedEvent.Payload["status"] != "success" {
		t.Fatalf("deployment.completed = %+v", completedEvent)
	}
}

// blockExecutionEventType installs a BEFORE INSERT trigger that refuses one
// event type, so a semantic append failure can be injected inside the
// mutation transaction. The fixture database is a throwaway clone, so the
// trigger cannot leak across tests; dropExecutionEventBlock removes it anyway.
func blockExecutionEventType(t *testing.T, st *PostgresStore, eventType string) {
	t.Helper()
	ctx := context.Background()
	// CREATE FUNCTION is a utility statement: bind parameters are not
	// allowed inside its body, so the (fixed, internal) event type is
	// embedded as a quoted literal.
	quoted := "'" + strings.ReplaceAll(eventType, "'", "''") + "'"
	ddl := `CREATE OR REPLACE FUNCTION kiwi_it_block_execution_event() RETURNS trigger
		LANGUAGE plpgsql AS $kiwi$
		BEGIN
			IF NEW.event_type = ` + quoted + ` THEN
				RAISE EXCEPTION 'kiwi_it blocked execution event %', NEW.event_type;
			END IF;
			RETURN NEW;
		END;
		$kiwi$`
	if _, err := st.pool.Exec(ctx, ddl); err != nil {
		t.Fatalf("create blocking function: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `CREATE TRIGGER kiwi_it_block_execution_event BEFORE INSERT ON execution_events FOR EACH ROW EXECUTE FUNCTION kiwi_it_block_execution_event()`); err != nil {
		t.Fatalf("create blocking trigger: %v", err)
	}
}

func dropExecutionEventBlock(t *testing.T, st *PostgresStore) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.pool.Exec(ctx, `DROP TRIGGER IF EXISTS kiwi_it_block_execution_event ON execution_events`); err != nil {
		t.Fatalf("drop blocking trigger: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `DROP FUNCTION IF EXISTS kiwi_it_block_execution_event()`); err != nil {
		t.Fatalf("drop blocking function: %v", err)
	}
}

// TestPostgresIntegrationSemanticEventAppendFailureRollsBack proves the DB
// fail-closed contract at representative sites: when the semantic event
// insert fails inside the mutation transaction, the artifact insert and the
// approval both roll back completely (no row, no event), and the same
// mutation succeeds once the failure is removed.
func TestPostgresIntegrationSemanticEventAppendFailureRollsBack(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	pgITSeedRunner(t, st, runnerID, 2, 0, 0)
	leased, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 2})
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	art := model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, JobKey: leased.Key, Name: "dist.tar.gz", Size: 42, SHA256: strings.Repeat("ab", 32), LeaseGeneration: 1, CreatedAt: time.Now().UTC()}

	blockExecutionEventType(t, st, model.EventArtifactPublished)
	if _, _, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, 1, art); err == nil || !strings.Contains(err.Error(), "kiwi_it blocked") {
		t.Fatalf("blocked artifact commit = %v, want the injected append failure", err)
	}
	dropExecutionEventBlock(t, st)
	if _, err := st.artifactByGenerationKey(ctx, jobID, 1, art.Name); err == nil {
		t.Fatal("artifact row survived the rolled-back commit")
	}
	if _, created, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, 1, art); err != nil || !created {
		t.Fatalf("artifact commit after unblock = created %v err %v", created, err)
	}
	pgITEventByType(t, st, model.EventArtifactPublished)

	// Approval site: the audit row is appended before the transactional
	// approval, but the JOB transition and its approval.granted event must
	// roll back together.
	apprRun, apprJob := pgITNewID(t), pgITNewID(t)
	appr := pgITJob(apprRun, apprJob, pgITRepo)
	appr.ApprovalRequired = true
	appr.Status = model.StatusWaitingApproval
	appr.Environment = "production"
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  model.Run{ID: apprRun, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{apprJob: appr},
	}); err != nil {
		t.Fatal(err)
	}
	blockExecutionEventType(t, st, model.EventApprovalGranted)
	if _, err := st.ApproveJob(ctx, apprJob, "alice"); err == nil || !strings.Contains(err.Error(), "kiwi_it blocked") {
		t.Fatalf("blocked approval = %v, want the injected append failure", err)
	}
	dropExecutionEventBlock(t, st)
	if j, err := st.GetJob(ctx, apprJob); err != nil || j.Status != model.StatusWaitingApproval || j.ApprovedBy != "" {
		t.Fatalf("job after rolled-back approval = %+v err %v, want untouched waiting_approval", j, err)
	}
	for _, e := range pgITAllExecutionEvents(t, st) {
		if e.Type == model.EventApprovalGranted {
			t.Fatalf("rolled-back approval left event %+v", e)
		}
	}
	if _, err := st.ApproveJob(ctx, apprJob, "alice"); err != nil {
		t.Fatalf("approval after unblock: %v", err)
	}
	pgITEventByType(t, st, model.EventApprovalGranted)
}

// TestPostgresIntegrationExecutionEventRetention proves the prefix prune on
// real PostgreSQL: only the contiguous oldest prefix is deleted, newer (and
// hole-guarding) events survive, retained_from advances in the same
// transaction, after=retainedFrom stays a valid cursor, and a later append
// keeps allocating monotonic seqs.
func TestPostgresIntegrationExecutionEventRetention(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	seqs := make([]int64, 0, 5)
	for i := 0; i < 5; i++ {
		at := now
		if i == 0 || i == 1 || i == 3 {
			at = old.Add(time.Duration(i) * time.Minute)
		}
		e := model.ExecutionEvent{RunID: pgITNewID(t), Type: model.EventGraphMutationCommitted, Attempt: int64(i + 1), Payload: map[string]string{"slot": "s", "fragment": "f", "children": "1"}, CreatedAt: at}
		if err := st.AppendExecutionEvent(ctx, e); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	events := pgITAllExecutionEvents(t, st)
	if len(events) != 5 {
		t.Fatalf("seeded events = %d, want 5", len(events))
	}
	for _, e := range events {
		seqs = append(seqs, e.Seq)
	}

	// Phase A: events 1,2 old | 3 fresh | 4 old | 5 fresh. The prune deletes
	// the contiguous prefix 1,2 and stops: seq 4 is old but sits behind the
	// fresh seq 3, so deleting it would punch a hole.
	pruned, retained, err := st.PruneExecutionEvents(ctx, now.Add(-24*time.Hour), 2)
	if err != nil || pruned != 2 || retained != seqs[1] {
		t.Fatalf("prune A = %d/%d err %v, want 2/%d", pruned, retained, err, seqs[1])
	}
	if rf, err := st.ExecutionEventRetainedFrom(ctx); err != nil || rf != seqs[1] {
		t.Fatalf("watermark A = %d err %v, want %d", rf, err, seqs[1])
	}
	page, cursor, err := st.ListExecutionEvents(ctx, retained, 100, "")
	if err != nil || len(page) != 3 || page[0].Seq != seqs[2] || cursor != seqs[4] {
		t.Fatalf("after=retainedFrom page = %+v cursor %d err %v, want the survivors %d..%d", page, cursor, err, seqs[2], seqs[4])
	}
	if latest, err := st.LatestExecutionEventSeq(ctx); err != nil || latest != seqs[4] {
		t.Fatalf("latest after prefix prune = %d err %v, want %d", latest, err, seqs[4])
	}
	pruned, retained, err = st.PruneExecutionEvents(ctx, now.Add(-24*time.Hour), 100)
	if err != nil || pruned != 0 || retained != seqs[1] {
		t.Fatalf("prune A2 = %d/%d err %v, want 0/%d (fresh seq 3 guards old seq 4)", pruned, retained, err, seqs[1])
	}

	// Phase B: age the guard too; the prune now advances through 4.
	if _, err := st.pool.Exec(ctx, `UPDATE execution_events SET created_at=$1 WHERE seq = ANY($2)`, old, []int64{seqs[2], seqs[3]}); err != nil {
		t.Fatalf("backdate guard: %v", err)
	}
	pruned, retained, err = st.PruneExecutionEvents(ctx, now.Add(-24*time.Hour), 100)
	if err != nil || pruned != 2 || retained != seqs[3] {
		t.Fatalf("prune B = %d/%d err %v, want 2/%d", pruned, retained, err, seqs[3])
	}

	// Phase C: a new append continues the cursor after the highest surviving
	// seq, never reusing a pruned one.
	if err := st.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: pgITNewID(t), Type: "job.running", ToStatus: "running", CreatedAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("append after prune: %v", err)
	}
	page, _, err = st.ListExecutionEvents(ctx, retained, 100, "")
	if err != nil || len(page) != 2 || page[0].Seq != seqs[4] || page[1].Seq != seqs[4]+1 {
		t.Fatalf("after=retainedFrom page = %+v err %v, want the survivor and the fresh append", page, err)
	}
	// Cursor-expiry truth table against the real watermark: after ==
	// retainedFrom is valid, strictly below is expired.
	expiredCases := []struct {
		after             int64
		wantExpired       bool
		wantFirstSurvivor int64
	}{
		{0, true, 0},
		{retained - 1, true, 0},
		{retained, false, seqs[4]},
		{seqs[4], false, seqs[4] + 1},
	}
	for _, tc := range expiredCases {
		if got := ExecutionEventCursorExpired(tc.after, retained); got != tc.wantExpired {
			t.Errorf("ExecutionEventCursorExpired(%d, %d) = %v, want %v", tc.after, retained, got, tc.wantExpired)
		}
		if tc.wantExpired {
			continue
		}
		page, _, err := st.ListExecutionEvents(ctx, tc.after, 1, "")
		if err != nil || len(page) != 1 || page[0].Seq != tc.wantFirstSurvivor {
			t.Errorf("after=%d first event = %+v err %v, want seq %d", tc.after, page, err, tc.wantFirstSurvivor)
		}
	}
}
