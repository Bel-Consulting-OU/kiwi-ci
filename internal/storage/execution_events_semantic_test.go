package storage

// Semantic execution event coverage (findings 12/13): every meaningful
// mutation emits the documented event with a small, non-secret payload, the
// memStore mirror matches the PostgreSQL emitter shapes (the builders are
// shared), and a replay is distinguishable from a first commit. The fs
// retention compaction is covered here too; the server-level fs append sites
// are covered in internal/server.

import (
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// memEventsSnapshot copies the memStore event stream under its lock.
func memEventsSnapshot(m *memStore) []model.ExecutionEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]model.ExecutionEvent(nil), m.events...)
}

// memEventByType returns the single event of typ, failing the test when it is
// missing or duplicated.
func memEventByType(t *testing.T, m *memStore, typ string) model.ExecutionEvent {
	t.Helper()
	var found []model.ExecutionEvent
	for _, e := range memEventsSnapshot(m) {
		if e.Type == typ {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("events of type %q = %d, want exactly 1: %+v", typ, len(found), found)
	}
	return found[0]
}

// TestMemStoreSemanticAttemptCreated proves the lease emits attempt.created
// with the new generation, the runner as actor and the job key.
func TestMemStoreSemanticAttemptCreated(t *testing.T) {
	m := newMemStore()
	seedLeaseRun(m, leaseJobID)
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	claim := leaseClaimFor(leaseJobID, leaseRunner, 1)
	if _, err := m.AcquireLeaseAtomic(ctx(), claim); err != nil {
		t.Fatalf("lease: %v", err)
	}
	e := memEventByType(t, m, model.EventAttemptCreated)
	if e.Attempt != 1 || e.JobID != leaseJobID || e.RunID != leaseRunID {
		t.Fatalf("attempt.created identity = %+v", e)
	}
	if e.Actor != leaseRunner || e.Payload["runner"] != leaseRunner || e.Payload["job"] != "build" {
		t.Fatalf("attempt.created payload = %+v", e)
	}
	// A failed claim (already running) emits nothing further.
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); err == nil {
		t.Fatal("re-lease of a running job must be refused")
	}
	memEventByType(t, m, model.EventAttemptCreated)
}

// TestMemStoreSemanticGraphMutation proves a first fragment emits
// graph.mutation_committed and an identical resubmission emits
// graph.mutation_replayed with the same slot/fragment, while a conflicting
// digest emits nothing.
func TestMemStoreSemanticGraphMutation(t *testing.T) {
	m := newMemStore()
	generation := seedLeasedParentForGeneration(t, m)
	childID := "dddddddddddddddddddddddddddddddd"
	req := withGeneratedLease(GeneratedFragmentRequest{
		ParentJobID:  testJob.ID,
		MutationSlot: "slot-1",
		FragmentID:   "fragment-sha",
		Jobs:         map[string]model.Job{childID: {ID: childID, RunID: testRun.ID, Key: "child", Status: model.StatusQueued, CreatedAt: time.Now().UTC()}},
		Children:     []GeneratedFragmentChild{{Key: "child", ID: childID}},
	}, generation)
	if _, replayed, err := m.InsertGeneratedFragmentTx(ctx(), req, nil); err != nil || replayed {
		t.Fatalf("commit = replayed %v err %v, want first commit", replayed, err)
	}
	commit := memEventByType(t, m, model.EventGraphMutationCommitted)
	if commit.Payload["slot"] != "slot-1" || commit.Payload["fragment"] != "fragment-sha" || commit.Payload["children"] != "1" {
		t.Fatalf("committed payload = %+v", commit)
	}
	if commit.Attempt != generation || commit.JobID != testJob.ID || commit.Actor != testGeneratedRunnerID {
		t.Fatalf("committed identity = %+v", commit)
	}

	if _, replayed, err := m.InsertGeneratedFragmentTx(ctx(), req, nil); err != nil || !replayed {
		t.Fatalf("resubmission = replayed %v err %v, want replay", replayed, err)
	}
	replay := memEventByType(t, m, model.EventGraphMutationReplayed)
	if replay.Payload["slot"] != "slot-1" || replay.Payload["fragment"] != "fragment-sha" || replay.Payload["children"] != "1" {
		t.Fatalf("replayed payload = %+v", replay)
	}
	// The replay added exactly one event (there is still exactly one
	// committed event; memEventByType would have failed on a duplicate).
	if got := len(memEventsSnapshot(m)); got != 3 { // 2 events here + seed attempt.created
		t.Fatalf("total events = %d, want 3", got)
	}

	conflict := req
	conflict.FragmentID = "different-sha"
	if _, _, err := m.InsertGeneratedFragmentTx(ctx(), conflict, nil); err == nil {
		t.Fatal("different digest in the same slot must conflict")
	}
	for _, e := range memEventsSnapshot(m) {
		if e.Type == model.EventGraphMutationCommitted && e.Payload["fragment"] == "different-sha" {
			t.Fatalf("conflict emitted an event: %+v", e)
		}
	}
}

// TestMemStoreSemanticArtifactAndCheckpoint proves artifact.published and
// checkpoint.published carry only name/digest/size/generation and phase, and
// that an idempotent artifact replay emits nothing.
func TestMemStoreSemanticArtifactAndCheckpoint(t *testing.T) {
	m := newMemStore()
	seedRunningJob(m)

	art := model.ArtifactRecord{ID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", RunID: testRun.ID, JobID: testJob.ID, JobKey: testJob.Key, Name: "dist.tar.gz", Size: 1234, SHA256: strings.Repeat("ab", 32), LeaseGeneration: 1, CreatedAt: time.Now().UTC()}
	if _, created, err := m.InsertArtifactOnceForLease(ctx(), testJob.ID, testRunner.ID, 1, art); err != nil || !created {
		t.Fatalf("artifact commit = created %v err %v", created, err)
	}
	published := memEventByType(t, m, model.EventArtifactPublished)
	if published.Payload["name"] != "dist.tar.gz" || published.Payload["sha256"] != art.SHA256 || published.Payload["size"] != "1234" || published.Payload["generation"] != "1" {
		t.Fatalf("artifact.published payload = %+v", published)
	}
	if len(published.Payload) != 4 {
		t.Fatalf("artifact.published payload has extra keys: %+v", published.Payload)
	}
	// Same digest replay: no new artifact.published.
	if _, created, err := m.InsertArtifactOnceForLease(ctx(), testJob.ID, testRunner.ID, 1, art); err != nil || created {
		t.Fatalf("artifact replay = created %v err %v", created, err)
	}
	memEventByType(t, m, model.EventArtifactPublished) // exactly one still
	// Different digest in the same (job, generation, name): conflict, no event.
	conflict := art
	conflict.ID = "ffffffffffffffffffffffffffffffff"
	conflict.SHA256 = strings.Repeat("cd", 32)
	if _, _, err := m.InsertArtifactOnceForLease(ctx(), testJob.ID, testRunner.ID, 1, conflict); err == nil {
		t.Fatal("digest conflict must fail")
	}
	memEventByType(t, m, model.EventArtifactPublished)

	snap := testSnapshot
	if err := m.InsertSnapshotForLease(ctx(), testJob.ID, testRunner.ID, 1, 10, snap); err != nil {
		t.Fatalf("snapshot commit: %v", err)
	}
	checkpoint := memEventByType(t, m, model.EventCheckpointPublished)
	if checkpoint.Payload["snapshot"] != snap.ID || checkpoint.Payload["phase"] != snap.Phase || checkpoint.Payload["sha256"] != snap.SHA256 || checkpoint.Payload["size"] != "10" || checkpoint.Payload["generation"] != "1" {
		t.Fatalf("checkpoint.published payload = %+v", checkpoint)
	}
}

// TestMemStoreSemanticApproval proves approval.granted records the actor and
// the resulting status transition.
func TestMemStoreSemanticApproval(t *testing.T) {
	m := newMemStore()
	j := testJob
	j.ApprovalRequired = true
	j.Status = model.StatusWaitingApproval
	j.Environment = "production"
	if err := m.UpdateJob(ctx(), j); err != nil {
		t.Fatal(err)
	}
	approved, err := m.ApproveJob(ctx(), testJob.ID, "alice")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if approved.Status != model.StatusQueued || approved.ApprovedBy != "alice" {
		t.Fatalf("approved job = %+v", approved)
	}
	e := memEventByType(t, m, model.EventApprovalGranted)
	if e.Actor != "alice" || e.JobID != testJob.ID || e.RunID != testRun.ID || e.Attempt != 0 {
		t.Fatalf("approval.granted identity = %+v", e)
	}
	if e.Payload["environment"] != "production" || e.Payload["status"] != "queued" {
		t.Fatalf("approval.granted payload = %+v", e)
	}
}

// TestMemStoreSemanticSecretIssued proves secret.issued carries only the
// secret NAME and generation, commits once, and never any sealed material.
func TestMemStoreSemanticSecretIssued(t *testing.T) {
	m := newMemStore()
	req := secretIssueLeaseJob(t, m)
	req.Ciphertext = []byte("sealed-bytes")
	req.EphemeralPublic = []byte("ephemeral")
	req.Nonce = []byte("nonce")
	if _, _, err := m.CommitSecretIssuance(ctx(), req); err != nil {
		t.Fatalf("commit secret: %v", err)
	}
	e := memEventByType(t, m, model.EventSecretIssued)
	if e.RunID != testRun.ID || e.JobID != testJob.ID || e.Attempt != 1 || e.Actor != testRunner.ID {
		t.Fatalf("secret.issued identity = %+v", e)
	}
	if len(e.Payload) != 2 || e.Payload["secret"] != "TOKEN" || e.Payload["generation"] != "1" {
		t.Fatalf("secret.issued payload = %+v (must be name/generation only)", e.Payload)
	}
	for _, v := range e.Payload {
		if strings.Contains(v, "sealed") || strings.Contains(v, "ephemeral") || strings.Contains(v, "nonce") {
			t.Fatalf("secret.issued leaked sealed material: %+v", e.Payload)
		}
	}
	// A same-key bare replay appends no second event.
	if _, _, err := m.CommitSecretIssuance(ctx(), req); err == nil {
		t.Fatal("bare duplicate must be refused")
	}
	memEventByType(t, m, model.EventSecretIssued)
}

// TestMemStoreSemanticOIDCIssued proves oidc.issued carries audience, kid and
// claim KEY names only, never a claim value or the token.
func TestMemStoreSemanticOIDCIssued(t *testing.T) {
	j := oidcIssueTestJob()
	m := seedOIDCIssueMemStore(t, j)
	if _, err := m.CommitOIDCIssuance(ctx(), oidcIssueTestRequest(j)); err != nil {
		t.Fatalf("commit OIDC: %v", err)
	}
	e := memEventByType(t, m, model.EventOIDCIssued)
	if e.RunID != j.RunID || e.JobID != j.ID || e.Attempt != j.LeaseGeneration || e.Actor != j.LeaseRunnerID {
		t.Fatalf("oidc.issued identity = %+v", e)
	}
	if len(e.Payload) != 3 || e.Payload["audience"] != "https://aud.example.com" || e.Payload["kid"] != "kid-1" {
		t.Fatalf("oidc.issued payload = %+v", e.Payload)
	}
	claims := e.Payload["claims"]
	for _, k := range []string{OIDCClaimJobID, OIDCClaimRunID, OIDCClaimRepository, OIDCClaimAudience} {
		if !strings.Contains(claims, k) {
			t.Fatalf("oidc.issued claims %q missing key %q", claims, k)
		}
	}
	for _, secretValue := range []string{j.SHA, j.RepoFullName, j.Ref, j.Event, j.Environment} {
		if strings.Contains(claims, secretValue) {
			t.Fatalf("oidc.issued claims %q leaked value %q", claims, secretValue)
		}
	}
}

// TestMemStoreSemanticDeployments proves deployment.started/completed are
// exactly-once with the record lifecycle.
func TestMemStoreSemanticDeployments(t *testing.T) {
	m := newMemStore()
	_, created, err := m.StartDeployment(ctx(), testDeployment, model.AuditEvent{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Action: "deployment.started"})
	if err != nil || !created {
		t.Fatalf("start = created %v err %v", created, err)
	}
	e := memEventByType(t, m, model.EventDeploymentStarted)
	if e.RunID != testRun.ID || e.JobID != testJob.ID || e.Payload["deployment"] != testDeployment.ID || e.Payload["environment"] != "staging" {
		t.Fatalf("deployment.started = %+v", e)
	}
	// Idempotent replay appends nothing.
	if _, created, err := m.StartDeployment(ctx(), testDeployment, model.AuditEvent{}); err != nil || created {
		t.Fatalf("start replay = created %v err %v", created, err)
	}
	memEventByType(t, m, model.EventDeploymentStarted)

	changed, err := m.FinishDeploymentOnce(ctx(), testDeployment.ID, model.StatusSuccess, time.Now().UTC(), model.AuditEvent{ID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Action: "deployment.completed"})
	if err != nil || !changed {
		t.Fatalf("finish = changed %v err %v", changed, err)
	}
	done := memEventByType(t, m, model.EventDeploymentCompleted)
	if done.Payload["deployment"] != testDeployment.ID || done.Payload["status"] != "success" {
		t.Fatalf("deployment.completed = %+v", done)
	}
	if changed, err := m.FinishDeploymentOnce(ctx(), testDeployment.ID, model.StatusSuccess, time.Now().UTC(), model.AuditEvent{}); err != nil || changed {
		t.Fatalf("finish replay = changed %v err %v", changed, err)
	}
	memEventByType(t, m, model.EventDeploymentCompleted)
}

// TestRepositoryExecutionEventRetentionCompaction proves the fs prefix prune,
// the durable watermark across reloads, the after=retainedFrom-1 continuity
// and that a semantic event survives the compaction.
func TestRepositoryExecutionEventRetentionCompaction(t *testing.T) {
	ctx := ctx()
	dir := t.TempDir()
	repo := New(dir)
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	for i := 0; i < 3; i++ {
		if err := repo.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "run-old", Type: "job.queued", ToStatus: "queued", CreatedAt: old.Add(time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "run-new", Type: model.EventGraphMutationCommitted, Attempt: 2, Payload: map[string]string{"slot": "s1", "fragment": "f1", "children": "1"}, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := repo.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "run-new", Type: "job.running", ToStatus: "running", CreatedAt: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}

	if rf, err := repo.ExecutionEventRetainedFrom(ctx); err != nil || rf != 0 {
		t.Fatalf("initial watermark = %d err %v, want 0", rf, err)
	}
	pruned, retained, err := repo.PruneExecutionEvents(ctx, now.Add(-24*time.Hour), 2)
	if err != nil || pruned != 2 || retained != 2 {
		t.Fatalf("prune 1 = %d/%d err %v, want 2/2", pruned, retained, err)
	}
	page, cursor, err := repo.ListExecutionEvents(ctx, retained-1, 100, "")
	if err != nil || len(page) != 3 || page[0].Seq != 3 || cursor != 5 {
		t.Fatalf("after=retainedFrom-1 page = %+v cursor %d err %v, want seqs 3..5", page, cursor, err)
	}
	// A second prune finishes the old prefix and stops at the first fresh
	// event; the semantic event and its payload survive.
	pruned, retained, err = repo.PruneExecutionEvents(ctx, now.Add(-24*time.Hour), 100)
	if err != nil || pruned != 1 || retained != 3 {
		t.Fatalf("prune 2 = %d/%d err %v, want 1/3", pruned, retained, err)
	}
	page, _, err = repo.ListExecutionEvents(ctx, retained-1, 100, "")
	if err != nil || len(page) != 2 || page[0].Type != model.EventGraphMutationCommitted {
		t.Fatalf("post-prune page = %+v err %v, want the semantic event first", page, err)
	}
	if page[0].Payload["slot"] != "s1" || page[0].Attempt != 2 {
		t.Fatalf("semantic event mangled by compaction: %+v", page[0])
	}
	// The watermark and survivors survive a restart.
	repo2 := New(dir)
	if _, err := repo2.Load(); err != nil {
		t.Fatal(err)
	}
	if rf, err := repo2.ExecutionEventRetainedFrom(ctx); err != nil || rf != 3 {
		t.Fatalf("reloaded watermark = %d err %v, want 3", rf, err)
	}
	if err := repo2.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "run-new", Type: "run.running", ToStatus: "running", CreatedAt: now.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	page, _, err = repo2.ListExecutionEvents(ctx, 3, 100, "")
	if err != nil || len(page) != 3 || page[2].Seq != 6 {
		t.Fatalf("post-restart page = %+v err %v, want seq 6 appended", page, err)
	}

	// Cursor-expiry boundaries: only after < retainedFrom-1 is expired.
	for _, tc := range []struct {
		after    int64
		retained int64
		expired  bool
	}{
		{0, 0, false},
		{0, 3, true},
		{1, 3, true},
		{2, 3, false},
		{3, 3, false},
		{4, 3, false},
	} {
		if got := ExecutionEventCursorExpired(tc.after, tc.retained); got != tc.expired {
			t.Errorf("ExecutionEventCursorExpired(%d, %d) = %v, want %v", tc.after, tc.retained, got, tc.expired)
		}
	}
}
