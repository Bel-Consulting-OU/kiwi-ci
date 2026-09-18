package server

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// Part 3: control-plane restart during outbox dispatch in DB mode. The
// scripted fake forge counts remote publications, so "exactly once" is
// asserted against the remote side effect, not just local bookkeeping.

// crashDBOutboxServer builds a server over the shared fake store with the
// scripted forge configured.
func crashDBOutboxServer(t *testing.T, f *dbFakeStore, apiBase string) *Server {
	t.Helper()
	s := New("token")
	s.GitHubToken = "tok"
	s.gitHubAPIBase = apiBase
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestCrashOutboxDispatchRestartExactlyOnceDB covers both mid-dispatch crash
// windows:
//
//  1. the row is claimed by a replica that dies before dispatching: after the
//     restart the fresh claim is honored (no double publish, nothing lost),
//     and the row is reclaimed and published exactly once when the claim
//     expires;
//  2. the remote publication succeeded but the process died before the durable
//     ACK: the restarted flusher re-dispatches idempotently through the
//     persisted check-run mapping (PATCH, never a second POST).
func TestCrashOutboxDispatchRestartExactlyOnceDB(t *testing.T) {
	api, srv := newForgeVersionAPI(t)
	defer srv.Close()
	ctx := context.Background()
	f := newDBFakeStore()
	run := model.Run{ID: "run-dispatch-crash", ForgeKind: "github", ForgeHost: "github.com",
		RepoFullName: "acme/backend", SHA: "sha-dispatch-crash", Status: model.StatusRunning}

	s1 := crashDBOutboxServer(t, f, srv.URL)
	inflight := s1.checkIntent(run, "Pipeline", "queued", "", "queued", nil)
	if err := s1.outbox.Enqueue(inflight); err != nil {
		t.Fatal(err)
	}
	// Mid-flight crash: another replica claimed the row and died before
	// dispatching or acking. The claim survives in the durable store.
	if _, err := f.ClaimOutbox(ctx, "crashed-replica", 10); err != nil {
		t.Fatal(err)
	}

	s2 := crashDBOutboxServer(t, f, srv.URL)
	if err := s2.outbox.ReplayDB(ctx); err != nil {
		t.Fatal(err)
	}
	s2.flushOutbox()
	if posts, patches, _ := api.snapshot(); posts != 0 || patches != 0 {
		t.Fatalf("restart republished a row another replica still claims: posts=%d patches=%d", posts, patches)
	}
	if got := len(s2.outbox.Pending()); got != 1 {
		t.Fatalf("claimed row lost across the restart: pending=%d, want 1", got)
	}

	// The claim expires (the crashed replica is gone): the restarted replica
	// reclaims and publishes exactly once.
	f.mu.Lock()
	f.outboxClaims[inflight.ID] = fakeOutboxClaim{claimer: "crashed-replica", at: time.Now().UTC().Add(-2 * storage.OutboxClaimTTL)}
	f.mu.Unlock()
	f.ForceAllOutboxDue()
	s2.flushOutbox()
	if posts, patches, published := api.snapshot(); posts != 1 || patches != 0 || len(published) != 1 {
		t.Fatalf("reclaimed dispatch = posts=%d patches=%d published=%v, want one publication", posts, patches, published)
	}
	if got := len(s2.outbox.Pending()); got != 0 {
		t.Fatalf("outbox pending after reclaimed dispatch = %d, want 0", got)
	}

	// Remote publication succeeded, crash before the durable ACK: the
	// restarted flusher must PATCH the persisted remote ID, not POST again.
	survivor := s2.checkIntent(run, "build", "completed", "success", "done", nil)
	if err := s2.outbox.Enqueue(survivor); err != nil {
		t.Fatal(err)
	}
	if err := s2.dispatchOutbox(ctx, survivor); err != nil {
		t.Fatalf("remote dispatch before the crash: %v", err)
	}
	if posts, patches, _ := api.snapshot(); posts != 2 || patches != 0 {
		t.Fatalf("pre-crash dispatch = posts=%d patches=%d, want the second POST", posts, patches)
	}

	s3 := crashDBOutboxServer(t, f, srv.URL)
	if err := s3.outbox.ReplayDB(ctx); err != nil {
		t.Fatal(err)
	}
	s3.flushOutbox()
	posts, patches, published := api.snapshot()
	if posts != 2 || patches != 1 {
		t.Fatalf("post-restart re-dispatch = posts=%d patches=%d, want 2/1 (no duplicate remote check)", posts, patches)
	}
	if len(published) == 0 || published[len(published)-1] != "completed" {
		t.Fatalf("published states = %v, want the replayed completed state", published)
	}
	if got := len(s3.outbox.Pending()); got != 0 {
		t.Fatalf("outbox pending after the lost-ACK replay = %d, want 0", got)
	}
}

// TestCrashOutboxDeadLetterRestartDB covers the dead-letter path across a
// restart: an intent that exhausts its attempts is retired durably (out of
// pending, present in the operator listing), a restarted control plane never
// replays it, and an operator requeue after the restart delivers it exactly
// once.
func TestCrashOutboxDeadLetterRestartDB(t *testing.T) {
	api, srv := newForgeVersionAPI(t)
	defer srv.Close()
	api.setFail(true)
	ctx := context.Background()
	f := newDBFakeStore()
	run := model.Run{ID: "run-deadletter-crash", ForgeKind: "github", ForgeHost: "github.com",
		RepoFullName: "acme/backend", SHA: "sha-deadletter", Status: model.StatusSuccess}

	s1 := crashDBOutboxServer(t, f, srv.URL)
	item := s1.checkIntent(run, "Pipeline", "completed", "success", "done", nil)
	if err := s1.outbox.Enqueue(item); err != nil {
		t.Fatal(err)
	}
	driveOutboxAttempts(s1, f, maxOutboxAttempts)
	dead, err := f.OutboxDeadLetters(ctx)
	if err != nil || len(dead) != 1 || dead[0].ID != item.ID {
		t.Fatalf("dead letters before restart = %+v, %v", dead, err)
	}
	if dead[0].Attempts < maxOutboxAttempts || dead[0].LastError == "" {
		t.Fatalf("dead letter context = %+v", dead[0])
	}

	// Restart: the retired row must not come back as pending work and the
	// operator listing must survive.
	s2 := crashDBOutboxServer(t, f, srv.URL)
	if err := s2.outbox.ReplayDB(ctx); err != nil {
		t.Fatal(err)
	}
	if got := len(s2.outbox.Pending()); got != 0 {
		t.Fatalf("dead letter replayed as pending after restart: %d", got)
	}
	s2.flushOutbox()
	if posts, patches, _ := api.snapshot(); posts != 0 || patches != 0 {
		t.Fatalf("restart published a dead letter: posts=%d patches=%d", posts, patches)
	}
	dead, err = f.OutboxDeadLetters(ctx)
	if err != nil || len(dead) != 1 || dead[0].ID != item.ID {
		t.Fatalf("dead letters after restart = %+v, %v", dead, err)
	}

	// Operator recovery on the RESTARTED replica: requeue, heal the forge,
	// and deliver exactly once.
	api.setFail(false)
	if err := f.OutboxRequeue(ctx, item.ID); err != nil {
		t.Fatalf("requeue: %v", err)
	}
	if dead, _ := f.OutboxDeadLetters(ctx); len(dead) != 0 {
		t.Fatalf("dead letters after requeue = %+v", dead)
	}
	f.ForceAllOutboxDue()
	s2.flushOutbox()
	if posts, patches, published := api.snapshot(); posts != 1 || patches != 0 || len(published) != 1 || published[0] != "completed" {
		t.Fatalf("requeued delivery = posts=%d patches=%d published=%v, want one completed publication", posts, patches, published)
	}
	if pending, _ := f.OutboxPending(ctx); len(pending) != 0 {
		t.Fatalf("pending after requeued delivery = %+v, want empty", pending)
	}
}
