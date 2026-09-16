package server

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestDownstreamStableKeyDerivation (P1-20): the stable launch key is a
// deterministic sha256 hex of (parent_job, target_repo, target_ref); the
// child run ID is its first 32 hex chars (a valid run ID). Different
// coordinates derive different keys.
func TestDownstreamStableKeyDerivation(t *testing.T) {
	key := downstreamStableKey("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "acme/child", "refs/heads/main")
	if len(key) != 64 {
		t.Fatalf("stable key length = %d, want 64 hex chars", len(key))
	}
	for _, c := range key {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			t.Fatalf("stable key is not lowercase hex: %q", key)
		}
	}
	id := downstreamStableChildRunID(key)
	if len(id) != 32 {
		t.Fatalf("stable child run id length = %d, want 32", len(id))
	}
	if err := storage.ValidateRunID(id); err != nil {
		t.Fatalf("stable child run id invalid: %v", err)
	}
	// Deterministic.
	if again := downstreamStableKey("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "acme/child", "refs/heads/main"); again != key {
		t.Fatal("stable key is not deterministic")
	}
	// Sensitive to every component.
	if downstreamStableKey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "acme/child", "refs/heads/main") == key {
		t.Fatal("parent job id does not affect the key")
	}
	if downstreamStableKey("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "other/child", "refs/heads/main") == key {
		t.Fatal("target repo does not affect the key")
	}
	if downstreamStableKey("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "acme/child", "refs/heads/dev") == key {
		t.Fatal("target ref does not affect the key")
	}
}

// TestDownstreamCrashRecoveryReusesStableChildID (P1-20, memory mode):
// simulate a crash between the reservation and the child launch — the
// reservation is taken, nothing else happens — then recover (expire the
// reservation) and redispatch: the SAME stable child ID is used, so no
// duplicate child can ever exist.
func TestDownstreamCrashRecoveryReusesStableChildID(t *testing.T) {
	s, _ := downstreamServer(t, downstreamPipeline)
	s.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		return childPipeline, nil
	}
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	parentJobID := task.Job.ID
	stable := downstreamStableKey(parentJobID, "acme/child", "refs/heads/main")
	wantChildID := downstreamStableChildRunID(stable)

	// Crash simulation: the reservation is claimed (as dispatchDownstream
	// does right before the fetch/enqueue), then the process dies before
	// the child launch.
	won, err := s.reserveDownstreamLaunch(context.Background(), parentJobID, "acme/child", "refs/heads/main", "tok")
	if err != nil || !won {
		t.Fatalf("reservation: won=%v err=%v", won, err)
	}
	// Recovery: the maintain pass expires the stale reservation.
	s.recoverDownstreamReservations(context.Background(), time.Now().UTC().Add(2*time.Hour))
	// Redispatch uses the SAME stable child ID.
	s.flushOutbox()
	children := childRunsOf(s)
	if len(children) != 1 {
		t.Fatalf("child runs = %d, want 1", len(children))
	}
	if children[0].ID != wantChildID {
		t.Fatalf("child run id = %q, want stable id %q", children[0].ID, wantChildID)
	}
	// The link is launched with the stable key.
	link, ok, err := s.getDownstreamLink(context.Background(), parentJobID, "acme/child", "refs/heads/main")
	if err != nil || !ok {
		t.Fatalf("link: ok=%v err=%v", ok, err)
	}
	if link.ChildRunID != wantChildID || link.StableChildID != stable || link.Reserved {
		t.Fatalf("link = %+v, want launched with stable id %q", link, wantChildID)
	}
	// A second flush (replayed outbox ack lost) must not create a second
	// child.
	s.flushOutbox()
	if got := childRunsOf(s); len(got) != 1 {
		t.Fatalf("child runs after replay = %d, want 1", len(got))
	}
}

// TestDownstreamConcurrentFlushersStableIDMemory (P1-20, memory mode):
// concurrent flushers of the same intent launch exactly one child, and it
// carries the stable ID.
func TestDownstreamConcurrentFlushersStableIDMemory(t *testing.T) {
	s, _ := downstreamServer(t, downstreamPipeline)
	s.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		return childPipeline, nil
	}
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	parentJobID := task.Job.ID
	item := downstreamPendingItem(t, s)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.dispatchOutbox(context.Background(), item)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
	}
	children := childRunsOf(s)
	if len(children) != 1 {
		t.Fatalf("child runs = %d, want exactly 1", len(children))
	}
	want := downstreamStableChildRunID(downstreamStableKey(parentJobID, "acme/child", "refs/heads/main"))
	if children[0].ID != want {
		t.Fatalf("child run id = %q, want stable id %q", children[0].ID, want)
	}
}

// TestDownstreamStableIDDBModeCrashRecovery (P1-20, DB mode): the launch
// claim inside InsertCompiledRun atomically marks the link; a replayed
// dispatch after a crash re-uses the SAME stable child ID.
func TestDownstreamStableIDDBModeCrashRecovery(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.DownstreamAllowlist = map[string][]string{"acme/child": {"o/r"}}
	s.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{"o/r": {CrossRepoTrigger: boolPtr(true)}}}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: downstreamPipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	parentJobID := task.Job.ID
	stable := downstreamStableKey(parentJobID, "acme/child", "refs/heads/main")
	wantChildID := downstreamStableChildRunID(stable)
	// Crash between reservation and launch: reserve, then "die".
	if won, err := s.reserveDownstreamLaunch(context.Background(), parentJobID, "acme/child", "refs/heads/main", "tok"); err != nil || !won {
		t.Fatalf("reserve: won=%v err=%v", won, err)
	}
	// Recovery expires the reservation, and the replayed dispatch launches
	// the child with the stable ID.
	s.recoverDownstreamReservations(context.Background(), time.Now().UTC().Add(2*time.Hour))
	s.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		return childPipeline, nil
	}
	s.flushOutbox()
	f.mu.Lock()
	childCount := 0
	for _, r := range f.runs {
		if r.RepoFullName == "acme/child" {
			childCount++
			if r.ID != wantChildID {
				t.Fatalf("child run id = %q, want stable id %q", r.ID, wantChildID)
			}
		}
	}
	link, ok := f.downstreamLinks[parentJobID+"\x00acme/child\x00refs/heads/main"]
	f.mu.Unlock()
	if childCount != 1 {
		t.Fatalf("child runs = %d, want 1", childCount)
	}
	if !ok || link.ChildRunID != wantChildID || link.StableChildID != stable || link.Reserved {
		t.Fatalf("link = %+v, want launched with stable id %q", link, wantChildID)
	}
	// Replayed dispatch (ack lost after commit) must not duplicate.
	s.flushOutbox()
	f.mu.Lock()
	childCount = 0
	for _, r := range f.runs {
		if r.RepoFullName == "acme/child" {
			childCount++
		}
	}
	f.mu.Unlock()
	if childCount != 1 {
		t.Fatalf("child runs after replay = %d, want 1", childCount)
	}
}
