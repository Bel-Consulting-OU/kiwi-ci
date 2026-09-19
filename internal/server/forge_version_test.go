package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// forgeVersionAPI is a scripted GitHub check-runs endpoint: it counts
// successful publications (POST/PATCH) by status and can be switched to fail
// every publication attempt, modelling a forge outage.
type forgeVersionAPI struct {
	mu        sync.Mutex
	fail      bool
	posts     int
	patches   int
	published []string
}

func newForgeVersionAPI(t *testing.T) (*forgeVersionAPI, *httptest.Server) {
	t.Helper()
	f := &forgeVersionAPI{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// No remote check exists yet: reconciliation finds nothing.
			_, _ = w.Write([]byte(`{"check_runs":[]}`))
		case http.MethodPost, http.MethodPatch:
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.fail {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"message":"forge down"}`))
				return
			}
			var body struct {
				Status     string `json:"status"`
				Conclusion string `json:"conclusion"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.published = append(f.published, body.Status)
			if r.Method == http.MethodPost {
				f.posts++
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"id": 4242}`))
				return
			}
			f.patches++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id": 4242}`))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	return f, srv
}

func (f *forgeVersionAPI) setFail(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = v
}

func (f *forgeVersionAPI) snapshot() (posts, patches int, published []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.posts, f.patches, append([]string(nil), f.published...)
}

// versionedCheckItems returns the durable versioned forge-check rows,
// optionally including dead letters.
func versionedCheckItems(t *testing.T, f *dbFakeStore, includeDead bool) []storage.OutboxItem {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []storage.OutboxItem{}
	for _, it := range f.outboxItems {
		if it.LogicalKey == "" {
			continue
		}
		if meta, ok := f.outboxMeta[it.ID]; ok && !meta.deadAt.IsZero() && !includeDead {
			continue
		}
		out = append(out, it)
	}
	return out
}

// driveOutboxAttempts flushes the outbox n times, forcing each retry deferral
// to elapse in between (the test analogue of the backoff window passing).
func driveOutboxAttempts(s *Server, f *dbFakeStore, n int) {
	for i := 0; i < n; i++ {
		_, _ = s.outbox.Flush(context.Background(), s.dispatchOutbox)
		f.ForceAllOutboxDue()
	}
}

// TestForgeCheckVersionGuardQueuedRunningCompleted is T1: the FIRST state
// publication (queued) exhausts its attempts and dead-letters while the forge
// is down; the later states still publish and the FINAL remote state is
// completed exactly once. The durable guard must never publish an older
// state after a newer one (including a stale re-enqueue after delivery).
func TestForgeCheckVersionGuardQueuedRunningCompleted(t *testing.T) {
	api, srv := newForgeVersionAPI(t)
	defer srv.Close()
	api.setFail(true)

	f := newDBFakeStore()
	s := New("token")
	s.GitHubToken = "tok"
	s.gitHubAPIBase = srv.URL
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	run := model.Run{ID: "run-1", ForgeKind: "github", ForgeHost: "github.com",
		RepoFullName: "acme/backend", SHA: "sha-1", Status: model.StatusQueued}
	logicalKey := forgeCheckLogicalKey(run.ForgeHost, run.ID, "Pipeline")

	// queued -> state version 1, first publication.
	if err := s.publishForgeStatus(context.Background(), run); err != nil {
		t.Fatalf("enqueue queued state: %v", err)
	}
	queued, err := f.OutboxPending(context.Background())
	if err != nil || len(queued) != 1 {
		t.Fatalf("pending queued state = %+v, %v", queued, err)
	}
	if queued[0].ID != forgeCheckRowID(logicalKey, 1) || queued[0].StateVersion != 1 {
		t.Fatalf("queued row identity = %s v%d, want %s#1", queued[0].ID, queued[0].StateVersion, logicalKey)
	}

	// The forge is down: the first state exhausts its attempts and
	// dead-letters; it must not be published.
	driveOutboxAttempts(s, f, maxOutboxAttempts)
	dead, err := f.OutboxDeadLetters(context.Background())
	if err != nil || len(dead) != 1 {
		t.Fatalf("dead letters after outage = %+v, %v; want the queued state only", dead, err)
	}
	if dead[0].StateVersion != 1 || dead[0].LogicalKey != logicalKey {
		t.Fatalf("dead letter identity = v%d key=%s", dead[0].StateVersion, dead[0].LogicalKey)
	}
	if posts, patches, published := api.snapshot(); posts != 0 || patches != 0 || len(published) != 0 {
		t.Fatalf("outage published states: posts=%d patches=%d %v", posts, patches, published)
	}
	if pending, _ := f.OutboxPending(context.Background()); len(pending) != 0 {
		t.Fatalf("dead-lettered state still pending: %+v", pending)
	}

	// running -> v2, completed -> v3. The newer state supersedes the older
	// PENDING one durably: exactly the newest survives.
	run.Status = model.StatusRunning
	if err := s.publishForgeStatus(context.Background(), run); err != nil {
		t.Fatalf("enqueue running state: %v", err)
	}
	run.Status = model.StatusSuccess
	if err := s.publishForgeStatus(context.Background(), run); err != nil {
		t.Fatalf("enqueue completed state: %v", err)
	}
	pending, err := f.OutboxPending(context.Background())
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending after queued->running->completed = %+v, %v; want only the newest", pending, err)
	}
	if pending[0].StateVersion != 3 || pending[0].ID != forgeCheckRowID(logicalKey, 3) {
		t.Fatalf("surviving pending row = %s v%d, want completed v3", pending[0].ID, pending[0].StateVersion)
	}

	// The forge recovers: the completed state publishes exactly once.
	api.setFail(false)
	if _, err := s.outbox.Flush(context.Background(), s.dispatchOutbox); err != nil {
		t.Fatalf("flush after recovery: %v", err)
	}
	posts, patches, published := api.snapshot()
	if posts != 1 || patches != 0 {
		t.Fatalf("publications after recovery = posts=%d patches=%d, want exactly one POST", posts, patches)
	}
	if len(published) != 1 || published[0] != "completed" {
		t.Fatalf("published states = %v, want [completed] exactly once", published)
	}
	if pending, _ := f.OutboxPending(context.Background()); len(pending) != 0 {
		t.Fatalf("outbox not drained: %+v", pending)
	}

	// A stale re-enqueue of the running state AFTER the completed state was
	// delivered is superseded by the durable watermark: nothing is inserted
	// and nothing can be published late. This is the exact dead-letter/
	// replay regression: the old state must never overwrite the newer one.
	run.Status = model.StatusRunning
	if err := s.publishForgeStatus(context.Background(), run); err != nil {
		t.Fatalf("stale re-enqueue: %v", err)
	}
	if pending, _ := f.OutboxPending(context.Background()); len(pending) != 0 {
		t.Fatalf("stale state was inserted despite a newer delivered state: %+v", pending)
	}
	if _, err := s.outbox.Flush(context.Background(), s.dispatchOutbox); err != nil {
		t.Fatalf("flush with stale state: %v", err)
	}
	if posts, patches, published = api.snapshot(); posts != 1 || patches != 0 || len(published) != 1 || published[0] != "completed" {
		t.Fatalf("older state published after newer: posts=%d patches=%d %v", posts, patches, published)
	}
	// The delivered watermark is durable.
	if got := f.forgeState[logicalKey]; got != 3 {
		t.Fatalf("delivered watermark = %d, want 3", got)
	}
}

// TestForgeCheckSupersedeRaceNewestSurvives is T2: concurrent enqueues of
// versions N and N+1 (from two Outbox instances over one durable store)
// leave exactly the newest pending, and dispatch publishes at most the
// newest — never an older state after a newer one.
func TestForgeCheckSupersedeRaceNewestSurvives(t *testing.T) {
	api, srv := newForgeVersionAPI(t)
	defer srv.Close()

	f := newDBFakeStore()
	s := New("token")
	s.GitHubToken = "tok"
	s.gitHubAPIBase = srv.URL
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	run := model.Run{ID: "run-2", ForgeKind: "github", ForgeHost: "github.com",
		RepoFullName: "acme/backend", SHA: "sha-2", Status: model.StatusQueued}
	logicalKey := forgeCheckLogicalKey(run.ForgeHost, run.ID, "Pipeline")

	// Sequential: v1 pending, then v2 supersedes it.
	if err := s.publishForgeStatus(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	run.Status = model.StatusRunning
	if err := s.publishForgeStatus(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	pending, _ := f.OutboxPending(context.Background())
	if len(pending) != 1 || pending[0].StateVersion != 2 {
		t.Fatalf("sequential supersede pending = %+v, want only v2", pending)
	}

	// Concurrent: two replicas enqueue v2 and v3 over the same durable
	// store. Whichever commits first, exactly v3 must survive.
	itemV2 := s.checkIntent(run, "Pipeline", "in_progress", "", "running", nil)
	successRun := run
	successRun.Status = model.StatusSuccess
	itemV3 := s.checkIntent(successRun, "Pipeline", "completed", "success", "ok", nil)
	o1 := NewOutbox(nil)
	o1.AttachDB(f)
	o2 := NewOutbox(nil)
	o2.AttachDB(f)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = o1.Enqueue(context.Background(), itemV2) }()
	go func() { defer wg.Done(); _ = o2.Enqueue(context.Background(), itemV3) }()
	wg.Wait()

	pending, err := f.OutboxPending(context.Background())
	if err != nil || len(pending) != 1 {
		t.Fatalf("concurrent supersede pending = %+v, %v; want exactly the newest", pending, err)
	}
	if pending[0].StateVersion != 3 || pending[0].ID != forgeCheckRowID(logicalKey, 3) {
		t.Fatalf("surviving row = %s v%d, want completed v3", pending[0].ID, pending[0].StateVersion)
	}
	// No older version survived as a pending or dead row.
	for _, it := range versionedCheckItems(t, f, true) {
		if it.StateVersion < 3 {
			t.Fatalf("older version survived durable state: %+v", it)
		}
	}

	// Dispatch only the newest: the durable guard must never publish the
	// older state (which is no longer even present).
	if _, err := s.outbox.Flush(context.Background(), s.dispatchOutbox); err != nil {
		t.Fatalf("flush: %v", err)
	}
	_, _, published := api.snapshot()
	if len(published) != 1 || published[0] != "completed" {
		t.Fatalf("published states = %v, want only [completed]", published)
	}
	if got := f.forgeState[logicalKey]; got != 3 {
		t.Fatalf("delivered watermark = %d, want 3", got)
	}
}

// TestForgeCheckVersionGuardFailsClosed pins the fail-closed guard: when the
// durable guard read fails, the dispatch must fail (no ACK) instead of
// publishing without the version check.
func TestForgeCheckVersionGuardFailsClosed(t *testing.T) {
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"check_runs":[]}`))
			return
		}
		posts++
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id": 7}`))
	}))
	defer srv.Close()

	f := newDBFakeStore()
	s := New("token")
	s.GitHubToken = "tok"
	s.gitHubAPIBase = srv.URL
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	run := model.Run{ID: "run-3", ForgeKind: "github", ForgeHost: "github.com",
		RepoFullName: "acme/backend", SHA: "sha-3", Status: model.StatusSuccess}
	item := s.checkIntent(run, "Pipeline", "completed", "success", "ok", nil)
	// The row must exist durably: the guard skips a row a concurrent
	// supersede deleted.
	if err := s.outbox.Enqueue(context.Background(), item); err != nil {
		t.Fatalf("enqueue versioned intent: %v", err)
	}
	f.mu.Lock()
	f.outboxGuardErr = errors.New("guard store down")
	f.mu.Unlock()
	if err := s.dispatchOutbox(context.Background(), item); err == nil {
		t.Fatal("guard read failure must fail the dispatch")
	}
	if posts != 0 {
		t.Fatalf("dispatch published %d times without the guard", posts)
	}
	// Once the guard recovers the same intent publishes.
	f.mu.Lock()
	f.outboxGuardErr = nil
	f.mu.Unlock()
	if err := s.dispatchOutbox(context.Background(), item); err != nil {
		t.Fatalf("dispatch after guard recovery: %v", err)
	}
	if posts != 1 {
		t.Fatalf("posts after recovery = %d, want 1", posts)
	}
}

// TestForgeCheckVersionGuardSkipsNewerPending: a newer PENDING version makes
// an older claimed row skip publication (it will be retired, not published),
// so the remote never sees an older state after a newer one was enqueued.
func TestForgeCheckVersionGuardSkipsNewerPending(t *testing.T) {
	var published []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"check_runs":[]}`))
			return
		}
		var body struct {
			Status string `json:"status"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		published = append(published, body.Status)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id": 11}`))
	}))
	defer srv.Close()

	f := newDBFakeStore()
	s := New("token")
	s.GitHubToken = "tok"
	s.gitHubAPIBase = srv.URL
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	run := model.Run{ID: "run-4", ForgeKind: "github", ForgeHost: "github.com",
		RepoFullName: "acme/backend", SHA: "sha-4", Status: model.StatusRunning}
	itemV2 := s.checkIntent(run, "Pipeline", "in_progress", "", "running", nil)
	itemV3 := s.checkIntent(run, "Pipeline", "completed", "success", "ok", nil)

	// Enqueue v2 durably, then v3 (which deletes the pending v2). Recreate
	// the "claimed v2 while v3 arrives" window by inserting v2 directly
	// after v3: the guard must skip v2 even though its row exists.
	f.mu.Lock()
	f.forgeState = map[string]int64{}
	f.outboxItems = nil
	f.outboxMeta = map[string]fakeOutboxMeta{}
	f.mu.Unlock()
	if err := f.OutboxAppend(context.Background(), storage.OutboxItem{ID: itemV3.ID, Kind: itemV3.Kind, Payload: itemV3.Payload, CreatedAt: itemV3.CreatedAt, LogicalKey: itemV3.LogicalKey, StateVersion: itemV3.StateVersion}); err != nil {
		t.Fatal(err)
	}
	// v2 row with a versioned identity that the SQL supersede would have
	// deleted; force-insert it to model the in-flight claim window.
	f.mu.Lock()
	f.outboxItems = append(f.outboxItems, storage.OutboxItem{ID: itemV2.ID, Kind: itemV2.Kind, Payload: itemV2.Payload, CreatedAt: itemV2.CreatedAt, LogicalKey: itemV2.LogicalKey, StateVersion: itemV2.StateVersion})
	f.mu.Unlock()

	if err := s.dispatchOutbox(context.Background(), itemV2); err != nil {
		t.Fatalf("older dispatch must be a guarded skip, got %v", err)
	}
	if len(published) != 0 {
		t.Fatalf("older state was published while a newer one was pending: %v", published)
	}
	if err := s.dispatchOutbox(context.Background(), itemV3); err != nil {
		t.Fatalf("newest dispatch: %v", err)
	}
	if len(published) != 1 || published[0] != "completed" {
		t.Fatalf("published states = %v, want [completed]", published)
	}
}

// TestOutboxDeadLetterLifecycleEndToEnd is T3: an intent that exhausts
// attempts is retired (out of pending and claims), appears in the operator
// listing, requeues, then delivers; deletion works.
func TestOutboxDeadLetterLifecycleEndToEnd(t *testing.T) {
	api, srv := newForgeVersionAPI(t)
	defer srv.Close()
	api.setFail(true)

	f := newDBFakeStore()
	s := New("token")
	s.GitHubToken = "tok"
	s.gitHubAPIBase = srv.URL
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	run := model.Run{ID: "run-3", ForgeKind: "github", ForgeHost: "github.com",
		RepoFullName: "acme/backend", SHA: "sha-3", Status: model.StatusQueued}
	item := s.checkIntent(run, "Pipeline", "in_progress", "", "running", nil)
	if err := s.outbox.Enqueue(context.Background(), item); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Exhaust attempts: the intent is retired with its failure context.
	driveOutboxAttempts(s, f, maxOutboxAttempts)
	dead, err := f.OutboxDeadLetters(context.Background())
	if err != nil || len(dead) != 1 || dead[0].ID != item.ID {
		t.Fatalf("operator listing = %+v, %v", dead, err)
	}
	if dead[0].Attempts != maxOutboxAttempts || dead[0].LastError == "" {
		t.Fatalf("dead letter context = %+v", dead[0])
	}
	// Gone from pending and never claimed.
	pending, _ := f.OutboxPending(context.Background())
	for _, it := range pending {
		if it.ID == item.ID {
			t.Fatalf("dead letter still pending: %+v", it)
		}
	}
	claims, err := f.ClaimOutbox(context.Background(), "lifecycle-claimer", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range claims {
		if it.ID == item.ID {
			t.Fatalf("dead letter claimed: %+v", it)
		}
	}
	// Requeue through the operator store path, heal the forge, deliver.
	if err := f.OutboxRequeue(context.Background(), item.ID); err != nil {
		t.Fatalf("requeue: %v", err)
	}
	if dead, _ := f.OutboxDeadLetters(context.Background()); len(dead) != 0 {
		t.Fatalf("dead letters after requeue = %+v", dead)
	}
	api.setFail(false)
	f.ForceAllOutboxDue()
	if _, err := s.outbox.Flush(context.Background(), s.dispatchOutbox); err != nil {
		t.Fatalf("flush after requeue: %v", err)
	}
	if posts, _, published := api.snapshot(); posts != 1 || len(published) != 1 || published[0] != "in_progress" {
		t.Fatalf("requeued delivery = posts=%d published=%v", posts, published)
	}
	// A second retired intent (fresh logical key: the delivered watermark of
	// the first key would supersede an equal/older state) deletes cleanly.
	second := s.checkIntent(run, "build", "queued", "", "queued", nil)
	if err := s.outbox.Enqueue(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	api.setFail(true)
	driveOutboxAttempts(s, f, maxOutboxAttempts)
	if dead, _ := f.OutboxDeadLetters(context.Background()); len(dead) != 1 || dead[0].ID != second.ID {
		t.Fatalf("second dead letter listing = %+v", dead)
	}
	if err := f.OutboxDelete(context.Background(), second.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := f.OutboxDelete(context.Background(), second.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("delete of missing dead letter = %v, want ErrNotFound", err)
	}
	if dead, _ := f.OutboxDeadLetters(context.Background()); len(dead) != 0 {
		t.Fatalf("dead letters after delete = %+v", dead)
	}
}

// TestOutboxFSVersionedSupersedeSurvivesRestart covers the filesystem store:
// superseded-but-unacked JSONL lines are dropped at load once a newer version
// was delivered, and a stale re-enqueue after delivery is never queued.
func TestOutboxFSVersionedSupersedeSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	store := storage.New(dir)
	key := "fsversionedkey0000000000000000000"
	v1 := forge.OutboxItem{ID: forgeCheckRowID(key, 1), Kind: forge.OutboxKindGitHubCheck,
		Payload: []byte(`{"state_version":1}`), LogicalKey: key, StateVersion: 1}
	v2 := forge.OutboxItem{ID: forgeCheckRowID(key, 2), Kind: forge.OutboxKindGitHubCheck,
		Payload: []byte(`{"state_version":2}`), LogicalKey: key, StateVersion: 2}

	o1 := NewOutbox(store)
	if err := o1.Enqueue(context.Background(), v1); err != nil {
		t.Fatal(err)
	}
	if err := o1.Enqueue(context.Background(), v2); err != nil {
		t.Fatal(err)
	}
	pending := o1.Pending()
	if len(pending) != 1 || pending[0].StateVersion != 2 {
		t.Fatalf("fs supersede pending = %+v, want only v2", pending)
	}
	// Restart BEFORE any flush: the JSONL still holds the superseded v1 line,
	// which must not be replayed as pending.
	o2 := NewOutbox(store)
	pending = o2.Pending()
	if len(pending) != 1 || pending[0].StateVersion != 2 {
		t.Fatalf("fs restart replay = %+v, want only v2", pending)
	}
	// Deliver v2, then restart again and attempt a stale v1: dropped.
	if _, err := o2.Flush(context.Background(), func(context.Context, forge.OutboxItem) error { return nil }); err != nil {
		t.Fatal(err)
	}
	o3 := NewOutbox(store)
	if err := o3.Enqueue(context.Background(), v1); err != nil {
		t.Fatal(err)
	}
	if pending := o3.Pending(); len(pending) != 0 {
		t.Fatalf("stale v1 re-enqueued after delivery: %+v", pending)
	}
	// v3 is newer and is accepted.
	v3 := forge.OutboxItem{ID: forgeCheckRowID(key, 3), Kind: forge.OutboxKindGitHubCheck,
		Payload: []byte(`{"state_version":3}`), LogicalKey: key, StateVersion: 3}
	if err := o3.Enqueue(context.Background(), v3); err != nil {
		t.Fatal(err)
	}
	if pending := o3.Pending(); len(pending) != 1 || pending[0].StateVersion != 3 {
		t.Fatalf("newer version after delivery = %+v, want v3", pending)
	}
}

// TestCompletionReconcileNeverDeadLettersOnForgeFailure is T4: with the
// forge publication path persistently failing, completion_reconcile keeps
// converging the INTERNAL markers and is never dead-lettered, while the
// separate forge_delivery intent owns the retry/dead-letter policy. The
// operator requeue then lets the forge intent deliver.
func TestCompletionReconcileNeverDeadLettersOnForgeFailure(t *testing.T) {
	api, srv := newForgeVersionAPI(t)
	defer srv.Close()

	f := newDBFakeStore()
	s, runnerID, task := effectsFixture(t, f)
	s.GitHubToken = "tok"
	s.gitHubAPIBase = srv.URL
	s.DownstreamAllowlist = map[string][]string{"acme/child": {"o/r"}}
	s.DownstreamPipelineFetcher = func(context.Context, string, string) (string, error) {
		return childPipeline, nil
	}
	crashComplete(t, s, task, runnerID)
	// The fake store does not recompute the run inside CompleteJob; mirror
	// the SQL store's recompute so the completion's run is terminal (the
	// forge_delivery intent only publishes terminal runs).
	f.mu.Lock()
	run := f.runs[task.Job.RunID]
	run.Status = model.StatusSuccess
	f.runs[task.Job.RunID] = run
	f.mu.Unlock()

	// Persistent forge-publication failure: every versioned forge-check
	// enqueue (the forge_delivery path) errors.
	reconcileID := storage.CompletionEffectID(task.Job.ID, task.LeaseGeneration, storage.OutboxKindCompletionReconcile)
	forgeID := storage.CompletionEffectID(task.Job.ID, task.LeaseGeneration, storage.OutboxKindForgeDelivery)
	f.mu.Lock()
	f.outboxVersionErr = errors.New("forge publication path down")
	f.mu.Unlock()

	driveOutboxAttempts(s, f, maxOutboxAttempts+2)

	// The forge intent dead-letters with its own policy...
	dead, err := f.OutboxDeadLetters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(dead) != 1 || dead[0].ID != forgeID {
		t.Fatalf("dead letters = %+v, want only the forge_delivery intent", dead)
	}
	if dead[0].Attempts < maxOutboxAttempts {
		t.Fatalf("forge intent dead-lettered after %d attempts, want >= %d", dead[0].Attempts, maxOutboxAttempts)
	}
	// ...while completion_reconcile is ACKed, never retired...
	f.mu.Lock()
	meta := f.outboxMeta[reconcileID]
	f.mu.Unlock()
	if !meta.deadAt.IsZero() {
		t.Fatalf("completion_reconcile was dead-lettered: %+v", meta)
	}
	f.mu.Lock()
	stillPending := false
	for _, it := range f.outboxItems {
		if it.ID == reconcileID {
			stillPending = true
		}
	}
	f.mu.Unlock()
	if stillPending {
		t.Fatalf("completion_reconcile still pending after internal convergence")
	}
	// ...and the internal invariants converged: usage recorded, deployment
	// finished, run aggregated terminal.
	job, err := f.GetJob(context.Background(), task.Job.ID)
	if err != nil || !job.UsageRecorded || job.Cost <= 0 {
		t.Fatalf("usage effect not applied: %+v err=%v", job, err)
	}
	d := deploymentOfJob(t, f, task.Job.ID)
	if d.FinishedAt == nil || d.Status != model.StatusSuccess {
		t.Fatalf("deployment effect not applied: %+v", d)
	}
	run, err = f.GetRun(context.Background(), task.Job.RunID)
	if err != nil || run.Status != model.StatusSuccess {
		t.Fatalf("run aggregation not applied: %+v err=%v", run, err)
	}

	// Operator recovery: the forge path heals, the dead letter is requeued
	// and the forge_delivery intent delivers the terminal checks itself.
	f.mu.Lock()
	f.outboxVersionErr = nil
	f.mu.Unlock()
	if err := f.OutboxRequeue(context.Background(), forgeID); err != nil {
		t.Fatalf("requeue forge intent: %v", err)
	}
	f.ForceAllOutboxDue()
	if _, err := s.outbox.Flush(context.Background(), s.dispatchOutbox); err != nil {
		t.Fatalf("flush after forge recovery: %v", err)
	}
	// The recovered forge_delivery intent enqueued and delivered the
	// terminal check publications itself; the remote sees only completed
	// states.
	_, _, published := api.snapshot()
	if len(published) == 0 {
		t.Fatal("recovered forge intent did not publish the terminal checks")
	}
	for _, status := range published {
		if status != "completed" {
			t.Fatalf("forge publication emitted non-terminal state %q", status)
		}
	}
}

// legacyForgeCheckPayload builds a pre-0018 forge-check payload: it carries
// the stable coordinates (host + run + check name) and the logical state, but
// no logical_key/state_version fields, exactly like rows persisted before
// migration 0018.
func legacyForgeCheckPayload(t *testing.T, run model.Run, name, status, conclusion, summary string) []byte {
	t.Helper()
	payload, err := jsonMarshal(forge.CheckPayload{
		RunID: run.ID, ForgeKind: run.ForgeKind, ForgeHost: run.ForgeHost,
		RepoFullName: run.RepoFullName, SHA: run.SHA, Name: name,
		Status: status, Conclusion: conclusion, Summary: summary,
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// appendLegacyForgeRow inserts one unversioned pre-0018 row directly into the
// durable fake outbox (NULL logical_key/state_version columns).
func appendLegacyForgeRow(t *testing.T, f *dbFakeStore, run model.Run, name, status, conclusion string) string {
	t.Helper()
	id := forgeCheckLogicalKey(run.ForgeHost, run.ID, name)
	payload := legacyForgeCheckPayload(t, run, name, status, conclusion, name+" "+status)
	f.mu.Lock()
	f.outboxItems = append(f.outboxItems, storage.OutboxItem{
		ID: id, Kind: forge.OutboxKindGitHubCheck, Payload: payload, CreatedAt: time.Now().UTC(),
	})
	f.mu.Unlock()
	return id
}

// TestLegacyForgeCheckRowsObeyVersionWatermark is FA-3: pre-0018 pending rows
// have NULL logical_key/state_version, so the supersede/guard machinery used
// to skip them entirely and a stale legacy state could publish after a newer
// version was delivered. The dispatcher now derives the identity from the
// payload (host + run + name; rank from status) and applies the SAME durable
// watermark guard, stamping the watermark after a successful publication.
func TestLegacyForgeCheckRowsObeyVersionWatermark(t *testing.T) {
	api, srv := newForgeVersionAPI(t)
	defer srv.Close()
	ctx := context.Background()

	f := newDBFakeStore()
	s := New("token")
	s.GitHubToken = "tok"
	s.gitHubAPIBase = srv.URL
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	delivered := model.Run{ID: "legacy-delivered", ForgeKind: "github", ForgeHost: "github.com",
		RepoFullName: "acme/backend", SHA: "sha-delivered", Status: model.StatusSuccess}
	key := forgeCheckLogicalKey(delivered.ForgeHost, delivered.ID, "Pipeline")

	// Deliver the terminal (v3) versioned state first: the durable watermark
	// is now 3.
	if err := s.publishForgeStatus(ctx, delivered); err != nil {
		t.Fatal(err)
	}
	if _, err := s.outbox.Flush(ctx, s.dispatchOutbox); err != nil {
		t.Fatal(err)
	}
	if got := f.forgeState[key]; got != 3 {
		t.Fatalf("watermark after versioned delivery = %d, want 3", got)
	}
	postsBefore, _, publishedBefore := api.snapshot()
	if len(publishedBefore) != 1 || publishedBefore[0] != "completed" {
		t.Fatalf("published before legacy probe = %v, want [completed]", publishedBefore)
	}

	// A stale pre-0018 row (in_progress, rank 2) is claimed and dispatched:
	// the derived guard must skip it (watermark 3 >= 2) without publishing.
	appendLegacyForgeRow(t, f, delivered, "Pipeline", "in_progress", "")
	if _, err := s.outbox.Flush(ctx, s.dispatchOutbox); err != nil {
		t.Fatalf("flush stale legacy row: %v", err)
	}
	if posts, _, published := api.snapshot(); posts != postsBefore || len(published) != len(publishedBefore) {
		t.Fatalf("stale legacy row published after a newer delivered state: posts %d->%d published %v->%v",
			postsBefore, posts, publishedBefore, published)
	}
	if dead, _ := f.OutboxDeadLetters(ctx); len(dead) != 0 {
		t.Fatalf("stale legacy row was dead-lettered instead of retired: %+v", dead)
	}
	if pending, _ := f.OutboxPending(ctx); len(pending) != 0 {
		t.Fatalf("stale legacy row still pending: %+v", pending)
	}
	if got := f.forgeState[key]; got != 3 {
		t.Fatalf("watermark regressed to %d", got)
	}

	// A legacy row with NO watermark for its own logical key publishes
	// exactly once and stamps the watermark to its status rank.
	fresh := model.Run{ID: "legacy-fresh", ForgeKind: "github", ForgeHost: "github.com",
		RepoFullName: "acme/backend", SHA: "sha-fresh", Status: model.StatusSuccess}
	freshKey := forgeCheckLogicalKey(fresh.ForgeHost, fresh.ID, "Pipeline")
	appendLegacyForgeRow(t, f, fresh, "Pipeline", "completed", "success")
	if _, err := s.outbox.Flush(ctx, s.dispatchOutbox); err != nil {
		t.Fatalf("flush fresh legacy row: %v", err)
	}
	posts, _, published := api.snapshot()
	if posts != postsBefore+1 {
		t.Fatalf("legacy publication POSTs = %d, want %d (exactly once)", posts-postsBefore, 1)
	}
	if len(published) != len(publishedBefore)+1 || published[len(published)-1] != "completed" {
		t.Fatalf("legacy publication states = %v, want one appended completed", published)
	}
	if got := f.forgeState[freshKey]; got != 3 {
		t.Fatalf("legacy publication did not stamp the watermark: %d, want 3", got)
	}

	// Any later legacy state at or below the stamped watermark is skipped:
	// the legacy rows now obey the same invariant as versioned ones.
	appendLegacyForgeRow(t, f, fresh, "Pipeline", "in_progress", "")
	if _, err := s.outbox.Flush(ctx, s.dispatchOutbox); err != nil {
		t.Fatalf("flush stale legacy row after stamp: %v", err)
	}
	if postsNow, _, publishedNow := api.snapshot(); postsNow != posts || len(publishedNow) != len(published) {
		t.Fatalf("legacy row published over its own stamped watermark: posts %d->%d published %v->%v",
			posts, postsNow, published, publishedNow)
	}
}

// TestLegacyForgeCheckFSWatermarkGuard covers the fs queue: a legacy row is
// guarded by the in-process delivered watermark, and a successful legacy
// publication stamps it DURABLY (the done journal marker), so a restart still
// blocks a stale state and a stale versioned re-enqueue after it.
func TestLegacyForgeCheckFSWatermarkGuard(t *testing.T) {
	api, srv := newForgeVersionAPI(t)
	defer srv.Close()
	ctx := context.Background()
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.GitHubToken = "tok"
	s.gitHubAPIBase = srv.URL
	run := model.Run{ID: "legacy-fs", ForgeKind: "github", ForgeHost: "github.com",
		RepoFullName: "acme/backend", SHA: "sha-legacy-fs", Status: model.StatusSuccess}
	key := forgeCheckLogicalKey(run.ForgeHost, run.ID, "Pipeline")
	item := forge.OutboxItem{
		ID: key, Kind: forge.OutboxKindGitHubCheck,
		Payload: legacyForgeCheckPayload(t, run, "Pipeline", "completed", "success", "pipeline success"),
	}
	if err := s.dispatchOutbox(ctx, item); err != nil {
		t.Fatalf("legacy fs dispatch: %v", err)
	}
	if posts, _, published := api.snapshot(); posts != 1 || len(published) != 1 || published[0] != "completed" {
		t.Fatalf("legacy fs publication = posts=%d %v, want one completed", posts, published)
	}

	// A restart rebuilds the watermark from the durable done-journal marker.
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.GitHubToken = "tok"
	s2.gitHubAPIBase = srv.URL
	stale := forge.OutboxItem{
		ID: key, Kind: forge.OutboxKindGitHubCheck,
		Payload: legacyForgeCheckPayload(t, run, "Pipeline", "queued", "", "pipeline queued"),
	}
	if err := s2.dispatchOutbox(ctx, stale); err != nil {
		t.Fatalf("stale legacy fs dispatch: %v", err)
	}
	if posts, _, published := api.snapshot(); posts != 1 || len(published) != 1 {
		t.Fatalf("stale legacy fs state published after restart: posts=%d %v", posts, published)
	}

	// A stale VERSIONED re-enqueue (v2) after the legacy v3 publication is
	// dropped by the restored watermark instead of being published late.
	staleVersioned := s2.checkIntent(run, "Pipeline", "in_progress", "", "running", nil)
	if err := s2.outbox.Enqueue(context.Background(), staleVersioned); err != nil {
		t.Fatal(err)
	}
	if pending := s2.outbox.Pending(); len(pending) != 0 {
		t.Fatalf("stale versioned state enqueued after a newer legacy delivery: %+v", pending)
	}
}
