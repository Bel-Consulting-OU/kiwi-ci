package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// countAuditAction counts recorded audit rows for one action across memory/fs
// and DB-mode stores (callers pass the concrete slice).
func countAuditAction(events []model.AuditEvent, action string) int {
	n := 0
	for _, e := range events {
		if e.Action == action {
			n++
		}
	}
	return n
}

// countExecutionEventType counts execution-stream events of one type.
func countExecutionEventType(events []model.ExecutionEvent, typ string) int {
	n := 0
	for _, e := range events {
		if e.Type == typ {
			n++
		}
	}
	return n
}

// executionEventsForRun reads one run's events through the stable HTTP
// surface, so the test does not depend on the storage retention API shape.
func executionEventsForRun(t *testing.T, s *Server, runID string) []model.ExecutionEvent {
	t.Helper()
	w := doJSON(t, s, http.MethodGet, "/api/v1/events?limit=1000&run_id="+runID, "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list events = %d: %s", w.Code, w.Body.String())
	}
	var page struct {
		Events []model.ExecutionEvent `json:"events"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	return page.Events
}

// TestCancelRunIdempotentMemory pins docs/INVARIANTS.md I8 on the in-memory/fs
// path: repeating POST /runs/{id}/cancel after the first cancel committed
// returns the current run and performs NO second audit append or forge status
// publish, and cancelling an already-successful run is a terminal-state no-op.
// The first cancel keeps its exact behavior (audit row, forge publication,
// job cancellation).
func TestCancelRunIdempotentMemory(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Configure forge publishing so a duplicate publication would be visible.
	s.GitHubToken = "gh-token"
	s.mu.Lock()
	s.runs["run-idem"] = model.Run{
		ID: "run-idem", Status: model.StatusRunning, ForgeKind: "github",
		ForgeHost: "github.com", RepoFullName: "acme/api", SHA: "sha-idem",
	}
	s.jobs["job-idem"] = model.Job{ID: "job-idem", RunID: "run-idem", Key: "build", Status: model.StatusRunning}
	s.mu.Unlock()

	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs/run-idem/cancel", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("first cancel = %d: %s", w.Code, w.Body.String())
	}
	audit, err := s.store.ReadAudit(1000)
	if err != nil {
		t.Fatal(err)
	}
	if got := countAuditAction(audit, "run.cancelled"); got != 1 {
		t.Fatalf("first cancel audit rows = %d, want 1", got)
	}
	pendingAfterFirst := len(s.outbox.Pending())
	if pendingAfterFirst == 0 {
		t.Fatal("first cancel published no forge status")
	}
	s.mu.Lock()
	job := s.jobs["job-idem"]
	s.mu.Unlock()
	if job.Status != model.StatusCancelled {
		t.Fatalf("first cancel job status = %q, want cancelled", job.Status)
	}

	w := doJSON(t, s, http.MethodPost, "/api/v1/runs/run-idem/cancel", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("repeat cancel = %d: %s", w.Code, w.Body.String())
	}
	var got model.Run
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != model.StatusCancelled {
		t.Fatalf("repeat cancel returned status %q, want the current cancelled run", got.Status)
	}
	audit, err = s.store.ReadAudit(1000)
	if err != nil {
		t.Fatal(err)
	}
	if n := countAuditAction(audit, "run.cancelled"); n != 1 {
		t.Fatalf("repeat cancel audit rows = %d, want exactly 1", n)
	}
	if n := len(s.outbox.Pending()); n != pendingAfterFirst {
		t.Fatalf("repeat cancel outbox intents = %d, want unchanged %d (no forge republish)", n, pendingAfterFirst)
	}

	// Cancel-after-success: a terminal run keeps its outcome; the request is
	// a 200 replay with no audit row and no forge publication.
	s.mu.Lock()
	s.runs["run-done"] = model.Run{
		ID: "run-done", Status: model.StatusSuccess, ForgeKind: "github",
		ForgeHost: "github.com", RepoFullName: "acme/api", SHA: "sha-done",
	}
	s.mu.Unlock()
	auditBefore := len(audit)
	pendingBefore := len(s.outbox.Pending())
	w = doJSON(t, s, http.MethodPost, "/api/v1/runs/run-done/cancel", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("cancel-after-success = %d: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != model.StatusSuccess {
		t.Fatalf("cancel-after-success returned status %q, want success", got.Status)
	}
	audit, err = s.store.ReadAudit(1000)
	if err != nil {
		t.Fatal(err)
	}
	if n := countAuditAction(audit, "run.cancelled"); n != 1 {
		t.Fatalf("cancel-after-success audit rows = %d, want 1 (only the real cancel)", n)
	}
	if n := len(s.outbox.Pending()); n != pendingBefore {
		t.Fatalf("cancel-after-success outbox intents = %d, want unchanged %d", n, pendingBefore)
	}
	if len(audit) != auditBefore {
		t.Fatalf("cancel-after-success appended %d audit rows, want 0", len(audit)-auditBefore)
	}
}

// TestCancelRunIdempotentDB is the DB-mode mirror of
// TestCancelRunIdempotentMemory: the second cancel is answered from the
// terminal run without a scheduler call, a second audit row or a forge
// republish.
func TestCancelRunIdempotentDB(t *testing.T) {
	f := newDBFakeStore()
	s := New("admin-tok")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.GitHubToken = "gh-token"
	ctx := context.Background()
	if err := f.InsertRun(ctx, model.Run{
		ID: "run-idem", Status: model.StatusRunning, ForgeKind: "github",
		ForgeHost: "github.com", RepoFullName: "acme/api", SHA: "sha-idem",
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.InsertJob(ctx, model.Job{ID: "job-idem", RunID: "run-idem", Key: "build", Status: model.StatusRunning}); err != nil {
		t.Fatal(err)
	}

	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs/run-idem/cancel", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("first cancel = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	auditRows, cancelCalls, pending := countAuditAction(f.audit, "run.cancelled"), len(f.cancelRunCalls), len(f.outboxItems)
	f.mu.Unlock()
	if auditRows != 1 || cancelCalls != 1 || pending == 0 {
		t.Fatalf("first cancel = audit %d / scheduler %d / outbox %d, want 1/1/>0", auditRows, cancelCalls, pending)
	}

	w := doJSON(t, s, http.MethodPost, "/api/v1/runs/run-idem/cancel", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("repeat cancel = %d: %s", w.Code, w.Body.String())
	}
	var got model.Run
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != model.StatusCancelled {
		t.Fatalf("repeat cancel returned status %q, want the current cancelled run", got.Status)
	}
	f.mu.Lock()
	auditRows2, cancelCalls2, pending2 := countAuditAction(f.audit, "run.cancelled"), len(f.cancelRunCalls), len(f.outboxItems)
	f.mu.Unlock()
	if auditRows2 != 1 || cancelCalls2 != 1 || pending2 != pending {
		t.Fatalf("repeat cancel = audit %d / scheduler %d / outbox %d, want 1/1/%d", auditRows2, cancelCalls2, pending2, pending)
	}

	// Cancel-after-success.
	if err := f.InsertRun(ctx, model.Run{
		ID: "run-done", Status: model.StatusSuccess, ForgeKind: "github",
		ForgeHost: "github.com", RepoFullName: "acme/api", SHA: "sha-done",
	}); err != nil {
		t.Fatal(err)
	}
	auditBefore := auditRows2
	pendingBefore := pending2
	w = doJSON(t, s, http.MethodPost, "/api/v1/runs/run-done/cancel", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("cancel-after-success = %d: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != model.StatusSuccess {
		t.Fatalf("cancel-after-success returned status %q, want success", got.Status)
	}
	f.mu.Lock()
	auditFinal, cancelFinal, pendingFinal := countAuditAction(f.audit, "run.cancelled"), len(f.cancelRunCalls), len(f.outboxItems)
	f.mu.Unlock()
	if auditFinal != auditBefore || cancelFinal != 1 || pendingFinal != pendingBefore {
		t.Fatalf("cancel-after-success = audit %d / scheduler %d / outbox %d, want %d/1/%d",
			auditFinal, cancelFinal, pendingFinal, auditBefore, pendingBefore)
	}
}

// TestApproveJobIdempotentMemory pins docs/INVARIANTS.md I8 for approvals on
// the in-memory/fs path: the first approve transitions waiting_approval ->
// queued with one audit row and one approval.granted event; every repeat on
// the non-terminal approved job returns the current job with no second audit
// row, no second event and the FIRST approver preserved.
func TestApproveJobIdempotentMemory(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.runs["run-appr"] = model.Run{ID: "run-appr", Status: model.StatusRunning}
	s.jobs["job-appr"] = model.Job{ID: "job-appr", RunID: "run-appr", Key: "deploy", Status: model.StatusWaitingApproval, ApprovalRequired: true, Environment: "prod"}
	s.mu.Unlock()

	first := doJSON(t, s, http.MethodPost, "/api/v1/jobs/job-appr/approve", "admin-tok", "")
	if first.Code != http.StatusOK {
		t.Fatalf("first approve = %d: %s", first.Code, first.Body.String())
	}
	var approved model.Job
	if err := json.Unmarshal(first.Body.Bytes(), &approved); err != nil {
		t.Fatal(err)
	}
	if approved.ApprovedBy == "" || approved.Status != model.StatusQueued {
		t.Fatalf("first approve job = %+v, want queued with an approver", approved)
	}
	approver := approved.ApprovedBy
	audit, err := s.store.ReadAudit(1000)
	if err != nil {
		t.Fatal(err)
	}
	if n := countAuditAction(audit, "job.approved"); n != 1 {
		t.Fatalf("first approve audit rows = %d, want 1", n)
	}
	events := executionEventsForRun(t, s, "run-appr")
	if n := countExecutionEventType(events, model.EventApprovalGranted); n != 1 {
		t.Fatalf("first approve events = %d, want 1", n)
	}

	second := doJSON(t, s, http.MethodPost, "/api/v1/jobs/job-appr/approve", "admin-tok", "")
	if second.Code != http.StatusOK {
		t.Fatalf("repeat approve = %d: %s", second.Code, second.Body.String())
	}
	var replayed model.Job
	if err := json.Unmarshal(second.Body.Bytes(), &replayed); err != nil {
		t.Fatal(err)
	}
	if replayed.ApprovedBy != approver || replayed.Status != model.StatusQueued {
		t.Fatalf("repeat approve job = %+v, want the first approval (%s) preserved", replayed, approver)
	}
	audit, err = s.store.ReadAudit(1000)
	if err != nil {
		t.Fatal(err)
	}
	if n := countAuditAction(audit, "job.approved"); n != 1 {
		t.Fatalf("repeat approve audit rows = %d, want exactly 1", n)
	}
	events = executionEventsForRun(t, s, "run-appr")
	if n := countExecutionEventType(events, model.EventApprovalGranted); n != 1 {
		t.Fatalf("repeat approve events = %d, want exactly 1", n)
	}

	// Unchanged refusals: a non-gated job and a terminal job stay 409 and
	// never touch the audit ledger or the event stream.
	s.mu.Lock()
	s.jobs["job-plain"] = model.Job{ID: "job-plain", RunID: "run-appr", Key: "build", Status: model.StatusQueued}
	s.jobs["job-done"] = model.Job{ID: "job-done", RunID: "run-appr", Key: "build", Status: model.StatusSuccess, ApprovalRequired: true}
	s.mu.Unlock()
	for _, tc := range []struct {
		job  string
		want int
	}{{"job-plain", http.StatusConflict}, {"job-done", http.StatusConflict}} {
		if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+tc.job+"/approve", "admin-tok", ""); w.Code != tc.want {
			t.Fatalf("approve %s = %d, want %d", tc.job, w.Code, tc.want)
		}
	}
	audit, err = s.store.ReadAudit(1000)
	if err != nil {
		t.Fatal(err)
	}
	if n := countAuditAction(audit, "job.approved"); n != 1 {
		t.Fatalf("refused approvals appended audit rows: total = %d, want 1", n)
	}
}

// TestApproveJobIdempotentDB is the DB-mode mirror: the second approve is
// answered from the stored approved job without a second audit row, a second
// approval.granted event or an approver rewrite, while the 409 refusals for
// non-gated and terminal jobs are unchanged.
func TestApproveJobIdempotentDB(t *testing.T) {
	f := newDBFakeStore()
	s := New("admin-tok")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.runs["run-appr"] = model.Run{ID: "run-appr", Status: model.StatusRunning}
	f.jobs["job-appr"] = model.Job{ID: "job-appr", RunID: "run-appr", Key: "deploy", Status: model.StatusWaitingApproval, ApprovalRequired: true, Environment: "prod"}
	f.jobs["job-plain"] = model.Job{ID: "job-plain", RunID: "run-appr", Key: "build", Status: model.StatusQueued}
	f.jobs["job-done"] = model.Job{ID: "job-done", RunID: "run-appr", Key: "build", Status: model.StatusSuccess, ApprovalRequired: true}
	f.mu.Unlock()

	first := doJSON(t, s, http.MethodPost, "/api/v1/jobs/job-appr/approve", "admin-tok", "")
	if first.Code != http.StatusOK {
		t.Fatalf("first approve = %d: %s", first.Code, first.Body.String())
	}
	var approved model.Job
	if err := json.Unmarshal(first.Body.Bytes(), &approved); err != nil {
		t.Fatal(err)
	}
	if approved.ApprovedBy == "" || approved.Status != model.StatusQueued {
		t.Fatalf("first approve job = %+v, want queued with an approver", approved)
	}
	approver := approved.ApprovedBy
	f.mu.Lock()
	auditRows, eventRows := countAuditAction(f.audit, "job.approved"), countExecutionEventType(f.executionEvents, model.EventApprovalGranted)
	f.mu.Unlock()
	if auditRows != 1 || eventRows != 1 {
		t.Fatalf("first approve = audit %d / events %d, want 1/1", auditRows, eventRows)
	}

	second := doJSON(t, s, http.MethodPost, "/api/v1/jobs/job-appr/approve", "admin-tok", "")
	if second.Code != http.StatusOK {
		t.Fatalf("repeat approve = %d: %s", second.Code, second.Body.String())
	}
	var replayed model.Job
	if err := json.Unmarshal(second.Body.Bytes(), &replayed); err != nil {
		t.Fatal(err)
	}
	if replayed.ApprovedBy != approver || replayed.Status != model.StatusQueued {
		t.Fatalf("repeat approve job = %+v, want the first approval (%s) preserved", replayed, approver)
	}
	f.mu.Lock()
	auditRows2, eventRows2 := countAuditAction(f.audit, "job.approved"), countExecutionEventType(f.executionEvents, model.EventApprovalGranted)
	f.mu.Unlock()
	if auditRows2 != 1 || eventRows2 != 1 {
		t.Fatalf("repeat approve = audit %d / events %d, want exactly 1/1", auditRows2, eventRows2)
	}

	for _, tc := range []struct {
		job  string
		want int
	}{{"job-plain", http.StatusConflict}, {"job-done", http.StatusConflict}} {
		if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+tc.job+"/approve", "admin-tok", ""); w.Code != tc.want {
			t.Fatalf("approve %s = %d, want %d", tc.job, w.Code, tc.want)
		}
	}
	f.mu.Lock()
	auditFinal := countAuditAction(f.audit, "job.approved")
	f.mu.Unlock()
	if auditFinal != 1 {
		t.Fatalf("refused approvals appended audit rows: total = %d, want 1", auditFinal)
	}
}
