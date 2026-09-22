package server

// Cross-feature composition: filesystem-mode crash boundaries.
//
// The "crash" is modelled as a fresh server constructed on the SAME data
// directory with no graceful shutdown of the first one: everything the first
// process acknowledged must already be durable, and the reloaded process must
// neither lose acknowledged state (exactly-once report delivery, a live claim)
// nor resurrect state that was revoked (a disabled runner). The staging spool
// prune is composed in too: an abandoned spool file is reclaimed at startup
// while a fresh one is kept.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// composeFSClaim enqueues one run on a fresh persistent server and leases its
// job to a newly registered in-memory runner, returning everything needed to
// act as that runner.
func composeFSClaim(t *testing.T, s *Server) (runnerID string, task Task) {
	t.Helper()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"compose-fs-runner","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: smokePipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	return ri.ID, task
}

// composeFSPostReport delivers one legacy (no delivery_id) test report for a
// claimed task with the server's admin/runner shared token.
func composeFSPostReport(s *Server, task Task, body string) int {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/tests", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer token")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code
}

// composeFoldedRuns reads the durable test-history cache file written by the
// memory/fs fold path and sums the folded run counters. A missing cache file
// means nothing was folded (the cache is disposable by design; the durable
// reports re-derive it).
func composeFoldedRuns(t *testing.T, dataDir string) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dataDir, testHistoryFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0
		}
		t.Fatalf("read test-history cache: %v", err)
	}
	var stats map[string]struct {
		Runs int `json:"runs"`
	}
	if err := json.Unmarshal(raw, &stats); err != nil {
		t.Fatalf("decode test-history cache: %v", err)
	}
	total := 0
	for _, st := range stats {
		total += st.Runs
	}
	return total
}

// TestComposeFSCrashReloadReportDeliveryExactlyOnce kills and reloads the
// server around the report-delivery lifecycle. The boundary before
// persistence must leave nothing behind; the acknowledged delivery must
// survive the reload; and the post-reload resend of the same delivery must
// converge to exactly one report and one folded outcome.
func TestComposeFSCrashReloadReportDeliveryExactlyOnce(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := composeFSClaim(t, s)
	body, _ := legacyReportBody(task.Job.ID, runnerID, task.LeaseToken, task.LeaseGeneration,
		model.TestResult{Name: "it", Class: "C", Duration: 1, Passed: true})

	// Boundary 1: the persistence write fails (crash before the report is
	// durable). Nothing may be acknowledged and nothing may reach the state
	// file.
	s.mu.Lock()
	s.persistFailForTest = errors.New("compose: injected state persist failure")
	s.mu.Unlock()
	if code := composeFSPostReport(s, task, body); code == http.StatusCreated || code == http.StatusOK {
		t.Fatalf("report delivery with a failing persist was acknowledged with %d", code)
	}
	s.mu.Lock()
	s.persistFailForTest = nil
	reportsBeforeCrash := len(s.reports)
	s.mu.Unlock()
	if reportsBeforeCrash != 0 {
		t.Fatalf("failed persist left %d in-memory report ghost(s)", reportsBeforeCrash)
	}

	// Boundary 2: a healthy delivery commits, then the process "crashes".
	if code := composeFSPostReport(s, task, body); code != http.StatusCreated {
		t.Fatalf("report delivery = %d, want 201", code)
	}
	// Do not reuse or gracefully close s: construct the reloaded process over
	// the same durable directory.
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	s2.mu.Lock()
	loaded := len(s2.reports)
	s2.mu.Unlock()
	if loaded != 1 {
		t.Fatalf("reloaded server has %d report(s), want the 1 acknowledged before the crash", loaded)
	}
	if folded := composeFoldedRuns(t, dir); folded != 1 {
		t.Fatalf("folded outcomes after reload = %d, want 1", folded)
	}
	// The resend of the same legacy delivery (no delivery_id) is the dropped
	// response retry: exactly one report, one fold.
	if code := composeFSPostReport(s2, task, body); code != http.StatusOK {
		t.Fatalf("legacy resend after crash = %d, want idempotent 200 (pre-fix: a duplicate report)", code)
	}
	s2.mu.Lock()
	reports := len(s2.reports)
	s2.mu.Unlock()
	if reports != 1 {
		t.Fatalf("reports after the post-crash resend = %d, want 1", reports)
	}
	if folded := composeFoldedRuns(t, dir); folded != 1 {
		t.Fatalf("folded outcomes after the post-crash resend = %d, want 1", folded)
	}

	// Boundary 3: crash again and resend again — still exactly one.
	s3, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	if code := composeFSPostReport(s3, task, body); code != http.StatusOK {
		t.Fatalf("second post-crash resend = %d, want 200", code)
	}
	s3.mu.Lock()
	reports3 := len(s3.reports)
	s3.mu.Unlock()
	if reports3 != 1 {
		t.Fatalf("reports after the second reload = %d, want 1", reports3)
	}
	if folded := composeFoldedRuns(t, dir); folded != 1 {
		t.Fatalf("folded outcomes after the second reload = %d, want 1", folded)
	}
}

// TestComposeFSCrashReloadClaimAndRevocationNotResurrected kills and reloads
// the server with a live claim and a disabled runner: the claim must still be
// running under the same lease on the new process (not unclaimed/resurrected),
// and the disabled runner must still be disabled (no resurrected revocation)
// and receive no new work.
func TestComposeFSCrashReloadClaimAndRevocationNotResurrected(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := composeFSClaim(t, s)

	// A second runner is registered and disabled by an operator before the
	// crash: the revocation must be durable.
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"compose-fs-disabled","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register disabled runner: %d %s", w.Code, w.Body.String())
	}
	var disabled model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &disabled); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+disabled.ID+"/disable", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("disable runner = %d: %s", w.Code, w.Body.String())
	}

	// Crash and reload.
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	s2.mu.Lock()
	reloadedDisabled := s2.runners[disabled.ID].Disabled
	reloadedJob := s2.jobs[task.Job.ID]
	s2.mu.Unlock()
	if !reloadedDisabled {
		t.Fatal("disabled runner was resurrected as enabled after the crash")
	}
	if reloadedJob.Status != model.StatusRunning || reloadedJob.LeaseRunnerID != runnerID || reloadedJob.LeaseGeneration != task.LeaseGeneration {
		t.Fatalf("claimed job state after reload = status %s runner %s gen %d, want the live claim", reloadedJob.Status, reloadedJob.LeaseRunnerID, reloadedJob.LeaseGeneration)
	}
	// The disabled runner receives no new work on the reloaded process.
	if w := doJSON(t, s2, http.MethodPost, "/api/v1/runners/"+disabled.ID+"/next", "token", ""); w.Code == http.StatusOK {
		t.Fatalf("disabled runner received a lease after the crash: %d", w.Code)
	}
	// The surviving claim is still usable: its completion is accepted on the
	// reloaded process and the job reaches a terminal state.
	complete := `{"runner_id":` + jsonStr(runnerID) + `,"lease_token":` + jsonStr(task.LeaseToken) + `,"lease_generation":` + itoa(task.LeaseGeneration) + `,"status":"success"}`
	if w := doJSON(t, s2, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", complete); w.Code != http.StatusNoContent {
		t.Fatalf("completion of the surviving claim = %d, want 204: %s", w.Code, w.Body.String())
	}
	s2.mu.Lock()
	final := s2.jobs[task.Job.ID]
	s2.mu.Unlock()
	if final.Status != model.StatusSuccess {
		t.Fatalf("job status after the surviving claim completed = %s, want success", final.Status)
	}
}

// TestComposeFSCrashReloadStagingDeadOwnerSpoolReclaimed composes the crash
// boundary with the staging area under the single-writer ownership contract:
// when the first owner is gone (Close releases the lock, exactly what process
// exit does), every kiwi-stage-* file left in the replica directory is
// provably a dead owner's and is reclaimed at startup WITHOUT an age floor — a
// fresh-looking file cannot belong to a live handler because no other live
// process can hold the directory lock — while a foreign file is never touched
// and the reloaded ledger starts at zero. Runtime age-based Prune remains for
// files abandoned by the CURRENT process, and the reloaded budget still
// accepts a real upload that stages inside the budget directory.
func TestComposeFSCrashReloadStagingDeadOwnerSpoolReclaimed(t *testing.T) {
	watched := composeTmpWatcher(t)
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	budget := s.StagingBudget()
	if budget == nil {
		t.Fatal("persistent server has no staging budget")
	}
	stagingDir := budget.Dir()
	// Two spool files a dead owner left behind — one aged, one fresh — plus a
	// foreign file that must never be touched.
	abandoned := filepath.Join(stagingDir, staging.FilePrefix+"snapshot-abandoned")
	if err := os.WriteFile(abandoned, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(abandoned, old, old); err != nil {
		t.Fatal(err)
	}
	freshDeadOwner := filepath.Join(stagingDir, staging.FilePrefix+"snapshot-fresh-dead-owner")
	if err := os.WriteFile(freshDeadOwner, []byte("fresh"), 0o600); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(stagingDir, "unrelated.dat")
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(foreign, old, old); err != nil {
		t.Fatal(err)
	}
	// Crash: release ownership and drop the ledger exactly as process exit
	// does, then reload from the same data dir. The persisted replica id
	// resolves the successor to the same replica directory.
	if err := budget.Close(); err != nil {
		t.Fatalf("close the crashed owner: %v", err)
	}
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	for _, dead := range []string{abandoned, freshDeadOwner} {
		if _, err := os.Stat(dead); !os.IsNotExist(err) {
			t.Fatalf("dead owner's spool file %s survived the restart (unaccounted bytes left on disk): %v", filepath.Base(dead), err)
		}
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("restart reclaim touched a foreign file: %v", err)
	}
	b2 := s2.StagingBudget()
	if b2 == nil || b2.Used() != 0 || b2.Dir() != stagingDir {
		t.Fatalf("reloaded staging budget = %v, want dir %q with a fresh zero ledger", b2, stagingDir)
	}
	// Runtime Prune is still age-based for files abandoned by the RUNNING
	// process: an aged spool file is removed, a fresh one is kept.
	runtimeAbandoned := filepath.Join(stagingDir, staging.FilePrefix+"runtime-abandoned")
	if err := os.WriteFile(runtimeAbandoned, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(runtimeAbandoned, old, old); err != nil {
		t.Fatal(err)
	}
	runtimeLive := filepath.Join(stagingDir, staging.FilePrefix+"runtime-live")
	if err := os.WriteFile(runtimeLive, []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := b2.Prune(context.Background()); err != nil || n != 1 {
		t.Fatalf("runtime Prune = (%d, %v), want (1, nil)", n, err)
	}
	if _, err := os.Stat(runtimeAbandoned); !os.IsNotExist(err) {
		t.Fatalf("runtime Prune kept an aged spool file: %v", err)
	}
	if _, err := os.Stat(runtimeLive); err != nil {
		t.Fatalf("runtime Prune removed a fresh spool file: %v", err)
	}
	if err := os.Remove(runtimeLive); err != nil {
		t.Fatal(err)
	}
	// The reloaded budget is usable: a full reservation succeeds and releases.
	res, err := b2.Acquire(context.Background(), 1024)
	if err != nil {
		t.Fatalf("reloaded staging budget refused a reservation: %v", err)
	}
	res.Release()
	// A real cache upload through the reloaded process stages inside the
	// budget directory (never the bare system temp directory).
	runnerID, task := composeFSClaim(t, s2)
	payload := "compose-reloaded-cache-payload"
	if w := doJSONHeaders(t, s2, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/cache/"+strings.Repeat("d", 64), "token", payload, leaseHeaders(task, runnerID)); w.Code != http.StatusCreated {
		t.Fatalf("cache upload after reload = %d: %s", w.Code, w.Body.String())
	}
	if got := b2.Used(); got != 0 {
		t.Fatalf("staging ledger after the reloaded upload = %d, want 0", got)
	}
	if entries := composeTempEntries(t, watched); len(entries) != 0 {
		t.Fatalf("reloaded upload staged into the bare system temp directory: %v", entries)
	}
}
