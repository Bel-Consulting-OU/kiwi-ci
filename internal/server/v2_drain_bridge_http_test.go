package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// registerLegacyRunner registers a pre-field runner: no
// supported_execution_semantics advertisement at all, which the server
// treats as the legacy kiwi.execution.v2 contract.
func registerLegacyRunner(t *testing.T, s *Server) string {
	t.Helper()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"legacy-r","protocol_version": 2, "protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2}`)
	if w.Code != http.StatusOK {
		t.Fatalf("legacy register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	if len(ri.SupportedExecutionSemantics) != 0 {
		t.Fatalf("legacy runner advertised %v, want none", ri.SupportedExecutionSemantics)
	}
	return ri.ID
}

// TestHTTPV2LegacyRunnerDrainBridge is the item-3 end-to-end oracle for the
// audited contradiction: a legacy v2 runner is allowed to LEASE a
// v2-stamped job (the lease predicate admits unadvertised runners to the
// legacy engine), so it must also be able to COMPLETE it — with the field
// omitted, exactly as a pre-field binary sends it. The acceptance must ride
// the persisted lease-time interpreter identity (LeaseInterpreter), never
// inference: a v3-stamped job with the same omission stays 409 (covered by
// TestHTTPCompletionSemanticsMismatch409), and a legacy runner must not be
// able to lease a v3-stamped job at all.
func TestHTTPV2LegacyRunnerDrainBridge(t *testing.T) {
	s := New("token")
	if _, err := s.enqueue(t.Context(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: "version: 1\njobs:\n  j:\n    runtime: container\n    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    steps:\n      - run: echo hi\n",
		Trusted:  true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	var jobID string
	s.mu.Lock()
	for id := range s.jobs {
		jobID = id
		// Simulate a PRE-UPGRADE enqueue: the job carries the legacy v2
		// stamp that was current before kiwi.execution.v3 existed.
		j := s.jobs[id]
		j.ExecutionSemantics = model.LegacyExecutionSemanticsVersion
		s.jobs[id] = j
	}
	s.mu.Unlock()

	runnerID := registerLegacyRunner(t, s)
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("legacy runner lease: %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	if task.Job.ID != jobID {
		t.Fatalf("leased %q, want the v2 job", task.Job.ID)
	}
	if task.Job.ExecutionSemantics != model.LegacyExecutionSemanticsVersion {
		t.Fatalf("leased job stamp = %q", task.Job.ExecutionSemantics)
	}
	// The lease must have PERSISTED the interpreter identity the bridge
	// later trusts: a pre-field runner cannot interpret anything but v2.
	s.mu.Lock()
	leased := s.jobs[jobID]
	s.mu.Unlock()
	if leased.LeaseInterpreter != model.LegacyExecutionSemanticsVersion {
		t.Fatalf("LeaseInterpreter = %q, want %q (lease-time identity not persisted)",
			leased.LeaseInterpreter, model.LegacyExecutionSemanticsVersion)
	}

	// Pre-field completion: the key is EXPLICIT-EMPTY (the production
	// unmarshal of an omitted key is identical; the doJSON test injector
	// leaves an explicit value alone).
	body, _ := json.Marshal(map[string]any{
		"runner_id": runnerID, "lease_token": task.LeaseToken,
		"lease_generation": task.LeaseGeneration, "status": "success",
		"execution_semantics": "",
	})
	w = doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", "token", string(body))
	if w.Code != http.StatusNoContent {
		t.Fatalf("v2 drain completion = %d %s, want 204 (legacy runner executed v2 work it was allowed to lease)", w.Code, w.Body.String())
	}
	s.mu.Lock()
	j := s.jobs[jobID]
	s.mu.Unlock()
	if j.ObservedExecutionSemantics != model.LegacyExecutionSemanticsVersion {
		t.Fatalf("ObservedExecutionSemantics = %q, want the v2 drain stamp", j.ObservedExecutionSemantics)
	}
}

// TestHTTPLegacyRunnerCannotLeaseV3Job pins the other half of the lease
// matrix: an unadvertised legacy runner is admitted ONLY to the v2 engine,
// so a v3-stamped job must stay queued for it — never leased, never
// executed by an interpreter that cannot honor v3 semantics.
func TestHTTPLegacyRunnerCannotLeaseV3Job(t *testing.T) {
	s := New("token")
	if _, err := s.enqueue(t.Context(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: "version: 1\njobs:\n  j:\n    runtime: container\n    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    steps:\n      - run: echo hi\n",
		Trusted:  true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	var jobID string
	s.mu.Lock()
	for id := range s.jobs {
		jobID = id
	}
	if s.jobs[jobID].ExecutionSemantics != model.ExecutionSemanticsVersion {
		s.mu.Unlock()
		t.Fatal("enqueue did not stamp v3")
	}
	s.mu.Unlock()

	runnerID := registerLegacyRunner(t, s)
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("legacy lease of v3 job = %d %s, want 204 with no task", w.Code, w.Body.String())
	}
	s.mu.Lock()
	j := s.jobs[jobID]
	s.mu.Unlock()
	if j.Status != model.StatusQueued {
		t.Fatalf("v3 job status after legacy poll = %q, want queued (never leased)", j.Status)
	}
	if j.LeaseRunnerID != "" {
		t.Fatalf("legacy runner holds the v3 lease: %q", j.LeaseRunnerID)
	}
}

// TestHTTPCurrentEngineLeasingV2JobCannotOmitStamp is the audit-exact
// REFUSAL arm, reachable natively once LeaseInterpreterFor records the
// ENGINE rather than the job stamp: a runner advertising BOTH engines can
// lease a v2-stamped job (the predicate allows it), but it is a post-field
// binary — it knew the completion contract. Its lease must persist the
// current engine identity, and an omitted execution_semantics on completion
// must be refused 409 (only a legacy-v2 or pre-field lease bridges).
func TestHTTPCurrentEngineLeasingV2JobCannotOmitStamp(t *testing.T) {
	s := New("token")
	if _, err := s.enqueue(t.Context(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: "version: 1\njobs:\n  j:\n    runtime: container\n    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    steps:\n      - run: echo hi\n",
		Trusted:  true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	var jobID string
	s.mu.Lock()
	for id := range s.jobs {
		jobID = id
		j := s.jobs[id]
		j.ExecutionSemantics = model.LegacyExecutionSemanticsVersion
		s.jobs[id] = j
	}
	s.mu.Unlock()

	// Dual-advertising (post-field) runner: allowed to lease the v2 job.
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"dual-r","protocol_version":2,"supported_execution_semantics":["kiwi.execution.v2","kiwi.execution.v3"],"protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2}`)
	if w.Code != http.StatusOK {
		t.Fatalf("dual register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("dual runner lease of v2 job: %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	leased := s.jobs[jobID]
	s.mu.Unlock()
	if leased.LeaseInterpreter != model.ExecutionSemanticsVersion {
		t.Fatalf("LeaseInterpreter = %q, want the CURRENT engine identity (not a restatement of the v2 stamp)", leased.LeaseInterpreter)
	}

	// Omission from a post-field engine: refused (no bridge).
	body, _ := json.Marshal(map[string]any{
		"runner_id": ri.ID, "lease_token": task.LeaseToken,
		"lease_generation": task.LeaseGeneration, "status": "success",
		"execution_semantics": "",
	})
	w = doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", "token", string(body))
	if w.Code != http.StatusConflict {
		t.Fatalf("omitted completion from a current engine = %d %s, want 409", w.Code, w.Body.String())
	}
	// The explicit equal stamp still completes the drained job.
	body, _ = json.Marshal(map[string]any{
		"runner_id": ri.ID, "lease_token": task.LeaseToken,
		"lease_generation": task.LeaseGeneration, "status": "success",
		"execution_semantics": model.LegacyExecutionSemanticsVersion,
	})
	w = doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", "token", string(body))
	if w.Code != http.StatusNoContent {
		t.Fatalf("explicit v2 completion from dual engine = %d %s, want 204", w.Code, w.Body.String())
	}
}

// TestDBHTTPV2LegacyRunnerDrainBridge is the DB-mode twin of the fs-mode
// drain bridge: the lease goes through the DB scheduler claim
// (AcquireLeaseAtomic), which must persist the lease-time interpreter
// identity into the durable payload — then a pre-field runner's omitted
// completion is accepted ONLY through that persisted legacy identity.
func TestDBHTTPV2LegacyRunnerDrainBridge(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(t.Context(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: "version: 1\njobs:\n  j:\n    runtime: container\n    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    steps:\n      - run: echo hi\n",
		Trusted:  true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	// Pre-upgrade record: v2-stamped job in the durable store.
	var jobID string
	f.mu.Lock()
	for id, j := range f.jobs {
		jobID = id
		j.ExecutionSemantics = model.LegacyExecutionSemanticsVersion
		f.jobs[id] = j
	}
	f.mu.Unlock()

	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"db-legacy","protocol_version":2,"protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2}`)
	if w.Code != http.StatusOK {
		t.Fatalf("legacy register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("legacy lease in DB mode: %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	leased := f.jobs[jobID]
	f.mu.Unlock()
	if leased.LeaseInterpreter != model.LegacyExecutionSemanticsVersion {
		t.Fatalf("DB-mode LeaseInterpreter = %q, want persisted legacy identity", leased.LeaseInterpreter)
	}

	// Pre-field completion: explicit empty == an omitted key after unmarshal.
	body, _ := json.Marshal(map[string]any{
		"runner_id": ri.ID, "lease_token": task.LeaseToken,
		"lease_generation": task.LeaseGeneration, "status": "success",
		"execution_semantics": "",
	})
	w = doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", "token", string(body))
	if w.Code != http.StatusNoContent {
		t.Fatalf("DB-mode v2 drain completion = %d %s, want 204", w.Code, w.Body.String())
	}
	f.mu.Lock()
	done := f.jobs[jobID]
	f.mu.Unlock()
	if done.ObservedExecutionSemantics != model.LegacyExecutionSemanticsVersion {
		t.Fatalf("ObservedExecutionSemantics = %q, want v2 drain stamp", done.ObservedExecutionSemantics)
	}
}
