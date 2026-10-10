package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	v1 "github.com/Bel-Consulting-OU/kiwi-ci/internal/api/v1"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const causalityFragment = `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo a"}]}},"deps":{}}`

// fragmentBodyWithContext injects the fragment id and an external_context into
// a raw fragment body exactly as the wire contract allows. The digest is
// computed from {jobs, deps} only, so the context never changes it.
func fragmentBodyWithContext(t *testing.T, raw, externalContext string) string {
	t.Helper()
	var frag generatedFragment
	if err := json.Unmarshal([]byte(raw), &frag); err != nil {
		t.Fatalf("parse fragment body: %v", err)
	}
	id, err := frag.Digest()
	if err != nil {
		t.Fatalf("fragment digest: %v", err)
	}
	frag.FragmentID = id
	frag.ExternalContext = externalContext
	b, err := json.Marshal(frag)
	if err != nil {
		t.Fatalf("marshal fragment body: %v", err)
	}
	return string(b)
}

// TestGeneratedChildrenCarryCausalityStamp proves the generated children are
// stamped with the parent node, the canonical mutation receipt identity and
// the request's bounded external context, while ordinary enqueued jobs stay
// empty, and that the graph.mutation_committed event carries the mutation id
// and the attached context.
func TestGeneratedChildrenCarryCausalityStamp(t *testing.T) {
	s, run := trustedGenerateServer(t)
	runnerID, task := leaseRunJob(t, s)
	// The ordinary enqueued parent carries no causality stamp.
	s.mu.Lock()
	parent := s.jobs[task.Job.ID]
	s.mu.Unlock()
	if parent.CreatedByNode != "" || parent.CreatedByMutation != "" || parent.ExternalContext != "" {
		t.Fatalf("ordinary enqueued job carries causality fields: %+v", parent)
	}

	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token",
		fragmentBodyWithContext(t, causalityFragment, "plan-42"), leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("generated = %d: %s", w.Code, w.Body.String())
	}
	var res generatedResponse
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.JobIDs) != 1 {
		t.Fatalf("children = %v", res.JobIDs)
	}
	wantMutation := task.Job.ID + ":" + storage.GeneratedFragmentMutationSlotDefault
	s.mu.Lock()
	child := s.jobs[res.JobIDs[0]]
	s.mu.Unlock()
	if child.CreatedByNode != task.Job.ID {
		t.Fatalf("CreatedByNode = %q, want parent %s", child.CreatedByNode, task.Job.ID)
	}
	if child.CreatedByMutation != wantMutation {
		t.Fatalf("CreatedByMutation = %q, want %q", child.CreatedByMutation, wantMutation)
	}
	if child.ExternalContext != "plan-42" {
		t.Fatalf("ExternalContext = %q, want plan-42", child.ExternalContext)
	}

	events, _, err := s.store.ListExecutionEvents(context.Background(), 0, 1000, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	committed := 0
	for _, e := range events {
		if e.Type != model.EventGraphMutationCommitted {
			continue
		}
		committed++
		if e.Payload["mutation"] != wantMutation {
			t.Fatalf("event mutation = %q, want %q", e.Payload["mutation"], wantMutation)
		}
		if e.Payload["external_context_attached"] != "true" || e.Payload["external_context"] != "plan-42" {
			t.Fatalf("event context payload = %+v, want the attached plan-42 context", e.Payload)
		}
	}
	if committed != 1 {
		t.Fatalf("graph.mutation_committed events = %d, want 1", committed)
	}
}

// TestGeneratedFragmentWithoutContextRecordsDetached proves a fragment
// without an external context stamps empty children fields and an event
// payload that records the absence instead of a raw value.
func TestGeneratedFragmentWithoutContextRecordsDetached(t *testing.T) {
	s, run := trustedGenerateServer(t)
	runnerID, task := leaseRunJob(t, s)
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token",
		fragmentBody(t, causalityFragment), leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("generated = %d: %s", w.Code, w.Body.String())
	}
	var res generatedResponse
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	child := s.jobs[res.JobIDs[0]]
	s.mu.Unlock()
	if child.ExternalContext != "" {
		t.Fatalf("ExternalContext = %q, want empty", child.ExternalContext)
	}
	events, _, err := s.store.ListExecutionEvents(context.Background(), 0, 1000, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Type != model.EventGraphMutationCommitted {
			continue
		}
		if e.Payload["external_context_attached"] != "false" {
			t.Fatalf("attached flag = %q, want false", e.Payload["external_context_attached"])
		}
		if _, ok := e.Payload["external_context"]; ok {
			t.Fatalf("detached event carries a raw context: %+v", e.Payload)
		}
	}
}

// TestGeneratedFragmentExternalContextValidation pins the bounded opaque
// grammar at the HTTP boundary: exactly 256 bytes are accepted, anything over
// the bound or carrying a control character is a 400 that inserts nothing.
func TestGeneratedFragmentExternalContextValidation(t *testing.T) {
	post := func(t *testing.T, contextValue string) int {
		t.Helper()
		s, _ := trustedGenerateServer(t)
		runnerID, task := leaseRunJob(t, s)
		w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token",
			fragmentBodyWithContext(t, causalityFragment, contextValue), leaseHeaders(task, runnerID))
		if w.Code == http.StatusCreated {
			s.mu.Lock()
			children := 0
			for _, j := range s.jobs {
				if j.DynamicDepth == 1 {
					children++
				}
			}
			s.mu.Unlock()
			if children == 0 {
				t.Fatal("201 without inserted children")
			}
		}
		return w.Code
	}
	if got := post(t, strings.Repeat("a", 256)); got != http.StatusCreated {
		t.Fatalf("256-byte context = %d, want 201", got)
	}
	if got := post(t, strings.Repeat("a", 257)); got != http.StatusBadRequest {
		t.Fatalf("257-byte context = %d, want 400", got)
	}
	if got := post(t, "line\nbreak"); got != http.StatusBadRequest {
		t.Fatalf("newline context = %d, want 400", got)
	}
	if got := post(t, "tab\there"); got != http.StatusBadRequest {
		t.Fatalf("tab context = %d, want 400", got)
	}
	if got := post(t, "del\x7f"); got != http.StatusBadRequest {
		t.Fatalf("DEL context = %d, want 400", got)
	}
	// The validator itself rejects invalid UTF-8 and non-printable runes
	// (bytes the JSON wire cannot even carry safely are still defined).
	if err := v1.ValidateExternalContext(string([]byte{0xff, 0xfe})); err == nil {
		t.Fatal("invalid UTF-8 accepted by the validator")
	}
	if err := v1.ValidateExternalContext("\u200b"); err == nil {
		t.Fatal("zero-width space accepted by the validator")
	}
	if err := v1.ValidateExternalContext("correlation/42"); err != nil {
		t.Fatalf("printable context rejected: %v", err)
	}
	if err := v1.ValidateExternalContext(""); err != nil {
		t.Fatalf("empty context rejected: %v", err)
	}
}

// TestGeneratedFragmentCausalitySurvivesFSRestart proves the stamping is
// payload-additive: the children, their causality fields and the external
// context survive a full snapshot/restore cycle.
func TestGeneratedFragmentCausalitySurvivesFSRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{
		Repositories: map[string]policy.RepoPolicy{
			"o/r": {GenerateChildGraph: boolPtr(true), CrossRepoTrigger: boolPtr(true)},
		},
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: generatePipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := leaseRunJob(t, s)
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token",
		fragmentBodyWithContext(t, causalityFragment, "restart-correlation"), leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("generated = %d: %s", w.Code, w.Body.String())
	}
	var res generatedResponse
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}

	s2 := fsMatrixReload(t, dir)
	s2.mu.Lock()
	child, ok := s2.jobs[res.JobIDs[0]]
	s2.mu.Unlock()
	if !ok {
		t.Fatal("child missing after restart")
	}
	if child.CreatedByNode != task.Job.ID ||
		child.CreatedByMutation != task.Job.ID+":"+storage.GeneratedFragmentMutationSlotDefault ||
		child.ExternalContext != "restart-correlation" {
		t.Fatalf("causality fields lost across restart: %+v", child)
	}
}
