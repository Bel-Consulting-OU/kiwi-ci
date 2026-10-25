package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// rerunServer enqueues a TRUSTED run and configures two principals:
// rerun-only ("rerun-token", ActionRerun but not ActionTrustedRun) and
// rerun+trusted_run ("trusted-token").
func rerunServer(t *testing.T) (*Server, model.Run) {
	t.Helper()
	s := storeServer(t, "", map[string]auth.Principal{
		"rerun-token":   {Subject: "rerun-bot", Roles: []auth.Role{auth.RoleRerun}},
		"trusted-token": {Subject: "trusted-bot", Roles: []auth.Role{auth.RoleRerun, auth.RoleTrustedRun}},
	})
	run, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/kiwi/repo.git", RepoFullName: "kiwi/repo",
		Ref: "main", SHA: "abc", Event: "push",
		Pipeline: testPipeline, Trusted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, run
}

func rerunAs(t *testing.T, s *Server, token, runID string) model.Run {
	t.Helper()
	c := newTestClientForServer(t, s, token)
	w := c.do(http.MethodPost, "/api/v1/runs/"+runID+"/rerun", nil, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("rerun = %d: %s", w.Code, w.Body.String())
	}
	var out model.Run
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Metadata["rerun_of"] != runID {
		t.Fatalf("rerun_of = %q, want %q", out.Metadata["rerun_of"], runID)
	}
	return out
}

// TestRerunTrustedRunDowngradedWithoutTrustedRun proves the bilateral rule:
// a principal holding ActionRerun but NOT ActionTrustedRun still reruns a
// trusted run, but the new run is downgraded to untrusted.
func TestRerunTrustedRunDowngradedWithoutTrustedRun(t *testing.T) {
	s, run := rerunServer(t)
	out := rerunAs(t, s, "rerun-token", run.ID)
	if out.Trusted {
		t.Fatal("rerun without trusted_run must be untrusted")
	}
}

// TestRerunTrustedRunPreservedWithTrustedRun proves a principal holding
// BOTH ActionRerun and ActionTrustedRun keeps the source run's trust.
func TestRerunTrustedRunPreservedWithTrustedRun(t *testing.T) {
	s, run := rerunServer(t)
	out := rerunAs(t, s, "trusted-token", run.ID)
	if !out.Trusted {
		t.Fatal("rerun with trusted_run must preserve trust")
	}
}

// TestRerunUntrustedRunStaysUntrusted: a rerun of an untrusted source run
// never becomes trusted, regardless of the principal.
func TestRerunUntrustedRunStaysUntrusted(t *testing.T) {
	s := storeServer(t, "", map[string]auth.Principal{
		"trusted-token": {Subject: "trusted-bot", Roles: []auth.Role{auth.RoleRerun, auth.RoleTrustedRun}},
	})
	run, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/kiwi/repo.git", RepoFullName: "kiwi/repo",
		Ref: "main", SHA: "abc", Event: "push",
		Pipeline: testPipeline, Trusted: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	out := rerunAs(t, s, "trusted-token", run.ID)
	if out.Trusted {
		t.Fatal("untrusted source run must stay untrusted")
	}
}

// TestRerunDBModeTrustDowngrade proves the same gating on the DB-mode
// rerun path.
func TestRerunDBModeTrustDowngrade(t *testing.T) {
	f := newDBFakeStore()
	s := storeServer(t, "", map[string]auth.Principal{
		"rerun-token":   {Subject: "rerun-bot", Roles: []auth.Role{auth.RoleRerun}},
		"trusted-token": {Subject: "trusted-bot", Roles: []auth.Role{auth.RoleRerun, auth.RoleTrustedRun}},
	})
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	run, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/kiwi/repo.git", RepoFullName: "kiwi/repo",
		Ref: "main", SHA: "abc", Event: "push",
		Pipeline: testPipeline, Trusted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out := rerunAs(t, s, "rerun-token", run.ID); out.Trusted {
		t.Fatal("DB-mode rerun without trusted_run must be untrusted")
	}
	if out := rerunAs(t, s, "trusted-token", run.ID); !out.Trusted {
		t.Fatal("DB-mode rerun with trusted_run must preserve trust")
	}
}

// TestRerunStampsExecutionSemantics: a rerun is a NEW execution and is
// stamped with the execution-engine semantics in effect when it is created
// (the enqueue path), with every job of the rerun inheriting the run's stamp.
// Covered in memory and dbFake.
func TestRerunStampsExecutionSemantics(t *testing.T) {
	for _, tc := range []struct {
		name string
		db   bool
	}{{"memory", false}, {"db", true}} {
		t.Run(tc.name, func(t *testing.T) {
			var s *Server
			var f *dbFakeStore
			var run model.Run
			var err error
			if tc.db {
				f = newDBFakeStore()
				s = storeServer(t, "", map[string]auth.Principal{
					"trusted-token": {Subject: "trusted-bot", Roles: []auth.Role{auth.RoleRerun, auth.RoleTrustedRun}},
				})
				if err := s.SwitchToDB(f); err != nil {
					t.Fatal(err)
				}
				run, err = s.enqueue(context.Background(), SubmitRun{
					RepoURL: "https://github.com/kiwi/repo.git", RepoFullName: "kiwi/repo",
					Ref: "main", SHA: "abc", Event: "push",
					Pipeline: testPipeline, Trusted: true,
				})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				s, run = rerunServer(t)
			}
			out := rerunAs(t, s, "trusted-token", run.ID)
			if out.ExecutionSemantics != model.ExecutionSemanticsVersion {
				t.Fatalf("rerun semantics = %q, want %q", out.ExecutionSemantics, model.ExecutionSemanticsVersion)
			}
			var jobs []model.Job
			if f != nil {
				f.mu.Lock()
				for _, j := range f.jobs {
					jobs = append(jobs, j)
				}
				f.mu.Unlock()
			} else {
				s.mu.Lock()
				for _, j := range s.jobs {
					jobs = append(jobs, j)
				}
				s.mu.Unlock()
			}
			assertJobsStampedWithCurrentSemantics(t, out.ID, jobs)
		})
	}
}
