package deploy

import (
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestNormalizeRollbackDefaults(t *testing.T) {
	n := Normalize(pipeline.DeploymentSpec{
		Canary:   []pipeline.Step{{Run: "deploy 10%"}},
		Verify:   []pipeline.Step{{Run: "curl /health"}},
		Rollback: []pipeline.Step{{Run: "deploy previous"}},
	})
	if n.DefaultRollbackCondition != DefaultRollbackCondition {
		t.Fatalf("default rollback condition = %q", n.DefaultRollbackCondition)
	}
	if n.Rollback[0].If != "failure()" {
		t.Fatalf("rollback step default condition = %q, want failure()", n.Rollback[0].If)
	}
	// Explicit conditions are preserved.
	n = Normalize(pipeline.DeploymentSpec{Rollback: []pipeline.Step{{Run: "x", If: "always()"}}})
	if n.Rollback[0].If != "always()" {
		t.Fatalf("explicit rollback condition clobbered: %q", n.Rollback[0].If)
	}
}

func TestEffectiveStepsOrderAndDefaults(t *testing.T) {
	n := Normalize(pipeline.DeploymentSpec{
		Canary:   []pipeline.Step{{Run: "c1", If: ""}, {Run: "c2"}},
		Verify:   []pipeline.Step{{Run: "v1"}},
		Rollback: []pipeline.Step{{Run: "r1", If: "cancelled()"}, {Run: "r2"}},
	})
	steps := n.EffectiveSteps()
	if len(steps) != 5 {
		t.Fatalf("steps = %d, want 5", len(steps))
	}
	order := []string{"c1", "c2", "v1", "r1", "r2"}
	for i, st := range steps {
		if st.Run != order[i] {
			t.Fatalf("step %d run = %q, want %q (order violated)", i, st.Run, order[i])
		}
	}
	// Canary steps keep no default condition.
	if steps[0].If != "" {
		t.Fatalf("canary step got a default condition %q", steps[0].If)
	}
	// Verify defaults to success().
	if steps[2].If != "success()" {
		t.Fatalf("verify default = %q, want success()", steps[2].If)
	}
	// Rollback keeps explicit conditions and defaults the rest.
	if steps[3].If != "cancelled()" {
		t.Fatalf("explicit rollback condition clobbered: %q", steps[3].If)
	}
	if steps[4].If != "failure()" {
		t.Fatalf("rollback default = %q, want failure()", steps[4].If)
	}
	// EffectiveSteps does not mutate the normalized step lists: verify
	// steps still have no condition and rollback defaults were set at
	// Normalize time, not by EffectiveSteps.
	if n.Verify[0].If != "" {
		t.Fatal("EffectiveSteps mutated the verify step list")
	}
}

func TestNormalizeEmpty(t *testing.T) {
	n := Normalize(pipeline.DeploymentSpec{})
	if len(n.EffectiveSteps()) != 0 {
		t.Fatal("empty spec yields steps")
	}
	if n.DefaultRollbackCondition != DefaultRollbackCondition {
		t.Fatal("empty spec must still carry the default rollback condition")
	}
}

func TestNewDeployment(t *testing.T) {
	started := time.Now().UTC().Add(-time.Minute)
	job := model.Job{ID: "j1", RunID: "r1", RepoURL: "https://github.com/o/r.git", SHA: "abc", Environment: "production"}
	d := NewDeployment(job, "alice", &started, &started)
	if d.ID != job.ID || d.RunID != job.RunID || d.Environment != "production" || d.Commit != "abc" {
		t.Fatalf("record fields wrong: %+v", d)
	}
	if d.Status != model.StatusRunning || d.ApprovedBy != "alice" {
		t.Fatalf("status/approval wrong: %+v", d)
	}
	if d.StartedAt == nil || !d.StartedAt.Equal(started) {
		t.Fatalf("started at wrong: %+v", d.StartedAt)
	}
}
