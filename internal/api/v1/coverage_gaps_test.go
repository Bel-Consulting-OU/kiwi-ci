package v1

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestStatusDTOSmoke(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	job := model.Job{
		ID: "j1", RunID: "r1", Key: "job[GO=1]", BaseKey: "job",
		RepoID: "github.com/org/app", RepoURL: "https://github.com/org/app.git",
		Ref: "refs/heads/main", SHA: "abc", Event: "push", Condition: "success()",
		DependencyStatus: model.StatusSuccess, Pipeline: "secret pipeline text",
		Trusted: true, ChangedFiles: []string{"a.go"}, Needs: []string{"build"},
		RequiredLabels: []string{"container"}, Network: "none", Environment: "prod",
		ApprovalRequired: true, EnvironmentBranches: []string{"main"},
		EnvironmentConcurrency: 1, OIDCAllowed: true, OIDCAudiences: []string{"aud"},
		DeclaredSecrets: []string{"S"}, Status: model.StatusRunning, Priority: 2,
		MaxInfraRetries: 1, CreatedAt: now, StartedAt: &now, FinishedAt: &now,
		Error: "boom", Outputs: map[string]string{"o": "v"},
		NeedsOutputs: map[string]map[string]string{"build": {"o": "v"}},
		Attempts:     3, LeaseRunnerID: "runner-1", LeaseGeneration: 4,
		LeaseExpiresAt: &now, ApprovedBy: "op", QueueReason: "RUNNER_CAPACITY",
		PlacementRegions: []string{"eu"}, ComponentDigest: "sha256:1",
		CompiledJobPayload: &model.CompiledJobPayload{SchemaVersion: 1},
		WaitingSince:       &now,
	}
	dto := JobDTOFrom(job)
	if dto.Pipeline != "" {
		t.Fatalf("pipeline must be redacted, got %q", dto.Pipeline)
	}
	if dto.ID != job.ID || dto.LeaseGeneration != 4 || dto.QueueReason != "RUNNER_CAPACITY" {
		t.Fatalf("job dto = %+v", dto)
	}
	if dto.StartedAt == nil || !dto.StartedAt.Equal(now) {
		t.Fatal("started_at not mapped")
	}
	if dto.StartedAt == job.StartedAt {
		t.Fatal("time pointers must be deep-copied")
	}
	raw, err := json.Marshal(dto)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"lease_token_hash", "secret pipeline text"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("redacted JSON leaked %q: %s", forbidden, raw)
		}
	}
	if !strings.Contains(string(raw), `"pipeline":""`) {
		t.Fatalf("pipeline key must stay present and empty: %s", raw)
	}

	empty := JobDTOFrom(model.Job{})
	if empty.StartedAt != nil || empty.FinishedAt != nil || empty.LeaseExpiresAt != nil || empty.WaitingSince != nil {
		t.Fatalf("nil time pointers must stay nil: %+v", empty)
	}

	run := RunDTOFrom(model.Run{ID: "r1", Status: model.StatusSuccess, CreatedAt: now, StartedAt: &now, FinishedAt: &now, Metadata: map[string]string{"k": "v"}})
	if run.ID != "r1" || run.Status != model.StatusSuccess || run.CreatedAt != now {
		t.Fatalf("run dto = %+v", run)
	}
	if RunDTOFrom(model.Run{}).StartedAt != nil {
		t.Fatal("run nil pointers must stay nil")
	}

	rn := RunnerDTOFrom(model.Runner{ID: "runner-1", Labels: []string{"l"}, Completed: 1, Failed: 2, LastSeen: now, Busy: true, RevokedAt: &now})
	if rn.ID != "runner-1" || !rn.Busy || rn.RevokedAt == nil {
		t.Fatalf("runner dto = %+v", rn)
	}
	if RunnerDTOFrom(model.Runner{}).RevokedAt != nil {
		t.Fatal("runner nil pointer must stay nil")
	}

	serving := RunnerServingDTOFrom(model.Runner{ID: "runner-1", Name: "n", Busy: true, LastSeen: now}, []string{"job-1"})
	if serving.ID != "runner-1" || len(serving.ActiveJobs) != 1 || serving.LastSeen != now {
		t.Fatalf("serving dto = %+v", serving)
	}

	art := ArtifactDTOFrom(model.ArtifactRecord{ID: "a1", Size: 3, SHA256: "s", CreatedAt: now, ExpiresAt: &now, ProvenanceSHA256: "p", LeaseGeneration: 2, SBOMSHA256: "b", SigstoreSHA256: "g"})
	if art.ID != "a1" || art.ExpiresAt == nil || art.SigstoreSHA256 != "g" {
		t.Fatalf("artifact dto = %+v", art)
	}
	if ArtifactDTOFrom(model.ArtifactRecord{}).ExpiresAt != nil {
		t.Fatal("artifact nil pointer must stay nil")
	}
}

func TestGeneratedFragmentDigest(t *testing.T) {
	f := GeneratedFragment{
		Jobs: map[string]pipeline.Job{"child": {Steps: []pipeline.Step{{Run: "echo"}}}},
		Deps: map[string][]string{"child": {}},
	}
	d1, err := f.Digest()
	if err != nil {
		t.Fatal(err)
	}
	d2, err := f.Digest()
	if err != nil || d1 != d2 {
		t.Fatalf("digest must be deterministic: %q vs %q (%v)", d1, d2, err)
	}
	if len(d1) != 64 {
		t.Fatalf("digest = %q, want 64 hex chars", d1)
	}

	empty, err := (GeneratedFragment{}).Digest()
	if err != nil || len(empty) != 64 {
		t.Fatalf("nil maps digest = %q, %v", empty, err)
	}

	withDeps, err := (GeneratedFragment{Deps: map[string][]string{"child": {"parent"}}}).Digest()
	if err != nil {
		t.Fatal(err)
	}
	if withDeps == empty {
		t.Fatal("different fragments must not collide")
	}
}
