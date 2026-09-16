package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/version"
)

func TestCompiledJobPayloadInTask(t *testing.T) {
	s := New("token")
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	if task.Job.CompiledJobPayload == nil {
		t.Fatal("task job lacks compiled_job_payload")
	}
	p := task.Job.CompiledJobPayload
	if p.SchemaVersion != 1 {
		t.Fatalf("schema version = %d", p.SchemaVersion)
	}
	if p.CompilerVersion != version.Version {
		t.Fatalf("compiler version = %q, want %q", p.CompilerVersion, version.Version)
	}
	// Recompute the digests from the submitted pipeline and compare.
	spec, err := pipeline.Parse([]byte(artifactsPipeline))
	if err != nil {
		t.Fatal(err)
	}
	wantPipelineDigest, err := pipeline.PipelineDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	if p.PipelineDigest != wantPipelineDigest {
		t.Fatalf("pipeline digest = %q, want %q", p.PipelineDigest, wantPipelineDigest)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	cj, ok := g.Jobs[task.Job.Key]
	if !ok {
		t.Fatalf("no compiled job for key %q", task.Job.Key)
	}
	// The enqueue applies the untrusted resource ceilings to the compiled
	// job BEFORE marshaling the payload, so the recomputation must mirror
	// that step to derive the same digest.
	cj = s.applyUntrustedResourceCeilings(cj, task.Job.Trusted)
	cjJSON, err := json.Marshal(cj)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cjJSON)
	wantJobDigest := hex.EncodeToString(sum[:])
	if p.JobDigest != wantJobDigest {
		t.Fatalf("job digest = %q, want %q", p.JobDigest, wantJobDigest)
	}
	// EffectiveJob round-trips into a pipeline.CompiledJob.
	raw, err := json.Marshal(p.EffectiveJob)
	if err != nil {
		t.Fatal(err)
	}
	var rt pipeline.CompiledJob
	if err := json.Unmarshal(raw, &rt); err != nil {
		t.Fatalf("effective job decode: %v", err)
	}
	if rt.ID != cj.ID || rt.BaseID != cj.BaseID {
		t.Fatalf("effective job mismatch: %+v vs %+v", rt, cj)
	}
	// The payload is also served on the redacted listing endpoint.
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/"+task.Job.RunID+"/jobs", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list jobs = %d", w.Code)
	}
	var jobs []struct {
		CompiledJobPayload *model.CompiledJobPayload `json:"compiled_job_payload"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &jobs); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, j := range jobs {
		if j.CompiledJobPayload != nil && j.CompiledJobPayload.JobDigest == p.JobDigest {
			found = true
		}
	}
	if !found {
		t.Fatal("compiled payload not served on the jobs listing")
	}
	_ = runnerID
}
