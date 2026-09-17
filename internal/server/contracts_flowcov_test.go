package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func TestFlowContractsBuildJobContractsEmptyName(t *testing.T) {
	out := buildJobContracts(pipeline.CompiledJob{Job: pipeline.Job{Artifacts: []pipeline.Artifact{{Name: "   "}}}})
	if len(out) != 0 {
		t.Fatalf("blank artifact names must be skipped, got %v", out)
	}
}

func TestFlowContractsPersistJobContracts(t *testing.T) {
	// Empty maps are a no-op.
	s := New("tok")
	s.persistJobContracts(context.Background(), "job", nil)
	if len(s.contracts) != 0 {
		t.Fatalf("empty contracts persisted: %v", s.contracts)
	}

	// DB store failure is logged, not returned.
	s2, f, _, _ := cacheFixture(t)
	s2.DB = &fcStore{dbFakeStore: f, insertContractsErr: errors.New("contract insert down")}
	s2.persistJobContracts(context.Background(), "job-x", map[string]storage.ArtifactContract{"bin": fcBinContract()})
	if _, ok := s2.contracts["job-x"]; ok {
		t.Fatal("failed DB persist must not fall through to the memory map")
	}

	// A DB store without the contract extension falls back to the memory map.
	s3, f3, _, _ := cacheFixture(t)
	s3.DB = fcPlainStore{f3}
	s3.persistJobContracts(context.Background(), "job-y", map[string]storage.ArtifactContract{"bin": fcBinContract()})
	if _, ok := s3.contracts["job-y"]; !ok {
		t.Fatal("memory fallback did not persist contracts")
	}
}

func TestFlowContractsJobContractsWithoutDBExtension(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	s.DB = fcPlainStore{f}
	m, found, err := s.jobContracts(context.Background(), "job-a")
	if err != nil || found || m != nil {
		t.Fatalf("plain store contracts = %v %v %v, want nil false nil", m, found, err)
	}
}

func TestFlowContractsForJobStoreError(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	s.DB = &fcStore{dbFakeStore: f, getContractsErr: errors.New("contract read down")}
	if _, err := s.contractsForJob(context.Background(), model.Job{ID: "job-a", Key: "build"}); err == nil {
		t.Fatal("contract store error must propagate")
	}
}

func TestFlowContractsLenientJobContracts(t *testing.T) {
	tests := []struct {
		name    string
		job     model.Job
		wantOK  bool
		wantHas string
	}{
		{
			name:    "direct key",
			job:     model.Job{Key: "build", Pipeline: "jobs:\n  build:\n    artifacts:\n      - name: bin\n        paths: [out/]\n        retention: 1h\n"},
			wantOK:  true,
			wantHas: "bin",
		},
		{
			name:    "base key fallback",
			job:     model.Job{Key: "build[x=1]", BaseKey: "build", Pipeline: "jobs:\n  build:\n    artifacts:\n      - name: lib\n"},
			wantOK:  true,
			wantHas: "lib",
		},
		{
			name:   "no matching job",
			job:    model.Job{Key: "missing", Pipeline: "jobs:\n  build:\n    artifacts:\n      - name: bin\n"},
			wantOK: false,
		},
		{
			name:   "blank artifact name only",
			job:    model.Job{Key: "build", Pipeline: "jobs:\n  build:\n    artifacts:\n      - name: \" \"\n"},
			wantOK: false,
		},
		{
			name:    "bad retention falls back to zero",
			job:     model.Job{Key: "build", Pipeline: "jobs:\n  build:\n    artifacts:\n      - name: bin\n        retention: bogus\n"},
			wantOK:  true,
			wantHas: "bin",
		},
		{
			name:   "invalid yaml",
			job:    model.Job{Key: "build", Pipeline: "jobs: [not a map"},
			wantOK: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, ok := lenientJobContracts(tc.job)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (out=%v)", ok, tc.wantOK, out)
			}
			if tc.wantHas != "" {
				if _, present := out[tc.wantHas]; !present {
					t.Fatalf("contract %q missing from %v", tc.wantHas, out)
				}
			}
			if tc.name == "bad retention falls back to zero" && out["bin"].Retention != 0 {
				t.Fatalf("bad retention parsed as %v", out["bin"].Retention)
			}
		})
	}
}

func TestFlowContractsCompileJobFromPipeline(t *testing.T) {
	if _, ok := compileJobFromPipeline(model.Job{Key: "build"}); ok {
		t.Fatal("empty pipeline must not compile")
	}
	if _, ok := compileJobFromPipeline(model.Job{Key: "build", Pipeline: "jobs: [oops"}); ok {
		t.Fatal("invalid yaml must not compile")
	}
	compileOnlyFailure := `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    artifacts:
      - name: bin
        paths:
          - ./${{ matrix.v }}/
    matrix:
      v:
        - ../escape
    steps:
      - run: echo hi
`
	if _, ok := compileJobFromPipeline(model.Job{Key: "build", Pipeline: compileOnlyFailure}); ok {
		t.Fatal("compile-time validation failure must not compile")
	}
	valid := `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo hi
`
	if _, ok := compileJobFromPipeline(model.Job{Key: "nope", Pipeline: valid}); ok {
		t.Fatal("unknown key must not compile")
	}
	if cj, ok := compileJobFromPipeline(model.Job{Key: "build", Pipeline: valid}); !ok || cj.ID != "build" {
		t.Fatalf("valid pipeline compile = %+v %v", cj, ok)
	}
}

func TestFlowContractsRetention(t *testing.T) {
	if got := contractRetention(2 * time.Hour); got != 2*time.Hour {
		t.Fatalf("positive retention = %v", got)
	}
	if got := contractRetention(-1); got != 0 {
		t.Fatalf("negative retention = %v, want 0", got)
	}
	if got := contractRetention(0); got != defaultRetention {
		t.Fatalf("unset retention = %v, want default", got)
	}
}

func TestFlowContractsFindArtifactByJobNameDBError(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	s.DB = &fcStore{dbFakeStore: f, listArtifactsErr: errors.New("artifact list down")}
	if _, err := s.findArtifactByJobName(context.Background(), "run-c", "job-a", "bin"); err == nil {
		t.Fatal("list error must propagate")
	}
}

func TestFlowContractsUploadNameResolution(t *testing.T) {
	contracts := map[string]storage.ArtifactContract{"bin": fcBinContract()}
	if c, kind, ok := contractForUploadName(contracts, "bin"); !ok || kind != "" || c.Name != "bin" {
		t.Fatalf("direct name = %+v %q %v", c, kind, ok)
	}
	if _, kind, ok := contractForUploadName(contracts, "bin.sbom"); !ok || kind != "sbom" {
		t.Fatalf("sbom sibling = %q %v", kind, ok)
	}
	if _, kind, ok := contractForUploadName(contracts, "bin.sigstore"); !ok || kind != "sigstore" {
		t.Fatalf("sigstore sibling = %q %v", kind, ok)
	}
	if _, _, ok := contractForUploadName(contracts, "other.sbom"); ok {
		t.Fatal("unknown sbom sibling must not resolve")
	}
	if _, _, ok := contractForUploadName(contracts, "lib"); ok {
		t.Fatal("unknown name must not resolve")
	}
}

func TestFlowContractsExistingArtifactForGeneration(t *testing.T) {
	recs := []model.ArtifactRecord{{ID: "a", LeaseGeneration: 3}}
	if rec, ok := existingArtifactForGeneration(recs, 3); !ok || rec.ID != "a" {
		t.Fatalf("generation hit = %+v %v", rec, ok)
	}
	if _, ok := existingArtifactForGeneration(recs, 4); ok {
		t.Fatal("generation miss reported a hit")
	}
}

func TestFlowContractsRequiredArtifactsMissing(t *testing.T) {
	s := New("tok")
	s.mu.Lock()
	s.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": {Name: "bin", Required: true}}
	missing := s.requiredArtifactsMissingLocked(model.Job{ID: "job-a"})
	s.artifacts["art"] = model.ArtifactRecord{ID: "art", JobID: "job-a", Name: "bin"}
	satisfied := s.requiredArtifactsMissingLocked(model.Job{ID: "job-a"})
	s.mu.Unlock()
	if missing != "bin" {
		t.Fatalf("missing required artifact = %q", missing)
	}
	if satisfied != "" {
		t.Fatalf("satisfied required artifact reported %q", satisfied)
	}
}

func TestFlowContractsRebuildArtifactContracts(t *testing.T) {
	s := New("tok")
	s.jobs["job-a"] = model.Job{ID: "job-a", Key: "build", Pipeline: artifactsPipeline}
	s.rebuildArtifactContractsLocked()
	if _, ok := s.contracts["job-a"]["bin"]; !ok {
		t.Fatalf("rebuild did not derive the bin contract: %v", s.contracts)
	}
}
