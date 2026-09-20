package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// regionParityTable is the canonical region-matching decision table shared
// by the DB scheduler and the server's memory-mode scheduler. The two
// implementations MUST agree on every row (see the identical
// regionParityTable in internal/scheduler/region_parity_test.go) — this
// test pins the memory-mode side.
var regionParityTable = []struct {
	name         string
	runnerRegion string
	jobRegions   []string
	lease        bool
}{
	{"regionless runner, region-constrained job", "", []string{"eu-west"}, false},
	{"matching region", "eu-west", []string{"eu-west"}, true},
	{"non-matching region", "us-east", []string{"eu-west"}, false},
	{"unconstrained job, regionless runner", "", nil, true},
	{"unconstrained job, any runner", "eu-west", nil, true},
	{"multi-region match", "us-east", []string{"eu-west", "us-east"}, true},
}

// TestRegionParityTableMemoryMode runs the canonical region table against
// the memory-mode matching predicate.
func TestRegionParityTableMemoryMode(t *testing.T) {
	for _, tc := range regionParityTable {
		if got := regionSatisfied(tc.runnerRegion, tc.jobRegions); got != tc.lease {
			t.Fatalf("%s: regionSatisfied(%q, %v) = %v, want %v", tc.name, tc.runnerRegion, tc.jobRegions, got, tc.lease)
		}
	}
}

// TestMemorySchedulerRefusesRegionlessRunnerForConstrainedJob (P2-28)
// exercises the full memory-mode next() path: a runner WITHOUT a region
// cannot lease a region-constrained job (previously it could, diverging
// from the DB scheduler).
func TestMemorySchedulerRefusesRegionlessRunnerForConstrainedJob(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	constrained := `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    placement:
      regions: [eu-west]
    steps:
      - run: echo hi
`
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "main", Pipeline: constrained,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	register := func(region string) model.Runner {
		body := `{"name":"r","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1`
		if region != "" {
			body += `,"region":"` + region + `"`
		}
		body += `}`
		w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", body)
		if w.Code != http.StatusOK {
			t.Fatalf("register: %d %s", w.Code, w.Body.String())
		}
		var ri model.Runner
		if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
			t.Fatal(err)
		}
		return ri
	}
	regionless := register("")
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+regionless.ID+"/next", "token", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("regionless runner next = %d, want 204 (must refuse region-constrained job): %s", w.Code, w.Body.String())
	}
	regional := register("eu-west")
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+regional.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("matching-region runner next = %d, want 200: %s", w.Code, w.Body.String())
	}
}
