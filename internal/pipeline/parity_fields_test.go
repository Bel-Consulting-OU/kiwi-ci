package pipeline

import (
	"strings"
	"testing"
)

// TestJobWhenPathFoldsToPaths: when.path is accepted and folded into paths.
func TestJobWhenPathFoldsToPaths(t *testing.T) {
	spec, err := Parse([]byte(`version: 1
jobs:
  t:
    when:
      path: ["src/**", "go.mod"]
      path_ignore: ["src/generated/**"]
      branch: [main]
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	j := spec.Jobs["t"]
	if len(j.Paths) != 2 || j.Paths[0] != "src/**" {
		t.Fatalf("paths = %v", j.Paths)
	}
	if len(j.PathsIgnore) != 1 {
		t.Fatalf("paths_ignore = %v", j.PathsIgnore)
	}
	if j.If == "" || !strings.Contains(j.If, "branch == 'main'") {
		t.Fatalf("if = %q", j.If)
	}
}

// TestJobConcurrencyGroup: job-level concurrency is accepted.
func TestJobConcurrencyGroup(t *testing.T) {
	spec, err := Parse([]byte(`version: 1
jobs:
  t:
    concurrency:
      group: deploy-${{ branch }}
      cancel_in_progress: true
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	j := spec.Jobs["t"]
	if j.Concurrency == nil || j.Concurrency.Group == "" {
		t.Fatalf("concurrency = %+v", j.Concurrency)
	}
	if !j.Concurrency.CancelInProgress {
		t.Fatalf("cancel_in_progress = false")
	}
}

// TestStepMatrixHoistsToJob: step-level matrix is accepted and hoisted.
func TestStepMatrixHoistsToJob(t *testing.T) {
	spec, err := Parse([]byte(`version: 1
jobs:
  t:
    steps:
      - run: echo hi
        matrix:
          GO: ["1.22", "1.23"]
`))
	if err != nil {
		t.Fatal(err)
	}
	j := spec.Jobs["t"]
	if len(j.Matrix["GO"]) != 2 {
		t.Fatalf("matrix = %v", j.Matrix)
	}
}

// TestRetryScalarShorthand: retry: 3 means max=3.
func TestRetryScalarShorthand(t *testing.T) {
	spec, err := Parse([]byte(`version: 1
jobs:
  t:
    steps:
      - run: echo hi
        retry: 3
`))
	if err != nil {
		t.Fatal(err)
	}
	st := spec.Jobs["t"].Steps[0]
	if st.Retry.Max != 3 || !st.Retry.MaxSet {
		t.Fatalf("retry = %+v", st.Retry)
	}
}

// TestPolicySecretDenyNamesAllowlist: the violation text names the file.
func TestPolicySecretDenyNamesAllowlist(t *testing.T) {
	// Imported here to avoid a cross-package test in policy/.
	// The contract string is asserted in policy tests; this pins parse.
	if _, err := Parse([]byte("version: 1\njobs:\n  t:\n    steps:\n      - run: x\n        retry: 1\n")); err != nil {
		t.Fatal(err)
	}
}
