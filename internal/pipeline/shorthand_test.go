package pipeline

import (
	"strings"
	"testing"
)

// Job-level run: shorthand — the simple case must be absurdly simple.
func TestJobRunShorthandCanonicalizesToStep(t *testing.T) {
	s, err := Parse([]byte(`version: 1
jobs:
  test:
    image: golang:1.27
    run: go test ./...
`))
	if err != nil {
		t.Fatal(err)
	}
	j := s.Jobs["test"]
	if j.Runtime != "container" {
		t.Fatalf("runtime = %q, want container (inferred from image)", j.Runtime)
	}
	if len(j.Steps) != 1 || j.Steps[0].Run != "go test ./..." {
		t.Fatalf("steps = %+v, want one run step", j.Steps)
	}
	if j.Run != "" {
		t.Fatal("canonical job must not keep the run shorthand")
	}
	if err := Validate(s); err != nil {
		t.Fatalf("validate shorthand job = %v", err)
	}
}

func TestJobRunShorthandMutuallyExclusiveWithSteps(t *testing.T) {
	_, err := Parse([]byte(`version: 1
jobs:
  test:
    image: golang:1.27
    run: go test
    steps:
      - run: go build
`))
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("run+steps = %v, want mutual exclusion", err)
	}
}

func TestJobVMInfersTartRuntime(t *testing.T) {
	s, err := Parse([]byte(`version: 1
jobs:
  mac:
    vm: ghcr.io/cirruslabs/macos-sequoia-base:latest
    run: swift test
`))
	if err != nil {
		t.Fatal(err)
	}
	if s.Jobs["mac"].Runtime != "tart" {
		t.Fatalf("runtime = %q, want tart", s.Jobs["mac"].Runtime)
	}
}

func TestConcurrencyLimitField(t *testing.T) {
	s, err := Parse([]byte(`version: 1
concurrency:
  group: production
  limit: 1
jobs:
  deploy:
    run: ./deploy.sh
`))
	if err != nil {
		t.Fatal(err)
	}
	if s.Concurrency.Limit != 1 {
		t.Fatalf("limit = %d, want 1", s.Concurrency.Limit)
	}
	if err := Validate(s); err != nil {
		t.Fatal(err)
	}
	s2, err := Parse([]byte(`version: 1
concurrency:
  group: g
  limit: -1
jobs:
  x:
    run: echo
`))
	if err == nil {
		if err := Validate(s2); err == nil {
			t.Fatal("negative concurrency.limit must be refused")
		}
	}
}
