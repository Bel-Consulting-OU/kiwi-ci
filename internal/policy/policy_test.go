package policy

import (
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"testing"
)

func TestUntrustedRejectsNativeAndSecrets(t *testing.T) {
	s, err := pipeline.Parse([]byte(`version: 1
jobs:
  x:
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAdmission(s, false); err == nil {
		t.Fatal("untrusted native job should be rejected")
	}
}
func TestUntrustedContainerAllowed(t *testing.T) {
	s, err := pipeline.Parse([]byte(`version: 1
jobs:
  x:
    runtime: container
    image: alpine
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAdmission(s, false); err != nil {
		t.Fatal(err)
	}
}
