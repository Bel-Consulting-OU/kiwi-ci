package policy

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestSecretDenyNamesPolicyAllowlist(t *testing.T) {
	spec, err := pipeline.Parse([]byte(`version: 1
secrets: [GITHUB_TOKEN]
jobs:
  t:
    steps:
      - run: x
        secrets: [GITHUB_TOKEN]
`))
	if err != nil {
		t.Fatal(err)
	}
	caps := Capabilities{Enforced: true, NativeExecution: true, Secrets: map[string]bool{}}
	err = ValidatePipeline(spec, caps)
	if err == nil {
		t.Fatal("expected secret deny")
	}
	msg := err.Error()
	for _, want := range []string{"GITHUB_TOKEN", ".kiwi/policy.toml", "secret_allowlist"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("deny message missing %q: %s", want, msg)
		}
	}
}
