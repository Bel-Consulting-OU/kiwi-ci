package policy

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// K6 contract: untrusted jobs NEVER receive secrets (the floor is
// deny-all and must not be liftable). The real fix is that (a) trusted
// jobs honor secret_allowlist as a scope, and (b) the deny message names
// --trusted / [runner] trusted = true, not a remedy that cannot work.
func TestUntrustedFloorDeniesAllSecrets(t *testing.T) {
	grant := Capabilities{
		Enforced: true,
		Secrets:  map[string]bool{"GITHUB_TOKEN": true},
	}
	eff := grant.Effective(false)
	if len(eff.Secrets) != 0 {
		t.Fatalf("untrusted floor lifted: %v", eff.Secrets)
	}
}

func TestTrustedAllowlistScopesSecrets(t *testing.T) {
	grant := Capabilities{
		Enforced: true,
		Secrets:  map[string]bool{"GITHUB_TOKEN": true},
	}
	eff := grant.Effective(true)
	if !eff.Secrets["GITHUB_TOKEN"] {
		t.Fatalf("trusted allowlist dropped: %v", eff.Secrets)
	}
	if eff.Secrets["OTHER"] {
		t.Fatalf("unlisted secret granted: %v", eff.Secrets)
	}
}

func TestSecretDenyNamesTrustedRequirement(t *testing.T) {
	spec, err := pipelineSpecWithSecret()
	if err != nil {
		t.Fatal(err)
	}
	err = ValidatePipeline(spec, Capabilities{Enforced: true, NativeExecution: true, Secrets: map[string]bool{}})
	if err == nil {
		t.Fatal("expected deny")
	}
	msg := err.Error()
	for _, want := range []string{"TRUSTED", "--trusted", "trusted = true", "secret_allowlist"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("deny message missing %q: %s", want, msg)
		}
	}
	// The old LIE ("add to secret_allowlist" alone) must not be the only advice.
	if !strings.Contains(msg, "secrets require a TRUSTED job") {
		t.Fatalf("message must say secrets need trusted: %s", msg)
	}
}

func pipelineSpecWithSecret() (*pipeline.Spec, error) {
	return pipeline.Parse([]byte(`version: 1
secrets: [GITHUB_TOKEN]
jobs:
  t:
    steps:
      - run: x
        secrets: [GITHUB_TOKEN]
`))
}
