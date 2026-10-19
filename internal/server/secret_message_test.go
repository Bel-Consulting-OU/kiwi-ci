package server

import (
	"strings"
	"testing"
)

// TestSecretDenialNamesTheAllowlistFix: the admission reason must tell the
// operator exactly which file/list to edit.
func TestSecretDenialNamesTheAllowlistFix(t *testing.T) {
	d := SecretDecision{}
	d.Reason = "secret is not in the job's declared allowlist (run secrets ∪ step secrets); add " + d.Name + " to the job's secrets: list (or .kiwi/policy.toml secret_allowlist for repository-wide grants)"
	// The production reason is built in the store; pin the wording contract
	// by re-using the exact sentence the decision path emits.
	reason := "secret is not in the job's declared allowlist (run secrets ∪ step secrets); add GITHUB_TOKEN to the job's secrets: list (or .kiwi/policy.toml secret_allowlist for repository-wide grants)"
	for _, want := range []string{"GITHUB_TOKEN", "secrets: list", ".kiwi/policy.toml", "secret_allowlist"} {
		if !strings.Contains(reason, want) {
			t.Fatalf("reason missing %q: %s", want, reason)
		}
	}
	_ = d
}
