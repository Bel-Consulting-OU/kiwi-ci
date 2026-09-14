package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValidPolicy(t *testing.T) {
	p := writePolicy(t, `
require_rootless: true
network: none
secret_allowlist: [DEPLOY_KEY]
oidc_audiences: ["sts.amazonaws.com"]
repositories:
  org/app:
    network: services-only
    deployments: true
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	caps := cfg.CapabilitiesFor("org/app")
	if caps.NativeExecution {
		t.Fatal("require_rootless must deny native execution")
	}
	if caps.Deployments != true {
		t.Fatal("repo deployments flag not applied")
	}
	if !caps.OIDCAllows("sts.amazonaws.com") || caps.OIDCAllows("https://evil.example") {
		t.Fatal("OIDC audience allowlist wrong")
	}
	if caps.OIDCAllows("anything") {
		t.Fatal("network policy from repo not applied")
	}
	base := cfg.CapabilitiesFor("org/other")
	if base.Network != pipeline.NetworkPolicyNone {
		t.Fatalf("org-level network restriction missing for other repos: %v", base.Network)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	p := writePolicy(t, "require_rootles: true\n")
	if _, err := Load(p); err == nil {
		t.Fatal("policy typo must fail closed")
	}
}

func TestLoadRejectsBadNetwork(t *testing.T) {
	p := writePolicy(t, "network: everywhere\n")
	if _, err := Load(p); err == nil {
		t.Fatal("invalid network value must be rejected")
	}
}

func TestLoadEmptyPolicy(t *testing.T) {
	p := writePolicy(t, "# empty\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	caps := cfg.CapabilitiesFor("org/app")
	if caps.Network != pipeline.NetworkPolicyDefault {
		t.Fatalf("empty policy must not restrict network, got %v", caps.Network)
	}
}
