package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

// TestPolicyTOMLAutoLoadedFromDotKiwi: K6 adversarial — the admission error
// names .kiwi/policy.toml; that file MUST load without extra config.
func TestPolicyTOMLAutoLoadedFromDotKiwi(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	if err := os.MkdirAll(".kiwi", 0o755); err != nil {
		t.Fatal(err)
	}
	body := "secret_allowlist = [\"GITHUB_TOKEN\", \"DEPLOY_KEY\"]\n"
	if err := os.WriteFile(filepath.Join(".kiwi", "policy.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	// The same resolution the server does when [policy].file is empty.
	policyPath := ""
	for _, cand := range []string{".kiwi/policy.toml", ".kiwi/policy.yaml"} {
		if _, serr := os.Stat(cand); serr == nil {
			policyPath = cand
			break
		}
	}
	if policyPath != ".kiwi/policy.toml" {
		t.Fatalf("policyPath = %q", policyPath)
	}
	cfg, err := policy.Load(policyPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.SecretAllowlist) != 2 {
		t.Fatalf("SecretAllowlist = %v", cfg.SecretAllowlist)
	}
	caps := cfg.CapabilitiesFor("acme/widget")
	if !caps.Secrets["GITHUB_TOKEN"] || !caps.Secrets["DEPLOY_KEY"] {
		t.Fatalf("caps.Secrets = %v", caps.Secrets)
	}
}

// TestPolicyTOMLBareListShape: the exact shape a user writes in TOML.
func TestPolicyTOMLBareListShape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	for _, body := range []string{
		"secret_allowlist = [\"GITHUB_TOKEN\"]\n",
		"secret_allowlist = [\n  \"GITHUB_TOKEN\",\n]\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, err := policy.Load(path)
		if err != nil {
			t.Fatalf("load %q: %v", body, err)
		}
		if len(cfg.SecretAllowlist) != 1 || cfg.SecretAllowlist[0] != "GITHUB_TOKEN" {
			t.Fatalf("SecretAllowlist = %v for %q", cfg.SecretAllowlist, body)
		}
	}
}
