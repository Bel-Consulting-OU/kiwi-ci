package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTOMLSecretAllowlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(path, []byte("secret_allowlist = [\"GITHUB_TOKEN\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.SecretAllowlist) != 1 || cfg.SecretAllowlist[0] != "GITHUB_TOKEN" {
		t.Fatalf("SecretAllowlist = %v", cfg.SecretAllowlist)
	}
	// CapabilitiesFor must surface the allowlist as the Secrets set.
	caps := cfg.CapabilitiesFor("github.com/acme/widget")
	if caps.Secrets == nil || !caps.Secrets["GITHUB_TOKEN"] {
		t.Fatalf("caps.Secrets = %v", caps.Secrets)
	}
}

func TestLoadTOMLRepoSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	body := "secret_allowlist = [\"ORG_SECRET\"]\n\n[repositories.\"acme/widget\"]\nsecret_allowlist = [\"REPO_SECRET\"]\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Repositories == nil {
		t.Fatal("repositories missing")
	}
	rp := cfg.Repositories["acme/widget"]
	if len(rp.SecretAllowlist) != 1 || rp.SecretAllowlist[0] != "REPO_SECRET" {
		t.Fatalf("repo SecretAllowlist = %v", rp.SecretAllowlist)
	}
}

func TestLoadYAMLSecretAllowlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("secret_allowlist:\n  - GITHUB_TOKEN\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.SecretAllowlist) != 1 || cfg.SecretAllowlist[0] != "GITHUB_TOKEN" {
		t.Fatalf("SecretAllowlist = %v", cfg.SecretAllowlist)
	}
}
