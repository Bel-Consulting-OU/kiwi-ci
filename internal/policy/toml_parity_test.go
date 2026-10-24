package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writePolicyFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func boolPtr(b bool) *bool { return &b }

// Adversarial: every permission-relevant Config field present in TOML must
// load. The old map-based decoder dropped most of these silently.
func TestTOMLFullFieldParity(t *testing.T) {
	tomlPath := writePolicyFile(t, "policy.toml", `
allowed_clone_hosts = ["github.com"]
allowed_runner_pools = ["linux"]
allowed_regions = ["eu"]
require_digest_pins = true
require_rootless = true
network = "none"
secret_allowlist = ["GITHUB_TOKEN"]
oidc_audiences = ["api"]
opa_rules = "package kiwi\n deny = false"

[environment_rules.prod]
allowed_branches = ["main"]
required_approvers = 2
concurrency = 1
oidc_audiences = ["deploy"]

[repositories."owner/repo"]
allowed_clone_hosts = ["github.com"]
allowed_runner_pools = ["linux"]
allowed_regions = ["eu"]
require_digest_pins = true
require_rootless = true
network = "none"
secret_allowlist = ["GITHUB_TOKEN"]
oidc_audiences = ["api"]
deployments = false
cross_repo_trigger = false
generate_child_graph = false
`)
	cfg, err := Load(tomlPath)
	if err != nil {
		t.Fatalf("Load TOML: %v", err)
	}
	if !reflect.DeepEqual(cfg.AllowedCloneHosts, []string{"github.com"}) {
		t.Fatalf("AllowedCloneHosts = %v", cfg.AllowedCloneHosts)
	}
	if !reflect.DeepEqual(cfg.AllowedRunnerPools, []string{"linux"}) {
		t.Fatalf("AllowedRunnerPools = %v", cfg.AllowedRunnerPools)
	}
	if !reflect.DeepEqual(cfg.AllowedRegions, []string{"eu"}) {
		t.Fatalf("AllowedRegions = %v", cfg.AllowedRegions)
	}
	if !cfg.RequireDigestPins || !cfg.RequireRootless {
		t.Fatalf("digest/rootless flags not loaded: %v %v", cfg.RequireDigestPins, cfg.RequireRootless)
	}
	if cfg.Network != "none" {
		t.Fatalf("Network = %q", cfg.Network)
	}
	if cfg.OPARules == "" || !cfg.opaRulesSet {
		t.Fatalf("opa_rules presence lost: rules=%q set=%v", cfg.OPARules, cfg.opaRulesSet)
	}
	er, ok := cfg.EnvironmentRules["prod"]
	if !ok {
		t.Fatal("environment_rules.prod missing")
	}
	if !reflect.DeepEqual(er.AllowedBranches, []string{"main"}) || er.RequiredApprovers != 2 || er.Concurrency != 1 {
		t.Fatalf("env rule = %+v", er)
	}
	rp, ok := cfg.Repositories["owner/repo"]
	if !ok {
		t.Fatal("repositories.owner/repo missing")
	}
	if rp.RequireDigestPins == nil || !*rp.RequireDigestPins {
		t.Fatalf("repo require_digest_pins = %v", rp.RequireDigestPins)
	}
	if rp.RequireRootless == nil || !*rp.RequireRootless {
		t.Fatalf("repo require_rootless = %v", rp.RequireRootless)
	}
	if rp.Deployments == nil || *rp.Deployments {
		t.Fatalf("repo deployments = %v", rp.Deployments)
	}
	if rp.CrossRepoTrigger == nil || *rp.CrossRepoTrigger {
		t.Fatalf("repo cross_repo_trigger = %v", rp.CrossRepoTrigger)
	}
	if rp.GenerateChildGraph == nil || *rp.GenerateChildGraph {
		t.Fatalf("repo generate_child_graph = %v", rp.GenerateChildGraph)
	}
	if rp.Network != "none" || !reflect.DeepEqual(rp.AllowedRunnerPools, []string{"linux"}) {
		t.Fatalf("repo network/pools = %+v", rp)
	}
}

// Adversarial: misspelled TOML keys must fail closed, same as YAML.
func TestTOMLUnknownKeyRejected(t *testing.T) {
	path := writePolicyFile(t, "policy.toml", "secret_alllow = [\"X\"]\n")
	if _, err := Load(path); err == nil {
		t.Fatal("unknown TOML key must be rejected")
	}
	path2 := writePolicyFile(t, "repo.toml", `
[repositories."owner/repo"]
require_digest_pin = true
`)
	if _, err := Load(path2); err == nil {
		t.Fatal("unknown repo TOML key must be rejected")
	}
}

// Adversarial: explicit empty opa_file must fail, matching YAML.
func TestTOMLEmptyOPAFilePresence(t *testing.T) {
	path := writePolicyFile(t, "policy.toml", "opa_file = \"\"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("explicit empty opa_file must fail")
	}
	path2 := writePolicyFile(t, "policy.toml", "opa_rules = \"\"\n")
	if _, err := Load(path2); err == nil {
		t.Fatal("explicit empty opa_rules must fail")
	}
}

// Adversarial: TOML and YAML for the same policy must produce equal configs.
func TestTOML_YAML_Parity(t *testing.T) {
	yamlBody := `
allowed_clone_hosts: [github.com]
allowed_runner_pools: [linux]
require_digest_pins: true
require_rootless: true
network: none
secret_allowlist: [GITHUB_TOKEN]
environment_rules:
  prod:
    allowed_branches: [main]
    required_approvers: 1
repositories:
  owner/repo:
    deployments: false
    cross_repo_trigger: false
    generate_child_graph: false
    network: services-only
`
	tomlBody := `
allowed_clone_hosts = ["github.com"]
allowed_runner_pools = ["linux"]
require_digest_pins = true
require_rootless = true
network = "none"
secret_allowlist = ["GITHUB_TOKEN"]

[environment_rules.prod]
allowed_branches = ["main"]
required_approvers = 1

[repositories."owner/repo"]
deployments = false
cross_repo_trigger = false
generate_child_graph = false
network = "services-only"
`
	yc, err := Load(writePolicyFile(t, "p.yaml", yamlBody))
	if err != nil {
		t.Fatal(err)
	}
	tc, err := Load(writePolicyFile(t, "p.toml", tomlBody))
	if err != nil {
		t.Fatal(err)
	}
	// Compare exported + presence-bearing fields.
	if !reflect.DeepEqual(yc.AllowedCloneHosts, tc.AllowedCloneHosts) ||
		!reflect.DeepEqual(yc.AllowedRunnerPools, tc.AllowedRunnerPools) ||
		yc.RequireDigestPins != tc.RequireDigestPins ||
		yc.RequireRootless != tc.RequireRootless ||
		yc.Network != tc.Network ||
		!reflect.DeepEqual(yc.SecretAllowlist, tc.SecretAllowlist) ||
		!reflect.DeepEqual(yc.EnvironmentRules, tc.EnvironmentRules) {
		t.Fatalf("YAML vs TOML top-level mismatch\nYAML=%+v\nTOML=%+v", yc, tc)
	}
	yRepo := yc.Repositories["owner/repo"]
	tRepo := tc.Repositories["owner/repo"]
	if yRepo.Deployments == nil || tRepo.Deployments == nil || *yRepo.Deployments != *tRepo.Deployments {
		t.Fatalf("deployments parity: yaml=%v toml=%v", yRepo.Deployments, tRepo.Deployments)
	}
	if yRepo.CrossRepoTrigger == nil || tRepo.CrossRepoTrigger == nil || *yRepo.CrossRepoTrigger != *tRepo.CrossRepoTrigger {
		t.Fatalf("cross_repo_trigger parity failed")
	}
	if yRepo.GenerateChildGraph == nil || tRepo.GenerateChildGraph == nil || *yRepo.GenerateChildGraph != *tRepo.GenerateChildGraph {
		t.Fatalf("generate_child_graph parity failed")
	}
	if yRepo.Network != tRepo.Network {
		t.Fatalf("repo network: yaml=%q toml=%q", yRepo.Network, tRepo.Network)
	}
}
