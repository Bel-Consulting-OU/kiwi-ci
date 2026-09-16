package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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
	if caps.Network != pipeline.NetworkPolicyInternet {
		t.Fatalf("empty policy must pass network through unrestricted, got %v", caps.Network)
	}
	if !caps.Container || !caps.NativeExecution {
		t.Fatal("empty policy must pass runtime capabilities through unrestricted")
	}
	if !caps.OIDCAllows("any-audience.example") {
		t.Fatal("empty policy must pass OIDC through unrestricted")
	}
	if !caps.Enforced {
		t.Fatal("CapabilitiesFor must return an enforced authorization set")
	}
}

// TestCapabilitiesForEnforcedSemantics pins the Enforced flag: the policy
// compilation and the runner registration profile produce authoritative
// sets, while the trust defaults are permissive policy bases. Enforcement
// is monotone through Intersect and Effective so no base can launder it
// away.
func TestCapabilitiesForEnforcedSemantics(t *testing.T) {
	cfg := &Config{Repositories: map[string]RepoPolicy{
		"org/app": {SecretAllowlist: []string{"s"}},
	}}
	caps := cfg.CapabilitiesFor("org/app")
	if !caps.Enforced {
		t.Fatal("CapabilitiesFor must return Enforced=true")
	}
	if DefaultTrustedCapabilities().Enforced || DefaultUntrustedCapabilities().Enforced {
		t.Fatal("trust defaults must not be enforced (they are policy bases)")
	}
	if !Intersect(DefaultTrustedCapabilities(), caps).Enforced {
		t.Fatal("Intersect with a policy restriction must stay enforced")
	}
	if !Intersect(caps, DefaultUntrustedCapabilities()).Enforced {
		t.Fatal("Intersect with the untrusted floor must stay enforced")
	}
	if !caps.Effective(true).Enforced {
		t.Fatal("Effective(true) must preserve enforcement")
	}
	if !caps.Effective(false).Enforced {
		t.Fatal("Effective(false) must preserve enforcement")
	}
}

// TestCapabilitiesForListIntersectionsFailClosed covers the CRITICAL-1
// fail-open: a disjoint org/repo list intersection is a non-nil EMPTY list,
// which must deny everything instead of being skipped as "unrestricted".
func TestCapabilitiesForListIntersectionsFailClosed(t *testing.T) {
	cfg := &Config{
		SecretAllowlist:    []string{"org_secret"},
		OIDCAudiences:      []string{"org-aud"},
		AllowedRunnerPools: []string{"linux"},
		Repositories: map[string]RepoPolicy{
			"org/app": {
				SecretAllowlist:    []string{"repo_secret"},
				OIDCAudiences:      []string{"repo-aud"},
				AllowedRunnerPools: []string{"gpu"},
			},
		},
	}
	caps := cfg.CapabilitiesFor("org/app")
	if caps.Secrets == nil || len(caps.Secrets) != 0 {
		t.Fatalf("disjoint secret allowlists must be non-nil empty (deny all), got %v", caps.Secrets)
	}
	if caps.OIDC == nil || len(caps.OIDC) != 0 {
		t.Fatalf("disjoint OIDC allowlists must be non-nil empty (deny all), got %v", caps.OIDC)
	}
	if caps.RunnerLabels == nil || len(caps.RunnerLabels) != 0 {
		t.Fatalf("disjoint runner pools must be non-nil empty (deny all), got %v", caps.RunnerLabels)
	}
	if caps.OIDCAllows("org-aud") || caps.OIDCAllows("repo-aud") {
		t.Fatal("disjoint OIDC allowlist must deny every audience")
	}

	secretSpec := mustParse(t, `version: 1
jobs:
  x:
    runtime: container
    image: alpine
    steps:
      - run: echo hi
        secrets: [any_secret]
`)
	if err := ValidatePipeline(secretSpec, caps); err == nil {
		t.Fatal("secret outside the empty intersection was admitted")
	} else if !IsViolation(err) {
		t.Fatalf("expected policy violation, got %v", err)
	}
	oidcSpec := mustParse(t, `version: 1
jobs:
  x:
    runtime: container
    image: alpine
    permissions:
      id_token: true
    steps:
      - run: echo hi
`)
	if err := ValidatePipeline(oidcSpec, caps); err == nil {
		t.Fatal("id_token request under the empty OIDC intersection was admitted")
	}
	labelSpec := mustParse(t, `version: 1
jobs:
  x:
    runtime: container
    image: alpine
    runner: [linux]
    steps:
      - run: echo hi
`)
	if err := ValidatePipeline(labelSpec, caps); err == nil {
		t.Fatal("runner label outside the empty pool intersection was admitted")
	}

	// Org-only and repo-only lists keep restricting (no fail-open from the
	// nil-aware guards either way).
	orgOnly := (&Config{
		SecretAllowlist:    []string{"org_secret"},
		OIDCAudiences:      []string{"org-aud"},
		AllowedRunnerPools: []string{"linux"},
	}).CapabilitiesFor("org/other")
	if !reflect.DeepEqual(orgOnly.Secrets, map[string]bool{"org_secret": true}) ||
		!reflect.DeepEqual(orgOnly.OIDC, []string{"org-aud"}) ||
		!reflect.DeepEqual(orgOnly.RunnerLabels, []string{"linux"}) {
		t.Fatalf("org-only lists must survive: %+v", orgOnly)
	}
	repoOnly := (&Config{Repositories: map[string]RepoPolicy{
		"org/app": {
			SecretAllowlist:    []string{"repo_secret"},
			OIDCAudiences:      []string{"repo-aud"},
			AllowedRunnerPools: []string{"gpu"},
		},
	}}).CapabilitiesFor("org/app")
	if !reflect.DeepEqual(repoOnly.Secrets, map[string]bool{"repo_secret": true}) ||
		!reflect.DeepEqual(repoOnly.OIDC, []string{"repo-aud"}) ||
		!reflect.DeepEqual(repoOnly.RunnerLabels, []string{"gpu"}) {
		t.Fatalf("repo-only lists must survive: %+v", repoOnly)
	}
	// Overlapping lists keep only the shared entries.
	overlap := (&Config{
		SecretAllowlist:    []string{"a", "b"},
		OIDCAudiences:      []string{"aud1", "aud2"},
		AllowedRunnerPools: []string{"linux", "gpu"},
		Repositories: map[string]RepoPolicy{
			"org/app": {
				SecretAllowlist:    []string{"b", "c"},
				OIDCAudiences:      []string{"aud2", "aud3"},
				AllowedRunnerPools: []string{"gpu", "arm64"},
			},
		},
	}).CapabilitiesFor("org/app")
	if !reflect.DeepEqual(overlap.Secrets, map[string]bool{"b": true}) ||
		!reflect.DeepEqual(overlap.OIDC, []string{"aud2"}) ||
		!reflect.DeepEqual(overlap.RunnerLabels, []string{"gpu"}) {
		t.Fatalf("overlapping lists must intersect: %+v", overlap)
	}
}

// TestLoadEmptyListRestrictionsDenyAll is the YAML end-to-end form of the
// nil/empty distinction: an explicitly EMPTY list is a deny-all allowlist,
// not an absent (unrestricted) one.
func TestLoadEmptyListRestrictionsDenyAll(t *testing.T) {
	p := writePolicy(t, `
secret_allowlist: []
oidc_audiences: []
allowed_runner_pools: []
allowed_clone_hosts: []
allowed_regions: []
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	caps := cfg.CapabilitiesFor("org/app")
	if caps.Secrets == nil || len(caps.Secrets) != 0 {
		t.Fatalf("explicit empty secret_allowlist must deny all secrets, got %v", caps.Secrets)
	}
	if caps.OIDC == nil || len(caps.OIDC) != 0 {
		t.Fatalf("explicit empty oidc_audiences must deny all audiences, got %v", caps.OIDC)
	}
	if caps.RunnerLabels == nil || len(caps.RunnerLabels) != 0 {
		t.Fatalf("explicit empty allowed_runner_pools must deny all labels, got %v", caps.RunnerLabels)
	}
	if hosts := cfg.AllowedCloneHostsFor("org/app"); hosts == nil || len(hosts) != 0 {
		t.Fatalf("explicit empty allowed_clone_hosts must deny all hosts, got %v", hosts)
	}
	if regions := cfg.AllowedRegionsFor("org/app"); regions == nil || len(regions) != 0 {
		t.Fatalf("explicit empty allowed_regions must deny all regions, got %v", regions)
	}
	if cfg.CloneHostAllowed("org/app", "github.com") || cfg.CloneHostAllowed("org/app", "") {
		t.Fatal("empty clone-host allowlist admitted a host")
	}
	if cfg.RegionAllowed("org/app", "eu-west-1") || cfg.RegionAllowed("org/app", "") {
		t.Fatal("empty region allowlist admitted a region")
	}
}

// TestCloneHostAndRegionAllowlistsFailClosed covers the org∩repo clone-host
// and region admission lists, including the disjoint deny-all case the
// len(...) > 0 guards used to skip.
func TestCloneHostAndRegionAllowlistsFailClosed(t *testing.T) {
	disjoint := &Config{
		AllowedCloneHosts: []string{"github.com"},
		AllowedRegions:    []string{"eu-west-1"},
		Repositories: map[string]RepoPolicy{
			"org/app": {
				AllowedCloneHosts: []string{"gitlab.com"},
				AllowedRegions:    []string{"us-east-1"},
			},
		},
	}
	if got := disjoint.AllowedCloneHostsFor("org/app"); got == nil || len(got) != 0 {
		t.Fatalf("disjoint clone hosts must be non-nil empty, got %v", got)
	}
	if got := disjoint.AllowedRegionsFor("org/app"); got == nil || len(got) != 0 {
		t.Fatalf("disjoint regions must be non-nil empty, got %v", got)
	}
	for _, host := range []string{"github.com", "gitlab.com", ""} {
		if disjoint.CloneHostAllowed("org/app", host) {
			t.Fatalf("disjoint clone-host allowlist admitted %q", host)
		}
	}
	for _, region := range []string{"eu-west-1", "us-east-1", ""} {
		if disjoint.RegionAllowed("org/app", region) {
			t.Fatalf("disjoint region allowlist admitted %q", region)
		}
	}

	// Org-only lists keep restricting repos without a repo-level entry.
	orgOnly := &Config{
		AllowedCloneHosts: []string{"github.com"},
		AllowedRegions:    []string{"eu-west-1"},
	}
	if got := orgOnly.AllowedCloneHostsFor("org/other"); !reflect.DeepEqual(got, []string{"github.com"}) {
		t.Fatalf("org-only clone hosts = %v", got)
	}
	if !orgOnly.CloneHostAllowed("org/other", "github.com") || orgOnly.CloneHostAllowed("org/other", "gitlab.com") {
		t.Fatal("org-only clone-host restriction wrong")
	}
	if !orgOnly.RegionAllowed("org/other", "eu-west-1") || orgOnly.RegionAllowed("org/other", "us-east-1") {
		t.Fatal("org-only region restriction wrong")
	}

	// Repo-only lists keep restricting when the org level is unrestricted.
	repoOnly := &Config{Repositories: map[string]RepoPolicy{
		"org/app": {
			AllowedCloneHosts: []string{"gitlab.com"},
			AllowedRegions:    []string{"us-east-1"},
		},
	}}
	if got := repoOnly.AllowedCloneHostsFor("org/app"); !reflect.DeepEqual(got, []string{"gitlab.com"}) {
		t.Fatalf("repo-only clone hosts = %v", got)
	}
	if !repoOnly.CloneHostAllowed("org/app", "gitlab.com") || repoOnly.CloneHostAllowed("org/app", "github.com") {
		t.Fatal("repo-only clone-host restriction wrong")
	}
	if !repoOnly.RegionAllowed("org/app", "us-east-1") || repoOnly.RegionAllowed("org/app", "eu-west-1") {
		t.Fatal("repo-only region restriction wrong")
	}

	// Overlapping lists intersect; both-nil is unrestricted.
	overlap := &Config{
		AllowedCloneHosts: []string{"github.com", "gitlab.com"},
		Repositories: map[string]RepoPolicy{
			"org/app": {AllowedCloneHosts: []string{"gitlab.com"}},
		},
	}
	if got := overlap.AllowedCloneHostsFor("org/app"); !reflect.DeepEqual(got, []string{"gitlab.com"}) {
		t.Fatalf("overlapping clone hosts = %v", got)
	}
	none := &Config{}
	if none.AllowedCloneHostsFor("org/app") != nil || none.AllowedRegionsFor("org/app") != nil {
		t.Fatal("absent allowlists must stay nil (unrestricted)")
	}
	if !none.CloneHostAllowed("org/app", "anything.example") || !none.RegionAllowed("org/app", "anywhere") {
		t.Fatal("absent allowlists must admit")
	}
}

// TestCapabilitiesForRepoNetworkCannotWidenOrg covers CRITICAL-2: the repo
// network policy narrows the org policy and can never replace/widen it.
func TestCapabilitiesForRepoNetworkCannotWidenOrg(t *testing.T) {
	cases := []struct {
		name, org, repo string
		want            pipeline.NetworkPolicy
	}{
		{"org none + repo internet", "none", "internet", pipeline.NetworkPolicyNone},
		{"org internet + repo none", "internet", "none", pipeline.NetworkPolicyNone},
		{"org services-only + repo internet", "services-only", "internet", pipeline.NetworkPolicyServicesOnly},
		{"org default + repo none", "default", "none", pipeline.NetworkPolicyNone},
		{"org none + repo unset", "none", "", pipeline.NetworkPolicyNone},
		{"org internet + repo services-only", "internet", "services-only", pipeline.NetworkPolicyServicesOnly},
		{"org unset + repo internet", "", "internet", pipeline.NetworkPolicyInternet},
		{"org services-only + repo none", "services-only", "none", pipeline.NetworkPolicyNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Network: tc.org, Repositories: map[string]RepoPolicy{
				"org/app": {Network: tc.repo},
			}}
			caps := cfg.CapabilitiesFor("org/app")
			if caps.Network != tc.want {
				t.Fatalf("effective network = %v, want %v", caps.Network, tc.want)
			}
			if !caps.Enforced {
				t.Fatal("network restriction set must be enforced")
			}
		})
	}
}

// TestCapabilitiesForRequireRootlessPropagates is the rootless regression:
// require_rootless must set the monotone requirement flags in addition to
// disabling native execution, and the effective policy JSON the runner
// decodes must carry rootless=true, read_only_rootfs=true, non_root=true.
func TestCapabilitiesForRequireRootlessPropagates(t *testing.T) {
	cfg := &Config{RequireRootless: true}
	restriction := cfg.CapabilitiesFor("org/app")
	if restriction.NativeExecution {
		t.Fatal("require_rootless must deny native execution")
	}
	if !restriction.RequireRootless || !restriction.RequireReadOnlyRootFS || !restriction.RequireNonRoot {
		t.Fatalf("require_rootless must set all requirement flags: %+v", restriction)
	}
	if !restriction.Container || !restriction.Tart {
		t.Fatal("require_rootless must not disable container/tart execution")
	}
	// Trusted repo: the trusted base intersected with the restriction keeps
	// the monotone requirements and loses only native execution.
	eff := Intersect(DefaultTrustedCapabilities(), restriction)
	if eff.NativeExecution || !eff.RequireRootless || !eff.RequireReadOnlyRootFS || !eff.RequireNonRoot {
		t.Fatalf("trusted effective caps wrong: %+v", eff)
	}
	raw, err := json.Marshal(eff)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"rootless", "read_only_rootfs", "non_root"} {
		if v, ok := decoded[key].(bool); !ok || !v {
			t.Fatalf("effective policy JSON %s = %v, want true", key, decoded[key])
		}
	}
	if v, ok := decoded["enforced"].(bool); !ok || !v {
		t.Fatalf("effective policy JSON enforced = %v, want true", decoded["enforced"])
	}

	// Repo-level require_rootless behaves identically.
	enabled := true
	repoCfg := &Config{Repositories: map[string]RepoPolicy{"org/app": {RequireRootless: &enabled}}}
	repoCaps := repoCfg.CapabilitiesFor("org/app")
	if repoCaps.NativeExecution || !repoCaps.RequireRootless || !repoCaps.RequireReadOnlyRootFS || !repoCaps.RequireNonRoot {
		t.Fatalf("repo-level require_rootless not propagated: %+v", repoCaps)
	}
	// An explicit false adds nothing.
	disabled := false
	offCfg := &Config{Repositories: map[string]RepoPolicy{"org/app": {RequireRootless: &disabled}}}
	offCaps := offCfg.CapabilitiesFor("org/app")
	if offCaps.RequireRootless || offCaps.RequireReadOnlyRootFS || offCaps.RequireNonRoot {
		t.Fatalf("require_rootless false must not demand sandboxing: %+v", offCaps)
	}
}
