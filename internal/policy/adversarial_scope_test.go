package policy

import (
	"encoding/json"
	"errors"
	"math/rand"
	"reflect"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// containerJobSpec builds a minimal valid container job whose body is the
// given YAML fragment (indented at the job level).
func containerJobSpec(t *testing.T, body string) *pipeline.Spec {
	t.Helper()
	return mustParse(t, `version: 1
jobs:
  x:
    runtime: container
    image: alpine
`+body)
}

// TestOrgEmptyListWithRepoListDeniesAll pins the hardest nil/empty
// intersection: an explicit ORG-level empty list (deny-all) combined with
// ANY repository-level list must stay deny-all in both directions. A
// fail-open here would let a repo list resurrect what the org explicitly
// denied.
func TestOrgEmptyListWithRepoListDeniesAll(t *testing.T) {
	cfg := &Config{
		SecretAllowlist:    []string{},
		OIDCAudiences:      []string{},
		AllowedRunnerPools: []string{},
		AllowedCloneHosts:  []string{},
		AllowedRegions:     []string{},
		Repositories: map[string]RepoPolicy{
			"org/app": {
				SecretAllowlist:    []string{"repo_secret"},
				OIDCAudiences:      []string{"repo-aud"},
				AllowedRunnerPools: []string{"gpu"},
				AllowedCloneHosts:  []string{"gitlab.example"},
				AllowedRegions:     []string{"us-east-1"},
			},
		},
	}
	caps := cfg.CapabilitiesFor("org/app")
	if caps.Secrets == nil || len(caps.Secrets) != 0 {
		t.Fatalf("org-empty ∩ repo secrets must be non-nil empty, got %#v", caps.Secrets)
	}
	if caps.OIDC == nil || len(caps.OIDC) != 0 {
		t.Fatalf("org-empty ∩ repo oidc must be non-nil empty, got %#v", caps.OIDC)
	}
	if caps.RunnerLabels == nil || len(caps.RunnerLabels) != 0 {
		t.Fatalf("org-empty ∩ repo pools must be non-nil empty, got %#v", caps.RunnerLabels)
	}
	if hosts := cfg.AllowedCloneHostsFor("org/app"); hosts == nil || len(hosts) != 0 {
		t.Fatalf("org-empty ∩ repo clone hosts must be non-nil empty, got %#v", hosts)
	}
	if regions := cfg.AllowedRegionsFor("org/app"); regions == nil || len(regions) != 0 {
		t.Fatalf("org-empty ∩ repo regions must be non-nil empty, got %#v", regions)
	}
	if cfg.CloneHostAllowed("org/app", "gitlab.example") || cfg.RegionAllowed("org/app", "us-east-1") {
		t.Fatal("repo list resurrected an org-level deny-all host/region")
	}
	if caps.OIDCAllows("repo-aud") {
		t.Fatal("repo audience resurrected an org-level deny-all OIDC policy")
	}
	secretSpec := containerJobSpec(t, `    steps:
      - run: echo hi
        secrets: [repo_secret]
`)
	if err := ValidatePipeline(secretSpec, caps); err == nil {
		t.Fatal("secret admitted through an org-level empty allowlist")
	}
	labelSpec := containerJobSpec(t, `    runner: [gpu]
    steps:
      - run: echo hi
`)
	if err := ValidatePipeline(labelSpec, caps); err == nil {
		t.Fatal("runner label admitted through an org-level empty pool allowlist")
	}

	// The mirror direction: a repo-level explicit empty list denies even
	// when the org list is non-empty.
	mirror := &Config{
		SecretAllowlist:    []string{"org_secret"},
		OIDCAudiences:      []string{"org-aud"},
		AllowedRunnerPools: []string{"linux"},
		AllowedCloneHosts:  []string{"github.com"},
		AllowedRegions:     []string{"eu-west-1"},
		Repositories: map[string]RepoPolicy{
			"org/app": {
				SecretAllowlist:    []string{},
				OIDCAudiences:      []string{},
				AllowedRunnerPools: []string{},
				AllowedCloneHosts:  []string{},
				AllowedRegions:     []string{},
			},
		},
	}
	mcaps := mirror.CapabilitiesFor("org/app")
	if mcaps.Secrets == nil || len(mcaps.Secrets) != 0 || mcaps.OIDC == nil || len(mcaps.OIDC) != 0 || mcaps.RunnerLabels == nil || len(mcaps.RunnerLabels) != 0 {
		t.Fatalf("repo-empty lists must stay deny-all: %+v", mcaps)
	}
	if h := mirror.AllowedCloneHostsFor("org/app"); h == nil || len(h) != 0 {
		t.Fatalf("repo-empty clone hosts must stay deny-all, got %#v", h)
	}
	if r := mirror.AllowedRegionsFor("org/app"); r == nil || len(r) != 0 {
		t.Fatalf("repo-empty regions must stay deny-all, got %#v", r)
	}
	if mirror.CloneHostAllowed("org/app", "github.com") || mirror.RegionAllowed("org/app", "eu-west-1") {
		t.Fatal("org list resurrected a repo-level deny-all host/region")
	}
	if err := ValidatePipeline(secretSpec, mcaps); err == nil {
		t.Fatal("secret admitted through a repo-level empty allowlist")
	}
}

// TestCapabilitiesEnforcedJSONRoundTrip pins the compiled-payload contract
// the runner decodes: marshal/unmarshal must preserve the Enforced flag,
// the deny-all empty (non-nil) sets, and the no-runtime semantics that make
// an enforced empty capability set deny every backend.
func TestCapabilitiesEnforcedJSONRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   Capabilities
	}{
		{
			name: "enforced empty runtime + deny-all sets",
			in: Capabilities{
				Enforced: true, Network: pipeline.NetworkPolicyNone,
				Secrets: map[string]bool{}, OIDC: []string{}, RunnerLabels: []string{},
				RequireRootless: true, RequireReadOnlyRootFS: true, RequireNonRoot: true,
			},
		},
		{
			name: "enforced full runtime + unrestricted sets",
			in: Capabilities{
				Enforced: true, NativeExecution: true, Container: true, Tart: true,
				Network: pipeline.NetworkPolicyInternet, CacheRead: true, CacheWrite: true,
				Deployments: true, GenerateChildGraph: true, CrossRepoTrigger: true,
			},
		},
		{
			name: "unenforced base with empty lists",
			in: Capabilities{
				Secrets: map[string]bool{}, OIDC: []string{}, RunnerLabels: []string{},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			var out Capabilities
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tc.in, out) {
				t.Fatalf("round trip changed capabilities:\n in=%+v\nout=%+v\njson=%s", tc.in, out, raw)
			}
			// Deny-all sets must not degrade to nil (unrestricted) across
			// the wire, and nil must stay nil.
			if tc.in.Secrets != nil && out.Secrets == nil {
				t.Fatal("empty secret allowlist degraded to nil (unrestricted) over JSON")
			}
			if tc.in.OIDC != nil && out.OIDC == nil {
				t.Fatal("empty OIDC allowlist degraded to nil (any audience) over JSON")
			}
			if tc.in.RunnerLabels != nil && out.RunnerLabels == nil {
				t.Fatal("empty runner label allowlist degraded to nil (any label) over JSON")
			}
			if tc.in.Secrets == nil && out.Secrets != nil {
				t.Fatal("nil secret set materialized over JSON")
			}
			var keys map[string]any
			if err := json.Unmarshal(raw, &keys); err != nil {
				t.Fatal(err)
			}
			if _, ok := keys["enforced"]; !ok {
				t.Fatalf("JSON missing the enforced key: %s", raw)
			}
			for _, k := range []string{"rootless", "read_only_rootfs", "non_root"} {
				if _, ok := keys[k]; !ok {
					t.Fatalf("JSON missing requirement key %q: %s", k, raw)
				}
			}
		})
	}

	// Semantic check after the round trip: the enforced empty-runtime set
	// still denies every backend.
	enforced := Capabilities{Enforced: true, Secrets: map[string]bool{}, OIDC: []string{}, RunnerLabels: []string{}}
	raw, err := json.Marshal(enforced)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Capabilities
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, runtime := range []string{"native", "container", "tart"} {
		spec := &pipeline.Spec{Jobs: map[string]pipeline.Job{"x": {Runtime: runtime, Image: "alpine"}}}
		if err := ValidatePipeline(spec, decoded); err == nil || !IsViolation(err) {
			t.Fatalf("enforced empty runtime set admitted runtime %q after JSON round trip: %v", runtime, err)
		}
	}
}

// TestIntersectRequirementFlagsRandomMonotone fuzzes the monotone
// requirement semantics: Rootless/ReadOnlyRootFS/NonRoot/Enforced are ORed
// under Intersect, so a demand from either side always survives — for any
// random pair of capability sets.
func TestIntersectRequirementFlagsRandomMonotone(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5eed))
	randCaps := func() Capabilities {
		return Capabilities{
			NativeExecution:       rng.Intn(2) == 1,
			Container:             rng.Intn(2) == 1,
			Tart:                  rng.Intn(2) == 1,
			Network:               pipeline.NetworkPolicy(rng.Intn(4)),
			Secrets:               randomSecretSet(rng),
			OIDC:                  randomStrings(rng),
			RunnerLabels:          randomStrings(rng),
			RequireRootless:       rng.Intn(2) == 1,
			RequireReadOnlyRootFS: rng.Intn(2) == 1,
			RequireNonRoot:        rng.Intn(2) == 1,
			Enforced:              rng.Intn(2) == 1,
		}
	}
	for i := 0; i < 2000; i++ {
		a, b := randCaps(), randCaps()
		got := Intersect(a, b)
		if got.RequireRootless != (a.RequireRootless || b.RequireRootless) {
			t.Fatalf("RequireRootless not monotone: %+v ∩ %+v = %+v", a, b, got)
		}
		if got.RequireReadOnlyRootFS != (a.RequireReadOnlyRootFS || b.RequireReadOnlyRootFS) {
			t.Fatalf("RequireReadOnlyRootFS not monotone: %+v ∩ %+v = %+v", a, b, got)
		}
		if got.RequireNonRoot != (a.RequireNonRoot || b.RequireNonRoot) {
			t.Fatalf("RequireNonRoot not monotone: %+v ∩ %+v = %+v", a, b, got)
		}
		if got.Enforced != (a.Enforced || b.Enforced) {
			t.Fatalf("Enforced not monotone: %+v ∩ %+v = %+v", a, b, got)
		}
		// Requirements only accumulate: intersecting again with either
		// side keeps every demand.
		again := Intersect(got, a)
		if again.RequireRootless != got.RequireRootless || again.RequireReadOnlyRootFS != got.RequireReadOnlyRootFS ||
			again.RequireNonRoot != got.RequireNonRoot || again.Enforced != got.Enforced {
			t.Fatalf("re-intersection dropped a monotone flag: %+v -> %+v", got, again)
		}
	}
}

func randomSecretSet(rng *rand.Rand) map[string]bool {
	switch rng.Intn(3) {
	case 0:
		return nil
	case 1:
		return map[string]bool{}
	default:
		m := map[string]bool{}
		for _, k := range []string{"a", "b", "c"} {
			m[k] = rng.Intn(2) == 1
		}
		return m
	}
}

func randomStrings(rng *rand.Rand) []string {
	switch rng.Intn(3) {
	case 0:
		return nil
	case 1:
		return []string{}
	default:
		out := []string{}
		for _, k := range []string{"x", "y", "z"} {
			if rng.Intn(2) == 1 {
				out = append(out, k)
			}
		}
		return out
	}
}

// TestCapabilitiesForDetachedSets proves callers cannot mutate the policy
// Config through a returned capability set or allowlist: every list/map the
// compiler returns must be a fresh copy.
func TestCapabilitiesForDetachedSets(t *testing.T) {
	cfg := &Config{
		SecretAllowlist:    []string{"org_secret"},
		OIDCAudiences:      []string{"org-aud"},
		AllowedRunnerPools: []string{"linux"},
		AllowedCloneHosts:  []string{"github.com"},
		AllowedRegions:     []string{"eu-west-1"},
		Repositories: map[string]RepoPolicy{
			"org/app": {
				SecretAllowlist:    []string{"org_secret"},
				OIDCAudiences:      []string{"org-aud"},
				AllowedRunnerPools: []string{"linux"},
				AllowedCloneHosts:  []string{"github.com"},
				AllowedRegions:     []string{"eu-west-1"},
			},
		},
	}
	caps := cfg.CapabilitiesFor("org/app")
	caps.Secrets["injected"] = true
	caps.OIDC[0] = "mutated"
	caps.RunnerLabels[0] = "mutated"

	fresh := cfg.CapabilitiesFor("org/app")
	if fresh.Secrets["injected"] || fresh.OIDC[0] != "org-aud" || fresh.RunnerLabels[0] != "linux" {
		t.Fatalf("returned capability set aliases config memory: %+v", fresh)
	}
	hosts := cfg.AllowedCloneHostsFor("org/app")
	hosts[0] = "evil.example"
	regions := cfg.AllowedRegionsFor("org/app")
	regions[0] = "evil-region"
	if !cfg.CloneHostAllowed("org/app", "github.com") || cfg.CloneHostAllowed("org/app", "evil.example") {
		t.Fatal("returned clone-host list aliases config memory")
	}
	if !cfg.RegionAllowed("org/app", "eu-west-1") || cfg.RegionAllowed("org/app", "evil-region") {
		t.Fatal("returned region list aliases config memory")
	}
	// Mutating the config lists afterwards must not leak into an already
	// returned value (defense in depth; callers must still treat the
	// returned values as read-only).
	snapshot := cfg.CapabilitiesFor("org/app")
	cfg.AllowedRunnerPools[0] = "changed-later"
	if snapshot.RunnerLabels[0] != "linux" {
		t.Fatalf("returned restriction aliases the live config: %v", snapshot.RunnerLabels)
	}
}

// TestPolicyAllowlistsAreExactMatchOnly pins byte-exact matching for every
// list restriction: case differences, trailing whitespace and unicode
// confusables must never match a differently-spelled entry.
func TestPolicyAllowlistsAreExactMatchOnly(t *testing.T) {
	// "appеt" below uses a Cyrillic 'е' (U+0435) to impersonate "appet".
	confusable := "app\u0435t"
	cfg := &Config{
		SecretAllowlist:    []string{confusable, "tok ", "TOK", "nul\x00byte"},
		OIDCAudiences:      []string{confusable, "AUD"},
		AllowedRunnerPools: []string{confusable, "GPU"},
		AllowedCloneHosts:  []string{"github.com"},
		AllowedRegions:     []string{"eu-west-1"},
	}
	caps := cfg.CapabilitiesFor("org/app")
	for _, secret := range []string{"appet", "tok", "tok  ", "nul", "nul\x00byte "} {
		if caps.Secrets[secret] {
			t.Fatalf("secret %q matched a confusable/whitespace/case variant", secret)
		}
	}
	if !caps.Secrets[confusable] || !caps.Secrets["tok "] || !caps.Secrets["TOK"] || !caps.Secrets["nul\x00byte"] {
		t.Fatalf("exact allowlist entries must still match: %#v", caps.Secrets)
	}
	if caps.OIDCAllows("appet") || caps.OIDCAllows("aud") || !caps.OIDCAllows("AUD") || !caps.OIDCAllows(confusable) {
		t.Fatal("OIDC audience matching is not byte-exact")
	}
	labelSpec := containerJobSpec(t, `    runner: [GPU]
    steps:
      - run: echo hi
`)
	if err := ValidatePipeline(labelSpec, caps); err != nil {
		t.Fatalf("exact label GPU must be admitted: %v", err)
	}
	for _, label := range []string{"gpu", "GPU ", "appet", confusable + " ", "\u0410pp\u0435t"} {
		spec := &pipeline.Spec{Jobs: map[string]pipeline.Job{
			"x": {Runtime: "container", Image: "alpine", Runner: []string{label}},
		}}
		if err := ValidatePipeline(spec, caps); err == nil {
			t.Fatalf("runner label %q matched a confusable/case variant", label)
		}
	}
	// Clone HOSTS are canonicalized on both sides (case, one trailing dot,
	// the scheme's default port): those spellings address the same forge and
	// must match the configured entry. Unrelated hosts still fail closed.
	for _, variant := range []string{"GitHub.com", "github.com.", "github.com:443", "HTTPS://GitHub.com"} {
		if !cfg.CloneHostAllowed("org/app", variant) {
			t.Fatalf("canonical host variant %q must be admitted", variant)
		}
	}
	for _, other := range []string{"github.com.evil.example", "evil.example", "github.com:8443", ""} {
		if cfg.CloneHostAllowed("org/app", other) {
			t.Fatalf("host %q must not be admitted by the github.com entry", other)
		}
	}
	if !cfg.CloneHostAllowed("org/app", "github.com") {
		t.Fatal("exact clone host must be admitted")
	}
	if cfg.RegionAllowed("org/app", "EU-WEST-1") || cfg.RegionAllowed("org/app", "eu-west-1 ") {
		t.Fatal("region matching is not byte-exact")
	}
	if !cfg.RegionAllowed("org/app", "eu-west-1") {
		t.Fatal("exact region must be admitted")
	}
}

// TestValidatePipelineUnknownRuntimeDenied is the defense-in-depth guard for
// the runtime switch: a runtime value the capability model cannot classify
// must be refused outright instead of silently skipping every runtime grant.
func TestValidatePipelineUnknownRuntimeDenied(t *testing.T) {
	caps := DefaultTrustedCapabilities()
	for _, runtime := range []string{"vm", "docker", "shell", "podman", "k8s", "Native", "CONTAINER", " container"} {
		spec := &pipeline.Spec{Jobs: map[string]pipeline.Job{
			"x": {Runtime: runtime, Image: "alpine"},
		}}
		err := ValidatePipeline(spec, caps)
		if err == nil {
			t.Fatalf("runtime %q was admitted by the capability gate", runtime)
		}
		var v *Violation
		if !errors.As(err, &v) || v.Kind != ViolationKindRuntime {
			t.Fatalf("runtime %q violation = %v, want runtime kind", runtime, err)
		}
	}
	// The known runtimes keep their per-backend grants.
	for runtime, want := range map[string]bool{"": true, "native": true, "container": true, "tart": true} {
		spec := &pipeline.Spec{Jobs: map[string]pipeline.Job{
			"x": {Runtime: runtime, Image: "alpine", VM: "macos"},
		}}
		if err := ValidatePipeline(spec, caps); (err == nil) != want {
			t.Fatalf("runtime %q admission = %v", runtime, err)
		}
	}
	// A capability set that denies a known runtime still denies it.
	noTart := DefaultTrustedCapabilities()
	noTart.Tart = false
	spec := &pipeline.Spec{Jobs: map[string]pipeline.Job{"x": {Runtime: "tart", VM: "macos"}}}
	if err := ValidatePipeline(spec, noTart); err == nil {
		t.Fatal("tart admitted without the tart grant")
	}
}

// TestLoadRejectsDuplicateKeys pins the strict parser: a duplicated policy
// key (a classic widening typo) must fail the load rather than silently
// resolving to one of the values.
func TestLoadRejectsDuplicateKeys(t *testing.T) {
	for _, doc := range []string{
		"network: none\nnetwork: internet\n",
		"allowed_clone_hosts: [github.com]\nallowed_clone_hosts: []\n",
		"repositories:\n  org/app:\n    network: none\n    network: internet\n",
	} {
		if _, err := Load(writePolicy(t, doc)); err == nil {
			t.Fatalf("duplicate-key policy loaded: %q", doc)
		}
	}
	// Sanity: the same document without the duplicate loads.
	cfg, err := Load(writePolicy(t, "network: none\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Network != "none" {
		t.Fatalf("network = %q", cfg.Network)
	}
}

// TestCapabilitiesForInvalidNetworkFailsClosed proves an unparseable
// network value in a programmatically constructed Config compiles to no
// egress instead of falling back to the permissive default.
func TestCapabilitiesForInvalidNetworkFailsClosed(t *testing.T) {
	cfg := &Config{Network: "everywhere"}
	caps := cfg.CapabilitiesFor("org/app")
	if caps.Network != pipeline.NetworkPolicyNone {
		t.Fatalf("invalid org network compiled to %v, want none", caps.Network)
	}
	repoCfg := &Config{Repositories: map[string]RepoPolicy{"org/app": {Network: "everywhere"}}}
	rcaps := repoCfg.CapabilitiesFor("org/app")
	if rcaps.Network != pipeline.NetworkPolicyNone {
		t.Fatalf("invalid repo network compiled to %v, want none", rcaps.Network)
	}
	// A valid repo narrowing still intersects with the org ceiling.
	ok := &Config{Network: "internet", Repositories: map[string]RepoPolicy{"org/app": {Network: "services-only"}}}
	if got := ok.CapabilitiesFor("org/app").Network; got != pipeline.NetworkPolicyServicesOnly {
		t.Fatalf("valid repo network = %v", got)
	}
	// And the config itself is never mutated by a compile.
	if cfg.Network != "everywhere" {
		t.Fatal("CapabilitiesFor mutated the config")
	}
}
