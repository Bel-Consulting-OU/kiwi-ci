package policy

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"gopkg.in/yaml.v3"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestCapabilitiesEffectiveNilNormalization(t *testing.T) {
	trusted := Capabilities{Container: true, Secrets: nil, OIDC: nil}
	if got := trusted.Effective(true); got.Secrets != nil || got.OIDC != nil {
		t.Fatalf("trusted Effective must pass through: %+v", got)
	}
	untrusted := Capabilities{Container: true, Deployments: true, Network: pipeline.NetworkPolicyInternet}
	got := untrusted.Effective(false)
	if got.Deployments {
		t.Fatal("untrusted Effective must intersect the floor")
	}
	if got.Secrets == nil || len(got.Secrets) != 0 {
		t.Fatalf("untrusted Effective must preserve deny-all secrets, got %v", got.Secrets)
	}
	if got.OIDC == nil || len(got.OIDC) != 0 {
		t.Fatalf("untrusted Effective must preserve deny-all OIDC, got %v", got.OIDC)
	}
}

func TestOIDCPolicyAllows(t *testing.T) {
	open := OIDCPolicy{}
	if !open.Allows("anything") {
		t.Fatal("nil audience allowlist must permit any audience")
	}
	restricted := OIDCPolicy{AllowedAudiences: []string{"a", "b"}}
	if !restricted.Allows("a") || restricted.Allows("c") {
		t.Fatalf("restricted allowlist misbehaved: %+v", restricted)
	}
	if got := OIDCFromCapabilities(Capabilities{OIDC: nil}); got.AllowedAudiences != nil {
		t.Fatalf("nil capabilities OIDC must derive an open policy, got %+v", got)
	}
	derived := OIDCFromCapabilities(Capabilities{OIDC: []string{"x"}})
	if len(derived.AllowedAudiences) != 1 || derived.AllowedAudiences[0] != "x" {
		t.Fatalf("derived policy = %+v", derived)
	}
	derived.AllowedAudiences[0] = "mutated"
	src := Capabilities{OIDC: []string{"x"}}
	if src.OIDC[0] != "x" {
		t.Fatal("OIDCFromCapabilities must copy the slice")
	}
}

func TestConfigLoadBranches(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("Load of a missing file must error")
	}
	big := filepath.Join(t.TempDir(), "big.yaml")
	if err := os.WriteFile(big, []byte(strings.Repeat("#", (1<<20)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(big); err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatalf("oversized policy file = %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("network: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), "policy:") {
		t.Fatalf("malformed policy file = %v", err)
	}
}

func TestValidateConfigNodeBranches(t *testing.T) {
	deep := "repositories:\n  r:\n"
	indent := "    "
	for i := 0; i < 40; i++ {
		deep += strings.Repeat(" ", len(indent)+2*i) + "network:\n"
	}
	if _, err := Load(writePolicy(t, deep)); err == nil || !strings.Contains(err.Error(), "nesting too deep") {
		t.Fatalf("deep policy nesting = %v", err)
	}
	if err := validateConfigNode(&yaml.Node{}, "", 0); err == nil || !strings.Contains(err.Error(), "unexpected node") {
		t.Fatalf("validateConfigNode(zero node) = %v", err)
	}
	if _, err := Load(writePolicy(t, "allowed_clone_hosts: [{bad: 1}]\n")); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("sequence item unknown field = %v", err)
	}
	if _, err := Load(writePolicy(t, "repositories:\n  r:\n    bad: 1\n")); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("repo section unknown field = %v", err)
	}
	if _, err := Load(writePolicy(t, "network: {bad: 1}\n")); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("nested unknown field = %v", err)
	}
}

func TestConfigValidateBranches(t *testing.T) {
	if _, err := Load(writePolicy(t, "repositories:\n  \"\": {}\n")); err == nil || !strings.Contains(err.Error(), "empty repository name") {
		t.Fatalf("empty repository name = %v", err)
	}
	if _, err := Load(writePolicy(t, "repositories:\n  r:\n    network: everywhere\n")); err == nil || !strings.Contains(err.Error(), "repository") {
		t.Fatalf("bad repo network = %v", err)
	}
	var nilCfg *Config
	if p, err := nilCfg.CompileOPA(); p != nil || err != nil {
		t.Fatalf("nil Config.CompileOPA = (%v, %v)", p, err)
	}
	if _, err := (&Config{OPAFile: filepath.Join(t.TempDir(), "nope.rego")}).CompileOPA(); err == nil || !strings.Contains(err.Error(), "opa_file") {
		t.Fatalf("CompileOPA missing file = %v", err)
	}
	if _, ok := nilCfg.RepoPolicyFor("org/app"); ok {
		t.Fatal("nil Config.RepoPolicyFor must miss")
	}
	if got := nilCfg.GrantsFor("org/app"); got.Deployments || got.CrossRepoTrigger || got.GenerateChildGraph {
		t.Fatalf("nil Config.GrantsFor = %+v", got)
	}
}

func TestGrantsForFromPolicy(t *testing.T) {
	cfg, err := Load(writePolicy(t, "repositories:\n  org/app:\n    deployments: true\n    cross_repo_trigger: false\n    generate_child_graph: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	g := cfg.GrantsFor("org/app")
	if !g.Deployments || g.CrossRepoTrigger || !g.GenerateChildGraph {
		t.Fatalf("GrantsFor = %+v", g)
	}
	if g := cfg.GrantsFor("org/other"); g.Deployments || g.CrossRepoTrigger || g.GenerateChildGraph {
		t.Fatalf("GrantsFor(unknown) = %+v", g)
	}
}

func TestOPADeniesBranches(t *testing.T) {
	cfg := &Config{}
	denied, reasons, err := cfg.OPADenies(context.Background(), OPAInput{})
	if err != nil || denied || reasons != nil {
		t.Fatalf("no OPA policy must pass: denied=%v reasons=%v err=%v", denied, reasons, err)
	}

	badCfg := &Config{OPARules: "package kiwi\nallow := nosuchfn(1)\ndeny contains \"x\" if { true }\n"}
	denied, reasons, err = badCfg.OPADenies(context.Background(), OPAInput{})
	if !denied || err == nil || len(reasons) != 1 || !strings.Contains(reasons[0], "failed to compile") {
		t.Fatalf("compile failure must deny: denied=%v reasons=%v err=%v", denied, reasons, err)
	}

	denyCfg := &Config{OPARules: "package kiwi\nallow := true\ndeny contains \"no\" if { true }\n"}
	denied, reasons, err = denyCfg.OPADenies(context.Background(), OPAInput{})
	if !denied || err != nil || len(reasons) != 1 || reasons[0] != "no" {
		t.Fatalf("deny policy = denied=%v reasons=%v err=%v", denied, reasons, err)
	}

	allowCfg := &Config{OPARules: allowAllPolicy}
	denied, reasons, err = allowCfg.OPADenies(context.Background(), OPAInput{})
	if denied || err != nil || reasons != nil {
		t.Fatalf("allow policy = denied=%v reasons=%v err=%v", denied, reasons, err)
	}
}

func TestOPAPolicyDecideBranches(t *testing.T) {
	var nilPolicy *OPAPolicy
	if _, err := nilPolicy.Decide(context.Background(), OPAInput{}); err == nil {
		t.Fatal("nil policy Decide must error")
	}
	if _, err := (&OPAPolicy{}).Decide(context.Background(), OPAInput{}); err == nil {
		t.Fatal("policy without engine must error")
	}

	ok := mustOPA(t, allowAllPolicy)
	//lint:ignore SA1012 nil context exercises the Decide background-context fallback.
	d, err := ok.Decide(nil, OPAInput{})
	if err != nil || !d.Allow {
		t.Fatalf("Decide(nil ctx) = %+v, %v", d, err)
	}

	undef := mustOPA(t, "package zz\nallow := true\n")
	if d, err := undef.Decide(context.Background(), OPAInput{}); err != nil || d.Allow || len(d.Reasons) != 1 || !strings.Contains(d.Reasons[0], "undefined") {
		t.Fatalf("undefined document = %+v, %v", d, err)
	}

	conflict := mustOPA(t, "package kiwi\nallow := true\nallow := false\ndeny contains \"x\" if { true }\n")
	if d, err := conflict.Decide(context.Background(), OPAInput{}); err != nil || d.Allow || len(d.Reasons) != 1 || !strings.Contains(d.Reasons[0], "opa evaluation failed") {
		t.Fatalf("eval error = %+v, %v", d, err)
	}

	nonBool := mustOPA(t, "package kiwi\nallow := \"yes\"\ndeny contains \"x\" if { true }\n")
	if d, err := nonBool.Decide(context.Background(), OPAInput{}); err != nil || d.Allow || !strings.Contains(d.Reasons[0], "must be boolean") {
		t.Fatalf("non-boolean allow = %+v, %v", d, err)
	}

	nonSet := mustOPA(t, "package kiwi\nallow := true\ndeny := \"oops\"\n")
	if d, err := nonSet.Decide(context.Background(), OPAInput{}); err != nil || d.Allow || !strings.Contains(d.Reasons[0], "must be a set") {
		t.Fatalf("non-set deny = %+v, %v", d, err)
	}

	objects := mustOPA(t, "package kiwi\nallow := true\ndeny contains {\"code\": 7}\ndeny contains 42\ndeny contains {\"message\": \"named\"}\n")
	d, err = objects.Decide(context.Background(), OPAInput{})
	if err != nil || d.Allow {
		t.Fatalf("object deny = %+v, %v", d, err)
	}
	want := []string{"42", "map[code:7]", "named"}
	if len(d.Reasons) != len(want) {
		t.Fatalf("reasons = %v, want %v", d.Reasons, want)
	}
	for i := range want {
		if d.Reasons[i] != want[i] {
			t.Fatalf("reasons = %v, want %v", d.Reasons, want)
		}
	}

	dynamic := mustOPA(t, "package kiwi\nallow := true\ndeny contains \"dyn\" if { some k\n input[k] }\n")
	if d, err := dynamic.Decide(context.Background(), OPAInput{}); err != nil || d.Allow || d.Reasons[0] != "dyn" {
		t.Fatalf("dynamic key = %+v, %v", d, err)
	}

	if _, err := LoadOPAPolicy(""); err == nil || !strings.Contains(err.Error(), "empty rego source") {
		t.Fatalf("empty rego source = %v", err)
	}
	engine, err := rego.New(rego.Query("42")).PrepareForEval(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	scalar := &OPAPolicy{engine: &engine}
	if d, err := scalar.Decide(context.Background(), OPAInput{}); err != nil || d.Allow || len(d.Reasons) != 1 || !strings.Contains(d.Reasons[0], "is not an object") {
		t.Fatalf("scalar document = %+v, %v", d, err)
	}

	client := strictBundleClient()
	if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("bundle client redirect policy = %v", err)
	}
}

func TestNetworkNameDefault(t *testing.T) {
	if got := networkName(pipeline.NetworkPolicyDefault); got != "default" {
		t.Fatalf("networkName(default) = %q", got)
	}
	if got := networkName(pipeline.NetworkPolicyNone); got != "none" {
		t.Fatalf("networkName(none) = %q", got)
	}
	if got := networkName(pipeline.NetworkPolicyServicesOnly); got != "services-only" {
		t.Fatalf("networkName(services-only) = %q", got)
	}
	if got := networkName(pipeline.NetworkPolicyInternet); got != "internet" {
		t.Fatalf("networkName(internet) = %q", got)
	}
}
