package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func mustOPA(t *testing.T, src string) *OPAPolicy {
	t.Helper()
	p, err := LoadOPAPolicy(src)
	if err != nil {
		t.Fatalf("LoadOPAPolicy: %v", err)
	}
	return p
}

func loadExamplePolicy(t *testing.T) *OPAPolicy {
	t.Helper()
	path := filepath.Join("..", "..", "examples", "policy", "allow_trusted_only.rego")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("example policy not shipped: %v", err)
	}
	return mustOPA(t, string(data))
}

const allowAllPolicy = `package kiwi

default allow := false

allow if {
	true
}

deny contains message if {
	message := "unreachable"
	false
}
`

const allowOnlyPolicy = `package kiwi

default allow := true
`

const denyOnlyPolicy = `package kiwi

deny contains message if {
	message := "no allow rule defined"
}
`

const evalErrorPolicy = `package kiwi

default allow := false

allow if {
	input.trusted
}

deny contains message if {
	message := sprintf("match=%v", [regex.match("(", input.branch)])
}
`

func TestLoadOPAPolicyAllowAll(t *testing.T) {
	p := mustOPA(t, allowAllPolicy)
	d, err := p.Decide(context.Background(), OPAInput{Trusted: true, Branch: "main"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !d.Allow {
		t.Fatalf("allow-all policy must allow trusted input, reasons=%v", d.Reasons)
	}
	if len(d.Reasons) != 0 {
		t.Fatalf("allow decision must carry no reasons, got %v", d.Reasons)
	}
	d, err = p.Decide(context.Background(), OPAInput{Trusted: false, Event: "pull_request"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !d.Allow {
		t.Fatalf("allow-all policy must allow untrusted input, reasons=%v", d.Reasons)
	}
}

func TestOPADenyUntrustedProduction(t *testing.T) {
	p := loadExamplePolicy(t)
	d, err := p.Decide(context.Background(), OPAInput{Trusted: true, Event: "push", Environment: "production", Network: "internet"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !d.Allow {
		t.Fatalf("trusted production deployment must be allowed, reasons=%v", d.Reasons)
	}
	d, err = p.Decide(context.Background(), OPAInput{Trusted: false, Event: "pull_request", Environment: "production", Network: "none"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Allow {
		t.Fatal("untrusted PR to production must be denied")
	}
	if len(d.Reasons) == 0 {
		t.Fatal("deny decision must carry reasons")
	}
	found := false
	for _, r := range d.Reasons {
		if strings.Contains(r, "protected environment") {
			found = true
		}
	}
	if !found {
		t.Fatalf("reasons must explain the protected environment rule, got %v", d.Reasons)
	}
	d, err = p.Decide(context.Background(), OPAInput{Trusted: false, Event: "push", Environment: "staging", Network: "internet"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Allow {
		t.Fatal("untrusted job requesting internet must be denied")
	}
	found = false
	for _, r := range d.Reasons {
		if strings.Contains(r, `network "internet"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("reasons must explain the internet rule, got %v", d.Reasons)
	}
	d, err = p.Decide(context.Background(), OPAInput{Trusted: false, Event: "push", Environment: "dev", Network: "none"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Allow {
		t.Fatal("untrusted input must never be allowed by the example policy")
	}
	if len(d.Reasons) != 1 || d.Reasons[0] != "data.kiwi.allow is false" {
		t.Fatalf("unmatched untrusted input must fall back to allow=false reason, got %v", d.Reasons)
	}
}

func TestLoadOPAPolicyMalformed(t *testing.T) {
	if _, err := LoadOPAPolicy("package kiwi\nallow := !!!\n"); err == nil {
		t.Fatal("malformed rego must fail the load")
	}
	if _, err := LoadOPAPolicy(""); err == nil {
		t.Fatal("empty rego must fail the load")
	}
}

func TestOPAMissingDenyRuleFailsClosed(t *testing.T) {
	p := mustOPA(t, allowOnlyPolicy)
	d, err := p.Decide(context.Background(), OPAInput{Trusted: true})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Allow {
		t.Fatal("policy without data.kiwi.deny must deny")
	}
	if len(d.Reasons) == 0 || !strings.Contains(d.Reasons[0], "data.kiwi.deny") {
		t.Fatalf("reason must name the missing deny rule, got %v", d.Reasons)
	}
}

func TestOPAMissingAllowRuleFailsClosed(t *testing.T) {
	p := mustOPA(t, denyOnlyPolicy)
	d, err := p.Decide(context.Background(), OPAInput{Trusted: true})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Allow {
		t.Fatal("policy without data.kiwi.allow must deny")
	}
	if len(d.Reasons) == 0 || !strings.Contains(d.Reasons[0], "data.kiwi.allow") {
		t.Fatalf("reason must name the missing allow rule, got %v", d.Reasons)
	}
}

func TestOPAEvalErrorDenies(t *testing.T) {
	p := mustOPA(t, evalErrorPolicy)
	d, err := p.Decide(context.Background(), OPAInput{Trusted: true, Branch: "main"})
	if err != nil {
		t.Fatalf("evaluation failure must be reported as a denial, not an error: %v", err)
	}
	if d.Allow {
		t.Fatal("evaluation error must deny")
	}
	if len(d.Reasons) == 0 || !strings.Contains(d.Reasons[0], "evaluation failed") {
		t.Fatalf("reason must explain the evaluation failure, got %v", d.Reasons)
	}
}

func TestOPAUnknownInputFieldRejectedAtLoad(t *testing.T) {
	src := `package kiwi

default allow := false

allow if {
	input.trusted
}

deny contains message if {
	input.git_ref == "main"
	message := "denied"
}
`
	if _, err := LoadOPAPolicy(src); err == nil {
		t.Fatal("policy referencing an unknown input field must fail the load")
	} else if !strings.Contains(err.Error(), "unknown input field") {
		t.Fatalf("unexpected load error: %v", err)
	}
}

func TestOPADenyObjectEntries(t *testing.T) {
	src := `package kiwi

default allow := false

allow if {
	input.trusted
}

deny contains entry if {
	not input.trusted
	entry := {"message": "object style reason"}
}
`
	p := mustOPA(t, src)
	d, err := p.Decide(context.Background(), OPAInput{Trusted: false})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if d.Allow {
		t.Fatal("deny entry must reject")
	}
	if len(d.Reasons) != 1 || d.Reasons[0] != "object style reason" {
		t.Fatalf("object deny entries must surface their message, got %v", d.Reasons)
	}
}

func TestOPADeterministic(t *testing.T) {
	p := loadExamplePolicy(t)
	in := OPAInput{Trusted: false, Event: "pull_request", Environment: "production", Network: "internet", RunnerLabels: []string{"linux", "gpu"}}
	first, err := p.Decide(context.Background(), in)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	for i := 0; i < 20; i++ {
		d, err := p.Decide(context.Background(), in)
		if err != nil {
			t.Fatalf("Decide: %v", err)
		}
		if !reflect.DeepEqual(d, first) {
			t.Fatalf("decision not deterministic: %+v vs %+v", first, d)
		}
	}
}

func TestOPAConcurrentDecide(t *testing.T) {
	p := loadExamplePolicy(t)
	inputs := []OPAInput{
		{Trusted: true, Event: "push", Environment: "production"},
		{Trusted: false, Event: "pull_request", Environment: "production"},
		{Trusted: false, Event: "push", Network: "internet"},
		{Trusted: false, Event: "push", Environment: "dev", Network: "none"},
	}
	want := make([]OPADecision, len(inputs))
	for i, in := range inputs {
		d, err := p.Decide(context.Background(), in)
		if err != nil {
			t.Fatalf("Decide: %v", err)
		}
		want[i] = d
	}
	var wg sync.WaitGroup
	errs := make(chan error, 10*len(inputs))
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i, in := range inputs {
				d, err := p.Decide(context.Background(), in)
				if err != nil {
					errs <- fmt.Errorf("Decide: %w", err)
					return
				}
				if !reflect.DeepEqual(d, want[i]) {
					errs <- fmt.Errorf("concurrent decision diverged for input %d: got %+v, want %+v", i, d, want[i])
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestConfigOPAFileMissingFailsValidate(t *testing.T) {
	cfg := &Config{OPAFile: filepath.Join(t.TempDir(), "nope.rego")}
	if err := cfg.Validate(); err == nil {
		t.Fatal("unreadable opa_file must fail validation")
	}
}

func TestConfigOPAFileAndRulesMutuallyExclusive(t *testing.T) {
	cfg := &Config{OPAFile: "x.rego", OPARules: "package kiwi"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("opa_file and opa_rules together must fail validation")
	}
	if _, err := cfg.CompileOPA(); err == nil {
		t.Fatal("opa_file and opa_rules together must fail compilation")
	}
}

func TestConfigOPARulesInlineCompiles(t *testing.T) {
	cfg := &Config{OPARules: allowAllPolicy}
	p, err := cfg.CompileOPA()
	if err != nil {
		t.Fatalf("CompileOPA: %v", err)
	}
	if p == nil {
		t.Fatal("inline rules must produce a policy")
	}
	d, err := p.Decide(context.Background(), OPAInput{Trusted: false})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !d.Allow {
		t.Fatal("inline allow-all policy must allow")
	}
	if p, err := (&Config{}).CompileOPA(); err != nil || p != nil {
		t.Fatalf("no OPA config must yield nil policy, nil error; got %v, %v", p, err)
	}
}

func TestConfigOPAFileLoads(t *testing.T) {
	regoPath := filepath.Join(t.TempDir(), "policy.rego")
	if err := os.WriteFile(regoPath, []byte(allowAllPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{OPAFile: regoPath}
	p, err := cfg.CompileOPA()
	if err != nil {
		t.Fatalf("CompileOPA: %v", err)
	}
	d, err := p.Decide(context.Background(), OPAInput{Trusted: true})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !d.Allow {
		t.Fatal("policy loaded from opa_file must allow")
	}
	policyPath := writePolicy(t, "opa_file: "+regoPath+"\n")
	loaded, err := Load(policyPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.OPAFile != regoPath {
		t.Fatalf("opa_file not decoded, got %q", loaded.OPAFile)
	}
}

func TestConfigOPARulesViaYAMLLoad(t *testing.T) {
	p := writePolicy(t, "opa_rules: |\n"+indent(allowAllPolicy, "  ")+"\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := cfg.CompileOPA(); err != nil {
		t.Fatalf("CompileOPA: %v", err)
	}
}

func TestConfigOPADenies(t *testing.T) {
	cfg := &Config{OPARules: `package kiwi

default allow := false

allow if {
	input.trusted
}

deny contains message if {
	not input.trusted
	message := "untrusted denied"
}
`}
	denied, reasons, err := cfg.OPADenies(context.Background(), OPAInput{Trusted: false})
	if err != nil {
		t.Fatalf("OPADenies: %v", err)
	}
	if !denied || len(reasons) == 0 {
		t.Fatalf("untrusted input must be denied with reasons, got denied=%v reasons=%v", denied, reasons)
	}
	denied, reasons, err = cfg.OPADenies(context.Background(), OPAInput{Trusted: true})
	if err != nil {
		t.Fatalf("OPADenies: %v", err)
	}
	if denied || len(reasons) != 0 {
		t.Fatalf("trusted input must pass the deny gate, got denied=%v reasons=%v", denied, reasons)
	}
	denied, reasons, err = (&Config{}).OPADenies(context.Background(), OPAInput{Trusted: false})
	if err != nil || denied || len(reasons) != 0 {
		t.Fatalf("config without OPA must not deny, got denied=%v reasons=%v err=%v", denied, reasons, err)
	}
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}
