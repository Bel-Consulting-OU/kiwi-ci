package explain

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestExplainWhyNilSpec(t *testing.T) {
	if _, err := ExplainWhy(nil, &pipeline.Graph{}, "x", ExplainContext{}); err == nil {
		t.Fatal("nil spec must error")
	}
}

func TestExplainWhyTriggerKeyEdgeCases(t *testing.T) {
	spec := &pipeline.Spec{
		On: map[string]pipeline.Trigger{
			"push": {},
		},
		Jobs: map[string]pipeline.Job{
			"build": {Steps: []pipeline.Step{{Run: "make"}}},
		},
	}
	g := mustCompile(t, spec)
	w, err := ExplainWhy(spec, g, "build", ExplainContext{Event: "push", Branch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if !w.EventMatched || !w.BranchMatched {
		t.Fatalf("trigger without filters must match every branch: %+v", w)
	}

}

func TestBranchAllowedAndMatchPattern(t *testing.T) {
	if !branchAllowed("main", nil, nil) {
		t.Fatal("no filters must allow every branch")
	}
	if !branchAllowed("main", []string{"main"}, []string{"release/*"}) {
		t.Fatal("include match with unrelated exclude must allow")
	}
	if branchAllowed("feature/x", []string{"main"}, nil) {
		t.Fatal("missing include must deny")
	}
	if branchAllowed("main", []string{"main"}, []string{"main"}) {
		t.Fatal("exclude must win")
	}
	if !matchPattern("main", []string{"", "ma?n"}) {
		t.Fatal("empty patterns are skipped and path.Match globs must match")
	}
	if matchPattern("main", []string{"[", "other"}) {
		t.Fatal("malformed globs must not match")
	}
}

func TestFirstMatchingPathRule(t *testing.T) {
	if _, ok := firstMatchingPathRule([]string{"src/a.go"}, nil, nil); ok {
		t.Fatal("no include patterns must not produce a rule")
	}
	rule, ok := firstMatchingPathRule([]string{"src/a.go"}, []string{"docs/**", "src/**"}, nil)
	if !ok || rule != "src/**" {
		t.Fatalf("firstMatchingPathRule = (%q, %v), want src/**", rule, ok)
	}
	if _, ok := firstMatchingPathRule([]string{"src/a.go"}, []string{"docs/**"}, nil); ok {
		t.Fatal("non-matching include must not produce a rule")
	}
}

func TestExplainWhyTartPolicyLines(t *testing.T) {
	spec := &pipeline.Spec{
		On: map[string]pipeline.Trigger{"push": {}},
		Jobs: map[string]pipeline.Job{
			"mac": {
				Runtime:     "tart",
				VM:          "macos-15",
				Permissions: pipeline.Permissions{IDToken: true},
				Sandbox:     pipeline.Sandbox{Rootless: true, ReadOnlyRootFS: true},
				Steps:       []pipeline.Step{{Run: "make"}},
			},
		},
	}
	g := mustCompile(t, spec)
	w, err := ExplainWhy(spec, g, "mac", ExplainContext{Event: "push", Branch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(w.Policy, ";")
	for _, want := range []string{"network=bridge", "sandbox.read_only_rootfs=true", "sandbox.rootless=true", "oidc.id_token=true"} {
		if !strings.Contains(joined, want) {
			t.Errorf("policy lines %v missing %q", w.Policy, want)
		}
	}
	labels := strings.Join(w.RequiredLabels, ",")
	if !strings.Contains(labels, "tart") || !strings.Contains(labels, "os:darwin") {
		t.Errorf("required labels = %v, want tart and os:darwin", w.RequiredLabels)
	}
}
