package explain

import (
	"reflect"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func mustCompile(t *testing.T, spec *pipeline.Spec) *pipeline.Graph {
	t.Helper()
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func testSpec() *pipeline.Spec {
	return &pipeline.Spec{
		On: map[string]pipeline.Trigger{
			"push": {
				Branches: []string{"main", "release/*"},
				Paths:    []string{"src/**"},
			},
			"pull_request": {
				Branches: []string{"*"},
			},
		},
		Packages: map[string]pipeline.Package{
			"core": {Paths: []string{"src/core/**"}},
			"web":  {Paths: []string{"src/web/**"}, DependsOn: []string{"core"}},
		},
		Jobs: map[string]pipeline.Job{
			"build": {
				Runner:  []string{"large"},
				Runtime: "container",
				Steps:   []pipeline.Step{{Run: "make build"}},
			},
			"deploy": {
				Needs:       []string{"build"},
				If:          "branch == 'main'",
				Paths:       []string{"src/web/**"},
				PathsIgnore: []string{"src/web/*_test.go"},
				Environment: pipeline.Environment{Name: "prod", Approval: true},
				Placement:   pipeline.Placement{Regions: []string{"eu-central"}},
				Cache:       []pipeline.Cache{{Name: "deps", Key: "deps-{{ hashFiles 'go.sum' }}", Paths: []string{".kiwi/go-cache"}}},
				Steps:       []pipeline.Step{{Run: "make deploy"}},
			},
		},
	}
}

func TestExplainWhyTriggerAndBranch(t *testing.T) {
	spec := testSpec()
	g := mustCompile(t, spec)

	w, err := ExplainWhy(spec, g, "build", ExplainContext{Event: "push", Branch: "main", ChangedFiles: []string{"src/core/a.go"}})
	if err != nil {
		t.Fatal(err)
	}
	if !w.EventMatched || w.TriggerKey != "push" {
		t.Fatalf("event: %+v", w)
	}
	if !w.BranchMatched {
		t.Fatalf("branch: %+v", w)
	}
	if !w.PathMatched || w.PathRule != "src/**" {
		t.Fatalf("path: %+v", w)
	}
	if !reflect.DeepEqual(w.Packages, []string{"core", "web"}) {
		t.Fatalf("packages: %v", w.Packages)
	}

	// Branch outside the push filter: the branch filter is part of the
	// trigger, so forge rejects the whole trigger (event matched: no).
	w2, err := ExplainWhy(spec, g, "build", ExplainContext{Event: "push", Branch: "feature/x", ChangedFiles: []string{"src/core/a.go"}})
	if err != nil {
		t.Fatal(err)
	}
	if w2.EventMatched || w2.BranchMatched {
		t.Fatalf("branch feature/x: %+v", w2)
	}

	// Unmatched event.
	w3, err := ExplainWhy(spec, g, "build", ExplainContext{Event: "schedule", Branch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if w3.EventMatched {
		t.Fatalf("schedule event should not match: %+v", w3)
	}
}

func TestExplainWhyDeployJob(t *testing.T) {
	spec := testSpec()
	g := mustCompile(t, spec)

	w, err := ExplainWhy(spec, g, "deploy", ExplainContext{Event: "push", Branch: "main", ChangedFiles: []string{"src/web/page.go"}})
	if err != nil {
		t.Fatal(err)
	}
	if !w.PathMatched {
		t.Fatalf("path matched: %+v", w)
	}
	if w.PathRule != "src/web/**" {
		t.Fatalf("path rule: %q", w.PathRule)
	}
	if !w.ConditionResult || w.Condition != "branch == 'main'" {
		t.Fatalf("condition: %+v", w)
	}
	if !reflect.DeepEqual(w.Needs, []string{"build"}) {
		t.Fatalf("needs: %v", w.Needs)
	}
	if !w.Approval {
		t.Fatalf("approval: %+v", w)
	}
	if !reflect.DeepEqual(w.Regions, []string{"eu-central"}) {
		t.Fatalf("regions: %v", w.Regions)
	}
	if !reflect.DeepEqual(w.CacheKeys, []string{"deps-{{ hashFiles 'go.sum' }}"}) {
		t.Fatalf("cache keys: %v", w.CacheKeys)
	}
	if !reflect.DeepEqual(w.RequiredLabels, []string{"native"}) {
		t.Fatalf("labels: %v", w.RequiredLabels)
	}
	if len(w.Policy) == 0 {
		t.Fatalf("policy: %v", w.Policy)
	}

	// Paths_ignore excludes test files.
	w2, err := ExplainWhy(spec, g, "deploy", ExplainContext{Event: "push", Branch: "main", ChangedFiles: []string{"src/web/page_test.go"}})
	if err != nil {
		t.Fatal(err)
	}
	if w2.PathMatched {
		t.Fatalf("test file should be ignored: %+v", w2)
	}

	// Condition fails on other branches.
	w3, err := ExplainWhy(spec, g, "deploy", ExplainContext{Event: "push", Branch: "dev", ChangedFiles: []string{"src/web/page.go"}})
	if err != nil {
		t.Fatal(err)
	}
	if w3.ConditionResult {
		t.Fatalf("condition should fail on dev: %+v", w3)
	}
}

func TestExplainWhyUnknownJob(t *testing.T) {
	spec := testSpec()
	g := mustCompile(t, spec)
	if _, err := ExplainWhy(spec, g, "nope", ExplainContext{Event: "push", Branch: "main"}); err == nil {
		t.Fatal("want error for unknown job")
	}
}

func TestExplainWhyMatrixJob(t *testing.T) {
	spec := &pipeline.Spec{
		Jobs: map[string]pipeline.Job{
			"test": {
				Matrix: map[string][]any{"os": {"linux", "darwin"}},
				Steps:  []pipeline.Step{{Run: "make test"}},
			},
		},
	}
	g := mustCompile(t, spec)
	w, err := ExplainWhy(spec, g, "test[os=linux]", ExplainContext{Event: "push", Branch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if w.JobID != "test[os=linux]" {
		t.Fatalf("job id: %q", w.JobID)
	}
	// Empty on-section matches everything.
	if !w.EventMatched || w.TriggerKey != "" || !w.BranchMatched {
		t.Fatalf("empty on-section: %+v", w)
	}
}
