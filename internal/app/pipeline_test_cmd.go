package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// pipelineTestResult is one fixture check outcome.
type pipelineTestResult struct {
	name string
	err  error
}

// Test validates pipeline self-tests: load + compile every requested
// pipeline, check DAG integrity, and (when fixtures are present) the
// standing path-selection fixtures. A CI migration without pipeline tests
// is how a harness deletion loses coverage; `kiwi test` is the standing
// guard that does not require re-running the product suite.
func Test(args []string) error {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	file := pipelineFlag(fs)
	fixtures := fs.String("fixtures", "", "directory of fixture pipelines (default: internal/pipelineselftest/testdata/selftest when present)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var results []pipelineTestResult

	// Primary pipeline (optional — pure fixture mode skips a missing default).
	if _, serr := os.Stat(*file); serr == nil {
		results = append(results, checkPipelineFile(*file))
	} else if *file != ".kiwi/pipeline.yaml" && *file != pipelineDefaultFile() {
		return fmt.Errorf("pipeline %s: %w", *file, serr)
	}

	fixDir := *fixtures
	if fixDir == "" {
		for _, cand := range []string{
			"internal/pipelineselftest/testdata/selftest",
			"testdata/selftest",
		} {
			if st, err := os.Stat(cand); err == nil && st.IsDir() {
				fixDir = cand
				break
			}
		}
	}
	if fixDir != "" {
		entries, err := os.ReadDir(fixDir)
		if err != nil {
			return fmt.Errorf("fixtures: %w", err)
		}
		found := 0
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			found++
			results = append(results, checkPipelineFile(filepath.Join(fixDir, e.Name())))
		}
		if found == 0 {
			return fmt.Errorf("fixtures: %s has no .yaml pipelines", fixDir)
		}
	}

	failed := 0
	for _, r := range results {
		if r.err != nil {
			fmt.Printf("FAIL  %s: %v\n", r.name, r.err)
			failed++
			continue
		}
		fmt.Printf("ok    %s\n", r.name)
	}
	if failed > 0 {
		return fmt.Errorf("kiwi test: %d fixture(s) failed", failed)
	}
	if len(results) == 0 {
		return fmt.Errorf("kiwi test: nothing to check (pass -f pipeline.yaml or --fixtures DIR)")
	}
	fmt.Printf("kiwi test: %d pipeline(s) ok\n", len(results))
	return nil
}

func pipelineDefaultFile() string {
	return filepath.Join(".kiwi", "pipeline.yaml")
}

func checkPipelineFile(path string) pipelineTestResult {
	s, err := pipeline.Load(path)
	if err != nil {
		return pipelineTestResult{name: path, err: err}
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		return pipelineTestResult{name: path, err: err}
	}
	if len(g.Jobs) == 0 {
		return pipelineTestResult{name: path, err: fmt.Errorf("compiled graph has no jobs")}
	}
	// DAG: every needs target must exist among compiled base IDs.
	base := map[string]bool{}
	for _, cj := range g.Jobs {
		base[cj.BaseID] = true
	}
	for id, cj := range g.Jobs {
		for _, n := range cj.Job.Needs {
			if !base[n] {
				return pipelineTestResult{name: path, err: fmt.Errorf("job %q needs unknown job %q", id, n)}
			}
		}
	}
	return pipelineTestResult{name: path, err: nil}
}

// RequiredChecks compares branch-protection required status contexts with
// the real jobs in a pipeline. A required context that no job publishes is
// a permanent red PR; this fails closed so protection cannot drift from the
// pipeline.
//
// File formats:
//
//	["changed", "quality"]                         // JSON array of contexts
//	{"contexts": ["changed", "quality"]}          // JSON object
//
// A context matches a job when it equals the job id, the job's `name:`, or
// `kiwi/<event>/<job-id>` for event push/pull_request.
func RequiredChecks(args []string) error {
	fs := flag.NewFlagSet("doctor-required-checks", flag.ContinueOnError)
	file := pipelineFlag(fs)
	checks := fs.String("required-checks", "", "JSON file of required status contexts (array or {contexts: []})")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*checks) == "" {
		return fmt.Errorf("--required-checks is required")
	}
	raw, err := os.ReadFile(*checks)
	if err != nil {
		return err
	}
	contexts, err := parseRequiredContexts(raw)
	if err != nil {
		return err
	}
	s, err := pipeline.Load(*file)
	if err != nil {
		return err
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		return err
	}
	// Published contexts: job id, job name, and kiwi/<event>/<id> for both
	// common events.
	published := map[string]string{}
	for id, cj := range g.Jobs {
		published[id] = id
		if n := strings.TrimSpace(cj.Job.Name); n != "" {
			published[n] = id
		}
		for _, ev := range []string{"pr", "push", "pull_request"} {
			published[fmt.Sprintf("kiwi/%s/%s", ev, id)] = id
		}
	}
	fmt.Println("== required checks vs pipeline jobs ==")
	failed := false
	for _, ctx := range contexts {
		if job, ok := published[ctx]; ok {
			fmt.Printf("%-40s ok  (job %s)\n", ctx, job)
			continue
		}
		fmt.Printf("%-40s FAIL (no job publishes this context; fix protection or add the job)\n", ctx)
		failed = true
	}
	if failed {
		return fmt.Errorf("doctor: required checks do not match pipeline jobs")
	}
	fmt.Printf("doctor: %d required context(s) match the pipeline\n", len(contexts))
	return nil
}

func parseRequiredContexts(raw []byte) ([]string, error) {
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr, nil
	}
	var obj struct {
		Contexts []string `json:"contexts"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil && len(obj.Contexts) > 0 {
		return obj.Contexts, nil
	}
	return nil, fmt.Errorf("required-checks file must be a JSON string array or {\"contexts\": [...]}")
}
