package app

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/explain"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// explainArgs carries the CLI options for `kiwi explain --why`.
type explainArgs struct {
	Event  string
	Branch string
}

// explainWhy prints why one compiled job would (or would not) run for the
// given event, branch and locally detected change set.
func explainWhy(g *pipeline.Graph, jobID string, args explainArgs) error {
	if _, ok := g.Jobs[jobID]; !ok {
		return fmt.Errorf("job %q not found in compiled pipeline", jobID)
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	branch := args.Branch
	if branch == "" {
		branch = detectCurrentBranch(wd)
	}
	w, err := explain.ExplainWhy(g.Spec, g, jobID, explain.ExplainContext{
		Event:        args.Event,
		Branch:       branch,
		ChangedFiles: detectChangedFiles(wd),
	})
	if err != nil {
		return err
	}
	printWhy(w)
	return nil
}

// printWhy renders the Why model line by line in the stable order the
// `kiwi explain --why` contract documents.
func printWhy(w *explain.Why) {
	yes := func(v bool) string {
		if v {
			return "yes"
		}
		return "no"
	}
	fmt.Printf("job: %s\n", w.JobID)
	fmt.Printf("  event matched: %s\n", yes(w.EventMatched))
	if w.TriggerKey != "" {
		fmt.Printf("  trigger key: %s\n", w.TriggerKey)
	}
	fmt.Printf("  branch matched: %s\n", yes(w.BranchMatched))
	fmt.Printf("  path matched: %s\n", yes(w.PathMatched))
	if w.PathRule != "" {
		fmt.Printf("  path rule: %s\n", w.PathRule)
	}
	if len(w.ChangedPaths) > 0 {
		fmt.Printf("  changed paths: %s\n", strings.Join(w.ChangedPaths, ", "))
	}
	if len(w.Packages) > 0 {
		fmt.Printf("  affected packages: %s\n", strings.Join(w.Packages, ", "))
	}
	if w.Condition != "" {
		fmt.Printf("  condition: %s\n", w.Condition)
	}
	fmt.Printf("  condition result: %s\n", yes(w.ConditionResult))
	if len(w.Needs) > 0 {
		fmt.Printf("  dependencies: %s\n", strings.Join(w.Needs, ", "))
	}
	fmt.Printf("  approval required: %s\n", yes(w.Approval))
	if len(w.RequiredLabels) > 0 {
		fmt.Printf("  required labels: %s\n", strings.Join(w.RequiredLabels, ", "))
	}
	if len(w.Regions) > 0 {
		fmt.Printf("  regions: %s\n", strings.Join(w.Regions, ", "))
	}
	if len(w.CacheKeys) > 0 {
		fmt.Printf("  cache keys: %s\n", strings.Join(w.CacheKeys, ", "))
	}
	if len(w.Policy) > 0 {
		fmt.Printf("  policy: %s\n", strings.Join(w.Policy, ", "))
	}
	if w.QueueReason != "" {
		fmt.Printf("  queue reason: %s\n", w.QueueReason)
	}
}

// detectCurrentBranch returns the current git branch, or "" when git is
// unavailable or the repository has no branch checked out.
func detectCurrentBranch(workspace string) string {
	cmd := exec.Command("git", "-C", workspace, "rev-parse", "--abbrev-ref", "HEAD")
	b, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
