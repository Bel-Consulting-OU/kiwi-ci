package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/workspace"
)

func pipelineFlag(fs *flag.FlagSet) *string {
	return fs.String("f", ".kiwi/pipeline.yaml", "pipeline file")
}

func RunLocal(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	file := pipelineFlag(fs)
	job := fs.String("job", "", "run one job and its matrix variants")
	parallel := fs.Int("max-parallel", 0, "maximum concurrent jobs")
	jsonOut := fs.Bool("json", false, "print final results as JSON")
	// Local runs inherit the host environment by default for parity with a
	// developer shell; distributed runners never inherit. --no-inherit-env
	// and --pass-env make the boundary explicit.
	inheritEnv := fs.Bool("inherit-env", true, "inherit the host environment for local runs")
	noInheritEnv := fs.Bool("no-inherit-env", false, "start from the clean environment instead of the host environment")
	passEnv := fs.String("pass-env", "", "comma-separated host environment variables to pass (overrides --inherit-env)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	spec, err := pipeline.Load(*file)
	if err != nil {
		return err
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		return err
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	// Local runs get per-job workspaces: parallel matrix jobs must never
	// share one checkout. The manager snapshots the current directory for
	// each job and cleans every workspace up when the run finishes.
	wm, err := workspace.NewManager(wd)
	if err != nil {
		return err
	}
	defer wm.Close()
	runID, err := newLocalRunID()
	if err != nil {
		return err
	}
	masker := &secrets.Masker{}
	logs := &logging.Console{Writer: os.Stdout, Masker: masker}
	provider := secrets.Chain{secrets.EnvProvider{Prefix: "KIWI_SECRET_"}, secrets.MacKeychainProvider{Service: "kiwi-ci"}}
	opts := executor.Options{Workspace: wd, WorkspaceFor: func(jobID string) (string, func(), error) { return wm.Prepare(ctx, jobID) }, RunID: runID, MaxParallel: *parallel, OnlyJob: *job, ChangedFiles: detectChangedFiles(wd), SecretProvider: provider, Logs: logs}
	if vars := splitEnvNames(*passEnv); len(vars) > 0 {
		// Explicit allowlist: only these vars plus the clean env; the
		// inherit-env default is ignored.
		opts.PassEnv = vars
	} else {
		opts.InheritEnv = *inheritEnv && !*noInheritEnv
	}
	ex := executor.Executor{Opt: opts, Masker: masker}
	res, runErr := ex.Run(ctx, g)
	if *jsonOut {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
	} else {
		printSummary(res)
	}
	return runErr
}

func newLocalRunID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func splitEnvNames(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func Validate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	file := pipelineFlag(fs)
	if err := fs.Parse(args); err != nil {
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
	fmt.Printf("valid: %d declared jobs, %d expanded jobs\n", len(s.Jobs), len(g.Jobs))
	return nil
}

func Explain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	file := pipelineFlag(fs)
	why := fs.String("why", "", "explain why one compiled job would run (event, branch, paths, condition, dependencies)")
	event := fs.String("event", "push", "event name for --why evaluation")
	branch := fs.String("branch", "", "branch name for --why evaluation")
	if err := fs.Parse(args); err != nil {
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
	if *why != "" {
		return explainWhy(g, *why, explainArgs{Event: *event, Branch: *branch})
	}
	ids := make([]string, 0, len(g.Jobs))
	for id := range g.Jobs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		j := g.Jobs[id]
		fmt.Printf("%s\n", id)
		fmt.Printf("  runtime: %s\n", defaultString(j.Job.Runtime, "native"))
		if len(j.Needs) > 0 {
			fmt.Printf("  needs: %v\n", j.Needs)
		}
		if len(j.Matrix) > 0 {
			fmt.Printf("  matrix: %v\n", j.Matrix)
		}
		fmt.Printf("  steps: %d\n", len(j.Job.Steps))
		for i, st := range j.Job.Steps {
			n := st.Name
			if n == "" {
				n = fmt.Sprintf("step-%d", i+1)
			}
			fmt.Printf("    - %s: %s\n", n, oneLine(st.Run))
		}
	}
	return nil
}

func detectChangedFiles(workspace string) []string {
	cmd := exec.Command("git", "-C", workspace, "diff", "--name-only", "HEAD~1", "HEAD")
	b, err := cmd.Output()
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range strings.Split(string(b), "\n") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func printSummary(res map[string]model.JobResult) {
	fmt.Println("\nKiwi summary")
	ids := make([]string, 0, len(res))
	for id := range res {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := res[id]
		fmt.Printf("  %-36s %-10s %s\n", id, r.Status, r.Duration.Round(1e6))
	}
}
func oneLine(s string) string {
	for i, r := range s {
		if r == '\n' {
			return s[:i] + " …"
		}
	}
	if len(s) > 70 {
		return s[:70] + "…"
	}
	return s
}
func defaultString(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

var _ = filepath.Separator
