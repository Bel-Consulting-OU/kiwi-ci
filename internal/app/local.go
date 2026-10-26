package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/config"
	"io"
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
	base := fs.String("base", "", "base ref for changed-file detection (default HEAD~1)")
	head := fs.String("head", "HEAD", "head ref for changed-file detection")
	mergeBase := fs.String("merge-base", "", "compute the base as the merge base of HEAD and this ref")
	changedFile := fs.String("changed-file", "", "explicit changed files (comma-separated); overrides git detection")
	changedFiles := fs.String("changed-files", "", "alias for --changed-file (comma-separated workspace-relative paths)")
	var inputs kvFlags
	fs.Var(&inputs, "input", "pipeline input k=v (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	// ONE run identity: freeze the working tree BEFORE loading the
	// pipeline, compiling, or reading Git metadata. Every later fact
	// (pipeline, image lock, graph, SHA/ref/branch, changed files, job
	// workspaces) is derived from that frozen run-base so a single
	// `kiwi run` cannot execute source state B with pipeline state A
	// while claiming Git state C.
	wm, err := workspace.NewManager(wd)
	if err != nil {
		return err
	}
	defer wm.Close()
	// Explicit ref inputs ride INTO the freeze transaction: their
	// resolutions are captured from the source before the run-base seals
	// Git away (a stripped linked-worktree base cannot re-answer them).
	wm.CaptureRefs(workspace.RefQuery{Base: *base, Head: *head, MergeBase: *mergeBase})
	if err := wm.Freeze(ctx); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("run cancelled: %w", ctx.Err())
		}
		return err
	}
	baseDir := wm.BasePath()
	// Prefer the pipeline bytes as frozen in the run-base when the file
	// lives under the working tree.
	fileToLoad := *file
	adoptedPipeline := false
	adoptedLockRoot := ""
	if baseDir != "" {
		if abs, aerr := filepath.Abs(*file); aerr == nil {
			needAdopt := false
			if rel, rerr := filepath.Rel(wd, abs); rerr == nil && !strings.HasPrefix(rel, "..") {
				frozen := filepath.Join(baseDir, rel)
				if fileExists(frozen) {
					fileToLoad = frozen
				} else {
					// Under the working tree but omitted from Freeze (e.g.
					// untracked under target/). Live bytes would still change
					// the run identity: adopt them into the frozen base.
					needAdopt = true
				}
			} else {
				// External pipeline: adopt bytes into the frozen run-base.
				needAdopt = true
			}
			if needAdopt {
				// The pipeline AND its image lock are adopted in ONE
				// stabilization transaction: the pair was simultaneously
				// stable or the run refuses to start. Two separate
				// adoptions could certify pipeline A with lock B even
				// though that combination never existed.
				origRoot := lockRootFor(*file)
				if origRoot == "" {
					origRoot = wd
				}
				origLock := filepath.Join(origRoot, ".kiwi", "lock.json")
				lockPath := ""
				if fileExists(origLock) {
					lockPath = origLock
				}
				adopted, aerr2 := wm.AdoptInputs(abs, lockPath)
				if aerr2 != nil {
					return fmt.Errorf("freeze adopted inputs: %w", aerr2)
				}
				fileToLoad = adopted.PipelineDst
				adoptedPipeline = true
				adoptedLockRoot = adopted.LockRoot
			}
		}
	}
	// Git identity is whatever Freeze captured from the SOURCE — never a
	// re-read of live Git or of the copied .git (linked worktrees can move
	// HEAD after freeze, and their stripped run-base has no remote left to
	// consult). NotRepo and RepoNoHead keep their frozen shape forever:
	// a repository (or a first commit) created after Freeze is invisible
	// to this run.
	fg := wm.FrozenGitInfo()
	if fg.CaptureFailed() {
		// Freeze should have refused an unstable capture; never fall back
		// to live Git after a source snapshot exists.
		return fmt.Errorf("run: Git identity capture failed atomically; re-run when the repository is quiet")
	}
	spec, err := pipeline.Load(fileToLoad)
	if err != nil {
		return err
	}
	// Image lock is COMPILATION authority, identical to the server
	// resolver: the lockfile is parsed strictly, applied to the effective
	// spec, and completeness is enforced BEFORE compile. Executor-time
	// rewrites are not authority — the compiled graph's identity must
	// describe what actually executes.
	lockRoot := lockRootFor(fileToLoad)
	switch {
	case adoptedPipeline && baseDir != "":
		// The pipeline and its image lock came from ONE joint adoption
		// transaction above: the combination is simultaneous by
		// construction. A lock that did not exist at that instant stays
		// absent for this run; a late-appearing lock is not authority
		// (same freeze rule as kiwi.toml).
		if adoptedLockRoot != "" {
			lockRoot = adoptedLockRoot
		} else {
			// No lock at the original location: point at a root with no
			// lockfile so applyLocalImageLock takes the documented
			// "no lockfile" path without reading the live tree.
			lockRoot = filepath.Join(baseDir, ".kiwi-frozen", "lockroot-absent")
		}
	case baseDir != "" && fileToLoad != *file:
		// Frozen in-tree pipeline: a lock that exists in the live working
		// tree but was absent at freeze must not silently apply (or be
		// silently dropped) — fail closed, same rule as kiwi.toml.
		origRoot := lockRootFor(*file)
		if origRoot == "" {
			origRoot = wd
		}
		liveLock := filepath.Join(origRoot, ".kiwi", "lock.json")
		frozenLock := filepath.Join(lockRoot, ".kiwi", "lock.json")
		if fileExists(liveLock) && !fileExists(frozenLock) && filepath.Clean(liveLock) != filepath.Clean(frozenLock) {
			return fmt.Errorf("image lockfile %s exists in the working tree but was not present at freeze time; re-run so the lock is part of the frozen run identity", liveLock)
		}
	}
	if err := applyLocalImageLock(spec, lockRoot); err != nil {
		return err
	}
	// The same input contract the server enforces at enqueue: defaults are
	// applied, required values must be present, unknown names and typed
	// violations are rejected, so local dispatch can never diverge.
	inputsMap, err := pipeline.ValidateRunInputs(spec, inputs.pairs)
	if err != nil {
		return err
	}
	if len(inputsMap) == 0 {
		inputsMap = nil
	}
	g, err := pipeline.CompileWithInputs(spec, inputsMap)
	if err != nil {
		return err
	}
	if *job != "" && !graphHasJob(g, *job) {
		return fmt.Errorf("unknown job %q", *job)
	}
	// Component references are resolved by the control plane (the resolved
	// steps are merged server-side); a local run cannot resolve them, and
	// silently running the raw job would ignore the reference entirely.
	for _, cj := range g.Jobs {
		if cj.Job.Component != "" {
			return fmt.Errorf("job %q references component %q, which requires the control plane: run it through kiwi dispatch/server", cj.ID, cj.Job.Component)
		}
	}
	runID, err := newLocalRunID()
	if err != nil {
		return err
	}
	masker := &secrets.Masker{}
	logs := &logging.Console{Writer: os.Stdout, Masker: masker}
	provider := secrets.Chain{secrets.EnvProvider{Prefix: "KIWI_SECRET_"}, secrets.MacKeychainProvider{Service: "kiwi-ci"}}
	// Repository identity and changed files come from the frozen capture —
	// zero post-Freeze Git reads. detectGitRepo on the (possibly stripped)
	// run-base used to lose remote coordinates for linked worktrees, and
	// live wd reads used to resurrect a HEAD created after Freeze.
	repoURL, repoFullName := fg.RepoURL, fg.RepoFullName
	explicitChanged := *changedFile
	if explicitChanged == "" {
		explicitChanged = *changedFiles
	}
	var changedList []string
	var changedKnown bool
	switch {
	case len(explicitChanged) > 0:
		// Explicit --changed-file(s): pure input parsing, no Git.
		for _, s := range strings.Split(explicitChanged, ",") {
			if s = strings.TrimSpace(s); s != "" {
				changedList = append(changedList, s)
			}
		}
		changedKnown = true
	case fg.Explicit != nil:
		// Explicit --base/--head/--merge-base resolved during the freeze
		// transaction; unresolved stays unknown (never re-derived live).
		changedList, changedKnown = fg.Explicit.Files, fg.Explicit.Known
	case fg.Captured:
		changedList, changedKnown = fg.ChangedFiles, fg.ChangedKnown
	default:
		// NotRepo / RepoNoHead: there is no trustworthy diff, and a
		// repository appearing after Freeze is not this run's authority.
		changedList, changedKnown = nil, false
	}
	opts := executor.Options{Workspace: wd, WorkspaceFor: func(jobID string) (string, func(), error) { return wm.Prepare(ctx, jobID) }, RunID: runID, MaxParallel: *parallel, OnlyJob: *job, ChangedFiles: changedList, ChangedFilesKnown: changedKnown, SecretProvider: provider, Logs: logs, RepoURL: repoURL, RepoFullName: repoFullName,
		// Local parity: job conditions evaluate against the same branch and
		// event context `kiwi explain --why` uses (the git-detected branch,
		// push event), so a branch/event condition cannot silently diverge
		// between explain, local runs and the control plane.
		Branch: frozenBranch(fg),
		Event:  "push",
		GitSHA: frozenSHA(fg),
		GitRef: frozenRef(fg),
		// Declared dependency downloads are restored from this run's local
		// artifact store (the distributed runner restores them through the
		// control plane).
		LocalDownloads: true,
	}
	if vars := splitEnvNames(*passEnv); len(vars) > 0 {
		// Explicit allowlist: only these vars plus the clean env; the
		// inherit-env default is ignored.
		opts.PassEnv = vars
	} else {
		opts.InheritEnv = *inheritEnv && !*noInheritEnv
	}
	// Local runner identity: jobs that require other labels/regions are
	// skipped (no matching runner) instead of running everywhere.
	opts.RunnerLabels = []string{"native", "local"}
	opts.RunnerRegions = []string{"local"}
	// [runner] allow_rootful_untrusted lifts the sandbox.rootless gate on
	// hosts without rootless docker (macOS/colima). Read ONLY from the
	// frozen run-base when Freeze ran: a kiwi.toml created after Freeze in
	// the live CWD must not change AllowRootfulUntrusted for this run.
	cfgPath := ""
	if baseDir != "" {
		if frozenCfg := filepath.Join(baseDir, "kiwi.toml"); fileExists(frozenCfg) {
			cfgPath = frozenCfg
		} else if !fileExists(filepath.Join(wd, "kiwi.toml")) {
			// Absent both in the frozen tree and the live source at load
			// time: nothing to apply.
			cfgPath = ""
		} else {
			// Present in live CWD but absent from the freeze: the file was
			// created after Freeze. Fail closed rather than let a late
			// write flip a security gate.
			return fmt.Errorf("kiwi.toml exists in the working tree but was not present at freeze time; re-run so the config is part of the frozen run identity")
		}
	} else if fileExists("kiwi.toml") {
		cfgPath = "kiwi.toml"
	}
	if cfgPath != "" {
		if cfg, cerr := config.Load(cfgPath); cerr == nil {
			opts.AllowRootfulUntrusted = cfg.Runner.AllowRootfulUntrusted
		}
	}
	ex := executor.Executor{Opt: opts, Masker: masker}
	res, runErr := ex.Run(ctx, g)
	if *jsonOut {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
	} else {
		printSummary(res)
		// A closed stdout pipe (kiwi run | head) used to swallow step output
		// silently. Surface the writer failure so a "silent success" is
		// explainable.
		if werr := logs.WriteErr(); werr != nil {
			fmt.Fprintf(os.Stderr, "kiwi: console output incomplete: %v\n", werr)
		}
	}
	// A cancelled run is never a success: an interrupt (SIGINT/SIGTERM) or a
	// parent-scoped cancellation must exit non-zero, or a `kiwi run && ...`
	// chain would treat an aborted CI run as passing.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("run cancelled: %w", ctxErr)
	}
	// Aggregate gate: every job must be success or skipped. Failure,
	// cancelled and blocked are all non-success outcomes; a run that still
	// contains one is not a green gate even if later jobs passed.
	for id, r := range res {
		switch r.Status {
		case model.StatusFailure:
			// surfaced via runErr
		case model.StatusCancelled:
			return fmt.Errorf("job %s cancelled (timeout or cancel_job_on_failure)", id)
		case model.StatusBlocked:
			return fmt.Errorf("job %s blocked (dependency failed or condition rejected)", id)
		}
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
	if err := applyLocalImageLock(s, lockRootFor(*file)); err != nil {
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
	changedFiles := fs.String("changed-files", "", "comma-separated changed paths for --why (overrides git detection)")
	changedFile := fs.String("changed-file", "", "alias for --changed-files")
	var inputs kvFlags
	fs.Var(&inputs, "input", "pipeline input k=v (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := pipeline.Load(*file)
	if err != nil {
		return err
	}
	if err := applyLocalImageLock(s, lockRootFor(*file)); err != nil {
		return err
	}
	var inputsMap map[string]string
	if len(inputs.pairs) > 0 {
		inputsMap = inputs.pairs
	}
	g, err := pipeline.CompileWithInputs(s, inputsMap)
	if err != nil {
		return err
	}
	changed := *changedFiles
	if changed == "" {
		changed = *changedFile
	}
	if *why != "" {
		return explainWhy(g, *why, explainArgs{Event: *event, Branch: *branch, ChangedFiles: parseCSVPaths(changed)})
	}
	wd, werr := os.Getwd()
	if werr != nil {
		return werr
	}
	return explainGraph(os.Stdout, g, wd)
}

// explainGraph renders the compiled DAG plus cache-key inputs and cache
// candidates (never enabled) for the local explain command.
func explainGraph(out io.Writer, g *pipeline.Graph, workspace string) error {
	ids := make([]string, 0, len(g.Jobs))
	for id := range g.Jobs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		j := g.Jobs[id]
		fmt.Fprintf(out, "%s\n", id)
		fmt.Fprintf(out, "  runtime: %s\n", defaultString(j.Job.Runtime, "native"))
		if len(j.Needs) > 0 {
			fmt.Fprintf(out, "  needs: %v\n", j.Needs)
		}
		if len(j.Matrix) > 0 {
			fmt.Fprintf(out, "  matrix: %v\n", j.Matrix)
		}
		fmt.Fprintf(out, "  steps: %d\n", len(j.Job.Steps))
		for i, st := range j.Job.Steps {
			n := st.Name
			if n == "" {
				n = fmt.Sprintf("step-%d", i+1)
			}
			fmt.Fprintf(out, "    - %s: %s\n", n, oneLine(st.Run))
		}
		printCacheInputs(out, j, workspace)
	}
	printCacheCandidates(out, workspace)
	return nil
}

func detectChangedFiles(workspace string) []string {
	files, _ := detectChangedFilesOpts(workspace, "", "HEAD", "", "")
	return files
}

// detectChangedFilesOpts resolves the changed-file list from explicit input
// or git. known is false when git could not produce a trustworthy diff
// (shallow history, missing HEAD~1, bad --base). Callers must treat
// known=false as "unknown", never as "empty".
func detectChangedFilesOpts(workspace, base, head, mergeBase, changedFile string) ([]string, bool) {
	if strings.TrimSpace(changedFile) != "" {
		var out []string
		for _, s := range strings.Split(changedFile, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out, true
	}
	if mergeBase != "" {
		b, err := exec.Command("git", "-C", workspace, "merge-base", "HEAD", mergeBase).Output()
		if err != nil {
			return nil, false
		}
		base = strings.TrimSpace(string(b))
	}
	if base == "" {
		base = "HEAD~1"
	}
	cmd := exec.Command("git", "-C", workspace, "diff", "--name-only", base, head)
	b, err := cmd.Output()
	if err != nil {
		// Single-commit repos, shallow clones, bad --base, non-git dirs:
		// the diff is unknown, not empty.
		return nil, false
	}
	var out []string
	for _, s := range strings.Split(string(b), "\n") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out, true
}

// parseCSVPaths splits a comma-separated path list (explain --changed-files).
func parseCSVPaths(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// graphHasJob reports whether a job name matches a compiled job or one of its
// matrix variants (every variant shares the declared base id).
func graphHasJob(g *pipeline.Graph, name string) bool {
	for _, cj := range g.Jobs {
		if cj.ID == name || cj.BaseID == name {
			return true
		}
	}
	return false
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

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// frozenBranch/SHA/Ref answer from the frozen capture ONLY. There is no
// gitDir fallback: after Freeze, live Git (or a stripped run-base) is
// never an authority — RepoNoHead keeps an empty SHA for the whole run
// even if the first commit lands later, and NotRepo never grows an
// identity because a repository appeared after the snapshot.
func frozenBranch(fg workspace.FrozenGit) string {
	return fg.Branch
}

func frozenSHA(fg workspace.FrozenGit) string {
	if fg.Captured {
		return fg.SHA
	}
	return ""
}

func frozenRef(fg workspace.FrozenGit) string {
	return fg.Ref
}
