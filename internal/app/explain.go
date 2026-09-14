package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
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

// lockfileDigest computes the SHA-256 cache-key digest of a job's lock
// files with exactly cache.Store.Key semantics: the empty base, a NUL
// separator, then each glob-matched file's workspace-relative path followed
// by its content, in sorted path order. It is deterministic and matches the
// digest the executor derives for a cache entry with an empty key base.
func lockfileDigest(workspace string, hashFiles []string) (string, error) {
	h := sha256.New()
	io.WriteString(h, "\x00")
	var files []string
	for _, p := range hashFiles {
		matches, _ := filepath.Glob(filepath.Join(workspace, p))
		files = append(files, matches...)
	}
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		rel, _ := filepath.Rel(workspace, f)
		io.WriteString(h, rel)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// printCacheInputs renders the cache-key inputs of one compiled job's cache
// entries: the exact lock files hashed, the computed lockfile digest, the
// key and restore keys, the toolchain (runtime + os/arch), the trust domain
// and the restore fallback order.
func printCacheInputs(w io.Writer, j pipeline.CompiledJob, workspace string) {
	for i, c := range j.Job.Cache {
		name := c.Name
		if name == "" {
			name = fmt.Sprintf("cache-%d", i+1)
		}
		digest := "(none)"
		if len(c.HashFiles) > 0 {
			if d, err := lockfileDigest(workspace, c.HashFiles); err == nil {
				digest = d
			} else {
				digest = "(unreadable: " + err.Error() + ")"
			}
		}
		runtimeName := defaultString(j.Job.Runtime, "native")
		trust := "trusted (local)"
		fmt.Fprintf(w, "  cache %s:\n", name)
		fmt.Fprintf(w, "    hash_files: %s\n", strings.Join(c.HashFiles, ", "))
		fmt.Fprintf(w, "    lockfile digest: %s\n", digest)
		fmt.Fprintf(w, "    key: %s\n", defaultString(c.Key, "(unset)"))
		fmt.Fprintf(w, "    restore_keys: %s\n", strings.Join(c.RestoreKeys, ", "))
		fmt.Fprintf(w, "    toolchain: %s (%s/%s)\n", runtimeName, runtime.GOOS, runtime.GOARCH)
		fmt.Fprintf(w, "    trust domain: %s\n", trust)
		fmt.Fprintf(w, "    restore fallback: local then remote\n")
	}
}

// printCacheCandidates surfaces cache.InferLockfiles / cache.SuggestCaches
// candidates for the workspace. These are candidate lines only: nothing is
// enabled.
func printCacheCandidates(w io.Writer, workspace string) {
	suggestions := cache.SuggestCaches(workspace)
	if len(suggestions) == 0 {
		return
	}
	fmt.Fprintf(w, "cache candidates:\n")
	for _, s := range suggestions {
		fmt.Fprintf(w, "  - %s: key_template %q hash_files %s paths %s (%s)\n", s.Name, s.KeyTemplate, strings.Join(s.HashFiles, ", "), strings.Join(s.Paths, ", "), s.Reason)
	}
}
