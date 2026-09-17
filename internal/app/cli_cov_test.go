package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/explain"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// chdir switches the process working directory for the duration of the test.
func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}

const richPipeline = `version: 1
name: cov
on:
  push:
    branches: [main]
    paths: ["src/**"]
env:
  GLOBAL: "1"
jobs:
  lint:
    steps:
      - name: vet
        run: echo vet
      - run: |
          echo multi
          echo line
  test:
    needs: [lint]
    matrix:
      go: ["1.22", "1.23"]
    cache:
      - name: go-cache
        key: go-{{ os }}
        restore_keys: [go-]
        hash_files: ["go.sum"]
        paths: [".cache"]
    steps:
      - run: echo test
`

func writePipeline(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "pipeline.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, ".gitkeep"), "")
	runGit(t, dir, "init", "-q", "-b", "main")
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-q", "-m", "one")
}

func TestRunLocalNativePipeline(t *testing.T) {
	dir := t.TempDir()
	pipelinePath := writePipeline(t, dir, "version: 1\njobs:\n  build:\n    steps:\n      - name: hello\n        run: echo local-ok\n")
	writeFile(t, filepath.Join(dir, "marker.txt"), "x")
	chdir(t, dir)
	if err := RunLocal(context.Background(), []string{"-f", pipelinePath, "--json", "--changed-file", "marker.txt,a b,,c", "--max-parallel", "1"}); err != nil {
		t.Fatalf("RunLocal: %v", err)
	}
	if err := RunLocal(context.Background(), []string{"-f", pipelinePath, "--job", "build", "--pass-env", "PATH, ,HOME", "--base", "HEAD"}); err != nil {
		t.Fatalf("RunLocal with --job/--pass-env: %v", err)
	}
	if err := RunLocal(context.Background(), []string{"-f", pipelinePath, "--no-inherit-env", "--input", "env=staging"}); err != nil {
		t.Fatalf("RunLocal with --input: %v", err)
	}
}

func TestRunLocalErrors(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	if err := RunLocal(context.Background(), []string{"-f", filepath.Join(dir, "nope.yaml")}); err == nil {
		t.Fatal("missing pipeline accepted")
	}
	bad := writePipeline(t, dir, "version: 1\njobs:\n  build:\n    steps: []\n")
	if err := RunLocal(context.Background(), []string{"-f", bad}); err == nil {
		t.Fatal("invalid pipeline accepted")
	}
	good := writePipeline(t, dir, "version: 1\njobs:\n  build:\n    steps:\n      - run: echo ok\n")
	if err := RunLocal(context.Background(), []string{"-f", good, "--input", "broken"}); err == nil {
		t.Fatal("malformed --input accepted")
	}
	if err := RunLocal(context.Background(), []string{"--bogus"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
}

func TestValidateCommand(t *testing.T) {
	dir := t.TempDir()
	good := writePipeline(t, dir, "version: 1\njobs:\n  build:\n    steps:\n      - run: echo ok\n")
	if err := Validate([]string{"-f", good}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := Validate([]string{"-f", filepath.Join(dir, "missing.yaml")}); err == nil {
		t.Fatal("missing pipeline accepted")
	}
	if err := Validate([]string{"--bogus"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
}

func TestExplainCommandGraphAndWhy(t *testing.T) {
	dir := t.TempDir()
	path := writePipeline(t, dir, richPipeline)
	chdir(t, dir)
	if err := Explain([]string{"-f", path}); err != nil {
		t.Fatalf("Explain graph: %v", err)
	}
	if err := Explain([]string{"-f", path, "--why", "lint", "--event", "push", "--branch", "main", "--input", "x=1"}); err != nil {
		t.Fatalf("Explain why: %v", err)
	}
	if err := Explain([]string{"-f", path, "--why", "missing"}); err == nil {
		t.Fatal("unknown job accepted")
	}
	if err := Explain([]string{"-f", filepath.Join(dir, "nope.yaml")}); err == nil {
		t.Fatal("missing pipeline accepted")
	}
	if err := Explain([]string{"--bogus"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
}

func TestExplainGraphRendersCacheAndMatrix(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte("digest\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := pipeline.Load(writePipeline(t, dir, richPipeline))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	if err := explainGraph(&sb, g, dir); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{"lint", "test", "matrix:", "cache go-cache", "lockfile digest:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("explain output missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "…") {
		t.Fatalf("multi-line run was not shortened:\n%s", out)
	}
}

func TestExplainWhyBranchFallbackAndPrintWhy(t *testing.T) {
	dir := t.TempDir()
	initGitRepo(t, dir)
	path := writePipeline(t, dir, richPipeline)
	chdir(t, dir)
	// No --branch: detectCurrentBranch resolves "main" from the git repo.
	if err := Explain([]string{"-f", path, "--why", "lint"}); err != nil {
		t.Fatalf("Explain why without branch: %v", err)
	}
	if got := detectCurrentBranch(dir); got != "main" {
		t.Fatalf("detectCurrentBranch = %q, want main", got)
	}
	if got := detectCurrentBranch(filepath.Join(dir, "does-not-exist")); got != "" {
		t.Fatalf("detectCurrentBranch on missing dir = %q", got)
	}
	printWhy(&explain.Why{
		JobID: "test", EventMatched: true, TriggerKey: "push", BranchMatched: true,
		PathMatched: true, PathRule: "src/**", ChangedPaths: []string{"src/a.go"},
		Packages: []string{"./src"}, Condition: "success()", ConditionResult: true,
		Needs: []string{"lint"}, Approval: true, RequiredLabels: []string{"ok"},
		Regions: []string{"eu"}, CacheKeys: []string{"go"}, Policy: []string{"trusted"},
		QueueReason: "capacity",
	})
}

func TestLockfileDigestDirectoryMatchFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "dir.lock"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := lockfileDigest(dir, []string{"dir.lock"}); err == nil {
		t.Fatal("directory match accepted as a lock file")
	}
}

func TestPrintCacheInputsUnreadableLockfile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "lockdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	j := pipeline.CompiledJob{Job: pipeline.Job{Cache: []pipeline.Cache{{Name: "", HashFiles: []string{"lockdir"}, Key: "", RestoreKeys: nil}}}}
	var sb strings.Builder
	printCacheInputs(&sb, j, dir)
	if !strings.Contains(sb.String(), "unreadable") {
		t.Fatalf("unreadable lockfile not surfaced: %s", sb.String())
	}
	if !strings.Contains(sb.String(), "cache-1") {
		t.Fatalf("unnamed cache not numbered: %s", sb.String())
	}
}

func TestDetectChangedFilesOpts(t *testing.T) {
	if got := detectChangedFilesOpts("/nonexistent", "", "HEAD", "", "a.go, b.go ,,"); len(got) != 2 || got[0] != "a.go" || got[1] != "b.go" {
		t.Fatalf("explicit changed files = %v", got)
	}
	if got := detectChangedFiles("/nonexistent-repo"); got != nil {
		t.Fatalf("changed files outside a repo = %v", got)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "first.txt"), "1")
	initGitRepo(t, dir)
	writeFile(t, filepath.Join(dir, "second.txt"), "2")
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-q", "-m", "two")
	got := detectChangedFilesOpts(dir, "HEAD~1", "HEAD", "", "")
	if len(got) != 1 || got[0] != "second.txt" {
		t.Fatalf("git diff changed files = %v", got)
	}
	got = detectChangedFilesOpts(dir, "", "HEAD", "HEAD", "")
	if len(got) != 0 {
		t.Fatalf("merge-base HEAD diff = %v, want empty", got)
	}
	if got := detectChangedFilesOpts(dir, "no-such-ref", "HEAD", "", ""); got != nil {
		t.Fatalf("bad ref changed files = %v", got)
	}
}

func TestPrintSummaryAndOneLine(t *testing.T) {
	printSummary(nil)
	if oneLine("a\nb") != "a …" {
		t.Fatal("oneLine newline truncation")
	}
	long := strings.Repeat("x", 80)
	if !strings.HasSuffix(oneLine(long), "…") {
		t.Fatal("oneLine long-line truncation")
	}
	if oneLine("short") != "short" {
		t.Fatal("oneLine short passthrough")
	}
	if defaultString("", "d") != "d" || defaultString("v", "d") != "v" {
		t.Fatal("defaultString")
	}
	if got := splitEnvNames("A, B ,,C"); len(got) != 3 || got[0] != "A" {
		t.Fatalf("splitEnvNames = %v", got)
	}
	if got := splitEnvNames(" , "); len(got) != 0 {
		t.Fatalf("blank splitEnvNames = %v", got)
	}
	if id, err := newLocalRunID(); err != nil || len(id) != 32 {
		t.Fatalf("newLocalRunID = %q, %v", id, err)
	}
}

func TestConfigCheckFlagAndEnvErrors(t *testing.T) {
	if err := ConfigCheck(context.Background(), []string{"--bogus"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	t.Setenv("KIWI_GITHUB_APP_ID", "not-a-number")
	if err := ConfigCheck(context.Background(), []string{"--config", writeConfigFile(t, "")}); err == nil {
		t.Fatal("invalid environment overlay accepted")
	}
}

func TestDoctorCoversFoundAndMissingLookups(t *testing.T) {
	if err := Doctor([]string{"--bogus"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if err := Doctor(nil); err != nil {
		t.Fatalf("Doctor: %v", err)
	}
	t.Setenv("PATH", t.TempDir())
	if err := Doctor(nil); err != nil {
		t.Fatalf("Doctor with empty PATH: %v", err)
	}
	// A fake docker/tart/security binary exercises the found branch.
	dir := t.TempDir()
	for _, name := range []string{"git", "bash", "docker", "tart", "xcodebuild", "security"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	if err := Doctor(nil); err != nil {
		t.Fatalf("Doctor with fake tools: %v", err)
	}
}

func TestImportAllTools(t *testing.T) {
	cases := []struct {
		tool string
		body string
	}{
		{"github-actions", "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo hi\n"},
		{"gitlab", "stages: [build]\nbuild:\n  stage: build\n  script:\n    - echo hi\n"},
		{"circleci", "version: 2.1\njobs:\n  build:\n    docker:\n      - image: cimg/go:1.23\n    steps:\n      - checkout\n      - run: echo hi\nworkflows:\n  main:\n    jobs: [build]\n"},
		{"woodpecker", "pipeline:\n  build:\n    image: golang:1.23\n    commands:\n      - echo hi\n"},
	}
	for _, c := range cases {
		t.Run(c.tool, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "src.yaml")
			if err := os.WriteFile(src, []byte(c.body), 0o644); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, "out", "pipeline.yaml")
			if err := Import([]string{c.tool, "--file", src, "--out", out}); err != nil {
				t.Fatalf("import %s: %v", c.tool, err)
			}
			if _, err := os.Stat(out); err != nil {
				t.Fatalf("import %s did not write output: %v", c.tool, err)
			}
			if err := Import([]string{c.tool, "--file", src, "--out", out}); err == nil {
				t.Fatal("existing output accepted")
			}
			if err := Import([]string{c.tool, "--file", src, "--list-unsupported"}); err != nil {
				t.Fatalf("import %s --list-unsupported: %v", c.tool, err)
			}
		})
	}
}

func TestImportErrorsAndDetection(t *testing.T) {
	if err := Import(nil); err == nil {
		t.Fatal("missing tool accepted")
	}
	if err := Import([]string{"bogus", "--file", "x"}); err == nil {
		t.Fatal("unknown importer accepted")
	}
	if err := Import([]string{"github-actions", "--bogus"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	missingTool := t.TempDir()
	if err := Import([]string{"github-actions", "--file", filepath.Join(missingTool, "nope.yml")}); err == nil {
		t.Fatal("missing source file accepted")
	}
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "bad.yml"), []byte("\tnot: [valid"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Import([]string{"github-actions", "--file", filepath.Join(bad, "bad.yml")}); err == nil {
		t.Fatal("malformed source accepted")
	}
	// A workflow with no jobs produces importer warnings on the write path.
	warnDir := t.TempDir()
	warnSrc := filepath.Join(warnDir, "empty.yml")
	if err := os.WriteFile(warnSrc, []byte("name: empty\non: push\njobs: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Import([]string{"github-actions", "--file", warnSrc, "--out", filepath.Join(warnDir, "out.yaml")}); err != nil {
		t.Fatalf("warning import: %v", err)
	}
	// Auto-detection from the conventional paths.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".github", "workflows", "ci.yml"), []byte("name: ci\non: push\njobs: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitlab-ci.yml"), []byte("build:\n  script: [echo hi]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".circleci"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".circleci", "config.yml"), []byte("version: 2.1\njobs: {}\nworkflows: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".woodpecker.yml"), []byte("pipeline:\n  build:\n    image: alpine\n    commands: [true]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	chdir(t, dir)
	for _, tool := range []string{"github-actions", "gitlab", "circleci", "woodpecker"} {
		if src := detectImportSource(tool); src == "" {
			t.Fatalf("detectImportSource(%s) found nothing", tool)
		}
	}
	if src := detectImportSource("bogus"); src != "" {
		t.Fatalf("detectImportSource(bogus) = %q", src)
	}
	out := filepath.Join(dir, "generated.yaml")
	if err := Import([]string{"gitlab", "--out", out}); err != nil {
		t.Fatalf("auto-detected import: %v", err)
	}
	// A directory standing in for the conventional file is not a source.
	if err := os.Remove(filepath.Join(dir, ".woodpecker.yml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, ".woodpecker.yml"), 0o755); err != nil {
		t.Fatal(err)
	}
	if src := detectImportSource("woodpecker"); src != "" {
		t.Fatalf("directory detected as import source: %q", src)
	}
}

func TestInitCoversStartersAndErrors(t *testing.T) {
	for _, lang := range []string{"go", "rust", "swift", "jvm", "python", "node", "bogus"} {
		for _, tool := range []string{"", "maven", "gradle", "uv", "poetry", "pip", "npm", "yarn", "pnpm"} {
			if spec := starterSpec(lang, tool); spec == nil {
				t.Fatalf("starterSpec(%s,%s) = nil", lang, tool)
			}
		}
	}
	if err := Init([]string{"--bogus"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	empty := t.TempDir()
	if err := Init([]string{"--dir", empty}); err == nil {
		t.Fatal("unknown language accepted")
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module x\n")
	if err := Init([]string{"--dir", dir, "-f", "ci/pipeline.yaml"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := Init([]string{"--dir", dir, "-f", "ci/pipeline.yaml"}); err == nil {
		t.Fatal("existing pipeline accepted without --force")
	}
	if err := Init([]string{"--dir", dir, "-f", "ci/pipeline.yaml", "--force"}); err != nil {
		t.Fatalf("Init --force: %v", err)
	}
	// The output parent being a regular file fails directory creation.
	blocked := t.TempDir()
	writeFile(t, filepath.Join(blocked, "go.mod"), "module x\n")
	writeFile(t, filepath.Join(blocked, "out"), "not a dir")
	if err := Init([]string{"--dir", blocked, "-f", "out/pipeline.yaml"}); err == nil {
		t.Fatal("output under a file accepted")
	}
}

func TestDetectLanguageMatrix(t *testing.T) {
	cases := []struct {
		files []string
		lang  string
		tool  string
	}{
		{[]string{"Cargo.toml"}, "rust", ""},
		{[]string{"Package.swift"}, "swift", ""},
		{[]string{"app.xcodeproj"}, "swift", ""},
		{[]string{"app.xcworkspace"}, "swift", ""},
		{[]string{"pom.xml"}, "jvm", "maven"},
		{[]string{"build.gradle"}, "jvm", "gradle"},
		{[]string{"build.gradle.kts"}, "jvm", "gradle"},
		{[]string{"pyproject.toml"}, "python", "pip"},
		{[]string{"uv.lock"}, "python", "uv"},
		{[]string{"poetry.lock"}, "python", "poetry"},
		{[]string{"pnpm-lock.yaml"}, "node", "pnpm"},
		{[]string{"yarn.lock"}, "node", "yarn"},
		{[]string{"package.json"}, "node", "npm"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		for _, f := range c.files {
			if strings.Contains(f, ".") && (strings.HasSuffix(f, "xcodeproj") || strings.HasSuffix(f, "xcworkspace")) {
				if err := os.Mkdir(filepath.Join(dir, f), 0o755); err != nil {
					t.Fatal(err)
				}
				continue
			}
			writeFile(t, filepath.Join(dir, f), "x")
		}
		lang, tool := detectLanguage(dir)
		if lang != c.lang || tool != c.tool {
			t.Fatalf("detectLanguage(%v) = %s/%s, want %s/%s", c.files, lang, tool, c.lang, c.tool)
		}
	}
}

func writeConfigFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kiwi.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=t@example.com", "-c", "user.name=t"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}
