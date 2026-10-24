package app

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer/circleci"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer/githubactions"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer/gitlab"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer/woodpecker"
)

// Import migrates a foreign CI configuration into a Kiwi pipeline.
//
// Safe-by-default: exact conversions write the pipeline; TODO-only
// conversions write with a strong review warning; Unsupported or Unsafe
// constructs refuse to write unless --allow-partial is set (and then the
// YAML carries an incomplete-pipeline header listing the gaps).
func Import(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: kiwi import <github-actions|gitlab|circleci|woodpecker> [--file <path>] [--out <path>] [--list-unsupported] [--allow-partial]")
	}
	tool := args[0]
	fs := flag.NewFlagSet("import "+tool, flag.ContinueOnError)
	file := fs.String("file", "", "source configuration file (auto-detected when omitted)")
	out := fs.String("out", ".kiwi/pipeline.yaml", "output pipeline path")
	listUnsupported := fs.Bool("list-unsupported", false, "print unsupported/unsafe/TODO constructs instead of writing")
	allowPartial := fs.Bool("allow-partial", false, "write an incomplete conversion despite unsupported or unsafe constructs")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	src := *file
	if src == "" {
		src = detectImportSource(tool)
	}
	if src == "" {
		return fmt.Errorf("no source file found for %s; pass --file", tool)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	var conv importer.Importer
	switch tool {
	case "github-actions", "github", "actions":
		conv = githubactions.New()
	case "gitlab":
		conv = gitlab.New()
	case "circleci", "circle":
		conv = circleci.New()
	case "woodpecker":
		conv = woodpecker.New()
	default:
		return fmt.Errorf("unknown importer %q (github-actions, gitlab, circleci, woodpecker)", tool)
	}
	res, err := conv.Import(string(data))
	if err != nil {
		return fmt.Errorf("import %s: %w", tool, err)
	}
	for _, w := range res.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	if *listUnsupported {
		fmt.Printf("confidence: %.0f%%\n", res.Confidence*100)
		for _, u := range res.Unsupported {
			fmt.Printf("unsupported: %s\n", u)
		}
		for _, u := range res.Unsafe {
			fmt.Printf("unsafe: %s\n", u)
		}
		for _, t := range res.TODOs {
			fmt.Printf("TODO: %s\n", t)
		}
		return nil
	}
	for _, u := range res.Unsupported {
		fmt.Fprintf(os.Stderr, "unsupported: %s\n", u)
	}
	for _, u := range res.Unsafe {
		fmt.Fprintf(os.Stderr, "unsafe: %s\n", u)
	}
	partial := len(res.Unsupported) > 0 || len(res.Unsafe) > 0
	if partial && !*allowPartial {
		return fmt.Errorf("import %s: %d unsupported and %d unsafe construct(s); not writing %s\nRe-run with --allow-partial to write an incomplete pipeline, or --list-unsupported for the full report",
			tool, len(res.Unsupported), len(res.Unsafe), *out)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s already exists; remove it or choose a different --out", *out)
	}
	yamlOut := res.PipelineYAML
	if partial {
		yamlOut = incompleteImportHeader(res) + yamlOut
	}
	if err := os.WriteFile(*out, []byte(yamlOut), 0o644); err != nil {
		return err
	}
	fmt.Printf("imported %s -> %s (confidence %.0f%%)\n", src, *out, res.Confidence*100)
	if partial {
		fmt.Fprintf(os.Stderr, "incomplete conversion written under --allow-partial: %d unsupported, %d unsafe, %d TODO; review before trusting this pipeline\n",
			len(res.Unsupported), len(res.Unsafe), len(res.TODOs))
	} else if len(res.TODOs) > 0 {
		fmt.Fprintf(os.Stderr, "REVIEW REQUIRED: %d TODO item(s); see --list-unsupported\n", len(res.TODOs))
	}
	return nil
}

// incompleteImportHeader is prepended to a partial conversion so the YAML
// itself cannot be mistaken for an exact migration.
func incompleteImportHeader(res *importer.Result) string {
	var b strings.Builder
	b.WriteString("# incomplete import — do not treat as an exact conversion.\n")
	b.WriteString("# Re-run `kiwi import ... --list-unsupported` for the full gap list.\n")
	for _, u := range res.Unsupported {
		fmt.Fprintf(&b, "# unsupported: %s\n", u)
	}
	for _, u := range res.Unsafe {
		fmt.Fprintf(&b, "# unsafe: %s\n", u)
	}
	for _, t := range res.TODOs {
		fmt.Fprintf(&b, "# TODO: %s\n", t)
	}
	b.WriteString("\n")
	return b.String()
}

// detectImportSource finds the conventional configuration file for a tool in
// the current directory. Aliases accepted by Import map to the same lookup.
func detectImportSource(tool string) string {
	switch tool {
	case "github", "actions":
		tool = "github-actions"
	case "circle":
		tool = "circleci"
	}
	candidates := map[string][]string{
		"github-actions": {".github/workflows/ci.yml", ".github/workflows/ci.yaml"},
		"gitlab":         {".gitlab-ci.yml", ".gitlab-ci.yaml"},
		"circleci":       {".circleci/config.yml", ".circleci/config.yaml"},
		"woodpecker":     {".woodpecker.yml", ".woodpecker.yaml"},
	}
	for _, c := range candidates[tool] {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}
