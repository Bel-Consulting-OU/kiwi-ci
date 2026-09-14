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

// Import migrates a foreign CI configuration into a Kiwi pipeline. It never
// silently approximates behavior: unsupported constructs are reported as
// warnings and TODO placeholders with a confidence score.
func Import(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: kiwi import <github-actions|gitlab|circleci|woodpecker> [--file <path>] [--out <path>] [--list-unsupported]")
	}
	tool := args[0]
	fs := flag.NewFlagSet("import "+tool, flag.ContinueOnError)
	file := fs.String("file", "", "source configuration file (auto-detected when omitted)")
	out := fs.String("out", ".kiwi/pipeline.yaml", "output pipeline path")
	listUnsupported := fs.Bool("list-unsupported", false, "print unsupported constructs instead of writing")
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
	for _, u := range res.Unsupported {
		fmt.Fprintf(os.Stderr, "unsupported: %s\n", u)
	}
	if *listUnsupported {
		fmt.Printf("confidence: %.0f%%\n", res.Confidence*100)
		for _, t := range res.TODOs {
			fmt.Printf("TODO: %s\n", t)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s already exists; remove it or choose a different --out", *out)
	}
	if err := os.WriteFile(*out, []byte(res.PipelineYAML), 0o644); err != nil {
		return err
	}
	fmt.Printf("imported %s -> %s (confidence %.0f%%)\n", src, *out, res.Confidence*100)
	if len(res.Unsupported) > 0 {
		fmt.Fprintf(os.Stderr, "note: %d unsupported constructs; see --list-unsupported\n", len(res.Unsupported))
	}
	return nil
}

// detectImportSource finds the conventional configuration file for a tool in
// the current directory.
func detectImportSource(tool string) string {
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

var _ = strings.TrimSpace
