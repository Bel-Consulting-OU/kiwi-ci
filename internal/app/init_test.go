package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestDetectLanguage exercises one fixture directory per language and
// toolchain variant.
func TestDetectLanguage(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		lang  string
		tool  string
	}{
		{"go", []string{"go.mod"}, "go", ""},
		{"node-npm", []string{"package.json"}, "node", "npm"},
		{"node-pnpm", []string{"package.json", "pnpm-lock.yaml"}, "node", "pnpm"},
		{"node-yarn", []string{"package.json", "yarn.lock"}, "node", "yarn"},
		{"rust", []string{"Cargo.toml"}, "rust", ""},
		{"python-pip", []string{"pyproject.toml"}, "python", "pip"},
		{"python-uv", []string{"pyproject.toml", "uv.lock"}, "python", "uv"},
		{"python-poetry", []string{"poetry.lock"}, "python", "poetry"},
		{"swift-package", []string{"Package.swift"}, "swift", ""},
		{"swift-xcodeproj", []string{"App.xcodeproj"}, "swift", ""},
		{"swift-workspace", []string{"App.xcworkspace"}, "swift", ""},
		{"jvm-maven", []string{"pom.xml"}, "jvm", "maven"},
		{"jvm-gradle", []string{"build.gradle"}, "jvm", "gradle"},
		{"none", []string{"README.md"}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, f := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			lang, tool := detectLanguage(dir)
			if lang != tc.lang || tool != tc.tool {
				t.Fatalf("detectLanguage = (%q, %q), want (%q, %q)", lang, tool, tc.lang, tc.tool)
			}
		})
	}
}

// TestStarterSpecsParse verifies every language's starter pipeline parses
// and carries the expected job shape.
func TestStarterSpecsParse(t *testing.T) {
	langs := []string{"go", "rust", "python", "swift", "jvm", "node"}
	for _, lang := range langs {
		t.Run(lang, func(t *testing.T) {
			spec := starterSpec(lang, toolFor(lang))
			body, err := importer.MarshalSpec(spec)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			parsed, err := pipeline.Parse([]byte(body))
			if err != nil {
				t.Fatalf("starter does not parse: %v\n%s", err, body)
			}
			if len(parsed.Jobs) == 0 {
				t.Fatalf("starter has no jobs")
			}
			for id, j := range parsed.Jobs {
				if len(j.Steps) == 0 {
					t.Fatalf("job %q has no steps", id)
				}
				if j.Runtime == "container" && !strings.Contains(j.Image, placeholderDigest) {
					t.Fatalf("job %q image %q is not pinned to the placeholder digest", id, j.Image)
				}
			}
		})
	}
}

func toolFor(lang string) string {
	switch lang {
	case "python":
		return "uv"
	case "jvm":
		return "maven"
	case "node":
		return "npm"
	}
	return ""
}

// TestInitWritesAndRefusesOverwrite exercises the CLI entry point.
func TestInitWritesAndRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Init([]string{"-dir", dir}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	path := filepath.Join(dir, ".kiwi", "pipeline.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("pipeline not written: %v", err)
	}
	if _, err := pipeline.Parse(b); err != nil {
		t.Fatalf("generated pipeline does not parse: %v", err)
	}
	if !strings.Contains(string(b), placeholderDigest) {
		t.Fatalf("generated pipeline lacks the pinning comment/digest")
	}
	// A second run without --force must refuse.
	if err := Init([]string{"-dir", dir}); err == nil {
		t.Fatalf("second Init overwrote the existing pipeline")
	}
	// With --force it succeeds.
	if err := Init([]string{"-dir", dir, "--force"}); err != nil {
		t.Fatalf("Init --force: %v", err)
	}
}

// TestInitRejectsUnknownLanguage checks the failure path.
func TestInitRejectsUnknownLanguage(t *testing.T) {
	dir := t.TempDir()
	if err := Init([]string{"-dir", dir}); err == nil {
		t.Fatalf("Init succeeded in an empty directory")
	}
}
