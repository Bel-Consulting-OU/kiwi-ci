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
				if j.Runtime == "container" {
					// Images must be READABLE tags: `kiwi lock` resolves
					// them to digests. The historical all-zero placeholder
					// must never reappear.
					if strings.Contains(j.Image, "sha256:0000000000000000000000000000000000000000000000000000000000000000") {
						t.Fatalf("job %q image %q carries the zero placeholder digest", id, j.Image)
					}
					if strings.Contains(j.Image, "@sha256:") && !strings.Contains(j.Image, "@sha256:0") {
						// A real digest is acceptable only if lock wrote it;
						// init itself emits tags.
						t.Fatalf("job %q image %q: init should emit a readable tag, not a digest", id, j.Image)
					}
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
	if strings.Contains(string(b), "sha256:0000000000000000000000000000000000000000000000000000000000000000") {
		t.Fatalf("generated pipeline must not carry the zero placeholder digest")
	}
	if !strings.Contains(string(b), "kiwi lock") {
		t.Fatalf("generated pipeline must point at kiwi lock for digest resolution")
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

// TestInitGenerateValidateRunFixtures is the executable-correctness
// contract the audit requires: for every project fixture kiwi init
// recognizes, the generated pipeline must pass `kiwi validate` (and the
// job graph must compile). A plausible-looking template that fails
// validation is a product defect, not a documentation issue.
func TestInitGenerateValidateRunFixtures(t *testing.T) {
	fixtures := []struct {
		name  string
		files map[string]string
		lang  string
		tool  string
		// wantIn is a substring that must appear in the generated pipeline
		// (pins the command/toolchain pairing).
		wantIn string
		// wantAbsent is a substring that must NOT appear (the old bug).
		wantAbsent string
	}{
		{
			name:   "go",
			files:  map[string]string{"go.mod": "module example.com/x\n\ngo 1.22\n"},
			lang:   "go",
			wantIn: "go test",
		},
		{
			name:   "cargo",
			files:  map[string]string{"Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"\n"},
			lang:   "rust",
			wantIn: "cargo test",
		},
		{
			name:  "npm",
			files: map[string]string{"package.json": `{"name":"x","version":"1.0.0"}`},
			lang:  "node", tool: "npm",
			wantIn:     "npm test",
			wantAbsent: "yarn run",
		},
		{
			name:  "yarn",
			files: map[string]string{"package.json": `{"name":"x"}`, "yarn.lock": "# yarn lockfile v1\n"},
			lang:  "node", tool: "yarn",
			wantIn:     "yarn install",
			wantAbsent: "npm ci",
		},
		{
			name:  "pnpm",
			files: map[string]string{"package.json": `{"name":"x"}`, "pnpm-lock.yaml": "lockfileVersion: 9\n"},
			lang:  "node", tool: "pnpm",
			wantIn:     "pnpm install",
			wantAbsent: "npm ci",
		},
		{
			name:  "python-setuptools",
			files: map[string]string{"pyproject.toml": "[project]\nname = \"x\"\n"},
			lang:  "python", tool: "pip",
			wantIn:     "python -m venv",
			wantAbsent: "uv sync",
		},
		{
			name:  "python-poetry",
			files: map[string]string{"pyproject.toml": "[project]\nname = \"x\"\n", "poetry.lock": "[]\n"},
			lang:  "python", tool: "poetry",
			wantIn:     "poetry install",
			wantAbsent: "uv sync",
		},
		{
			name:  "python-uv",
			files: map[string]string{"pyproject.toml": "[project]\nname = \"x\"\n", "uv.lock": "version = 1\n"},
			lang:  "python", tool: "uv",
			// uv is not in python:3.12: the generated pipeline must
			// install it before calling it.
			wantIn:     "pip install",
			wantAbsent: "uv sync --frozen && uv run ruff",
		},
		{
			name:   "swift-package",
			files:  map[string]string{"Package.swift": "// swift-tools-version:5.9\n"},
			lang:   "swift",
			wantIn: "swift build",
		},
		{
			name:  "xcodeproj",
			files: map[string]string{"App.xcodeproj/project.pbxproj": "// !$*UTF8*$!\n"},
			lang:  "swift",
			// The old sed-over-JSON scheme inference is gone; SCHEME is
			// explicit.
			wantIn:     "SCHEME",
			wantAbsent: "xcodebuild -list",
		},
		{
			name:  "maven",
			files: map[string]string{"pom.xml": "<project/>\n"},
			lang:  "jvm", tool: "maven",
			wantIn: "mvn",
		},
		{
			name:  "gradle",
			files: map[string]string{"build.gradle": "plugins {}\n"},
			lang:  "jvm", tool: "gradle",
			wantIn: "gradlew",
		},
	}
	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range tc.files {
				full := filepath.Join(dir, name)
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			// Detection must agree with the fixture.
			lang, tool := detectLanguage(dir)
			if lang != tc.lang || tool != tc.tool {
				t.Fatalf("detectLanguage = (%q, %q), want (%q, %q)", lang, tool, tc.lang, tc.tool)
			}
			// init must succeed.
			if err := Init([]string{"-dir", dir}); err != nil {
				t.Fatalf("Init: %v", err)
			}
			raw, err := os.ReadFile(filepath.Join(dir, ".kiwi", "pipeline.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			body := string(raw)
			if tc.wantIn != "" && !strings.Contains(body, tc.wantIn) {
				t.Fatalf("generated pipeline missing %q:\n%s", tc.wantIn, body)
			}
			if tc.wantAbsent != "" && strings.Contains(body, tc.wantAbsent) {
				t.Fatalf("generated pipeline must NOT contain %q:\n%s", tc.wantAbsent, body)
			}
			// THE contract: the generated pipeline must validate.
			if err := Validate([]string{"-f", filepath.Join(dir, ".kiwi", "pipeline.yaml")}); err != nil {
				t.Fatalf("kiwi validate failed for fixture %s: %v\n%s", tc.name, err, body)
			}
			// And compile to a non-empty graph.
			spec, err := pipeline.Parse(raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			g, err := pipeline.Compile(spec)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if len(g.Jobs) == 0 {
				t.Fatal("compiled graph is empty")
			}
		})
	}
}
