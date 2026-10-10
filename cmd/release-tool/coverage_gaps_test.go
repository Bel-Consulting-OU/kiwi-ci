package main

import (
	"debug/buildinfo"
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
)

// TestRunSurfacesModuleGraphError proves a module-graph failure aborts run
// before any SBOM is produced.
func TestRunSurfacesModuleGraphError(t *testing.T) {
	orig := readModuleGraph
	readModuleGraph = func(string) (moduleGraph, error) { return moduleGraph{}, errors.New("graph unavailable") }
	t.Cleanup(func() { readModuleGraph = orig })

	binary := writeTempBinary(t)
	in := testInput(t, binary)
	if err := run(in); err == nil || !strings.Contains(err.Error(), "graph unavailable") {
		t.Fatalf("run = %v, want the module-graph error", err)
	}
	if _, err := os.Stat(filepath.Join(in.OutDir, filepath.Base(binary)+".sbom.cdx.json")); !os.IsNotExist(err) {
		t.Fatalf("SBOM was written despite the graph failure: %v", err)
	}
}

// TestGraphFromBuildInfoReplaceAndNilDep covers the build-info conversion's
// replace directive and nil dependency guard.
func TestGraphFromBuildInfoReplaceAndNilDep(t *testing.T) {
	bi := &buildinfo.BuildInfo{
		Main: debug.Module{
			Path: "example.com/main", Version: "v1.0.0",
			Replace: &debug.Module{Path: "example.com/fork", Version: "v2.0.0"},
		},
		Deps: []*debug.Module{
			nil,
			{Path: "example.com/dep", Version: "v3.0.0", Replace: &debug.Module{Path: "example.com/depfork", Version: "v4.0.0"}},
		},
	}
	g := graphFromBuildInfo(bi)
	if g.Main.Path != "example.com/main" || g.Main.Replace == nil || g.Main.Replace.Path != "example.com/fork" {
		t.Fatalf("main = %+v", g.Main)
	}
	if len(g.Deps) != 1 {
		t.Fatalf("deps = %+v, want the nil entry skipped", g.Deps)
	}
	if g.Deps[0].Replace == nil || g.Deps[0].Replace.Path != "example.com/depfork" {
		t.Fatalf("dep replace = %+v", g.Deps[0])
	}
}

// TestParseGoVersionMStandaloneReplace covers both replacement encodings and
// the short/incomplete lines the parser skips: a standalone `=>` line after
// the mod line replaces the main module, and a `=>` line with too few fields
// is ignored.
func TestParseGoVersionMStandaloneReplace(t *testing.T) {
	out := strings.Join([]string{
		"example.com/main: go1.27",
		"\tmod\texample.com/main\tv1.0.0",
		"\t=>\texample.com/fork\tv2.0.0",
	}, "\n")
	g, err := parseGoVersionM(out)
	if err != nil {
		t.Fatal(err)
	}
	if g.Main.Path != "example.com/main" || g.Main.Replace == nil || g.Main.Replace.Path != "example.com/fork" || g.Main.Replace.Version != "v2.0.0" {
		t.Fatalf("main = %+v", g.Main)
	}

	short := "example.com/main: go1.27\n\tmod\texample.com/main\n\t=>\tonly-one-field\n"
	g, err = parseGoVersionM(short)
	if err != nil {
		t.Fatal(err)
	}
	if g.Main.Replace != nil {
		t.Fatalf("short => line applied: %+v", g.Main.Replace)
	}

	if _, err := parseGoVersionM("no indented lines at all\n"); err == nil {
		t.Fatal("output without a main module must fail")
	}
}

// TestCDXDocumentDeduplicatesGraphModules covers the bom-ref dedup: two graph
// entries resolving to the same module contribute one component.
func TestCDXDocumentDeduplicatesGraphModules(t *testing.T) {
	g := moduleGraph{
		Main: moduleEntry{Path: "example.com/main", Version: "v1.0.0"},
		Deps: []moduleEntry{
			{Path: "example.com/dep", Version: "v1.0.0"},
			{Path: "example.com/dep", Version: "v1.0.0"},
		},
	}
	doc := cdxDocumentForGraph(g, "9.9.9", "kiwi", strings.Repeat("a", 64), "tool", time.Unix(0, 0).UTC())
	if doc.Metadata.Component == nil || doc.Metadata.Component.Version != "9.9.9" {
		t.Fatalf("root = %+v", doc.Metadata.Component)
	}
	// One library component plus the artifact file component.
	if len(doc.Components) != 2 {
		t.Fatalf("components = %+v, want the duplicate module collapsed", doc.Components)
	}
	if len(doc.Dependencies) != 1 || len(doc.Dependencies[0].DependsOn) != 1 {
		t.Fatalf("dependencies = %+v, want exactly one dependency edge", doc.Dependencies)
	}
}

// TestDefaultReadModuleGraphFallsBackToGoVersionM drives the production
// fallback with a fake `go` on PATH: a non-Go file fails buildinfo, so the
// parser decides — once failing with undeclared main-module information, once
// succeeding with a mod line.
func TestDefaultReadModuleGraphFallsBackToGoVersionM(t *testing.T) {
	testutil.UnixShell(t)
	dir := t.TempDir()
	shim := filepath.Join(dir, "go")
	plain := filepath.Join(t.TempDir(), "not-a-go-binary")
	if err := os.WriteFile(plain, []byte("plain text"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := os.WriteFile(shim, []byte("#!/bin/sh\nprintf '\\tdep\\texample.com/x\\tv1.0.0\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultReadModuleGraph(plain); err == nil || !strings.Contains(err.Error(), "no main module information") {
		t.Fatalf("undeclared main module = %v, want the parser failure", err)
	}

	if err := os.WriteFile(shim, []byte("#!/bin/sh\nprintf '\\tmod\\texample.com/main\\tv1.0.0\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	g, err := defaultReadModuleGraph(plain)
	if err != nil || g.Main.Path != "example.com/main" || g.Main.Version != "v1.0.0" {
		t.Fatalf("fallback graph = %+v/%v", g, err)
	}
}
