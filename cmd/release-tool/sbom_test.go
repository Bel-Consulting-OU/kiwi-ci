package main

import (
	"debug/buildinfo"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// fixtureGoVersionM mirrors `go version -m kiwi` output for a small module
// graph with one direct dependency, one transitive dependency, and one
// replaced module.
const fixtureGoVersionM = "/tmp/kiwi: go1.27.1\n" +
	"\tpath\tgithub.com/Bel-Consulting-OU/kiwi-ci\n" +
	"\tmod\tgithub.com/Bel-Consulting-OU/kiwi-ci\t(devel)\t\n" +
	"\tdep\tgithub.com/jackc/pgx/v5\tv5.11.0\th1:pgxsum\n" +
	"\tdep\tgithub.com/jackc/pgpassfile\tv1.0.0\th1:pgpasssum\n" +
	"\tdep\tgithub.com/example/old\tv1.0.0\th1:oldsum\n" +
	"\t=>\tgithub.com/example/new\tv2.0.0\th1:newsum\n"

// fixtureBuildInfo is the pure fixture for the debug/buildinfo conversion.
func fixtureBuildInfo() *buildinfo.BuildInfo {
	return &buildinfo.BuildInfo{
		GoVersion: "go1.27.1",
		Path:      "github.com/Bel-Consulting-OU/kiwi-ci",
		Main:      debug.Module{Path: "github.com/Bel-Consulting-OU/kiwi-ci", Version: "(devel)"},
		Deps: []*debug.Module{
			{Path: "github.com/jackc/pgx/v5", Version: "v5.11.0", Sum: "h1:pgxsum"},
			{Path: "github.com/jackc/pgpassfile", Version: "v1.0.0", Sum: "h1:pgpasssum"},
			{Path: "github.com/example/old", Version: "v1.0.0", Sum: "h1:oldsum",
				Replace: &debug.Module{Path: "github.com/example/new", Version: "v2.0.0", Sum: "h1:newsum"}},
		},
	}
}

func fixtureGraph() moduleGraph {
	return graphFromBuildInfo(fixtureBuildInfo())
}

func TestGraphFromBuildInfo(t *testing.T) {
	g := fixtureGraph()
	if g.Main.Path != "github.com/Bel-Consulting-OU/kiwi-ci" {
		t.Fatalf("main module = %+v", g.Main)
	}
	if len(g.Deps) != 3 {
		t.Fatalf("deps = %+v, want 3 modules", g.Deps)
	}
	if g.Deps[0].effective().Path != "github.com/jackc/pgx/v5" || g.Deps[1].effective().Path != "github.com/jackc/pgpassfile" {
		t.Fatalf("direct/transitive deps lost: %+v", g.Deps)
	}
	replaced := g.Deps[2].effective()
	if replaced.Path != "github.com/example/new" || replaced.Version != "v2.0.0" {
		t.Fatalf("replace directive not followed: %+v", replaced)
	}
}

func TestParseGoVersionMFixture(t *testing.T) {
	g, err := parseGoVersionM(fixtureGoVersionM)
	if err != nil {
		t.Fatal(err)
	}
	if g.Main.Path != "github.com/Bel-Consulting-OU/kiwi-ci" || g.Main.Version != "(devel)" {
		t.Fatalf("main module = %+v", g.Main)
	}
	if len(g.Deps) != 3 {
		t.Fatalf("deps = %+v, want 3 modules", g.Deps)
	}
	if g.Deps[0].Path != "github.com/jackc/pgx/v5" || g.Deps[0].Version != "v5.11.0" {
		t.Fatalf("direct dependency lost: %+v", g.Deps[0])
	}
	if g.Deps[1].Path != "github.com/jackc/pgpassfile" || g.Deps[1].Version != "v1.0.0" {
		t.Fatalf("transitive dependency lost: %+v", g.Deps[1])
	}
	if repl := g.Deps[2].effective(); repl.Path != "github.com/example/new" || repl.Version != "v2.0.0" {
		t.Fatalf("=> replacement line not parsed: %+v", g.Deps[2])
	}
}

func TestParseGoVersionMInlineReplacement(t *testing.T) {
	out := "/tmp/kiwi: go1.27.1\n" +
		"\tpath\tgithub.com/Bel-Consulting-OU/kiwi-ci\n" +
		"\tmod\tgithub.com/Bel-Consulting-OU/kiwi-ci\t(devel)\n" +
		"\tdep\tgithub.com/example/old\tv1.0.0\th1:oldsum\t=>\tgithub.com/example/new\tv2.0.0\th1:newsum\n"
	g, err := parseGoVersionM(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Deps) != 1 {
		t.Fatalf("deps = %+v", g.Deps)
	}
	if repl := g.Deps[0].effective(); repl.Path != "github.com/example/new" || repl.Version != "v2.0.0" {
		t.Fatalf("inline replacement not parsed: %+v", g.Deps[0])
	}
}

func TestParseGoVersionMMalformed(t *testing.T) {
	if _, err := parseGoVersionM("/tmp/not-a-binary: no build info\n"); err == nil {
		t.Fatal("output without module information must error")
	}
	if _, err := parseGoVersionM(""); err == nil {
		t.Fatal("empty output must error")
	}
}

func TestCycloneDXFromGraph(t *testing.T) {
	const (
		rootVersion = "1.2.3"
		artifact    = "kiwi-test-binary"
		artifactSHA = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
		toolVersion = "1.2.3"
	)
	when := time.Unix(1700000000, 0).UTC()
	doc := cdxDocumentForGraph(fixtureGraph(), rootVersion, artifact, artifactSHA, toolVersion, when)

	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" || doc.Version != 1 {
		t.Fatalf("unexpected document header: %+v", doc)
	}
	if doc.Metadata.Timestamp != when.Format(time.RFC3339) {
		t.Fatalf("timestamp = %q", doc.Metadata.Timestamp)
	}
	if doc.Metadata.Component == nil {
		t.Fatal("missing root component")
	}
	root := *doc.Metadata.Component
	if root.Type != "application" || root.Name != "github.com/Bel-Consulting-OU/kiwi-ci" || root.Version != rootVersion {
		t.Fatalf("root component = %+v", root)
	}
	wantRootPURL := "pkg:golang/github.com/Bel-Consulting-OU/kiwi-ci@1.2.3"
	if root.PURL != wantRootPURL || root.BOMRef != wantRootPURL {
		t.Fatalf("root purl/bom-ref = %q/%q", root.PURL, root.BOMRef)
	}

	byName := map[string]cdxComponent{}
	for _, c := range doc.Components {
		byName[c.Name] = c
	}
	direct, ok := byName["github.com/jackc/pgx/v5"]
	if !ok {
		t.Fatalf("direct dependency missing from SBOM components: %+v", doc.Components)
	}
	if direct.Version != "v5.11.0" || direct.Type != "library" || direct.PURL != "pkg:golang/github.com/jackc/pgx/v5@v5.11.0" {
		t.Fatalf("direct dependency component = %+v", direct)
	}
	if direct.BOMRef != direct.PURL {
		t.Fatalf("direct dependency bom-ref = %q", direct.BOMRef)
	}
	transitive, ok := byName["github.com/jackc/pgpassfile"]
	if !ok {
		t.Fatalf("transitive dependency missing from SBOM components: %+v", doc.Components)
	}
	if transitive.PURL != "pkg:golang/github.com/jackc/pgpassfile@v1.0.0" {
		t.Fatalf("transitive dependency component = %+v", transitive)
	}
	if replaced, ok := byName["github.com/example/new"]; !ok || replaced.Version != "v2.0.0" {
		t.Fatalf("replaced module missing from SBOM components: %+v", doc.Components)
	}
	if _, ok := byName["github.com/example/old"]; ok {
		t.Fatalf("replaced-away module must not appear as the supplied module: %+v", doc.Components)
	}
	file, ok := byName[artifact]
	if !ok || file.Type != "file" || len(file.Hashes) != 1 || file.Hashes[0].Content != artifactSHA {
		t.Fatalf("artifact file component = %+v", file)
	}

	if len(doc.Dependencies) != 1 {
		t.Fatalf("dependencies = %+v, want one root entry", doc.Dependencies)
	}
	dep := doc.Dependencies[0]
	if dep.Ref != wantRootPURL {
		t.Fatalf("dependency root ref = %q, want %q", dep.Ref, wantRootPURL)
	}
	wantDependsOn := []string{
		"pkg:golang/github.com/example/new@v2.0.0",
		"pkg:golang/github.com/jackc/pgpassfile@v1.0.0",
		"pkg:golang/github.com/jackc/pgx/v5@v5.11.0",
	}
	if strings.Join(dep.DependsOn, ",") != strings.Join(wantDependsOn, ",") {
		t.Fatalf("root dependsOn = %v, want %v", dep.DependsOn, wantDependsOn)
	}
}

// TestCycloneDXRootVersionPrecedence pins the precedence between the
// authoritative -version supplied by the release pipeline and the version
// embedded in the binary. A `make build` binary is VCS-stamped, so its
// embedded main-module version is a pseudo-version like
// v0.0.0-20240101000000-bc3661db6c26+dirty that must not leak into the SBOM
// when the pipeline passes the real release version.
func TestCycloneDXRootVersionPrecedence(t *testing.T) {
	const vcsVersion = "v0.0.0-20240101000000-bc3661db6c26+dirty"
	for _, tt := range []struct {
		label       string
		buildInfo   string
		rootVersion string
		want        string
	}{
		{"explicit wins over VCS pseudo-version", vcsVersion, "1.2.3", "1.2.3"},
		{"explicit wins over empty build info", "", "1.2.3", "1.2.3"},
		{"explicit wins over (devel)", "(devel)", "1.2.3", "1.2.3"},
		{"no explicit version keeps VCS pseudo-version", vcsVersion, "", vcsVersion},
		{"no explicit version keeps release build info", "v1.2.3", "", "v1.2.3"},
		{"(devel) root version keeps real build info", "v1.2.3", "(devel)", "v1.2.3"},
		{"(devel) root version keeps VCS pseudo-version", vcsVersion, "(devel)", vcsVersion},
		{"(devel) build info falls back to explicit", "(devel)", "1.2.3", "1.2.3"},
	} {
		t.Run(tt.label, func(t *testing.T) {
			doc := cdxDocumentForGraph(
				moduleGraph{Main: moduleEntry{Path: "github.com/Bel-Consulting-OU/kiwi-ci", Version: tt.buildInfo}},
				tt.rootVersion, "", "", "", time.Unix(0, 0),
			)
			if doc.Metadata.Component == nil {
				t.Fatal("missing root component")
			}
			root := *doc.Metadata.Component
			if root.Name != "github.com/Bel-Consulting-OU/kiwi-ci" {
				t.Fatalf("root name must stay the main module path: %+v", root)
			}
			if root.Version != tt.want {
				t.Fatalf("root version = %q, want %q (build info %q, -version %q)", root.Version, tt.want, tt.buildInfo, tt.rootVersion)
			}
			wantPURL := "pkg:golang/github.com/Bel-Consulting-OU/kiwi-ci@" + tt.want
			if root.PURL != wantPURL || root.BOMRef != wantPURL {
				t.Fatalf("root purl/bom-ref = %q/%q, want %q", root.PURL, root.BOMRef, wantPURL)
			}
			if len(doc.Dependencies) != 1 || doc.Dependencies[0].Ref != wantPURL {
				t.Fatalf("dependency root ref = %+v, want %q", doc.Dependencies, wantPURL)
			}
		})
	}
}

func TestCycloneDXRootVersionFallback(t *testing.T) {
	doc := cdxDocumentForGraph(
		moduleGraph{Main: moduleEntry{Path: "github.com/Bel-Consulting-OU/kiwi-ci", Version: "(devel)"}},
		"9.9.9", "", "", "", time.Unix(0, 0),
	)
	if doc.Metadata.Component.Version != "9.9.9" {
		t.Fatalf("main module (devel) must fall back to the release version: %+v", doc.Metadata.Component)
	}
	if doc.Components != nil {
		t.Fatalf("no components expected without deps/artifact: %+v", doc.Components)
	}
}
