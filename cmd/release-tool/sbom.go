package main

import (
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// moduleEntry is one Go module from the dependency graph embedded in a built
// binary. Replace records an active `replace` directive, if any.
type moduleEntry struct {
	Path    string
	Version string
	Replace *moduleEntry
}

// effective returns the module that actually supplies the code, following a
// replace directive when present.
func (m moduleEntry) effective() moduleEntry {
	if m.Replace != nil {
		return *m.Replace
	}
	return m
}

// moduleGraph is the complete module identity embedded in a Go binary: the
// main module plus every direct and transitive dependency.
type moduleGraph struct {
	Main moduleEntry
	Deps []moduleEntry
}

// readModuleGraph is the production entry point for extracting the complete
// module graph of a built binary; tests replace it with fixture data.
var readModuleGraph = defaultReadModuleGraph

// defaultReadModuleGraph prefers the build info embedded by the Go toolchain
// and falls back to parsing `go version -m` output when buildinfo is not
// readable (for example, for a binary rewritten after the build).
func defaultReadModuleGraph(path string) (moduleGraph, error) {
	bi, err := buildinfo.ReadFile(path)
	if err == nil {
		g := graphFromBuildInfo(bi)
		if g.Main.Path != "" {
			return g, nil
		}
	}
	out, gerr := exec.Command("go", "version", "-m", path).Output()
	if gerr != nil {
		if err != nil {
			return moduleGraph{}, fmt.Errorf("read module graph from %s: build info: %v; go version -m: %v", path, err, gerr)
		}
		return moduleGraph{}, fmt.Errorf("read module graph from %s: go version -m: %v", path, gerr)
	}
	g, perr := parseGoVersionM(string(out))
	if perr != nil {
		return moduleGraph{}, fmt.Errorf("read module graph from %s: %w", path, perr)
	}
	return g, nil
}

func graphFromBuildInfo(bi *buildinfo.BuildInfo) moduleGraph {
	g := moduleGraph{Main: moduleEntry{Path: bi.Main.Path, Version: bi.Main.Version}}
	if bi.Main.Replace != nil {
		g.Main.Replace = &moduleEntry{Path: bi.Main.Replace.Path, Version: bi.Main.Replace.Version}
	}
	for _, d := range bi.Deps {
		if d == nil {
			continue
		}
		e := moduleEntry{Path: d.Path, Version: d.Version}
		if d.Replace != nil {
			e.Replace = &moduleEntry{Path: d.Replace.Path, Version: d.Replace.Version}
		}
		g.Deps = append(g.Deps, e)
	}
	return g
}

// parseGoVersionM decodes the tab-separated output of `go version -m`. Both
// replacement encodings are supported: an inline `=>` on the dep/mod line,
// and a following `=>` line.
func parseGoVersionM(out string) (moduleGraph, error) {
	var g moduleGraph
	sawModule := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" || line[0] != '\t' {
			continue
		}
		fields := strings.Split(strings.TrimPrefix(line, "\t"), "\t")
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		switch fields[0] {
		case "path":
			if len(fields) >= 2 && g.Main.Path == "" {
				g.Main.Path = fields[1]
			}
		case "mod":
			if len(fields) < 2 {
				continue
			}
			g.Main.Path = fields[1]
			if len(fields) >= 3 {
				g.Main.Version = fields[2]
			}
			if idx := indexOf(fields, "=>"); idx >= 0 && idx+1 < len(fields) {
				repl := moduleEntry{Path: fields[idx+1]}
				if idx+2 < len(fields) {
					repl.Version = fields[idx+2]
				}
				g.Main.Replace = &repl
			}
			sawModule = true
		case "dep":
			if len(fields) < 2 {
				continue
			}
			e := moduleEntry{Path: fields[1]}
			if len(fields) >= 3 {
				e.Version = fields[2]
			}
			if idx := indexOf(fields, "=>"); idx >= 0 && idx+1 < len(fields) {
				repl := moduleEntry{Path: fields[idx+1]}
				if idx+2 < len(fields) {
					repl.Version = fields[idx+2]
				}
				e.Replace = &repl
			}
			g.Deps = append(g.Deps, e)
		case "=>":
			if len(fields) < 3 {
				continue
			}
			repl := moduleEntry{Path: fields[1], Version: fields[2]}
			if n := len(g.Deps); n > 0 {
				g.Deps[n-1].Replace = &repl
			} else if sawModule {
				g.Main.Replace = &repl
			}
		}
	}
	if g.Main.Path == "" {
		return moduleGraph{}, fmt.Errorf("no main module information in go version -m output")
	}
	return g, nil
}

func indexOf(fields []string, want string) int {
	for i, f := range fields {
		if f == want {
			return i
		}
	}
	return -1
}

// CycloneDX 1.5 document shapes for the dependency SBOM.
type cdxDocument struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	Version      int             `json:"version"`
	Metadata     cdxMetadata     `json:"metadata"`
	Components   []cdxComponent  `json:"components,omitempty"`
	Dependencies []cdxDependency `json:"dependencies,omitempty"`
}

type cdxMetadata struct {
	Timestamp string        `json:"timestamp"`
	Tools     []cdxTool     `json:"tools"`
	Component *cdxComponent `json:"component,omitempty"`
}

type cdxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxComponent struct {
	Type    string    `json:"type"`
	Name    string    `json:"name"`
	Version string    `json:"version,omitempty"`
	PURL    string    `json:"purl,omitempty"`
	BOMRef  string    `json:"bom-ref"`
	Hashes  []cdxHash `json:"hashes,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// cdxDocumentForGraph renders the complete dependency SBOM for one release
// artifact: the main module is the root component, every direct and
// transitive dependency is a library component with a purl and bom-ref, and
// the dependency graph records the root depending on every module. The
// artifact file itself is included as a file component carrying its digest.
//
// rootVersion is the release version supplied by the caller (-version). When
// it is authoritative (non-empty and not the toolchain's "(devel)"
// placeholder) it wins over the version embedded in the binary, which for a
// VCS-stamped build is a pseudo-version such as
// v0.0.0-20240101000000-bc3661db6c26+dirty. Without an authoritative
// rootVersion the embedded version is kept and rootVersion only fills in an
// empty or "(devel)" value.
func cdxDocumentForGraph(g moduleGraph, rootVersion, artifactName, artifactSHA256, toolVersion string, now time.Time) cdxDocument {
	main := g.Main.effective()
	if rootVersion != "" && rootVersion != "(devel)" {
		main.Version = rootVersion
	} else if main.Version == "" || main.Version == "(devel)" {
		main.Version = rootVersion
	}
	root := moduleComponent(main, "application")
	doc := cdxDocument{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: cdxMetadata{
			Timestamp: now.UTC().Format(time.RFC3339),
			Tools:     []cdxTool{{Vendor: "kiwi-ci", Name: "release-tool", Version: toolVersion}},
			Component: &root,
		},
	}
	seen := map[string]bool{root.BOMRef: true}
	var depRefs []string
	for _, d := range g.Deps {
		c := moduleComponent(d.effective(), "library")
		if seen[c.BOMRef] {
			continue
		}
		seen[c.BOMRef] = true
		doc.Components = append(doc.Components, c)
		depRefs = append(depRefs, c.BOMRef)
	}
	sort.Slice(doc.Components, func(i, j int) bool { return doc.Components[i].BOMRef < doc.Components[j].BOMRef })
	sort.Strings(depRefs)
	if artifactName != "" {
		doc.Components = append(doc.Components, cdxComponent{
			Type:   "file",
			Name:   artifactName,
			BOMRef: "pkg:file:" + artifactName,
			Hashes: []cdxHash{{Alg: "SHA-256", Content: artifactSHA256}},
		})
	}
	doc.Dependencies = []cdxDependency{{Ref: root.BOMRef, DependsOn: depRefs}}
	return doc
}

func moduleComponent(m moduleEntry, componentType string) cdxComponent {
	purl := modulePURL(m.Path, m.Version)
	return cdxComponent{Type: componentType, Name: m.Path, Version: m.Version, PURL: purl, BOMRef: purl}
}

func modulePURL(path, version string) string {
	p := "pkg:golang/" + purlEscape(path)
	if version != "" {
		p += "@" + purlEscape(version)
	}
	return p
}

func purlEscape(s string) string {
	return strings.NewReplacer("%", "%25", " ", "%20").Replace(s)
}

func marshalCycloneDX(doc cdxDocument) ([]byte, error) {
	return json.MarshalIndent(doc, "", "  ")
}
