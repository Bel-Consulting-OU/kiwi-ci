package main

import (
	"os"
	"strings"
	"testing"
)

// TestDefaultReadModuleGraphRealBinary drives the production reader through
// the embedded-build-info path on the test binary itself, and through the
// both-readers-fail error path.
func TestDefaultReadModuleGraphRealBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	g, err := defaultReadModuleGraph(exe)
	if err != nil {
		t.Fatalf("defaultReadModuleGraph(self) = %v", err)
	}
	if g.Main.Path == "" {
		t.Fatal("test binary module graph has no main path")
	}

	if _, err := defaultReadModuleGraph("/nonexistent/kiwi-release-tool"); err == nil {
		t.Fatal("defaultReadModuleGraph on a missing path succeeded")
	}
}

// TestParseGoVersionMBranchEdges covers the malformed/truncated field arms the
// fixture tests do not reach.
func TestParseGoVersionMBranchEdges(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
		check   func(moduleGraph) bool
	}{
		{
			name:    "bare path line is ignored",
			in:      "\tpath\n",
			wantErr: true,
		},
		{
			name:    "bare mod line is ignored",
			in:      "\tmod\n",
			wantErr: true,
		},
		{
			name: "mod with inline replacement",
			in:   "\tmod\tmainmod\tv1.0.0\t=>\treplmod\tv2.0.0\n",
			check: func(g moduleGraph) bool {
				return g.Main.Path == "mainmod" && g.Main.Replace != nil && g.Main.Replace.Path == "replmod" && g.Main.Replace.Version == "v2.0.0"
			},
		},
		{
			name: "bare dep line is ignored",
			in:   "\tmod\tmainmod\tv1.0.0\n\tdep\n",
			check: func(g moduleGraph) bool {
				return len(g.Deps) == 0
			},
		},
		{
			name: "short arrow line is ignored",
			in:   "\tmod\tmainmod\tv1.0.0\n\t=>\tonlyone\n",
			check: func(g moduleGraph) bool {
				return g.Main.Replace == nil
			},
		},
		{
			name: "separate arrow line replaces the last dep",
			in:   "\tmod\tmainmod\tv1.0.0\n\tdep\tdepmod\tv1.0.0\n\t=>\treplmod\tv2.0.0\n",
			check: func(g moduleGraph) bool {
				return len(g.Deps) == 1 && g.Deps[0].Replace != nil && g.Deps[0].Replace.Path == "replmod"
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := parseGoVersionM(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseGoVersionM(%q) = %+v, want error", tc.in, g)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseGoVersionM(%q) = %v", tc.in, err)
			}
			if tc.check != nil && !tc.check(g) {
				t.Fatalf("parseGoVersionM(%q) = %+v, want the checked shape", tc.in, g)
			}
		})
	}

	// A line with no leading tab and empty lines are ignored.
	if g, err := parseGoVersionM("not indented\n\n\tmod\tm\tv1\n"); err != nil || !strings.HasPrefix(g.Main.Path, "m") {
		t.Fatalf("indented-line handling = %+v, %v", g, err)
	}
}
