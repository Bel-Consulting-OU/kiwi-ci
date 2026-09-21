package testintel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// c3JUnit is a tiny valid report used to prove content was or was not read.
const c3JUnit = `<testsuite name="host" tests="1"><testcase name="host-case"/></testsuite>`

func c3Dir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestAggregateRejectsSymlinkedParentDir covers the container-escape shape:
// a job creates ws/reports as a symlink to a host directory and drops a
// regular result.xml inside it. The lexical Within check cannot see this;
// the root-anchored resolver must reject the symlink component and read no
// content through it.
func TestAggregateRejectsSymlinkedParentDir(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	host := filepath.Join(root, "host")
	c3Dir(t, ws)
	c3Dir(t, host)
	writeFixture(t, host, "result.xml", c3JUnit)
	if err := os.Symlink(host, filepath.Join(ws, "reports")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	// The same shape one level deeper, so a symlink that only the glob walk
	// reaches is rejected too.
	if err := os.MkdirAll(filepath.Join(ws, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(host, filepath.Join(ws, "nested", "reports")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	for _, pattern := range []string{
		"reports/*.xml",
		"reports/result.xml",
		"*/*.xml",
		"nested/reports/*.xml",
		"nested/*/*.xml",
	} {
		rep, err := Aggregate(ws, []string{pattern})
		if err == nil {
			t.Fatalf("pattern %q: symlinked parent accepted: %+v", pattern, rep)
		}
		if !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("pattern %q: err = %v, want a symlink rejection", pattern, err)
		}
		if rep.Tests != 0 || len(rep.Cases) != 0 || rep.Path != "" {
			t.Fatalf("pattern %q: content read through symlink: %+v", pattern, rep)
		}
	}
}

// TestAggregateRejectsSymlinkedFinalFile proves a symlinked final component
// is still rejected on both the literal and the glob path once enumeration
// moved under the workspace root.
func TestAggregateRejectsSymlinkedFinalFile(t *testing.T) {
	ws := t.TempDir()
	writeFixture(t, ws, "real.xml", c3JUnit)
	if err := os.Symlink(filepath.Join(ws, "real.xml"), filepath.Join(ws, "link.xml")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	for _, pattern := range []string{"link.xml", "*.xml"} {
		rep, err := Aggregate(ws, []string{pattern})
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("pattern %q: err = %v, want a symlink rejection", pattern, err)
		}
		if rep.Tests != 0 {
			t.Fatalf("pattern %q: report = %+v", pattern, rep)
		}
	}
}

// TestAggregateRejectsSymlinkedWorkspaceRoot keeps the fail-closed root
// contract: the collector refuses to anchor reads at a symlinked workspace
// in the first place.
func TestAggregateRejectsSymlinkedWorkspaceRoot(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	c3Dir(t, real)
	writeFixture(t, real, "a.xml", c3JUnit)
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, err := Aggregate(link, []string{"*.xml"}); err == nil {
		t.Fatal("symlinked workspace root accepted")
	}
}

// TestAggregateAcceptsNestedRegularPaths proves the stricter resolver still
// accepts ordinary nested layouts on the literal, glob and mixed paths.
func TestAggregateAcceptsNestedRegularPaths(t *testing.T) {
	ws := t.TempDir()
	c3Dir(t, filepath.Join(ws, "reports", "sub"))
	writeFixture(t, filepath.Join(ws, "reports"), "top.xml", c3JUnit)
	writeFixture(t, filepath.Join(ws, "reports", "sub"), "deep.xml",
		`<testsuite name="deep" tests="1"><testcase name="deep-case"/></testsuite>`)

	cases := []struct {
		name     string
		patterns []string
		want     int
		path     string
	}{
		{"glob", []string{"reports/*/*.xml"}, 1, "reports/sub/deep.xml"},
		{"literal", []string{"reports/sub/deep.xml"}, 1, "reports/sub/deep.xml"},
		{"mixed", []string{"reports/*.xml", "reports/*/*.xml"}, 2, "reports/sub/deep.xml, reports/top.xml"},
	}
	for _, tc := range cases {
		rep, err := Aggregate(ws, tc.patterns)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if rep.Tests != tc.want || rep.Path != tc.path {
			t.Fatalf("%s: report = %+v, want tests=%d path=%q", tc.name, rep, tc.want, tc.path)
		}
	}
}

// TestAggregateRejectsEscapingPatterns pins the pattern grammar: absolute
// patterns, backslashes, NUL bytes and any ".." component are refused
// before a single directory entry is listed.
func TestAggregateRejectsEscapingPatterns(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	c3Dir(t, ws)
	writeFixture(t, root, "escape.xml", c3JUnit)
	patterns := []string{
		"../escape.xml",
		"reports/../../escape.xml",
		"../",
		"reports/..",
		"/etc/hostname",
		"/",
		".",
		"",
		`..\..\escape.xml`,
		"reports/\x00.xml",
	}
	for _, pattern := range patterns {
		rep, err := Aggregate(ws, []string{pattern})
		if err == nil {
			t.Errorf("pattern %q accepted: %+v", pattern, rep)
		}
		if rep.Tests != 0 {
			t.Errorf("pattern %q read content: %+v", pattern, rep)
		}
	}
}
