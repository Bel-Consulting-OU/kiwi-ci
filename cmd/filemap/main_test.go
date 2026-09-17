package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withFlagSet installs a fresh ContinueOnError flag set as flag.CommandLine
// for the duration of fn. In production the global ExitOnError set aborts on
// parse errors; run() mirrors that abort by returning 2 when Parse fails.
func withFlagSet(t *testing.T, fn func()) {
	t.Helper()
	old := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet("filemap", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	t.Cleanup(func() { flag.CommandLine = old })
	fn()
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunGeneratesMap(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.go"), "// Package sample does things.\n\n// Second line ignored.\npackage main\n")
	writeFile(t, filepath.Join(root, "README.md"), "# Sample project\n\nBody\n")
	writeFile(t, filepath.Join(root, "schema.sql"), "-- users table\nCREATE TABLE users (id int);\n")
	writeFile(t, filepath.Join(root, "ci.yaml"), "# pipeline config\non: push\n")
	writeFile(t, filepath.Join(root, "data.json"), `{"a": 1}`)
	writeFile(t, filepath.Join(root, "LICENSE"), "MIT License\n")
	writeFile(t, filepath.Join(root, "Makefile"), "all:\n\ttrue\n# trailing comment\n")
	writeFile(t, filepath.Join(root, ".gitignore"), "# comment\nbin/\n")
	writeFile(t, filepath.Join(root, "notes.txt"), "  plain text notes  \n")
	writeFile(t, filepath.Join(root, "nogodoc.go"), "package main\n")
	writeFile(t, filepath.Join(root, "empty.md"), "")
	writeFile(t, filepath.Join(root, "sub", "inner.md"), "# Inner\n")
	writeFile(t, filepath.Join(root, ".DS_Store"), "junk")
	writeFile(t, filepath.Join(root, "Thumbs.db"), "junk")
	writeFile(t, filepath.Join(root, "desktop.ini"), "junk")
	writeFile(t, filepath.Join(root, "leftover.tmp"), "junk")
	writeFile(t, filepath.Join(root, "cpu.prof"), "junk")
	writeFile(t, filepath.Join(root, "coverage.out"), "junk")
	writeFile(t, filepath.Join(root, "go.sum"), "module sums\n")
	writeFile(t, filepath.Join(root, "FILE_MAP.md"), "stale map\n")
	writeFile(t, filepath.Join(root, "nested", "FILE_MAP.md"), "nested map\n")
	for _, dir := range []string{".git", "dist", "tmp", "vendor", "testdata"} {
		writeFile(t, filepath.Join(root, dir, "f.go"), "// Hidden file.\npackage hidden\n")
	}

	out := filepath.Join(t.TempDir(), "map.md")
	var stdout, stderr bytes.Buffer
	var code int
	withFlagSet(t, func() {
		code = run([]string{"-root", root, "-out", out}, &stdout, &stderr)
	})
	if code != 0 {
		t.Fatalf("run = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "filemap: wrote "+out) {
		t.Fatalf("stdout = %q", stdout.String())
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "It lists **14 files**.") {
		t.Fatalf("file count wrong:\n%s", text)
	}
	for _, want := range []string{
		"| `.gitignore` | bin/ |",
		"| `LICENSE` | MIT License |",
		"| `Makefile` | trailing comment |",
		"| `README.md` | Sample project |",
		"| `ci.yaml` | pipeline config |",
		"| `data.json` | {\"a\": 1} |",
		"| `empty.md` | Documentation file. |",
		"| `go.sum` | module sums |",
		"| `main.go` | Package sample does things. |",
		"| `nested/FILE_MAP.md` | nested map |",
		"| `nogodoc.go` | Go source in the repository root. |",
		"| `notes.txt` | plain text notes |",
		"| `schema.sql` | users table |",
		"| `sub/inner.md` | Inner |",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("map missing %q", want)
		}
	}
	for _, banned := range []string{
		"FILE_MAP.md` | stale map", ".DS_Store", "Thumbs.db", "desktop.ini",
		"leftover.tmp", "cpu.prof", "coverage.out", ".git/f.go", "dist/f.go", "tmp/f.go",
		"vendor/f.go", "testdata/f.go",
	} {
		if strings.Contains(text, banned) {
			t.Errorf("map must not contain %q:\n%s", banned, text)
		}
	}
	if strings.Index(text, "| `Makefile`") > strings.Index(text, "| `main.go`") {
		t.Errorf("rows are not sorted:\n%s", text)
	}

	// The output is deterministic: a second run produces identical bytes.
	out2 := filepath.Join(t.TempDir(), "map2.md")
	stdout.Reset()
	stderr.Reset()
	withFlagSet(t, func() {
		if code := run([]string{"-root", root, "-out", out2}, &stdout, &stderr); code != 0 {
			t.Fatalf("second run = %d", code)
		}
	})
	body2, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, body2) {
		t.Fatalf("filemap output is not deterministic")
	}
}

func TestRunDefaultOutDirIsRoot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), "a\n")
	var stdout, stderr bytes.Buffer
	withFlagSet(t, func() {
		if code := run([]string{"-root", root}, &stdout, &stderr); code != 0 {
			t.Fatalf("run = %d, stderr = %q", code, stderr.String())
		}
	})
	dest := filepath.Join(root, "FILE_MAP.md")
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("default destination %s missing: %v", dest, err)
	}
	if !strings.Contains(stdout.String(), "wrote "+dest) {
		t.Fatalf("stdout = %q", stdout.String())
	}
	body, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "FILE_MAP.md` |") {
		t.Fatalf("default output must exclude itself:\n%s", body)
	}
}

func TestRunCheckMode(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), "a\n")
	dest := filepath.Join(root, "FILE_MAP.md")

	var stdout, stderr bytes.Buffer
	withFlagSet(t, func() {
		if code := run([]string{"-root", root, "-check"}, &stdout, &stderr); code != 1 {
			t.Fatalf("check on missing file = %d, want 1", code)
		}
	})
	if !strings.Contains(stderr.String(), "is stale; run") {
		t.Fatalf("stderr = %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	withFlagSet(t, func() {
		if code := run([]string{"-root", root}, &stdout, &stderr); code != 0 {
			t.Fatalf("generate = %d", code)
		}
	})

	stdout.Reset()
	stderr.Reset()
	withFlagSet(t, func() {
		if code := run([]string{"-root", root, "-check"}, &stdout, &stderr); code != 0 {
			t.Fatalf("check on fresh file = %d, want 0", code)
		}
	})
	if !strings.Contains(stdout.String(), "is up to date (1 files)") {
		t.Fatalf("stdout = %q", stdout.String())
	}

	writeFile(t, dest, "manually edited\n")
	stdout.Reset()
	stderr.Reset()
	withFlagSet(t, func() {
		if code := run([]string{"-root", root, "-check"}, &stdout, &stderr); code != 1 {
			t.Fatalf("check on stale file = %d, want 1", code)
		}
	})
	if !strings.Contains(stderr.String(), "is stale; run") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunFlagParseErrorReturnsTwo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	withFlagSet(t, func() {
		if code := run([]string{"-no-such-flag"}, &stdout, &stderr); code != 2 {
			t.Fatalf("bad flag exit = %d, want 2", code)
		}
	})
}

func TestRunMissingRootFails(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	var stdout, stderr bytes.Buffer
	withFlagSet(t, func() {
		if code := run([]string{"-root", missing}, &stdout, &stderr); code != 1 {
			t.Fatalf("missing root exit = %d, want 1", code)
		}
	})
	if !strings.HasPrefix(stderr.String(), "filemap: ") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunWriteFailure(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), "a\n")
	dest := filepath.Join(root, "adir")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	withFlagSet(t, func() {
		if code := run([]string{"-root", root, "-out", dest}, &stdout, &stderr); code != 1 {
			t.Fatalf("write-to-directory exit = %d, want 1", code)
		}
	})
	if !strings.HasPrefix(stderr.String(), "filemap: ") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestSkipFileNames(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{".DS_Store", "Thumbs.db", "desktop.ini", "x.tmp", "y.prof", "z.out"} {
		writeFile(t, filepath.Join(root, name), "data")
	}
	writeFile(t, filepath.Join(root, "go.sum"), "sums")
	writeFile(t, filepath.Join(root, "keep.txt"), "keep")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Name()] = skipFile(root, e.Name(), e)
	}
	for _, name := range []string{".DS_Store", "Thumbs.db", "desktop.ini", "x.tmp", "y.prof", "z.out"} {
		if !seen[name] {
			t.Errorf("skipFile(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"go.sum", "keep.txt"} {
		if seen[name] {
			t.Errorf("skipFile(%q) = true, want false", name)
		}
	}
}

// TestSkipFileBinaryDetection proves skipFile resolves rel beneath the walk
// root it is given, independent of the process working directory (the test
// never chdirs into the fixture root).
func TestSkipFileBinaryDetection(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "blob.bin")
	if err := os.WriteFile(binary, []byte{0x7f, 'E', 'L', 'F', 0x00, 0x01}, 0o644); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "text.go"), "package x\n")
	nulAfter512 := append(bytes.Repeat([]byte{'a'}, 550), 0)
	writeFile(t, filepath.Join(root, "late-nul.bin"), string(nulAfter512))
	writeFile(t, filepath.Join(root, "empty.dat"), "")

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = skipFile(root, e.Name(), e)
	}
	if !got["blob.bin"] {
		t.Error("a file with a NUL in its first 512 bytes must be skipped")
	}
	if got["text.go"] {
		t.Error("a text file must not be skipped")
	}
	if got["late-nul.bin"] {
		t.Error("a NUL after the first 512 bytes must not be detected (documented probe window)")
	}
	if got["empty.dat"] {
		t.Error("an empty file counts as text")
	}
}

// TestRunSkipsBinaryUnderRoot copies a small tree to a temporary location and
// runs filemap with -root pointing there: the process working directory is
// not the walk root, so a root-relative probe must find and skip the fake
// binary (random bytes with an embedded NUL).
func TestRunSkipsBinaryUnderRoot(t *testing.T) {
	root := t.TempDir()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "main.go"), string(src))
	writeFile(t, filepath.Join(root, "sub", "inner.go"), "package sub\n")
	binary := make([]byte, 600)
	if _, err := rand.Read(binary); err != nil {
		t.Fatal(err)
	}
	binary[0] = 0
	for _, rel := range []string{"blob.bin", filepath.Join("sub", "blob.bin")} {
		if err := os.WriteFile(filepath.Join(root, rel), binary, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	out := filepath.Join(t.TempDir(), "map.md")
	var stdout, stderr bytes.Buffer
	withFlagSet(t, func() {
		if code := run([]string{"-root", root, "-out", out}, &stdout, &stderr); code != 0 {
			t.Fatalf("run = %d, stderr = %q", code, stderr.String())
		}
	})
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "| `main.go` | Command filemap generates") ||
		!strings.Contains(text, "| `sub/inner.go` | Go source in internal/sub. |") {
		t.Fatalf("copied sources missing from map:\n%s", text)
	}
	if strings.Contains(text, "blob.bin") {
		t.Fatalf("binary files under -root must be skipped:\n%s", text)
	}
}

func TestIsText(t *testing.T) {
	if !isText(nil) || !isText([]byte("")) {
		t.Fatal("empty content is text")
	}
	if !isText([]byte("plain ascii")) {
		t.Fatal("ascii is text")
	}
	if isText([]byte{'a', 0, 'b'}) {
		t.Fatal("NUL byte makes content binary")
	}
	if !isText(append(bytes.Repeat([]byte{'x'}, 512), 0)) {
		t.Fatal("NUL beyond the 512-byte probe window is ignored")
	}
	if isText(append(bytes.Repeat([]byte{'x'}, 511), 0)) {
		t.Fatal("NUL within the probe window is detected")
	}
}

func TestDescribeByKind(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"a.go", "// Doc line.\n// more\npackage a\n", "Doc line."},
		{"b.go", "/* Block doc. */\npackage b\n", "Block doc. */"},
		{"pkg/c.go", "package c\n", "Go source in internal/pkg."},
		{"pkg/d_test.go", "package d\n", "Regression tests for the pkg package."},
		{"root.go", "package main\n", "Go source in the repository root."},
		{"root_test.go", "package main\n", "Regression tests for the repository root."},
		{"cmd/tool/main.go", "package main\n", "Go source for the tool command."},
		{"cmd/tool/main_test.go", "package main\n", "Regression tests for the tool command."},
		{"e.md", "# Heading\nbody\n", "Heading"},
		{"f.md", "no heading here\n", "no heading here"},
		{"g.md", "\n\n", "Documentation file."},
		{"h.sql", "SELECT 1;\n-- comment line\n", "comment line"},
		{"i.sql", "\n", "Repository file."},
		{"j.yaml", "key: value\n# later comment\n", "later comment"},
		{"nohead.yaml", "\n\n", "YAML configuration file."},
		{"k.yml", "# yaml comment\n", "yaml comment"},
		{"l.toml", "# toml comment\n", "toml comment"},
		{"m.json", "\n  {\"k\": 1}\n", "{\"k\": 1}"},
		{"n.txt", "some|piped\ttext\n", `some\|piped text`},
		{"o.txt", strings.Repeat("x", 200) + "\n", strings.Repeat("x", 117) + "..."},
		{"LICENSE", "Apache License\n", "Apache License"},
		{"Makefile", "# build everything\nall:\n", "build everything"},
		{".gitignore", "# comment\n\nbuild/\n", "build/"},
		{"FILE_MAP.md", "stale\n", "Generated inventory of every file in the repository (this file)."},
		{"empty.json", "", "JSON data file."},
		{"empty.yml", "", "YAML configuration file."},
		{"Weird", "", "Repository file."},
	}
	for _, tc := range cases {
		writeFile(t, filepath.Join(root, tc.name), tc.content)
		got := describe(tc.name, filepath.Join(root, tc.name))
		if got != tc.want {
			t.Errorf("describe(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestDescribeUnreadable(t *testing.T) {
	got := describe("missing.txt", filepath.Join(t.TempDir(), "missing.txt"))
	if got != "File could not be read." {
		t.Fatalf("describe(missing) = %q", got)
	}
}

func TestFirstGoDocComment(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"package x\n", ""},
		{"// one\n// two\npackage x\n", "one"},
		{"\n\n// after blanks\npackage x\n", "after blanks"},
		{"/* block start\npackage x\n", "block start"},
		{"// first\n\npackage x\n", "first"},
		{"code();\n// trailing\n", ""},
	}
	for _, tc := range cases {
		if got := firstGoDocComment(tc.in); got != tc.want {
			t.Errorf("firstGoDocComment(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFirstHeadingOrLine(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"\n\n", ""},
		{"# H1\nbody\n", "H1"},
		{"### Deep\n", "Deep"},
		{"plain\n# later\n", "plain"},
	}
	for _, tc := range cases {
		if got := firstHeadingOrLine(tc.in); got != tc.want {
			t.Errorf("firstHeadingOrLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFirstCommentOrLine(t *testing.T) {
	cases := []struct {
		in, marker, want string
	}{
		{"", "#", ""},
		{"# heading\n", "#", "heading"},
		{"value\n# comment\n", "#", "comment"},
		{"value only\n", "#", "value only"},
		{"-- sql comment\n", "--", "sql comment"},
	}
	for _, tc := range cases {
		if got := firstCommentOrLine(tc.in, tc.marker); got != tc.want {
			t.Errorf("firstCommentOrLine(%q, %q) = %q, want %q", tc.in, tc.marker, got, tc.want)
		}
	}
}

func TestFirstUncommentedLine(t *testing.T) {
	cases := []struct {
		in, marker, want string
	}{
		{"", "#", ""},
		{"# only comment\n", "#", ""},
		{"# comment\nbin/\n", "#", "bin/"},
		{"first\n# comment\n", "#", "first"},
	}
	for _, tc := range cases {
		if got := firstUncommentedLine(tc.in, tc.marker); got != tc.want {
			t.Errorf("firstUncommentedLine(%q, %q) = %q, want %q", tc.in, tc.marker, got, tc.want)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	cases := map[string]string{
		"":                     "",
		"\n \t\n":              "",
		"  spaced  \nsecond\n": "spaced",
		"\n\nvalue\n":          "value",
	}
	for in, want := range cases {
		if got := firstNonEmpty(in); got != want {
			t.Errorf("firstNonEmpty(%q) = %q, want %q", in, got, want)
		}
	}
}
