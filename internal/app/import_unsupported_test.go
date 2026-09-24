package app

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout redirects os.Stdout into a buffer for the duration of fn.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = old
	return <-done
}

// TestImportListUnsupportedPrintsStdout pins the F6-I fix: the report the
// --list-unsupported flag documents is written to stdout (previously the
// unsupported constructs always went to stderr).
func TestImportListUnsupportedPrintsStdout(t *testing.T) {
	body := "name: ci\non:\n  push:\n  schedule:\n    - cron: '0 3 * * 1'\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
	src := filepath.Join(t.TempDir(), "ci.yml")
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := Import([]string{"github-actions", "--file", src, "--list-unsupported"}); err != nil {
			t.Fatalf("import: %v", err)
		}
	})
	if !strings.Contains(out, "unsupported:") {
		t.Fatalf("--list-unsupported did not print unsupported constructs to stdout: %q", out)
	}
	if !strings.Contains(out, "confidence:") {
		t.Fatalf("confidence line missing from stdout: %q", out)
	}
}
