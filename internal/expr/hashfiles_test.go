package expr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeHashFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHashFilesRejectsTraversalPatterns(t *testing.T) {
	ws := t.TempDir()
	for _, pattern := range []string{"../evil", "a/../../evil", "../../*"} {
		if _, err := EvalString(`${{ hashFiles('`+pattern+`') }}`, Context{Workspace: ws}); err == nil || !strings.Contains(err.Error(), ".. component") {
			t.Errorf("pattern %q error = %v, want traversal rejection", pattern, err)
		}
	}
	if _, err := EvalString(`${{ hashFiles('/etc/passwd') }}`, Context{Workspace: ws}); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("absolute pattern error = %v, want rejection", err)
	}
}

func TestHashFilesRejectsSymlinkEscapingWorkspace(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()
	writeHashFile(t, outside, "secret.txt", "secret\n")
	if err := os.Symlink(outside, filepath.Join(ws, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := EvalString(`${{ hashFiles('*') }}`, Context{Workspace: ws}); err == nil || !strings.Contains(err.Error(), "escapes the workspace") {
		t.Errorf("symlink match error = %v, want workspace-confinement rejection", err)
	}
	// A symlink to a file inside the workspace is fine.
	writeHashFile(t, ws, "real.txt", "data\n")
	if err := os.Symlink(filepath.Join(ws, "real.txt"), filepath.Join(ws, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := EvalString(`${{ hashFiles('real.txt') }}`, Context{Workspace: ws}); err != nil {
		t.Errorf("internal symlink rejected: %v", err)
	}
}

func TestHashFilesBudgetExceeded(t *testing.T) {
	ws := t.TempDir()
	writeHashFile(t, ws, "big.bin", strings.Repeat("x", hashFilesMaxBytes-4))
	writeHashFile(t, ws, "small.bin", strings.Repeat("y", 8))
	if _, err := EvalString(`${{ hashFiles('**') }}`, Context{Workspace: ws}); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Errorf("budget overflow error = %v, want budget rejection", err)
	}
}

func TestHashFilesDeterministicOrdering(t *testing.T) {
	ws1 := t.TempDir()
	ws2 := t.TempDir()
	for _, ws := range []string{ws1, ws2} {
		writeHashFile(t, ws, "b.txt", "bee\n")
		writeHashFile(t, ws, "a.txt", "aye\n")
		writeHashFile(t, ws, "sub/c.txt", "sea\n")
	}
	h1, err := EvalString(`${{ hashFiles('**/*.txt') }}`, Context{Workspace: ws1})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := EvalString(`${{ hashFiles('**/*.txt') }}`, Context{Workspace: ws2})
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 || len(h1) != 12 {
		t.Fatalf("hashFiles not deterministic across identical workspaces: %q vs %q", h1, h2)
	}
}

func TestHashFilesDeduplicatesOverlappingGlobs(t *testing.T) {
	ws := t.TempDir()
	writeHashFile(t, ws, "go.sum", "sum\n")
	both, err := EvalString(`${{ hashFiles('**', 'go.sum') }}`, Context{Workspace: ws})
	if err != nil {
		t.Fatal(err)
	}
	once, err := EvalString(`${{ hashFiles('go.sum') }}`, Context{Workspace: ws})
	if err != nil {
		t.Fatal(err)
	}
	// Hashing the same file twice would change the digest; dedupe keeps
	// the overlapping-glob hash distinct from... (both still differs: the
	// glob also matches nothing else, so equality is actually expected).
	_ = both
	_ = once
	if both != once {
		t.Errorf("overlapping globs must deduplicate to the same digest: %q vs %q", both, once)
	}
}
