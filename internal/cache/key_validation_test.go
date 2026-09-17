package cache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStoreRejectsUnsafeKeys verifies every store operation refuses keys that
// would address files or URLs outside the cache root.
func TestStoreRejectsUnsafeKeys(t *testing.T) {
	ws := t.TempDir()
	root := t.TempDir()
	s := &Store{Root: root}
	bad := []string{"", ".", "..", "../escape", "a/b", `a\b`, "/abs", "a?b", "a#b", "a b", strings.Repeat("k", 129)}
	for _, key := range bad {
		if err := s.Save(key, ws, []string{"."}); err == nil {
			t.Errorf("Save(%q) accepted", key)
		}
		if _, err := s.Restore(key, ws, nil); err == nil {
			t.Errorf("Restore(%q) accepted", key)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected keys left files behind: %v", entries)
	}
}

// TestStoreRestoreRejectsTraversalKey proves a traversal key cannot read a
// tar.gz planted outside the cache root.
func TestStoreRestoreRejectsTraversalKey(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "cache")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// A valid-looking archive one level above the cache root.
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	key, err := (&Store{Root: root}).Key("", ws, []string{"file"})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&Store{Root: root}).Save(key, ws, []string{"file"}); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(filepath.Join(root, key+".tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.tar.gz")
	if err := os.WriteFile(outside, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	s := &Store{Root: root}
	if hit, err := s.Restore("../outside", dest, nil); err == nil || hit {
		t.Fatalf("traversal key must be rejected: hit=%v err=%v", hit, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "file")); !os.IsNotExist(err) {
		t.Fatal("traversal key extracted content")
	}
}
