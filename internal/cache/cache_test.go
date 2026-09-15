package cache

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	ws := t.TempDir()
	root := t.TempDir()
	s := &Store{Root: root}
	if err := os.MkdirAll(filepath.Join(ws, "node_modules", "pkg"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "node_modules", "pkg", "x.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	key, err := s.Key("deps", ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(key, ws, []string{"node_modules"}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(ws, "node_modules")); err != nil {
		t.Fatal(err)
	}
	hit, err := s.Restore(key, ws, []string{"node_modules"})
	if err != nil {
		t.Fatal(err)
	}
	if !hit {
		t.Fatal("expected cache hit")
	}
	b, err := os.ReadFile(filepath.Join(ws, "node_modules", "pkg", "x.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello" {
		t.Fatalf("got %q", b)
	}
}

func TestSaveCapExceededLeavesNoPartialArchive(t *testing.T) {
	root := t.TempDir()
	s := &Store{Root: root, MaxCacheBytes: 64}
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "big"), bytes.Repeat([]byte("x"), 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Save("some-key", ws, []string{"."}); err == nil {
		t.Fatal("expected cap error")
	} else if !strings.Contains(err.Error(), "cap") {
		t.Fatalf("error %q does not mention cap", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Fatalf("no archive may remain after cap failure, found %q", e.Name())
	}
}
