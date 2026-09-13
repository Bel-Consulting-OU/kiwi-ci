package cache

import (
	"os"
	"path/filepath"
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
