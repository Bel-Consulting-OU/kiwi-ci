package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAdoptLockStructuredRoot: AdoptLock must place lock.json at
// <root>/.kiwi/lock.json under the run-base so applyLocalImageLock's
// lockfilePath join resolves, and must refuse directories (the previous
// AdoptFile-of-lockRoot-for-path could adopt a directory).
func TestAdoptLockStructuredRoot(t *testing.T) {
	m := &Manager{Root: t.TempDir()}
	if err := m.Freeze(t.Context()); err == nil {
		// Source is the temp dir itself once Root is set differently —
		// construct properly via NewManager instead.
	}
	src := t.TempDir()
	proj := filepath.Join(src, "proj")
	if err := os.MkdirAll(filepath.Join(proj, ".kiwi"), 0o755); err != nil {
		t.Fatal(err)
	}
	lockBody := []byte(`{"version":1,"images":[{"ref":"alpine","digest":"sha256:aa"}]}`)
	if err := os.WriteFile(filepath.Join(proj, ".kiwi", "lock.json"), lockBody, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "pipeline.yaml"), []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mm, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer mm.Close()
	if err := mm.Freeze(t.Context()); err != nil {
		t.Fatal(err)
	}
	root, err := mm.AdoptLock(filepath.Join(proj, ".kiwi", "lock.json"))
	if err != nil {
		t.Fatalf("AdoptLock: %v", err)
	}
	got := filepath.Join(root, ".kiwi", "lock.json")
	b, err := os.ReadFile(got)
	if err != nil {
		t.Fatalf("adopted lock path: %v", err)
	}
	if string(b) != string(lockBody) {
		t.Fatalf("adopted lock body = %q", b)
	}
	// Directory must be refused.
	if _, err := mm.AdoptLock(proj); err == nil {
		t.Fatal("AdoptLock of a directory must fail")
	}
	// AdoptFile of a directory must also fail (was a silent copy error).
	if _, err := mm.AdoptFile(proj); err == nil {
		t.Fatal("AdoptFile of a directory must fail")
	}
}
