package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContextLoginUseList(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KIWI_CONFIG_DIR", dir)
	// Force the file secret store (portable in tests).
	orig := DefaultSecretStore
	DefaultSecretStore = func() (SecretStore, error) { return FileSecretStore{Dir: dir}, nil }
	t.Cleanup(func() { DefaultSecretStore = orig })

	if err := ContextCommand([]string{"login", "https://ci.example.com", "--name", "prod", "--token", "tok-1"}); err != nil {
		t.Fatal(err)
	}
	url, tok, err := ActiveContext()
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://ci.example.com" || tok != "tok-1" {
		t.Fatalf("active = %q %q", url, tok)
	}
	if err := ContextCommand([]string{"context", "add", "staging", "https://staging.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := ContextCommand([]string{"context", "use", "staging"}); err != nil {
		t.Fatal(err)
	}
	f, err := loadContexts()
	if err != nil {
		t.Fatal(err)
	}
	if currentContextName(f) != "staging" {
		t.Fatalf("current = %q", currentContextName(f))
	}
	if err := ContextCommand([]string{"logout", "staging"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ActiveContext(); err == nil {
		// staging removed; prod is no longer current.
		f, _ = loadContexts()
		if currentContextName(f) == "staging" {
			t.Fatal("staging still current after logout")
		}
	}
}

func TestLockCollectsImageRefs(t *testing.T) {
	src := `version: 1
jobs:
  test:
    image: golang:1.27
    run: go test
  build:
    image: golang:1.27
    run: go build
  pinned:
    image: alpine:3.20@sha256:aaaa
    run: echo
`
	refs := collectImageRefs(src)
	if len(refs) != 2 {
		t.Fatalf("refs = %v, want 2 unique (golang:1.27 + pinned alpine)", refs)
	}
	foundPinned := false
	for _, r := range refs {
		if r == "alpine:3.20@sha256:aaaa" {
			foundPinned = true
		}
	}
	if !foundPinned {
		t.Fatalf("pinned ref missing: %v", refs)
	}
}

func TestLockCommandWritesFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	ResolveImageDigest = func(ref string) (string, error) {
		return ref + "@sha256:deadbeef", nil
	}
	t.Cleanup(func() { ResolveImageDigest = resolveImageDigestCLI })
	p := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(p, []byte("version: 1\njobs:\n  t:\n    image: golang:1.27\n    run: go test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := LockCommand([]string{"-f", p}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(lockfilePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "golang:1.27@sha256:deadbeef") {
		t.Fatalf("lockfile = %s", raw)
	}
	// A digest change without --update must refuse.
	ResolveImageDigest = func(ref string) (string, error) {
		return ref + "@sha256:cafebabe", nil
	}
	if err := LockCommand([]string{"-f", p}); err == nil {
		t.Fatal("digest change without --update must be refused")
	}
	if err := LockCommand([]string{"-f", p, "--update"}); err != nil {
		t.Fatal(err)
	}
}

func TestSetupPrintChecklist(t *testing.T) {
	if err := Setup([]string{"--print"}); err != nil {
		t.Fatal(err)
	}
}

// LockLookup must read the lockfile from the given root (the job workspace),
// never from process CWD — a remote runner's CWD is not the checkout.
func TestLockLookupUsesWorkspaceRootNotCWD(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, ".kiwi"), 0o755); err != nil {
		t.Fatal(err)
	}
	lock := `{"version":1,"images":[{"ref":"golang:1.27","digest":"golang:1.27@sha256:abc"}]}`
	if err := os.WriteFile(filepath.Join(ws, ".kiwi", "lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	// A different CWD with a different lockfile must NOT win.
	other := t.TempDir()
	t.Chdir(other)
	if err := os.MkdirAll(filepath.Join(other, ".kiwi"), 0o755); err != nil {
		t.Fatal(err)
	}
	otherLock := `{"version":1,"images":[{"ref":"golang:1.27","digest":"golang:1.27@sha256:WRONG"}]}`
	if err := os.WriteFile(filepath.Join(other, ".kiwi", "lock.json"), []byte(otherLock), 0o644); err != nil {
		t.Fatal(err)
	}
	got := LockLookup(ws, "golang:1.27")
	if got != "golang:1.27@sha256:abc" {
		t.Fatalf("LockLookup(ws) = %q, want the WORKSPACE lock (not CWD %q)", got, other)
	}
}
