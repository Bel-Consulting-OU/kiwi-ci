package app

import (
	"os"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
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
	// Refs are enumerated from the PARSED spec (job + service + VM), the
	// same model the server resolver executes — not a line scan.
	src := []byte(`version: 1
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
  mac:
    vm: ghcr.io/cirruslabs/macos-sequoia-base:latest
    run: swift test
  svc:
    image: alpine:3.20
    services:
      - name: db
        image: postgres:16
    run: echo
`)
	spec, err := pipeline.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	refs := spec.ImageRefs()
	// Unique: golang:1.27, alpine:3.20@sha256:aaaa, macos vm, alpine:3.20, postgres:16
	if len(refs) != 5 {
		t.Fatalf("refs = %v, want 5 unique (job+service+VM)", refs)
	}
	joined := strings.Join(refs, ",")
	for _, want := range []string{"golang:1.27", "alpine:3.20@sha256:aaaa", "macos-sequoia-base", "postgres:16"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in %v", want, refs)
		}
	}
}

func TestLockCommandWritesFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	ResolveImageDigest = func(ref string) (string, error) {
		return ref + "@sha256:" + strings.Repeat("d", 64), nil
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
	if !strings.Contains(string(raw), "golang:1.27@sha256:"+strings.Repeat("d", 64)) {
		t.Fatalf("lockfile = %s", raw)
	}
	// A digest change without --update must refuse.
	ResolveImageDigest = func(ref string) (string, error) {
		return ref + "@sha256:" + strings.Repeat("c", 64), nil
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
	lock := `{"version":1,"images":[{"ref":"golang:1.27","digest":"golang:1.27@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`
	if err := os.WriteFile(filepath.Join(ws, ".kiwi", "lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	// A different CWD with a different lockfile must NOT win.
	other := t.TempDir()
	t.Chdir(other)
	if err := os.MkdirAll(filepath.Join(other, ".kiwi"), 0o755); err != nil {
		t.Fatal(err)
	}
	otherLock := `{"version":1,"images":[{"ref":"golang:1.27","digest":"golang:1.27@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}`
	if err := os.WriteFile(filepath.Join(other, ".kiwi", "lock.json"), []byte(otherLock), 0o644); err != nil {
		t.Fatal(err)
	}
	got := LockLookup(ws, "golang:1.27")
	if got != "golang:1.27@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("LockLookup(ws) = %q, want the WORKSPACE lock (not CWD %q)", got, other)
	}
}

// Local execution must lock EVERY executable identity (job, service, VM) —
// not just the job image. A service running a mutable tag is the same
// determinism hole as a mutable job image.
func TestLockLookupCoversServiceAndVM(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, ".kiwi"), 0o755); err != nil {
		t.Fatal(err)
	}
	lock := `{"version":1,"images":[
		{"ref":"golang:1.27","digest":"golang:1.27@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		{"ref":"postgres:16","digest":"postgres:16@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
		{"ref":"macos:15","digest":"macos:15@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}
	]}`
	if err := os.WriteFile(filepath.Join(ws, ".kiwi", "lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	for ref, want := range map[string]string{
		"golang:1.27": "golang:1.27@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"postgres:16": "postgres:16@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		"macos:15":    "macos:15@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	} {
		if got := LockLookup(ws, ref); got != want {
			t.Fatalf("LockLookup(%s) = %q, want %q", ref, got, want)
		}
	}
}

// Local execution applies the lock at COMPILE time via the same strict
// algorithm as the server (ParseImageLockfile + RequireComplete +
// ApplyImageLock). A malformed lock is fail-closed; an incomplete lock
// (lock exists, mutable ref missing) is fail-closed.
func TestApplyLocalImageLockStrictAndComplete(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, ".kiwi"), 0o755); err != nil {
		t.Fatal(err)
	}
	spec, err := pipeline.Parse([]byte("version: 1\njobs:\n  b:\n    image: golang:1.27\n    run: echo hi\n"))
	if err != nil {
		t.Fatal(err)
	}
	// No lockfile: fine.
	if err := applyLocalImageLock(spec, ws); err != nil {
		t.Fatalf("no lock = %v", err)
	}
	// Malformed lock: fail closed.
	if err := os.WriteFile(filepath.Join(ws, ".kiwi", "lock.json"), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applyLocalImageLock(spec, ws); err == nil {
		t.Fatal("malformed lock must fail closed")
	}
	// Incomplete lock: fail closed (mutable ref has no entry).
	lock := `{"version":1,"images":[{"ref":"other:1","digest":"other:1@sha256:` + strings.Repeat("a", 64) + `"}]}`
	if err := os.WriteFile(filepath.Join(ws, ".kiwi", "lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applyLocalImageLock(spec, ws); err == nil {
		t.Fatal("incomplete lock must fail closed")
	}
	// Present-but-empty lockfile is NOT "no lockfile" — fail closed.
	if err := os.WriteFile(filepath.Join(ws, ".kiwi", "lock.json"), []byte("  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applyLocalImageLock(spec, ws); err == nil {
		t.Fatal("empty lockfile must fail closed")
	}
	// Empty images list claims authority while pinning nothing — fail closed.
	if err := os.WriteFile(filepath.Join(ws, ".kiwi", "lock.json"), []byte(`{"version":1,"images":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applyLocalImageLock(spec, ws); err == nil {
		t.Fatal("empty images lock must fail closed")
	}
	// Complete lock: applied.
	lock = `{"version":1,"images":[{"ref":"golang:1.27","digest":"golang:1.27@sha256:` + strings.Repeat("b", 64) + `"}]}`
	if err := os.WriteFile(filepath.Join(ws, ".kiwi", "lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applyLocalImageLock(spec, ws); err != nil {
		t.Fatalf("complete lock = %v", err)
	}
	if !strings.Contains(spec.Jobs["b"].Image, "@sha256:") {
		t.Fatalf("image not locked: %q", spec.Jobs["b"].Image)
	}
}

// Default -f .kiwi/pipeline.yaml must read/write .kiwi/lock.json at the
// project root — never .kiwi/.kiwi/lock.json.
func TestLockRootForDefaultPipelinePath(t *testing.T) {
	if got := lockRootFor(".kiwi/pipeline.yaml"); got != "." && got != "" {
		// filepath.Dir(".kiwi/pipeline.yaml") = ".kiwi", parent = "."
		if got != filepath.Dir(".kiwi") {
			t.Fatalf("lockRootFor(.kiwi/pipeline.yaml) = %q", got)
		}
	}
	if got := lockRootFor("ci/pipeline.yaml"); got != "ci" {
		t.Fatalf("lockRootFor(ci/pipeline.yaml) = %q", got)
	}
	if got := lockRootFor("pipeline.yaml"); got != "." {
		t.Fatalf("lockRootFor(pipeline.yaml) = %q", got)
	}
}

// kiwi lock must write next to the pipeline's project root, not CWD.
func TestLockCommandWritesBesidePipelineProjectRoot(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	ResolveImageDigest = func(ref string) (string, error) {
		return ref + "@sha256:" + strings.Repeat("e", 64), nil
	}
	t.Cleanup(func() { ResolveImageDigest = resolveImageDigestCLI })
	p := filepath.Join(dir, ".kiwi", "pipeline.yaml")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("version: 1\njobs:\n  b:\n    image: golang:1.27\n    run: echo hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := LockCommand([]string{"-f", p}); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, ".kiwi", "lock.json")
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("lock must land at %s: %v", lockPath, err)
	}
	nested := filepath.Join(dir, ".kiwi", ".kiwi", "lock.json")
	if _, err := os.Stat(nested); err == nil {
		t.Fatal("lock must NOT nest at .kiwi/.kiwi/lock.json")
	}
	// applyLocalImageLock must find that same document.
	spec, err := pipeline.Parse([]byte("version: 1\njobs:\n  b:\n    image: golang:1.27\n    run: echo hi\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := applyLocalImageLock(spec, lockRootFor(p)); err != nil {
		t.Fatalf("applyLocalImageLock = %v", err)
	}
	if !strings.Contains(spec.Jobs["b"].Image, "@sha256:") {
		t.Fatalf("image not locked: %q", spec.Jobs["b"].Image)
	}
}

// kiwi lock cannot see component-injected images. Writing a lock that
// omits them would be an incomplete authority document; refuse instead.
func TestLockCommandRefusesComponentJobs(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	ResolveImageDigest = func(ref string) (string, error) {
		return ref + "@sha256:" + strings.Repeat("e", 64), nil
	}
	t.Cleanup(func() { ResolveImageDigest = resolveImageDigestCLI })
	p := filepath.Join(dir, "p.yaml")
	body := "version: 1\njobs:\n  b:\n    component: build@sha256:" + strings.Repeat("a", 64) + "\n    with:\n      environment: staging\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	err := LockCommand([]string{"-f", p})
	if err == nil {
		t.Fatal("component pipeline must be refused by kiwi lock")
	}
	if !strings.Contains(err.Error(), "component") {
		t.Fatalf("error must name the component gap: %v", err)
	}
}

// A component job's injected images are invisible to the local spec, so
// once a lockfile exists a local completeness check can never cover them.
// No lockfile remains ordinary trusted policy (components still need the
// control plane at run time).
func TestApplyLocalImageLockRefusesComponents(t *testing.T) {
	ws := t.TempDir()
	spec, err := pipeline.ParseWithComponents([]byte("version: 1\njobs:\n  b:\n    component: build@sha256:" + strings.Repeat("a", 64) + "\n    with:\n      environment: staging\n"))
	if err != nil {
		t.Fatal(err)
	}
	// No lockfile: ordinary policy, not a lock-completeness error.
	if err := applyLocalImageLock(spec, ws); err != nil {
		t.Fatalf("no lockfile = %v", err)
	}
	// Present lockfile: must refuse rather than under-count ImageRefs.
	if err := os.MkdirAll(filepath.Join(ws, ".kiwi"), 0o755); err != nil {
		t.Fatal(err)
	}
	lock := `{"version":1,"images":[{"ref":"x:1","digest":"x:1@sha256:` + strings.Repeat("c", 64) + `"}]}`
	if err := os.WriteFile(filepath.Join(ws, ".kiwi", "lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applyLocalImageLock(spec, ws); err == nil {
		t.Fatal("component pipeline + lockfile must be refused")
	}
}
