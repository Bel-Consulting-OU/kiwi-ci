package pipeline

import (
	"strings"
	"testing"
)

// Image lock is COMPILATION authority: every executable identity (job,
// service, VM) resolves through it before the graph is built.
func TestApplyImageLockResolvesJobServiceVM(t *testing.T) {
	s := &Spec{Jobs: map[string]Job{
		"build": {
			Image: "golang:1.27",
			VM:    "macos:15",
			Services: []Service{
				{Name: "db", Image: "postgres:16"},
			},
			Steps: []Step{{Run: "go test"}},
		},
	}}
	lock := map[string]string{
		"golang:1.27": "golang:1.27@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"postgres:16": "postgres:16@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"macos:15":    "macos:15@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	s.ApplyImageLock(lock)
	j := s.Jobs["build"]
	if j.Image != "golang:1.27@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("job image = %q", j.Image)
	}
	if j.VM != "macos:15@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" {
		t.Fatalf("vm = %q", j.VM)
	}
	if j.Services[0].Image != "postgres:16@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("service image = %q", j.Services[0].Image)
	}
	// Unlocked refs stay as written (the compiled graph still records them).
	s2 := &Spec{Jobs: map[string]Job{"b": {Image: "alpine:3.20", Steps: []Step{{Run: "x"}}}}}
	s2.ApplyImageLock(map[string]string{"golang:1.27": "golang:1.27@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	if s2.Jobs["b"].Image != "alpine:3.20" {
		t.Fatalf("unlocked ref must stay as written: %q", s2.Jobs["b"].Image)
	}
}

func TestImageRefsCoversJobServiceVM(t *testing.T) {
	s := &Spec{Jobs: map[string]Job{
		"a": {Image: "golang:1.27", VM: "mac:1", Services: []Service{{Image: "pg:16"}}, Steps: []Step{{Run: "x"}}},
		"b": {Image: "golang:1.27", Steps: []Step{{Run: "y"}}}, // dup
	}}
	refs := s.ImageRefs()
	if len(refs) != 3 {
		t.Fatalf("refs = %v, want 3 unique", refs)
	}
	joined := strings.Join(refs, ",")
	for _, want := range []string{"golang:1.27", "mac:1", "pg:16"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in %v", want, refs)
		}
	}
}

func TestParseImageLockfile(t *testing.T) {
	f, err := ParseImageLockfile([]byte(`{"version":1,"images":[{"ref":"golang:1.27","digest":"golang:1.27@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	m := f.LockMap()
	if m["golang:1.27"] != "golang:1.27@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("lockmap = %v", m)
	}
	if _, err := ParseImageLockfile([]byte(`{bad`)); err == nil {
		t.Fatal("malformed lockfile must fail closed")
	}
}

// Lock fetch fail-closed: only ErrFileNotFound is "no lockfile". A 500 is
// NOT a default — swallowing it would let mutable tags execute.
func TestImageLockFetchSemantics(t *testing.T) {
	// Documented contract: callers match forge.ErrFileNotFound for "absent".
	// This test pins the ApplyImageLock side: an empty lock map leaves refs
	// as written (the "no lockfile" path), which is the ONLY tolerated
	// fallback.
	s := &Spec{Jobs: map[string]Job{"b": {Image: "alpine:3.20", Steps: []Step{{Run: "x"}}}}}
	s.ApplyImageLock(nil)
	s.ApplyImageLock(map[string]string{})
	if s.Jobs["b"].Image != "alpine:3.20" {
		t.Fatalf("empty lock must leave refs as written: %q", s.Jobs["b"].Image)
	}
}

// Once a lockfile EXISTS it must be COMPLETE: every mutable executable
// identity needs an entry. A lock that silently omits a tag defeats its
// own meaning (and component-injected images are exactly the hole).
func TestRequireCompleteLockCoversAllMutableRefs(t *testing.T) {
	s := &Spec{Jobs: map[string]Job{
		"a": {Image: "golang:1.27", Steps: []Step{{Run: "x"}}},
		"b": {Image: "alpine:3.20@sha256:" + strings.Repeat("d", 64), Steps: []Step{{Run: "y"}}},
		"c": {Image: "postgres:16", Services: []Service{{Image: "redis:7"}}, Steps: []Step{{Run: "z"}}},
	}}
	lock := map[string]string{
		"golang:1.27": "golang:1.27@sha256:" + strings.Repeat("a", 64),
	}
	// Incomplete: postgres:16 and redis:7 are mutable and unlocked.
	err := s.RequireComplete(lock)
	if err == nil {
		t.Fatal("incomplete lock must fail when a lockfile exists")
	}
	if !strings.Contains(err.Error(), "postgres:16") || !strings.Contains(err.Error(), "redis:7") {
		t.Fatalf("error must name the missing refs: %v", err)
	}
	// Complete lock passes; already-pinned refs need no entry.
	lock["postgres:16"] = "postgres:16@sha256:" + strings.Repeat("b", 64)
	lock["redis:7"] = "redis:7@sha256:" + strings.Repeat("c", 64)
	if err := s.RequireComplete(lock); err != nil {
		t.Fatalf("complete lock = %v", err)
	}
	// No lock at all: ordinary trusted policy (mutable refs allowed).
	if err := s.RequireComplete(nil); err != nil {
		t.Fatalf("no lock = %v", err)
	}
}

// An empty images list is a lockfile that CLAIMS authority while pinning
// nothing. RequireComplete must treat a non-nil empty map as "lockfile
// exists" and refuse every mutable ref — only a missing document (nil)
// is ordinary trusted policy.
func TestEmptyLockfileIsStillIncomplete(t *testing.T) {
	s := &Spec{Jobs: map[string]Job{
		"a": {Image: "golang:1.27", Steps: []Step{{Run: "x"}}},
	}}
	if err := s.RequireComplete(map[string]string{}); err == nil {
		t.Fatal("empty lock map must be incomplete when mutable refs exist")
	}
	// No document at all remains ordinary policy.
	if err := s.RequireComplete(nil); err != nil {
		t.Fatalf("nil lock = %v", err)
	}
	// All-digest spec is complete even under an empty lock map.
	pinned := &Spec{Jobs: map[string]Job{
		"b": {Image: "alpine:3.20@sha256:" + strings.Repeat("f", 64), Steps: []Step{{Run: "y"}}},
	}}
	if err := pinned.RequireComplete(map[string]string{}); err != nil {
		t.Fatalf("digest-only spec under empty lock = %v", err)
	}
}
