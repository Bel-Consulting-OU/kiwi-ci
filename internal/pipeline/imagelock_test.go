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
		"golang:1.27": "golang:1.27@sha256:aaa",
		"postgres:16": "postgres:16@sha256:bbb",
		"macos:15":    "macos:15@sha256:ccc",
	}
	s.ApplyImageLock(lock)
	j := s.Jobs["build"]
	if j.Image != "golang:1.27@sha256:aaa" {
		t.Fatalf("job image = %q", j.Image)
	}
	if j.VM != "macos:15@sha256:ccc" {
		t.Fatalf("vm = %q", j.VM)
	}
	if j.Services[0].Image != "postgres:16@sha256:bbb" {
		t.Fatalf("service image = %q", j.Services[0].Image)
	}
	// Unlocked refs stay as written (the compiled graph still records them).
	s2 := &Spec{Jobs: map[string]Job{"b": {Image: "alpine:3.20", Steps: []Step{{Run: "x"}}}}}
	s2.ApplyImageLock(map[string]string{"golang:1.27": "golang:1.27@sha256:aaa"})
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
	f, err := ParseImageLockfile([]byte(`{"version":1,"images":[{"ref":"golang:1.27","digest":"golang:1.27@sha256:aaa"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	m := f.LockMap()
	if m["golang:1.27"] != "golang:1.27@sha256:aaa" {
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
