package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// lockfileWorkspace builds a fixture workspace with a go.sum so the cache
// inference and digest helpers see a real Go module.
func lockfileWorkspace(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte("example.com/mod v1.0.0 h1:abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLockfileDigestDeterministic(t *testing.T) {
	dir := lockfileWorkspace(t)
	first, err := lockfileDigest(dir, []string{"go.sum"})
	if err != nil {
		t.Fatalf("lockfileDigest: %v", err)
	}
	second, err := lockfileDigest(dir, []string{"go.sum"})
	if err != nil {
		t.Fatalf("lockfileDigest: %v", err)
	}
	if first != second {
		t.Fatalf("digest not deterministic: %q vs %q", first, second)
	}
	if len(first) != 64 {
		t.Fatalf("digest length = %d, want 64", len(first))
	}
	// The helper must reproduce cache.Store.Key with an empty base, which
	// is the digest semantics the executor uses for hash_files.
	want, err := cache.Default().Key("", dir, []string{"go.sum"})
	if err != nil {
		t.Fatalf("cache.Key: %v", err)
	}
	if first != want {
		t.Fatalf("lockfileDigest %q diverges from cache.Store.Key %q", first, want)
	}
}

func TestLockfileDigestMissingFile(t *testing.T) {
	dir := t.TempDir()
	got, err := lockfileDigest(dir, []string{"go.sum"})
	if err != nil {
		t.Fatalf("unmatched glob must not error (cache.Store.Key parity): %v", err)
	}
	// An unmatched hash_files glob hashes nothing: the digest is that of the
	// empty base, exactly like cache.Store.Key with no matched files.
	want, err := cache.Default().Key("", dir, []string{"go.sum"})
	if err != nil {
		t.Fatalf("cache.Key: %v", err)
	}
	if got != want {
		t.Fatalf("lockfileDigest %q diverges from cache.Store.Key %q", got, want)
	}
}

func TestLockfileDigestMatchesGoSumChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.sum")
	os.WriteFile(path, []byte("v1\n"), 0o644)
	a, err := lockfileDigest(dir, []string{"go.sum"})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte("v2\n"), 0o644)
	b, err := lockfileDigest(dir, []string{"go.sum"})
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("digest must change when the lockfile content changes")
	}
}

func TestPrintCacheInputsRendersAllFields(t *testing.T) {
	dir := lockfileWorkspace(t)
	cj := pipeline.CompiledJob{ID: "test", Job: pipeline.Job{
		Runtime: "container",
		Cache: []pipeline.Cache{{
			Name:        "go-cache",
			Paths:       []string{".kiwi/cache"},
			Key:         "go-${{ matrix.GO_VERSION }}",
			HashFiles:   []string{"go.sum"},
			RestoreKeys: []string{"go-"},
		}},
	}}
	var buf bytes.Buffer
	printCacheInputs(&buf, cj, dir)
	out := buf.String()
	for _, want := range []string{
		"cache go-cache:",
		"hash_files: go.sum",
		"lockfile digest: ",
		"key: go-${{ matrix.GO_VERSION }}",
		"restore_keys: go-",
		"toolchain: container (",
		"trust domain: trusted (local)",
		"restore fallback: local then remote",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("cache inputs output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "lockfile digest: (none)") {
		t.Errorf("computed digest must be shown when hash_files resolve:\n%s", out)
	}
}

func TestPrintCacheInputsNoHashFiles(t *testing.T) {
	cj := pipeline.CompiledJob{ID: "test", Job: pipeline.Job{
		Cache: []pipeline.Cache{{Name: "no-lock", Paths: []string{"x"}, Key: "k"}},
	}}
	var buf bytes.Buffer
	printCacheInputs(&buf, cj, t.TempDir())
	if !strings.Contains(buf.String(), "lockfile digest: (none)") {
		t.Errorf("cache without hash_files must show (none):\n%s", buf.String())
	}
}

func TestPrintCacheCandidatesSurfacesGoSum(t *testing.T) {
	dir := lockfileWorkspace(t)
	var buf bytes.Buffer
	printCacheCandidates(&buf, dir)
	out := buf.String()
	if !strings.Contains(out, "cache candidates:") {
		t.Fatalf("candidate section missing:\n%s", out)
	}
	if !strings.Contains(out, "GOCACHE") || !strings.Contains(out, "go.sum") {
		t.Fatalf("go.sum candidate missing:\n%s", out)
	}
}

func TestPrintCacheCandidatesEmptyWorkspace(t *testing.T) {
	var buf bytes.Buffer
	printCacheCandidates(&buf, t.TempDir())
	if strings.Contains(buf.String(), "cache candidates:") {
		t.Fatalf("no candidates expected in an empty workspace:\n%s", buf.String())
	}
}
