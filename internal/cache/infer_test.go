package cache

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestInferLockfilesFirstLevelOnly(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"go.sum", "package-lock.json", "yarn.lock", "Cargo.lock", "Gemfile.lock", "sub/poetry.lock"} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := InferLockfiles(dir)
	names := []string{}
	for _, lf := range got {
		names = append(names, lf.Name)
	}
	want := []string{"Cargo.lock", "Gemfile.lock", "go.sum", "package-lock.json", "yarn.lock"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("lockfiles: %v, want %v", names, want)
	}
	// The nested poetry.lock must not be reported (first level only).
	for _, lf := range got {
		if lf.Name == "poetry.lock" {
			t.Fatal("nested lockfile reported")
		}
	}
}

func TestInferLockfilesEmpty(t *testing.T) {
	if got := InferLockfiles(filepath.Join(t.TempDir(), "missing")); len(got) != 0 {
		t.Fatalf("expected none, got %v", got)
	}
}

func TestSuggestCaches(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"go.sum", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock", "poetry.lock", "uv.lock", "Gemfile.lock"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := SuggestCaches(dir)
	if len(got) != 8 {
		t.Fatalf("suggestions: %d", len(got))
	}
	byName := map[string]Suggest{}
	for _, s := range got {
		byName[s.Name] = s
		if s.Status != "candidate" {
			t.Fatalf("status: %q", s.Status)
		}
		if s.Reason == "" || s.KeyTemplate == "" {
			t.Fatalf("explainable strings empty: %+v", s)
		}
		if len(s.Paths) == 0 || len(s.HashFiles) != 1 {
			t.Fatalf("paths/hash files: %+v", s)
		}
	}
	if !reflect.DeepEqual(byName["GOCACHE"].Paths, []string{".kiwi/go-cache"}) {
		t.Fatalf("GOCACHE: %+v", byName["GOCACHE"])
	}
	if !reflect.DeepEqual(byName["node_modules"].Paths, []string{"node_modules"}) {
		t.Fatalf("node_modules: %+v", byName["node_modules"])
	}
	if !reflect.DeepEqual(byName["cargo"].Paths, []string{"target", ".kiwi/cargo-home"}) {
		t.Fatalf("cargo: %+v", byName["cargo"])
	}
	if byName["bundler"].Lockfile != "Gemfile.lock" {
		t.Fatalf("bundler: %+v", byName["bundler"])
	}
}

func TestVerifyLockfile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLockfile(dir, "go.sum"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLockfile(dir, "missing.lock"); err == nil {
		t.Fatal("want missing error")
	}
	if err := VerifyLockfile(dir, "../go.sum"); err == nil {
		t.Fatal("want escape rejection")
	}
}
