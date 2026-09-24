package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestCreateFileCASPhaseMatrix drives every reachable phase of the
// create-if-absent publish sequence through a dedicated failure and pins the
// typed state model: pre-publish failures (create, write, chmod, file-sync,
// close) leave no destination, while the post-publish directory fsync reports
// published-but-uncertain. Every case then proves a healthy retry publishes.
func TestCreateFileCASPhaseMatrix(t *testing.T) {
	cases := []struct {
		name       string
		hooks      Hooks
		phase      Phase
		renamed    bool
		missingDir bool
	}{
		{name: "create", phase: PhaseCreate, missingDir: true},
		{name: "write", phase: PhaseWrite, hooks: Hooks{Write: func(*os.File, []byte) (int, error) {
			return 0, errors.New("injected write failure")
		}}},
		{name: "short-write", phase: PhaseWrite, hooks: Hooks{Write: func(f *os.File, b []byte) (int, error) {
			return f.Write(b[:1])
		}}},
		{name: "chmod", phase: PhaseChmod, hooks: Hooks{Chmod: func(string, os.FileMode) error {
			return errors.New("injected chmod failure")
		}}},
		{name: "file-sync", phase: PhaseFileSync, hooks: Hooks{FileSync: func(*os.File) error {
			return errors.New("injected file-sync failure")
		}}},
		{name: "close", phase: PhaseClose, hooks: Hooks{FileClose: func(f *os.File) error {
			_ = RealFileClose(f)
			return errors.New("injected close failure")
		}}},
		{name: "dir-sync", phase: PhaseDirSync, renamed: true, hooks: Hooks{DirSync: func(string) error {
			return errors.New("injected dir-sync failure")
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "trust.key")
			if tc.missingDir {
				path = filepath.Join(dir, "missing", "trust.key")
			}
			restore := SetHooks(tc.hooks)
			err := CreateFileCAS(path, []byte("material"), 0o600)
			restore()
			if err == nil {
				t.Fatalf("%s fault was acknowledged", tc.name)
			}
			var awe *AtomicWriteError
			if !errors.As(err, &awe) {
				t.Fatalf("%s error is not typed: %v", tc.name, err)
			}
			if awe.Phase != tc.phase || awe.Renamed != tc.renamed {
				t.Fatalf("%s error = phase %s renamed %v, want %s/%v", tc.name, awe.Phase, awe.Renamed, tc.phase, tc.renamed)
			}
			if tc.renamed {
				if !errors.Is(err, ErrPublishedUncertain) {
					t.Fatalf("%s error does not match ErrPublishedUncertain", tc.name)
				}
			} else if !errors.Is(err, ErrNotPublished) {
				t.Fatalf("%s error does not match ErrNotPublished", tc.name)
			}
			assertNoScratch(t, dir, "trust.key")
			if tc.renamed {
				if b, rerr := os.ReadFile(path); rerr != nil || string(b) != "material" {
					t.Fatalf("post-publish failure did not leave the bytes visible: %q, %v", b, rerr)
				}
				return
			}
			if _, serr := os.Stat(path); !os.IsNotExist(serr) {
				t.Fatalf("pre-publish failure created the destination: %v", serr)
			}
			// The primitive does not create the destination directory.
			if tc.missingDir {
				return
			}
			if rerr := CreateFileCAS(path, []byte("material"), 0o600); rerr != nil {
				t.Fatalf("retry after %s failure: %v", tc.name, rerr)
			}
			if b, rerr := os.ReadFile(path); rerr != nil || string(b) != "material" {
				t.Fatalf("content after retry = %q, %v", b, rerr)
			}
		})
	}
}

// TestCreateFileCASSuccessAndCreateIfAbsent pins the happy path and the
// create-if-absent contract: mode and bytes round-trip with no scratch file,
// a second publication loses to os.ErrExist and leaves the original intact.
func TestCreateFileCASSuccessAndCreateIfAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.key")
	if err := CreateFileCAS(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "first" {
		t.Fatalf("content = %q, %v", b, err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v; want 0600", fi.Mode().Perm(), err)
	}
	assertNoScratch(t, dir, "trust.key")

	err := CreateFileCAS(path, []byte("second"), 0o600)
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("second publish = %v, want os.ErrExist", err)
	}
	if b, rerr := os.ReadFile(path); rerr != nil || string(b) != "first" {
		t.Fatalf("second publish changed the original: %q, %v", b, rerr)
	}
	assertNoScratch(t, dir, "trust.key")
}
