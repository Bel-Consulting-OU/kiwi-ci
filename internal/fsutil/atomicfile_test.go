package fsutil

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// durableFault describes one injected failure of a durability step.
type durableFault struct {
	name string
	// preRename is true while the failure happens before the rename, so the
	// previous durable file must be bit-for-bit intact afterwards. A
	// directory-fsync failure happens after the rename and therefore cannot
	// preserve the old bytes (the rename is already visible); the write is
	// still unacknowledged, which is what the tests assert for it.
	preRename bool
	hooks     Hooks
}

func durableFaults() []durableFault {
	return []durableFault{
		{"file sync", true, Hooks{FileSync: func(*os.File) error {
			return errors.New("injected file fsync failure")
		}}},
		{"close", true, Hooks{FileClose: func(f *os.File) error {
			_ = RealFileClose(f)
			return errors.New("injected close failure")
		}}},
		{"rename", true, Hooks{Rename: func(string, string) error {
			return errors.New("injected rename failure")
		}}},
		{"dir sync", false, Hooks{DirSync: func(string) error {
			return errors.New("injected directory fsync failure")
		}}},
	}
}

// assertNoScratch fails when dir holds any durable-write scratch entry (the
// "."+base+".tmp-*" temp pattern) besides the named final files.
func assertNoScratch(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{}
	for _, w := range want {
		allowed[w] = true
	}
	for _, e := range entries {
		if !allowed[e.Name()] {
			t.Fatalf("scratch entry survived the write: %q", e.Name())
		}
	}
}

// TestAtomicWriteFileDurableSuccess proves the full sequence on the happy
// path: content and mode round-trip, the parent directory is fsynced exactly
// once, and no scratch file survives.
func TestAtomicWriteFileDurableSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	syncs := 0
	restore := SetHooks(Hooks{DirSync: func(d string) error {
		syncs++
		return RealSyncDir(d)
	}})
	defer restore()

	if err := AtomicWriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "v1" {
		t.Fatalf("content after first write = %q, %v; want v1", b, err)
	}
	if syncs != 1 {
		t.Fatalf("directory fsyncs = %d, want 1", syncs)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v; want 0600", fi.Mode().Perm(), err)
	}

	if err := AtomicWriteFile(path, []byte("v2"), 0o600); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "v2" {
		t.Fatalf("content after second write = %q, %v; want v2", b, err)
	}
	if syncs != 2 {
		t.Fatalf("directory fsyncs after second write = %d, want 2", syncs)
	}
	assertNoScratch(t, dir, "state.json")
}

// TestAtomicWriteFileModeApplied pins the chmod step: the caller's perm (e.g.
// 0644 for a public sidecar) replaces the 0600 CreateTemp default.
func TestAtomicWriteFileModeApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.crt")
	if err := AtomicWriteFile(path, []byte("pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", fi.Mode().Perm())
	}
	assertNoScratch(t, dir, "ca.crt")
}

// TestAtomicWriteFileStaleFixedTempPathIsInert proves the old path+".tmp"
// hazard is gone: a stale file (or directory) at the legacy fixed temp path
// neither blocks the durable write nor is touched, because the temp name is
// unique.
func TestAtomicWriteFileStaleFixedTempPathIsInert(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "web-session.key")
	stale := path + ".tmp"
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(stale, "keep")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write blocked by a stale fixed temp path: %v", err)
	}
	if b, err := os.ReadFile(sentinel); err != nil || string(b) != "keep" {
		t.Fatalf("stale temp path was touched: %q, %v", b, err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "secret" {
		t.Fatalf("final file = %q, %v; want secret", b, err)
	}
}

// TestAtomicWriteFileMissingDirectoryFails documents that the primitive does
// not create the destination directory: a write into a missing directory is
// an error, never an implicit mkdir (callers own directory creation).
func TestAtomicWriteFileMissingDirectoryFails(t *testing.T) {
	dir := t.TempDir()
	if err := AtomicWriteFile(filepath.Join(dir, "missing", "x.json"), []byte("v"), 0o600); err == nil {
		t.Fatal("write into a missing directory succeeded")
	}
	assertNoScratch(t, dir)
}

// TestAtomicWriteFileFaultsBlockDurability is the failure matrix: each
// durability step fails, the write reports the error, no scratch file
// survives, and for every pre-rename fault the previous durable bytes are
// bit-for-bit intact.
func TestAtomicWriteFileFaultsBlockDurability(t *testing.T) {
	for _, fault := range durableFaults() {
		t.Run(fault.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "state.json")
			if err := AtomicWriteFile(path, []byte("v1"), 0o600); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			restore := SetHooks(fault.hooks)
			err = AtomicWriteFile(path, []byte("v2"), 0o600)
			restore()
			if err == nil {
				t.Fatalf("injected %s failure was acknowledged", fault.name)
			}
			if !strings.Contains(err.Error(), "injected") {
				t.Fatalf("error %q does not surface the injected failure", err)
			}
			if fault.preRename {
				after, rerr := os.ReadFile(path)
				if rerr != nil {
					t.Fatal(rerr)
				}
				if !bytes.Equal(after, before) {
					t.Fatalf("previous durable bytes changed after a %s failure: %q, want %q", fault.name, after, before)
				}
			}
			assertNoScratch(t, dir, "state.json")
			// The old value is still readable and a healthy retry works.
			if err := AtomicWriteFile(path, []byte("v3"), 0o600); err != nil {
				t.Fatalf("retry after %s failure: %v", fault.name, err)
			}
			if b, err := os.ReadFile(path); err != nil || string(b) != "v3" {
				t.Fatalf("content after retry = %q, %v; want v3", b, err)
			}
		})
	}
}

// TestAtomicWriteFileDirSyncFailureIsPostRename pins the documented asymmetry:
// a failing parent-directory fsync surfaces as an error (nothing may be
// acknowledged) even though the rename already published the new bytes.
func TestAtomicWriteFileDirSyncFailureIsPostRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := AtomicWriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetHooks(Hooks{DirSync: func(string) error { return errors.New("parent fsync failed") }})
	err := AtomicWriteFile(path, []byte("v2"), 0o600)
	restore()
	if err == nil {
		t.Fatal("failing parent fsync was ignored")
	}
	if got := err.Error(); !strings.Contains(got, "parent fsync failed") {
		t.Fatalf("error %q does not surface the fsync failure", got)
	}
	// The rename happened, so the new bytes are visible; the durability
	// certificate is what failed.
	if b, rerr := os.ReadFile(path); rerr != nil || string(b) != "v2" {
		t.Fatalf("bytes after a failed parent fsync = (%q, %v)", b, rerr)
	}
	assertNoScratch(t, dir, "state.json")
}

// TestAtomicWriteFileUnwritableParent pins the CreateTemp failure path: a
// non-directory parent fails the write before anything is touched.
func TestAtomicWriteFileUnwritableParent(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteFile(filepath.Join(blocker, "child.json"), []byte("v"), 0o600); err == nil {
		t.Fatal("write under a regular file succeeded")
	}
	if b, err := os.ReadFile(blocker); err != nil || string(b) != "x" {
		t.Fatalf("blocker changed: %q, %v", b, err)
	}
}

// TestAtomicWriteFileRenameOntoNonEmptyDirectory pins the post-write cleanup:
// the rename cannot replace a non-empty directory, so the write fails and the
// scratch file is removed.
func TestAtomicWriteFileRenameOntoNonEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")
	if err := os.MkdirAll(filepath.Join(target, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteFile(target, []byte("v1"), 0o600); err == nil {
		t.Fatal("write over a non-empty directory succeeded")
	}
	if _, err := os.Stat(filepath.Join(target, "keep")); err != nil {
		t.Fatalf("target directory contents were lost: %v", err)
	}
	assertNoScratch(t, dir, "state.json")
}

// TestAtomicWriteFileConcurrentWritersProduceOneIntactFile stresses concurrent
// writers on one path (run under -race): every write must succeed, the final
// file must be exactly one writer's payload (no cross-contamination), and no
// scratch file may survive. Under the old fixed-temp implementation concurrent
// writers clobbered each other's scratch file.
func TestAtomicWriteFileConcurrentWritersProduceOneIntactFile(t *testing.T) {
	const writers = 8
	const rounds = 24
	const payloadSize = 64 << 10

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	payloads := make([][]byte, writers)
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte{byte('A' + i)}, payloadSize)
	}

	for round := 0; round < rounds; round++ {
		errs := make([]error, writers)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				errs[i] = AtomicWriteFile(path, payloads[i], 0o600)
			}(i)
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d: writer %d: %v", round, i, err)
			}
		}
		final, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		matched := false
		for i := range payloads {
			if bytes.Equal(final, payloads[i]) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("round %d: final file matches no single writer's payload (%d bytes, torn/cross-contaminated)", round, len(final))
		}
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("round %d: mode = %v, %v; want 0600", round, fi.Mode().Perm(), err)
		}
		assertNoScratch(t, dir, "state.json")
	}
}
