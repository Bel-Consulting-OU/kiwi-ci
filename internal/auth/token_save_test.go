package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
)

// TestSavePropagatesAtomicWriteFailures pins the Save contract for every
// durability stage of the underlying primitive: a failing file sync, close,
// rename or parent-directory fsync surfaces as an error from Save, the
// previous durable file is untouched, and Save leaves no temporary files.
// The seam replaces fsutil.AtomicWriteFile, so this asserts that Save does
// no writes of its own and forwards the exact mode/path to the primitive.
func TestSavePropagatesAtomicWriteFailures(t *testing.T) {
	for _, stage := range []string{"sync", "close", "rename", "dir-sync"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "tokens.json")

			seed := NewTokenStore()
			if err := seed.AddToken("v1", Principal{Subject: "s", Roles: []Role{RoleRead}}); err != nil {
				t.Fatal(err)
			}
			if err := seed.Save(path); err != nil {
				t.Fatalf("seed save: %v", err)
			}
			durable, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			boom := fmt.Errorf("%s boom", stage)
			old := atomicWriteFile
			atomicWriteFile = func(gotPath string, data []byte, mode os.FileMode) error {
				if gotPath != path {
					t.Errorf("atomic write path = %q, want %q", gotPath, path)
				}
				if mode != 0o600 {
					t.Errorf("atomic write mode = %o, want 600", mode)
				}
				if len(data) == 0 {
					t.Errorf("atomic write of empty data")
				}
				return boom
			}
			t.Cleanup(func() { atomicWriteFile = old })

			next := NewTokenStore()
			if err := next.AddToken("v2", Principal{Subject: "s2", Roles: []Role{RoleAdmin}}); err != nil {
				t.Fatal(err)
			}
			err = next.Save(path)
			if err == nil {
				t.Fatalf("%s failure: Save returned nil", stage)
			}
			if !errors.Is(err, boom) {
				t.Fatalf("%s failure: Save error %v does not wrap the primitive error", stage, err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(durable) {
				t.Fatalf("%s failure changed the durable file: %q, want %q", stage, after, durable)
			}
			assertOnlyTokenFile(t, dir, path)
		})
	}
}

// TestSaveIgnoresStaleLegacyTempPath proves the fixed-temp defect is gone:
// a stale "tokens.json.tmp" directory (the exact shape a pre-fsutil release
// could leave behind) neither blocks Save nor is touched, because the durable
// write uses a unique temp name. Under the old fixed-temp implementation this
// test fails: Save tried to write into that stale path.
func TestSaveIgnoresStaleLegacyTempPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	stale := path + ".tmp"
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}

	store := NewTokenStore()
	if err := store.AddToken("raw", Principal{Subject: "s", Roles: []Role{RoleRun}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(path); err != nil {
		t.Fatalf("Save blocked by a stale legacy temp path: %v", err)
	}
	loaded := NewTokenStore()
	if err := loaded.Load(path); err != nil {
		t.Fatalf("reload after save with stale temp path: %v", err)
	}
	if got, ok := loaded.Authenticate("raw"); !ok || !effectivePrincipalEqual(got, Principal{Subject: "s", Roles: []Role{RoleRun}}) {
		t.Fatalf("reload lost the token: (%+v, %v)", got, ok)
	}
	if fi, err := os.Stat(stale); err != nil || !fi.IsDir() {
		t.Fatalf("stale temp path was touched: fi=%v err=%v", fi, err)
	}
}

// TestSaveIsDurableAndLeavesNoScratchFiles proves a successful Save is a
// single complete file with mode 0600 and that no scratch entries survive
// (repeated overwrites included).
func TestSaveIsDurableAndLeavesNoScratchFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	store := NewTokenStore()
	for i := 0; i < 3; i++ {
		if err := store.AddToken(fmt.Sprintf("raw-%d", i), Principal{Subject: fmt.Sprintf("s-%d", i)}); err != nil {
			t.Fatal(err)
		}
		if err := store.Save(path); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("round %d: mode = %o, want 600", i, fi.Mode().Perm())
		}
		assertOnlyTokenFile(t, dir, path)
	}
}

// TestSaveConcurrentWritersProduceOneIntactFile stresses concurrent Save on
// one store (run under -race): every call must succeed, the final file must
// be exactly one writer's complete snapshot, and no temp file may survive.
// Cross-contamination (bytes from two snapshots mixed) fails the equality
// check against each writer's expected map.
func TestSaveConcurrentWritersProduceOneIntactFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	const writers = 8
	const rounds = 16

	stores := make([]*TokenStore, writers)
	expected := make([]map[string]Principal, writers)
	for w := 0; w < writers; w++ {
		s := NewTokenStore()
		want := map[string]Principal{}
		principal := Principal{
			Subject:      fmt.Sprintf("writer-%d", w),
			Roles:        []Role{RoleRun},
			Repositories: map[string]RepositoryPermission{fmt.Sprintf("acme/repo-%d", w): {Run: true}},
		}
		for j := 0; j < 40; j++ {
			raw := fmt.Sprintf("writer-%d-token-%d", w, j)
			if err := s.AddToken(raw, principal); err != nil {
				t.Fatal(err)
			}
			want[TokenDigest(raw)] = principal
		}
		stores[w] = s
		expected[w] = want
	}

	for round := 0; round < rounds; round++ {
		start := make(chan struct{})
		errs := make([]error, writers)
		var wg sync.WaitGroup
		for w := 0; w < writers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				<-start
				errs[w] = stores[w].Save(path)
			}(w)
		}
		close(start)
		wg.Wait()
		for w, err := range errs {
			if err != nil {
				t.Fatalf("round %d: writer %d Save: %v", round, w, err)
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]Principal
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("round %d: final file is not valid JSON (%d bytes): %v", round, len(b), err)
		}
		matched := false
		for w := 0; w < writers; w++ {
			if reflect.DeepEqual(got, expected[w]) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("round %d: final file matches no single writer's snapshot (%d entries, %d bytes)", round, len(got), len(b))
		}
		assertOnlyTokenFile(t, dir, path)
	}
}

// TestSaveRenameFailureKeepsPriorStateAndNoScratch exercises the real
// primitive's rename step: renaming over a non-empty directory fails after
// the temp file was written, so Save must error, leave the existing tree
// untouched and clean up its scratch file.
func TestSaveRenameFailureKeepsPriorStateAndNoScratch(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokens.json")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(target, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewTokenStore()
	if err := store.AddToken("raw", Principal{Subject: "s", Roles: []Role{RoleRun}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(target); err == nil {
		t.Fatal("Save over a non-empty directory must fail")
	}
	b, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("sentinel lost after failed Save: %v", err)
	}
	if string(b) != "keep" {
		t.Fatalf("sentinel changed after failed Save: %q", b)
	}
	assertOnlyTokenFile(t, dir, target)
}

// TestSaveUnwritableParentKeepsPriorFile uses the real primitive's temp-file
// creation failure: with the parent directory unwritable, Save must error,
// keep the previously written file byte-identical and leave no scratch file.
func TestSaveUnwritableParentKeepsPriorFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permissions required")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	seed := NewTokenStore()
	if err := seed.AddToken("v1", Principal{Subject: "s"}); err != nil {
		t.Fatal(err)
	}
	if err := seed.Save(path); err != nil {
		t.Fatal(err)
	}
	durable, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	next := NewTokenStore()
	if err := next.AddToken("v2", Principal{Subject: "s2"}); err != nil {
		t.Fatal(err)
	}
	if err := next.Save(path); err == nil {
		t.Fatal("Save in an unwritable directory must fail")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(durable) {
		t.Fatalf("unwritable-parent failure changed the durable file: %q", after)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	assertOnlyTokenFile(t, dir, path)
}

// assertOnlyTokenFile fails when dir holds anything besides path.
func assertOnlyTokenFile(t *testing.T, dir, path string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Fatalf("unexpected scratch entry %q in %s", e.Name(), dir)
		}
	}
}
