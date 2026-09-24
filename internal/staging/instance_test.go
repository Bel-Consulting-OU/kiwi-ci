package staging

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

// TestInstanceIDRootFsyncFailureLeavesIDForAdoption is the R4-B regression:
// loadOrCreateInstanceID must fsync the ROOT after the id file's own fsync and
// close. Without it a power loss can lose the file's NAME, so a restart would
// generate a SECOND id, stage in a new subdirectory, and strand the previous
// replica directory unreclaimable.
//
// The test injects a root-fsync (DirSync) failure: ReplicaDir must fail
// startup, but the visible id file must be LEFT in place (published-uncertain)
// so the next attempt adopts the same id instead of generating another.
func TestInstanceIDRootFsyncFailureLeavesIDForAdoption(t *testing.T) {
	root := t.TempDir()
	var syncs atomic.Int64
	restore := fsutil.SetHooks(fsutil.Hooks{
		DirSync: func(dir string) error {
			if dir != root {
				return fsutil.RealSyncDir(dir)
			}
			syncs.Add(1)
			return errors.New("simulated power loss before root fsync")
		},
	})
	restored := false
	restoreOnce := func() {
		if !restored {
			restored = true
			restore()
		}
	}
	defer restoreOnce()

	_, _, err := ReplicaDir(root, "")
	if err == nil {
		t.Fatal("ReplicaDir accepted an id whose root fsync failed")
	}
	if !errors.Is(err, fsutil.ErrPublishedUncertain) {
		t.Fatalf("root-fsync failure = %v, want it to report published-uncertain", err)
	}
	if syncs.Load() == 0 {
		t.Fatal("the staging root was never fsynced before accepting the generated id")
	}
	path := filepath.Join(root, InstanceIDFileName)
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("the published id file must be LEFT for adoption, got: %v", rerr)
	}
	generated := strings.TrimSpace(string(data))
	if verr := ValidateInstanceID(generated); verr != nil {
		t.Fatalf("left id file %q is not a usable id: %v", generated, verr)
	}

	// Restore real durability: the restart must adopt the visible id and NOT
	// create a second generation.
	restoreOnce()
	dir, adopted, err := ReplicaDir(root, "")
	if err != nil {
		t.Fatalf("restart ReplicaDir: %v", err)
	}
	if adopted != generated {
		t.Fatalf("restart generated a second id %q, want to adopt the published %q", adopted, generated)
	}
	if dir != filepath.Join(root, generated) {
		t.Fatalf("restart resolved %q, want %q", dir, filepath.Join(root, generated))
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	idFiles := 0
	for _, e := range entries {
		if e.Name() == InstanceIDFileName {
			idFiles++
		}
	}
	if idFiles != 1 {
		t.Fatalf("found %d staging.instance files, want exactly 1", idFiles)
	}
}

// TestInstanceIDCrashRestartAdoptsExistingGeneration: once an id is durably
// published, repeated starts (and a fresh ReplicaDir after a "crash") resolve
// to the same directory and never generate a new id.
func TestInstanceIDCrashRestartAdoptsExistingGeneration(t *testing.T) {
	root := t.TempDir()
	firstDir, firstID, err := ReplicaDir(root, "")
	if err != nil {
		t.Fatalf("first derive: %v", err)
	}
	for i := 0; i < 5; i++ {
		dir, id, err := ReplicaDir(root, "")
		if err != nil {
			t.Fatalf("restart %d: %v", i, err)
		}
		if id != firstID || dir != firstDir {
			t.Fatalf("restart %d resolved (%q,%q), want (%q,%q)", i, dir, id, firstDir, firstID)
		}
	}
}

// TestInstanceIDPrePublishFailuresLeaveNoVisibleFile is the R2-1 regression
// for the torn-file window: the id is now written to a unique temp file and
// published create-if-absent, so a failure in any write/fsync/close step must
// happen strictly BEFORE the staging.instance name exists. The previous
// OpenFile(O_CREATE) sequence created the destination name first, so a failed
// write could leave a torn/empty file (and its cleanup unlinked it with no
// parent-directory fsync). Each case injects one failing durability step and
// asserts the destination was never created and the failure is typed
// "definitely not published".
func TestInstanceIDPrePublishFailuresLeaveNoVisibleFile(t *testing.T) {
	cases := map[string]fsutil.Hooks{
		"write error": {Write: func(*os.File, []byte) (int, error) {
			return 0, errors.New("injected write failure")
		}},
		"short write": {Write: func(_ *os.File, b []byte) (int, error) {
			return len(b) - 1, nil
		}},
		"file fsync error": {FileSync: func(*os.File) error {
			return errors.New("injected file fsync failure")
		}},
		"close error": {FileClose: func(f *os.File) error {
			_ = f.Close()
			return errors.New("injected close failure")
		}},
	}
	for name, hooks := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			restore := fsutil.SetHooks(hooks)
			defer restore()

			_, _, err := ReplicaDir(root, "")
			if err == nil {
				t.Fatal("ReplicaDir accepted an id whose publish failed before the destination existed")
			}
			if fsutil.Renamed(err) {
				t.Fatalf("pre-publish failure reported as published: %v", err)
			}
			if !errors.Is(err, fsutil.ErrNotPublished) {
				t.Fatalf("pre-publish failure = %v, want it to match ErrNotPublished", err)
			}
			if _, statErr := os.Stat(filepath.Join(root, InstanceIDFileName)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("a visible %s survived a pre-publish failure (torn file): stat err = %v", InstanceIDFileName, statErr)
			}
		})
	}
}

// TestInstanceIDAdoptsConcurrentWinner exercises the lost create-if-absent
// race: a valid id that is already published is adopted rather than replaced,
// and no second staging.instance is ever created.
func TestInstanceIDAdoptsConcurrentWinner(t *testing.T) {
	root := t.TempDir()
	winner := "replica-winner"
	if err := os.WriteFile(filepath.Join(root, InstanceIDFileName), []byte(winner+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := loadOrCreateInstanceID(root)
	if err != nil {
		t.Fatalf("loadOrCreateInstanceID: %v", err)
	}
	if id != winner {
		t.Fatalf("adopted id = %q, want the already-published %q", id, winner)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	idFiles := 0
	for _, e := range entries {
		if e.Name() == InstanceIDFileName {
			idFiles++
		}
	}
	if idFiles != 1 {
		t.Fatalf("found %d %s files, want exactly 1 (the winner)", idFiles, InstanceIDFileName)
	}
}
