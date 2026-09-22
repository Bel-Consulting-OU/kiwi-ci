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
