package staging

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

// TestReadInstanceIDWithRetryAdoptsAndFails covers the concurrent-publish
// retry: a valid id that appears within the window is adopted, a missing file
// fails immediately with the underlying error, and a file that stays
// incomplete past the window reports the typed unpublished error.
func TestReadInstanceIDWithRetryAdoptsAndFails(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, InstanceIDFileName)
	if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(40 * time.Millisecond)
		_ = os.WriteFile(path, []byte("replica-adopted\n"), 0o600)
	}()
	id, err := readInstanceIDWithRetry(path)
	if err != nil || id != "replica-adopted" {
		t.Fatalf("retry adopt = %q, %v; want replica-adopted", id, err)
	}

	if _, err := readInstanceIDWithRetry(filepath.Join(root, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing id error = %v, want os.ErrNotExist", err)
	}

	stuck := t.TempDir()
	stuckPath := filepath.Join(stuck, InstanceIDFileName)
	if err := os.WriteFile(stuckPath, []byte("bad id!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = readInstanceIDWithRetry(stuckPath)
	if !errors.Is(err, ErrInstanceIDUnpublished) {
		t.Fatalf("stuck id error = %v, want ErrInstanceIDUnpublished", err)
	}
	if time.Since(start) < time.Second {
		t.Fatal("stuck id returned before the retry window elapsed")
	}
}

// TestLoadOrCreateInstanceIDErrorPaths covers the adopt-existing, read-error
// and open-error arms of the id publisher.
func TestLoadOrCreateInstanceIDErrorPaths(t *testing.T) {
	// An existing valid id is adopted.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, InstanceIDFileName), []byte("replica-existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if id, err := loadOrCreateInstanceID(root); err != nil || id != "replica-existing" {
		t.Fatalf("adopt = %q, %v", id, err)
	}

	// The id path is a directory: OpenFile O_EXCL loses to EEXIST, then the
	// retry read reports a non-unpublished error.
	dirRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(dirRoot, InstanceIDFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateInstanceID(dirRoot); err == nil {
		t.Fatal("expected an error when the id path is a directory")
	}

	// A read-only root fails the O_EXCL open.
	roRoot := t.TempDir()
	if err := os.Chmod(roRoot, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(roRoot, 0o700) })
	if _, err := loadOrCreateInstanceID(roRoot); err == nil {
		t.Fatal("expected an error when the root is read-only")
	}
}

// TestValidateInstanceIDBranches pins the id shape contract.
func TestValidateInstanceIDBranches(t *testing.T) {
	long := strings.Repeat("a", MaxInstanceIDLen+1)
	bad := []string{"", "  ", long, ".", "..", ".hidden", "a/b", "a b", "a!"}
	for _, id := range bad {
		if err := ValidateInstanceID(id); err == nil {
			t.Errorf("ValidateInstanceID(%q) = nil, want error", id)
		}
	}
	for _, id := range []string{"replica-abc", "a_b.1", "A1"} {
		if err := ValidateInstanceID(id); err != nil {
			t.Errorf("ValidateInstanceID(%q) = %v, want nil", id, err)
		}
	}
}

// TestReplicaDirValidation covers the constructor's input rejection arms.
func TestReplicaDirValidation(t *testing.T) {
	if _, _, err := ReplicaDir("", "id"); !errors.Is(err, ErrNoBound) {
		t.Fatalf("empty root = %v, want ErrNoBound", err)
	}
	root := t.TempDir()
	for _, id := range []string{"../escape", ".hidden", "a/b"} {
		if _, _, err := ReplicaDir(root, id); err == nil {
			t.Errorf("ReplicaDir(root, %q) succeeded, want an invalid-id error", id)
		}
	}
	dir, id, err := ReplicaDir(root, "explicit-1")
	if err != nil || id != "explicit-1" || dir != filepath.Join(root, "explicit-1") {
		t.Fatalf("explicit id = (%q,%q,%v)", dir, id, err)
	}
}

// TestSweepSpoolFilesEdges covers the reclaim helper's missing-directory,
// not-a-directory and removal-failure arms.
func TestSweepSpoolFilesEdges(t *testing.T) {
	if n, err := sweepSpoolFiles(filepath.Join(t.TempDir(), "missing")); n != 0 || err != nil {
		t.Fatalf("missing dir = %d, %v", n, err)
	}
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sweepSpoolFiles(file); err == nil {
		t.Fatal("not-a-directory sweep succeeded")
	}

	ro := t.TempDir()
	spool := filepath.Join(ro, FilePrefix+"stranded")
	if err := os.WriteFile(spool, []byte("bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
	if _, err := sweepSpoolFiles(ro); err == nil {
		t.Fatal("removal failure was not surfaced")
	}
}

// TestPruneErrorArms covers Prune's cancelled-context and removal-failure
// arms on a real budget.
func TestPruneErrorArms(t *testing.T) {
	dir := t.TempDir()
	b, err := NewBudget(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.PruneMinAge = time.Nanosecond

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Prune(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Prune = %v, want context.Canceled", err)
	}

	spool := filepath.Join(dir, FilePrefix+"old")
	if err := os.WriteFile(spool, []byte("bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(spool, past, past); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := b.Prune(context.Background()); err == nil {
		t.Fatal("Prune removal failure was not surfaced")
	}
}

// noProgressAfterLimit returns exactly n bytes on its first read and then
// (0, nil) forever, modelling a reader that cannot prove EOF after the limit.
type noProgressAfterLimit struct {
	n     int
	first bool
}

func (r *noProgressAfterLimit) Read(p []byte) (int, error) {
	if !r.first {
		r.first = true
		for i := 0; i < r.n && i < len(p); i++ {
			p[i] = 'x'
		}
		return r.n, nil
	}
	return 0, nil
}

// TestSpoolFileAndSpoolCopyEdges covers SpoolFile's directory-creation failure
// and spoolCopy's no-progress fail-closed arm.
func TestSpoolFileAndSpoolCopyEdges(t *testing.T) {
	parent := t.TempDir()
	blocker := filepath.Join(parent, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := &Budget{dir: filepath.Join(blocker, "staging"), notify: make(chan struct{})}
	if _, _, err := bad.SpoolFile(bytes.NewReader([]byte("x")), 0); err == nil {
		t.Fatal("SpoolFile under a file parent succeeded")
	}

	var dst bytes.Buffer
	if _, err := spoolCopy(&dst, &noProgressAfterLimit{n: 8}, 8); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("no-progress spoolCopy = %v, want ErrTooLarge", err)
	}
}

// ioReaderFunc adapts a function to io.Reader for tiny fakes.
type ioReaderFunc func([]byte) (int, error)

func (f ioReaderFunc) Read(p []byte) (int, error) { return f(p) }

var _ io.Reader = ioReaderFunc(nil)

// TestAcquireDirLockEdges covers the lock-open and nil-release arms.
func TestAcquireDirLockEdges(t *testing.T) {
	if _, err := acquireDirLock(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("acquireDirLock on a missing directory succeeded")
	}
	var l *dirLock
	if err := l.release(); err != nil {
		t.Fatalf("nil release = %v, want nil", err)
	}
	empty := &dirLock{}
	if err := empty.release(); err != nil {
		t.Fatalf("empty release = %v, want nil", err)
	}
}

// TestMigrateLegacyStagingLayoutErrorArms covers the migration's
// directory-creation, root-read and removal-failure arms.
func TestMigrateLegacyStagingLayoutErrorArms(t *testing.T) {
	parent := t.TempDir()
	blocker := filepath.Join(parent, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateLegacyStagingLayout(context.Background(), filepath.Join(blocker, "root")); err == nil {
		t.Fatal("migration under a file parent succeeded")
	}

	// A write+execute (unreadable) root fails the entry read after the lock.
	noRead := t.TempDir()
	if err := os.WriteFile(filepath.Join(noRead, LockFileName), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(noRead, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(noRead, 0o700) })
	if _, err := MigrateLegacyStagingLayout(context.Background(), noRead); err == nil {
		t.Fatal("unreadable root migration succeeded")
	}

	// A read-only root fails the spool removal.
	ro := t.TempDir()
	if err := os.WriteFile(filepath.Join(ro, LockFileName), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ro, FilePrefix+"legacy"), []byte("bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
	if _, err := MigrateLegacyStagingLayout(context.Background(), ro); err == nil {
		t.Fatal("read-only root migration succeeded")
	}
}

// TestReplicaDirSyncable covers the published-uncertain SyncDir failure via
// the public constructor when the root itself cannot be fsynced.
func TestLoadOrCreateInstanceIDDirSyncFailure(t *testing.T) {
	root := t.TempDir()
	restore := fsutil.SetHooks(fsutil.Hooks{DirSync: func(string) error {
		return errors.New("injected root fsync failure")
	}})
	defer restore()
	if _, err := loadOrCreateInstanceID(root); err == nil {
		t.Fatal("root fsync failure was not surfaced")
	} else if !errors.Is(err, fsutil.ErrPublishedUncertain) {
		t.Fatalf("root fsync failure = %v, want ErrPublishedUncertain", err)
	}
	if _, err := os.Stat(filepath.Join(root, InstanceIDFileName)); err != nil {
		t.Fatalf("published-uncertain id file was removed: %v", err)
	}
}
