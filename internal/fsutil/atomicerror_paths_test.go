package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestAtomicWriteErrorFallbacks pins the unmatched branches of the typed
// error helpers: a foreign error is never a phase error, Is only matches the
// two durability sentinels, and the sentinels themselves stay non-matching
// for an ordinary error.
func TestAtomicWriteErrorFallbacks(t *testing.T) {
	plain := errors.New("plain failure")
	if _, ok := PhaseOf(plain); ok {
		t.Fatal("PhaseOf(plain) reported a phase")
	}
	if Renamed(plain) || NotPublished(plain) {
		t.Fatal("plain error classified as an atomic write failure")
	}

	pre := newAtomicWriteError("/tmp/x", PhaseWrite, plain)
	if !pre.Is(ErrNotPublished) || pre.Is(ErrPublishedUncertain) {
		t.Fatalf("pre-rename Is = %v/%v", pre.Is(ErrNotPublished), pre.Is(ErrPublishedUncertain))
	}
	if !errors.Is(pre, plain) {
		t.Fatal("foreign target did not fall through to the unwrap chain")
	}
	if errors.Is(plain, ErrNotPublished) {
		t.Fatal("plain error matched ErrNotPublished")
	}

	post := newAtomicWriteError("/tmp/x", PhaseDirSync, plain)
	if post.Is(ErrNotPublished) || !post.Is(ErrPublishedUncertain) {
		t.Fatalf("post-rename Is = %v/%v", post.Is(ErrNotPublished), post.Is(ErrPublishedUncertain))
	}
	if got, ok := PhaseOf(post); !ok || got != PhaseDirSync {
		t.Fatalf("PhaseOf(post) = %q/%v", got, ok)
	}
	if !Renamed(post) || NotPublished(post) {
		t.Fatal("post-rename classification wrong")
	}
}

// TestRealSyncDirFailurePaths exercises the production directory-fsync door
// directly: a missing directory fails at open, and a device whose fsync is
// unsupported fails at the sync step (never silently succeeding).
func TestRealSyncDirFailurePaths(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	if err := RealSyncDir(missing); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("RealSyncDir(absent) = %v, want os.ErrNotExist", err)
	}

	if runtime.GOOS != "linux" {
		return
	}
	// /dev/null opens fine but its fsync is unsupported (EINVAL), which must
	// surface as an error rather than a false durable acknowledgement.
	if err := RealSyncDir("/dev/null"); err == nil {
		t.Fatal("RealSyncDir(/dev/null) acknowledged an unsupported fsync")
	}
}
