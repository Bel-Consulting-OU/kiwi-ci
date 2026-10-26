package workspace

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFreezeManifestDetectsOversizedMiddleRewrite is the >64 MiB
// byte-authority oracle: a same-size, same-mtime rewrite OUTSIDE any
// head/middle/tail sample bands (offset 20 MiB of a 65 MiB file) must
// flip the freeze manifest. The old sampled digest for oversized files
// left this exact hole — the run-base could be certified against a tree
// whose large-file bytes had silently changed.
func TestFreezeManifestDetectsOversizedMiddleRewrite(t *testing.T) {
	src := t.TempDir()
	path := filepath.Join(src, "huge.bin")
	size := int64(65 << 20)
	if err := os.WriteFile(path, bytes.Repeat([]byte{'A'}, int(size)), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	m1, err := freezeManifest(src, "")
	if err != nil {
		t.Fatal(err)
	}

	// Same size, same mtime, bytes far from head/middle/tail bands.
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(bytes.Repeat([]byte{'B'}, 64<<10), 20<<20); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	st2, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st2.Size() != st.Size() || !st2.ModTime().Equal(st.ModTime()) {
		t.Fatalf("rewrite perturbed size/mtime: %d/%v vs %d/%v", st2.Size(), st2.ModTime(), st.Size(), st.ModTime())
	}

	m2, err := freezeManifest(src, "")
	if err != nil {
		t.Fatal(err)
	}
	if m1 == m2 {
		t.Fatal("middle-only rewrite of an oversized file escaped the freeze manifest — sampled equality was treated as byte proof")
	}
}

// TestFreezeManifestRefusesMetadataOnlyProof: when a file's bytes cannot be
// fully hashed, the canonical freeze must FAIL rather than silently degrade
// to size/mode/mtime identity. Metadata is invalidation, not proof.
func TestFreezeManifestRefusesMetadataOnlyProof(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode-0200 files; the unreadability precondition needs an unprivileged runner")
	}
	src := t.TempDir()
	path := filepath.Join(src, "unreadable.bin")
	if err := os.WriteFile(path, []byte("secret-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o200); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })

	_, err := freezeManifest(src, "")
	if err == nil {
		t.Fatal("freeze accepted a metadata-only identity for an unreadable file (must fail closed)")
	}
	if !strings.Contains(err.Error(), "content identity") {
		t.Fatalf("error = %v, want content-identity refusal", err)
	}
}

// TestFreezeByteProofCatchesMidCopyMutation pins the copied-vs-source
// equality proof inside the real freeze transaction: the source is
// mutated AFTER its bytes were copied (freezeAfterCopyHook) with a
// per-attempt content counter, so the before/after manifests of each
// attempt stay internally consistent but the run-base holds bytes the
// source no longer has. The proof must fail BOTH attempts with the
// content-integrity message — a generic "source changed" failure is not
// the contract (and would not fire when the mutation is restored before
// the after-manifest).
func TestFreezeByteProofCatchesMidCopyMutation(t *testing.T) {
	src := t.TempDir()
	path := filepath.Join(src, "payload.bin")
	orig := []byte("original-payload-0123456789")
	if err := os.WriteFile(path, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(path, orig, 0o644) })

	calls := 0
	origInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	origHook := freezeAfterCopyHook
	freezeAfterCopyHook = func() {
		calls++
		// In-place single-byte flip with size and mtime restored: the
		// stat-identity bracket stays satisfied, so ONLY the content
		// comparison can catch the divergence (exactly the path a
		// metadata-only proof would miss). Alternate bytes so the retry's
		// copy (previous flip) also diverges from the post-copy source.
		flip := byte('X')
		if calls%2 == 0 {
			flip = 'Y'
		}
		f, ferr := os.OpenFile(path, os.O_WRONLY, 0)
		if ferr != nil {
			t.Errorf("hook open: %v", ferr)
			return
		}
		if _, werr := f.WriteAt([]byte{flip}, 0); werr != nil {
			_ = f.Close()
			t.Errorf("hook write: %v", werr)
			return
		}
		_ = f.Close()
		_ = os.Chtimes(path, origInfo.ModTime(), origInfo.ModTime())
	}
	t.Cleanup(func() { freezeAfterCopyHook = origHook })

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	err = m.Freeze(t.Context())
	if err == nil {
		t.Fatal("freeze accepted a run-base whose copied bytes diverge from the source")
	}
	if !strings.Contains(err.Error(), "copied bytes do not match source") {
		t.Fatalf("error = %v, want the content-integrity failure (attempt-specific proof), not a generic instability", err)
	}
	if calls != 2 {
		t.Fatalf("freezeAfterCopyHook fired %d time(s), want one per transaction attempt (2)", calls)
	}
	if m.BasePath() != "" {
		t.Fatalf("failed byte proof must not publish a run-base (base=%q)", m.BasePath())
	}
}

// TestFreezeManifestFailureRetriesBeforeFailing: a transient content-
// identity failure (file unreadable during the FIRST manifest, readable
// for the retry) must ride the freeze transaction's retry instead of
// aborting outright. The transaction exists precisely for busy trees; a
// fail-closed rule must not be stricter than the transaction that carries
// it.
func TestFreezeManifestFailureRetriesBeforeFailing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode-0200 files; the unreadability precondition needs an unprivileged runner")
	}
	src := t.TempDir()
	path := filepath.Join(src, "transient.bin")
	if err := os.WriteFile(path, []byte("transient"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })

	origHook := freezeBeforeManifestHook
	calls := 0
	freezeBeforeManifestHook = func() {
		calls++
		if calls == 1 {
			_ = os.Chmod(path, 0o200) // unreadable for attempt 1
		} else {
			_ = os.Chmod(path, 0o644) // stable for the retry
		}
	}
	t.Cleanup(func() { freezeBeforeManifestHook = origHook })

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(t.Context()); err != nil {
		t.Fatalf("transient manifest failure must retry, not abort the freeze: %v", err)
	}
	if calls != 2 {
		t.Fatalf("freeze attempts = %d, want 2 (one per transaction attempt)", calls)
	}
	if m.BasePath() == "" {
		t.Fatal("no run-base published after a recovered retry")
	}
}

// TestFreezeManifestFailurePersistentFailsClosed: when content identity
// STILL cannot be established on the retry, the freeze fails closed with
// the content-identity message — never a metadata-only run-base — and the
// attempt counter proves the retry actually ran first.
func TestFreezeManifestFailurePersistentFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode-0200 files; the unreadability precondition needs an unprivileged runner")
	}
	src := t.TempDir()
	path := filepath.Join(src, "unprovable.bin")
	if err := os.WriteFile(path, []byte("unprovable"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })

	origHook := freezeBeforeManifestHook
	calls := 0
	freezeBeforeManifestHook = func() {
		calls++
		_ = os.Chmod(path, 0o200) // unreadable for EVERY attempt
	}
	t.Cleanup(func() { freezeBeforeManifestHook = origHook })

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	err = m.Freeze(t.Context())
	if err == nil {
		t.Fatal("freeze published a run-base without provable content identity")
	}
	if !strings.Contains(err.Error(), "content identity") {
		t.Fatalf("error = %v, want the content-identity refusal", err)
	}
	if calls != 2 {
		t.Fatalf("freeze attempts = %d, want 2 (retry before failing closed)", calls)
	}
	if m.BasePath() != "" {
		t.Fatalf("failed freeze must not publish a run-base (base=%q)", m.BasePath())
	}
}
