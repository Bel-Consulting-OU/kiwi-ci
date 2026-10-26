package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFreezeExternalSymlinkTargetMidCopyMutationFailsClosed is the P1
// oracle for external symlink materialization: an out-of-tree target that
// changes BETWEEN the copy read and the post-copy source rehash (size and
// mtime restored, so the identity bracket alone would pass) must fail the
// freeze with the content-integrity message — never publish a run-base
// holding hybrid external bytes. The hook fires once per transaction
// attempt; the freeze retries, then refuses.
func TestFreezeExternalSymlinkTargetMidCopyMutationFailsClosed(t *testing.T) {
	src := t.TempDir()
	ext := filepath.Join(t.TempDir(), "model.bin")
	orig := make([]byte, 4096)
	for i := range orig {
		orig[i] = 'A'
	}
	if err := os.WriteFile(ext, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(ext, orig, 0o644) })
	if err := os.Symlink(ext, filepath.Join(src, "model.bin")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(src, "seed.txt"), "s")

	extInfo, err := os.Stat(ext)
	if err != nil {
		t.Fatal(err)
	}
	origHook := freezeAfterExternalReadHook
	calls := 0
	freezeAfterExternalReadHook = func(string) {
		calls++
		// In-place single-byte flip with size and mtime restored, a
		// DIFFERENT byte every attempt (so the retry's copy also diverges
		// from the post-copy source and cannot "recover" onto a stable
		// mutated state): the SameFile/mtime bracket stays satisfied, so
		// ONLY the copied-vs-source rehash can catch the divergence.
		flip := byte('B')
		if calls%2 == 0 {
			flip = 'C'
		}
		f, ferr := os.OpenFile(ext, os.O_WRONLY, 0)
		if ferr != nil {
			t.Errorf("hook open: %v", ferr)
			return
		}
		if _, werr := f.WriteAt([]byte{flip}, 16); werr != nil {
			_ = f.Close()
			t.Errorf("hook write: %v", werr)
			return
		}
		_ = f.Close()
		_ = os.Chtimes(ext, extInfo.ModTime(), extInfo.ModTime())
	}
	t.Cleanup(func() { freezeAfterExternalReadHook = origHook })

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	err = m.Freeze(t.Context())
	if err == nil {
		t.Fatal("freeze accepted hybrid bytes for an external symlink target")
	}
	if !strings.Contains(err.Error(), "external target") || !strings.Contains(err.Error(), "do not match source") {
		t.Fatalf("error = %v, want external-target content-integrity failure", err)
	}
	if calls != 2 {
		t.Fatalf("external-read hook fired %d time(s), want one per freeze attempt (2)", calls)
	}
	if m.BasePath() != "" {
		t.Fatalf("failed freeze must not publish a run-base (base=%q)", m.BasePath())
	}
}

// TestFreezeExternalSymlinkTargetDisappearsMidRead: a target that vanishes
// after its bytes were copied fails that attempt (post-stat cannot confirm
// identity); the retry then finds the target gone outright and refuses the
// dangling absolute link. No run-base is published either way.
func TestFreezeExternalSymlinkTargetDisappearsMidRead(t *testing.T) {
	src := t.TempDir()
	ext := filepath.Join(t.TempDir(), "ghost.bin")
	if err := os.WriteFile(ext, []byte("ghost-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ext, filepath.Join(src, "ghost.bin")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(src, "seed.txt"), "s")

	origHook := freezeAfterExternalReadHook
	freezeAfterExternalReadHook = func(string) { _ = os.Remove(ext) }
	t.Cleanup(func() { freezeAfterExternalReadHook = origHook; _ = os.WriteFile(ext, []byte("ghost-bytes"), 0o644) })

	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	err = m.Freeze(t.Context())
	if err == nil {
		t.Fatal("freeze accepted a run-base whose external target vanished mid-copy")
	}
	// Attempt 1 reports the vanishing target; attempt 2 finds the absolute
	// link dangling. Both are external-target refusals; the final message
	// is attempt 2's, and the contract is: failed, and no run-base.
	if !strings.Contains(err.Error(), "external target") && !strings.Contains(err.Error(), "dangling") {
		t.Fatalf("error = %v, want an external-target refusal", err)
	}
	if m.BasePath() != "" {
		t.Fatalf("failed freeze must not publish a run-base (base=%q)", m.BasePath())
	}
}

// TestFreezeExternalTargetStoreContentAddressed pins the store contract:
// the store file NAME is the full 256-bit digest of its bytes, two
// symlinks to the same external file share ONE entry, distinct contents
// get distinct entries, and a corrupt pre-existing entry at the digest
// name is replaced by the proven copy rather than blindly reused.
func TestFreezeExternalTargetStoreContentAddressed(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	ext := filepath.Join(t.TempDir(), "shared.conf")
	body := []byte("v=shared\n")
	if err := os.WriteFile(ext, body, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"conf-a", "conf-b"} {
		if err := os.Symlink(ext, filepath.Join(src, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"conf-a", "conf-b"} {
		if err := materializeSymlink(filepath.Join(src, name), ext, src, dst, filepath.Join(dst, name)); err != nil {
			t.Fatal(err)
		}
	}
	store := filepath.Join(dst, ".kiwi-frozen-link-targets")
	entries, err := os.ReadDir(store)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(body)
	wantName := hex.EncodeToString(wantDigest[:])
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("store entries = %v, want exactly one content-addressed file", names)
	}
	if entries[0].Name() != wantName {
		t.Fatalf("store name = %q, want the full digest %q (no truncated namespace)", entries[0].Name(), wantName)
	}
	if len(entries[0].Name()) != 64 {
		t.Fatalf("store name length = %d, want 64 hex chars (256 bits)", len(entries[0].Name()))
	}
	for _, name := range []string{"conf-a", "conf-b"} {
		res, err := filepath.EvalSymlinks(filepath.Join(dst, name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(res)
		if err != nil || string(got) != string(body) {
			t.Fatalf("%s content = %q err=%v", name, got, err)
		}
	}

	// Distinct content → distinct entry.
	ext2 := filepath.Join(t.TempDir(), "other.conf")
	body2 := []byte("v=other\n")
	if err := os.WriteFile(ext2, body2, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ext2, filepath.Join(src, "other")); err != nil {
		t.Fatal(err)
	}
	if err := materializeSymlink(filepath.Join(src, "other"), ext2, src, dst, filepath.Join(dst, "other")); err != nil {
		t.Fatal(err)
	}
	entries, err = os.ReadDir(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("store entries after second target = %d, want 2", len(entries))
	}

	// Corrupt the first entry in place: re-materializing the same target
	// must REPLACE the corrupt file with the proven copy (reuse is verified
	// by hashing, never by path existence).
	corrupt := filepath.Join(store, wantName)
	if err := os.WriteFile(corrupt, []byte("CORRUPTED\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := materializeSymlink(filepath.Join(src, "conf-a"), ext, src, dst, filepath.Join(dst, "conf-a2")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(corrupt)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("corrupt store entry was reused verbatim: %q", got)
	}
}
