package workspace

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// scriptedStat returns an os.FileInfo whose Size follows a script — the
// test seam for a file mutating between the before/after samples of the
// adopt stability bracket.
type scriptedStat struct {
	size  int64
	mtime time.Time
}

func (s scriptedStat) Name() string       { return "planted" }
func (s scriptedStat) Size() int64        { return s.size }
func (s scriptedStat) Mode() os.FileMode  { return 0o644 }
func (s scriptedStat) ModTime() time.Time { return s.mtime }
func (s scriptedStat) IsDir() bool        { return false }
func (s scriptedStat) Sys() any           { return nil }

// TestAdoptFileRefusesMidReadMutation pins the adopted-file stability
// bracket: if the source's size/mtime moves between the before-sample and
// the after-sample of the read, the bytes are a hybrid of two writes —
// AdoptFile must retry once and then REFUSE, never adopt them as run
// authority (the audit's unbracketed adopt-copy race).
func TestAdoptFileRefusesMidReadMutation(t *testing.T) {
	src := t.TempDir()
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(t.Context()); err != nil {
		t.Fatal(err)
	}
	ext := filepath.Join(t.TempDir(), "pipeline.yaml")
	if err := os.WriteFile(ext, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Script: AdoptFile's dir-check samples first; then EVERY before/after
	// pair of both bracket attempts reports a grown file (mid-write
	// growth), so neither attempt can certify a stable read.
	mut := time.Now()
	sizes := []int64{11, 11, 12, 11, 12}
	calls := 0
	orig := adoptStat
	adoptStat = func(string) (os.FileInfo, error) {
		i := calls
		calls++
		if i >= len(sizes) {
			i = len(sizes) - 1
		}
		return scriptedStat{size: sizes[i], mtime: mut}, nil
	}
	t.Cleanup(func() { adoptStat = orig })

	_, err = m.AdoptFile(ext)
	adoptStat = orig
	if err == nil {
		t.Fatal("AdoptFile adopted a file that mutated mid-read")
	}
	if !strings.Contains(err.Error(), "changed while it was being read") {
		t.Fatalf("error = %v, want mid-read mutation refusal", err)
	}
	if calls < 5 {
		t.Fatalf("stability bracket sampled %d times, want dir-check + full retry bracket (5)", calls)
	}
	// Nothing may have been adopted into the run-base.
	if _, err := os.Stat(filepath.Join(m.BasePath(), ".kiwi-frozen", "pipeline.yaml")); err == nil {
		t.Fatal("hybrid bytes were written into the run-base")
	}

	// Stable file (real stat, no script): adoption succeeds and matches
	// the source bytes exactly.
	if got, aerr := m.AdoptFile(ext); aerr != nil {
		t.Fatalf("stable AdoptFile: %v", aerr)
	} else if b, rerr := os.ReadFile(got); rerr != nil || string(b) != "version: 1\n" {
		t.Fatalf("adopted bytes = %q %v", b, rerr)
	}
}

// TestFreezeContentDigestCatchesMiddleOnlyRewrite: files above the full-
// hash cap (64 MiB) are sampled head/tail — a same-size, same-mtime
// rewrite of the MIDDLE band (repacked archive core, overwritten blob
// segment) escaped that sample entirely. The middle band closes it: the
// audit's ">64MiB middle-only rewrite" oracle.
func TestFreezeContentDigestCatchesMiddleOnlyRewrite(t *testing.T) {
	src := t.TempDir()
	path := filepath.Join(src, "huge.bin")
	size := int64(freezeContentHashMax) + (1 << 20) // 65 MiB: over the full-hash cap
	payload := bytes.Repeat([]byte{'A'}, int(size))
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	d1, ok := freezeContentDigest(path, size)
	if !ok {
		t.Fatal("digest of the oversized file unavailable")
	}

	// Rewrite ONLY the middle band; restore size and mtime exactly.
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	mid := size/2 - (16 << 10)
	if _, err := f.WriteAt(bytes.Repeat([]byte{'B'}, 64<<10), mid); err != nil {
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
	d2, ok := freezeContentDigest(path, size)
	if !ok {
		t.Fatal("digest after rewrite unavailable")
	}
	if d1 == d2 {
		t.Fatal("middle-only rewrite of an oversized file escaped the freeze digest (head/tail-only sampling)")
	}
}
