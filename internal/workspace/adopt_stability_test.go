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
// authority (the audit's unbracketed adopt-copy race). AdoptFile routes
// through the joint AdoptInputs transaction, so each attempt samples
// stat-before and stat-after (the dir check is the before-sample).
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

	// Script: every before/after pair of both bracket attempts reports a
	// grown file (mid-write growth), so neither attempt can certify a
	// stable read. Call order per attempt: stat-before, stat-after.
	mut := time.Now()
	sizes := []int64{11, 12, 11, 12}
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
	if calls < 4 {
		t.Fatalf("stability bracket sampled %d times, want the full retry bracket (4)", calls)
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

// TestAdoptInputsRejectsUnstableSet is the cross-file atomicity oracle: a
// pipeline and lock that are each read-able must still be refused as a SET
// when any member's stat moves inside the joint window. Individually
// stable reads could certify a combination that never existed (pipeline A
// + lock B). Nothing may be written when the set fails.
func TestAdoptInputsRejectsUnstableSet(t *testing.T) {
	src := t.TempDir()
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(t.Context()); err != nil {
		t.Fatal(err)
	}
	extDir := t.TempDir()
	pip := filepath.Join(extDir, "pipeline.yaml")
	lock := filepath.Join(extDir, "lock.json")
	if err := os.WriteFile(pip, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Call order per attempt: S1(pipeline), S1(lock), S2(pipeline),
	// S2(lock). The lock's after-sample always reports growth.
	mut := time.Now()
	sizes := []int64{10, 10, 10, 11, 10, 10, 10, 11}
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

	_, err = m.AdoptInputs(pip, lock)
	adoptStat = orig
	if err == nil {
		t.Fatal("AdoptInputs accepted a set that was never simultaneously stable")
	}
	if !strings.Contains(err.Error(), "one transaction") {
		t.Fatalf("error = %v, want joint-transaction refusal", err)
	}
	if !strings.Contains(err.Error(), "lock.json") {
		t.Fatalf("error should name the moving member: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(m.BasePath(), ".kiwi-frozen", "pipeline.yaml")); serr == nil {
		t.Fatal("pipeline was adopted despite the unstable set")
	}
	if _, serr := os.Stat(filepath.Join(m.BasePath(), ".kiwi-frozen", "lockroot", ".kiwi", "lock.json")); serr == nil {
		t.Fatal("lock was adopted despite the unstable set")
	}

	// Stable set: BOTH members land with their layouts, one window.
	res, err := m.AdoptInputs(pip, lock)
	if err != nil {
		t.Fatalf("stable AdoptInputs: %v", err)
	}
	if res.PipelineDst == "" || res.LockRoot == "" {
		t.Fatalf("stable adoption returned %+v, want both destinations", res)
	}
	if b, rerr := os.ReadFile(res.PipelineDst); rerr != nil || string(b) != "version: 1\n" {
		t.Fatalf("adopted pipeline = %q %v", b, rerr)
	}
	if b, rerr := os.ReadFile(filepath.Join(res.LockRoot, ".kiwi", "lock.json")); rerr != nil || string(b) != `{"version":1}` {
		t.Fatalf("adopted lock = %q %v", b, rerr)
	}
}

// TestFreezeContentDigestCatchesMiddleOnlyRewrite: a same-size, same-mtime
// rewrite deep inside a large file (well past any historic head/tail
// sampling bands) must change the freeze content digest. The canonical
// freeze hashes every byte of every regular file, so any offset flips it.
func TestFreezeContentDigestCatchesMiddleOnlyRewrite(t *testing.T) {
	src := t.TempDir()
	path := filepath.Join(src, "huge.bin")
	size := int64(65 << 20) // 65 MiB: well past any historic sampling cap
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

// TestAdoptInputsRejectsInodeSwapWithSameStat: size, mode and mtime all
// matching is not proof the file is the same FILE. An unlink/recreate (or
// a swap to another inode whose metadata was cloned) between the before
// and after samples must fail the adoption set — the metadata-only bracket
// accepted it, exactly the class of proof the freeze byte-proof refuses
// everywhere else.
func TestAdoptInputsRejectsInodeSwapWithSameStat(t *testing.T) {
	src := t.TempDir()
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(t.Context()); err != nil {
		t.Fatal(err)
	}
	pip := filepath.Join(t.TempDir(), "pipeline.yaml")
	body := []byte("version: 1\n")
	if err := os.WriteFile(pip, body, 0o644); err != nil {
		t.Fatal(err)
	}
	stP, err := os.Stat(pip)
	if err != nil {
		t.Fatal(err)
	}
	// A different inode with identical size, mode and mtime.
	other := filepath.Join(t.TempDir(), "other.yaml")
	if err := os.WriteFile(other, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(other, stP.ModTime(), stP.ModTime()); err != nil {
		t.Fatal(err)
	}
	stQ, err := os.Stat(other)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(stP, stQ) {
		t.Fatal("fixture: expected distinct inodes")
	}
	if stP.Size() != stQ.Size() || !stP.ModTime().Equal(stQ.ModTime()) || stP.Mode() != stQ.Mode() {
		t.Fatal("fixture: expected identical size/mode/mtime")
	}

	// Script: S1 sees the original inode, S2 sees the spoofed twin — every
	// attempt.
	seq := []os.FileInfo{stP, stQ, stP, stQ}
	calls := 0
	orig := adoptStat
	adoptStat = func(string) (os.FileInfo, error) {
		i := calls
		calls++
		if i >= len(seq) {
			i = len(seq) - 1
		}
		return seq[i], nil
	}
	t.Cleanup(func() { adoptStat = orig })

	_, err = m.AdoptInputs(pip, "")
	adoptStat = orig
	if err == nil {
		t.Fatal("adoption accepted an inode swap with cloned metadata")
	}
	if !strings.Contains(err.Error(), "one transaction") {
		t.Fatalf("error = %v, want joint-transaction refusal", err)
	}
	if _, serr := os.Stat(filepath.Join(m.BasePath(), ".kiwi-frozen", "pipeline.yaml")); serr == nil {
		t.Fatal("bytes were adopted despite the inode swap")
	}
}

// TestAdoptInputsTreatsLockAbsenceAsState pins the absence-state contract:
// a missing optional lock is an OBSERVED state of the joint transaction,
// not an error. A lock that APPEARS inside the window fails the attempt;
// the retry then coherently adopts the now-present pair. (The old
// fileExists-then-adopt design could observe "no lock" outside the window
// and silently ignore a lock created mid-transaction.)
func TestAdoptInputsTreatsLockAbsenceAsState(t *testing.T) {
	src := t.TempDir()
	m, err := NewManager(src)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Freeze(t.Context()); err != nil {
		t.Fatal(err)
	}
	extDir := t.TempDir()
	pip := filepath.Join(extDir, "pipeline.yaml")
	lock := filepath.Join(extDir, "lock.json")
	if err := os.WriteFile(pip, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// (a) Lock never exists: the pair (pipeline, absence) is certified.
	res, err := m.AdoptInputs(pip, lock)
	if err != nil {
		t.Fatalf("absent lock must be an observed state, not an error: %v", err)
	}
	if res.LockRoot != "" {
		t.Fatalf("LockRoot = %q, want \"\" for verified absence", res.LockRoot)
	}
	if res.PipelineDst == "" {
		t.Fatal("pipeline was not adopted alongside the verified absence")
	}
	if b, rerr := os.ReadFile(res.PipelineDst); rerr != nil || string(b) != "version: 1\n" {
		t.Fatalf("adopted pipeline = %q %v", b, rerr)
	}
	if _, serr := os.Stat(filepath.Join(m.BasePath(), ".kiwi-frozen", "lockroot", ".kiwi", "lock.json")); serr == nil {
		t.Fatal("absent lock must not produce a lockroot file")
	}

	// (b) The lock APPEARS inside the window (S1 absent, S2 present): the
	// attempt fails, the retry sees a present pair and adopts BOTH.
	if err := os.WriteFile(lock, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	stP2, err := os.Stat(pip)
	if err != nil {
		t.Fatal(err)
	}
	stL, err := os.Stat(lock)
	if err != nil {
		t.Fatal(err)
	}
	// Call order per attempt: S1(pip), S1(lock), S2(pip), S2(lock).
	seq := []func() (os.FileInfo, error){
		func() (os.FileInfo, error) { return scriptedStat{size: stP2.Size(), mtime: stP2.ModTime()}, nil },
		func() (os.FileInfo, error) { return nil, os.ErrNotExist }, // lock absent at S1
		func() (os.FileInfo, error) { return scriptedStat{size: stP2.Size(), mtime: stP2.ModTime()}, nil },
		func() (os.FileInfo, error) { return stL, nil }, // lock appeared at S2
		// Retry: lock present and stable both samples.
		func() (os.FileInfo, error) { return scriptedStat{size: stP2.Size(), mtime: stP2.ModTime()}, nil },
		func() (os.FileInfo, error) { return stL, nil },
		func() (os.FileInfo, error) { return scriptedStat{size: stP2.Size(), mtime: stP2.ModTime()}, nil },
		func() (os.FileInfo, error) { return stL, nil },
	}
	calls := 0
	orig := adoptStat
	adoptStat = func(string) (os.FileInfo, error) {
		i := calls
		calls++
		if i >= len(seq) {
			i = len(seq) - 1
		}
		return seq[i]()
	}
	t.Cleanup(func() { adoptStat = orig })

	res2, err := m.AdoptInputs(pip, lock)
	adoptStat = orig
	if err != nil {
		t.Fatalf("retry must adopt the coherent present pair: %v", err)
	}
	if res2.LockRoot == "" {
		t.Fatal("retry adopted the pair without the lock root")
	}
	if b, rerr := os.ReadFile(filepath.Join(res2.LockRoot, ".kiwi", "lock.json")); rerr != nil || string(b) != `{"version":1}` {
		t.Fatalf("retry-adapted lock = %q %v", b, rerr)
	}
	if calls < 8 {
		t.Fatalf("stat samples = %d, want the full appearance-retry bracket (8)", calls)
	}
}
