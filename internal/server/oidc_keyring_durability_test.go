package server

// Durability regressions for the legacy (nil-cluster) file-mode OIDC ring:
// persistOIDCKeyRing must write through the SAME hardened primitive the FS
// cluster-key store uses (fsutil.AtomicWriteFile), not the historical raw
// fixed-suffix "<ring>.tmp" + os.WriteFile + os.Rename sequence, whose crash
// outcome could leave the newly active ring non-durable. On-disk
// compatibility is pinned too: a ring written by the pre-change writer still
// loads, and the first write through the new primitive keeps the key material
// (a durability upgrade, never a rotation).

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

// writePreChangeOIDCRing recreates the exact pre-change file-mode writer:
// marshal the ring, os.WriteFile to a fixed "<ring>.tmp" scratch file, then
// os.Rename over the ring. It returns the ring path.
func writePreChangeOIDCRing(t *testing.T, dir string, s *oidcSigner) string {
	t.Helper()
	path := filepath.Join(dir, oidcKeyRingFile)
	rf := oidcKeyRingJSON{
		Active: oidcActiveKeyFile{
			KID:       s.KID,
			Pub:       base64.RawStdEncoding.EncodeToString(s.Public),
			Priv:      base64.RawStdEncoding.EncodeToString(s.Private),
			NotBefore: s.NotBefore.UTC().Format(time.RFC3339Nano),
		},
	}
	b, err := json.MarshalIndent(rf, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLegacyOIDCRingPreChangeWriteLoadsAndUpgradesWithoutRotation pins key
// material compatibility: a ring written by the pre-change raw writer loads
// unchanged, and the first write through the shared primitive keeps the same
// private key (a durability upgrade, never a rotation).
func TestLegacyOIDCRingPreChangeWriteLoadsAndUpgradesWithoutRotation(t *testing.T) {
	dir := t.TempDir()
	old := newOIDCSigner()
	path := writePreChangeOIDCRing(t, dir, old)
	oldPriv := append([]byte(nil), old.Private...)

	loaded, err := loadOIDCSigner(dir)
	if err != nil {
		t.Fatalf("pre-change ring failed to load: %v", err)
	}
	if loaded.KID != old.KID {
		t.Fatalf("pre-change ring loaded under a different kid: %q vs %q", loaded.KID, old.KID)
	}
	if !bytes.Equal(loaded.Private, oldPriv) {
		t.Fatal("pre-change ring loaded different key material")
	}
	if loaded.ringPath != path {
		t.Fatalf("loaded signer ringPath = %q, want %q", loaded.ringPath, path)
	}

	// The next persist upgrades the on-disk write path (shared primitive)
	// without touching the key material.
	if err := persistOIDCKeyRing(loaded); err != nil {
		t.Fatalf("upgrade persist: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("ring mode = %v, want 0600", info.Mode().Perm())
	}
	reloaded, err := oidcSignerFromRing(mustReadFile(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.KID != old.KID || !bytes.Equal(reloaded.Private, oldPriv) {
		t.Fatal("upgrade write rotated or changed key material")
	}
	// A restart adopts the same material from disk.
	restarted, err := loadOIDCSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.KID != old.KID || !bytes.Equal(restarted.Private, oldPriv) {
		t.Fatal("restart changed key material")
	}
}

// TestLegacyOIDCRingWriteUsesAtomicPrimitive proves the ring write rides
// fsutil.AtomicWriteFile in BOTH sinks: the rename source is the primitive's
// unique "."+oidcKeyRingFile+".tmp-*" temp file (never the historical fixed
// "<ring>.tmp"), the destination mode is 0600, and every pre-rename phase
// failure is a typed ErrNotPublished error that leaves the previous ring
// bit-for-bit intact with no scratch file behind. A post-rename failure
// (directory fsync) is published-uncertain.
func TestLegacyOIDCRingWriteUsesAtomicPrimitive(t *testing.T) {
	observeRename := func(t *testing.T, persist func() error) (from, to string) {
		t.Helper()
		var renamedFrom, renamedTo string
		restore := fsutil.SetHooks(fsutil.Hooks{Rename: func(oldpath, newpath string) error {
			renamedFrom, renamedTo = oldpath, newpath
			return fsutil.RealRename(oldpath, newpath)
		}})
		err := persist()
		restore()
		if err != nil {
			t.Fatalf("persist: %v", err)
		}
		return renamedFrom, renamedTo
	}
	assertUniqueTempRename := func(t *testing.T, from, to, path string) {
		t.Helper()
		if to != path {
			t.Fatalf("rename destination = %q, want the ring path %q", to, path)
		}
		if base := filepath.Base(from); !strings.HasPrefix(base, "."+oidcKeyRingFile+".tmp-") {
			t.Fatalf("rename source %q is not the fsutil unique temp pattern", base)
		}
	}

	t.Run("file mode", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, oidcKeyRingFile)
		s := newOIDCSigner()
		s.ringPath = path
		from, to := observeRename(t, func() error { return persistOIDCKeyRing(s) })
		assertUniqueTempRename(t, from, to, path)
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("ring mode = %v, %v; want 0600", info.Mode().Perm(), err)
		}
		if _, err := oidcSignerFromRing(mustReadFile(t, path)); err != nil {
			t.Fatalf("ring written through the primitive does not parse: %v", err)
		}
		if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
			t.Fatalf("fixed-suffix scratch file exists: %v", err)
		}
		assertNoAtomicScratch(t, dir)
	})

	t.Run("cluster store", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, oidcKeyRingFile)
		store := &FSClusterKeyStore{Dir: dir}
		s := newOIDCSigner()
		s.cluster = store
		from, to := observeRename(t, func() error { return persistOIDCKeyRing(s) })
		assertUniqueTempRename(t, from, to, path)
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("cluster ring mode = %v, %v; want 0600", info.Mode().Perm(), err)
		}
		if _, err := oidcSignerFromRing(mustReadFile(t, path)); err != nil {
			t.Fatalf("cluster ring written through the primitive does not parse: %v", err)
		}
		assertNoAtomicScratch(t, dir)
	})

	t.Run("pre-rename failures keep previous ring", func(t *testing.T) {
		faults := []struct {
			name  string
			phase fsutil.Phase
			hooks fsutil.Hooks
		}{
			{"write", fsutil.PhaseWrite, fsutil.Hooks{Write: func(*os.File, []byte) (int, error) {
				return 0, errors.New("injected write failure")
			}}},
			{"chmod", fsutil.PhaseChmod, fsutil.Hooks{Chmod: func(string, os.FileMode) error {
				return errors.New("injected chmod failure")
			}}},
			{"file-sync", fsutil.PhaseFileSync, fsutil.Hooks{FileSync: func(*os.File) error {
				return errors.New("injected file fsync failure")
			}}},
			{"close", fsutil.PhaseClose, fsutil.Hooks{FileClose: func(f *os.File) error {
				_ = fsutil.RealFileClose(f)
				return errors.New("injected close failure")
			}}},
			{"rename", fsutil.PhaseRename, fsutil.Hooks{Rename: func(string, string) error {
				return errors.New("injected rename failure")
			}}},
		}
		for _, fault := range faults {
			t.Run(fault.name, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, oidcKeyRingFile)
				seed := newOIDCSigner()
				seed.ringPath = path
				if err := persistOIDCKeyRing(seed); err != nil {
					t.Fatal(err)
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}

				next := newOIDCSigner()
				next.ringPath = path
				restore := fsutil.SetHooks(fault.hooks)
				err = persistOIDCKeyRing(next)
				restore()
				if err == nil {
					t.Fatalf("failing %s was acknowledged", fault.name)
				}
				if !errors.Is(err, fsutil.ErrNotPublished) || fsutil.Renamed(err) {
					t.Fatalf("failing %s error = %v, want ErrNotPublished", fault.name, err)
				}
				if phase, ok := fsutil.PhaseOf(err); !ok || phase != fault.phase {
					t.Fatalf("failing %s phase = %q (ok=%v), want %q", fault.name, phase, ok, fault.phase)
				}
				after, rerr := os.ReadFile(path)
				if rerr != nil {
					t.Fatal(rerr)
				}
				if !bytes.Equal(after, before) {
					t.Fatalf("failing %s changed the previous ring", fault.name)
				}
				if _, serr := os.Stat(path + ".tmp"); !os.IsNotExist(serr) {
					t.Fatalf("failing %s left the fixed-suffix scratch file", fault.name)
				}
				assertNoAtomicScratch(t, dir)
			})
		}
	})

	t.Run("dir-sync failure is published-uncertain", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, oidcKeyRingFile)
		seed := newOIDCSigner()
		seed.ringPath = path
		if err := persistOIDCKeyRing(seed); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		next := newOIDCSigner()
		next.ringPath = path
		restore := fsutil.SetHooks(fsutil.Hooks{DirSync: func(string) error {
			return errors.New("injected directory fsync failure")
		}})
		err = persistOIDCKeyRing(next)
		restore()
		if err == nil || !fsutil.Renamed(err) {
			t.Fatalf("dir-sync failure = %v, want published-uncertain", err)
		}
		if phase, _ := fsutil.PhaseOf(err); phase != fsutil.PhaseDirSync {
			t.Fatalf("dir-sync phase = %q, want %q", phase, fsutil.PhaseDirSync)
		}
		after, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if bytes.Equal(after, before) {
			t.Fatal("published-but-uncertain ring write did not update the visible file")
		}
		published, perr := oidcSignerFromRing(after)
		if perr != nil || published.KID != next.KID {
			t.Fatalf("visible ring = %+v, %v; want the new kid %q", published, perr, next.KID)
		}
		// The signer's recorded identity converges on the published file.
		info, serr := os.Stat(path)
		if serr != nil {
			t.Fatal(serr)
		}
		if !next.ringMod.Equal(info.ModTime()) || next.ringSize != info.Size() {
			t.Fatalf("published ring identity = (%v, %d), want (%v, %d)", next.ringMod, next.ringSize, info.ModTime(), info.Size())
		}
		if _, serr := os.Stat(path + ".tmp"); !os.IsNotExist(serr) {
			t.Fatalf("published-but-uncertain write left the fixed-suffix scratch file: %v", serr)
		}
		assertNoAtomicScratch(t, dir)
	})
}

// TestLegacyOIDCRingDirSyncFailureRetainsRingAndDegrades drives rotation over
// the legacy file-mode sink: a post-rename (directory fsync) failure must
// retain the new ring in memory, record the published file's identity, and
// arm the per-directory degraded readiness marker; a later successful
// rotation clears it.
func TestLegacyOIDCRingDirSyncFailureRetainsRingAndDegrades(t *testing.T) {
	dir := t.TempDir()
	s := New("t")
	initial := newOIDCSigner()
	initial.ringPath = filepath.Join(dir, oidcKeyRingFile)
	if err := persistOIDCKeyRing(initial); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.oidc = initial
	s.mu.Unlock()
	oldKID := initial.KID

	restore := fsutil.SetHooks(fsutil.Hooks{DirSync: func(string) error {
		return errors.New("injected directory fsync failure")
	}})
	s.mu.Lock()
	s.rotateOIDCKeyLocked(time.Now().UTC())
	s.mu.Unlock()
	restore()

	s.mu.Lock()
	rotated := s.oidc
	s.mu.Unlock()
	if rotated == nil || rotated == initial {
		t.Fatal("published-but-uncertain legacy rotation must install the new ring")
	}
	if rotated.KID == oldKID {
		t.Fatal("published-but-uncertain legacy rotation kept the old active key")
	}
	if len(rotated.Previous) != 1 || rotated.Previous[0].KID != oldKID {
		t.Fatalf("retired ring = %+v, want the previous active key %q", rotated.Previous, oldKID)
	}
	if !s.stateDegraded.Load() {
		t.Fatal("published-but-uncertain legacy rotation did not arm degraded readiness")
	}
	published, err := oidcSignerFromRing(mustReadFile(t, rotated.ringPath))
	if err != nil || published.KID != rotated.KID {
		t.Fatalf("published legacy ring = %+v, %v; want kid %q", published, err, rotated.KID)
	}
	if _, serr := os.Stat(rotated.ringPath + ".tmp"); !os.IsNotExist(serr) {
		t.Fatalf("legacy rotation left a fixed-suffix scratch file: %v", serr)
	}

	// A later successful rotation persists the next ring and reconciles the
	// same-directory uncertainty.
	s.mu.Lock()
	s.rotateOIDCKeyLocked(time.Now().UTC())
	s.mu.Unlock()
	if s.stateDegraded.Load() {
		t.Fatal("successful legacy rotation did not clear the degraded marker")
	}
	assertNoAtomicScratch(t, dir)
}

// TestNoRawOIDCRingWriter is the grep assertion that the OIDC ring's
// file-mode persistence has exactly one durability implementation: oidc.go
// must not carry a raw os.WriteFile/os.Rename writer and must call the
// shared fsutil.AtomicWriteFile primitive.
func TestNoRawOIDCRingWriter(t *testing.T) {
	src, err := os.ReadFile("oidc.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"os.WriteFile(", "os.Rename("} {
		if bytes.Contains(src, []byte(needle)) {
			t.Fatalf("oidc.go still carries a raw writer (%s)", needle)
		}
	}
	if !bytes.Contains(src, []byte("fsutil.AtomicWriteFile(")) {
		t.Fatal("persistOIDCKeyRing does not call the shared fsutil.AtomicWriteFile primitive")
	}
}
