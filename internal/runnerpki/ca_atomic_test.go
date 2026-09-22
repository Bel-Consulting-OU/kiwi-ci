package runnerpki

// Crash-durability tests for the runner CA: LoadOrCreateCA publishes ca.crt
// (0644) and ca.key (0600) through the shared fsutil durable primitive. Each
// durability step (file fsync, checked close, rename, parent-directory fsync)
// is failed in turn; the CA write must never be acknowledged and, for every
// pre-rename failure, the previous bytes on disk must be intact with no
// scratch files left behind.
//
// The documented asymmetry is the parent-directory fsync: it runs after the
// rename, so its failure surfaces as an error (nothing is acknowledged) even
// though the new certificate is already visible. The private key, written
// second, is then never reached.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

var errInjectedDurability = errors.New("injected durability failure")

// assertNoCAScratch fails on any leftover durable-write scratch entry (the
// "."+base+".tmp-*" CreateTemp pattern) in dir.
func assertNoCAScratch(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("durable-write scratch entry survived: %s", e.Name())
		}
	}
}

// TestRunnerCAAtomicFilePermissions pins the published modes: the certificate
// is world-readable (0644) and the private key is owner-only (0600).
func TestRunnerCAAtomicFilePermissions(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateCA(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, caCertFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("ca.crt mode = %o, want 644", fi.Mode().Perm())
	}
	fi, err = os.Stat(filepath.Join(dir, caKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("ca.key mode = %o, want 600", fi.Mode().Perm())
	}
}

// TestRunnerCAAtomicDurabilitySeams proves a failed durability step is
// surfaced as an error and never acknowledged. Pre-rename failures publish
// nothing; a failed parent-directory fsync leaves the renamed certificate
// visible but still returns an error before the private key is written.
func TestRunnerCAAtomicDurabilitySeams(t *testing.T) {
	faults := []struct {
		name      string
		preRename bool
		hooks     fsutil.Hooks
	}{
		{"file sync", true, fsutil.Hooks{FileSync: func(*os.File) error { return errInjectedDurability }}},
		{"close", true, fsutil.Hooks{FileClose: func(f *os.File) error {
			_ = fsutil.RealFileClose(f)
			return errInjectedDurability
		}}},
		{"rename", true, fsutil.Hooks{Rename: func(string, string) error { return errInjectedDurability }}},
		{"dir sync", false, fsutil.Hooks{DirSync: func(string) error { return errInjectedDurability }}},
	}
	for _, fault := range faults {
		t.Run(fault.name, func(t *testing.T) {
			dir := t.TempDir()
			restore := fsutil.SetHooks(fault.hooks)
			_, err := LoadOrCreateCA(dir)
			restore()
			if err == nil {
				t.Fatalf("a failed %s must not acknowledge the CA write", fault.name)
			}
			assertNoCAScratch(t, dir)
			_, certErr := os.Stat(filepath.Join(dir, caCertFile))
			_, keyErr := os.Stat(filepath.Join(dir, caKeyFile))
			if fault.preRename {
				if certErr == nil || keyErr == nil {
					t.Fatalf("pre-rename %s failure published material: cert=%v key=%v", fault.name, certErr, keyErr)
				}
				return
			}
			if certErr != nil {
				t.Fatalf("dir-sync failure should leave the renamed ca.crt visible: %v", certErr)
			}
			if keyErr == nil {
				t.Fatal("dir-sync failure must return before the ca.key write")
			}
		})
	}
}

// TestRunnerCAAtomicPreservesPreviousCertOnPreRenameFailure seeds a directory
// with a certificate but no key (a half-restored CA), forcing the create path
// to rewrite the certificate. A pre-rename failure must leave the previous
// certificate bytes untouched and publish no key.
func TestRunnerCAAtomicPreservesPreviousCertOnPreRenameFailure(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateCA(dir); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, caCertFile)
	before, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, caKeyFile)); err != nil {
		t.Fatal(err)
	}
	faults := []struct {
		name  string
		hooks fsutil.Hooks
	}{
		{"file sync", fsutil.Hooks{FileSync: func(*os.File) error { return errInjectedDurability }}},
		{"close", fsutil.Hooks{FileClose: func(f *os.File) error {
			_ = fsutil.RealFileClose(f)
			return errInjectedDurability
		}}},
		{"rename", fsutil.Hooks{Rename: func(string, string) error { return errInjectedDurability }}},
	}
	for _, fault := range faults {
		t.Run(fault.name, func(t *testing.T) {
			restore := fsutil.SetHooks(fault.hooks)
			_, err := LoadOrCreateCA(dir)
			restore()
			if err == nil {
				t.Fatalf("a failed %s must not acknowledge the CA write", fault.name)
			}
			after, rerr := os.ReadFile(certPath)
			if rerr != nil {
				t.Fatal(rerr)
			}
			if !bytes.Equal(after, before) {
				t.Fatalf("previous ca.crt changed after a %s failure", fault.name)
			}
			if _, serr := os.Stat(filepath.Join(dir, caKeyFile)); serr == nil {
				t.Fatal("failed pre-rename write published ca.key")
			}
			assertNoCAScratch(t, dir)
		})
	}
}

// TestRunnerCAAtomicKeyWriteNotAcknowledged fails the SECOND durable write
// (the private key, after a successful certificate write): the error must
// surface, the partial publish must not be reported as a usable CA, and no
// scratch file may survive.
func TestRunnerCAAtomicKeyWriteNotAcknowledged(t *testing.T) {
	dir := t.TempDir()
	writes := 0
	restore := fsutil.SetHooks(fsutil.Hooks{Write: func(f *os.File, b []byte) (int, error) {
		writes++
		if writes == 2 {
			return 0, errInjectedDurability
		}
		return f.Write(b)
	}})
	_, err := LoadOrCreateCA(dir)
	restore()
	if err == nil {
		t.Fatal("a failed private-key write must not be acknowledged")
	}
	if writes != 2 {
		t.Fatalf("durable write attempts = %d, want 2 (certificate then key)", writes)
	}
	if _, serr := os.Stat(filepath.Join(dir, caKeyFile)); serr == nil {
		t.Fatal("failed private-key write published ca.key")
	}
	assertNoCAScratch(t, dir)
}
