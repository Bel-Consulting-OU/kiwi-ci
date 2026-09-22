package server

// Durability tests for the create-if-absent cluster-key publication primitive
// (createFileCAS) and for the per-directory degraded tracking that makes a
// published-but-uncertified first key creation fail closed at /readiness.
//
// These are the R3-A/R3-B regressions: the pre-fix createFileCAS returned
// success without fsyncing the parent directory, so a first creation of
// lease.key / the OIDC ring / provenance key / cache-signing key / runner-CA
// object could be acknowledged while the directory entry was not crash-durable
// (a restart could then mint DIFFERENT trust material). Per-directory tracking
// additionally prevents a successful, unrelated data-dir write from clearing
// the uncertainty for a separate --cluster-key-dir.
//
// The tests intentionally use only long-standing APIs so the same file can be
// dropped into a pristine checkout to prove they FAIL before the fix.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

// assertNoCASScratch fails when a createFileCAS temp file ("<base>.cas-*")
// survived a failed publication.
func assertNoCASScratch(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".cas-") {
			t.Fatalf("createFileCAS scratch file survived: %s", e.Name())
		}
	}
}

// TestDurableCreateFileCASDirSyncFailureKeepsFileAndReuses is the R3-A
// regression for a first publication: when the parent-directory fsync fails
// AFTER the hard link published the file, LoadOrCreate must report the typed
// published-but-uncertain error and KEEP the file (never delete or regenerate
// it), and a restart must load that exact file rather than minting new trust
// material.
func TestDurableCreateFileCASDirSyncFailureKeepsFileAndReuses(t *testing.T) {
	dir := t.TempDir()
	store := &FSClusterKeyStore{Dir: dir}

	restore := failDirSync(t)
	_, err := store.LoadOrCreate(clusterKindLease)
	restore()
	// Pre-fix this was nil: createFileCAS never fsynced the directory, so the
	// injected directory-fsync failure was never observed.
	if err == nil {
		t.Fatal("first publication with a failing parent-directory fsync was acknowledged (no error)")
	}
	assertPublishedUncertain(t, err)

	path := filepath.Join(dir, "lease.key")
	onDisk, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("published key file was deleted after a directory-fsync failure: %v", rerr)
	}
	raw, derr := hex.DecodeString(strings.TrimSpace(string(onDisk)))
	if derr != nil || len(raw) != 32 {
		t.Fatalf("published lease.key is not a valid 32-byte key: %v, %d", derr, len(raw))
	}
	assertNoCASScratch(t, dir)

	// A restart (a fresh store over the same directory) REUSES the published
	// file: no regeneration, identical material.
	store2 := &FSClusterKeyStore{Dir: dir}
	again, err := store2.LoadOrCreate(clusterKindLease)
	if err != nil {
		t.Fatalf("restart LoadOrCreate: %v", err)
	}
	if !bytes.Equal(again, raw) {
		t.Fatalf("restart regenerated key material instead of reusing the published file:\n got %x\nwant %x", again, raw)
	}
}

// TestCreateFileCASPrePublishFailureLeavesNothing: a failure BEFORE the publish
// (here the temp-file fsync) is definitely not published — the typed error
// matches ErrNotPublished, the destination does not exist, and the scratch
// temp file is removed.
func TestDurableCreateFileCASPrePublishFailureLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	store := &FSClusterKeyStore{Dir: dir}

	restore := fsutil.SetHooks(fsutil.Hooks{FileSync: func(*os.File) error {
		return errors.New("injected file fsync failure")
	}})
	_, err := store.LoadOrCreate(clusterKindLease)
	restore()
	if err == nil || !errors.Is(err, fsutil.ErrNotPublished) {
		t.Fatalf("pre-publish failure = %v, want ErrNotPublished", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "lease.key")); !os.IsNotExist(serr) {
		t.Fatalf("pre-publish failure created lease.key: %v", serr)
	}
	assertNoCASScratch(t, dir)
}

// TestPerDirectoryUncertaintyClusterDirSurvivesUnrelatedDataDirSuccess is the
// R3-B regression: an uncertain --cluster-key-dir must NOT be healed by a
// successful write in the (unrelated) data dir. Pre-fix every security-file
// outcome fed one global marker, so the data-dir success cleared the cluster
// directory's uncertainty and /readiness returned 200 while the first key
// publication was still not certified durable.
func TestPerDirectoryUncertaintyClusterDirSurvivesUnrelatedDataDirSuccess(t *testing.T) {
	dataDir := t.TempDir()
	clusterDir := t.TempDir()
	s, err := NewPersistentWithCluster("t", "t", dataDir, &FSClusterKeyStore{Dir: clusterDir})
	if err != nil {
		t.Fatal(err)
	}
	// Make the lease key a genuine FIRST publication again.
	leasePath := filepath.Join(clusterDir, "lease.key")
	if err := os.Remove(leasePath); err != nil {
		t.Fatal(err)
	}

	restore := failDirSync(t)
	_, err = s.ClusterKeys.(*FSClusterKeyStore).LoadOrCreate(clusterKindLease)
	restore()
	if err == nil {
		t.Fatal("cluster-key first publication with a failing directory fsync was acknowledged")
	}
	assertPublishedUncertain(t, err)
	if _, serr := os.Stat(leasePath); serr != nil {
		t.Fatalf("published cluster key was deleted: %v", serr)
	}
	if !s.stateDegraded.Load() {
		t.Fatal("uncertified cluster-key publication did not arm degraded readiness")
	}

	// Readiness is 503 with the fixed body while the cluster directory is
	// uncertain (the directory name is in the logs, never on this probe).
	w := doJSON(t, s, http.MethodGet, "/readiness", "", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness after an uncertain cluster-key publication = %d, want 503: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Kiwi-State"); got != "degraded" {
		t.Fatalf("X-Kiwi-State = %q, want degraded", got)
	}
	if got := w.Body.String(); got != statePersistenceDegradedBody+"\n" {
		t.Fatalf("readiness body = %q, want the fixed %q", got, statePersistenceDegradedBody)
	}
	if strings.Contains(w.Body.String(), clusterDir) {
		t.Fatalf("readiness body leaked the cluster directory path: %q", w.Body.String())
	}

	// An unrelated SUCCESS in the data dir must not clear the cluster dir.
	s.mu.Lock()
	s.crl = map[string]string{"aaa": "runner-a"}
	s.mu.Unlock()
	if err := s.persistCRL(); err != nil {
		t.Fatalf("unrelated data-dir persist: %v", err)
	}
	if !s.stateDegraded.Load() {
		t.Fatal("unrelated data-dir success cleared the cluster-dir uncertainty")
	}
	if w := doJSON(t, s, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness after an unrelated data-dir success = %d, want 503", w.Code)
	}

	// A successful persist in the SAME cluster directory reconciles it.
	if err := s.ClusterKeys.(*FSClusterKeyStore).Store(clusterKindLease, bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatalf("same-directory reconcile: %v", err)
	}
	if s.stateDegraded.Load() {
		t.Fatal("same-directory success did not clear the cluster-dir uncertainty")
	}
	if w := doJSON(t, s, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusOK {
		t.Fatalf("readiness after same-directory reconcile = %d, want 200: %s", w.Code, w.Body.String())
	}
}
