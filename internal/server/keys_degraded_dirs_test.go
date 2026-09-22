package server

// Tests for the per-directory reporting surface of the degraded state: the
// server names the uncertain directories (for the structured log / operator
// diagnostics) while /readiness keeps the fixed body, and OIDC rotation
// against a filesystem cluster store attributes its uncertainty to the
// cluster-key directory rather than the data directory.

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

// TestUncertainPersistDirsReportsClusterKeyDir: after an uncertified
// first-publication in the cluster-key directory, the server reports exactly
// that directory; an unrelated data-dir success leaves it; a same-directory
// success removes it.
func TestUncertainPersistDirsReportsClusterKeyDir(t *testing.T) {
	dataDir := t.TempDir()
	clusterDir := t.TempDir()
	s, err := NewPersistentWithCluster("t", "t", dataDir, &FSClusterKeyStore{Dir: clusterDir})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.uncertainPersistDirs(); got != nil {
		t.Fatalf("fresh server reports uncertain dirs %v, want none", got)
	}

	// Make the cache-signing key a genuine first publication again.
	if err := os.Remove(filepath.Join(clusterDir, cacheSigningKeyFile)); err != nil {
		t.Fatal(err)
	}
	restore := failDirSync(t)
	_, cerr := s.ClusterKeys.(*FSClusterKeyStore).LoadOrCreate(clusterKindCacheSigning)
	restore()
	assertPublishedUncertain(t, cerr)
	if got, want := s.uncertainPersistDirs(), []string{clusterDir}; !reflect.DeepEqual(got, want) {
		t.Fatalf("uncertain dirs = %v, want %v", got, want)
	}

	// Unrelated data-dir success does not remove it.
	if err := s.persistDrainFlagLocked(); err != nil {
		t.Fatalf("data-dir persist: %v", err)
	}
	if got, want := s.uncertainPersistDirs(), []string{clusterDir}; !reflect.DeepEqual(got, want) {
		t.Fatalf("uncertain dirs after unrelated success = %v, want %v", got, want)
	}

	// Same-directory success removes it.
	key, gerr := createClusterKey(clusterKindCacheSigning)
	if gerr != nil {
		t.Fatal(gerr)
	}
	if err := s.ClusterKeys.(*FSClusterKeyStore).Store(clusterKindCacheSigning, key); err != nil {
		t.Fatalf("same-directory persist: %v", err)
	}
	if got := s.uncertainPersistDirs(); got != nil {
		t.Fatalf("uncertain dirs after same-directory success = %v, want none", got)
	}
}

// TestRotateOIDCUncertaintyAttributedToClusterDir: an OIDC rotation that
// publishes the ring through a filesystem cluster store but fails the
// directory fsync must arm the CLUSTER directory, not the data directory, and
// reconcile only on a successful rotation in that same directory.
func TestRotateOIDCUncertaintyAttributedToClusterDir(t *testing.T) {
	dataDir := t.TempDir()
	clusterDir := t.TempDir()
	s, err := NewPersistentWithCluster("t", "t", dataDir, &FSClusterKeyStore{Dir: clusterDir})
	if err != nil {
		t.Fatal(err)
	}

	restore := failDirSync(t)
	s.mu.Lock()
	s.rotateOIDCKeyLocked(time.Now().UTC())
	s.mu.Unlock()
	restore()

	if got, want := s.uncertainPersistDirs(), []string{clusterDir}; !reflect.DeepEqual(got, want) {
		t.Fatalf("OIDC rotation uncertainty = %v, want %v", got, want)
	}
	if w := doJSON(t, s, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness = %d, want 503", w.Code)
	}

	// A second, successful rotation in the same directory reconciles it.
	s.mu.Lock()
	s.rotateOIDCKeyLocked(time.Now().UTC())
	s.mu.Unlock()
	if got := s.uncertainPersistDirs(); got != nil {
		t.Fatalf("uncertain dirs after successful rotation = %v, want none", got)
	}
	if s.stateDegraded.Load() {
		t.Fatal("successful rotation did not clear degraded readiness")
	}
}

// TestNoteFilePersistResultPreRenameLeavesUncertaintyEmpty: a pre-rename
// failure must not arm any directory, matching the rollback contract, and a
// typed error's Path is used when the caller passes no path.
func TestKeyFilePersistPreRenameLeavesUncertaintyEmpty(t *testing.T) {
	s := New("t")
	s.noteFilePersistResult("/tmp/whatever/state.json", &fsutil.AtomicWriteError{
		Path:  "/tmp/whatever/state.json",
		Phase: fsutil.PhaseFileSync,
		Err:   errors.New("injected pre-rename failure"),
	})
	if got := s.uncertainPersistDirs(); got != nil {
		t.Fatalf("pre-rename failure armed dirs %v, want none", got)
	}
	if s.stateDegraded.Load() {
		t.Fatal("pre-rename failure degraded readiness")
	}

	// Path-less caller: the directory comes from the typed error.
	s.noteFilePersistResult("", &fsutil.AtomicWriteError{
		Path:    "/tmp/whatever/other.json",
		Phase:   fsutil.PhaseDirSync,
		Renamed: true,
		Err:     errors.New("injected directory fsync failure"),
	})
	if got, want := s.uncertainPersistDirs(), []string{"/tmp/whatever"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("uncertain dirs from typed error = %v, want %v", got, want)
	}
	s.noteFilePersistResult("/tmp/whatever/other.json", nil)
	if got := s.uncertainPersistDirs(); got != nil {
		t.Fatalf("success did not clear the typed-error dir: %v", got)
	}
}
