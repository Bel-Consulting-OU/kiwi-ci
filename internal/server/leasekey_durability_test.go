package server

// Durability regressions for the nil-cluster ("legacy data-dir loader") path:
// loadLeaseKey must create the lease HMAC key through the SAME durable
// create-if-absent primitive the FS cluster-key store uses, instead of the old
// fixed-suffix scratch file + os.WriteFile + os.Rename sequence. The old
// sequence certified no temp uniqueness, no file fsync, no checked close and
// no parent-directory fsync, so a crash after a successful startup could leave
// a lease key whose publish was not durable; a later start then minted a
// DIFFERENT key while persisted running jobs still held leases derived from
// the previous one, breaking lease authentication.
//
// The suite pins: durable create + adopt on restart, an adopted pre-existing
// key (never overwritten), each durability seam failing closed, the
// published-but-uncertain contract (visible key retained, startup fails, a
// restart adopts it), concurrent creators converging on one key, and a lease
// issued before a restart still authenticating afterwards.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestNoTmpBasedLeaseKeyWriter is the grep assertion: the server source must
// not carry any remaining scratch-file lease-key writer. The historical
// writer used a fixed ".tmp" suffix, so a plain grep for that suffix is the
// regression guard.
func TestNoTmpBasedLeaseKeyWriter(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	if i := bytes.Index(src, []byte(".tmp")); i >= 0 {
		start := i - 40
		if start < 0 {
			start = 0
		}
		end := i + 40
		if end > len(src) {
			end = len(src)
		}
		t.Fatalf("server.go still references a scratch-file writer: %q", src[start:end])
	}
}

// readLeaseKeyRaw reads and decodes the persisted lease key under dir.
func readLeaseKeyRaw(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "lease.key"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("lease.key is not hex: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("lease.key size = %d, want 32", len(raw))
	}
	return raw
}

// TestNilClusterLeaseKeyDurableCreateAdoptRestart drives the supported
// NewPersistentWithCluster(..., nil) path: it must create a durable key, leave
// no scratch file behind, and adopt that exact key on a restart. A
// pre-existing valid key must be adopted, never overwritten.
func TestNilClusterLeaseKeyDurableCreateAdoptRestart(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewPersistentWithCluster("runner-tok", "", dir, nil)
	if err != nil {
		t.Fatalf("NewPersistentWithCluster(nil) = %v", err)
	}
	if s1.ClusterKeys != nil {
		t.Fatal("nil cluster store must stay nil on the legacy path")
	}
	if len(s1.leaseKey) != 32 {
		t.Fatalf("lease key size = %d, want 32", len(s1.leaseKey))
	}
	onDisk := readLeaseKeyRaw(t, dir)
	if !bytes.Equal(onDisk, s1.leaseKey) {
		t.Fatal("in-memory lease key does not match the durable key file")
	}
	assertNoCASScratch(t, dir)

	// A restart over the same data dir reuses the durable key.
	s2, err := NewPersistentWithCluster("runner-tok", "", dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s2.leaseKey, onDisk) {
		t.Fatal("restart did not adopt the durable lease key")
	}

	// A pre-existing valid key wins over freshly generated material.
	pre := bytes.Repeat([]byte{0xAB}, 32)
	if err := os.WriteFile(filepath.Join(dir, "lease.key"), []byte(hex.EncodeToString(pre)), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadLeaseKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pre) {
		t.Fatal("pre-existing valid lease key was overwritten by freshly generated material")
	}
	if !bytes.Equal(readLeaseKeyRaw(t, dir), pre) {
		t.Fatal("pre-existing valid lease key file was overwritten")
	}
}

// TestNilClusterLeaseKeyCreationSeamsFailClosed injects each pre-publish
// durability step of lease-key creation: a fault must be surfaced and must
// leave no key file and no scratch file. This is the write / file-fsync /
// checked-close half of the seam matrix.
func TestNilClusterLeaseKeyCreationSeamsFailClosed(t *testing.T) {
	cases := []struct {
		name  string
		hooks fsutil.Hooks
	}{
		{"write", fsutil.Hooks{Write: func(*os.File, []byte) (int, error) {
			return 0, errors.New("injected write failure")
		}}},
		{"file-sync", fsutil.Hooks{FileSync: func(*os.File) error {
			return errors.New("injected file fsync failure")
		}}},
		{"close", fsutil.Hooks{FileClose: func(f *os.File) error {
			_ = fsutil.RealFileClose(f)
			return errors.New("injected close failure")
		}}},
		{"chmod", fsutil.Hooks{Chmod: func(string, os.FileMode) error {
			return errors.New("injected chmod failure")
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			restore := fsutil.SetHooks(tc.hooks)
			_, err := loadLeaseKey(dir)
			restore()
			if err == nil {
				t.Fatalf("%s fault was acknowledged", tc.name)
			}
			if !errors.Is(err, fsutil.ErrNotPublished) {
				t.Fatalf("%s error = %v, want ErrNotPublished", tc.name, err)
			}
			if _, serr := os.Stat(filepath.Join(dir, "lease.key")); !os.IsNotExist(serr) {
				t.Fatalf("%s fault created lease.key: %v", tc.name, serr)
			}
			assertNoCASScratch(t, dir)
		})
	}
}

// TestNilClusterLeaseKeyPublishCollisionFailsClosed covers the publish
// boundary itself. CreateFileCAS publishes with a hard link on unix, so the
// fsutil Rename hook is not consulted; a dangling symlink at the key path
// makes the initial read resolve to not-exist (it follows the link) while the
// hard-link publish collides with the existing directory entry (EEXIST) and
// adoption then finds nothing to read. Startup must fail closed instead of
// silently minting a key that was not published.
func TestNilClusterLeaseKeyPublishCollisionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "missing-target"), filepath.Join(dir, "lease.key")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := loadLeaseKey(dir); err == nil {
		t.Fatal("publish collision with no adoptable key was acknowledged")
	}
	assertNoCASScratch(t, dir)
}

// TestNilClusterLeaseKeyDirSyncFailureKeepsFileAndFailsClosed covers the
// post-publish seam: a failed parent-directory fsync must report the typed
// published-but-uncertain error, KEEP the visible key, and fail startup
// closed. A healthy restart then adopts that exact key, so a crash can never
// let a different key be minted while persisted leases still reference the
// published one.
func TestNilClusterLeaseKeyDirSyncFailureKeepsFileAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	restore := failDirSync(t)
	_, err := loadLeaseKey(dir)
	restore()
	assertPublishedUncertain(t, err)

	raw := readLeaseKeyRaw(t, dir)
	assertNoCASScratch(t, dir)

	// The restart reads the visible key back; it must not regenerate material.
	again, lerr := loadLeaseKey(dir)
	if lerr != nil {
		t.Fatalf("restart loadLeaseKey = %v", lerr)
	}
	if !bytes.Equal(again, raw) {
		t.Fatalf("restart regenerated the lease key instead of adopting the published one:\n got %x\nwant %x", again, raw)
	}
}

// TestNilClusterLeaseKeyStartupFailsClosedOnUncertainPublish proves the
// failure propagates through the real nil-cluster constructor (startup fails
// closed) while the visible key is retained. The dir-scoped hook lets the
// unrelated staging-directory fsyncs succeed.
func TestNilClusterLeaseKeyStartupFailsClosedOnUncertainPublish(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewPersistentWithCluster("t", "t", dir, nil); err != nil {
		t.Fatal(err)
	}
	// Make the lease key a genuine first publication again.
	if err := os.Remove(filepath.Join(dir, "lease.key")); err != nil {
		t.Fatal(err)
	}
	restore := fsutil.SetHooks(fsutil.Hooks{DirSync: func(d string) error {
		if d == dir {
			return errors.New("injected directory fsync failure")
		}
		return fsutil.RealSyncDir(d)
	}})
	_, err := NewPersistentWithCluster("t", "t", dir, nil)
	restore()
	assertPublishedUncertain(t, err)
	// It must be the LEASE-key publish that failed, not a later data-dir
	// snapshot write: the nil-cluster constructor must reach (and fail on) the
	// lease key before anything else in the data dir is published.
	var awe *fsutil.AtomicWriteError
	if !errors.As(err, &awe) || filepath.Base(awe.Path) != "lease.key" {
		t.Fatalf("startup failed on %v (failed path %q), want the lease.key publish", err, func() string {
			if awe != nil {
				return awe.Path
			}
			return ""
		}())
	}

	raw, rerr := os.ReadFile(filepath.Join(dir, "lease.key"))
	if rerr != nil {
		t.Fatalf("startup failure deleted the visible lease key: %v", rerr)
	}
	decoded, derr := hex.DecodeString(strings.TrimSpace(string(raw)))
	if derr != nil || len(decoded) != 32 {
		t.Fatalf("published lease key is not a valid 32-byte key: %v, %d", derr, len(decoded))
	}
	assertNoCASScratch(t, dir)

	// A healthy restart adopts the published key.
	s2, err := NewPersistentWithCluster("t", "t", dir, nil)
	if err != nil {
		t.Fatalf("restart after uncertain publish = %v", err)
	}
	if !bytes.Equal(s2.leaseKey, decoded) {
		t.Fatal("restart regenerated the lease key after an uncertain publish")
	}
}

// TestNilClusterLeaseKeyConcurrentCreatorsAgree drives the create-if-absent
// adoption branch: concurrent first-time callers must all converge on the one
// key the hard-link publish made durable, never on a per-caller generation.
func TestNilClusterLeaseKeyConcurrentCreatorsAgree(t *testing.T) {
	dir := t.TempDir()
	const n = 16
	results := make(chan []byte, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := loadLeaseKey(dir)
			if err != nil {
				t.Errorf("loadLeaseKey: %v", err)
				return
			}
			results <- b
		}()
	}
	wg.Wait()
	close(results)
	var first []byte
	for b := range results {
		if first == nil {
			first = b
			continue
		}
		if !bytes.Equal(first, b) {
			t.Fatalf("concurrent loadLeaseKey callers disagreed:\n got %x\nwant %x", b, first)
		}
	}
	if len(first) != 32 {
		t.Fatalf("lease key size = %d, want 32", len(first))
	}
	if !bytes.Equal(first, readLeaseKeyRaw(t, dir)) {
		t.Fatal("converged key does not match the durable lease key file")
	}
	assertNoCASScratch(t, dir)
}

// TestNilClusterLeaseKeyRestartExistingLeasesSameMaterial is the defect
// regression: a lease digest persisted for a running job before a restart must
// still authenticate after the restart, which holds only if the restarted
// server reloads the SAME lease key material.
func TestNilClusterLeaseKeyRestartExistingLeasesSameMaterial(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewPersistentWithCluster("t", "t", dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	const rawToken = "existing-lease-token"
	exp := time.Now().UTC().Add(time.Hour)
	job := model.Job{
		ID: "job-1", RunID: "run-1", Key: "build",
		Status: model.StatusRunning, Trusted: true,
		LeaseRunnerID:   "runner-1",
		LeaseGeneration: 1,
		LeaseExpiresAt:  &exp,
		LeaseTokenHash:  hashLeaseToken(s1.leaseKey, rawToken),
	}
	if !s1.validActiveLease(job, "runner-1", rawToken, 1, time.Now().UTC()) {
		t.Fatal("lease did not authenticate before restart")
	}

	s2, err := NewPersistentWithCluster("t", "t", dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hashLeaseToken(s2.leaseKey, rawToken), job.LeaseTokenHash) {
		t.Fatal("restart changed the lease key material; persisted leases no longer authenticate")
	}
	if !s2.validActiveLease(job, "runner-1", rawToken, 1, time.Now().UTC()) {
		t.Fatal("persisted lease stopped authenticating after restart")
	}
}
