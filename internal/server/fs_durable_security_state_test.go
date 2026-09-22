package server

// Crash-durability tests for the FS-mode security state that rides the
// fsutil durable primitive: the runner CRL carried by the runner-disable
// snapshot and the legacy runner-crl.json mirror, the single-use enrollment
// grants, and the web-session key path. Each durability step (file fsync,
// checked close, rename, parent-directory fsync) is failed in turn; the
// mutation must not be acknowledged and, for every pre-rename failure, the
// PREVIOUS on-disk bytes must be intact with no scratch files left behind.
//
// The one documented asymmetry is the parent-directory fsync: it runs after
// the rename, so its failure surfaces as an error (nothing is acknowledged,
// in-memory state rolls back) but the new bytes are already visible. The
// tests assert the unacknowledged/rollback contract there instead of the
// byte-preservation one, matching storage's
// TestAtomicWriteFileParentDirErrorIsReturned.

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// fsDurableFault is one injected durability-step failure for the FS-mode
// security-state writers.
type fsDurableFault struct {
	name string
	// preRename is true while the failure happens before the rename, so the
	// previous durable file must be bit-for-bit intact afterwards.
	preRename bool
	hooks     fsutil.Hooks
}

func fsDurableFaults() []fsDurableFault {
	return []fsDurableFault{
		{"file sync", true, fsutil.Hooks{FileSync: func(*os.File) error {
			return errors.New("injected file fsync failure")
		}}},
		{"close", true, fsutil.Hooks{FileClose: func(f *os.File) error {
			_ = fsutil.RealFileClose(f)
			return errors.New("injected close failure")
		}}},
		{"rename", true, fsutil.Hooks{Rename: func(string, string) error {
			return errors.New("injected rename failure")
		}}},
		{"dir sync", false, fsutil.Hooks{DirSync: func(string) error {
			return errors.New("injected directory fsync failure")
		}}},
	}
}

// assertNoAtomicScratch walks dir and fails on any leftover durable-write
// scratch entry (the "."+base+".tmp-*" CreateTemp pattern).
func assertNoAtomicScratch(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(d.Name(), ".tmp-") {
			t.Fatalf("durable-write scratch entry survived: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestCRLPersistFailuresBlockDisableAcknowledgment is the FS-mode CRL
// acknowledgement proof: runnerDisable persists the CRL as part of the
// checked state snapshot. When a durability step fails the handler answers an
// opaque 503, the runner/CRL/lease mutations roll back, and (for pre-rename
// failures) the previous state.json bytes are untouched.
func TestCRLPersistFailuresBlockDisableAcknowledgment(t *testing.T) {
	const serial = "0c0ffee"
	for _, fault := range fsDurableFaults() {
		t.Run(fault.name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := NewPersistent("runner-tok", "admin-tok", dir)
			if err != nil {
				t.Fatal(err)
			}
			s.mu.Lock()
			s.runners["runner-a"] = model.Runner{ID: "runner-a", Name: "ra", Capacity: 1, CertSerial: serial}
			perr := s.persistCheckedErrLocked("test.seed")
			s.mu.Unlock()
			if perr != nil {
				t.Fatalf("seed persist: %v", perr)
			}
			statePath := filepath.Join(dir, "state.json")
			before, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatal(err)
			}

			restore := fsutil.SetHooks(fault.hooks)
			w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-a/disable", "admin-tok", "")
			restore()
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("disable with failing %s = %d, want opaque 503: %s", fault.name, w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "injected") {
				t.Fatalf("disable failure leaked the raw durability error: %q", w.Body.String())
			}
			if !s.stateDegraded.Load() {
				t.Fatal("failed durable write did not arm the degraded state")
			}
			if fault.preRename {
				after, rerr := os.ReadFile(statePath)
				if rerr != nil {
					t.Fatal(rerr)
				}
				if !bytes.Equal(after, before) {
					t.Fatalf("previous durable state.json changed after a %s failure", fault.name)
				}
			}
			assertNoAtomicScratch(t, dir)

			// Whole-state rollback: no phantom disable and no phantom
			// revocation after an unacknowledged kill switch.
			s.mu.Lock()
			ri := s.runners["runner-a"]
			_, locallyRevoked := s.crl[serial]
			s.mu.Unlock()
			if ri.Disabled {
				t.Fatalf("failed %s disable left the runner disabled", fault.name)
			}
			if locallyRevoked {
				t.Fatalf("failed %s disable left a local CRL revocation", fault.name)
			}

			// The previous durable state is still usable: the healed retry
			// acknowledges exactly once and survives a restart.
			if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-a/disable", "admin-tok", ""); w.Code != http.StatusOK {
				t.Fatalf("healed disable = %d: %s", w.Code, w.Body.String())
			}
			if !crlRevoked(t, s, serial) {
				t.Fatal("healed disable did not revoke locally")
			}
			s2, err := NewPersistent("runner-tok", "admin-tok", dir)
			if err != nil {
				t.Fatal(err)
			}
			if !crlRevoked(t, s2, serial) {
				t.Fatal("revocation did not survive the restart")
			}
		})
	}
}

// TestCRLPersistFailuresKeepPreviousDurableFile drives persistCRL (the
// runner-crl.json mirror, crl.go) through every durability failure: the
// error surfaces and, except for the post-rename directory fsync, the
// previous file bytes are intact with no scratch leftovers.
func TestCRLPersistFailuresKeepPreviousDurableFile(t *testing.T) {
	for _, fault := range fsDurableFaults() {
		t.Run(fault.name, func(t *testing.T) {
			dir := t.TempDir()
			s := New("runner-tok")
			s.dataDir = dir
			s.mu.Lock()
			s.crl = map[string]string{"aaa": "runner-a"}
			s.mu.Unlock()
			if err := s.persistCRL(); err != nil {
				t.Fatal(err)
			}
			crlPath := filepath.Join(dir, crlFile)
			before, err := os.ReadFile(crlPath)
			if err != nil {
				t.Fatal(err)
			}

			s.mu.Lock()
			s.crl["bbb"] = "runner-b"
			s.mu.Unlock()
			restore := fsutil.SetHooks(fault.hooks)
			err = s.persistCRL()
			restore()
			if err == nil {
				t.Fatalf("persistCRL with a failing %s was acknowledged", fault.name)
			}
			if fault.preRename {
				after, rerr := os.ReadFile(crlPath)
				if rerr != nil {
					t.Fatal(rerr)
				}
				if !bytes.Equal(after, before) {
					t.Fatalf("previous runner-crl.json changed after a %s failure", fault.name)
				}
			}
			assertNoAtomicScratch(t, dir)

			// A healthy retry writes the pending revocation durably.
			if err := s.persistCRL(); err != nil {
				t.Fatalf("retry after %s failure: %v", fault.name, err)
			}
			b, err := os.ReadFile(crlPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(b, []byte("runner-b")) {
				t.Fatalf("retry did not persist the pending revocation: %s", b)
			}
		})
	}
}

// TestEnrollGrantPersistFailuresBlockMintAcknowledgment proves CreateEnrollGrant
// never returns a token for a grant whose write was not certified durable:
// every durability-step failure surfaces as an error with an empty token, the
// in-memory map is rolled back, and (pre-rename) the previous
// enroll-grants.json bytes are intact.
func TestEnrollGrantPersistFailuresBlockMintAcknowledgment(t *testing.T) {
	for _, fault := range fsDurableFaults() {
		t.Run(fault.name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := NewPersistent("runner-tok", "admin-tok", dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil); err != nil {
				t.Fatal(err)
			}
			grantPath := filepath.Join(dir, enrollGrantsFile)
			before, err := os.ReadFile(grantPath)
			if err != nil {
				t.Fatal(err)
			}

			restore := fsutil.SetHooks(fault.hooks)
			tok, err := s.CreateEnrollGrant(context.Background(), time.Hour, []string{"os:linux"})
			restore()
			if err == nil {
				t.Fatalf("mint with a failing %s was acknowledged", fault.name)
			}
			if tok != "" {
				t.Fatalf("mint with a failing %s returned a token", fault.name)
			}
			s.mu.Lock()
			grants := len(s.EnrollGrants)
			s.mu.Unlock()
			if grants != 1 {
				t.Fatalf("failed %s mint left %d grants in memory, want the 1 seeded", fault.name, grants)
			}
			if fault.preRename {
				after, rerr := os.ReadFile(grantPath)
				if rerr != nil {
					t.Fatal(rerr)
				}
				if !bytes.Equal(after, before) {
					t.Fatalf("previous enroll-grants.json changed after a %s failure", fault.name)
				}
			}
			assertNoAtomicScratch(t, dir)

			// Healed retry: the new grant and the seeded one both load after
			// a restart.
			healed, err := s.CreateEnrollGrant(context.Background(), time.Hour, []string{"os:linux"})
			if err != nil {
				t.Fatalf("healed mint after %s failure: %v", fault.name, err)
			}
			s2, err := NewPersistent("runner-tok", "admin-tok", dir)
			if err != nil {
				t.Fatal(err)
			}
			s2.mu.Lock()
			_, ok := s2.EnrollGrants[auth.TokenDigest(healed)]
			s2.mu.Unlock()
			if !ok {
				t.Fatal("healed grant did not survive the restart")
			}
		})
	}
}

// TestEnrollGrantPersistFailuresBlockConsumeAcknowledgment proves the enroll
// handler never issues a certificate for a consumption whose write was not
// certified durable: each failure refuses the request with the enrollment
// tier's existing 401 convention, rolls the consumed grant back, and
// (pre-rename) leaves the on-disk file showing the grant as unused.
func TestEnrollGrantPersistFailuresBlockConsumeAcknowledgment(t *testing.T) {
	ca, err := runnerpki.NewCA("durable grant ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range fsDurableFaults() {
		t.Run(fault.name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := NewPersistent("runner-tok", "admin-tok", dir)
			if err != nil {
				t.Fatal(err)
			}
			s.RunnerCA = ca
			s.RunnerEnrollToken = ""
			raw, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil)
			if err != nil {
				t.Fatal(err)
			}
			grantPath := filepath.Join(dir, enrollGrantsFile)
			before, err := os.ReadFile(grantPath)
			if err != nil {
				t.Fatal(err)
			}

			restore := fsutil.SetHooks(fault.hooks)
			w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/enroll",
				enrollBodyFor(t, "runner-g", nil), raw, nil)
			restore()
			if w.Code == http.StatusOK {
				t.Fatalf("enrollment with a failing %s was acknowledged: %s", fault.name, w.Body.String())
			}
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("enrollment with a failing %s = %d, want the enrollment tier's 401: %s", fault.name, w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "CERTIFICATE") {
				t.Fatalf("certificate issued for a %s failure: %s", fault.name, w.Body.String())
			}
			s.mu.Lock()
			g := s.EnrollGrants[auth.TokenDigest(raw)]
			s.mu.Unlock()
			if g.Used {
				t.Fatalf("failed %s consume left the grant used in memory", fault.name)
			}
			if fault.preRename {
				after, rerr := os.ReadFile(grantPath)
				if rerr != nil {
					t.Fatal(rerr)
				}
				if !bytes.Equal(after, before) {
					t.Fatalf("previous enroll-grants.json changed after a %s failure", fault.name)
				}
			}
			assertNoAtomicScratch(t, dir)

			// The grant is still consumable exactly once after healing.
			if err := s.consumeEnrollGrant(context.Background(), raw, nil); err != nil {
				t.Fatalf("consume after healed %s failure: %v", fault.name, err)
			}
			if err := s.consumeEnrollGrant(context.Background(), raw, nil); err == nil {
				t.Fatal("grant consumed twice after healing")
			}
		})
	}
}

// TestPersistWebSessionKeyConcurrentWritersProduceValidFile stresses the
// web-session key path (the same bytes and mode loadWebSessionSecret writes)
// with parallel writers: every durable write must succeed, the final file
// must be exactly one writer's secret and must load through the real
// loadWebSessionSecret parser, and no scratch file may survive. Cross-
// contamination or a fixed temp name would fail the loader or the equality
// check.
func TestPersistWebSessionKeyConcurrentWritersProduceValidFile(t *testing.T) {
	const writers = 8
	const rounds = 8

	dir := t.TempDir()
	path := filepath.Join(dir, webSessionKeyFile)
	secrets := make([][]byte, writers)
	hexSecrets := make([][]byte, writers)
	for i := range secrets {
		secrets[i] = bytes.Repeat([]byte{byte(i + 1)}, 32)
		hexSecrets[i] = []byte(hex.EncodeToString(secrets[i]))
	}

	for round := 0; round < rounds; round++ {
		errs := make([]error, writers)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				errs[i] = fsutil.AtomicWriteFile(path, hexSecrets[i], 0o600)
			}(i)
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d: writer %d: %v", round, i, err)
			}
		}
		assertNoAtomicScratch(t, dir)

		// The real loader must accept the final file and produce exactly one
		// writer's secret.
		loaded := New("runner-tok")
		if err := loaded.loadWebSessionSecret(dir); err != nil {
			t.Fatalf("round %d: reload of the final key file: %v", round, err)
		}
		matched := false
		for i := range secrets {
			if bytes.Equal(loaded.WebSessionSecret, secrets[i]) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("round %d: final key matches no single writer (torn/cross-contaminated)", round)
		}
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("round %d: mode = %v, %v; want 0600", round, fi.Mode().Perm(), err)
		}
	}
}
