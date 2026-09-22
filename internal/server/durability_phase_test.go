package server

// Durability-phase tests: a post-rename failure (the parent-directory fsync)
// leaves the NEW state visible at the destination while its crash durability
// is uncertified (fsutil.ErrPublishedUncertain). Security-monotonic callers
// must retain the published state — never roll back to the permissive one —
// and keep readiness degraded until a later successful persist reconciles.
// Pre-rename failures keep the existing rollback behavior, which the
// fs_durable_security_state_test.go matrix covers.

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// failDirSync installs a directory-fsync failure and returns the restore
// function. Every durable write performed while it is installed fails AFTER
// its rename, i.e. with fsutil.Renamed(err) == true.
func failDirSync(t *testing.T) func() {
	t.Helper()
	restore := fsutil.SetHooks(fsutil.Hooks{DirSync: func(string) error {
		return errors.New("injected directory fsync failure")
	}})
	return restore
}

// assertPublishedUncertain pins the typed error contract of a post-rename
// failure as observed by a server caller.
func assertPublishedUncertain(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("post-rename failure was not surfaced")
	}
	if !fsutil.Renamed(err) {
		t.Fatalf("error %v is not reported as published (Renamed=false)", err)
	}
	if !errors.Is(err, fsutil.ErrPublishedUncertain) {
		t.Fatalf("error %v does not match fsutil.ErrPublishedUncertain", err)
	}
	if errors.Is(err, fsutil.ErrNotPublished) {
		t.Fatalf("error %v must not match fsutil.ErrNotPublished", err)
	}
	if phase, ok := fsutil.PhaseOf(err); !ok || phase != fsutil.PhaseDirSync {
		t.Fatalf("error %v phase = %q,%v; want dir-sync,true", err, phase, ok)
	}
}

// TestRunnerDisableDirSyncFailureRetainsPublishedRevocation drives the
// fs-mode kill switch through a post-rename failure: the snapshot rename
// already published the disable, the lease cancellations and the CRL, so the
// handler answers 503 with the degraded marker while the restrictive state
// stays in memory, a restart sees the revocation, and a later successful
// persist reconciles.
func TestRunnerDisableDirSyncFailureRetainsPublishedRevocation(t *testing.T) {
	const serial = "0c0ffee"
	dir := t.TempDir()
	// The shared runner token must be "token": registerRollbackRunner and
	// leaseNextRollbackTask drive the runner endpoints with bearer "token".
	s, err := NewPersistent("token", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID := registerRollbackRunner(t, s, 1)
	task := leaseNextRollbackTask(t, s, runnerID)
	seedRunnerCertSerial(t, s, runnerID, serial)

	restore := failDirSync(t)
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/disable", "admin-tok", "")
	restore()
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("disable with a failing dir fsync = %d, want 503: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Kiwi-State"); got != "degraded" {
		t.Fatalf("X-Kiwi-State = %q, want degraded", got)
	}
	if strings.Contains(w.Body.String(), "injected") {
		t.Fatalf("disable failure leaked the raw durability error: %q", w.Body.String())
	}

	// Retention, not rollback: the visible snapshot already holds the
	// disable, the cancellation and the revocation.
	s.mu.Lock()
	ri := s.runners[runnerID]
	_, locallyRevoked := s.crl[serial]
	cancelled := s.jobs[task.Job.ID].Status
	s.mu.Unlock()
	if !ri.Disabled {
		t.Fatal("published disable rolled the runner back to enabled")
	}
	if !locallyRevoked {
		t.Fatal("published disable rolled the local CRL revocation back")
	}
	if cancelled != model.StatusCancelled {
		t.Fatalf("published disable revived the cancelled job: %q", cancelled)
	}
	if !s.stateDegraded.Load() {
		t.Fatal("published disable did not leave readiness degraded")
	}
	published, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(published, []byte(serial)) {
		t.Fatalf("state.json does not contain the published revocation: %s", published)
	}

	// Restart: the visible snapshot is authoritative and the revocation is
	// permanent.
	s2, err := NewPersistent("token", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !crlRevoked(t, s2, serial) {
		t.Fatal("restart lost the published revocation")
	}
	s2.mu.Lock()
	restarted := s2.runners[runnerID]
	s2.mu.Unlock()
	if !restarted.Disabled {
		t.Fatalf("restarted runner = %+v, want disabled", restarted)
	}

	// Reconciliation: a later successful persist clears the degraded marker.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/disable", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("reconciling disable = %d: %s", w.Code, w.Body.String())
	}
	if s.stateDegraded.Load() {
		t.Fatal("successful persist did not clear the degraded marker")
	}
}

// TestCRLMirrorDirSyncFailureKeepsRevocationAndReconciles covers the
// runner-crl.json mirror writer directly: the post-rename failure is typed,
// the in-memory revocation is retained, the mirror file already shows it,
// readiness degrades, and re-persisting the same state heals.
func TestCRLMirrorDirSyncFailureKeepsRevocationAndReconciles(t *testing.T) {
	dir := t.TempDir()
	s := New("runner-tok")
	s.dataDir = dir
	s.mu.Lock()
	s.crl = map[string]string{"aaa": "runner-a"}
	s.mu.Unlock()
	if err := s.persistCRL(); err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	s.crl["bbb"] = "runner-b"
	s.mu.Unlock()
	restore := failDirSync(t)
	err := s.persistCRL()
	restore()
	assertPublishedUncertain(t, err)

	if !s.stateDegraded.Load() {
		t.Fatal("published-uncertain CRL mirror did not leave readiness degraded")
	}
	s.mu.Lock()
	_, kept := s.crl["bbb"]
	s.mu.Unlock()
	if !kept {
		t.Fatal("published-uncertain CRL mirror rolled the revocation back in memory")
	}
	b, err := os.ReadFile(filepath.Join(dir, crlFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("runner-b")) {
		t.Fatalf("runner-crl.json does not show the published revocation: %s", b)
	}

	// Re-persisting the same state reconciles: success clears the marker.
	if err := s.persistCRL(); err != nil {
		t.Fatalf("reconcile persistCRL: %v", err)
	}
	if s.stateDegraded.Load() {
		t.Fatal("successful persistCRL did not clear the degraded marker")
	}
}

// TestEnrollGrantConsumeDirSyncFailureStaysConsumed is the grant replay
// regression: after a post-rename failure the grant must stay CONSUMED in
// memory and on disk (no permissive rollback), a replay must be refused
// everywhere, and a later successful persist must reconcile readiness.
func TestEnrollGrantConsumeDirSyncFailureStaysConsumed(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := auth.TokenDigest(raw)

	restore := failDirSync(t)
	err = s.consumeEnrollGrant(context.Background(), raw, nil)
	restore()
	assertPublishedUncertain(t, err)

	s.mu.Lock()
	g := s.EnrollGrants[digest]
	s.mu.Unlock()
	if !g.Used {
		t.Fatal("published consume rolled the grant back to unused in memory")
	}
	if !s.stateDegraded.Load() {
		t.Fatal("published consume did not leave readiness degraded")
	}
	if s.enrollGrantOK(context.Background(), raw) {
		t.Fatal("published consume still validates the grant")
	}
	if err := s.consumeEnrollGrant(context.Background(), raw, nil); err == nil {
		t.Fatal("published consume allowed an in-memory replay")
	}
	b, err := os.ReadFile(filepath.Join(dir, enrollGrantsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"used": true`)) {
		t.Fatalf("enroll-grants.json does not show the published consumption: %s", b)
	}

	// Restart: the durable file decides and the replay is refused there too.
	s2, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	diskGrant := s2.EnrollGrants[digest]
	s2.mu.Unlock()
	if !diskGrant.Used {
		t.Fatal("restart resurrected an unused grant")
	}
	if err := s2.consumeEnrollGrant(context.Background(), raw, nil); err == nil {
		t.Fatal("restart allowed a replay of a published consumption")
	}

	if err := s.persistEnrollGrants(); err != nil {
		t.Fatalf("reconcile persistEnrollGrants: %v", err)
	}
	if s.stateDegraded.Load() {
		t.Fatal("successful reconcile did not clear the degraded marker")
	}
}

// TestEnrollGrantMintDirSyncFailureRetainsPublishedGrant covers the mint
// side: no token is returned for an uncertified write, but the grant that
// the visible file now carries is retained in memory (never a state that
// denies the file), readiness degrades, and re-persisting heals.
func TestEnrollGrantMintDirSyncFailureRetainsPublishedGrant(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateEnrollGrant(context.Background(), time.Hour, nil); err != nil {
		t.Fatal(err)
	}

	restore := failDirSync(t)
	tok, err := s.CreateEnrollGrant(context.Background(), time.Hour, []string{"os:linux"})
	restore()
	assertPublishedUncertain(t, err)
	if tok != "" {
		t.Fatalf("uncertified mint returned a token %q", tok)
	}

	s.mu.Lock()
	grants := len(s.EnrollGrants)
	s.mu.Unlock()
	if grants != 2 {
		t.Fatalf("in-memory grants = %d, want the seeded plus the published one", grants)
	}
	b, err := os.ReadFile(filepath.Join(dir, enrollGrantsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("os:linux")) {
		t.Fatalf("enroll-grants.json does not carry the published grant: %s", b)
	}
	if !s.stateDegraded.Load() {
		t.Fatal("published mint did not leave readiness degraded")
	}
	if err := s.persistEnrollGrants(); err != nil {
		t.Fatalf("reconcile persistEnrollGrants: %v", err)
	}
	if s.stateDegraded.Load() {
		t.Fatal("successful reconcile did not clear the degraded marker")
	}
}

// TestClusterKeyStoreDirSyncFailureRetainsPublishedMaterial pins the
// store-level contract for the cluster key writer: a post-rename failure
// reports the phase and leaves the NEW material published (every read now
// returns it), while a pre-rename failure leaves the previous material
// intact. A retry converges.
func TestClusterKeyStoreDirSyncFailureRetainsPublishedMaterial(t *testing.T) {
	dir := t.TempDir()
	store := &FSClusterKeyStore{Dir: dir}
	k1 := bytes.Repeat([]byte{1}, 32)
	k2 := bytes.Repeat([]byte{2}, 32)
	if err := store.Store(clusterKindLease, k1); err != nil {
		t.Fatal(err)
	}

	preRename := fsutil.SetHooks(fsutil.Hooks{FileSync: func(*os.File) error {
		return errors.New("injected file fsync failure")
	}})
	err := store.Store(clusterKindLease, k2)
	preRename()
	if err == nil || !errors.Is(err, fsutil.ErrNotPublished) {
		t.Fatalf("pre-rename store failure = %v, want ErrNotPublished", err)
	}
	if got, found, lerr := store.Lookup(clusterKindLease); lerr != nil || !found || !bytes.Equal(got, k1) {
		t.Fatalf("pre-rename failure changed the stored material: %x, %v, %v", got, found, lerr)
	}

	restore := failDirSync(t)
	err = store.Store(clusterKindLease, k2)
	restore()
	assertPublishedUncertain(t, err)
	got, found, lerr := store.Lookup(clusterKindLease)
	if lerr != nil || !found {
		t.Fatalf("Lookup after a published-uncertain write = %v, %v", found, lerr)
	}
	if !bytes.Equal(got, k2) {
		t.Fatalf("published key material was not retained: %x, want %x", got, k2)
	}
	assertNoAtomicScratch(t, dir)

	if err := store.Store(clusterKindLease, k2); err != nil {
		t.Fatalf("retry after a published-uncertain write: %v", err)
	}
}

// TestClusterRunnerCADirSyncFailureRetainsPublishedObject covers the
// trust-root object: the post-rename failure is reported, the published
// object stays authoritative (Lookup returns the new CA), and a retry
// re-derives the legacy ca.crt/ca.key sidecars from it.
func TestClusterRunnerCADirSyncFailureRetainsPublishedObject(t *testing.T) {
	dir := t.TempDir()
	store := &FSClusterKeyStore{Dir: dir}
	obj1, err := createClusterKey(clusterKindRunnerCA)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Store(clusterKindRunnerCA, obj1); err != nil {
		t.Fatal(err)
	}
	obj2, err := createClusterKey(clusterKindRunnerCA)
	if err != nil {
		t.Fatal(err)
	}

	restore := failDirSync(t)
	err = store.Store(clusterKindRunnerCA, obj2)
	restore()
	assertPublishedUncertain(t, err)

	got, found, lerr := store.Lookup(clusterKindRunnerCA)
	if lerr != nil || !found {
		t.Fatalf("Lookup after a published-uncertain CA write = %v, %v", found, lerr)
	}
	if !bytes.Equal(got, obj2) {
		t.Fatal("published runner CA object was not retained")
	}

	// Retry: the sidecars are re-derived from the authoritative object.
	if err := store.Store(clusterKindRunnerCA, obj2); err != nil {
		t.Fatalf("retry after a published-uncertain CA write: %v", err)
	}
	certPEM, keyPEM, serr := splitRunnerCAPEMs(obj2)
	if serr != nil {
		t.Fatal(serr)
	}
	for name, want := range map[string][]byte{"ca.crt": certPEM, "ca.key": keyPEM} {
		b, rerr := os.ReadFile(filepath.Join(dir, name))
		if rerr != nil {
			t.Fatal(rerr)
		}
		if !bytes.Equal(b, want) {
			t.Fatalf("%s does not match the published object after retry", name)
		}
	}
}

// TestDrainDirSyncFailureKeepsPublishedFlagAndDegrades covers the drain
// flag: a post-rename failure leaves the NEW flag visible (a restart stays
// draining), the in-memory state stays draining (fail closed), readiness is
// degraded until the retry persists successfully, and the retry reconciles.
func TestDrainDirSyncFailureKeepsPublishedFlagAndDegrades(t *testing.T) {
	s := New("secret")
	s.dataDir = t.TempDir()

	restore := failDirSync(t)
	w := doJSON(t, s, http.MethodPost, "/api/v1/drain", "secret", `{"reason":"rolling update"}`)
	restore()
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("drain with a failing dir fsync = %d, want 503: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Kiwi-State"); got != "degraded" {
		t.Fatalf("X-Kiwi-State = %q, want degraded", got)
	}
	if !strings.Contains(w.Body.String(), statePersistenceDegradedBody) {
		t.Fatalf("drain failure body = %q; want %q", w.Body.String(), statePersistenceDegradedBody)
	}
	if !s.isDraining() {
		t.Fatal("published drain rolled the in-memory state back to serving")
	}
	if !s.stateDegraded.Load() {
		t.Fatal("published drain did not leave readiness degraded")
	}
	b, err := readFileIfExists(s.dataDir, drainFlagFile)
	if err != nil || !bytes.Contains(b, []byte("rolling update")) {
		t.Fatalf("drain.flag was not published with the reason: %q, %v", b, err)
	}

	// Readiness stays 503 (draining wins the label) and the flag survives a
	// restart, so the published drain is honored.
	if w := doJSON(t, s, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness after a published drain = %d, want 503", w.Code)
	}
	restarted, err := NewPersistent("secret", "secret", s.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.isDraining() || restarted.drainReasonOf() != "rolling update" {
		t.Fatalf("restarted drain state = %v %q; want draining with the published reason",
			restarted.isDraining(), restarted.drainReasonOf())
	}

	// Retry persists the same state and reconciles the degraded marker.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/drain", "secret", `{"reason":"rolling update"}`); w.Code != http.StatusOK {
		t.Fatalf("drain retry after a published failure = %d: %s", w.Code, w.Body.String())
	}
	if s.stateDegraded.Load() {
		t.Fatal("successful drain retry did not clear the degraded marker")
	}
}

// TestSidecarPendingDirSyncFailureRetainsPublishedPointer pins the
// supply-chain persist helper: the published pending-sidecar pointer is
// retained (a restart resolves the accepted digest instead of guessing),
// while a pre-rename failure still rolls it out of memory.
func TestSidecarPendingDirSyncFailureRetainsPublishedPointer(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	j := model.Job{ID: "job-1", LeaseGeneration: 1}
	ctx := context.Background()

	fileSyncFail := fsutil.SetHooks(fsutil.Hooks{FileSync: func(*os.File) error {
		return errors.New("injected file fsync failure")
	}})
	err = s.rememberPendingSidecar(ctx, j, "out.bin", "sbom", "digest-1")
	fileSyncFail()
	if err == nil || !errors.Is(err, fsutil.ErrNotPublished) {
		t.Fatalf("pre-rename pending-sidecar failure = %v, want ErrNotPublished", err)
	}
	s.mu.Lock()
	pending := len(s.pendingSidecars)
	s.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pre-rename failure left %d pending pointers in memory", pending)
	}

	restore := failDirSync(t)
	err = s.rememberPendingSidecar(ctx, j, "out.bin", "sbom", "digest-1")
	restore()
	assertPublishedUncertain(t, err)
	s.mu.Lock()
	pending = len(s.pendingSidecars)
	s.mu.Unlock()
	if pending != 1 {
		t.Fatalf("published pending pointer was rolled back: %d entries", pending)
	}
	if !s.stateDegraded.Load() {
		t.Fatal("published pending pointer did not leave readiness degraded")
	}
	if err := s.persistLocked(); err != nil {
		t.Fatalf("reconcile persist: %v", err)
	}
	if s.stateDegraded.Load() {
		t.Fatal("successful reconcile did not clear the degraded marker")
	}
}
