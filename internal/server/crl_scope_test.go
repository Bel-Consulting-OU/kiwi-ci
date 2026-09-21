package server

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// crlRequestWithCert builds an identity-resolution request carrying the
// given peer certificate.
func crlRequestWithCert(t *testing.T, cert *x509.Certificate) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return req
}

// crlRevoked reports whether serial is revoked, failing the test on a
// lookup error. The fail-closed error path (revoked=true WITH the error) is
// asserted explicitly where a store outage is injected.
func crlRevoked(t *testing.T, s *Server, serial string) bool {
	t.Helper()
	revoked, err := s.certSerialRevoked(context.Background(), serial)
	if err != nil {
		t.Fatalf("certSerialRevoked(%q) error: %v", serial, err)
	}
	return revoked
}

// crlErrorStore injects a revocation-store outage while satisfying the
// full storage contract through the embedded fake.
type crlErrorStore struct {
	*dbFakeStore
}

func (crlErrorStore) CertRevoked(ctx context.Context, serial string) (bool, error) {
	return false, errors.New("revocation store down")
}

// TestCRLRevokedCertCannotReRegister proves a revoked certificate stays
// rejected: after the runner is disabled (serial revoked) a re-registration
// presenting the same certificate is refused at the identity gate, so a
// revoked credential can never resurrect a runner. Re-enabling the runner
// does not resurrect the certificate either.
func TestCRLRevokedCertCannotReRegister(t *testing.T) {
	ca, err := runnerpki.NewCA("crl ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, certA := pkiSignRunner(t, ca, "runner-a")
	serial := certA.SerialNumber.Text(16)

	t.Run("memory", func(t *testing.T) {
		s := New("runner-tok")
		s.AdminToken = "admin-tok"
		s.RunnerCA = ca
		h := s.Handler()
		// Register, then disable (revokes the serial).
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
			map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "runner-tok", certA); w.Code != http.StatusOK {
			t.Fatalf("register: %d %s", w.Code, w.Body.String())
		}
		if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-a/disable", "admin-tok", ""); w.Code != http.StatusOK {
			t.Fatalf("disable: %d", w.Code)
		}
		if !crlRevoked(t, s, serial) {
			t.Fatal("serial not revoked")
		}
		// Re-registration with the revoked certificate is refused.
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
			map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "runner-tok", certA); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
			t.Fatalf("revoked cert re-registered: %d %s", w.Code, w.Body.String())
		}
		// Every runner-tier route rejects it too.
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/runner-a/next", map[string]any{}, "runner-tok", certA); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
			t.Fatalf("revoked cert on next(): %d", w.Code)
		}
		// Re-enabling the runner does NOT resurrect the certificate.
		if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-a/enable", "admin-tok", ""); w.Code != http.StatusOK {
			t.Fatalf("enable: %d", w.Code)
		}
		s.mu.Lock()
		ri := s.runners["runner-a"]
		reEnabled := !ri.Disabled
		s.mu.Unlock()
		if !reEnabled {
			t.Fatal("runner was not re-enabled")
		}
		if !crlRevoked(t, s, serial) {
			t.Fatal("enable cleared the certificate revocation")
		}
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/runner-a/next", map[string]any{}, "runner-tok", certA); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
			t.Fatalf("re-enabled runner reused the revoked cert: %d %s", w.Code, w.Body.String())
		}
	})

	t.Run("db", func(t *testing.T) {
		f := newDBFakeStore()
		s := New("runner-tok")
		s.AdminToken = "admin-tok"
		s.RunnerCA = ca
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		h := s.Handler()
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
			map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "runner-tok", certA); w.Code != http.StatusOK {
			t.Fatalf("register: %d %s", w.Code, w.Body.String())
		}
		if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-a/disable", "admin-tok", ""); w.Code != http.StatusOK {
			t.Fatalf("disable: %d", w.Code)
		}
		revoked, err := f.CertRevoked(context.Background(), serial)
		if err != nil || !revoked {
			t.Fatalf("durable revocation missing: %v %v", revoked, err)
		}
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
			map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "runner-tok", certA); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
			t.Fatalf("revoked cert re-registered in DB mode: %d %s", w.Code, w.Body.String())
		}
		if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/runner-a/next", map[string]any{}, "runner-tok", certA); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
			t.Fatalf("revoked cert on next() in DB mode: %d", w.Code)
		}
	})
}

// TestCRLFailClosedWhenRevocationStoreUnavailable pins the documented
// fail-closed behavior: an error consulting the revocation store must not
// accept the certificate, even when the local dev mirror knows nothing.
func TestCRLFailClosedWhenRevocationStoreUnavailable(t *testing.T) {
	ca, err := runnerpki.NewCA("crl ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	s := New("runner-tok")
	s.RunnerCA = ca
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.DB = crlErrorStore{dbFakeStore: f}
	if revoked, err := s.certSerialRevoked(context.Background(), "anything"); !revoked || err == nil {
		t.Fatalf("revocation store outage = revoked %v, err %v; want revoked=true with the error (fail closed)", revoked, err)
	}
	_, certA := pkiSignRunner(t, ca, "runner-a")
	if s.verifyRunnerIdentity(crlRequestWithCert(t, certA), "runner-a") {
		t.Fatal("revocation store outage accepted a peer certificate")
	}
	// The outage is also reported to the caller as an identity error.
	if _, _, err := s.resolveRunnerIdentity(crlRequestWithCert(t, certA), "runner-a"); err == nil {
		t.Fatal("revocation outage did not fail the identity resolution")
	}
}

// TestCRLSerialMatchingIsExact pins the serial key format: only the exact
// canonical hex string is revoked; case, whitespace and prefix variants are
// different certificates.
func TestCRLSerialMatchingIsExact(t *testing.T) {
	s := New("runner-tok")
	s.mu.Lock()
	s.crl["deadbeef"] = "runner-a"
	s.mu.Unlock()
	if !crlRevoked(t, s, "deadbeef") {
		t.Fatal("exact serial not revoked")
	}
	for _, other := range []string{"DEADBEEF", "DeadBeef", "deadbeef ", " deadbeef", "0xdeadbeef", "deadbee", ""} {
		if crlRevoked(t, s, other) {
			t.Fatalf("serial %q matched the revoked entry", other)
		}
	}
	// Revocation by record with an empty serial is a no-op, never a wildcard.
	s.revokeRunnerCert(context.Background(), model.Runner{ID: "runner-b"}, "admin")
	if crlRevoked(t, s, "") {
		t.Fatal("empty serial must never be revoked")
	}
}

// countingCRLStore counts revocation-store reads so tests can prove
// unverified certificates never reach the CRL.
type countingCRLStore struct {
	*dbFakeStore
	reads int32
}

func (c *countingCRLStore) CertRevoked(ctx context.Context, serial string) (bool, error) {
	atomic.AddInt32(&c.reads, 1)
	return c.dbFakeStore.CertRevoked(ctx, serial)
}

// TestCRLLookupOnlyForVerifiedCertificates proves the ordering: arbitrary
// unverified peer certificates (self-signed, wrong CA) are rejected by the
// chain verification BEFORE the revocation store is consulted, so they can
// neither drive CRL lookups nor be mistaken for revoked identities. A
// verified certificate does reach the CRL.
func TestCRLLookupOnlyForVerifiedCertificates(t *testing.T) {
	ca, err := runnerpki.NewCA("crl ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	cs := &countingCRLStore{dbFakeStore: f}
	s := New("runner-tok")
	s.RunnerCA = ca
	if err := s.SwitchToDB(cs); err != nil {
		t.Fatal(err)
	}
	// Self-signed certificate: does not chain to the runner CA.
	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xbadc0de),
		Subject:      pkix.Name{CommonName: "not-a-runner"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	selfSigned, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.resolveRunnerIdentity(crlRequestWithCert(t, selfSigned), ""); err == nil {
		t.Fatal("self-signed certificate passed identity resolution")
	}
	if got := atomic.LoadInt32(&cs.reads); got != 0 {
		t.Fatalf("unverified certificate drove %d CRL lookups", got)
	}
	// A verified certificate reaches the CRL (once, then the decision
	// cache serves the replica).
	_, certA := pkiSignRunner(t, ca, "runner-a")
	if _, _, err := s.resolveRunnerIdentity(crlRequestWithCert(t, certA), "runner-a"); err != nil {
		t.Fatalf("verified certificate rejected: %v", err)
	}
	if got := atomic.LoadInt32(&cs.reads); got == 0 {
		t.Fatal("verified certificate never consulted the CRL")
	}
}

// TestCorruptPersistedSecurityStateRefusesStartup proves a truncated or
// corrupt CRL, enrollment-grant or secret-receipt file refuses server
// construction instead of silently starting with an empty (fail-open)
// security state.
func TestCorruptPersistedSecurityStateRefusesStartup(t *testing.T) {
	for _, file := range []string{crlFile, enrollGrantsFile, secretReceiptsFile} {
		t.Run(file, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := NewPersistent("runner-tok", "admin-tok", dir); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, file), []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewPersistent("runner-tok", "admin-tok", dir); err == nil {
				t.Fatalf("corrupt %s accepted at startup", file)
			}
		})
	}
}

// revokeErrStore accepts disables but fails the CERTIFICATE REVOCATION write
// inside the atomic disable transaction while fail is set, modelling a store
// blip during disable.
type revokeErrStore struct {
	*dbFakeStore
	fail atomic.Bool
}

func (r *revokeErrStore) DisableRunnerAndRevokeCert(ctx context.Context, runnerID, certSerial, actor string) (int, error) {
	if r.fail.Load() {
		return 0, errors.New("durable revoke failed")
	}
	return r.dbFakeStore.DisableRunnerAndRevokeCert(ctx, runnerID, certSerial, actor)
}

// TestDisableRevocationWriteFailureFailsClosed is the ADAPTED former
// TestLocalRevocationSurvivesCacheTTLAndStoreFailure (S6-B behavior change,
// documented).
//
// The old admin disable composed UpsertRunner + RevokeRunnerLeases + a
// best-effort RevokeCert and answered 200 even when the durable revocation
// write failed, relying on this replica's local mirror to stay safe. The fix
// makes disable + lease revocation + certificate revocation one store
// transaction, so when the revocation cannot be recorded the handler answers
// an opaque 503 and NOTHING changes: the runner is not disabled, no lease
// moves and no local CRL entry appears (the certificate was never revoked
// anywhere). Healing and retrying succeeds exactly once, and once the
// revocation is durably recorded it stays effective after cache expiry.
func TestDisableRevocationWriteFailureFailsClosed(t *testing.T) {
	ca, err := runnerpki.NewCA("crl ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, certA := pkiSignRunner(t, ca, "runner-a")
	f := newDBFakeStore()
	rs := &revokeErrStore{dbFakeStore: f}
	rs.fail.Store(true)
	s := New("runner-tok")
	s.AdminToken = "admin-tok"
	s.RunnerCA = ca
	if err := s.SwitchToDB(rs); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "runner-tok", certA); w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	// A leased job makes the lease revocation observable.
	f.mu.Lock()
	f.runs["run-a"] = model.Run{ID: "run-a", Status: model.StatusRunning}
	f.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-a", Key: "build", Status: model.StatusRunning, LeaseRunnerID: "runner-a"}
	f.mu.Unlock()

	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-a/disable", "admin-tok", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("disable with failing revocation = %d, want 503: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "durable revoke failed") {
		t.Fatalf("disable failure leaked the raw store error: %q", w.Body.String())
	}
	serial := certA.SerialNumber.Text(16)
	if crlRevoked(t, s, serial) {
		t.Fatal("failed disable left a local revocation")
	}
	f.mu.Lock()
	ri, job := f.runners["runner-a"], f.jobs["job-a"]
	f.mu.Unlock()
	if ri.Disabled {
		t.Fatalf("failed disable marked the runner disabled: %+v", ri)
	}
	if job.Status != model.StatusRunning || job.LeaseRunnerID != "runner-a" {
		t.Fatalf("failed disable moved the lease: %+v", job)
	}
	// The certificate was never revoked, so identity verification still
	// accepts it despite the failed attempt (no phantom revocation).
	if !s.verifyRunnerIdentity(crlRequestWithCert(t, certA), "runner-a") {
		t.Fatal("failed disable revoked the certificate on the identity path")
	}

	// Heal the store: the retry disables and revokes exactly once, and the
	// revocation survives decision-cache expiry because the durable row and
	// the local mirror agree.
	rs.fail.Store(false)
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-a/disable", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("healed disable = %d: %s", w.Code, w.Body.String())
	}
	if !crlRevoked(t, s, serial) {
		t.Fatal("healed disable did not revoke locally")
	}
	s.crlMu.Lock()
	s.crlCache = map[string]crlCacheEntry{}
	s.crlMu.Unlock()
	if !crlRevoked(t, s, serial) {
		t.Fatal("revocation lost after cache expiry")
	}
	if s.verifyRunnerIdentity(crlRequestWithCert(t, certA), "runner-a") {
		t.Fatal("revoked certificate accepted after cache expiry")
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "runner-tok", certA); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("revoked cert re-registered after cache expiry: %d", w.Code)
	}
}
