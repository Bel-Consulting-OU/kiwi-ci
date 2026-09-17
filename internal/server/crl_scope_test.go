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
		if !s.certSerialRevoked(serial) {
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
		if !s.certSerialRevoked(serial) {
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
	if !s.certSerialRevoked("anything") {
		t.Fatal("revocation store outage accepted the serial (fail open)")
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
	if !s.certSerialRevoked("deadbeef") {
		t.Fatal("exact serial not revoked")
	}
	for _, other := range []string{"DEADBEEF", "DeadBeef", "deadbeef ", " deadbeef", "0xdeadbeef", "deadbee", ""} {
		if s.certSerialRevoked(other) {
			t.Fatalf("serial %q matched the revoked entry", other)
		}
	}
	// Revocation by record with an empty serial is a no-op, never a wildcard.
	s.revokeRunnerCert(model.Runner{ID: "runner-b"}, "admin")
	if s.certSerialRevoked("") {
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

// revokeErrStore accepts disables but always fails the durable revocation
// write, modelling a store blip during disable.
type revokeErrStore struct {
	*dbFakeStore
}

func (revokeErrStore) RevokeCert(ctx context.Context, serial, runnerID, reason string) error {
	return errors.New("durable revoke failed")
}

// TestLocalRevocationSurvivesCacheTTLAndStoreFailure proves a revocation
// performed on this replica stays effective even when the durable write
// fails and the decision cache expires: the local mirror is authoritative
// for locally observed revocations, so a disable can never silently undo
// itself after crlCacheTTL.
func TestLocalRevocationSurvivesCacheTTLAndStoreFailure(t *testing.T) {
	ca, err := runnerpki.NewCA("crl ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, certA := pkiSignRunner(t, ca, "runner-a")
	f := newDBFakeStore()
	rs := revokeErrStore{dbFakeStore: f}
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
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-a/disable", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}
	serial := certA.SerialNumber.Text(16)
	if !s.certSerialRevoked(serial) {
		t.Fatal("local revocation not effective")
	}
	// Expire the decision cache (and clear the mirror-aware fast path) to
	// prove the local mirror, not the cache, holds the decision.
	s.crlMu.Lock()
	s.crlCache = map[string]crlCacheEntry{}
	s.crlMu.Unlock()
	if !s.certSerialRevoked(serial) {
		t.Fatal("revocation lost after cache expiry when the durable write failed")
	}
	// The certificate stays rejected on the identity path too.
	if s.verifyRunnerIdentity(crlRequestWithCert(t, certA), "runner-a") {
		t.Fatal("revoked certificate accepted after cache expiry")
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "runner-tok", certA); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("revoked cert re-registered after cache expiry: %d", w.Code)
	}
}
