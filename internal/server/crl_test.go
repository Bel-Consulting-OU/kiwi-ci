package server

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

func TestCRLRevocationRejectsPeerCert(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("token")
	s.RunnerCA = ca
	_, cert := pkiSignRunner(t, ca, "runner-a")
	serial := cert.SerialNumber.Text(16)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	if !s.verifyRunnerIdentity(req, "runner-a") {
		t.Fatal("valid cert must pass before revocation")
	}

	// Register the runner with its certificate serial and disable it
	// through the admin endpoint: the serial lands in the CRL.
	s.mu.Lock()
	s.runners["runner-a"] = model.Runner{ID: "runner-a", Name: "runner-a", CertSerial: serial, Capacity: 1}
	s.mu.Unlock()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-a/disable", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("disable = %d: %s", w.Code, w.Body.String())
	}
	if !crlRevoked(t, s, serial) {
		t.Fatal("serial not recorded in the CRL")
	}
	req2 := httptest.NewRequest(http.MethodPost, "/", nil)
	req2.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	if s.verifyRunnerIdentity(req2, "runner-a") {
		t.Fatal("revoked cert must be rejected")
	}
	// The runner record carries the revocation timestamp.
	s.mu.Lock()
	ri := s.runners["runner-a"]
	s.mu.Unlock()
	if ri.RevokedAt == nil {
		t.Fatal("runner record lacks revoked_at")
	}
}

func TestCRLPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.runners["runner-a"] = model.Runner{ID: "runner-a", Name: "runner-a", CertSerial: "0c0ffee", Capacity: 1}
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-a/disable", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("disable = %d", w.Code)
	}
	// A restarted control plane must load the persisted CRL.
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !crlRevoked(t, s2, "0c0ffee") {
		t.Fatal("CRL not restored from runner-crl.json")
	}
}
