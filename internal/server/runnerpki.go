package server

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

const (
	// ProtocolMin/ProtocolMax is the runner API protocol version range this
	// control plane speaks. Runners whose declared range does not overlap it
	// are rejected at registration.
	ProtocolMin = 3
	ProtocolMax = 3

	// runnerCertTTL is the validity period of enrolled runner certificates.
	runnerCertTTL = 24 * 365 * time.Hour

	maxRunnerIDLen = 128
)

// loadRunnerCA loads a persisted runner CA from dataDir when present. Missing
// files leave RunnerCA nil: runner enrollment and certificate identity
// binding stay disabled (bearer-token mode).
func (s *Server) loadRunnerCA(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	certPEM, err := os.ReadFile(filepath.Join(dataDir, "ca.crt"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dataDir, "ca.key"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	ca, err := runnerpki.LoadCA(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("load runner CA: %w", err)
	}
	s.RunnerCA = ca
	return nil
}

// EnsureRunnerCA makes sure a runner CA is available for enrollment,
// generating and persisting one in dataDir when needed.
func (s *Server) EnsureRunnerCA(dataDir string) error {
	if s.RunnerCA != nil || dataDir == "" {
		return nil
	}
	ca, err := runnerpki.LoadOrCreateCA(dataDir)
	if err != nil {
		return err
	}
	s.RunnerCA = ca
	return nil
}

// SetRunnerCA installs a runner CA from explicit PEM file paths.
func (s *Server) SetRunnerCA(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read runner CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read runner CA key: %w", err)
	}
	ca, err := runnerpki.LoadCA(certPEM, keyPEM)
	if err != nil {
		return err
	}
	s.RunnerCA = ca
	return nil
}

// enroll signs a runner CSR after the enrollment token check already
// performed by auth(). The issued certificate binds the runner to its ID.
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	if s.RunnerCA == nil {
		http.Error(w, "runner CA not configured", http.StatusServiceUnavailable)
		return
	}
	var in EnrollRequest
	if !decode(w, r, &in) {
		return
	}
	runnerID := strings.TrimSpace(in.RunnerID)
	if runnerID == "" || len(runnerID) > maxRunnerIDLen {
		http.Error(w, "runner_id is required", http.StatusBadRequest)
		return
	}
	csrPEM, err := base64.StdEncoding.DecodeString(in.CSR)
	if err != nil || len(csrPEM) == 0 || len(csrPEM) > 64<<10 {
		http.Error(w, "csr must be base64-encoded PEM", http.StatusBadRequest)
		return
	}
	certPEM, err := s.RunnerCA.SignRunnerCSR(csrPEM, runnerID, runnerCertTTL, nil)
	if err != nil {
		http.Error(w, "CSR rejected: "+err.Error(), http.StatusBadRequest)
		return
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.RunnerCA.Cert.Raw})
	s.auditLocked("runner.enrolled", runnerID, "", "", "runner certificate enrolled", nil)
	writeJSON(w, http.StatusOK, EnrollResponse{
		Certificate:   string(certPEM),
		CACertificate: string(caPEM),
		TTLSeconds:    int64(runnerCertTTL / time.Second),
	})
}

// peerRunnerID verifies the TLS peer certificate against the runner CA and
// returns the runner identity it carries.
func (s *Server) peerRunnerID(r *http.Request) (string, error) {
	if s.RunnerCA == nil {
		return "", fmt.Errorf("runner CA not configured")
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", fmt.Errorf("runner certificate required")
	}
	roots := runnerpki.Pool(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.RunnerCA.Cert.Raw}))
	return s.RunnerCA.VerifyPeer(r.TLS.PeerCertificates[0], roots)
}

// bindRunnerIdentity binds a runner request to its TLS peer identity when
// runner mTLS is enabled. The verified peer runner ID must match id (an empty
// id skips the comparison, letting register() adopt the peer identity). With
// mTLS disabled the bearer token is the identity and binding is a no-op.
func (s *Server) bindRunnerIdentity(r *http.Request, id string) error {
	if s.RunnerCA == nil {
		return nil
	}
	peerID, err := s.peerRunnerID(r)
	if err != nil {
		return err
	}
	if id != "" && id != peerID {
		return fmt.Errorf("certificate identity %q does not match runner id %q", peerID, id)
	}
	return nil
}

// verifyRunnerIdentity reports whether the TLS peer certificate identity
// matches the runner ID a request acts for. Lease tokens remain the
// capability; this pins the transport identity to the claimed runner. With
// mTLS disabled the bearer token is authoritative and this accepts.
// Revoked certificates (CRL, see crl.go) are rejected after the identity
// check: revocation is a control-plane decision that must not be bypassed
// by reusing a still-valid certificate.
func (s *Server) verifyRunnerIdentity(r *http.Request, payloadRunnerID string) bool {
	if s.RunnerCA == nil {
		return true
	}
	peerID, err := s.peerRunnerID(r)
	if err != nil {
		return false
	}
	if peerID != payloadRunnerID {
		return false
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && r.TLS.PeerCertificates[0] != nil {
		serial := r.TLS.PeerCertificates[0].SerialNumber.Text(16)
		if s.certSerialRevoked(serial) {
			return false
		}
	}
	return true
}
