package server

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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

// EnsureRunnerCA makes sure a runner CA is available for enrollment. Every
// auto-CA path goes through the cluster key store: the CA material is ONE
// atomic cluster-key object ("runner-ca") shared by all replicas, never
// node-local dataDir files. In DB mode without a cluster key store this
// refuses — a data-dir-local CA could never be shared with replicas.
func (s *Server) EnsureRunnerCA() error {
	if s.RunnerCA != nil {
		return nil
	}
	if s.ClusterKeys == nil {
		return fmt.Errorf("runner CA requires a cluster key store: configure --cluster-key-dir (with --data-dir) or pass explicit --runner-ca-cert/--runner-ca-key")
	}
	b, err := s.ClusterKeys.LoadOrCreate(clusterKindRunnerCA)
	if err != nil {
		return err
	}
	return s.setRunnerCAFromBlob(b)
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
// performed by auth(). A request authenticated with a single-use grant
// instead of the static enroll token has the grant consumed here (atomic
// single-use, expiry and label binding) before any certificate is signed.
// The issued certificate binds the runner to its authenticated ID; the CSR's
// own identity fields are discarded (server-synthesized identity, see
// runnerpki.SignRunnerCSR).
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
	// The ID is bound into the certificate CN/URI SAN and into every
	// identity comparison, so it must be valid UTF-8 without control
	// characters: a NUL/newline would survive into certificate identity
	// fields and into the secret envelope's AAD framing. Printable
	// (including non-ASCII) names stay allowed.
	if !validRunnerID(runnerID) {
		http.Error(w, "runner_id contains invalid characters", http.StatusBadRequest)
		return
	}
	tok := enrollTokenFrom(r)
	if s.RunnerEnrollToken == "" || !bearerOK(tok, s.RunnerEnrollToken) {
		// Not the static enrollment token: the request must have been
		// gated by a grant. Consume it (single-use + expiry + label
		// binding) before signing.
		if err := s.consumeEnrollGrant(tok, in.Labels); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
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
		RunnerID:      runnerID,
		Certificate:   string(certPEM),
		CACertificate: string(caPEM),
		TTLSeconds:    int64(runnerCertTTL / time.Second),
	})
}

// validRunnerID reports whether a runner ID is safe to bind into a
// certificate identity and into identity/AAD comparisons: valid UTF-8 with
// no control characters (C0, DEL, or other unicode control runes).
// Printable non-ASCII names remain allowed; only framing-hostile characters
// are refused.
func validRunnerID(id string) bool {
	if !utf8.ValidString(id) {
		return false
	}
	for _, r := range id {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
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

// resolveRunnerIdentity is the SINGLE transport identity resolution shared
// by bindRunnerIdentity (mutation-time binding) and verifyRunnerIdentity
// (per-request verification), so both enforce IDENTICAL semantics:
//
//   - RequireRunnerClientCerts with a runner CA makes the TLS peer
//     certificate mandatory and authoritative on every runner route: a
//     request without a valid peer certificate is rejected, and a presented
//     per-runner bearer token must agree with it;
//   - without the requirement, a per-runner bearer token is acceptable on
//     EVERY runner route even when a runner CA exists (no peer-cert
//     requirement); a peer certificate that is presented must agree with
//     the bearer identity;
//   - with a CA and neither a bearer nor a peer certificate the request is
//     rejected: one of the two mechanisms must carry the identity;
//   - with neither mechanism configured the legacy shared bearer token is
//     the identity and no binding check applies.
//
// Revoked peer certificates (CRL, see crl.go) are rejected on EVERY
// identity path — the tier gate, registration and the per-route checks —
// but only AFTER the presented certificate has been verified against the
// runner CA: an arbitrary unverified serial must never reach the revocation
// store (lookup amplification) or be treated as a revoked identity.
// Revocation is a control-plane decision, distinct from the identity
// binding, and must not be bypassable by re-registering with a still-valid
// revoked certificate. resolved is the authenticated runner ID; constrained
// reports whether an identity comparison actually took place.
func (s *Server) resolveRunnerIdentity(r *http.Request, claimedID string) (resolved string, constrained bool, err error) {
	bearerID, hasBearer := s.runnerBearerID(r)
	if s.RunnerCA != nil && s.RequireRunnerClientCerts {
		peerID, err := s.peerRunnerID(r)
		if err != nil {
			return "", true, err
		}
		if err := s.checkPeerCertRevoked(r); err != nil {
			return "", true, err
		}
		if hasBearer && bearerID != peerID {
			return "", true, fmt.Errorf("bearer identity %q does not match certificate identity %q", bearerID, peerID)
		}
		if claimedID != "" && claimedID != peerID {
			return "", true, fmt.Errorf("certificate identity %q does not match runner id %q", peerID, claimedID)
		}
		return peerID, true, nil
	}
	if s.RunnerCA != nil {
		peerID, peerErr := s.peerRunnerID(r)
		havePeer := peerErr == nil
		if havePeer {
			if err := s.checkPeerCertRevoked(r); err != nil {
				return "", true, err
			}
		}
		switch {
		case hasBearer && havePeer:
			if bearerID != peerID {
				return "", true, fmt.Errorf("bearer identity %q does not match certificate identity %q", bearerID, peerID)
			}
			if claimedID != "" && claimedID != bearerID {
				return "", true, fmt.Errorf("bearer identity %q does not match runner id %q", bearerID, claimedID)
			}
			return bearerID, true, nil
		case hasBearer:
			if claimedID != "" && claimedID != bearerID {
				return "", true, fmt.Errorf("bearer identity %q does not match runner id %q", bearerID, claimedID)
			}
			return bearerID, true, nil
		case havePeer:
			if claimedID != "" && claimedID != peerID {
				return "", true, fmt.Errorf("certificate identity %q does not match runner id %q", peerID, claimedID)
			}
			return peerID, true, nil
		default:
			return "", true, fmt.Errorf("runner certificate or per-runner bearer token required")
		}
	}
	if hasBearer {
		if claimedID != "" && claimedID != bearerID {
			return "", true, fmt.Errorf("bearer identity %q does not match runner id %q", bearerID, claimedID)
		}
		return bearerID, true, nil
	}
	return "", false, nil
}

// checkPeerCertRevoked rejects a request whose presented TLS peer
// certificate is on the revocation list. No peer certificate (or no CA) is
// not an error here: the requirement decision belongs to
// resolveRunnerIdentity.
func (s *Server) checkPeerCertRevoked(r *http.Request) error {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0] == nil {
		return nil
	}
	serial := r.TLS.PeerCertificates[0].SerialNumber.Text(16)
	if s.certSerialRevoked(serial) {
		return fmt.Errorf("runner certificate %s is revoked", serial)
	}
	return nil
}

// bindRunnerIdentity binds a runner request to its authenticated identity
// (the shared resolveRunnerIdentity semantics): the per-runner bearer
// token's bound runner ID and/or the TLS peer certificate identity. When
// both mechanisms carry an identity they must agree; a claimed id must
// equal the authenticated one (an empty id skips the comparison, letting
// register() adopt the identity). With neither mechanism configured the
// legacy shared bearer token is the identity and no additional binding
// check applies.
func (s *Server) bindRunnerIdentity(r *http.Request, id string) error {
	_, _, err := s.resolveRunnerIdentity(r, id)
	return err
}

// verifyRunnerIdentity reports whether the request's authenticated identity
// matches the runner ID it acts for, using the SAME semantics as
// bindRunnerIdentity (see resolveRunnerIdentity), which also rejects revoked
// peer certificates (CRL, see crl.go). Lease tokens remain the capability;
// this pins the transport identity (per-runner bearer token and/or TLS peer
// certificate) to the claimed runner. With neither configured (legacy shared
// bearer mode) this accepts.
func (s *Server) verifyRunnerIdentity(r *http.Request, payloadRunnerID string) bool {
	resolved, constrained, err := s.resolveRunnerIdentity(r, payloadRunnerID)
	if err != nil {
		return false
	}
	if constrained && resolved != payloadRunnerID {
		return false
	}
	return true
}

// requestCertSerial resolves the certificate serial identifying the
// registering runner: the TLS peer certificate when runner mTLS is in
// play, otherwise the payload's cert_serial (bearer mode, where the serial
// is the profile binding key). An empty result means no binding.
//
// In bearer mode the payload serial is client-asserted, so it is honored
// only when it is not already owned by a DIFFERENT runner: a per-runner
// bearer token must not be able to claim another runner's serial, because
// that would hand the presenter the other runner's profile (labels,
// capabilities, capacity, repository ACL) and with it the other runner's
// leases. A serial already owned by the authenticated runner (legacy
// re-registration without a bearer identity) or not owned at all (first
// registration) is honored.
func (s *Server) requestCertSerial(r *http.Request, payloadSerial string) string {
	if s.RunnerCA != nil {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && r.TLS.PeerCertificates[0] != nil {
			return r.TLS.PeerCertificates[0].SerialNumber.Text(16)
		}
		return ""
	}
	serial := strings.TrimSpace(payloadSerial)
	if serial == "" {
		return ""
	}
	if bearerID, ok := s.runnerBearerID(r); ok {
		stolen, err := s.serialClaimedByOther(r.Context(), serial, bearerID)
		if err != nil || stolen {
			return ""
		}
	}
	return serial
}

// serialClaimedByOther reports whether a certificate serial is currently
// registered to a runner other than self. A store error fails closed
// (reported as claimed): the profile binding is only granted when ownership
// can be positively verified as absent or self.
func (s *Server) serialClaimedByOther(ctx context.Context, serial, self string) (bool, error) {
	if serial == "" {
		return false, nil
	}
	if s.DB != nil {
		runners, err := s.DB.ListRunners(ctx)
		if err != nil {
			return true, err
		}
		for _, ri := range runners {
			if strings.TrimSpace(ri.CertSerial) == serial && ri.ID != self {
				return true, nil
			}
		}
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ri := range s.runners {
		if strings.TrimSpace(ri.CertSerial) == serial && ri.ID != self {
			return true, nil
		}
	}
	return false, nil
}
