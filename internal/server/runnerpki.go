package server

import (
	"bytes"
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
// auto-CA path goes through the cluster key store's InstallOrLoad primitive:
// the CA material is ONE atomic cluster-key object ("runner-ca") shared by
// all replicas, never node-local dataDir files. A store that already holds
// material wins, so replicas racing to enroll converge on ONE CA instead of
// each minting its own. In DB mode without a cluster key store this refuses —
// a data-dir-local CA could never be shared with replicas.
func (s *Server) EnsureRunnerCA() error {
	if s.RunnerCA != nil {
		return nil
	}
	if s.ClusterKeys == nil {
		return fmt.Errorf("runner CA requires a cluster key store: configure --database-url (the DB-backed store), --cluster-key-dir (with --data-dir), or pass explicit --runner-ca-cert/--runner-ca-key")
	}
	if installer, ok := s.ClusterKeys.(ClusterKeyInstaller); ok {
		// Generate a candidate and let the store's create-if-absent
		// semantics decide: when a shared CA already exists it is returned
		// and the candidate is discarded, so every replica trusts one CA.
		candidate, err := createClusterKey(clusterKindRunnerCA)
		if err != nil {
			return err
		}
		b, _, err := installer.InstallOrLoad(clusterKindRunnerCA, candidate)
		if err != nil {
			return err
		}
		return s.setRunnerCAFromBlob(b)
	}
	b, err := s.ClusterKeys.LoadOrCreate(clusterKindRunnerCA)
	if err != nil {
		return err
	}
	return s.setRunnerCAFromBlob(b)
}

// SetRunnerCA installs a runner CA from explicit PEM file paths. When a
// shared cluster key store is configured, the material is atomically
// installed into it (create-if-absent) and compared against the shared
// runner CA the other replicas trust: bytes that disagree with the cluster's
// CA fail startup with a clear error instead of silently trusting a
// node-local CA that peers reject. The loaded CA always comes from the
// store's bytes, never from the local files alone. Without a cluster store
// (in-memory dev server) the explicit files remain the only CA source.
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
	if s.ClusterKeys == nil {
		s.RunnerCA = ca
		return nil
	}
	installer, ok := s.ClusterKeys.(ClusterKeyInstaller)
	if !ok {
		return fmt.Errorf("configured runner CA requires a cluster key store that supports install-or-load sharing; the configured store cannot share runner CA material")
	}
	explicit := runnerCAObject(certPEM, keyPEM)
	shared, created, err := installer.InstallOrLoad(clusterKindRunnerCA, explicit)
	if err != nil {
		return fmt.Errorf("install runner CA in the cluster key store: %w", err)
	}
	if !created && !runnerCAObjectsAgree(shared, explicit) {
		return fmt.Errorf("configured runner CA disagrees with cluster runner CA: the shared cluster key store already holds different runner CA material, so --runner-ca-cert/--runner-ca-key would make this replica trust certificates the other replicas reject; use the shared CA material or remove the divergent files")
	}
	return s.setRunnerCAFromBlob(shared)
}

// runnerCAObject joins a runner CA certificate PEM and private key PEM into
// the canonical single cluster-key object (cert PEM + NUL + key PEM).
func runnerCAObject(certPEM, keyPEM []byte) []byte {
	obj := make([]byte, 0, len(certPEM)+1+len(keyPEM))
	obj = append(obj, certPEM...)
	obj = append(obj, 0)
	obj = append(obj, keyPEM...)
	return obj
}

// runnerCAObjectsAgree reports whether two runner CA cluster objects
// identify the same CA. Byte-identical objects agree trivially; otherwise
// both are parsed and compared by certificate DER, so PEM formatting
// differences and the legacy separator-less object layout cannot turn the
// same CA into a startup failure while a genuinely different CA always
// disagrees.
func runnerCAObjectsAgree(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	certA, keyA, errA := splitRunnerCAPEMs(a)
	certB, keyB, errB := splitRunnerCAPEMs(b)
	if errA != nil || errB != nil {
		return false
	}
	caA, errA := runnerpki.LoadCA(certA, keyA)
	caB, errB := runnerpki.LoadCA(certB, keyB)
	return errA == nil && errB == nil && bytes.Equal(caA.Cert.Raw, caB.Cert.Raw)
}

// enroll signs a runner CSR after the enrollment token check already
// performed by auth(). A request authenticated with a single-use grant
// instead of the static enroll token has the grant consumed here (atomic
// single-use, expiry and allowed-label validation) before any certificate
// is signed. The issued certificate binds the runner to its authenticated
// ID; the CSR's own identity fields are discarded (server-synthesized
// identity, see runnerpki.SignRunnerCSR).
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
	if s.RunnerEnrollToken == "" || !tokenEqual(tok, s.RunnerEnrollToken) {
		// Not the static enrollment token: the request must have been
		// gated by a grant. Consume it (single-use + expiry + allowed
		// labels) before signing.
		if err := s.consumeEnrollGrant(r.Context(), tok, in.Labels); err != nil {
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
	bearerID, hasBearer, bErr := s.runnerBearerID(r)
	if bErr != nil {
		return "", true, bErr
	}
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
// resolveRunnerIdentity. The lookup runs under the request context (bounded
// by crlLookupTimeout), so a stalled revocation store can neither pin the
// request after the client is gone nor authorize the certificate: a lookup
// failure is an identity error (fail closed).
func (s *Server) checkPeerCertRevoked(r *http.Request) error {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0] == nil {
		return nil
	}
	serial := r.TLS.PeerCertificates[0].SerialNumber.Text(16)
	revoked, err := s.certSerialRevoked(r.Context(), serial)
	if err != nil {
		return fmt.Errorf("runner certificate %s revocation check failed: %w", serial, err)
	}
	if revoked {
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

// runnerProfileBinding names the identity a registering request was
// AUTHENTICATED with, which is the only thing allowed to select a runner
// profile. At most one field is set:
//
//   - Serial: a certificate serial safe to use as a binding key. It is the
//     serial of the TLS peer certificate AFTER that certificate verified
//     against the runner CA (mTLS identity), or — in the legacy/dev
//     shared-token mode only — the client-asserted payload serial.
//   - RunnerID: the authenticated per-runner bearer identity, resolved
//     through the durable runner_profile_links binding.
type runnerProfileBinding struct {
	Serial   string
	RunnerID string
}

// resolveRegistrationProfileBinding derives the profile-binding identity
// from the transport identity that AUTHENTICATED the request. It is the
// ONLY place a registration profile key is chosen, and it NEVER honors the
// client-asserted cert_serial while a per-runner identity mode is active:
//
//   - mTLS: the serial of the VERIFIED TLS peer certificate. peerRunnerID
//     verifies the chain against the runner CA, so a presented-but-
//     unverified certificate contributes nothing (an arbitrary client
//     certificate must not select another runner's serial binding).
//   - per-runner bearer token (with or without a runner CA): the
//     authenticated runner ID. The payload cert_serial is ignored, so a
//     bearer token can never claim another runner's certificate-serial
//     binding. This replaces the old payload-serial ownership scan, which
//     was client-asserted and racy: two concurrent bearers both saw the
//     serial "unclaimed" and both inherited the profile.
//   - legacy/dev shared-token mode (no runner CA and no per-runner token
//     resolved): the payload serial is the dev binding key, honored only
//     while no OTHER runner row currently holds it (serialClaimedByOther).
//     Production bearer mode always has per-runner credentials, so this
//     branch is unreachable there.
//
// self is the runner ID the registration acts for (the authenticated ID, or
// the claimed/minted one in legacy mode); it only scopes the legacy
// uniqueness check to "owned by someone else". An auth-store failure yields
// an empty binding: registration continues WITHOUT a profile and fails
// closed under RequireProfiles.
func (s *Server) resolveRegistrationProfileBinding(r *http.Request, self, payloadSerial string) runnerProfileBinding {
	if s.RunnerCA != nil {
		// mTLS identity: only a certificate that verified against the
		// runner CA may contribute its serial.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && r.TLS.PeerCertificates[0] != nil {
			if _, err := s.peerRunnerID(r); err == nil {
				return runnerProfileBinding{Serial: r.TLS.PeerCertificates[0].SerialNumber.Text(16)}
			}
		}
		if bearerID, ok, err := s.runnerBearerID(r); err == nil && ok {
			return runnerProfileBinding{RunnerID: bearerID}
		}
		return runnerProfileBinding{}
	}
	if bearerID, ok, err := s.runnerBearerID(r); err == nil && ok {
		return runnerProfileBinding{RunnerID: bearerID}
	} else if err != nil {
		// Identity-store failure: no binding, no profile (fail closed).
		return runnerProfileBinding{}
	}
	serial := strings.TrimSpace(payloadSerial)
	if serial == "" {
		return runnerProfileBinding{}
	}
	if claimed, err := s.serialClaimedByOther(r.Context(), serial, self); err != nil || claimed {
		return runnerProfileBinding{}
	}
	return runnerProfileBinding{Serial: serial}
}

// serialClaimedByOther reports whether a certificate serial is currently
// registered to a runner other than self. It is a DEV/LEGACY uniqueness
// helper ONLY (the legacy shared-token registration path), so two dev
// runners do not both record one payload serial. It is NOT an authorization
// gate: no profile is ever selected from a client-asserted serial, so a
// false "unclaimed" answer cannot hand the caller a profile — profile
// selection for per-runner identities comes exclusively from the
// runner_profile_links PRIMARY KEY binding. A store error fails closed
// (reported as claimed).
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
