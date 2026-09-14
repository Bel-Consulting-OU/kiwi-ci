package server

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const crlFile = "runner-crl.json"

// crlJSON is the on-disk CRL format: certificate serial (decimal hex from
// x509 serial.Text(16)) -> runner ID, written atomically under dataDir.
type crlJSON map[string]string

// loadCRL loads the persisted runner certificate revocation list from
// dataDir. A missing file leaves an empty CRL (nothing revoked yet).
func (s *Server) loadCRL(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(dataDir, crlFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var list crlJSON
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	s.crl = map[string]string(list)
	return nil
}

// persistCRL atomically writes the CRL to dataDir. Memory servers without
// a data dir keep the revocation only in process memory.
func (s *Server) persistCRL() error {
	if s.dataDir == "" {
		return nil
	}
	return marshalJSONFile(filepath.Join(s.dataDir, crlFile), crlJSON(s.crl))
}

// revokeRunnerCert records the runner's certificate serial in the
// revocation list and persists it. Revocation is permanent: re-enabling a
// runner does not un-revoke its certificate — the runner must re-enroll to
// obtain fresh credentials.
func (s *Server) revokeRunnerCert(ri model.Runner, actor string) {
	if ri.CertSerial == "" {
		return
	}
	s.mu.Lock()
	s.crl[ri.CertSerial] = ri.ID
	persistErr := s.persistCRL()
	s.mu.Unlock()
	if persistErr != nil {
		s.logError("crl: persist failed", "error", persistErr.Error())
	}
	s.auditLocked("runner.cert_revoked", actor, "", "", "runner certificate serial revoked", map[string]string{"runner": ri.ID, "serial": ri.CertSerial})
}

// certSerialRevoked reports whether a peer certificate serial is on the
// CRL.
func (s *Server) certSerialRevoked(serial string) bool {
	if serial == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.crl[serial]
	return ok
}
