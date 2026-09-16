package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const crlFile = "runner-crl.json"

// crlCacheTTL bounds how long a replica caches a DB-backed revocation
// decision before re-consulting the durable cert_revocations row.
const crlCacheTTL = 30 * time.Second

// crlJSON is the on-disk CRL format: certificate serial (decimal hex from
// x509 serial.Text(16)) -> runner ID, written atomically under dataDir.
type crlJSON map[string]string

// crlCacheEntry is one cached revocation decision for DB mode.
type crlCacheEntry struct {
	revoked bool
	at      time.Time
}

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
// revocation list. In DB mode the durable cert_revocations row is written
// transactionally so every replica rejects the serial; the in-memory map
// and file CRL remain the dev-mode mirror. Revocation is permanent:
// re-enabling a runner does not un-revoke its certificate — the runner must
// re-enroll to obtain fresh credentials.
func (s *Server) revokeRunnerCert(ri model.Runner, actor string) {
	if ri.CertSerial == "" {
		return
	}
	s.mu.Lock()
	s.crl[ri.CertSerial] = ri.ID
	persistErr := s.persistCRL()
	s.mu.Unlock()
	if s.DB != nil {
		if rev, ok := s.DB.(storage.CertRevocationStore); ok {
			if err := rev.RevokeCert(context.Background(), ri.CertSerial, ri.ID, "runner revoked"); err != nil {
				s.logError("crl: durable revoke failed", "serial", ri.CertSerial, "error", err.Error())
			}
		}
	}
	if persistErr != nil {
		s.logError("crl: persist failed", "error", persistErr.Error())
	}
	s.auditLocked("runner.cert_revoked", actor, "", "", "runner certificate serial revoked", map[string]string{"runner": ri.ID, "serial": ri.CertSerial})
}

// certSerialRevoked reports whether a peer certificate serial is on the
// CRL. Memory mode consults the in-process map; DB mode consults a
// short-TTL cache backed by the durable cert_revocations row, so a
// revocation written by any replica rejects the certificate on every other
// replica within crlCacheTTL.
func (s *Server) certSerialRevoked(serial string) bool {
	if serial == "" {
		return false
	}
	if s.DB != nil {
		if rev, ok := s.DB.(storage.CertRevocationStore); ok {
			now := time.Now()
			s.crlMu.Lock()
			if e, hit := s.crlCache[serial]; hit && now.Sub(e.at) < crlCacheTTL {
				s.crlMu.Unlock()
				return e.revoked
			}
			s.crlMu.Unlock()
			revoked, err := rev.CertRevoked(context.Background(), serial)
			if err != nil {
				s.logError("crl: cache fill failed", "serial", serial, "error", err.Error())
				// Fail closed on an unavailable revocation store.
				s.mu.Lock()
				_, known := s.crl[serial]
				s.mu.Unlock()
				return known
			}
			s.crlMu.Lock()
			if s.crlCache == nil {
				s.crlCache = map[string]crlCacheEntry{}
			}
			s.crlCache[serial] = crlCacheEntry{revoked: revoked, at: now}
			s.crlMu.Unlock()
			return revoked
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.crl[serial]
	return ok
}
