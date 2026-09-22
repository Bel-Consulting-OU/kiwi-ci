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

// crlLookupTimeout bounds one durable cert_revocations lookup (the
// uncached cache-fill on the runner authentication path) so a stalled
// revocation store cannot pin an HTTP request after the client is gone.
// It is a var, not a const, so tests can shorten it; production keeps the
// 5s default.
var crlLookupTimeout = 5 * time.Second

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

// persistCRL durably writes the CRL to dataDir through marshalJSONFile, i.e.
// fsutil.AtomicWriteFile's unique temp file, checked file fsync/close, rename
// and parent-directory fsync. The error is a typed *fsutil.AtomicWriteError:
//
//   - a pre-rename failure (fsutil.NotPublished) means the mirror file still
//     holds the previous CRL and the revocation was definitely not published
//     there; the in-memory decision stays revoked regardless (memory may be
//     stricter than the mirror, never more permissive).
//   - a post-rename failure (fsutil.Renamed, the parent-directory fsync)
//     means the new CRL IS visible in the file with uncertified crash
//     durability. The caller must not roll the in-memory revocation back:
//     memory and the visible file both say revoked, and
//     noteFilePersistResult keeps readiness degraded until a later
//     successful persist reconciles.
//
// The FS-mode authoritative revocation path does not use this mirror:
// runnerDisable carries the CRL in the checked state snapshot and answers an
// opaque 503 when it cannot be persisted (see runnerDisable). Memory servers
// without a data dir keep the revocation only in process memory.
func (s *Server) persistCRL() error {
	if s.dataDir == "" {
		return nil
	}
	err := marshalJSONFile(filepath.Join(s.dataDir, crlFile), crlJSON(s.crl))
	s.noteFilePersistResult(err)
	return err
}

// mirrorRunnerCertRevoked records an ALREADY DURABLY COMMITTED certificate
// revocation in this replica's decision state: the in-memory CRL map, the
// DB-mode decision cache and the file mirror. The admin disable path calls
// it only after the store transaction committed the revocation, so a failure
// here can never authorize a revoked certificate on this replica; the file
// write is a dev-mode mirror and its failure is logged, never fatal (the
// durable authority is the cert_revocations row). The write itself is the
// same durable primitive as every other security-state file, so when it
// succeeds the mirror survives a crash; the log-only failure policy is about
// DB authority, not about the write's durability.
//
// The in-memory decision is never rolled back: the revocation is set before
// the write and a failure of any phase leaves it set, because memory may be
// stricter than the mirror but never more permissive. A post-rename
// directory-fsync failure (fsutil.Renamed) means the mirror file already
// shows the revocation with uncertified durability; persistCRL folds that
// into the shared degraded marker so /readiness and the lease gate fail
// closed until a later successful persist reconciles. The caller must NOT
// hold s.mu.
func (s *Server) mirrorRunnerCertRevoked(ri model.Runner) {
	if ri.CertSerial == "" {
		return
	}
	s.mu.Lock()
	if s.crl == nil {
		s.crl = map[string]string{}
	}
	s.crl[ri.CertSerial] = ri.ID
	persistErr := s.persistCRL()
	s.mu.Unlock()
	now := time.Now()
	s.crlMu.Lock()
	if s.crlCache == nil {
		s.crlCache = map[string]crlCacheEntry{}
	}
	s.crlCache[ri.CertSerial] = crlCacheEntry{revoked: true, at: now}
	s.crlMu.Unlock()
	if persistErr != nil {
		s.logError("crl: persist failed", "error", persistErr.Error())
	}
}

// certSerialRevoked reports whether a peer certificate serial is on the
// CRL. A locally observed revocation (the persisted in-process mirror,
// written by mirrorRunnerCertRevoked) is authoritative and never expires
// locally: it stays effective even if the durable revocation row could not be
// written, so a disable on this replica can never be undone by the cache
// TTL. DB mode additionally consults a short-TTL cache backed by the
// durable cert_revocations row, so a revocation written by any replica
// rejects the certificate on every other replica within crlCacheTTL.
//
// The durable lookup runs under the caller's ctx (the request context on
// the authentication path), bounded by crlLookupTimeout: a stalled store
// cannot pin the request past the client's cancellation. On any lookup
// failure the decision is fail-closed — revoked=true is returned TOGETHER
// WITH the error, so a caller that inspects the error rejects the
// certificate and a caller that ignores it still treats the serial as
// revoked (revoked/unknown must never authorize).
func (s *Server) certSerialRevoked(ctx context.Context, serial string) (bool, error) {
	if serial == "" {
		return false, nil
	}
	s.mu.Lock()
	_, locallyRevoked := s.crl[serial]
	s.mu.Unlock()
	if locallyRevoked {
		return true, nil
	}
	if s.DB != nil {
		if rev, ok := s.DB.(storage.CertRevocationStore); ok {
			now := time.Now()
			s.crlMu.Lock()
			if e, hit := s.crlCache[serial]; hit && now.Sub(e.at) < crlCacheTTL {
				s.crlMu.Unlock()
				return e.revoked, nil
			}
			s.crlMu.Unlock()
			lookupCtx, cancel := context.WithTimeout(ctx, crlLookupTimeout)
			defer cancel()
			revoked, err := rev.CertRevoked(lookupCtx, serial)
			if err != nil {
				s.logError("crl: cache fill failed", "serial", serial, "error", err.Error())
				// Fail closed on an unavailable revocation store: an
				// unreachable revocation source must never resurrect a
				// certificate it might have revoked. The local dev mirror
				// can only make the decision MORE strict, never less.
				return true, err
			}
			s.crlMu.Lock()
			if s.crlCache == nil {
				s.crlCache = map[string]crlCacheEntry{}
			}
			s.crlCache[serial] = crlCacheEntry{revoked: revoked, at: now}
			s.crlMu.Unlock()
			return revoked, nil
		}
	}
	return false, nil
}
