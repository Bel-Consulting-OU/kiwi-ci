package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// errLeaseCommitUnsupported reports that the configured DB store has no
// transactional lease-commit capability (storage.LeaseCommitStore). Every
// runner-produced metadata commit is REFUSED with this typed error (HTTP 503)
// rather than being downgraded to a handler-side check plus a plain write:
// the plain write cannot make the predicate and the write atomic, so a
// concurrent revoke could still commit. There is no best-effort path.
var errLeaseCommitUnsupported = errors.New("store does not support transactional lease commits")

// leaseCommitSupported reports whether runner-produced commits can be
// authorized transactionally by the configured store. Memory and fs modes are
// supported through s.mu; DB mode requires storage.LeaseCommitStore.
func (s *Server) leaseCommitSupported() bool {
	if s.DB == nil {
		return true
	}
	_, ok := s.DB.(storage.LeaseCommitStore)
	return ok
}

// requireLeaseCommitSupport fails the request with 503 when the configured DB
// store cannot authorize runner-produced commits transactionally. It returns
// true when the caller may proceed. Handlers call it immediately after
// request/lease authorization — before reading a body, taking a staging
// reservation or writing anything — so a static wiring error is cheap and
// deterministic instead of surfacing after an expensive staged upload; the
// commit-site assertions remain as defense in depth.
func (s *Server) requireLeaseCommitSupport(w http.ResponseWriter, r *http.Request) bool {
	if s.leaseCommitSupported() {
		return true
	}
	s.logError("runner commit refused: store lacks transactional lease commits", "path", r.URL.Path)
	// The fixed body text is intentionally literal: /internal/server has a
	// static contract test forbidding raw error strings in 5xx bodies.
	http.Error(w, "store does not support transactional lease commits", http.StatusServiceUnavailable)
	return false
}

// leaseActiveAtCommit reports whether the presented lease is still live when
// the handler is about to commit metadata. In DB mode the authoritative check
// runs inside the store's transactional predicate (storage.LeaseCommitStore),
// so this returns true and the store method is the enforcement point; the
// handler must still call the lease-fenced store method, never the plain one,
// and a DB store WITHOUT that capability is refused before this point
// (leaseCommitSupported/requireLeaseCommitSupport) — there is no best-effort
// fallback. In dev/memory mode it re-checks the in-memory job under s.mu,
// which is the server's transaction for the in-memory maps.
func (s *Server) leaseActiveAtCommit(ctx context.Context, jobID, runnerID, token string, gen int64) bool {
	if s.DB != nil {
		// DB mode is enforced by the transactional predicate; a store without
		// the capability is refused before this point (leaseCommitSupported).
		return s.leaseCommitSupported()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	return ok && s.validActiveLease(j, runnerID, token, gen, time.Now().UTC())
}

// leaseLostAtCommit reports whether a store error is a commit-time lease
// predicate failure (the write committed nothing).
func leaseLostAtCommit(err error) bool {
	return errors.Is(err, storage.ErrLeaseLost)
}
