package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

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
// true when the caller may proceed.
func (s *Server) requireLeaseCommitSupport(w http.ResponseWriter, r *http.Request) bool {
	if s.leaseCommitSupported() {
		return true
	}
	s.logError("runner commit refused: store lacks transactional lease commits", "path", r.URL.Path)
	http.Error(w, "store does not support transactional lease commits", http.StatusServiceUnavailable)
	return false
}

// leaseActiveAtCommit reports whether the presented lease is still live when
// the handler is about to commit metadata. In DB mode the authoritative check
// runs inside the store's transactional predicate (storage.LeaseCommitStore),
// so this returns true and the store method is the enforcement point; the
// handler must still call the lease-fenced store method, never the plain one.
// A DB store WITHOUT that capability falls back to a handler-side re-read
// (best effort; the fallback is what the plain method's contract supports). In
// dev/memory mode it re-checks the in-memory job under s.mu, which is the
// server's transaction for the in-memory maps.
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
