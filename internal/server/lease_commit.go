package server

import (
	"context"
	"errors"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

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
		if _, ok := s.DB.(storage.LeaseCommitStore); ok {
			return true
		}
		j, err := s.DB.GetJob(ctx, jobID)
		return err == nil && s.validActiveLease(j, runnerID, token, gen, time.Now().UTC())
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
