package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// Sentinel authorization errors returned by authorizeRunnerLease so every
// runner endpoint maps them to the same HTTP statuses.
var (
	errRunnerIdentityMismatch = errors.New("runner identity mismatch")
	errStaleLease             = errors.New("stale or invalid lease")
	// errLeaseLiveUnsupported reports that a DB-mode server is wired to a
	// store without the LiveLeaseStore capability. The application clock must
	// never decide a shared database's lease lifetime, so the gate fails
	// closed (503) instead of silently downgrading to replica-clock liveness.
	errLeaseLiveUnsupported = errors.New("store does not support database-clock lease liveness")
)

// authorizeRunnerLease is the single runner-endpoint authorization gate:
// it verifies the transport/certificate identity (verifyRunnerIdentity),
// resolves the addressed job (jobForLease, reading the job ID from the
// request path), and validates the ACTIVE lease. The expiry half of that
// validation runs in the store's own clock domain when the store offers
// LiveLeaseStore (DB mode: clock_timestamp()), so a skewed serving replica
// can neither reject a database-live lease nor admit an expired one; only a
// single-process store falls back to the application clock. It returns the
// authorized job, or one of:
//
//	errRunnerIdentityMismatch (403) — the presented identity does not bind
//	to the claimed runner, or the certificate is revoked;
//	storage.ErrNotFound (404) — the job does not exist;
//	errStaleLease (409) — the job is not running under this runner, lease
//	generation and token, or the lease is not live;
//	the underlying store error (500).
func (s *Server) authorizeRunnerLease(r *http.Request, runnerID, token string, generation int64) (model.Job, error) {
	if !s.verifyRunnerIdentity(r, runnerID) {
		return model.Job{}, errRunnerIdentityMismatch
	}
	jobID := r.PathValue("id")
	j, err := s.jobForLease(r.Context(), jobID)
	if err != nil {
		return model.Job{}, err
	}
	live, err := s.authorizeLiveLease(r.Context(), j, runnerID, token, generation)
	if err != nil {
		return model.Job{}, err
	}
	if !live {
		return model.Job{}, errStaleLease
	}
	return j, nil
}

// validLeaseIdentity validates everything about a lease EXCEPT its expiry:
// the job is running, the runner/generation match, and the presented token
// hashes to the stored digest. Expiry is decided separately by leaseLive so
// the clock domain can follow the store.
func (s *Server) validLeaseIdentity(j model.Job, runnerID, token string, generation int64) bool {
	if j.Status != model.StatusRunning {
		return false
	}
	if j.LeaseRunnerID != runnerID || j.LeaseGeneration != generation || len(j.LeaseTokenHash) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(hashLeaseToken(s.leaseKey, token), j.LeaseTokenHash) == 1
}

// leaseNow samples the server's lease clock; tests may install a skewed clock
// to prove that DB-mode liveness no longer depends on it.
func (s *Server) leaseNow() time.Time {
	if s.leaseClock != nil {
		return s.leaseClock().UTC()
	}
	return time.Now().UTC()
}

// leaseLive is the authoritative liveness decision for a job whose identity
// already validated: the store's own clock domain when it implements
// LiveLeaseStore (DB mode: clock_timestamp()), else the application clock
// (single-process stores, where skew is not a concept). A DB store WITHOUT
// the capability fails closed: falling back to the serving replica's clock
// would hand lease authority back to application time, the exact property
// this gate exists to remove.
func (s *Server) leaseLive(ctx context.Context, j model.Job, runnerID string, generation int64) (bool, error) {
	if s.DB != nil {
		live, ok := s.DB.(storage.LiveLeaseStore)
		if !ok {
			return false, errLeaseLiveUnsupported
		}
		return live.LeaseLive(ctx, j.ID, runnerID, generation)
	}
	return j.LeaseExpiresAt != nil && j.LeaseExpiresAt.After(s.leaseNow()), nil
}

// authorizeLiveLease combines identity validation with leaseLive and returns
// the store error (if any) so callers can fail closed with a 5xx instead of a
// misleading 409.
func (s *Server) authorizeLiveLease(ctx context.Context, j model.Job, runnerID, token string, generation int64) (bool, error) {
	if !s.validLeaseIdentity(j, runnerID, token, generation) {
		return false, nil
	}
	return s.leaseLive(ctx, j, runnerID, generation)
}

// writeLeaseAuthError renders a failed authorizeRunnerLease uniformly.
func (s *Server) writeLeaseAuthError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errRunnerIdentityMismatch):
		http.Error(w, err.Error(), http.StatusForbidden)
	case errors.Is(err, errStaleLease):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, storage.ErrNotFound):
		http.NotFound(w, r)
	default:
		s.internalError(w, r, err, "")
	}
}
