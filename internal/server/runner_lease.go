package server

import (
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
)

// authorizeRunnerLease is the single runner-endpoint authorization gate:
// it verifies the transport/certificate identity (verifyRunnerIdentity),
// resolves the addressed job (jobForLease, reading the job ID from the
// request path), and validates the active lease (validActiveLease). It
// returns the authorized job, or one of:
//
//	errRunnerIdentityMismatch (403) — the presented identity does not bind
//	to the claimed runner, or the certificate is revoked;
//	storage.ErrNotFound (404) — the job does not exist;
//	errStaleLease (409) — the job is not running under this runner, lease
//	generation and token;
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
	if !s.validActiveLease(j, runnerID, token, generation, time.Now().UTC()) {
		return model.Job{}, errStaleLease
	}
	return j, nil
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
