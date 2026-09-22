package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// profileForRunnerBinding resolves the profile linked to the authenticated
// registration identity (see resolveRegistrationProfileBinding): the
// runner-ID binding for per-runner bearer identities, the certificate-serial
// binding for mTLS and legacy serials.
func (s *Server) profileForRunnerBinding(ctx context.Context, b runnerProfileBinding) (model.RunnerProfile, bool, error) {
	if b.RunnerID != "" {
		return s.profileForRunnerID(ctx, b.RunnerID)
	}
	return s.profileForSerial(ctx, b.Serial)
}

// profileForRunnerID resolves the durable runner-ID -> profile binding: the
// runner_profile_links row in DB mode, the fs-snapshot mirror otherwise. A
// store without the RunnerProfileLinkStore surface, an unbound runner and a
// dangling binding all resolve to not-found, so registration fails closed
// under RequireProfiles instead of inheriting anything.
//
// Lease-time live resolution (the SQL claim, the DB scheduler's
// effectiveRunner, the memory-mode liveRunnerLocked and the queue explainers)
// resolves the runner-ID binding through the same shared precedence as the
// certificate-serial binding (storage.ResolveLiveProfileBinding), so a
// profile edit takes effect on the next lease without re-registration; a
// dangling binding — runner-ID included — DENIES the lease, exactly like a
// dangling certificate binding, so a deleted profile can never keep applying
// through the registration snapshot.
func (s *Server) profileForRunnerID(ctx context.Context, runnerID string) (model.RunnerProfile, bool, error) {
	if runnerID == "" {
		return model.RunnerProfile{}, false, nil
	}
	if s.DB != nil {
		ls, ok := s.DB.(storage.RunnerProfileLinkStore)
		if !ok {
			return model.RunnerProfile{}, false, nil
		}
		return ls.ProfileForRunnerID(ctx, runnerID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profileID, ok := s.runnerProfiles[runnerID]
	if !ok {
		return model.RunnerProfile{}, false, nil
	}
	p, ok := s.profiles[profileID]
	if !ok {
		// A binding whose profile vanished denies the profile (fail closed),
		// matching the DB join.
		return model.RunnerProfile{}, false, nil
	}
	return p, true, nil
}

// errUnknownProfile marks a binding request naming a profile that does not
// exist: it is the only linkRunnerProfile failure that is a client error.
var errUnknownProfile = errors.New("unknown runner profile")

// linkRunnerProfile binds a runner ID to a profile (admin operation). The
// profile must exist before a runner may bind to it; the binding itself is
// the PRIMARY KEY fact per-runner bearer identities resolve through.
func (s *Server) linkRunnerProfile(ctx context.Context, runnerID, profileID string) error {
	if runnerID == "" {
		return fmt.Errorf("runner id is required")
	}
	if _, err := s.getProfile(ctx, profileID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("%w %q", errUnknownProfile, profileID)
		}
		return err
	}
	if s.DB != nil {
		ls, ok := s.DB.(storage.RunnerProfileLinkStore)
		if !ok {
			return fmt.Errorf("store does not support runner profile links")
		}
		return ls.LinkRunnerProfile(ctx, runnerID, profileID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runnerProfiles == nil {
		s.runnerProfiles = map[string]string{}
	}
	prev, had := s.runnerProfiles[runnerID]
	s.runnerProfiles[runnerID] = profileID
	if perr := s.persistCheckedErrLocked("runner_profile.link"); perr != nil {
		// Durability first: a binding the snapshot does not contain must not
		// survive in memory, and a failed persist is a server-side failure
		// (503), never a 400.
		if had {
			s.runnerProfiles[runnerID] = prev
		} else {
			delete(s.runnerProfiles, runnerID)
		}
		return notDurable(perr)
	}
	return nil
}

// unlinkRunnerProfile removes a runner's binding (admin operation) and
// revokes the profile-derived registration-snapshot attributes it supplied,
// in one locked step that is mirrored into the fs snapshot: after the call,
// neither the binding nor s.runners carries the removed profile's grants.
// It is idempotent: an unbound runner with no marked snapshot is a
// successful no-op (and does not touch the snapshot), so an admin can always
// assert the unbound state. The DB path delegates the same revocation to the
// store's UnlinkRunnerProfile.
func (s *Server) unlinkRunnerProfile(ctx context.Context, runnerID string) error {
	if runnerID == "" {
		return fmt.Errorf("runner id is required")
	}
	if s.DB != nil {
		ls, ok := s.DB.(storage.RunnerProfileLinkStore)
		if !ok {
			return fmt.Errorf("store does not support runner profile links")
		}
		return ls.UnlinkRunnerProfile(ctx, runnerID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.runnerProfiles[runnerID]
	prevRunner, hadRunner := s.runners[runnerID]
	clearedRunner, runnerChanged := prevRunner, false
	if hadRunner {
		clearedRunner, runnerChanged = storage.ClearProfileDerivedRunnerFields(prevRunner)
	}
	if !had && !runnerChanged {
		return nil
	}
	delete(s.runnerProfiles, runnerID)
	if runnerChanged {
		s.runners[runnerID] = clearedRunner
	}
	if perr := s.persistCheckedErrLocked("runner_profile.unlink"); perr != nil {
		// Durability first: the binding AND the snapshot fields must roll
		// back together, or memory would keep a revocation the snapshot
		// does not contain.
		if had {
			s.runnerProfiles[runnerID] = prev
		}
		if runnerChanged {
			s.runners[runnerID] = prevRunner
		}
		return notDurable(perr)
	}
	return nil
}

// bindRunnerProfileRunner implements PUT
// /api/v1/runner-profiles/{id}/runner/{runnerID}: the admin-tier binding a
// per-runner bearer identity resolves its profile through at registration.
// The runner must not exist yet: pre-provisioning a binding before the
// runner's first registration is the intended flow.
func (s *Server) bindRunnerProfileRunner(w http.ResponseWriter, r *http.Request) {
	if !s.requireAction(w, r, auth.ActionAdmin, "", false) {
		return
	}
	profileID := r.PathValue("id")
	runnerID := strings.TrimSpace(r.PathValue("runnerID"))
	if runnerID == "" || len(runnerID) > maxRunnerIDLen || !validRunnerID(runnerID) {
		http.Error(w, "valid runner_id is required", http.StatusBadRequest)
		return
	}
	if err := s.linkRunnerProfile(r.Context(), runnerID, profileID); err != nil {
		// A durability failure is not a client error: fail closed with 503
		// so the caller retries instead of treating the binding as rejected.
		var nd *stateNotDurableError
		if errors.As(err, &nd) {
			s.serverError(w, r, http.StatusServiceUnavailable, nd, "state not durable")
			return
		}
		if errors.Is(err, errUnknownProfile) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Anything else (store error, missing store surface) is a
		// server-side failure, never a rejected binding.
		s.internalError(w, r, err, "")
		return
	}
	s.auditLocked("runner_profile.link", actorFrom(r), "", "", "runner profile bound to runner", map[string]string{"profile": profileID, "runner": runnerID})
	writeJSON(w, http.StatusOK, map[string]string{"runner_id": runnerID, "profile_id": profileID})
}

// unbindRunnerProfileRunner implements DELETE
// /api/v1/runner-profiles/{id}/runner/{runnerID}: it removes the runner's
// binding AND revokes the profile-derived registration-snapshot attributes
// in the same store operation, so the removed profile stops applying to the
// very next lease (not only after a re-registration); the next registration
// is unprofiled and fails closed under RequireProfiles. Unbinding an unbound
// runner is a 200 no-op.
func (s *Server) unbindRunnerProfileRunner(w http.ResponseWriter, r *http.Request) {
	if !s.requireAction(w, r, auth.ActionAdmin, "", false) {
		return
	}
	profileID := r.PathValue("id")
	runnerID := strings.TrimSpace(r.PathValue("runnerID"))
	if runnerID == "" || len(runnerID) > maxRunnerIDLen || !validRunnerID(runnerID) {
		http.Error(w, "valid runner_id is required", http.StatusBadRequest)
		return
	}
	if err := s.unlinkRunnerProfile(r.Context(), runnerID); err != nil {
		var nd *stateNotDurableError
		if errors.As(err, &nd) {
			s.serverError(w, r, http.StatusServiceUnavailable, nd, "state not durable")
			return
		}
		s.internalError(w, r, err, "")
		return
	}
	s.auditLocked("runner_profile.unlink", actorFrom(r), "", "", "runner profile unbound from runner", map[string]string{"profile": profileID, "runner": runnerID})
	writeJSON(w, http.StatusOK, map[string]any{"runner_id": runnerID, "profile_id": profileID, "unlinked": true})
}
