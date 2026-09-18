package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// runnerProfileIDRegexp matches the profile ID grammar: a leading
// alphanumeric followed by up to 63 alphanumerics, dots, underscores or
// hyphens (admin-facing slugs like "macos-builders").
var runnerProfileIDRegexp = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// profileCapabilities are the only capability values a profile may declare.
var profileCapabilities = map[string]bool{"native": true, "container": true, "tart": true}

// validateRunnerProfile enforces the profile invariants: ID grammar, label
// grammar, region grammar, capability values, capacity bounds and finite
// non-negative cost/energy rates.
func validateRunnerProfile(p *model.RunnerProfile) error {
	if p == nil {
		return fmt.Errorf("runner profile is required")
	}
	if p.ID == "" || !runnerProfileIDRegexp.MatchString(p.ID) {
		return fmt.Errorf("invalid profile id %q", p.ID)
	}
	for _, l := range p.Labels {
		if !runnerLabelRegexp.MatchString(l) {
			return fmt.Errorf("invalid runner label %q", l)
		}
	}
	if p.Region != "" && !runnerRegionRegexp.MatchString(p.Region) {
		return fmt.Errorf("invalid runner region %q", p.Region)
	}
	if p.MaxCapacity < 0 || p.MaxCapacity > maxRunnerCapacity {
		return fmt.Errorf("max_capacity must be in 0..%d, got %d", maxRunnerCapacity, p.MaxCapacity)
	}
	for _, c := range p.Capabilities {
		if !profileCapabilities[c] {
			return fmt.Errorf("invalid runner capability %q (want native, container or tart)", c)
		}
	}
	for _, r := range p.Repositories {
		if strings.TrimSpace(r) == "" {
			return fmt.Errorf("invalid empty repository id in profile")
		}
	}
	if !finiteNonNegative(p.CostPerHour) {
		return fmt.Errorf("cost_per_hour must be finite and non-negative, got %v", p.CostPerHour)
	}
	if !finiteNonNegative(p.PowerWatts) {
		return fmt.Errorf("power_watts must be finite and non-negative, got %v", p.PowerWatts)
	}
	return nil
}

// upsertProfile persists a profile: the durable ProfileStore in DB mode,
// the in-memory map (mirrored into the fs snapshot) otherwise.
func (s *Server) upsertProfile(ctx context.Context, p model.RunnerProfile) error {
	if s.DB != nil {
		ps, ok := s.DB.(storage.ProfileStore)
		if !ok {
			return fmt.Errorf("store does not support runner profiles")
		}
		return ps.UpsertProfile(ctx, p)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.profiles == nil {
		s.profiles = map[string]model.RunnerProfile{}
	}
	prev, had := s.profiles[p.ID]
	s.profiles[p.ID] = p
	if perr := s.persistCheckedErrLocked("runner_profile.upsert"); perr != nil {
		// Durability first: restore the previous profile (or remove the
		// fresh entry) so the next successful persist cannot commit a
		// profile the admin was told failed.
		if had {
			s.profiles[p.ID] = prev
		} else {
			delete(s.profiles, p.ID)
		}
		return perr
	}
	return nil
}

// getProfile resolves one profile.
func (s *Server) getProfile(ctx context.Context, id string) (model.RunnerProfile, error) {
	if s.DB != nil {
		ps, ok := s.DB.(storage.ProfileStore)
		if !ok {
			return model.RunnerProfile{}, fmt.Errorf("store does not support runner profiles")
		}
		return ps.GetProfile(ctx, id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[id]
	if !ok {
		return model.RunnerProfile{}, storage.ErrNotFound
	}
	return p, nil
}

// listProfiles returns every profile.
func (s *Server) listProfiles(ctx context.Context) ([]model.RunnerProfile, error) {
	if s.DB != nil {
		ps, ok := s.DB.(storage.ProfileStore)
		if !ok {
			return nil, fmt.Errorf("store does not support runner profiles")
		}
		return ps.ListProfiles(ctx)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.RunnerProfile, 0, len(s.profiles))
	for _, p := range s.profiles {
		out = append(out, p)
	}
	return out, nil
}

// bindCertProfile links a certificate serial to a profile. The profile must
// exist before a serial may bind to it.
func (s *Server) bindCertProfile(ctx context.Context, serial, profileID string) error {
	if _, err := s.getProfile(ctx, profileID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("unknown profile %q", profileID)
		}
		return err
	}
	if s.DB != nil {
		return s.DB.(storage.ProfileStore).BindCertProfile(ctx, serial, profileID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.certProfiles == nil {
		s.certProfiles = map[string]string{}
	}
	prev, had := s.certProfiles[serial]
	s.certProfiles[serial] = profileID
	if perr := s.persistCheckedErrLocked("runner_profile.bind"); perr != nil {
		// Durability first: a binding the snapshot does not contain must not
		// survive in memory, and a failed persist is a server-side failure
		// (503), never a 400.
		if had {
			s.certProfiles[serial] = prev
		} else {
			delete(s.certProfiles, serial)
		}
		return notDurable(perr)
	}
	return nil
}

// profileForSerial resolves the profile bound to a certificate serial
// (durable cert_profile_links in DB mode, the fs snapshot otherwise).
func (s *Server) profileForSerial(ctx context.Context, serial string) (model.RunnerProfile, bool, error) {
	if serial == "" {
		return model.RunnerProfile{}, false, nil
	}
	if s.DB != nil {
		ps, ok := s.DB.(storage.ProfileStore)
		if !ok {
			return model.RunnerProfile{}, false, nil
		}
		return ps.ProfileForSerial(ctx, serial)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.certProfiles[serial]
	if !ok {
		return model.RunnerProfile{}, false, nil
	}
	p, ok := s.profiles[id]
	return p, ok, nil
}

// intersectCapabilities returns the elements of profile caps that are also
// in reported, preserving profile order. The profile is the ceiling; the
// runner's hardware-discovered capabilities can only narrow it.
func intersectCapabilities(profile, reported []string) []string {
	if len(profile) == 0 || len(reported) == 0 {
		return nil
	}
	have := map[string]bool{}
	for _, c := range reported {
		have[c] = true
	}
	out := make([]string, 0, len(profile))
	for _, c := range profile {
		if have[c] {
			out = append(out, c)
		}
	}
	return out
}

// runnerProfiles handler: POST /api/v1/runner-profiles (admin or
// policy_manage) creates a profile; the ID may be chosen by the caller or
// left empty to mint a canonical control-plane ID.
func (s *Server) createRunnerProfile(w http.ResponseWriter, r *http.Request) {
	if !s.requireAction(w, r, auth.ActionPolicyManage, "", false) {
		return
	}
	var in model.RunnerProfile
	if !decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.ID) == "" {
		id, err := newID()
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		in.ID = id
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = time.Now().UTC()
	}
	if err := validateRunnerProfile(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.upsertProfile(r.Context(), in); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.auditLocked("runner_profile.upsert", actorFrom(r), "", "", "runner profile created", map[string]string{"profile": in.ID})
	writeJSON(w, http.StatusCreated, in)
}

func (s *Server) getRunnerProfile(w http.ResponseWriter, r *http.Request) {
	if !s.requireAction(w, r, auth.ActionPolicyManage, "", false) {
		return
	}
	p, err := s.getProfile(r.Context(), r.PathValue("id"))
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) listRunnerProfiles(w http.ResponseWriter, r *http.Request) {
	if !s.requireAction(w, r, auth.ActionPolicyManage, "", false) {
		return
	}
	out, err := s.listProfiles(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if out == nil {
		out = []model.RunnerProfile{}
	}
	writeJSON(w, http.StatusOK, out)
}

// updateRunnerProfile implements PUT /api/v1/runner-profiles/{id}: full
// replacement of the profile's scheduling attributes.
func (s *Server) updateRunnerProfile(w http.ResponseWriter, r *http.Request) {
	if !s.requireAction(w, r, auth.ActionPolicyManage, "", false) {
		return
	}
	var in model.RunnerProfile
	if !decode(w, r, &in) {
		return
	}
	in.ID = r.PathValue("id")
	if in.ID == "" {
		http.Error(w, "profile id is required", http.StatusBadRequest)
		return
	}
	if _, err := s.getProfile(r.Context(), in.ID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), 500)
		return
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = time.Now().UTC()
	}
	if err := validateRunnerProfile(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.upsertProfile(r.Context(), in); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.auditLocked("runner_profile.upsert", actorFrom(r), "", "", "runner profile updated", map[string]string{"profile": in.ID})
	writeJSON(w, http.StatusOK, in)
}

// bindRunnerProfileCert implements PUT
// /api/v1/runner-profiles/{id}/cert/{serial}: the certificate serial's
// runner inherits the profile at registration.
func (s *Server) bindRunnerProfileCert(w http.ResponseWriter, r *http.Request) {
	if !s.requireAction(w, r, auth.ActionPolicyManage, "", false) {
		return
	}
	profileID := r.PathValue("id")
	serial := strings.TrimSpace(r.PathValue("serial"))
	if serial == "" {
		http.Error(w, "certificate serial is required", http.StatusBadRequest)
		return
	}
	if err := s.bindCertProfile(r.Context(), serial, profileID); err != nil {
		// A durability failure is not a client error: fail closed with 503
		// so the caller retries instead of treating the binding as rejected.
		var nd *stateNotDurableError
		if errors.As(err, &nd) {
			http.Error(w, nd.Error(), http.StatusServiceUnavailable)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.auditLocked("runner_profile.bind", actorFrom(r), "", "", "runner profile bound to certificate", map[string]string{"profile": profileID, "serial": serial})
	writeJSON(w, http.StatusOK, map[string]string{"serial": serial, "profile_id": profileID})
}
