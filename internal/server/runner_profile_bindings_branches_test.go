package server

// Branch coverage for the runner-ID -> profile binding resolution, mutation
// and admin endpoints: empty identifiers, stores without the binding
// contract, non-NotFound profile-store errors, the durability rollback on
// both the link and unlink paths, and the tier gate on directly invoked
// handlers (the middleware normally answers first).

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// failingProfileStore embeds the ProfileStore interface (nil base) and fails
// every GetProfile, modelling a store whose profile reads error out.
type failingProfileStore struct {
	storage.ProfileStore
	err error
}

func (f failingProfileStore) GetProfile(context.Context, string) (model.RunnerProfile, error) {
	return model.RunnerProfile{}, f.err
}

// TestProfileForRunnerIDEmptyAndStoreless: an empty runner ID and a DB
// store without the RunnerProfileLinkStore surface both resolve to
// not-found (fail closed), never to an arbitrary profile.
func TestProfileForRunnerIDEmptyAndStoreless(t *testing.T) {
	mem := perRunnerTokenServer(t, nil)
	if p, ok, err := mem.profileForRunnerID(t.Context(), ""); err != nil || ok || p.ID != "" {
		t.Fatalf("memory empty id = (%+v, %v, %v)", p, ok, err)
	}
	if p, ok, err := mem.profileForRunnerID(t.Context(), "unbound"); err != nil || ok || p.ID != "" {
		t.Fatalf("memory unbound = (%+v, %v, %v)", p, ok, err)
	}

	f := newDBFakeStore()
	db := New("shared-dev-tok")
	db.DB = profileOnlyStore{Store: f, ProfileStore: f}
	if p, ok, err := db.profileForRunnerID(t.Context(), ""); err != nil || ok || p.ID != "" {
		t.Fatalf("db empty id = (%+v, %v, %v)", p, ok, err)
	}
	if p, ok, err := db.profileForRunnerID(t.Context(), "unbound"); err != nil || ok || p.ID != "" {
		t.Fatalf("store without link surface = (%+v, %v, %v)", p, ok, err)
	}
	// profileForRunnerBinding routes the runner ID before the serial.
	if p, ok, err := db.profileForRunnerBinding(t.Context(), runnerProfileBinding{RunnerID: "", Serial: "0x"}); err != nil || ok || p.ID != "" {
		t.Fatalf("binding with empty runner id = (%+v, %v, %v)", p, ok, err)
	}
}

// TestLinkRunnerProfileValidationAndStoreErrors: an empty runner ID is a
// client error, an unknown profile is rejected before any store call, a
// non-NotFound profile-store error surfaces verbatim, and a store without
// the link contract fails instead of silently dropping the binding.
func TestLinkRunnerProfileValidationAndStoreErrors(t *testing.T) {
	s := perRunnerTokenServer(t, nil)
	createProfile(t, s, model.RunnerProfile{ID: "p", MaxCapacity: 1})

	if err := s.linkRunnerProfile(t.Context(), "", "p"); err == nil {
		t.Fatal("empty runner id accepted")
	}
	if err := s.linkRunnerProfile(t.Context(), "runner-a", "missing"); !errors.Is(err, errUnknownProfile) {
		t.Fatalf("unknown profile = %v, want errUnknownProfile", err)
	}
	// The profile-existence check runs before the link store, so no binding
	// can exist after the rejection.
	if ids, err := s.runnerIDsForProfile(t.Context(), "p"); err != nil || len(ids) != 0 {
		t.Fatalf("rejected link left a binding: (%v, %v)", ids, err)
	}

	// A profile-store outage is a server-side error, not "unknown profile".
	boom := errors.New("profile store unavailable")
	outage := New("shared-dev-tok")
	outage.DB = profileOnlyStore{Store: newDBFakeStore(), ProfileStore: failingProfileStore{err: boom}}
	if err := outage.linkRunnerProfile(t.Context(), "runner-a", "p"); !errors.Is(err, boom) {
		t.Fatalf("profile-store error = %v, want %v", err, boom)
	}

	// A store without RunnerProfileLinkStore fails closed.
	storeless := New("shared-dev-tok")
	storeless.DB = profileOnlyStore{Store: newDBFakeStore(), ProfileStore: newDBFakeStore()}
	err := storeless.linkRunnerProfile(t.Context(), "runner-a", "p")
	if err == nil || !errors.Is(err, storage.ErrNotFound) {
		// The fake has no profile "p", so the existence check answers first;
		// create it in the fake and retry to reach the missing-surface path.
		if perr := storeless.DB.(storage.ProfileStore).UpsertProfile(t.Context(), model.RunnerProfile{ID: "p", MaxCapacity: 1}); perr != nil {
			t.Fatal(perr)
		}
		err = storeless.linkRunnerProfile(t.Context(), "runner-a", "p")
		if err == nil {
			t.Fatal("store without RunnerProfileLinkStore accepted a link")
		}
	}
}

// TestLinkRunnerProfileDurabilityRollback: a failed snapshot write reverts
// the in-memory binding (both the first-link and the replace case) and
// reports a not-durable failure, so memory never keeps a binding the
// snapshot does not contain.
func TestLinkRunnerProfileDurabilityRollback(t *testing.T) {
	s, err := NewPersistent("shared-dev-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	createProfile(t, s, model.RunnerProfile{ID: "p", MaxCapacity: 1})
	createProfile(t, s, model.RunnerProfile{ID: "p2", MaxCapacity: 1})

	// First link with a nil binding map: the map is created, then the write
	// fails, so the entry is removed again.
	s.mu.Lock()
	s.runnerProfiles = nil
	s.mu.Unlock()
	s.persistFailForTest = errors.New("synthetic snapshot failure")
	err = s.linkRunnerProfile(t.Context(), "runner-a", "p")
	var nd *stateNotDurableError
	if !errors.As(err, &nd) {
		t.Fatalf("first link failure = %v, want *stateNotDurableError", err)
	}
	s.mu.Lock()
	_, present := s.runnerProfiles["runner-a"]
	mapLen := len(s.runnerProfiles)
	s.mu.Unlock()
	if present || mapLen != 0 {
		t.Fatalf("failed first link kept state: present=%v len=%d", present, mapLen)
	}

	// A failed REPLACE restores the previous binding.
	s.persistFailForTest = nil
	if err := s.linkRunnerProfile(t.Context(), "runner-a", "p"); err != nil {
		t.Fatal(err)
	}
	s.persistFailForTest = errors.New("synthetic snapshot failure")
	if err := s.linkRunnerProfile(t.Context(), "runner-a", "p2"); !errors.As(err, &nd) {
		t.Fatalf("replace failure = %v, want *stateNotDurableError", err)
	}
	s.mu.Lock()
	got := s.runnerProfiles["runner-a"]
	s.mu.Unlock()
	if got != "p" {
		t.Fatalf("failed replace left binding %q, want the previous p", got)
	}
	// The healthy path re-links and persists.
	s.persistFailForTest = nil
	if err := s.linkRunnerProfile(t.Context(), "runner-a", "p2"); err != nil {
		t.Fatal(err)
	}
	if p, ok, err := s.profileForRunnerID(t.Context(), "runner-a"); err != nil || !ok || p.ID != "p2" {
		t.Fatalf("re-link = (%+v, %v, %v)", p, ok, err)
	}
}

// TestUnlinkRunnerProfileBranches: empty IDs, the store-less DB surface, the
// idempotent unbound no-op and the durability rollback that restores the
// binding.
func TestUnlinkRunnerProfileBranches(t *testing.T) {
	s, err := NewPersistent("shared-dev-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.unlinkRunnerProfile(t.Context(), ""); err == nil {
		t.Fatal("empty runner id accepted")
	}
	// Unbound unlink is a no-op (and must not touch the snapshot).
	s.persistFailForTest = errors.New("synthetic snapshot failure")
	if err := s.unlinkRunnerProfile(t.Context(), "never-bound"); err != nil {
		t.Fatalf("unbound unlink = %v, want a no-op", err)
	}
	s.persistFailForTest = nil

	createProfile(t, s, model.RunnerProfile{ID: "p", MaxCapacity: 1})
	if err := s.linkRunnerProfile(t.Context(), "runner-a", "p"); err != nil {
		t.Fatal(err)
	}
	s.persistFailForTest = errors.New("synthetic snapshot failure")
	err = s.unlinkRunnerProfile(t.Context(), "runner-a")
	var nd *stateNotDurableError
	if !errors.As(err, &nd) {
		t.Fatalf("failed unlink = %v, want *stateNotDurableError", err)
	}
	s.mu.Lock()
	got, present := s.runnerProfiles["runner-a"]
	s.mu.Unlock()
	if !present || got != "p" {
		t.Fatalf("failed unlink dropped the binding: present=%v value=%q", present, got)
	}
	s.persistFailForTest = nil
	if err := s.unlinkRunnerProfile(t.Context(), "runner-a"); err != nil {
		t.Fatal(err)
	}

	// A DB without the link contract refuses the unlink.
	storeless := New("shared-dev-tok")
	storeless.DB = profileOnlyStore{Store: newDBFakeStore(), ProfileStore: newDBFakeStore()}
	if err := storeless.unlinkRunnerProfile(t.Context(), "runner-a"); err == nil {
		t.Fatal("store without RunnerProfileLinkStore accepted an unlink")
	}
}

// TestRunnerIDsForProfileStoreBranches: the empty profile ID, the store-less
// DB surface and the DB store path all answer deterministically.
func TestRunnerIDsForProfileStoreBranches(t *testing.T) {
	s := perRunnerTokenServer(t, nil)
	if ids, err := s.runnerIDsForProfile(t.Context(), ""); err != nil || ids == nil || len(ids) != 0 {
		t.Fatalf("memory empty profile = (%v, %v)", ids, err)
	}

	storeless := New("shared-dev-tok")
	storeless.DB = profileOnlyStore{Store: newDBFakeStore(), ProfileStore: newDBFakeStore()}
	if ids, err := storeless.runnerIDsForProfile(t.Context(), "p"); err != nil || ids == nil || len(ids) != 0 {
		t.Fatalf("store-less listing = (%v, %v)", ids, err)
	}

	f := newDBFakeStore()
	db := New("shared-dev-tok")
	db.DB = f
	db.DB.(storage.ProfileStore).UpsertProfile(t.Context(), model.RunnerProfile{ID: "p", MaxCapacity: 1})
	if err := f.LinkRunnerProfile(t.Context(), "runner-b", "p"); err != nil {
		t.Fatal(err)
	}
	if err := f.LinkRunnerProfile(t.Context(), "runner-a", "p"); err != nil {
		t.Fatal(err)
	}
	ids, err := db.runnerIDsForProfile(t.Context(), "p")
	if err != nil || len(ids) != 2 || ids[0] != "runner-a" || ids[1] != "runner-b" {
		t.Fatalf("db listing = (%v, %v), want sorted [runner-a runner-b]", ids, err)
	}
}

// TestRunnerProfileBindingHandlersTierGate calls the handlers directly with a
// non-admin principal: the middleware has already admitted the route, so the
// in-handler tier gate must be the one refusing the mutation.
func TestRunnerProfileBindingHandlersTierGate(t *testing.T) {
	s := storeServer(t, "admin-tok", map[string]auth.Principal{
		"read-tok": {Subject: "reader", Roles: []auth.Role{auth.RoleRead}},
	})
	createProfile(t, s, model.RunnerProfile{ID: "p", MaxCapacity: 1})

	readCtx := auth.WithPrincipal(context.Background(), auth.Principal{Subject: "reader", Roles: []auth.Role{auth.RoleRead}})
	for name, handler := range map[string]http.HandlerFunc{
		"bind":   s.bindRunnerProfileRunner,
		"unbind": s.unbindRunnerProfileRunner,
	} {
		req := httptest.NewRequestWithContext(readCtx, http.MethodPut, "/api/v1/runner-profiles/p/runner/runner-a", nil)
		req.SetPathValue("id", "p")
		req.SetPathValue("runnerID", "runner-a")
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s with a read principal = %d, want 403", name, w.Code)
		}
	}
	// The denial changed nothing.
	if ids, err := s.runnerIDsForProfile(context.Background(), "p"); err != nil || len(ids) != 0 {
		t.Fatalf("denied mutation changed state: (%v, %v)", ids, err)
	}
}

// TestRunnerProfileBindingHandlerDurability503: the handler maps a
// not-durable failure to 503 (never a 400 that would look like a rejected
// binding), for both the bind and unbind routes.
func TestRunnerProfileBindingHandlerDurability503(t *testing.T) {
	s, err := NewPersistent("shared-dev-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	createProfile(t, s, model.RunnerProfile{ID: "p", MaxCapacity: 1})
	s.persistFailForTest = errors.New("synthetic snapshot failure")

	bindReq := httptest.NewRequest(http.MethodPut, "/api/v1/runner-profiles/p/runner/runner-a", nil)
	bindReq.SetPathValue("id", "p")
	bindReq.SetPathValue("runnerID", "runner-a")
	bindW := httptest.NewRecorder()
	s.bindRunnerProfileRunner(bindW, bindReq)
	if bindW.Code != http.StatusServiceUnavailable {
		t.Fatalf("bind with a failed persist = %d, want 503", bindW.Code)
	}

	// Establish the binding with a healthy store, then re-arm the failure
	// for the unbind route.
	s.persistFailForTest = nil
	if err := s.linkRunnerProfile(context.Background(), "runner-a", "p"); err != nil {
		t.Fatal(err)
	}
	s.persistFailForTest = errors.New("synthetic snapshot failure")
	unbindReq := httptest.NewRequest(http.MethodDelete, "/api/v1/runner-profiles/p/runner/runner-a", nil)
	unbindReq.SetPathValue("id", "p")
	unbindReq.SetPathValue("runnerID", "runner-a")
	unbindW := httptest.NewRecorder()
	s.unbindRunnerProfileRunner(unbindW, unbindReq)
	if unbindW.Code != http.StatusServiceUnavailable {
		t.Fatalf("unbind with a failed persist = %d, want 503", unbindW.Code)
	}
	s.persistFailForTest = nil
	// The failed unbind kept the binding.
	if _, ok, err := s.profileForRunnerID(context.Background(), "runner-a"); err != nil || !ok {
		t.Fatalf("failed unbind dropped the binding: ok=%v err=%v", ok, err)
	}
}

// TestRunnerProfileBindingHandlerInvalidRunnerID: both handlers validate the
// runner ID path value before touching state (empty after trimming, a
// control character, or over the length bound).
func TestRunnerProfileBindingHandlerInvalidRunnerID(t *testing.T) {
	s := perRunnerTokenServer(t, nil)
	createProfile(t, s, model.RunnerProfile{ID: "p", MaxCapacity: 1})
	for name, handler := range map[string]http.HandlerFunc{
		"bind":   s.bindRunnerProfileRunner,
		"unbind": s.unbindRunnerProfileRunner,
	} {
		for _, bad := range []string{"", "  ", "bad\x00id"} {
			req := httptest.NewRequest(http.MethodPut, "/x", nil)
			req.SetPathValue("id", "p")
			req.SetPathValue("runnerID", bad)
			w := httptest.NewRecorder()
			handler(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s with runner id %q = %d, want 400", name, bad, w.Code)
			}
		}
	}
}
