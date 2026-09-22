package server

// Post-fix coverage for the runner-ID -> profile binding model: the
// admin-managed PUT/DELETE endpoints, the mTLS-vs-bearer-vs-legacy
// resolution matrix, the admin-tier authorization gate and the fs/DB
// durability of the binding. The exploit/TOCTOU proofs live in
// runner_profile_serial_attack_test.go.

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// bindRunnerProfile links runnerID to profileID through the admin API.
func bindRunnerProfile(t *testing.T, s *Server, profileID, runnerID, token string) {
	t.Helper()
	w := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/"+profileID+"/runner/"+runnerID, token, "{}")
	if w.Code != http.StatusOK {
		t.Fatalf("bind %s -> %s: %d %s", profileID, runnerID, w.Code, w.Body.String())
	}
}

// runnerIDsForProfile lists the runner IDs bound to ONE profile, ordered by
// runner ID: DB mode through the store's RunnerIDsForProfile (the SELECT that
// migration 0031's profile_id index, runner_profile_links_profile_idx, backs)
// and memory mode from the fs-snapshot mirror. It is a TEST-ONLY helper:
// production has no profile -> runners listing route (registration and every
// lease path resolve runner -> profile, never the reverse), so the server
// method was removed as a dead seam (K7-C) and the listing is exercised here
// over both store modes.
func (s *Server) runnerIDsForProfile(ctx context.Context, profileID string) ([]string, error) {
	if profileID == "" {
		return []string{}, nil
	}
	if s.DB != nil {
		ls, ok := s.DB.(storage.RunnerProfileLinkStore)
		if !ok {
			return []string{}, nil
		}
		return ls.RunnerIDsForProfile(ctx, profileID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []string{}
	for id, pid := range s.runnerProfiles {
		if pid == profileID {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

// registerWithToken registers through the HTTP API with an explicit bearer
// (the per-runner token in the production bearer mode) and returns the
// stored record.
func registerWithToken(t *testing.T, s *Server, body map[string]any, token string) model.Runner {
	t.Helper()
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/register", body, token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("register with %q: %d %s", token, w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	return ri
}

// TestBearerRunnerResolvesOwnBoundProfile: a per-runner bearer runner with
// an admin-created runner_profile_links binding gets that profile at
// registration — including when its payload carries another profile's
// certificate serial — and loses it again when the binding is unlinked
// (fail closed under RequireProfiles).
func TestBearerRunnerResolvesOwnBoundProfile(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		s := perRunnerTokenServer(t, map[string]string{"runner-a": "token-a"})
		createProfile(t, s, model.RunnerProfile{
			ID: "p", Labels: []string{"container"}, Region: "own",
			Repositories: []string{"github.com/o/mine"},
			Capabilities: []string{"native", "container"},
			MaxCapacity:  4, CostPerHour: 1.5, PowerWatts: 100,
		})
		// A second, privileged profile bound to a serial the attacker knows:
		// the bearer runner must resolve its OWN runner-ID binding instead.
		createProfile(t, s, privilegedProfile())
		bindSerial(t, s, "priv", "0priv")

		bindRunnerProfile(t, s, "p", "runner-a", "admin-tok")
		if got, err := s.runnerIDsForProfile(t.Context(), "p"); err != nil || len(got) != 1 || got[0] != "runner-a" {
			t.Fatalf("RunnerIDsForProfile = (%v, %v)", got, err)
		}

		ri := registerWithToken(t, s, map[string]any{
			"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
			"cert_serial": "0priv", "capabilities": []string{"native", "tart"},
		}, "token-a")
		if len(ri.Labels) != 1 || ri.Labels[0] != "container" || ri.Region != "own" {
			t.Fatalf("bound runner profile not applied: %+v", ri)
		}
		if ri.Capacity != 4 || ri.CostPerHour != 1.5 || ri.PowerWatts != 100 {
			t.Fatalf("bound runner rates/capacity wrong: %+v", ri)
		}
		if len(ri.AllowedRepositories) != 1 || ri.AllowedRepositories[0] != "github.com/o/mine" {
			t.Fatalf("bound runner repository ACL wrong: %+v", ri)
		}
		// Capabilities are the profile ceiling intersected with the reported
		// hardware set: tart is dropped, native survives.
		if len(ri.Capabilities) != 1 || ri.Capabilities[0] != "native" {
			t.Fatalf("capabilities = %v, want intersection [native]", ri.Capabilities)
		}
		if ri.CertSerial != "" {
			t.Fatalf("bearer runner stored a certificate serial: %q", ri.CertSerial)
		}

		// A profile edit is live on the next resolution.
		if err := s.upsertProfile(t.Context(), model.RunnerProfile{ID: "p", Labels: []string{"container"}, MaxCapacity: 9}); err != nil {
			t.Fatal(err)
		}
		if p, ok, err := s.profileForRunnerID(t.Context(), "runner-a"); err != nil || !ok || p.MaxCapacity != 9 {
			t.Fatalf("live runner-ID profile = (%+v, %v, %v)", p, ok, err)
		}

		// Unlink takes effect: the next registration is unprofiled and
		// fails closed under RequireProfiles.
		if w := doJSON(t, s, http.MethodDelete, "/api/v1/runner-profiles/p/runner/runner-a", "admin-tok", ""); w.Code != http.StatusOK {
			t.Fatalf("unbind: %d %s", w.Code, w.Body.String())
		}
		if _, ok, err := s.profileForRunnerID(t.Context(), "runner-a"); err != nil || ok {
			t.Fatalf("unlinked profile still resolves ok=%v err=%v", ok, err)
		}
		ri = registerWithToken(t, s, map[string]any{
			"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
			"cert_serial": "0priv", "capacity": 8,
		}, "token-a")
		assertNoPrivilegeInheritance(t, "unlinked runner", ri)

		// A binding whose profile row vanished also denies the profile (fail
		// closed), matching the DB join and the lease-path behavior.
		bindRunnerProfile(t, s, "p", "runner-a", "admin-tok")
		s.mu.Lock()
		delete(s.profiles, "p")
		s.mu.Unlock()
		ri = registerWithToken(t, s, map[string]any{
			"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
			"capacity": 8,
		}, "token-a")
		assertNoPrivilegeInheritance(t, "dangling-binding runner", ri)
	})

	t.Run("db", func(t *testing.T) {
		f := newDBFakeStore()
		s := New("shared-dev-tok")
		s.AdminToken = "admin-tok"
		s.RequireProfiles = true
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		if err := s.ProvisionRunnerTokensDB(t.Context(), map[string]string{"runner-a": auth.TokenDigest("token-a")}); err != nil {
			t.Fatal(err)
		}
		createProfile(t, s, model.RunnerProfile{ID: "p", Labels: []string{"container"}, MaxCapacity: 4, Capabilities: []string{"container"}})
		bindRunnerProfile(t, s, "p", "runner-a", "admin-tok")
		// The binding is durable in the store, not a server memory map.
		if p, ok, err := f.ProfileForRunnerID(t.Context(), "runner-a"); err != nil || !ok || p.ID != "p" {
			t.Fatalf("durable binding = (%+v, %v, %v)", p, ok, err)
		}
		ri := registerWithToken(t, s, map[string]any{
			"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
			"cert_serial": "0stolen", "capabilities": []string{"container"},
		}, "token-a")
		if len(ri.Labels) != 1 || ri.Labels[0] != "container" || ri.Capacity != 4 || ri.CertSerial != "" {
			t.Fatalf("db bound runner profile not applied: %+v", ri)
		}
		if w := doJSON(t, s, http.MethodDelete, "/api/v1/runner-profiles/p/runner/runner-a", "admin-tok", ""); w.Code != http.StatusOK {
			t.Fatalf("db unbind: %d %s", w.Code, w.Body.String())
		}
		if _, ok, err := f.ProfileForRunnerID(t.Context(), "runner-a"); err != nil || ok {
			t.Fatalf("durable binding survived unlink ok=%v err=%v", ok, err)
		}
	})
}

// TestRunnerProfileBindingSurvivesFSRestart: the fs-mode mirror of the
// runner-ID binding rides the atomic snapshot, so a restarted control plane
// still resolves the profile.
func TestRunnerProfileBindingSurvivesFSRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	createProfile(t, s, model.RunnerProfile{ID: "p", Labels: []string{"container"}, MaxCapacity: 2})
	bindRunnerProfile(t, s, "p", "runner-a", "admin-tok")

	restarted, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	p, ok, err := restarted.profileForRunnerID(context.Background(), "runner-a")
	if err != nil || !ok || p.ID != "p" || p.MaxCapacity != 2 {
		t.Fatalf("binding after restart = (%+v, %v, %v)", p, ok, err)
	}
	if ids, err := restarted.runnerIDsForProfile(context.Background(), "p"); err != nil || len(ids) != 1 || ids[0] != "runner-a" {
		t.Fatalf("post-restart RunnerIDsForProfile = (%v, %v)", ids, err)
	}
}

// TestMtlsProfileResolutionUsesVerifiedPeerSerial pins the mTLS row of the
// resolution matrix: the profile comes from the serial of the VERIFIED peer
// certificate, never from the payload field, and a certificate that does not
// chain to the runner CA contributes nothing.
func TestMtlsProfileResolutionUsesVerifiedPeerSerial(t *testing.T) {
	caA, err := runnerpki.NewCA("resolution ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caB, err := runnerpki.NewCA("foreign ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := perRunnerTokenServer(t, map[string]string{"runner-a": "token-a"})
	s.RunnerCA = caA
	createProfile(t, s, model.RunnerProfile{ID: "cert-prof", Labels: []string{"from-cert"}, MaxCapacity: 3, Capabilities: []string{"container"}})
	createProfile(t, s, model.RunnerProfile{ID: "foreign-prof", Labels: []string{"from-foreign"}, MaxCapacity: 9})
	_, certA := pkiSignRunner(t, caA, "runner-a")
	_, foreign := pkiSignRunner(t, caB, "runner-a")
	bindSerial(t, s, "cert-prof", certA.SerialNumber.Text(16))
	bindSerial(t, s, "foreign-prof", foreign.SerialNumber.Text(16))

	// Verified peer certificate + a payload serial pointing at the OTHER
	// profile: the verified serial wins.
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/register",
		map[string]any{
			"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
			"cert_serial": foreign.SerialNumber.Text(16), "capabilities": []string{"container"},
		}, "token-a", certA)
	if w.Code != http.StatusOK {
		t.Fatalf("verified-cert register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	if len(ri.Labels) != 1 || ri.Labels[0] != "from-cert" || ri.Capacity != 3 {
		t.Fatalf("verified peer serial did not select the profile: %+v", ri)
	}
	if ri.CertSerial != certA.SerialNumber.Text(16) {
		t.Fatalf("stored serial = %q, want the verified peer serial", ri.CertSerial)
	}

	// A presented certificate that does NOT chain to the runner CA must not
	// select a serial binding — and the payload serial must not be a
	// fallback while the runner CA is configured.
	w = pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/register",
		map[string]any{
			"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
			"cert_serial": foreign.SerialNumber.Text(16), "capacity": 50,
		}, "token-a", foreign)
	if w.Code != http.StatusOK {
		t.Fatalf("foreign-cert register: %d %s", w.Code, w.Body.String())
	}
	var foreignReg model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &foreignReg); err != nil {
		t.Fatal(err)
	}
	if len(foreignReg.Labels) != 0 || foreignReg.Capacity != 0 || foreignReg.CertSerial != "" {
		t.Fatalf("unverified certificate selected a profile: %+v", foreignReg)
	}
}

// TestRegistrationProfileResolutionLegacySerialPathStillWorks pins the
// legacy/dev row of the matrix: with neither a runner CA nor per-runner
// credentials, the payload serial remains the binding key (existing dev
// flows keep working), and it is stored on the runner row.
func TestRegistrationProfileResolutionLegacySerialPathStillWorks(t *testing.T) {
	s := New("runner-tok")
	s.AdminToken = "admin-tok"
	s.RequireProfiles = true
	createProfile(t, s, model.RunnerProfile{ID: "legacy", Labels: []string{"container"}, MaxCapacity: 2})
	bindSerial(t, s, "legacy", "0legacy")

	ri := registerProfiled(t, s, map[string]any{
		"id": "runner-legacy", "name": "rl", "protocol_min": 3, "protocol_max": 3,
		"cert_serial": "0legacy",
	}, nil)
	if len(ri.Labels) != 1 || ri.Capacity != 2 || ri.CertSerial != "0legacy" {
		t.Fatalf("legacy serial profile not applied: %+v", ri)
	}
}

// TestStolenSerialLeavesNoBindingRows: the persistent model exposes exactly
// the admin-created binding — registrations never mint one, so the
// "at most one binding per runner" uniqueness is a PRIMARY KEY fact, not a
// race-prone payload scan.
func TestStolenSerialLeavesNoBindingRows(t *testing.T) {
	s := perRunnerTokenServer(t, map[string]string{
		"runner-a": "token-a",
		"runner-b": "token-b",
		"runner-c": "token-c",
	})
	createProfile(t, s, privilegedProfile())
	bindSerial(t, s, "priv", "0stolen")

	for _, id := range []string{"runner-a", "runner-b"} {
		w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/register",
			map[string]any{"id": id, "name": id, "protocol_min": 3, "protocol_max": 3, "cert_serial": "0stolen"},
			"token-"+id[len(id)-1:], nil)
		if w.Code != http.StatusOK {
			t.Fatalf("register %s: %d %s", id, w.Code, w.Body.String())
		}
	}
	if got, err := s.runnerIDsForProfile(t.Context(), "priv"); err != nil || len(got) != 0 {
		t.Fatalf("registration minted bindings: (%v, %v)", got, err)
	}
	s.mu.Lock()
	n := len(s.runnerProfiles)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("runner-profile bindings after registrations = %d, want 0", n)
	}
	// Only the admin API creates a binding, and it replaces rather than
	// duplicates.
	bindRunnerProfile(t, s, "priv", "runner-c", "admin-tok")
	if got, err := s.runnerIDsForProfile(t.Context(), "priv"); err != nil || len(got) != 1 || got[0] != "runner-c" {
		t.Fatalf("admin binding = (%v, %v)", got, err)
	}
	createProfile(t, s, model.RunnerProfile{ID: "priv2", Labels: []string{"other"}, MaxCapacity: 1})
	bindRunnerProfile(t, s, "priv2", "runner-c", "admin-tok")
	if got, err := s.runnerIDsForProfile(t.Context(), "priv"); err != nil || len(got) != 0 {
		t.Fatalf("re-link left the old profile bound: (%v, %v)", got, err)
	}
	if got, err := s.runnerIDsForProfile(t.Context(), "priv2"); err != nil || len(got) != 1 || got[0] != "runner-c" {
		t.Fatalf("re-link binding = (%v, %v)", got, err)
	}
}

// TestRunnerProfileBindingAdminAPIAuth: the bind/unbind route is admin tier
// — the AdminToken or an admin-role principal, and nothing weaker. All other
// principals (policy_manage included) and runner bearers are refused by the
// tier gate.
func TestRunnerProfileBindingAdminAPIAuth(t *testing.T) {
	s := storeServer(t, "admin-tok", map[string]auth.Principal{
		"admin-user": {Subject: "admin-user", Roles: []auth.Role{auth.RoleAdmin}},
		"policy-tok": {Subject: "policy", Roles: []auth.Role{auth.RolePolicyManage}},
		"manage-tok": {Subject: "manage", Roles: []auth.Role{auth.RoleRunnerManage}},
		"read-tok":   {Subject: "read", Roles: []auth.Role{auth.RoleRead}},
	})
	createProfile(t, s, model.RunnerProfile{ID: "p", Labels: []string{"container"}, MaxCapacity: 1})

	path := "/api/v1/runner-profiles/p/runner/runner-a"
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		if w := doJSON(t, s, method, path, "admin-tok", "{}"); w.Code != http.StatusOK {
			t.Fatalf("admin token %s: %d %s", method, w.Code, w.Body.String())
		}
		if w := doJSON(t, s, method, path, "admin-user", "{}"); w.Code != http.StatusOK {
			t.Fatalf("admin principal %s: %d %s", method, w.Code, w.Body.String())
		}
		for _, tok := range []string{"policy-tok", "manage-tok", "read-tok", ""} {
			if w := doJSON(t, s, method, path, tok, "{}"); w.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s = %d, want 401", tok, method, w.Code)
			}
		}
	}
	// A runner bearer cannot reach the admin tier either.
	if w := pkiRequest(t, s.Handler(), http.MethodPut, path, map[string]any{}, "runner-tok", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("runner bearer on the binding route = %d, want 401", w.Code)
	}
}

// TestRunnerProfileBindingValidation: unknown profiles, missing/invalid
// runner IDs and store-less surfaces are refused without creating a binding.
func TestRunnerProfileBindingValidation(t *testing.T) {
	s := perRunnerTokenServer(t, map[string]string{})
	createProfile(t, s, model.RunnerProfile{ID: "p", MaxCapacity: 1})

	if w := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/nope/runner/runner-a", "admin-tok", "{}"); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown profile bind = %d, want 400", w.Code)
	}
	if w := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/p/runner/rack%00et", "admin-tok", "{}"); w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
		t.Fatalf("control-character runner id = %d", w.Code)
	}
	long := make([]byte, maxRunnerIDLen+1)
	for i := range long {
		long[i] = 'a'
	}
	if w := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/p/runner/"+string(long), "admin-tok", "{}"); w.Code != http.StatusBadRequest {
		t.Fatalf("over-long runner id = %d, want 400", w.Code)
	}
	// Unbinding an unbound runner is an idempotent success.
	if w := doJSON(t, s, http.MethodDelete, "/api/v1/runner-profiles/p/runner/runner-a", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("idempotent unbind = %d %s", w.Code, w.Body.String())
	}

	// A store without the RunnerProfileLinkStore surface fails the admin
	// bind with a server error instead of silently dropping it.
	f := newDBFakeStore()
	s2 := New("shared-dev-tok")
	s2.AdminToken = "admin-tok"
	s2.DB = profileOnlyStore{Store: f, ProfileStore: f}
	if err := s2.upsertProfile(t.Context(), model.RunnerProfile{ID: "p", MaxCapacity: 1}); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s2, http.MethodPut, "/api/v1/runner-profiles/p/runner/runner-a", "admin-tok", "{}"); w.Code != http.StatusInternalServerError {
		t.Fatalf("store without link surface = %d %s, want 500", w.Code, w.Body.String())
	}
}

// profileOnlyStore exposes the base Store and ProfileStore surfaces but NOT
// RunnerProfileLinkStore, modelling a store that lacks the binding contract.
type profileOnlyStore struct {
	storage.Store
	storage.ProfileStore
}
