package server

// Real-PostgreSQL integration tests for the runner-ID -> profile binding.
// Gated on KIWI_TEST_POSTGRES_URL via the shared pgITServer* helpers (skipped
// when unset, and in -short mode); every test opens its own throwaway schema.
//
// They drive the production DB-mode topology: per-runner bearer credentials
// in runner_bearer_tokens, the admin-managed runner_profile_links binding and
// the certificate binding in cert_profile_links, asserting against the
// durable rows rather than in-memory mirrors.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITBindingProfile creates a profile through the admin HTTP surface. The
// pgITServer fixture's admin token is "token".
func pgITBindingProfile(t *testing.T, s *Server, p model.RunnerProfile) {
	t.Helper()
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runner-profiles", "token", string(body), nil); w.Code != http.StatusCreated {
		t.Fatalf("create profile %s: %d %s", p.ID, w.Code, w.Body.String())
	}
}

// pgITBindingCert binds a certificate serial through the admin HTTP surface.
func pgITBindingCert(t *testing.T, s *Server, profileID, serial string) {
	t.Helper()
	if w := pgITDo(t, s, http.MethodPut, "/api/v1/runner-profiles/"+profileID+"/cert/"+serial, "token", "{}", nil); w.Code != http.StatusOK {
		t.Fatalf("bind cert %s -> %s: %d %s", serial, profileID, w.Code, w.Body.String())
	}
}

// pgITBindingRunner binds a runner ID through the admin HTTP surface.
func pgITBindingRunner(t *testing.T, s *Server, profileID, runnerID string) {
	t.Helper()
	if w := pgITDo(t, s, http.MethodPut, "/api/v1/runner-profiles/"+profileID+"/runner/"+runnerID, "token", "{}", nil); w.Code != http.StatusOK {
		t.Fatalf("bind runner %s -> %s: %d %s", runnerID, profileID, w.Code, w.Body.String())
	}
}

// pgITRegisterBearer registers one runner with a per-runner bearer token and
// returns the decoded record.
func pgITRegisterBearer(t *testing.T, s *Server, token, body string) model.Runner {
	t.Helper()
	w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/register", token, body, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("register with %s: %d %s", token, w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	return ri
}

// TestIntegrationRunnerProfileBindingPostgres is the durable-mode matrix:
// the stolen serial grants nothing, the admin runner-ID binding grants the
// bound profile, and the certificate binding stays untouched.
func TestIntegrationRunnerProfileBindingPostgres(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	s.RequireProfiles = true
	ctx := context.Background()
	// The SQL store validates runner IDs as 32-hex canonical IDs.
	lowID := pgITServerRandomHex(t, 32)
	privID := pgITServerRandomHex(t, 32)

	// Per-runner bearer credentials are durable rows.
	if err := s.ProvisionRunnerTokensDB(ctx, map[string]string{
		lowID:  auth.TokenDigest("token-low"),
		privID: auth.TokenDigest("token-priv"),
	}); err != nil {
		t.Fatal(err)
	}

	pgITBindingProfile(t, s, privilegedProfile())
	pgITBindingCert(t, s, "priv", "0priv-pg")
	pgITBindingProfile(t, s, model.RunnerProfile{
		ID: "own", Labels: []string{"container"}, Region: "own",
		Capabilities: []string{"native", "container"}, MaxCapacity: 2,
	})

	// Attack: the low-privilege bearer submits the pre-bound serial.
	low := pgITRegisterBearer(t, s, "token-low",
		`{"id":"`+lowID+`","name":"low","protocol_min":3,"protocol_max":3,"cert_serial":"0priv-pg","labels":["self"],"capacity":9}`)
	assertNoPrivilegeInheritance(t, "pg attacker", low)

	// The admin certificate binding is untouched by the attack.
	if p, ok, err := st.ProfileForSerial(ctx, "0priv-pg"); err != nil || !ok || p.ID != "priv" {
		t.Fatalf("cert binding after attack = (%+v, %v, %v)", p, ok, err)
	}

	// The admin runner-ID binding is the supported path and it is durable.
	pgITBindingRunner(t, s, "own", privID)
	if p, ok, err := st.ProfileForRunnerID(ctx, privID); err != nil || !ok || p.ID != "own" {
		t.Fatalf("durable runner binding = (%+v, %v, %v)", p, ok, err)
	}
	priv := pgITRegisterBearer(t, s, "token-priv",
		`{"id":"`+privID+`","name":"rp","protocol_min":3,"protocol_max":3,"cert_serial":"0priv-pg","capabilities":["native","tart"]}`)
	if len(priv.Labels) != 1 || priv.Labels[0] != "container" || priv.Region != "own" || priv.Capacity != 2 {
		t.Fatalf("bound bearer runner profile not applied: %+v", priv)
	}
	if len(priv.Capabilities) != 1 || priv.Capabilities[0] != "native" {
		t.Fatalf("capabilities = %v, want the profile intersection [native]", priv.Capabilities)
	}
	if priv.CertSerial != "" {
		t.Fatalf("bearer runner stored a client-asserted serial: %q", priv.CertSerial)
	}

	// The durable runner rows: the attacker stored no serial, the bound
	// runner's serial field is empty, and the binding points at "own".
	runners, err := st.ListRunners(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]model.Runner{}
	for _, ri := range runners {
		seen[ri.ID] = ri
	}
	if got := seen[lowID]; got.CertSerial != "" || got.Capacity != 0 {
		t.Fatalf("attacker row = %+v, want no serial and no capacity", got)
	}
	if got := seen[privID]; got.CertSerial != "" || got.Capacity != 2 {
		t.Fatalf("bound runner row = %+v, want no serial and capacity 2", got)
	}
}

// TestIntegrationRunnerProfileUnlinkPostgres proves the unbind is durable and
// takes effect on the next registration, which then fails closed under
// RequireProfiles instead of keeping the previously registered snapshot.
func TestIntegrationRunnerProfileUnlinkPostgres(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	s.RequireProfiles = true
	ctx := context.Background()
	runnerID := pgITServerRandomHex(t, 32)

	if err := s.ProvisionRunnerTokensDB(ctx, map[string]string{runnerID: auth.TokenDigest("token-a")}); err != nil {
		t.Fatal(err)
	}
	pgITBindingProfile(t, s, model.RunnerProfile{ID: "p", Labels: []string{"container"}, MaxCapacity: 3})
	pgITBindingRunner(t, s, "p", runnerID)
	if ids, err := st.RunnerIDsForProfile(ctx, "p"); err != nil || len(ids) != 1 || ids[0] != runnerID {
		t.Fatalf("RunnerIDsForProfile = (%v, %v)", ids, err)
	}

	ri := pgITRegisterBearer(t, s, "token-a",
		`{"id":"`+runnerID+`","name":"ra","protocol_min":3,"protocol_max":3}`)
	if len(ri.Labels) != 1 || ri.Capacity != 3 {
		t.Fatalf("bound profile not applied: %+v", ri)
	}

	if w := pgITDo(t, s, http.MethodDelete, "/api/v1/runner-profiles/p/runner/"+runnerID, "token", "", nil); w.Code != http.StatusOK {
		t.Fatalf("unbind: %d %s", w.Code, w.Body.String())
	}
	if ids, err := st.RunnerIDsForProfile(ctx, "p"); err != nil || len(ids) != 0 {
		t.Fatalf("durable binding survived unlink: (%v, %v)", ids, err)
	}

	ri = pgITRegisterBearer(t, s, "token-a",
		`{"id":"`+runnerID+`","name":"ra","protocol_min":3,"protocol_max":3,"labels":["self"],"capacity":9}`)
	assertNoPrivilegeInheritance(t, "unlinked pg runner", ri)

	// The unlink is idempotent through the API as well.
	if w := pgITDo(t, s, http.MethodDelete, "/api/v1/runner-profiles/p/runner/"+runnerID, "token", "", nil); w.Code != http.StatusOK {
		t.Fatalf("idempotent unbind: %d %s", w.Code, w.Body.String())
	}
}
