package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// adminProfileServer builds a profile-enforced memory server with distinct
// admin and runner tokens.
func adminProfileServer(t *testing.T) *Server {
	t.Helper()
	s := New("runner-tok")
	s.AdminToken = "admin-tok"
	s.RequireProfiles = true
	return s
}

func createProfile(t *testing.T, s *Server, p model.RunnerProfile) {
	t.Helper()
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runner-profiles", "admin-tok", string(body))
	if w.Code != http.StatusCreated {
		t.Fatalf("create profile: %d %s", w.Code, w.Body.String())
	}
}

func bindSerial(t *testing.T, s *Server, profileID, serial string) {
	t.Helper()
	w := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/"+profileID+"/cert/"+serial, "admin-tok", "{}")
	if w.Code != http.StatusOK {
		t.Fatalf("bind profile %s to %s: %d %s", profileID, serial, w.Code, w.Body.String())
	}
}

// TestRunnerProfileAdminEndpoints exercises the profile CRUD and the
// cert-binding endpoint, including the policy_manage RBAC gate.
func TestRunnerProfileAdminEndpoints(t *testing.T) {
	s := adminProfileServer(t)

	// Validation: bad capability and NaN rates are rejected.
	bad := model.RunnerProfile{ID: "p-bad", Capabilities: []string{"quantum"}, CostPerHour: 1}
	if body, _ := json.Marshal(bad); true {
		w := doJSON(t, s, http.MethodPost, "/api/v1/runner-profiles", "admin-tok", string(body))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid capability accepted: %d", w.Code)
		}
	}

	createProfile(t, s, model.RunnerProfile{
		ID: "macos-builders", Labels: []string{"os:macos", "container"},
		Region: "east", Repositories: []string{"github.com/o/r"},
		Capabilities: []string{"native", "container", "tart"},
		MaxCapacity:  4, CostPerHour: 1.5, PowerWatts: 120,
	})
	// GET list and single.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runner-profiles", "admin-tok", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "macos-builders") {
		t.Fatalf("list profiles: %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runner-profiles/macos-builders", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("get profile: %d", w.Code)
	}
	// PUT updates.
	updated := model.RunnerProfile{ID: "macos-builders", Labels: []string{"os:macos"}, Region: "west", Capabilities: []string{"native", "tart"}, MaxCapacity: 8, CostPerHour: 2}
	body, _ := json.Marshal(updated)
	if w := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/macos-builders", "admin-tok", string(body)); w.Code != http.StatusOK {
		t.Fatalf("update profile: %d %s", w.Code, w.Body.String())
	}
	// Binding to a missing profile is refused.
	if w := doJSON(t, s, http.MethodPut, "/api/v1/runner-profiles/nope/cert/0cafe", "admin-tok", "{}"); w.Code != http.StatusBadRequest {
		t.Fatalf("bind to unknown profile: %d", w.Code)
	}
	bindSerial(t, s, "macos-builders", "0cafe")

	// RBAC: a policy_manage principal may manage profiles.
	s2 := storeServer(t, "admin-tok", map[string]auth.Principal{
		"policy-tok": {Subject: "policy-bot", Roles: []auth.Role{auth.RolePolicyManage}},
	})
	create := `{"id":"p-rbac","labels":["native"]}`
	if w := doJSON(t, s2, http.MethodPost, "/api/v1/runner-profiles", "policy-tok", create); w.Code != http.StatusCreated {
		t.Fatalf("policy_manage create: %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s2, http.MethodPost, "/api/v1/runner-profiles", "read-tok", create); w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
		t.Fatalf("unprivileged create: %d", w.Code)
	}
}

// TestProfileEnforcedRegistrationIgnoresSelfReportedFields: with profile
// enforcement the runner-supplied labels/region/capacity/cost/power are
// ignored — the linked profile supplies them, capabilities are intersected,
// and a profile-less runner registers empty (capacity 0, no rates).
func TestProfileEnforcedRegistrationIgnoresSelfReportedFields(t *testing.T) {
	s := adminProfileServer(t)
	createProfile(t, s, model.RunnerProfile{
		ID: "p1", Labels: []string{"container"}, Region: "east",
		Capabilities: []string{"native", "container"},
		MaxCapacity:  2, CostPerHour: 1.5, PowerWatts: 100,
	})
	bindSerial(t, s, "p1", "0cafe")

	// Self-reported labels/capacity/cost/power/region are ignored;
	// capabilities are intersected with the profile (tart is dropped,
	// native survives).
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "runner-tok",
		`{"name":"r1","labels":["evil"],"region":"west","capacity":999,"cost_per_hour":9999,"power_watts":9999,"capabilities":["native","tart"],"cert_serial":"0cafe","protocol_min":3,"protocol_max":3}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	if len(ri.Labels) != 1 || ri.Labels[0] != "container" {
		t.Fatalf("labels = %v, want profile-derived [container]", ri.Labels)
	}
	if ri.Region != "east" {
		t.Fatalf("region = %q, want east", ri.Region)
	}
	if ri.Capacity != 2 {
		t.Fatalf("capacity = %d, want profile max_capacity 2", ri.Capacity)
	}
	if ri.CostPerHour != 1.5 || ri.PowerWatts != 100 {
		t.Fatalf("rates = %v/%v, want 1.5/100", ri.CostPerHour, ri.PowerWatts)
	}
	if len(ri.Capabilities) != 1 || ri.Capabilities[0] != "native" {
		t.Fatalf("capabilities = %v, want intersection [native]", ri.Capabilities)
	}

	// Without a linked profile the runner registers empty: no labels, no
	// region, capacity 0, no rates.
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "runner-tok",
		`{"name":"r2","labels":["container"],"capacity":8,"cost_per_hour":3,"protocol_min":3,"protocol_max":3}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register no-profile: %d %s", w.Code, w.Body.String())
	}
	var r2 model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &r2); err != nil {
		t.Fatal(err)
	}
	if len(r2.Labels) != 0 || r2.Region != "" || r2.Capacity != 0 || r2.CostPerHour != 0 || r2.PowerWatts != 0 {
		t.Fatalf("no-profile runner: %+v, want empty labels/region, capacity 0, no rates", r2)
	}
}

// TestNoProfileRunnerNeverLeasedForConstrainedJobs: a capacity-0,
// label-less runner receives nothing; only the profile-bound runner leases
// the label-constrained job.
func TestNoProfileRunnerNeverLeasedForConstrainedJobs(t *testing.T) {
	s := adminProfileServer(t)
	h := s.Handler()
	// A label-constrained job.
	run := SubmitRun{RepoURL: "https://github.com/o/r.git", Ref: "main", Pipeline: `version: 1
jobs:
  build:
    runtime: container
    image: ubuntu@sha256:` + pinnedImage + `
    placement:
      labels: [container]
    steps:
      - run: echo hi
`}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runs", run, "admin-tok", nil); w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	// The profile-less runner registers empty and never leases.
	w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"name": "r0", "protocol_min": 3, "protocol_max": 3}, "runner-tok", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var r0 model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &r0); err != nil {
		t.Fatal(err)
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/"+r0.ID+"/next", map[string]any{}, "runner-tok", nil); w.Code != http.StatusNoContent {
		t.Fatalf("profile-less runner leased: %d %s", w.Code, w.Body.String())
	}
	// A profile-bound runner with the matching label leases it.
	createProfile(t, s, model.RunnerProfile{ID: "builders", Labels: []string{"container"}, Capabilities: []string{"container"}, MaxCapacity: 1})
	bindSerial(t, s, "builders", "0x5e2")
	w = pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"name": "r1", "cert_serial": "0x5e2", "capabilities": []string{"container"}, "protocol_min": 3, "protocol_max": 3}, "runner-tok", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("register profiled runner: %d %s", w.Code, w.Body.String())
	}
	var r1 model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &r1); err != nil {
		t.Fatal(err)
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/"+r1.ID+"/next", map[string]any{}, "runner-tok", nil); w.Code != http.StatusOK {
		t.Fatalf("profiled runner lease: %d %s", w.Code, w.Body.String())
	}
}

// TestProfileBindingViaMTLSCert: with runner mTLS the profile binds to the
// TLS peer certificate serial, and the runner's claimed fields never
// override it.
func TestProfileBindingViaMTLSCert(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("runner-tok")
	s.AdminToken = "admin-tok"
	s.RequireProfiles = true
	s.RunnerCA = ca
	h := s.Handler()
	createProfile(t, s, model.RunnerProfile{ID: "ci", Labels: []string{"container"}, Capabilities: []string{"container"}, MaxCapacity: 3, CostPerHour: 0.5})
	_, cert := pkiSignRunner(t, ca, "runner-a")
	bindSerial(t, s, "ci", cert.SerialNumber.Text(16))

	w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"name": "ra", "labels": []string{"spoofed"}, "capacity": 50, "cost_per_hour": 99, "protocol_min": 3, "protocol_max": 3},
		"runner-tok", cert)
	if w.Code != http.StatusOK {
		t.Fatalf("register with cert: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	if ri.Capacity != 3 || ri.CostPerHour != 0.5 || len(ri.Labels) != 1 || ri.Labels[0] != "container" {
		t.Fatalf("cert-bound profile not applied: %+v", ri)
	}
}

// TestPerRunnerBearerTokenBinding: per-runner bearer tokens authenticate
// runner-tier routes and bind to exactly their runner ID; the shared
// runner token is rejected once per-runner credentials exist.
func TestPerRunnerBearerTokenBinding(t *testing.T) {
	s := New("global-tok")
	s.LoadRunnerTokens(map[string]string{
		"runner-a": auth.TokenDigest("token-a"),
		"runner-b": auth.TokenDigest("token-b"),
	})
	h := s.Handler()

	// Token A registers its own runner.
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": "runner-a", "name": "a", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "token-a", nil); w.Code != http.StatusOK {
		t.Fatalf("register with own token: %d %s", w.Code, w.Body.String())
	}
	// Token A acting for runner-b is refused.
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": "runner-b", "name": "b", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "token-a", nil); w.Code != http.StatusForbidden {
		t.Fatalf("register another runner with token-a: %d", w.Code)
	}
	// next() for another runner's ID is refused.
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/runner-b/next", map[string]any{}, "token-a", nil); w.Code != http.StatusForbidden {
		t.Fatalf("next runner-b with token-a: %d", w.Code)
	}
	// next() for the bound runner works (no content: nothing queued).
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/runner-a/next", map[string]any{}, "token-a", nil); w.Code != http.StatusNoContent && w.Code != http.StatusNotFound {
		t.Fatalf("next runner-a with token-a: %d %s", w.Code, w.Body.String())
	}
	// The shared runner token is dev-only: rejected on runner-tier routes
	// now that per-runner credentials exist.
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/runner-a/next", map[string]any{}, "global-tok", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("global token with per-runner credentials: %d", w.Code)
	}
	// Unknown bearer: 401.
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/runner-a/next", map[string]any{}, "bogus", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown bearer: %d", w.Code)
	}
	// Dev mode without per-runner tokens keeps the shared token working.
	dev := New("global-tok")
	if w := pkiRequest(t, dev.Handler(), http.MethodPost, "/api/v1/runners/register",
		map[string]any{"name": "d", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "global-tok", nil); w.Code != http.StatusOK {
		t.Fatalf("dev global token: %d %s", w.Code, w.Body.String())
	}
}

// TestPerRunnerTokensDBMode: in DB mode the durable runner_bearer_tokens
// rows authenticate runner-tier routes.
func TestPerRunnerTokensDBMode(t *testing.T) {
	f := newDBFakeStore()
	s := New("")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if err := s.ProvisionRunnerTokensDB(t.Context(), map[string]string{
		"runner-a": auth.TokenDigest("token-a"),
	}); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": "runner-a", "name": "a", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "token-a", nil); w.Code != http.StatusOK {
		t.Fatalf("db per-runner register: %d %s", w.Code, w.Body.String())
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": "runner-a", "name": "a", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "token-b", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown db token: %d", w.Code)
	}
}

// TestUnifiedMiddlewareRunnerBearerWithPopulatedStore: the generic bearer
// middleware must not reject runner-tier routes just because the principal
// store is populated — classification runs first.
func TestUnifiedMiddlewareRunnerBearerWithPopulatedStore(t *testing.T) {
	s := storeServer(t, "admin-tok", map[string]auth.Principal{
		"ci-token": {Subject: "ci-bot", Roles: []auth.Role{auth.RoleRun, auth.RoleRead}},
	})
	s.RunnerToken = "runner-tok"
	h := s.Handler()
	// Runner bearer on a runner route reaches the handler.
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"name": "r1", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "runner-tok", nil); w.Code != http.StatusOK {
		t.Fatalf("runner bearer with populated store: %d %s", w.Code, w.Body.String())
	}
	// A store principal cannot reach the runner tier.
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"name": "r2", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "ci-token", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("store principal on runner tier: %d", w.Code)
	}
	// The store principal still reaches its own RBAC routes.
	if w := pkiRequest(t, h, http.MethodGet, "/api/v1/runs", nil, "ci-token", nil); w.Code != http.StatusOK {
		t.Fatalf("store principal on rbac route: %d", w.Code)
	}
}

// TestUnifiedMiddlewareMTLSOnlyWithPopulatedStore: an mTLS-only runner
// (no bearer) works while the principal store is populated.
func TestUnifiedMiddlewareMTLSOnlyWithPopulatedStore(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := storeServer(t, "admin-tok", map[string]auth.Principal{
		"ci-token": {Subject: "ci-bot", Roles: []auth.Role{auth.RoleRun}},
	})
	s.RunnerToken = ""
	s.RunnerCA = ca
	s.RequireRunnerClientCerts = true
	h := s.Handler()
	_, cert := pkiSignRunner(t, ca, "runner-a")
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "", cert); w.Code != http.StatusOK {
		t.Fatalf("mTLS-only runner with populated store: %d %s", w.Code, w.Body.String())
	}
	// Without a certificate the same route is refused.
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("cert-less runner route: %d", w.Code)
	}
}

// TestRevocationSharedAcrossReplicas: a revocation written by one server
// instance (same DB store) rejects the certificate on a second instance.
func TestRevocationSharedAcrossReplicas(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	s1 := New("runner-tok")
	s1.RunnerCA = ca
	s1.RequireRunnerClientCerts = true
	if err := s1.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s2 := New("runner-tok")
	s2.RunnerCA = ca
	s2.RequireRunnerClientCerts = true
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	_, cert := pkiSignRunner(t, ca, "runner-a")
	serial := cert.SerialNumber.Text(16)
	// Register the runner on s1 (DB row), then disable it there: the
	// revocation lands in the durable cert_revocations table.
	if w := pkiRequest(t, s1.Handler(), http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "protocol_min": 3, "protocol_max": 3}, "runner-tok", cert); w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	if w := pkiRequest(t, s1.Handler(), http.MethodPost, "/api/v1/runners/runner-a/disable", map[string]any{}, "runner-tok", nil); w.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}
	// The second instance rejects the revoked certificate on runner-tier
	// routes (identity verification consults the shared revocation row).
	if w := pkiRequest(t, s2.Handler(), http.MethodPost, "/api/v1/runners/runner-a/next", map[string]any{}, "runner-tok", cert); w.Code != http.StatusForbidden {
		t.Fatalf("second instance accepted revoked cert: %d %s", w.Code, w.Body.String())
	}
	// The durable row is present.
	if revoked, err := f.CertRevoked(t.Context(), serial); err != nil || !revoked {
		t.Fatalf("durable revocation missing: revoked=%v err=%v", revoked, err)
	}
}

// TestConcurrentGrantConsumptionOneWinnerDB: two concurrent enrollments of
// the same grant yield exactly one winner (DB-mode conditional consume).
func TestConcurrentGrantConsumptionOneWinnerDB(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	s := New("runner-tok")
	s.RunnerCA = ca
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	raw, err := s.CreateEnrollGrant(time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	_, csrPEM, err := runnerpki.GenerateKeyAndCSR("runner-x")
	if err != nil {
		t.Fatal(err)
	}
	enrollBody := EnrollRequest{RunnerID: "runner-x", CSR: base64.StdEncoding.EncodeToString(csrPEM)}
	rawBody, err := json.Marshal(enrollBody)
	if err != nil {
		t.Fatal(err)
	}
	const n = 8
	results := make(chan int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", rawBody, raw, nil)
			results <- w.Code
		}()
	}
	wg.Wait()
	close(results)
	wins := 0
	for code := range results {
		if code == http.StatusOK {
			wins++
		} else if code != http.StatusUnauthorized {
			t.Fatalf("unexpected enroll status %d", code)
		}
	}
	if wins != 1 {
		t.Fatalf("grant winners = %d, want exactly 1", wins)
	}
}

// TestEnrollGrantPersistsInDB: DB-mode grants are stored (and consumed)
// through the durable table, not the memory map.
func TestEnrollGrantPersistsInDB(t *testing.T) {
	f := newDBFakeStore()
	s := New("runner-tok")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	raw, err := s.CreateEnrollGrant(time.Hour, []string{"os:macos"})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	rec, ok := f.grants[auth.TokenDigest(raw)]
	f.mu.Unlock()
	if !ok || rec.Consumed || len(rec.BoundLabels) != 1 {
		t.Fatalf("grant not stored durably: ok=%v %+v", ok, rec)
	}
	s.mu.Lock()
	_, inMemory := s.EnrollGrants[auth.TokenDigest(raw)]
	s.mu.Unlock()
	if inMemory {
		t.Fatal("DB-mode grant must not land in the memory map")
	}
}

// TestHARunnerCASharedThroughClusterStore: two servers sharing one cluster
// store resolve the SAME runner CA object, and EnsureRunnerCA refuses to
// materialize a CA without a cluster store in DB mode.
func TestHARunnerCASharedThroughClusterStore(t *testing.T) {
	shared := &StaticClusterKeyStore{Keys: map[string][]byte{}}
	s1 := &Server{ClusterKeys: shared}
	if err := s1.EnsureRunnerCA(); err != nil {
		t.Fatal(err)
	}
	s2 := &Server{ClusterKeys: shared}
	if err := s2.EnsureRunnerCA(); err != nil {
		t.Fatal(err)
	}
	if s1.RunnerCA == nil || s2.RunnerCA == nil {
		t.Fatal("runner CA not materialized")
	}
	if string(s1.RunnerCA.Cert.Raw) != string(s2.RunnerCA.Cert.Raw) {
		t.Fatal("two servers resolved different runner CA certificates from the shared store")
	}

	// DB mode without a cluster store refuses auto-CA materialization.
	s3 := New("t")
	if err := s3.SwitchToDB(newDBFakeStore()); err != nil {
		t.Fatal(err)
	}
	if err := s3.EnsureRunnerCA(); err == nil {
		t.Fatal("EnsureRunnerCA without a cluster store in DB mode must fail")
	}
}

// TestValidateHAReadyRunnerCAFingerprint: when a runner CA is loaded, the
// cluster store must resolve the same certificate fingerprint.
func TestValidateHAReadyRunnerCAFingerprint(t *testing.T) {
	// Matching material: load through the shared store, then validate.
	shared := &StaticClusterKeyStore{Keys: map[string][]byte{}}
	s, err := NewPersistentWithCluster("t", "t", t.TempDir(), shared)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureRunnerCA(); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateHAReady(); err != nil {
		t.Fatalf("matching runner CA failed HA validation: %v", err)
	}

	// Divergent material: an unrelated CA loaded in the server while the
	// store holds a different one.
	unrelated, err := runnerpki.NewCA("unrelated", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	divergent := New("t")
	divergent.RunnerCA = unrelated
	divergent.ClusterKeys = shared
	if err := divergent.ValidateHAReady(); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("divergent runner CA: %v", err)
	}
}

// TestRunnerInventoryRBAC: the full inventory requires runner_manage; the
// /runners/serving projection serves read principals a redacted subset.
func TestRunnerInventoryRBAC(t *testing.T) {
	s := scopedStoreServer(t)
	// A read principal cannot list the full inventory.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runners", "reader", ""); w.Code != http.StatusForbidden {
		t.Fatalf("full inventory for reader: %d", w.Code)
	}
	// The serving projection is redacted: no labels, filtered jobs.
	w := doJSON(t, s, http.MethodGet, "/api/v1/runners/serving", "reader", "")
	if w.Code != http.StatusOK {
		t.Fatalf("serving list: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "labels") || strings.Contains(w.Body.String(), "region") {
		t.Fatalf("serving DTO leaks profile fields: %s", w.Body.String())
	}
	var out []struct {
		ID         string   `json:"id"`
		ActiveJobs []string `json:"active_jobs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].ID != "r-a" || len(out[0].ActiveJobs) != 1 || out[0].ActiveJobs[0] != "job-a" {
		t.Fatalf("serving projection = %+v, want only r-a serving job-a", out)
	}
	// A runner_manage principal gets the full inventory.
	if err := s.AuthStore.AddToken("manager", auth.Principal{Subject: "runner-manager", Roles: []auth.Role{auth.RoleRunnerManage}}); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runners", "manager", ""); w.Code != http.StatusOK {
		t.Fatalf("runner_manage inventory: %d %s", w.Code, w.Body.String())
	}
}
