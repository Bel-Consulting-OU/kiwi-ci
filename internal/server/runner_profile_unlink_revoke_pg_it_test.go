package server

// Real-PostgreSQL integration test for the unlink revocation (K1-A) and the
// registration overlay (K1-B) in the production DB topology: a per-runner
// bearer runner bound through runner_profile_links registers with the
// profile's ResourceCapacity (a client-asserted resource_capacity is
// ignored), the profile's resource ceiling bounds admission, the admin
// unlink clears the binding AND the marked runner row in one store
// operation, a dangling binding denies the next lease, and a re-link
// restores the live profile. Gated on KIWI_TEST_POSTGRES_URL via the shared
// pgITServer* helpers.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITUnlinkRevokePipeline is a 5 GiB container job requiring the profile's
// "container" label.
const pgITUnlinkRevokePipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    runner: [container]
    resources:
      memory: 5GiB
    steps:
      - run: echo hi
`

// pgITBlockedNext asserts a lease miss for a per-runner bearer.
func pgITBlockedNext(t *testing.T, s *Server, runnerID, bearer string) {
	t.Helper()
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", bearer, "", nil); w.Code != http.StatusNoContent {
		t.Fatalf("blocked next %s = %d, want 204: %s", runnerID, w.Code, w.Body.String())
	}
}

// TestIntegrationRunnerProfileUnlinkRevokesCapacityPostgres exercises the
// whole stack: profile capacity at registration and lease, revocation on
// unlink, dangling-binding denial, and re-link restoration.
func TestIntegrationRunnerProfileUnlinkRevokesCapacityPostgres(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	s.RequireProfiles = true
	// The untrusted memory ceiling is the enqueue bound; raise it above the
	// profile's capacity so resource ADMISSION decides the oversubscription.
	s.UntrustedMemoryCeiling = 16 << 30
	ctx := context.Background()
	runnerID := pgITServerRandomHex(t, 32)
	if err := s.ProvisionRunnerTokensDB(ctx, map[string]string{runnerID: auth.TokenDigest("token-a")}); err != nil {
		t.Fatal(err)
	}

	// The profile carries the same grants the fs-mode tests use; the
	// repository ACL matches the repository pgITSubmit submits to.
	prof := unlinkRevokeProfile()
	prof.ID = "revoke-pg"
	prof.Repositories = []string{"example.com/o/r"}
	pgITBindingProfile(t, s, prof)
	pgITBindingRunner(t, s, "revoke-pg", runnerID)

	// K1-B: the payload's self-asserted labels/capacity/resource_capacity are
	// all ignored in favor of the profile, and the profile's ResourceCapacity
	// reaches the registration response.
	ri := pgITRegisterBearer(t, s, "token-a",
		`{"id":"`+runnerID+`","name":"ra","protocol_min":3,"protocol_max":3,"labels":["self"],"capacity":9,`+
			`"resource_capacity":{"cpu":999,"memory":4611686018427387904,"disk":4611686018427387904,"pids":1000000}}`)
	want := model.ResourceCapacity{CPU: 4, Memory: 8 << 30, Disk: 16 << 30, PIDs: 512}
	if ri.Capacity != 4 || ri.ResourceCapacity != want || ri.ProfileID != "revoke-pg" {
		t.Fatalf("registration = %+v, want the profile's capacity and marker", ri)
	}
	if len(ri.Labels) != 1 || ri.Labels[0] != "container" || ri.Region != "east" {
		t.Fatalf("registration labels/region = (%v, %q), want the profile's", ri.Labels, ri.Region)
	}
	// The durable row carries the same effective values, and the lease-time
	// overlay agrees with the registration overlay.
	stored, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ResourceCapacity != want || stored.ProfileID != "revoke-pg" || stored.Capacity != 4 {
		t.Fatalf("stored runner = %+v, want the profile's resource capacity and marker", stored)
	}
	if eff := s.Sched.EffectiveRunner(ctx, stored); eff.ResourceCapacity != want || eff.Capacity != 4 {
		t.Fatalf("lease-time overlay = %+v, want parity with the registration overlay", eff)
	}

	pgITServerAwaitLeadership(t, s)
	run1 := pgITSubmit(t, s, pgITUnlinkRevokePipeline)
	run2 := pgITSubmit(t, s, pgITUnlinkRevokePipeline)
	task1 := pgITLiveProfileNext(t, s, runnerID, "token-a")
	if task1.Job.RunID != run1.ID {
		t.Fatalf("first lease = %s, want %s", task1.Job.RunID, run1.ID)
	}
	// The profile's 8 GiB memory ceiling: the second 5 GiB job cannot fit the
	// remaining 3 GiB and waits with the explainable reason.
	pgITBlockedNext(t, s, runnerID, "token-a")
	if reason := pgITJobQueueReason(t, s, run2.ID); reason != "RUNNER_CAPACITY" {
		t.Fatalf("second job reason = %q, want RUNNER_CAPACITY", reason)
	}
	// Complete the first job (releasing its reservation) so the re-link below
	// can admit the waiter.
	completeBody, err := json.Marshal(map[string]any{"runner_id": runnerID, "lease_token": task1.LeaseToken, "lease_generation": task1.LeaseGeneration, "status": "success"})
	if err != nil {
		t.Fatal(err)
	}
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+task1.Job.ID+"/complete", "token-a", string(completeBody), nil); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d %s", w.Code, w.Body.String())
	}

	// K1-A: the unlink is a revocation — the binding AND the marked runner
	// row are cleared in one store operation.
	if w := pgITDo(t, s, http.MethodDelete, "/api/v1/runner-profiles/revoke-pg/runner/"+runnerID, "token", "", nil); w.Code != http.StatusOK {
		t.Fatalf("unbind: %d %s", w.Code, w.Body.String())
	}
	stored, err = st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ProfileID != "" || stored.Capacity != 0 || stored.ResourceCapacity != (model.ResourceCapacity{}) ||
		stored.Labels != nil || stored.Region != "" || stored.AllowedRepositories != nil ||
		stored.Capabilities != nil || stored.CostPerHour != 0 || stored.PowerWatts != 0 {
		t.Fatalf("runner after unlink = %+v, want every profile-derived field cleared", stored)
	}
	// The removed profile stops applying to the very next poll: the required
	// label is gone and the revoked capacity admits nothing.
	pgITBlockedNext(t, s, runnerID, "token-a")

	// A dangling runner-ID binding denies the lease instead of falling back
	// to the snapshot.
	if err := st.LinkRunnerProfile(ctx, runnerID, "ghost-"+pgITServerRandomHex(t, 8)); err != nil {
		t.Fatal(err)
	}
	pgITBlockedNext(t, s, runnerID, "token-a")

	// Re-link restores the live profile: the waiter leases again.
	if err := st.LinkRunnerProfile(ctx, runnerID, "revoke-pg"); err != nil {
		t.Fatal(err)
	}
	task2 := pgITLiveProfileNext(t, s, runnerID, "token-a")
	if task2.Job.RunID != run2.ID {
		t.Fatalf("re-linked lease = %s, want %s", task2.Job.RunID, run2.ID)
	}
}
