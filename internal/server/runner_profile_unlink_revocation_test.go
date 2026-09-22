package server

// Regression coverage for the two profile-authorization defects of the
// runner-ID binding model:
//
//   - K1-A revocation: DELETE /api/v1/runner-profiles/{id}/runner/{runnerID}
//     removes the binding AND clears the profile-derived registration
//     snapshot fields (marker included) in one store operation, so the removed
//     profile stops applying to the very next lease; a DANGLING runner-ID
//     binding fails the lease closed exactly like a dangling certificate
//     binding instead of silently falling back to the stale snapshot.
//   - K1-B overlay: registration applies the shared
//     storage.ResolveRunnerProfile overlay, so the profile's ResourceCapacity
//     reaches the runner row and a client-asserted resource_capacity is always
//     dropped (zero = unconstrained, so accepting it could only widen
//     admission).
//
// The fs-mode tests drive the real HTTP lease path (Server.next, the
// in-memory mirror persisted through the atomic snapshot); the DB-mode PG ITs
// live in runner_profile_unlink_revoke_pg_it_test.go and the store-level
// mem/PG parity in internal/storage.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// unlinkRevokeNext leases through the runner's OWN per-runner bearer.
func unlinkRevokeNext(t *testing.T, s *Server, runnerID, bearer string) Task {
	t.Helper()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", bearer, "")
	if w.Code != http.StatusOK {
		t.Fatalf("next %s = %d %s", runnerID, w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	return task
}

// unlinkRevokeBlockedNext asserts a lease miss through the HTTP path.
func unlinkRevokeBlockedNext(t *testing.T, s *Server, runnerID, bearer string) {
	t.Helper()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", bearer, ""); w.Code != http.StatusNoContent {
		t.Fatalf("blocked next %s = %d, want 204: %s", runnerID, w.Code, w.Body.String())
	}
}

// unlinkRevokeComplete completes a leased task.
func unlinkRevokeComplete(t *testing.T, s *Server, runnerID, bearer string, task Task, status string) {
	t.Helper()
	body := `{"runner_id":"` + runnerID + `","lease_token":"` + task.LeaseToken +
		`","lease_generation":` + strconv.FormatInt(task.LeaseGeneration, 10) + `,"status":"` + status + `"}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", bearer, body); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d %s", w.Code, w.Body.String())
	}
}

// unlinkRevokePipeline is a 5 GiB container job that requires the profile's
// "container" label.
const unlinkRevokePipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    runner: [container]
    resources:
      memory: 5GiB
    steps:
      - run: echo hi
`

// unlinkRevokeProfile is the capacity-bearing profile the K1-A/K1-B tests
// bind: distinctive grants on every scheduling dimension. The repository ACL
// is the canonical identity of the repository the fs tests submit to, so the
// lease decisions below are decided by labels/capacity rather than the ACL.
func unlinkRevokeProfile() model.RunnerProfile {
	return model.RunnerProfile{
		ID: "revoke", Labels: []string{"container"}, Region: "east",
		Repositories: []string{"github.com/revoke/res"},
		Capabilities: []string{"container"},
		MaxCapacity:  4, MaxCPU: 4, MaxMemory: 8 << 30, MaxDisk: 16 << 30, MaxPIDs: 512,
		CostPerHour: 1.5, PowerWatts: 50,
	}
}

// TestRegistrationOverlaysProfileResourceCapacity: the registration overlay
// is the lease-time overlay (storage.ResolveRunnerProfile): the profile's
// ResourceCapacity is stored on the runner row alongside the other
// attributes, and a payload resource_capacity claiming far more is ignored.
func TestRegistrationOverlaysProfileResourceCapacity(t *testing.T) {
	s := perRunnerTokenServer(t, map[string]string{"runner-a": "token-a"})
	createProfile(t, s, unlinkRevokeProfile())
	bindRunnerProfile(t, s, "revoke", "runner-a", "admin-tok")

	ri := registerWithToken(t, s, map[string]any{
		"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
		"labels": []string{"spoofed"}, "capacity": 99,
		"resource_capacity": map[string]any{"cpu": 999, "memory": int64(1) << 62, "disk": int64(1) << 62, "pids": 1000000},
	}, "token-a")
	want := model.ResourceCapacity{CPU: 4, Memory: 8 << 30, Disk: 16 << 30, PIDs: 512}
	if ri.ResourceCapacity != want {
		t.Fatalf("registration resource capacity = %+v, want the profile's %+v", ri.ResourceCapacity, want)
	}
	if ri.ProfileID != "revoke" || ri.Capacity != 4 {
		t.Fatalf("registration marker/capacity = (%q, %d), want (revoke, 4)", ri.ProfileID, ri.Capacity)
	}
	if len(ri.Labels) != 1 || ri.Labels[0] != "container" {
		t.Fatalf("registration labels = %v, want the profile's [container]", ri.Labels)
	}

	// The stored row carries the same effective values, so a snapshot-path
	// decision (no live binding) is constrained by the profile's max_*.
	s.mu.Lock()
	stored := s.runners["runner-a"]
	s.mu.Unlock()
	if stored.ResourceCapacity != want || stored.ProfileID != "revoke" || stored.Capacity != 4 {
		t.Fatalf("stored runner = %+v, want the profile's resource capacity and marker", stored)
	}
	if eff, linked := liveRunnerForTest(t, s, stored); !linked || eff.ResourceCapacity != want {
		t.Fatalf("lease-time overlay = (%+v, linked=%v), want parity with the registration overlay", eff, linked)
	}
}

// TestRegistrationZeroesClientResourceCapacity: resource_capacity has no
// legacy self-report semantics — a client-asserted value is dropped in every
// branch, bound or not.
func TestRegistrationZeroesClientResourceCapacity(t *testing.T) {
	hostile := map[string]any{"cpu": 999, "memory": int64(1) << 62, "disk": int64(1) << 62, "pids": 1000000}

	t.Run("require profiles unbound", func(t *testing.T) {
		s := perRunnerTokenServer(t, map[string]string{"runner-a": "token-a"})
		ri := registerWithToken(t, s, map[string]any{
			"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
			"labels": []string{"self"}, "capacity": 9, "resource_capacity": hostile,
		}, "token-a")
		assertNoPrivilegeInheritance(t, "unbound runner", ri)
		if ri.ResourceCapacity != (model.ResourceCapacity{}) || ri.ProfileID != "" {
			t.Fatalf("unbound registration = %+v, want no resource capacity and no marker", ri)
		}
		s.mu.Lock()
		stored := s.runners["runner-a"]
		s.mu.Unlock()
		if stored.ResourceCapacity != (model.ResourceCapacity{}) || stored.ProfileID != "" || stored.Capacity != 0 {
			t.Fatalf("stored unbound runner = %+v, want the empty registration", stored)
		}
	})

	t.Run("legacy dev unbound", func(t *testing.T) {
		// Legacy dev-mode registration still consumes self-reported labels
		// and the count capacity, but never resource_capacity.
		s := New("runner-tok")
		s.AdminToken = "admin-tok"
		ri := registerProfiled(t, s, map[string]any{
			"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
			"labels": []string{"self"}, "capacity": 3, "resource_capacity": hostile,
		}, nil)
		if len(ri.Labels) != 1 || ri.Labels[0] != "self" || ri.Capacity != 3 {
			t.Fatalf("legacy self-report changed: %+v", ri)
		}
		if ri.ResourceCapacity != (model.ResourceCapacity{}) || ri.ProfileID != "" {
			t.Fatalf("legacy dev registration = %+v, want resource_capacity dropped", ri)
		}
	})

	t.Run("db mode unbound", func(t *testing.T) {
		f := newDBFakeStore()
		s := New("shared-dev-tok")
		s.AdminToken = "admin-tok"
		s.RequireProfiles = true
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		ri := registerWithToken(t, s, map[string]any{
			"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
			"labels": []string{"self"}, "capacity": 9, "resource_capacity": hostile,
		}, "shared-dev-tok")
		assertNoPrivilegeInheritance(t, "db unbound runner", ri)
		if ri.ResourceCapacity != (model.ResourceCapacity{}) || ri.ProfileID != "" {
			t.Fatalf("db unbound registration = %+v, want resource_capacity dropped", ri)
		}
		stored, err := f.GetRunner(t.Context(), "runner-a")
		if err != nil {
			t.Fatal(err)
		}
		if stored.ResourceCapacity != (model.ResourceCapacity{}) || stored.ProfileID != "" {
			t.Fatalf("db stored unbound runner = %+v, want resource_capacity dropped", stored)
		}
	})
}

// TestUnlinkRevokesProfileSnapshotInFSMode drives the fs-mode revocation end
// to end: a bound runner leases under its profile (including the profile's
// resource admission), the admin unlink clears the marked snapshot row AND
// the binding in one step, the very next poll takes nothing, the revocation
// survives a restart through the atomic snapshot, and a re-bind restores the
// profile.
func TestUnlinkRevokesProfileSnapshotInFSMode(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.RequireProfiles = true
	// Per-runner bearer credentials so the registration resolves the
	// runner-ID binding (the shared dev token has no runner identity).
	s.LoadRunnerTokens(map[string]string{"runner-a": auth.TokenDigest("token-a")})
	// The untrusted memory ceiling is the enqueue bound; raise it above the
	// profile's capacity so ADMISSION decides the oversubscription.
	s.UntrustedMemoryCeiling = 16 << 30
	createProfile(t, s, unlinkRevokeProfile())
	bindRunnerProfile(t, s, "revoke", "runner-a", "admin-tok")

	ri := registerWithToken(t, s, map[string]any{
		"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
		"labels": []string{"spoofed"}, "capacity": 99,
		"resource_capacity": map[string]any{"memory": int64(1) << 62},
	}, "token-a")
	wantCapacity := model.ResourceCapacity{CPU: 4, Memory: 8 << 30, Disk: 16 << 30, PIDs: 512}
	if ri.Capacity != 4 || ri.ResourceCapacity != wantCapacity || ri.ProfileID != "revoke" {
		t.Fatalf("bound registration = %+v, want the profile's capacity and marker", ri)
	}

	// Resource admission at lease time honors the profile's 8 GiB: one 5 GiB
	// job leases, the second cannot fit the remaining 3 GiB.
	jobA := fsSubmitResource(t, s, "revoke/res", unlinkRevokePipeline)
	jobB := fsSubmitResource(t, s, "revoke/res", unlinkRevokePipeline)
	taskA := unlinkRevokeNext(t, s, "runner-a", "token-a")
	if taskA.Job.ID != jobA {
		t.Fatalf("first lease = %s, want %s", taskA.Job.ID, jobA)
	}
	unlinkRevokeBlockedNext(t, s, "runner-a", "token-a")
	if got := fsJob(t, s, jobB).QueueReason; got != "RUNNER_CAPACITY" {
		t.Fatalf("second job reason = %q, want RUNNER_CAPACITY", got)
	}
	unlinkRevokeComplete(t, s, "runner-a", "token-a", taskA, "success")

	// Unlink: the binding AND the marked snapshot row are cleared together.
	if w := doJSON(t, s, http.MethodDelete, "/api/v1/runner-profiles/revoke/runner/runner-a", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("unbind: %d %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	stored := s.runners["runner-a"]
	s.mu.Unlock()
	if stored.ProfileID != "" || stored.Capacity != 0 || stored.ResourceCapacity != (model.ResourceCapacity{}) ||
		len(stored.Labels) != 0 || stored.Region != "" || len(stored.AllowedRepositories) != 0 ||
		len(stored.Capabilities) != 0 || stored.CostPerHour != 0 || stored.PowerWatts != 0 {
		t.Fatalf("snapshot after unlink = %+v, want every profile-derived field cleared", stored)
	}
	// The removed profile stops applying to the very next poll: the revoked
	// row admits nothing, and the explainer reports the runner's exhausted
	// capacity (the label it removed is no longer declared either).
	unlinkRevokeBlockedNext(t, s, "runner-a", "token-a")
	if got := fsJob(t, s, jobB).QueueReason; got != "RUNNER_CAPACITY" {
		t.Fatalf("post-unlink reason = %q, want RUNNER_CAPACITY", got)
	}

	// The revocation rides the fs snapshot: a restart keeps every
	// profile-derived field cleared. (The fs loader's legacy dev-mode clamp
	// may hand an unprofiled capacity-0 row the generic dev capacity 1 — the
	// same value a fresh dev-mode registration gets — but it can never
	// restore a profile grant; the label-requiring job below still refuses.)
	restarted, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted.RequireProfiles = true
	restarted.LoadRunnerTokens(map[string]string{"runner-a": auth.TokenDigest("token-a")})
	restarted.UntrustedMemoryCeiling = 16 << 30
	restarted.mu.Lock()
	stored = restarted.runners["runner-a"]
	restarted.mu.Unlock()
	if stored.ProfileID != "" || stored.ResourceCapacity != (model.ResourceCapacity{}) || len(stored.Labels) != 0 ||
		stored.Region != "" || len(stored.AllowedRepositories) != 0 || len(stored.Capabilities) != 0 ||
		stored.CostPerHour != 0 || stored.PowerWatts != 0 {
		t.Fatalf("post-restart snapshot = %+v, want the revocation persisted", stored)
	}
	unlinkRevokeBlockedNext(t, restarted, "runner-a", "token-a")

	// Re-bind and re-register restore the profile (the documented repair).
	bindRunnerProfile(t, restarted, "revoke", "runner-a", "admin-tok")
	re := registerWithToken(t, restarted, map[string]any{
		"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
	}, "token-a")
	if re.Capacity != 4 || re.ResourceCapacity != wantCapacity || re.ProfileID != "revoke" {
		t.Fatalf("re-registration = %+v, want the re-bound profile restored", re)
	}
	taskB := unlinkRevokeNext(t, restarted, "runner-a", "token-a")
	if taskB.Job.ID != jobB {
		t.Fatalf("post-rebind lease = %s, want %s", taskB.Job.ID, jobB)
	}
}

// TestFSDanglingRunnerIDBindingDeniesLease: a binding whose profile row is
// gone fails the fs-mode lease path closed (zero capacity, 204), exactly like
// a dangling certificate binding — never the stale (marked) snapshot.
func TestFSDanglingRunnerIDBindingDeniesLease(t *testing.T) {
	s := adminProfileServer(t)
	s.UntrustedMemoryCeiling = 16 << 30
	createProfile(t, s, unlinkRevokeProfile())
	bindRunnerProfile(t, s, "revoke", "runner-a", "admin-tok")
	s.mu.Lock()
	s.runners["runner-a"] = model.Runner{
		ID: "runner-a", Name: "ra", ProfileID: "revoke", Capacity: 4,
		Labels: []string{"container"}, ResourceCapacity: model.ResourceCapacity{Memory: 8 << 30},
	}
	s.mu.Unlock()
	fsSubmitResource(t, s, "revoke/res", unlinkRevokePipeline)

	// Delete the profile row out from under the live binding (the
	// profile-delete path; the admin surface has no delete endpoint).
	s.mu.Lock()
	delete(s.profiles, "revoke")
	s.mu.Unlock()

	s.mu.Lock()
	eff, linked := s.liveRunnerLocked(s.runners["runner-a"])
	s.mu.Unlock()
	if !linked || eff.Capacity != 0 {
		t.Fatalf("dangling runner-ID effective = (%+v, linked=%v), want capacity 0 fail closed", eff, linked)
	}
	fsBlockedNext(t, s, "runner-a")
}

// TestUnlinkRevokesProfileSerializedWithLease pins the lock+snapshot
// discipline: the unlink mutation and the lease decision are serialized by
// the server mutex, so a lease either sees the binding (and the untouched
// snapshot) or the revoked row — never a binding-less row that still carries
// the profile's capacity.
func TestUnlinkRevokesProfileSerializedWithLease(t *testing.T) {
	s := adminProfileServer(t)
	createProfile(t, s, unlinkRevokeProfile())
	bindRunnerProfile(t, s, "revoke", "runner-a", "admin-tok")
	s.mu.Lock()
	s.runners["runner-a"] = model.Runner{
		ID: "runner-a", Name: "ra", ProfileID: "revoke", Capacity: 4,
		Labels: []string{"container"}, ResourceCapacity: model.ResourceCapacity{Memory: 8 << 30},
	}
	s.mu.Unlock()

	// Interleave the two mutex holders explicitly: the lease resolution
	// first (binding live), then the unlink mutation, then the resolution
	// again (binding gone, snapshot revoked).
	s.mu.Lock()
	before, linkedBefore := s.liveRunnerLocked(s.runners["runner-a"])
	s.mu.Unlock()
	if !linkedBefore || before.Capacity != 4 || before.ResourceCapacity.Memory != 8<<30 {
		t.Fatalf("pre-unlink effective = (%+v, linked=%v), want the profile", before, linkedBefore)
	}

	if w := doJSON(t, s, http.MethodDelete, "/api/v1/runner-profiles/revoke/runner/runner-a", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("unbind: %d %s", w.Code, w.Body.String())
	}

	s.mu.Lock()
	after, linkedAfter := s.liveRunnerLocked(s.runners["runner-a"])
	s.mu.Unlock()
	if linkedAfter || after.Capacity != 0 || after.ResourceCapacity != (model.ResourceCapacity{}) {
		t.Fatalf("post-unlink effective = (%+v, linked=%v), want no binding and zero capacity", after, linkedAfter)
	}
}

// TestUnlinkRevokesProfileMaterializedByLease: a runner that registered
// BEFORE its binding existed still gets its profile-derived attributes
// revoked on unlink. The lease-time overlay stamps the materialized snapshot
// with the profile's provenance, so the write-back in next() cannot leave an
// unmarked row holding the removed profile's grants.
func TestUnlinkRevokesProfileMaterializedByLease(t *testing.T) {
	s := perRunnerTokenServer(t, map[string]string{"runner-a": "token-a"})
	s.UntrustedMemoryCeiling = 16 << 30
	createProfile(t, s, unlinkRevokeProfile())

	// Unprofiled registration first (RequireProfiles registers empty).
	ri := registerWithToken(t, s, map[string]any{
		"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
	}, "token-a")
	if ri.Capacity != 0 || ri.ProfileID != "" {
		t.Fatalf("unprofiled registration = %+v, want the empty registration", ri)
	}

	// The binding arrives afterwards; the next poll materializes the live
	// profile onto the stored row (next writes the effective view back).
	bindRunnerProfile(t, s, "revoke", "runner-a", "admin-tok")
	fsSubmitResource(t, s, "revoke/res", unlinkRevokePipeline)
	unlinkRevokeNext(t, s, "runner-a", "token-a")
	s.mu.Lock()
	stored := s.runners["runner-a"]
	s.mu.Unlock()
	if stored.ProfileID != "revoke" || stored.Capacity != 4 || stored.ResourceCapacity.Memory != 8<<30 {
		t.Fatalf("materialized snapshot = %+v, want the profile's provenance and attributes", stored)
	}

	// Unlink revokes the materialized attributes.
	if w := doJSON(t, s, http.MethodDelete, "/api/v1/runner-profiles/revoke/runner/runner-a", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("unbind: %d %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	stored = s.runners["runner-a"]
	s.mu.Unlock()
	if stored.ProfileID != "" || stored.Capacity != 0 || stored.ResourceCapacity != (model.ResourceCapacity{}) || len(stored.Labels) != 0 {
		t.Fatalf("snapshot after unlink = %+v, want the materialized grants cleared", stored)
	}
	fsSubmitResource(t, s, "revoke/res", unlinkRevokePipeline)
	unlinkRevokeBlockedNext(t, s, "runner-a", "token-a")
}

// TestUnlinkResponseStillReportsTheUnboundState: the handler's response is
// unchanged (idempotent 200 with unlinked=true), including for a runner that
// never registered — revocation must not turn a no-op unlink into an error.
func TestUnlinkResponseStillReportsTheUnboundState(t *testing.T) {
	s := adminProfileServer(t)
	createProfile(t, s, unlinkRevokeProfile())
	w := doJSON(t, s, http.MethodDelete, "/api/v1/runner-profiles/revoke/runner/never-registered", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("unregistered unlink = %d %s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["unlinked"] != true || got["runner_id"] != "never-registered" || got["profile_id"] != "revoke" {
		t.Fatalf("unlink response = %v", got)
	}
}
