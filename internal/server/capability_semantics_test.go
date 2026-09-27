package server

// W3-A server-side capability-separation tests: the registration derives the
// reported hardware claim from the payload's capabilities field and persists
// the intersection with the linked profile, a live profile edit can never
// re-widen the runner past that claim, and the queue-reason explainer applies
// the same enforced runtime predicate the lease path uses.

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/queue"
)

// TestRegistrationCapabilityIntersectionPersistsAndStaysNarrow drives the
// memory-mode registration: payload capabilities [native] against a profile
// ceiling [native,container] store the effective [native] with the enforced
// marker and the derived reported claim (client-asserted
// reported_capabilities/capabilities_enforced keys never survive), and a live
// profile widening recomputes the same [native].
func TestRegistrationCapabilityIntersectionPersistsAndStaysNarrow(t *testing.T) {
	s := perRunnerTokenServer(t, map[string]string{"runner-a": "token-a"})
	createProfile(t, s, model.RunnerProfile{
		ID: "cap-prof", Labels: []string{"container"},
		Capabilities: []string{"native", "container"}, MaxCapacity: 2,
	})
	bindRunnerProfile(t, s, "cap-prof", "runner-a", "admin-tok")

	ri := registerWithToken(t, s, map[string]any{
		"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
		"capabilities":          []string{"native"},
		"reported_capabilities": []string{"tart"},
		"capabilities_enforced": false,
		"allowed_repositories":  []string{"github.com/o/elsewhere"},
		"resource_capacity":     map[string]any{"cpu": 999},
		"profile_id":            "attacker",
	}, "token-a")
	if !reflect.DeepEqual(ri.Capabilities, []string{"native"}) {
		t.Fatalf("response capabilities = %v, want the intersection [native]", ri.Capabilities)
	}
	if !reflect.DeepEqual(ri.ReportedCapabilities, []string{"native"}) {
		t.Fatalf("response reported capabilities = %v, want the derived payload claim [native]", ri.ReportedCapabilities)
	}
	if !ri.CapabilitiesEnforced {
		t.Fatal("a profile-linked registration must be enforced")
	}

	s.mu.Lock()
	stored := s.runners["runner-a"]
	s.mu.Unlock()
	if !reflect.DeepEqual(stored.Capabilities, []string{"native"}) ||
		!reflect.DeepEqual(stored.ReportedCapabilities, []string{"native"}) || !stored.CapabilitiesEnforced {
		t.Fatalf("stored runner = caps %v reported %v enforced %v, want the [native]/[native]/true triple",
			stored.Capabilities, stored.ReportedCapabilities, stored.CapabilitiesEnforced)
	}

	// The live profile widens back to [native,container]: the recomputed
	// intersection stays [native].
	if err := s.upsertProfile(t.Context(), model.RunnerProfile{
		ID: "cap-prof", Labels: []string{"container"},
		Capabilities: []string{"native", "container"}, MaxCapacity: 2,
	}); err != nil {
		t.Fatal(err)
	}
	eff, linked := liveRunnerForTest(t, s, stored)
	if !linked || !eff.CapabilitiesEnforced || !reflect.DeepEqual(eff.Capabilities, []string{"native"}) {
		t.Fatalf("live effective = caps %v enforced %v linked %v, want the [native] intersection",
			eff.Capabilities, eff.CapabilitiesEnforced, linked)
	}
}

// TestDBRegistrationCapabilityIntersectionPersists is the durable-store
// mirror: the guarded runner write persists the reported claim and enforced
// intersection, and the scheduler's live view recomputes the same set.
func TestDBRegistrationCapabilityIntersectionPersists(t *testing.T) {
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
	createProfile(t, s, model.RunnerProfile{
		ID: "cap-db-prof", Labels: []string{"container"},
		Capabilities: []string{"native", "container"}, MaxCapacity: 2,
	})
	bindRunnerProfile(t, s, "cap-db-prof", "runner-a", "admin-tok")

	ri := registerWithToken(t, s, map[string]any{
		"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
		"capabilities": []string{"container"},
	}, "token-a")
	if !reflect.DeepEqual(ri.Capabilities, []string{"container"}) || !ri.CapabilitiesEnforced {
		t.Fatalf("response = caps %v enforced %v, want [container]/true", ri.Capabilities, ri.CapabilitiesEnforced)
	}
	stored, err := f.GetRunner(t.Context(), "runner-a")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored.ReportedCapabilities, []string{"container"}) ||
		!reflect.DeepEqual(stored.Capabilities, []string{"container"}) || !stored.CapabilitiesEnforced {
		t.Fatalf("stored runner = reported %v caps %v enforced %v, want the persisted [container] claim",
			stored.ReportedCapabilities, stored.Capabilities, stored.CapabilitiesEnforced)
	}
	eff := s.Sched.EffectiveRunner(t.Context(), stored)
	if !eff.CapabilitiesEnforced || !reflect.DeepEqual(eff.Capabilities, []string{"container"}) {
		t.Fatalf("live effective = caps %v enforced %v, want [container]/true", eff.Capabilities, eff.CapabilitiesEnforced)
	}
}

// TestQueueReasonRuntimeCapabilityMismatch pins the capability dimension of
// the fleet explainer: an enforced runner whose intersection excludes the
// job's runtime is not a compatible runner, while a legacy unenforced empty
// list stays unrestricted.
func TestQueueReasonRuntimeCapabilityMismatch(t *testing.T) {
	jobWithRuntime := func(runtime string) model.Job {
		j := model.Job{ID: "j", RunID: "r", Key: "k", Status: model.StatusQueued}
		if runtime != "" {
			j.CompiledJobPayload = &model.CompiledJobPayload{
				EffectiveJob: map[string]any{"job": map[string]any{"runtime": runtime}},
			}
		}
		return j
	}
	enforced := func(caps ...string) queueRunnerView {
		return queueRunnerView{slots: 2, capabilities: caps, capsEnforced: true}
	}
	cases := []struct {
		name  string
		job   model.Job
		fleet []queueRunnerView
		want  queue.ReasonCode
	}{
		{"enforced native runner cannot take a container job", jobWithRuntime("container"),
			[]queueRunnerView{enforced("native")}, queue.NoCompatibleRunner},
		{"enforced container runner takes a container job", jobWithRuntime("container"),
			[]queueRunnerView{enforced("container")}, queue.None},
		{"enforced empty intersection denies the native default", jobWithRuntime(""),
			[]queueRunnerView{enforced()}, queue.NoCompatibleRunner},
		{"legacy unenforced empty list is unrestricted", jobWithRuntime("container"),
			[]queueRunnerView{{slots: 2}}, queue.None},
		{"a runtime-compatible runner still makes the fleet compatible", jobWithRuntime("container"),
			[]queueRunnerView{enforced("native"), enforced("container")}, queue.None},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := queueReasonForJob(tc.job, tc.fleet, true, false); got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMemoryQueueReasonRuntimeCapabilityFromProfile drives the memory
// explainer with a profile-linked runner whose live intersection excludes the
// queued job's runtime: the job is explained as NO_COMPATIBLE_RUNNER even
// though its labels would match the profile.
func TestMemoryQueueReasonRuntimeCapabilityFromProfile(t *testing.T) {
	s := adminProfileServer(t)
	createProfile(t, s, model.RunnerProfile{
		ID: "q-cap-prof", Labels: []string{"container"},
		Capabilities: []string{"native"}, MaxCapacity: 1,
	})
	bindRunnerProfile(t, s, "q-cap-prof", "runner-a", "admin-tok")
	ri := model.Runner{ID: "runner-a", Capacity: 1, Labels: []string{"snapshot"}, ReportedCapabilities: []string{"native"}}
	seedLiveRunner(t, s, ri)
	s.mu.Lock()
	s.jobs["job-q"] = model.Job{
		ID: "job-q", RunID: "run-q", Key: "build", Status: model.StatusQueued,
		RequiredLabels: []string{"container"}, RepoID: "github.com/o/r",
		CompiledJobPayload: &model.CompiledJobPayload{EffectiveJob: map[string]any{"job": map[string]any{"runtime": "container"}}},
	}
	s.mu.Unlock()

	s.mu.Lock()
	s.applyQueueReasonsMemoryLocked(ri)
	reason := s.jobs["job-q"].QueueReason
	s.mu.Unlock()
	if reason != string(queue.NoCompatibleRunner) {
		t.Fatalf("container job on an enforced [native] profile = %q, want NO_COMPATIBLE_RUNNER", reason)
	}
}

// TestRegistrationMalformedCapabilityPayload: a payload whose capabilities
// field is not a string list is refused (400) instead of being silently
// coerced.
func TestRegistrationMalformedCapabilityPayload(t *testing.T) {
	s := perRunnerTokenServer(t, map[string]string{"runner-a": "token-a"})
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": "runner-a", "name": "ra", "protocol_min": 3, "protocol_max": 3,
			"capabilities": map[string]any{"native": true}},
		"token-a", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed capabilities register = %d %s, want 400", w.Code, w.Body.String())
	}
}
