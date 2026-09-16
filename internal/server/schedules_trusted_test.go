package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// trustedScheduleBody is the PUT body for a TRUSTED schedule targeting
// gitlab.com/acme/service.
var trustedScheduleBody = `{"repository":"acme/service","repo_url":"https://gitlab.com/acme/service.git","trusted":true,"spec":` + jsonString(scheduleSpec) + `}`

// nativeScheduleSpec runs under native runtime: it only admits when the
// schedule fires with trusted capabilities, proving the stored Trusted flag
// (not the request context) drives the fire.
const nativeScheduleSpec = `version: 1
on:
  schedule:
    cron: "0 0 * * *"
    branches:
      - main
jobs:
  nightly:
    runtime: native
    steps:
      - run: echo nightly
`

// TestTrustedScheduleCreationRequiresTrustedRun (P0-4): creating a TRUSTED
// schedule requires the repo-scoped trusted_run grant for that repository
// in addition to policy_manage.
func TestTrustedScheduleCreationRequiresTrustedRun(t *testing.T) {
	// A principal with policy_manage but NO trusted_run grant is refused.
	s := storeServer(t, "", map[string]auth.Principal{
		"mgmt": {Subject: "mgmt-bot", Roles: []auth.Role{auth.RolePolicyManage}},
	})
	w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "mgmt", trustedScheduleBody)
	if w.Code != http.StatusForbidden {
		t.Fatalf("trusted schedule without trusted_run = %d, want 403: %s", w.Code, w.Body.String())
	}
	// A principal WITH the repo-scoped trusted_run grant succeeds.
	s2 := storeServer(t, "", map[string]auth.Principal{
		"mgmt": {
			Subject: "mgmt-bot",
			Roles:   []auth.Role{auth.RolePolicyManage},
			Repositories: map[string]auth.RepositoryPermission{
				"gitlab.com/acme/service": {TrustedRun: true},
			},
		},
	})
	w = doJSON(t, s2, http.MethodPut, "/api/v1/schedules", "mgmt", trustedScheduleBody)
	if w.Code != http.StatusOK {
		t.Fatalf("trusted schedule with trusted_run = %d, want 200: %s", w.Code, w.Body.String())
	}
	var sc storage.Schedule
	if err := json.Unmarshal(w.Body.Bytes(), &sc); err != nil {
		t.Fatal(err)
	}
	if !sc.Trusted {
		t.Fatal("stored schedule lost the Trusted flag")
	}
}

// TestScheduleStoresCanonicalIdentity (P0-4): the schedule persists the
// canonical RepoID, the clone RepoURL, the derived Forge and the Trusted
// flag — Repository is the full name, no longer both clone URL and identity.
func TestScheduleStoresCanonicalIdentity(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", trustedScheduleBody)
	if w.Code != http.StatusOK {
		t.Fatalf("put = %d: %s", w.Code, w.Body.String())
	}
	var sc storage.Schedule
	if err := json.Unmarshal(w.Body.Bytes(), &sc); err != nil {
		t.Fatal(err)
	}
	if sc.Repository != "acme/service" {
		t.Fatalf("repository = %q", sc.Repository)
	}
	if sc.RepoID != "gitlab.com/acme/service" {
		t.Fatalf("repo_id = %q, want canonical gitlab.com/acme/service", sc.RepoID)
	}
	if sc.RepoURL != "https://gitlab.com/acme/service.git" {
		t.Fatalf("repo_url = %q", sc.RepoURL)
	}
	if sc.Forge != "gitlab" {
		t.Fatalf("forge = %q, want gitlab", sc.Forge)
	}
	if !sc.Trusted {
		t.Fatal("trusted flag not persisted")
	}
}

// TestFireScheduleUsesStoredIdentity (P0-4): automatic firing uses the
// STORED immutable identity — RepoID as identity, RepoURL as clone URL,
// Trusted from the stored flag — even when no request context exists at
// all.
func TestFireScheduleUsesStoredIdentity(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sc := storage.Schedule{
		ID: "sched-native", Repository: "acme/service",
		RepoID: "gitlab.com/acme/service", RepoURL: "https://gitlab.com/acme/service.git",
		Forge: "gitlab", Trusted: true, Spec: nativeScheduleSpec, Enabled: true,
		CreatedAt: time.Now().UTC(),
	}
	// Seed the schedule directly and fire it with NO request context: the
	// fire must use the stored fields. The native runtime only admits
	// because Trusted is stored true.
	if s.DB != nil {
		_ = s
		t.Skip("memory mode only")
	}
	s.mu.Lock()
	s.schedules[sc.ID] = sc
	s.mu.Unlock()
	run, fired, err := s.fireSchedule(context.Background(), sc, time.Now().UTC().Truncate(time.Minute))
	if err != nil {
		t.Fatalf("fireSchedule: %v", err)
	}
	if !fired {
		t.Fatal("fireSchedule reported not fired")
	}
	if run.RepoFullName != "gitlab.com/acme/service" {
		t.Fatalf("fired run RepoFullName = %q, want stored RepoID", run.RepoFullName)
	}
	if run.Repo != "https://gitlab.com/acme/service.git" {
		t.Fatalf("fired run Repo = %q, want stored RepoURL", run.Repo)
	}
	if !run.Trusted {
		t.Fatal("fired run lost the stored Trusted flag")
	}
	s.mu.Lock()
	jobs := len(s.jobs)
	s.mu.Unlock()
	if jobs != 1 {
		t.Fatalf("fired run has %d jobs, want 1", jobs)
	}
}

// TestManualTriggerRechecksTrustedRun (P0-4): manually triggering a TRUSTED
// schedule re-checks the repo-scoped trusted_run grant — a principal whose
// grant is absent (even with policy_manage) gets 403.
func TestManualTriggerRechecksTrustedRun(t *testing.T) {
	s := storeServer(t, "", map[string]auth.Principal{
		"creator": {
			Subject: "creator-bot",
			Roles:   []auth.Role{auth.RolePolicyManage},
			Repositories: map[string]auth.RepositoryPermission{
				"gitlab.com/acme/service": {TrustedRun: true},
			},
		},
		"unprivileged": {Subject: "mgmt-only", Roles: []auth.Role{auth.RolePolicyManage}},
		"ops":          {Subject: "ops", Roles: []auth.Role{auth.RoleAdmin}},
	})
	w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "creator", trustedScheduleBody)
	if w.Code != http.StatusOK {
		t.Fatalf("put = %d: %s", w.Code, w.Body.String())
	}
	var sc storage.Schedule
	if err := json.Unmarshal(w.Body.Bytes(), &sc); err != nil {
		t.Fatal(err)
	}
	// A principal without the trusted_run grant cannot trigger the trusted
	// schedule manually.
	w = doJSON(t, s, http.MethodPost, "/api/v1/schedules/"+sc.ID+"/trigger", "unprivileged", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("manual trigger without trusted_run = %d, want 403: %s", w.Code, w.Body.String())
	}
	// The original grant holder can.
	w = doJSON(t, s, http.MethodPost, "/api/v1/schedules/"+sc.ID+"/trigger", "creator", "")
	if w.Code != http.StatusAccepted {
		t.Fatalf("manual trigger with trusted_run = %d, want 202: %s", w.Code, w.Body.String())
	}
}
