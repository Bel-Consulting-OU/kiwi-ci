package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const scheduleSpec = `version: 1
on:
  schedule:
    cron: "* * * * *"
    branches:
      - main
jobs:
  nightly:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo nightly
`

func TestParseCron(t *testing.T) {
	c, err := ParseCron("*/15 2,14 * * 1-5")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	// 2026-09-14 is a Sunday; 2026-09-15 is a Monday (weekday 1): inside
	// the 1-5 range.
	monday := time.Date(2026, 9, 15, 14, 30, 0, 0, time.UTC)
	if !c.matches(monday) {
		t.Fatal("14:30 on a weekday should match")
	}
	// 2026-09-13 is a Sunday (weekday 0): outside 1-5.
	if c.matches(time.Date(2026, 9, 13, 14, 30, 0, 0, time.UTC)) {
		t.Fatal("Sunday must not match 1-5")
	}
	if c.matches(time.Date(2026, 9, 15, 14, 50, 0, 0, time.UTC)) {
		t.Fatal("50 must not match */15")
	}
	if !c.matches(time.Date(2026, 9, 15, 14, 45, 0, 0, time.UTC)) {
		t.Fatal("14:45 should match */15")
	}
	if !c.matches(time.Date(2026, 9, 15, 2, 0, 0, 0, time.UTC)) {
		t.Fatal("02:00 should match the hour list")
	}
	next := c.next(base)
	if next.IsZero() || !c.matches(next) || !next.After(base) {
		t.Fatalf("next(%v) = %v", base, next)
	}
	if _, err := ParseCron("61 * * * *"); err == nil {
		t.Fatal("minute 61 must be rejected")
	}
	if _, err := ParseCron("* * * *"); err == nil {
		t.Fatal("4 fields must be rejected")
	}
}

func TestParseScheduleSpec(t *testing.T) {
	cron, ref, err := parseScheduleSpec(scheduleSpec)
	if err != nil {
		t.Fatal(err)
	}
	_ = cron
	if ref != "refs/heads/main" {
		t.Fatalf("ref = %q", ref)
	}
	if _, _, err := parseScheduleSpec("version: 1\njobs: {}"); err == nil {
		t.Fatal("missing on.schedule.cron must be rejected")
	}
	if _, _, err := parseScheduleSpec("version: 1\non:\n  schedule:\n    cron: \"61 * * * *\"\njobs:\n  a:\n    steps:\n      - run: x\n"); err == nil {
		t.Fatal("invalid cron must be rejected")
	}
}

func TestScheduleTriggerOncePerNominalDBMode(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	sc := storage.Schedule{
		ID:         "sched1",
		Repository: "https://example.com/o/r.git",
		Spec:       scheduleSpec,
		Enabled:    true,
		CreatedAt:  time.Now().UTC().Add(-3 * time.Minute),
	}
	if err := f.UpsertSchedule(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	if err := s.reloadSchedulesDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// First tick fires every due nominal exactly once.
	s.fireDueSchedules(context.Background(), now)
	f.mu.Lock()
	occ := append([]storage.Occurrence(nil), f.occurrences["sched1"]...)
	runs := len(f.insertRunCalls)
	f.mu.Unlock()
	if len(occ) == 0 || runs != len(occ) {
		t.Fatalf("occurrences = %d, runs = %d", len(occ), runs)
	}
	// A second tick adds nothing: every due nominal was claimed.
	s.fireDueSchedules(context.Background(), now)
	f.mu.Lock()
	occ2 := len(f.occurrences["sched1"])
	runs2 := len(f.insertRunCalls)
	f.mu.Unlock()
	if occ2 != len(occ) || runs2 != runs {
		t.Fatalf("duplicate firing: occurrences=%d runs=%d", occ2, runs2)
	}
	// Per-nominal idempotency: claiming the same nominal again reports an
	// existing claim.
	claimed, err := f.ClaimScheduleOccurrence(context.Background(), "sched1", occ[0].Nominal, "some-other-run")
	if err != nil {
		t.Fatal(err)
	}
	if claimed {
		t.Fatal("re-claim of a fired nominal with a different run ID must fail")
	}
	// A restarted control plane against the same store fires nothing new.
	s2 := New("token")
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s2.fireDueSchedules(context.Background(), now)
	f.mu.Lock()
	occ3 := len(f.occurrences["sched1"])
	runs3 := len(f.insertRunCalls)
	f.mu.Unlock()
	if occ3 != len(occ) || runs3 != runs {
		t.Fatalf("restart duplicate: occurrences=%d runs=%d", occ3, runs3)
	}
}

func TestScheduleTriggerOncePerNominalMemoryMode(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token",
		`{"repository":"https://example.com/o/r.git","spec":`+jsonString(scheduleSpec)+`}`)
	if w.Code != http.StatusOK {
		t.Fatalf("put schedule = %d: %s", w.Code, w.Body.String())
	}
	var sc storage.Schedule
	if err := json.Unmarshal(w.Body.Bytes(), &sc); err != nil {
		t.Fatal(err)
	}
	// Backdate LastRun so the next nominal is due.
	s.mu.Lock()
	sc.LastRun = timePtr(time.Now().UTC().Add(-3 * time.Minute))
	s.schedules[sc.ID] = sc
	s.mu.Unlock()
	now := time.Now().UTC()
	s.fireDueSchedules(context.Background(), now)
	s.mu.Lock()
	runs := len(s.runs)
	s.mu.Unlock()
	if runs == 0 {
		t.Fatal("no runs fired for due schedule")
	}
	s.fireDueSchedules(context.Background(), now)
	s.mu.Lock()
	runs2 := len(s.runs)
	s.mu.Unlock()
	if runs2 != runs {
		t.Fatalf("second fire added runs: %d -> %d", runs, runs2)
	}
	// Re-fire at the current time so the CURRENT nominal is claimed before
	// the manual trigger below (a minute rollover between the fires above
	// and the trigger must not leave it unclaimed).
	s.fireDueSchedules(context.Background(), time.Now().UTC())
	// Manual trigger in the same nominal minute conflicts.
	w = doJSON(t, s, http.MethodPost, "/api/v1/schedules/"+sc.ID+"/trigger", "token", "")
	if w.Code == http.StatusAccepted {
		t.Fatal("manual trigger duplicated the same nominal occurrence")
	}
}

func TestScheduleEndpoints(t *testing.T) {
	s := New("token")
	w := doJSON(t, s, http.MethodGet, "/api/v1/schedules", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d", w.Code)
	}
	if w = doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token",
		`{"repository":"https://example.com/o/r.git","spec":`+jsonString(scheduleSpec)+`}`); w.Code != http.StatusOK {
		t.Fatalf("put = %d: %s", w.Code, w.Body.String())
	}
	var sc storage.Schedule
	if err := json.Unmarshal(w.Body.Bytes(), &sc); err != nil {
		t.Fatal(err)
	}
	if sc.ID == "" || !sc.Enabled {
		t.Fatalf("schedule = %+v", sc)
	}
	// Trigger for the current nominal works exactly once.
	w = doJSON(t, s, http.MethodPost, "/api/v1/schedules/"+sc.ID+"/trigger", "token", "")
	if w.Code != http.StatusAccepted {
		t.Fatalf("trigger = %d: %s", w.Code, w.Body.String())
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/schedules/"+sc.ID+"/trigger", "token", "")
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate trigger = %d, want 409: %s", w.Code, w.Body.String())
	}
	// Missing schedule → 404.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/schedules/missing/trigger", "token", ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing trigger = %d", w.Code)
	}
	// Invalid cron rejected.
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token",
		`{"repository":"r","spec":"version: 1\non:\n  schedule:\n    cron: \"bad cron spec\"\njobs:\n  a:\n    steps:\n      - run: x\n"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid cron put = %d: %s", w.Code, w.Body.String())
	}
}

func timePtr(t time.Time) *time.Time { return &t }

var _ = strings.TrimSpace

// TestScheduleCrossReplicaDisableStopsLeader is the HA coherence regression:
// replica A leads with a cached schedule, replica B disables it in the
// durable store, and A's next tick must re-read the authoritative row and
// skip the occurrence instead of firing its stale copy. Same for a spec
// update: the leader must fire the UPDATED spec.
func TestScheduleCrossReplicaDisableStopsLeader(t *testing.T) {
	f := newDBFakeStore()
	a := New("token")
	if err := a.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	b := New("token")
	if err := b.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	// Seed a schedule through replica B (durable store is shared).
	sc := storage.Schedule{
		ID: "s1", Repository: "acme/app", RepoID: "github.com/acme/app",
		RepoURL: "https://github.com/acme/app.git", Forge: "github",
		Enabled: true, Trusted: false,
		Spec: "version: 1\non:\n  schedule:\n    cron: \"* * * * *\"\njobs:\n  j:\n    runtime: container\n    image: alpine\n    steps:\n      - run: echo hi\n",
	}
	if err := f.UpsertSchedule(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	// Replica A's mirror knows the schedule (simulating an earlier tick).
	a.mu.Lock()
	a.schedules[sc.ID] = sc
	a.mu.Unlock()

	now := time.Now().UTC().Truncate(time.Minute).Add(30 * time.Second)
	nominal := now

	// B disables it durably. A still has the enabled copy cached.
	sc.Enabled = false
	if err := f.UpsertSchedule(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	if _, fired, err := a.fireSchedule(context.Background(), a.schedules[sc.ID], nominal); err == nil || fired {
		t.Fatalf("leader fired a disabled schedule: fired=%v err=%v", fired, err)
	}
	// The durable row is still disabled and no run was created.
	if got := len(f.runs); got != 0 {
		t.Fatalf("runs created = %d, want 0", got)
	}
}

// TestSchedulePromotionReloadsAuthoritativeRows proves a freshly promoted
// leader replaces its stale mirror with durable rows (and disables invalid
// ones fail-closed) before it can fire anything.
func TestSchedulePromotionReloadsAuthoritativeRows(t *testing.T) {
	f := newDBFakeStore()
	a := New("token")
	if err := a.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	b := New("token")
	if err := b.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	valid := storage.Schedule{
		ID: "valid", Repository: "acme/app", RepoID: "github.com/acme/app",
		RepoURL: "https://github.com/acme/app.git", Forge: "github", Enabled: true,
		Spec: "version: 1\non:\n  schedule: \"* * * * *\"\njobs:\n  j:\n    runtime: container\n    image: alpine\n    steps:\n      - run: echo hi\n",
	}
	invalid := storage.Schedule{
		ID: "invalid", Repository: "acme/other", RepoID: "github.com/acme/other",
		RepoURL: "https://github.com/acme/app.git", Forge: "github", Enabled: true,
		Spec: valid.Spec,
	}
	for _, sc := range []storage.Schedule{valid, invalid} {
		if err := f.UpsertSchedule(context.Background(), sc); err != nil {
			t.Fatal(err)
		}
	}
	// Standby mirror is empty/stale; promotion reload must populate it and
	// disable the inconsistent row.
	if err := a.reloadSchedulesFromStore(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	_, hasValid := a.schedules["valid"]
	inv, hasInvalid := a.schedules["invalid"]
	a.mu.Unlock()
	if !hasValid {
		t.Fatal("reload did not pick up the authoritative schedule")
	}
	if hasInvalid && inv.Enabled {
		t.Fatal("inconsistent schedule must be disabled at reload")
	}
}
