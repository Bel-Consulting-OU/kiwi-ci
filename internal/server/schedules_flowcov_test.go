package server

import (
	"context"
	"errors"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func TestFlowCronValueAndField(t *testing.T) {
	if v, err := cronValue("jan", 1, 12, cronMonthNames); err != nil || v != 1 {
		t.Fatalf("named month = %d %v", v, err)
	}
	if _, err := cronValue("bogus", 1, 12, cronMonthNames); err == nil {
		t.Fatal("invalid name must fail")
	}
	if v, err := cronValue("7", 0, 59, nil); err != nil || v != 7 {
		t.Fatalf("numeric = %d %v", v, err)
	}
	if _, err := parseCronField("", 0, 59, nil); err == nil {
		t.Fatal("empty entry must fail")
	}
	if _, err := parseCronField("*/0", 0, 59, nil); err == nil {
		t.Fatal("zero step must fail")
	}
	if _, err := parseCronField("*/x", 0, 59, nil); err == nil {
		t.Fatal("non-numeric step must fail")
	}
	if _, err := parseCronField("a-b", 0, 59, nil); err == nil {
		t.Fatal("non-numeric range must fail")
	}
	if _, err := parseCronField("1-bogus", 0, 59, nil); err == nil {
		t.Fatal("non-numeric range end must fail")
	}
	if _, err := parseCronField("9-5", 0, 59, nil); err == nil {
		t.Fatal("inverted range must fail")
	}
	if _, err := parseCronField("70", 0, 59, nil); err == nil {
		t.Fatal("out-of-range value must fail")
	}
	f, err := parseCronField("1-5/2,9,*/20", 0, 59, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !f.mask[1] || !f.mask[3] || !f.mask[9] {
		t.Fatalf("mask missing stepped/list entries: %v", f.mask)
	}
	if _, err := parseCronField("?", 0, 59, nil); err != nil {
		t.Fatalf("question-mark wildcard = %v", err)
	}
}

func TestFlowParseCronErrors(t *testing.T) {
	for _, spec := range []string{
		"* * * *",
		"x * * * *",
		"* x * * *",
		"* * x * *",
		"* * * x *",
		"* * * * x",
	} {
		if _, err := ParseCron(spec); err == nil {
			t.Fatalf("cron %q must fail", spec)
		}
	}
	if _, err := ParseCron("0 0 * * mon-fri"); err != nil {
		t.Fatalf("weekday names = %v", err)
	}
}

func TestFlowCronMatchesSemantics(t *testing.T) {
	// Both DOM and DOW restricted: either may match.
	both, err := ParseCron("0 12 1 * mon")
	if err != nil {
		t.Fatal(err)
	}
	firstOfMonthSunday := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	if !both.matches(firstOfMonthSunday) {
		t.Fatal("DOM match must satisfy OR semantics")
	}
	mondayNotFirst := time.Date(2026, 2, 2, 12, 0, 0, 0, time.UTC)
	if !both.matches(mondayNotFirst) {
		t.Fatal("DOW match must satisfy OR semantics")
	}
	neither := time.Date(2026, 2, 3, 12, 0, 0, 0, time.UTC)
	if both.matches(neither) {
		t.Fatal("neither DOM nor DOW must not match")
	}
	// DOM only.
	domOnly, _ := ParseCron("0 12 1 * *")
	if !domOnly.matches(firstOfMonthSunday) || domOnly.matches(mondayNotFirst) {
		t.Fatal("DOM-only restriction misbehaved")
	}
	// DOW only.
	dowOnly, _ := ParseCron("0 12 * * mon")
	if !dowOnly.matches(mondayNotFirst) || dowOnly.matches(firstOfMonthSunday) {
		t.Fatal("DOW-only restriction misbehaved")
	}
	// Neither restricted: any day matches.
	any, _ := ParseCron("0 12 * * *")
	if !any.matches(firstOfMonthSunday) || !any.matches(neither) {
		t.Fatal("unrestricted day fields must match")
	}
}

func TestFlowCronNextHorizon(t *testing.T) {
	never, err := ParseCron("0 0 30 2 *")
	if err != nil {
		t.Fatal(err)
	}
	if got := never.next(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); !got.IsZero() {
		t.Fatalf("impossible cron next = %v, want zero", got)
	}
	if _, err := ParseCron("0 0 30 2 5"); err != nil {
		t.Fatal(err)
	}
}

const fcMemoryScheduleSpec = `version: 1
on:
  schedule:
    cron: "0 3 * * *"
jobs:
  nightly:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo nightly
`

func TestFlowSchedulesSanitizeSpec(t *testing.T) {
	if got := sanitizeScheduleSpec("jobs: [oops"); got != "jobs: [oops" {
		t.Fatalf("invalid yaml must pass through: %q", got)
	}
	// A schedule-only trigger strips the whole on block.
	spec := scheduleSpec
	out := sanitizeScheduleSpec(spec)
	if strings.Contains(out, "schedule") {
		t.Fatalf("schedule trigger not stripped: %q", out)
	}
	// A spec without on is returned unchanged modulo YAML re-marshal.
	if got := sanitizeScheduleSpec("version: 1\njobs:\n  a:\n    steps:\n      - run: x\n"); !strings.Contains(got, "a") {
		t.Fatalf("sanitized spec = %q", got)
	}
}

func TestFlowSchedulesLoadUnreadable(t *testing.T) {
	testutil.UnixChmod(t)
	if os.Geteuid() == 0 {
		t.Skip("root ignores file modes")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, schedulesFile)
	if err := os.WriteFile(path, []byte("{}"), 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0o600)
	s := New("tok")
	if err := s.loadSchedules(dir); err == nil {
		t.Fatal("unreadable schedules file must fail")
	}
}

func fcScopedManagerServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AuthStore.AddToken("reader", auth.Principal{Subject: "reader", Roles: []auth.Role{auth.RoleRead},
		Repositories: map[string]auth.RepositoryPermission{"o/r": {Read: true}}}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFlowSchedulesScopedDenials(t *testing.T) {
	s := fcScopedManagerServer(t)
	if w := doJSON(t, s, http.MethodGet, "/api/v1/schedules", "reader", ""); w.Code != http.StatusForbidden {
		t.Fatalf("scoped list = %d, want 403", w.Code)
	}
	body := `{"repository":"https://github.com/o/r.git","spec":` + jsonString(fcMemoryScheduleSpec) + `}`
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "reader", body); w.Code != http.StatusForbidden {
		t.Fatalf("scoped upsert = %d, want 403", w.Code)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/schedules/x/trigger", "reader", ""); w.Code != http.StatusForbidden {
		t.Fatalf("scoped trigger = %d, want 403", w.Code)
	}
	// Malformed upsert body.
	s2, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s2, http.MethodPut, "/api/v1/schedules", "token", "{"); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed upsert = %d, want 400", w.Code)
	}
}

func TestFlowSchedulesDBListOrdering(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.schedules["b"] = storage.Schedule{ID: "b", CreatedAt: time.Now().UTC()}
	f.schedules["a"] = storage.Schedule{ID: "a", CreatedAt: time.Now().UTC().Add(-time.Hour)}
	f.mu.Unlock()
	if w := doJSON(t, s, http.MethodGet, "/api/v1/schedules", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("db list = %d", w.Code)
	}
}

func TestFlowSchedulesFirePersistFailures(t *testing.T) {
	// DB durable-advance failure after a successful enqueue only logs.
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	sc := storage.Schedule{ID: "s1", Repository: "https://example.com/o/r.git", RepoID: "example.com/o/r", RepoURL: "https://example.com/o/r.git", Spec: scheduleSpec, Enabled: true, CreatedAt: time.Now().UTC()}
	f.mu.Lock()
	f.schedules["s1"] = sc
	f.mu.Unlock()
	if err := s.reloadSchedulesDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.advanceScheduleErr = errors.New("advance down")
	f.mu.Unlock()
	if _, fired, err := s.fireSchedule(context.Background(), sc, time.Now().UTC().Truncate(time.Minute)); err != nil || !fired {
		t.Fatalf("fire with advance failure = fired=%v err=%v", fired, err)
	}

	// Memory persist failure after a successful enqueue only logs.
	s2, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sc2 := storage.Schedule{ID: "s2", Repository: "https://github.com/o/r.git", RepoID: "github.com/o/r", RepoURL: "https://github.com/o/r.git", Spec: scheduleSpec, Enabled: true, CreatedAt: time.Now().UTC()}
	s2.mu.Lock()
	s2.schedules["s2"] = sc2
	s2.mu.Unlock()
	block := filepath.Join(t.TempDir(), "block")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2.dataDir = block
	// The occurrence-claiming enqueue persists schedules itself, so the
	// unwritable data dir surfaces as an enqueue failure.
	if _, fired, err := s2.fireSchedule(context.Background(), sc2, time.Now().UTC().Truncate(time.Minute)); err == nil || fired {
		t.Fatalf("fire with persist failure = fired=%v err=%v", fired, err)
	}

	// A spec that parses nowhere is rejected by a direct fire. The durable
	// row is authoritative now, so the bad spec must be persisted before the
	// fire (the leader re-reads it immediately before evaluating).
	bad := sc
	bad.Spec = "jobs: [oops"
	if ss, ok := s.scheduleStoreDB(); ok {
		if err := ss.UpsertSchedule(context.Background(), bad); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.fireSchedule(context.Background(), bad, time.Now().UTC()); err == nil {
		t.Fatal("bad spec fire must fail")
	}
}

func TestFlowSchedulesNextDueNeverMatching(t *testing.T) {
	s := New("tok")
	base := time.Now().UTC().Add(-time.Minute)
	s.mu.Lock()
	s.schedules["impossible"] = storage.Schedule{ID: "impossible", Enabled: true, CreatedAt: base,
		Spec: strings.Replace(scheduleSpec, `"* * * * *"`, `"0 0 30 2 *"`, 1)}
	s.mu.Unlock()
	if _, _, ok := s.nextDueScheduleFrom(time.Now().UTC(), map[string]bool{}); ok {
		t.Fatal("never-matching cron must not produce a due occurrence")
	}
}

func TestFlowSchedulesLoad(t *testing.T) {
	s := New("tok")
	if err := s.loadSchedules(""); err != nil {
		t.Fatalf("empty data dir = %v", err)
	}
	dir := t.TempDir()
	if err := s.loadSchedules(dir); err != nil {
		t.Fatalf("missing file = %v", err)
	}
	// A malformed file surfaces the decode error.
	if err := os.WriteFile(filepath.Join(dir, schedulesFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.loadSchedules(dir); err == nil {
		t.Fatal("malformed schedules file must fail")
	}
	// A valid file restores schedules and occurrences.
	body := `{"schedules":[{"id":"s1","repository":"o/r","spec":"x","enabled":true}],"occurrences":{"s1":{"1":"run-1"}}}`
	if err := os.WriteFile(filepath.Join(dir, schedulesFile), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.loadSchedules(dir); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	_, ok := s.schedules["s1"]
	occ := s.occurrences["s1"][1]
	s.mu.Unlock()
	if !ok || occ != "run-1" {
		t.Fatalf("loaded schedule/occurrence = %v %q", ok, occ)
	}
}

func TestFlowSchedulesReloadDBBranches(t *testing.T) {
	ctx := context.Background()
	s := New("tok")
	if err := s.reloadSchedulesDB(ctx); err != nil {
		t.Fatalf("reload without store = %v", err)
	}
	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.DB = &fcStore{dbFakeStore: f, listSchedulesErr: errors.New("schedule list down")}
	if err := s.reloadSchedulesDB(ctx); err == nil {
		t.Fatal("schedule list failure must propagate")
	}
	s.DB = f
	f.mu.Lock()
	f.schedules["s1"] = storage.Schedule{ID: "s1", Repository: "o/r", Enabled: true}
	f.mu.Unlock()
	if err := s.reloadSchedulesDB(ctx); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	_, ok := s.schedules["s1"]
	s.mu.Unlock()
	if !ok {
		t.Fatal("reload did not load the schedule")
	}
}

func TestFlowSchedulesPersistLocked(t *testing.T) {
	s := New("tok")
	if err := s.persistSchedulesLocked(); err != nil {
		t.Fatalf("no data dir persist = %v", err)
	}
	// DB mode skips the fs file.
	s2 := New("tok")
	if err := s2.SwitchToDB(newDBFakeStore()); err != nil {
		t.Fatal(err)
	}
	s2.dataDir = t.TempDir()
	if err := s2.persistSchedulesLocked(); err != nil {
		t.Fatalf("db persist = %v", err)
	}
	// Write failure surfaces.
	block := filepath.Join(t.TempDir(), "block")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s3 := New("tok")
	s3.dataDir = block
	if err := s3.persistSchedulesLocked(); err == nil {
		t.Fatal("unwritable data dir must fail the persist")
	}
}

func TestFlowSchedulesListEndpoints(t *testing.T) {
	// Memory listing sorts by CreatedAt.
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/schedules", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("empty list = %d", w.Code)
	}
	s.mu.Lock()
	s.schedules["b"] = storage.Schedule{ID: "b", CreatedAt: time.Now().UTC()}
	s.schedules["a"] = storage.Schedule{ID: "a", CreatedAt: time.Now().UTC().Add(-time.Hour)}
	s.mu.Unlock()
	w := doJSON(t, s, http.MethodGet, "/api/v1/schedules", "token", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"a"`) {
		t.Fatalf("memory list = %d %s", w.Code, w.Body.String())
	}

	// DB listing error and success.
	f := newDBFakeStore()
	sdb := New("token")
	if err := sdb.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	sdb.DB = &fcStore{dbFakeStore: f, listSchedulesErr: errors.New("schedule list down")}
	if w := doJSON(t, sdb, http.MethodGet, "/api/v1/schedules", "token", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("db list error = %d, want 500", w.Code)
	}
	sdb.DB = f
	f.mu.Lock()
	f.schedules["s1"] = storage.Schedule{ID: "s1", Repository: "o/r", CreatedAt: time.Now().UTC()}
	f.mu.Unlock()
	if w := doJSON(t, sdb, http.MethodGet, "/api/v1/schedules", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("db list = %d", w.Code)
	}
}

func TestFlowSchedulesUpsertValidation(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Missing repository.
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", `{"spec":"x"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("missing repository = %d", w.Code)
	}
	// Missing spec.
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", `{"repository":"o/r"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("missing spec = %d", w.Code)
	}
	// Invalid spec.
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", `{"repository":"o/r","spec":"jobs: {}"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid spec = %d", w.Code)
	}
	// URL-shaped repository without a path.
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", `{"repository":"https://github.com","spec":`+jsonString(fcMemoryScheduleSpec)+`}`); w.Code != http.StatusBadRequest {
		t.Fatalf("URL without path = %d", w.Code)
	}
	// Bare name without a forge host.
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", `{"repository":"o/r","spec":`+jsonString(fcMemoryScheduleSpec)+`}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bare repository = %d", w.Code)
	}
	// Trusted request without the grant: a policy manager whose trusted_run
	// grant is absent is refused.
	if err := s.AuthStore.AddToken("manager", auth.Principal{Subject: "manager", Roles: []auth.Role{auth.RolePolicyManage}}); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "manager", `{"repository":"https://github.com/o/r.git","trusted":true,"spec":`+jsonString(fcMemoryScheduleSpec)+`}`); w.Code != http.StatusForbidden {
		t.Fatalf("trusted without grant = %d", w.Code)
	}
}

func TestFlowSchedulesUpsertMemoryBranches(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := `{"repository":"https://github.com/o/r.git","spec":` + jsonString(fcMemoryScheduleSpec) + `}`
	w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", body)
	if w.Code != http.StatusOK {
		t.Fatalf("create = %d: %s", w.Code, w.Body.String())
	}
	var created storage.Schedule
	if err := jsonUnmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	// Update by ID.
	update := `{"id":` + jsonString(created.ID) + `,"repository":"https://github.com/o/r.git","spec":` + jsonString(fcMemoryScheduleSpec) + `,"enabled":false}`
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", update); w.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	sc := s.schedules[created.ID]
	s.mu.Unlock()
	if sc.Enabled {
		t.Fatal("update did not disable the schedule")
	}
	// An unknown explicit ID creates a new schedule.
	createUnknown := `{"id":"chosen","repository":"https://github.com/o/r.git","spec":` + jsonString(fcMemoryScheduleSpec) + `}`
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", createUnknown); w.Code != http.StatusOK {
		t.Fatalf("create by id = %d: %s", w.Code, w.Body.String())
	}
	if _, ok := s.schedules["chosen"]; !ok {
		t.Fatal("explicit-ID schedule not stored")
	}
	// Persist failure surfaces as 503 (durability failure, not a client error).
	block := filepath.Join(t.TempDir(), "block")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.dataDir = block
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", body); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("persist failure = %d, want 503", w.Code)
	}
}

func TestFlowSchedulesUpsertDBBranches(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	body := `{"repository":"https://github.com/o/r.git","spec":` + jsonString(fcMemoryScheduleSpec) + `}`
	w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", body)
	if w.Code != http.StatusOK {
		t.Fatalf("db create = %d: %s", w.Code, w.Body.String())
	}
	var created storage.Schedule
	if err := jsonUnmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	// DB update of an existing row.
	update := `{"id":` + jsonString(created.ID) + `,"repository":"https://github.com/o/r.git","spec":` + jsonString(fcMemoryScheduleSpec) + `}`
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", update); w.Code != http.StatusOK {
		t.Fatalf("db update = %d: %s", w.Code, w.Body.String())
	}
	// DB list failure during lookup.
	f.mu.Lock()
	f.schedules["s2"] = storage.Schedule{ID: "s2", Repository: "o/r"}
	f.mu.Unlock()
	lookupUpdate := `{"id":"s2","repository":"https://github.com/o/r.git","spec":` + jsonString(fcMemoryScheduleSpec) + `}`
	s.DB = &fcStore{dbFakeStore: f, listSchedulesErr: errors.New("schedule list down")}
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", lookupUpdate); w.Code != http.StatusInternalServerError {
		t.Fatalf("db lookup failure = %d, want 500", w.Code)
	}
	// Unknown explicit ID creates a DB row.
	s.DB = f
	unknown := `{"id":"db-chosen","repository":"https://github.com/o/r.git","spec":` + jsonString(fcMemoryScheduleSpec) + `}`
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", unknown); w.Code != http.StatusOK {
		t.Fatalf("db create by id = %d: %s", w.Code, w.Body.String())
	}
	// Upsert failure surfaces.
	s.DB = &fcStore{dbFakeStore: f, upsertScheduleErr: errors.New("upsert down")}
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", body); w.Code != http.StatusInternalServerError {
		t.Fatalf("db upsert failure = %d, want 500", w.Code)
	}
}

func TestFlowSchedulesTriggerBranches(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := `{"repository":"https://github.com/o/r.git","spec":` + jsonString(scheduleSpec) + `}`
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", body); w.Code != http.StatusOK {
		t.Fatalf("create = %d", w.Code)
	}
	var sc storage.Schedule
	s.mu.Lock()
	for _, v := range s.schedules {
		sc = v
	}
	s.mu.Unlock()
	// Unknown schedule.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/schedules/missing/trigger", "token", ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown trigger = %d, want 404", w.Code)
	}
	// Happy path (the current nominal is unclaimed, even across a minute
	// rollover).
	s.mu.Lock()
	delete(s.occurrences[sc.ID], time.Now().UTC().Truncate(time.Minute).Unix())
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/schedules/"+sc.ID+"/trigger", "token", ""); w.Code != http.StatusAccepted {
		t.Fatalf("trigger = %d: %s", w.Code, w.Body.String())
	}
	// A different run already holding the current nominal conflicts.
	s.mu.Lock()
	s.claimScheduleOccurrenceLocked(sc.ID, time.Now().UTC().Truncate(time.Minute), "other-run")
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/schedules/"+sc.ID+"/trigger", "token", ""); w.Code != http.StatusConflict {
		t.Fatalf("duplicate trigger = %d, want 409", w.Code)
	}
}

func TestFlowSchedulesTriggerDBBranches(t *testing.T) {
	ctx := context.Background()
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	sc := storage.Schedule{ID: "s1", Repository: "https://example.com/o/r.git", RepoID: "example.com/o/r", RepoURL: "https://example.com/o/r.git", Spec: scheduleSpec, Enabled: true, CreatedAt: time.Now().UTC()}
	f.mu.Lock()
	f.schedules["s1"] = sc
	f.mu.Unlock()
	// scheduleByID list failure.
	s.DB = &fcStore{dbFakeStore: f, listSchedulesErr: errors.New("schedule list down")}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/schedules/s1/trigger", "token", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("list failure trigger = %d, want 500", w.Code)
	}
	// scheduleByID not found.
	s.DB = f
	if w := doJSON(t, s, http.MethodPost, "/api/v1/schedules/absent/trigger", "token", ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing trigger = %d, want 404", w.Code)
	}
	// Enqueue failure surfaces as 500.
	f.mu.Lock()
	f.enqueueFailOnce = true
	f.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/schedules/s1/trigger", "token", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("enqueue failure trigger = %d, want 500", w.Code)
	}
	// Success.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/schedules/s1/trigger", "token", ""); w.Code != http.StatusAccepted {
		t.Fatalf("db trigger = %d: %s", w.Code, w.Body.String())
	}
	_ = ctx
}

func TestFlowSchedulesTrustRevocation(t *testing.T) {
	// Revoked creators skip due occurrences and advance the schedule.
	s := New("token")
	s.AuthStore = auth.NewTokenStore()
	if err := s.AuthStore.AddToken("creator", auth.Principal{Subject: "creator", Roles: []auth.Role{auth.RoleRun}}); err != nil {
		t.Fatal(err)
	}
	sc := storage.Schedule{ID: "trusted-1", Repository: "https://github.com/o/r.git", RepoID: "github.com/o/r", RepoURL: "https://github.com/o/r.git", Spec: scheduleSpec, Enabled: true, Trusted: true, CreatedBy: "creator", CreatedAt: time.Now().UTC().Add(-3 * time.Minute)}
	s.mu.Lock()
	s.schedules[sc.ID] = sc
	s.mu.Unlock()
	if s.scheduleTrustStillGranted(sc) {
		t.Fatal("revoked creator must not keep the grant")
	}
	// Automatic firing advances past the unauthorized nominal.
	s.fireDueSchedules(context.Background(), time.Now().UTC())
	s.mu.Lock()
	after := s.schedules[sc.ID]
	s.mu.Unlock()
	if after.LastRun == nil {
		t.Fatal("unauthorized occurrence must advance LastRun")
	}
	// Direct fire reports the sentinel error.
	if _, fired, err := s.fireSchedule(context.Background(), sc, time.Now().UTC()); !errors.Is(err, errScheduleUnauthorized) || fired {
		t.Fatalf("unauthorized fire = fired=%v err=%v", fired, err)
	}

	// A pre-migration row without a creator also fails closed.
	noCreator := sc
	noCreator.CreatedBy = ""
	if s.scheduleTrustStillGranted(noCreator) {
		t.Fatal("creatorless schedule must fail closed")
	}
	// A missing principal fails closed.
	unknown := sc
	unknown.CreatedBy = "ghost"
	if s.scheduleTrustStillGranted(unknown) {
		t.Fatal("unknown principal must fail closed")
	}
	// An open-mode server preserves historical behavior.
	open := New("token")
	open.AuthStore = nil
	if !open.scheduleTrustStillGranted(sc) {
		t.Fatal("open mode must preserve creation-time trust")
	}
	// The grant is still honored when present.
	granted := New("token")
	granted.AuthStore = auth.NewTokenStore()
	if err := granted.AuthStore.AddToken("trusted", auth.Principal{Subject: "trusted", Roles: []auth.Role{auth.RoleTrustedRun},
		Repositories: map[string]auth.RepositoryPermission{"github.com/o/r": {TrustedRun: true}}}); err != nil {
		t.Fatal(err)
	}
	withGrant := sc
	withGrant.CreatedBy = "trusted"
	if !granted.scheduleTrustStillGranted(withGrant) {
		t.Fatal("granted principal must keep the trusted schedule")
	}
}

func TestFlowSchedulesAdvancePast(t *testing.T) {
	s := New("tok")
	nominal := time.Now().UTC().Truncate(time.Minute)
	sc := storage.Schedule{ID: "s1"}
	s.mu.Lock()
	s.schedules["s1"] = sc
	s.mu.Unlock()
	s.advanceSchedulePast(context.Background(), sc, nominal)
	s.mu.Lock()
	got := s.schedules["s1"]
	s.mu.Unlock()
	if got.LastRun == nil || !got.LastRun.Equal(nominal) {
		t.Fatalf("advanced LastRun = %v", got.LastRun)
	}
	// A LastRun already past the nominal is left alone.
	later := nominal.Add(time.Hour)
	sc.LastRun = &later
	s.advanceSchedulePast(context.Background(), sc, nominal)
	s.mu.Lock()
	got = s.schedules["s1"]
	s.mu.Unlock()
	if !got.LastRun.Equal(nominal) {
		t.Fatalf("LastRun moved backwards: %v", got.LastRun)
	}
}

func TestFlowSchedulesFireDueErrors(t *testing.T) {
	// Enqueue failure leaves the schedule for the next tick.
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lastRun := now.Truncate(time.Minute).Add(-time.Minute)
	sc := storage.Schedule{ID: "s1", Repository: "https://example.com/o/r.git", RepoID: "example.com/o/r", RepoURL: "https://example.com/o/r.git", Spec: scheduleSpec, Enabled: true, CreatedAt: lastRun.Add(-time.Hour), LastRun: &lastRun}
	f.mu.Lock()
	f.schedules["s1"] = sc
	f.enqueueFailOnce = true
	f.mu.Unlock()
	if err := s.reloadSchedulesDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.fireDueSchedules(context.Background(), now)
	f.mu.Lock()
	runs := len(f.insertRunCalls)
	f.mu.Unlock()
	if runs != 0 {
		t.Fatalf("failed enqueue inserted %d runs", runs)
	}
	s.mu.Lock()
	after := s.schedules["s1"]
	s.mu.Unlock()
	if after.LastRun == nil || !after.LastRun.Equal(lastRun) {
		t.Fatalf("failed enqueue advanced LastRun to %v", after.LastRun)
	}
}

func TestFlowSchedulesFireDueClaimLost(t *testing.T) {
	ctx := context.Background()
	s := New("token")
	now := time.Now().UTC()
	base := now.Truncate(time.Minute).Add(-time.Minute)
	sc := storage.Schedule{ID: "s1", Repository: "https://example.com/o/r.git", RepoID: "example.com/o/r", RepoURL: "https://example.com/o/r.git", Spec: scheduleSpec, Enabled: true, CreatedAt: base.Add(-time.Hour), LastRun: &base}
	// Pre-claim the only due nominal for another run.
	firstDue := now.Truncate(time.Minute)
	s.mu.Lock()
	s.schedules["s1"] = sc
	s.occurrences["s1"] = map[int64]string{firstDue.Unix(): "other-run"}
	s.mu.Unlock()
	s.fireDueSchedules(ctx, now)
	s.mu.Lock()
	after := s.schedules["s1"]
	s.mu.Unlock()
	if after.LastRun == nil || after.LastRun.Before(firstDue) {
		t.Fatalf("claim-lost nominal did not advance: %v", after.LastRun)
	}
}

func TestFlowSchedulesNextDueSeenAndLimits(t *testing.T) {
	s := New("tok")
	now := time.Now().UTC()
	base := now.Add(-2 * time.Minute).Truncate(time.Minute)
	s.mu.Lock()
	s.schedules["disabled"] = storage.Schedule{ID: "disabled", Enabled: false, CreatedAt: base, Spec: scheduleSpec}
	s.schedules["invalid"] = storage.Schedule{ID: "invalid", Enabled: true, CreatedAt: base, Spec: "jobs: [oops"}
	s.schedules["due"] = storage.Schedule{ID: "due", Enabled: true, CreatedAt: base, Spec: scheduleSpec}
	s.mu.Unlock()
	sc, nominal, ok := s.nextDueScheduleFrom(now, map[string]bool{})
	if !ok || sc.ID != "due" {
		t.Fatalf("next due = %+v %v %v", sc, nominal, ok)
	}
	// The seen set skips the computed nominal and finds the next one.
	seen := map[string]bool{sc.ID + "\x00" + nominal.UTC().Format(time.RFC3339Nano): true}
	_, nominal2, ok2 := s.nextDueScheduleFrom(now, seen)
	if !ok2 {
		t.Fatal("second nominal must still be due")
	}
	if nominal2.Equal(nominal) {
		t.Fatal("seen nominal was returned again")
	}
	// A fully-seen schedule set reports nothing.
	all := map[string]bool{}
	for i := 0; i < 200; i++ {
		sc3, n3, ok3 := s.nextDueScheduleFrom(now, all)
		if !ok3 {
			break
		}
		all[sc3.ID+"\x00"+n3.UTC().Format(time.RFC3339Nano)] = true
	}
	if _, _, ok := s.nextDueScheduleFrom(now, all); ok {
		t.Fatal("exhausted seen set must report nothing due")
	}
}

func TestFlowSchedulesClaimOccurrenceLocked(t *testing.T) {
	s := New("tok")
	nominal := time.Now().UTC().Truncate(time.Minute)
	if !s.claimScheduleOccurrenceLocked("s", nominal, "run-1") {
		t.Fatal("fresh claim must win")
	}
	if !s.claimScheduleOccurrenceLocked("s", nominal, "run-1") {
		t.Fatal("same-run re-claim must report the existing claim")
	}
	if s.claimScheduleOccurrenceLocked("s", nominal, "run-2") {
		t.Fatal("different-run claim must lose")
	}
}
