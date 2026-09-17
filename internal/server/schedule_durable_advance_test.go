package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// revokedTrustStore builds a principal store whose only principal holds no
// trusted_run grant, so trusted schedules fail the revocation re-check.
func revokedTrustStore(t *testing.T) *auth.TokenStore {
	t.Helper()
	store := auth.NewTokenStore()
	if err := store.AddToken("creator-token", auth.Principal{Subject: "creator", Roles: []auth.Role{auth.RoleRun}}); err != nil {
		t.Fatal(err)
	}
	return store
}

// TestScheduleAdvanceDurableRevocationSkipDBRestart: a revoked trusted
// occurrence skipped by the fire loop advances last_run durably, so a
// restarted replica (and other replicas) never retry the settled nominal.
func TestScheduleAdvanceDurableRevocationSkipDBRestart(t *testing.T) {
	ctx := context.Background()
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.AuthStore = revokedTrustStore(t)
	now := time.Now().UTC()
	sc := storage.Schedule{
		ID: "s1", Repository: "o/r", RepoID: "github.com/o/r", RepoURL: "https://github.com/o/r.git",
		Spec: scheduleSpec, Enabled: true, Trusted: true, CreatedBy: "creator",
		CreatedAt: now.Add(-3 * time.Minute),
	}
	if err := f.UpsertSchedule(ctx, sc); err != nil {
		t.Fatal(err)
	}
	if err := s.reloadSchedulesDB(ctx); err != nil {
		t.Fatal(err)
	}
	s.fireDueSchedules(ctx, now)

	f.mu.Lock()
	stored := f.schedules["s1"]
	runs := len(f.insertRunCalls)
	occurrences := len(f.occurrences["s1"])
	f.mu.Unlock()
	if stored.LastRun == nil {
		t.Fatal("revocation skip did not durably advance last_run")
	}
	if stored.LastRun.Before(now.Truncate(time.Minute)) {
		t.Fatalf("durable last_run = %v, want at least %v", stored.LastRun, now.Truncate(time.Minute))
	}
	if runs != 0 || occurrences != 0 {
		t.Fatalf("revoked schedule produced %d runs and %d occurrences", runs, occurrences)
	}

	// Restart with the same store: the settled nominal must not refire.
	s2 := New("token")
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s2.AuthStore = revokedTrustStore(t)
	if err := s2.reloadSchedulesDB(ctx); err != nil {
		t.Fatal(err)
	}
	s2.fireDueSchedules(ctx, now)
	f.mu.Lock()
	runsAfter := len(f.insertRunCalls)
	occAfter := len(f.occurrences["s1"])
	f.mu.Unlock()
	if runsAfter != 0 || occAfter != 0 {
		t.Fatalf("restart refired a settled occurrence: runs=%d occurrences=%d", runsAfter, occAfter)
	}
}

// TestScheduleAdvanceDurableRevocationSkipFSRestart is the fs-mode twin: the
// advance is persisted in schedules.json before the local mirror moves, so a
// restarted process never refires the settled occurrence.
func TestScheduleAdvanceDurableRevocationSkipFSRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.AuthStore = revokedTrustStore(t)
	now := time.Now().UTC()
	sc := storage.Schedule{
		ID: "s1", Repository: "o/r", RepoID: "github.com/o/r", RepoURL: "https://github.com/o/r.git",
		Spec: scheduleSpec, Enabled: true, Trusted: true, CreatedBy: "creator",
		CreatedAt: now.Add(-3 * time.Minute),
	}
	s.mu.Lock()
	s.schedules[sc.ID] = sc
	s.mu.Unlock()
	s.fireDueSchedules(ctx, now)

	s.mu.Lock()
	mirror := s.schedules[sc.ID]
	runs := len(s.runs)
	s.mu.Unlock()
	if mirror.LastRun == nil || mirror.LastRun.Before(now.Truncate(time.Minute)) {
		t.Fatalf("fs advance did not move LastRun: %v", mirror.LastRun)
	}
	if runs != 0 {
		t.Fatalf("revoked schedule produced %d runs", runs)
	}

	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.AuthStore = revokedTrustStore(t)
	s2.mu.Lock()
	restored := s2.schedules[sc.ID]
	s2.mu.Unlock()
	if restored.LastRun == nil || restored.LastRun.Before(now.Truncate(time.Minute)) {
		t.Fatalf("restart lost the durable advance: %v", restored.LastRun)
	}
	s2.fireDueSchedules(ctx, now)
	s2.mu.Lock()
	runsAfter := len(s2.runs)
	s2.mu.Unlock()
	if runsAfter != 0 {
		t.Fatalf("restart refired a settled occurrence: %d runs", runsAfter)
	}
}

// TestScheduleAdvanceMonotonicStaleReplica: a stale replica holding an older
// marker cannot move last_run backwards, in the store or in the mirror.
func TestScheduleAdvanceMonotonicStaleReplica(t *testing.T) {
	ctx := context.Background()
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	t2 := time.Now().UTC().Truncate(time.Minute)
	t1 := t2.Add(-2 * time.Hour)
	t3 := t2.Add(time.Minute)
	sc := storage.Schedule{ID: "s1", Repository: "o/r", RepoID: "github.com/o/r", RepoURL: "https://github.com/o/r.git",
		Spec: scheduleSpec, Enabled: true, CreatedAt: t1.Add(-time.Hour), LastRun: &t2}
	if err := f.UpsertSchedule(ctx, sc); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.schedules[sc.ID] = sc
	s.mu.Unlock()

	// Replica A advances the store to t3.
	if err := s.advanceSchedulePast(ctx, sc, t3); err != nil {
		t.Fatalf("replica A advance = %v", err)
	}
	// Replica B holds a stale mirror (t1) and tries to advance to t2.
	sB := New("token")
	if err := sB.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	stale := sc
	stale.LastRun = &t1
	sB.mu.Lock()
	sB.schedules[stale.ID] = stale
	sB.mu.Unlock()
	if err := sB.advanceSchedulePast(ctx, stale, t2); err != nil {
		t.Fatalf("stale replica advance = %v", err)
	}
	f.mu.Lock()
	stored := f.schedules["s1"]
	f.mu.Unlock()
	if !stored.LastRun.Equal(t3) {
		t.Fatalf("stale replica moved durable last_run back to %v, want %v", stored.LastRun, t3)
	}

	// A genuine forward advance still moves both the store and the mirror.
	if err := s.advanceSchedulePast(ctx, sc, t3.Add(time.Minute)); err != nil {
		t.Fatalf("forward advance = %v", err)
	}
	t3 = t3.Add(time.Minute)
	f.mu.Lock()
	stored = f.schedules["s1"]
	f.mu.Unlock()
	s.mu.Lock()
	mirror := s.schedules["s1"]
	s.mu.Unlock()
	if !stored.LastRun.Equal(t3) || !mirror.LastRun.Equal(t3) {
		t.Fatalf("forward advance = store %v mirror %v, want %v", stored.LastRun, mirror.LastRun, t3)
	}
}

// TestScheduleAdvanceFailureInjectionLeavesMirror: a failed durable advance
// is returned and leaves both the store and the in-memory mirror untouched;
// the retried advance converges.
func TestScheduleAdvanceFailureInjectionLeavesMirror(t *testing.T) {
	ctx := context.Background()
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	nominal := base.Add(time.Minute)
	sc := storage.Schedule{ID: "s1", Repository: "o/r", RepoID: "github.com/o/r", RepoURL: "https://github.com/o/r.git",
		Spec: scheduleSpec, Enabled: true, CreatedAt: base.Add(-time.Hour), LastRun: &base}
	if err := f.UpsertSchedule(ctx, sc); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.schedules[sc.ID] = sc
	s.mu.Unlock()

	f.mu.Lock()
	f.advanceScheduleErr = errors.New("advance down")
	f.mu.Unlock()
	if err := s.advanceSchedulePast(ctx, sc, nominal); err == nil {
		t.Fatal("failed durable advance must be returned")
	}
	f.mu.Lock()
	stored := f.schedules["s1"]
	f.advanceScheduleErr = nil
	f.mu.Unlock()
	s.mu.Lock()
	mirror := s.schedules["s1"]
	s.mu.Unlock()
	if !stored.LastRun.Equal(base) {
		t.Fatalf("failed advance changed the store: %v", stored.LastRun)
	}
	if !mirror.LastRun.Equal(base) {
		t.Fatalf("failed advance changed the mirror: %v", mirror.LastRun)
	}

	if err := s.advanceSchedulePast(ctx, sc, nominal); err != nil {
		t.Fatalf("retried advance = %v", err)
	}
	f.mu.Lock()
	stored = f.schedules["s1"]
	f.mu.Unlock()
	s.mu.Lock()
	mirror = s.schedules["s1"]
	s.mu.Unlock()
	if !stored.LastRun.Equal(nominal) || !mirror.LastRun.Equal(nominal) {
		t.Fatalf("retry = store %v mirror %v, want %v", stored.LastRun, mirror.LastRun, nominal)
	}
}

// TestScheduleAdvanceFailureInjectionLeavesMirrorFS is the fs-mode twin: a
// failed schedules-file write leaves the mirror (and the file) at the old
// marker, and the retried advance persists and then mirrors it.
func TestScheduleAdvanceFailureInjectionLeavesMirrorFS(t *testing.T) {
	ctx := context.Background()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	nominal := base.Add(time.Minute)
	sc := storage.Schedule{ID: "s1", Repository: "o/r", RepoID: "github.com/o/r", RepoURL: "https://github.com/o/r.git",
		Spec: scheduleSpec, Enabled: true, CreatedAt: base.Add(-time.Hour), LastRun: &base}
	s.mu.Lock()
	s.schedules[sc.ID] = sc
	s.mu.Unlock()
	if err := s.persistSchedulesLocked(); err != nil {
		t.Fatal(err)
	}

	old := writeSchedulesFile
	writeSchedulesFile = func(string, any) error { return errors.New("schedules file down") }
	if err := s.advanceSchedulePast(ctx, sc, nominal); err == nil {
		t.Fatal("failed schedules-file write must be returned")
	}
	s.mu.Lock()
	mirror := s.schedules[sc.ID]
	s.mu.Unlock()
	if !mirror.LastRun.Equal(base) {
		t.Fatalf("failed advance changed the mirror: %v", mirror.LastRun)
	}
	// The persisted file still carries the old marker.
	s3 := New("token")
	s3.schedules = map[string]storage.Schedule{}
	if err := s3.loadSchedules(s.dataDir); err != nil {
		t.Fatal(err)
	}
	if got := s3.schedules[sc.ID]; got.LastRun == nil || !got.LastRun.Equal(base) {
		t.Fatalf("failed write changed the persisted marker: %v", got.LastRun)
	}
	writeSchedulesFile = old

	if err := s.advanceSchedulePast(ctx, sc, nominal); err != nil {
		t.Fatalf("retried advance = %v", err)
	}
	s.mu.Lock()
	mirror = s.schedules[sc.ID]
	s.mu.Unlock()
	if !mirror.LastRun.Equal(nominal) {
		t.Fatalf("retried advance mirror = %v, want %v", mirror.LastRun, nominal)
	}
	// Reload the file through the same path a restart uses.
	s2 := New("token")
	s2.schedules = map[string]storage.Schedule{}
	if err := s2.loadSchedules(s.dataDir); err != nil {
		t.Fatal(err)
	}
	if got := s2.schedules[sc.ID]; got.LastRun == nil || !got.LastRun.Equal(nominal) {
		t.Fatalf("persisted last_run = %v, want %v", got.LastRun, nominal)
	}
}
