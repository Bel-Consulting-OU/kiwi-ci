package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// scheduleReconcileFixture builds an fs-mode server with one enabled
// schedule and returns it with the next due nominal.
func scheduleReconcileFixture(t *testing.T, dir string) (*Server, storage.Schedule, time.Time) {
	t.Helper()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	sc := storage.Schedule{
		ID: "s-reconcile", Repository: "o/r", RepoID: "github.com/o/r", RepoURL: "https://github.com/o/r.git",
		Spec: scheduleSpec, Enabled: true, CreatedAt: now.Add(-3 * time.Minute),
	}
	s.mu.Lock()
	s.schedules[sc.ID] = sc
	s.mu.Unlock()
	if err := s.persistSchedulesLocked(); err != nil {
		t.Fatal(err)
	}
	due, nominal, ok := s.nextDueScheduleFrom(now, map[string]bool{})
	if !ok {
		t.Fatal("no due nominal for the fixture schedule")
	}
	return s, due, nominal
}

// TestCrashScheduleOccurrenceAdoptionSurvivesRestartFS reconstructs the
// crash window "run snapshot committed, schedules journal not" and proves
// the adoption is itself durable: the first tick after the crash adopts the
// claim from the committed run's metadata (state.json), the next restart
// still sees the adoption (schedules.json), and the nominal is never
// refired.
func TestCrashScheduleOccurrenceAdoptionSurvivesRestartFS(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s1, due, nominal := scheduleReconcileFixture(t, dir)
	schedulesPath := filepath.Join(dir, schedulesFile)
	before, err := os.ReadFile(schedulesPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, fired, err := s1.fireSchedule(ctx, due, nominal); err != nil || !fired {
		t.Fatalf("fire = fired=%v err=%v, want a committed run", fired, err)
	}
	// Crash window: restore the pre-fire schedules journal. state.json keeps
	// the committed run; the journal loses the claim and last_run.
	if err := os.WriteFile(schedulesPath, before, 0o600); err != nil {
		t.Fatal(err)
	}

	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.fireDueSchedules(ctx, time.Now().UTC())
	if n := crashRunsForNominal(t, s2, due.ID, nominal); n != 1 {
		t.Fatalf("reconcile fired the adopted nominal again: %d runs, want 1", n)
	}
	s2.mu.Lock()
	_, claimed := s2.occurrences[due.ID][nominal.UTC().Unix()]
	s2.mu.Unlock()
	if !claimed {
		t.Fatal("reconcile did not adopt the occurrence claim from the committed run")
	}

	// The adoption was persisted through the schedules journal: a further
	// restart reads it instead of depending on a scan, and still never
	// refires the nominal.
	s3, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s3.mu.Lock()
	restored := s3.occurrences[due.ID][nominal.UTC().Unix()]
	s3.mu.Unlock()
	if restored == "" {
		t.Fatal("adopted occurrence claim was not durable across a restart")
	}
	s3.fireDueSchedules(ctx, time.Now().UTC())
	if n := crashRunsForNominal(t, s3, due.ID, nominal); n != 1 {
		t.Fatalf("second restart refired the adopted nominal: %d runs, want 1", n)
	}
}

// TestCrashScheduleOccurrenceOrphanClaimRecordsFailureFS is the inverse
// case: a durable occurrence claim whose run is absent (the claim committed
// without its run snapshot — the inverse half of the two-store split) must
// not silently consume the occurrence. The reconcile records the failure
// (audit + log), keeps the claim so a possibly-produced run is never
// duplicated, and reports it exactly once.
func TestCrashScheduleOccurrenceOrphanClaimRecordsFailureFS(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s1, due, nominal := scheduleReconcileFixture(t, dir)

	// Construction of "claim durable, run write failed": claim the nominal
	// with a run ID that has no committed run, then persist the schedules
	// journal. This is exactly the disk state the inverse ordering leaves.
	s1.mu.Lock()
	s1.claimScheduleOccurrenceLocked(due.ID, nominal, "phantom-run-no-state")
	s1.mu.Unlock()
	if err := s1.persistSchedulesLocked(); err != nil {
		t.Fatal(err)
	}

	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.fireDueSchedules(ctx, time.Now().UTC())
	if n := crashRunsForNominal(t, s2, due.ID, nominal); n != 0 {
		t.Fatalf("orphaned claim produced %d run(s); the claim must be kept, not refired", n)
	}
	events, err := s2.store.ReadAudit(1000)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, e := range events {
		if e.Action == "schedule.occurrence_orphaned" && e.Metadata["schedule"] == due.ID && e.Metadata["nominal"] == nominal.UTC().Format(time.RFC3339) {
			found++
		}
	}
	if found == 0 {
		t.Fatal("orphaned occurrence claim was silently lost: no schedule.occurrence_orphaned audit row recorded")
	}

	// The failure is reported once, not on every tick.
	s2.fireDueSchedules(ctx, time.Now().UTC())
	events, err = s2.store.ReadAudit(1000)
	if err != nil {
		t.Fatal(err)
	}
	again := 0
	for _, e := range events {
		if e.Action == "schedule.occurrence_orphaned" && e.Metadata["schedule"] == due.ID {
			again++
		}
	}
	if again != found {
		t.Fatalf("orphan failure reported %d times after a second tick, want %d", again, found)
	}
}
