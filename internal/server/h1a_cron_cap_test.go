package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// cronSpecWith swaps the scheduleSpec cron expression for expr.
func cronSpecWith(expr string) string {
	return strings.Replace(scheduleSpec, `"* * * * *"`, strconv.Quote(expr), 1)
}

// TestCronRejectsUnreachableExpression is the H1-A admission regression: an
// expression whose next occurrence never falls inside the bounded horizon
// (e.g. the auditor's "0 0 31 2 *") is refused at parseScheduleSpec instead
// of being accepted and then rescanned ~1M times on every maintenance tick.
// Reachable expressions that only fire across a leap-year gap (Feb 29) must
// still be accepted.
func TestCronRejectsUnreachableExpression(t *testing.T) {
	for _, expr := range []string{
		"0 0 31 2 *", // Feb 31 never exists
		"0 0 30 2 *", // Feb 30 never exists
		"0 0 31 4 *", // Apr 31 never exists
		"0 0 31 6 *",
		"0 0 31 9 *",
		"0 0 31 11 *",
	} {
		if _, _, err := parseScheduleSpec(cronSpecWith(expr)); err == nil {
			t.Errorf("parseScheduleSpec accepted unreachable cron %q", expr)
		}
	}
	// Feb 29 IS reachable (next leap year within the horizon), so it must be
	// accepted even though a two-year minute scan would have missed it.
	if _, _, err := parseScheduleSpec(cronSpecWith("0 0 29 2 *")); err != nil {
		t.Fatalf("parseScheduleSpec rejected reachable Feb-29 cron: %v", err)
	}
}

// TestCronNextBudgetBoundsWork proves the scan is day-bounded and that the
// shared budget actually stops it: a Feb-29 expression whose next match is
// across a skipped century leap year is found by an unlimited scan but not
// when the budget cannot cover it.
func TestCronNextBudgetBoundsWork(t *testing.T) {
	cron, err := ParseCron("0 0 29 2 *")
	if err != nil {
		t.Fatal(err)
	}
	// 2100 is not a leap year (divisible by 100, not 400): the next Feb 29
	// is 2104, roughly 1460 days away.
	base := time.Date(2100, 3, 1, 0, 0, 0, 0, time.UTC)
	next := cron.next(base)
	if next.IsZero() || next.Year() != 2104 || next.Month() != time.February || next.Day() != 29 {
		t.Fatalf("unlimited next(2100-03-01) = %v, want 2104-02-29", next)
	}
	if got := cron.nextBudget(base, newCronScanBudget(10)); !got.IsZero() {
		t.Fatalf("budgeted next returned %v, want zero when the budget is exhausted", got)
	}
	if got := cron.nextBudget(base, newCronScanBudget(maxCronHorizonDays+10)); got.IsZero() {
		t.Fatalf("budgeted next with the full horizon returned zero, want 2104-02-29")
	}
}

// TestCronNeverDueSetTickBounded is the H1-A DoS regression: 2000 schedules
// that can never become due must not make a maintenance tick proportional to
// 2000 * ~1M minute scans. With the bounded day scan plus admission-time
// rejection, the tick returns almost immediately and fires nothing.
func TestCronNeverDueSetTickBounded(t *testing.T) {
	s := New("tok")
	now := time.Now().UTC()
	base := now.Add(-time.Minute)
	s.mu.Lock()
	for i := 0; i < 2000; i++ {
		id := fmt.Sprintf("never-%04d", i)
		s.schedules[id] = storage.Schedule{ID: id, Enabled: true, CreatedAt: base, Spec: cronSpecWith("0 0 30 2 *")}
	}
	s.mu.Unlock()

	start := time.Now()
	s.fireDueSchedules(context.Background(), now)
	elapsed := time.Since(start)
	if elapsed > 3*time.Second {
		t.Fatalf("2000 never-due schedules took %v for one tick; the scan is not bounded", elapsed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sc := range s.schedules {
		if sc.LastRun != nil {
			t.Fatalf("never-due schedule %s fired at %v", id, sc.LastRun)
		}
	}
}

// TestScheduleCapEnforced is the H1-A cap regression: new schedules are
// refused once the configured cap is reached, while updating an existing
// schedule still works.
func TestScheduleCapEnforced(t *testing.T) {
	body := func(repo string) string {
		return `{"repository":` + strconv.Quote(repo) + `,"spec":` + jsonString(fcMemoryScheduleSpec) + `}`
	}
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.MaxSchedules = 1
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", body("https://github.com/o/r.git")); w.Code != http.StatusOK {
		t.Fatalf("first schedule = %d, want 200: %s", w.Code, w.Body.String())
	}
	w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", body("https://github.com/o/other.git"))
	if w.Code != http.StatusConflict {
		t.Fatalf("second schedule past the cap = %d, want 409: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	n := len(s.schedules)
	s.mu.Unlock()
	if n != 1 {
		t.Fatalf("stored schedules = %d, want the cap of 1", n)
	}
}

// TestScheduleCapEnforcedDB is the same cap contract in DB mode.
func TestScheduleCapEnforcedDB(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.MaxSchedules = 1
	body := func(repo string) string {
		return `{"repository":` + strconv.Quote(repo) + `,"spec":` + jsonString(fcMemoryScheduleSpec) + `}`
	}
	if w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", body("https://github.com/o/r.git")); w.Code != http.StatusOK {
		t.Fatalf("first DB schedule = %d, want 200: %s", w.Code, w.Body.String())
	}
	w := doJSON(t, s, http.MethodPut, "/api/v1/schedules", "token", body("https://github.com/o/other.git"))
	if w.Code != http.StatusConflict {
		t.Fatalf("second DB schedule past the cap = %d, want 409: %s", w.Code, w.Body.String())
	}
}
