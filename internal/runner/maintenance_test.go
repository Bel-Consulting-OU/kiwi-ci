package runner

import (
	"strings"
	"testing"
	"time"
)

func TestMaintenanceScheduleDue(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	m := maintenanceSchedule{GCInterval: time.Hour, PrewarmInterval: 5 * time.Minute, StagingInterval: 30 * time.Second}

	t.Run("first run always due", func(t *testing.T) {
		gc, prewarm, staging := m.due(now, time.Time{}, time.Time{}, time.Time{})
		if !gc || !prewarm || !staging {
			t.Fatalf("zero last-run times must be due: gc=%t prewarm=%t staging=%t", gc, prewarm, staging)
		}
	})
	t.Run("intervals elapse", func(t *testing.T) {
		gc, prewarm, staging := m.due(now, now.Add(-time.Hour), now.Add(-6*time.Minute), now.Add(-time.Minute))
		if !gc || !prewarm || !staging {
			t.Fatalf("elapsed intervals must be due: gc=%t prewarm=%t staging=%t", gc, prewarm, staging)
		}
	})
	t.Run("intervals not elapsed", func(t *testing.T) {
		gc, prewarm, staging := m.due(now, now.Add(-30*time.Minute), now.Add(-2*time.Minute), now.Add(-10*time.Second))
		if gc || prewarm || staging {
			t.Fatalf("unelapsed intervals must not be due: gc=%t prewarm=%t staging=%t", gc, prewarm, staging)
		}
	})
	t.Run("gc only", func(t *testing.T) {
		gc, prewarm, staging := m.due(now, now.Add(-90*time.Minute), now.Add(-time.Minute), now.Add(-time.Second))
		if !gc || prewarm || staging {
			t.Fatalf("want gc only: gc=%t prewarm=%t staging=%t", gc, prewarm, staging)
		}
	})
	t.Run("staging only", func(t *testing.T) {
		gc, prewarm, staging := m.due(now, now.Add(-time.Minute), now.Add(-time.Minute), now.Add(-time.Minute))
		if gc || prewarm || !staging {
			t.Fatalf("want staging only: gc=%t prewarm=%t staging=%t", gc, prewarm, staging)
		}
	})
	t.Run("disabled interval never due", func(t *testing.T) {
		mZero := maintenanceSchedule{}
		gc, prewarm, staging := mZero.due(now, time.Time{}, time.Time{}, time.Time{})
		if gc || prewarm || staging {
			t.Fatalf("zero intervals must never be due: gc=%t prewarm=%t staging=%t", gc, prewarm, staging)
		}
	})
}

func TestNextSurfacesDisabledHeader(t *testing.T) {
	// The disabled detection lives in next(); assert the sentinel errors
	// match the documented exit contract.
	if !strings.Contains(ErrRunnerDisabledOrRevoked.Error(), "re-enroll required") {
		t.Fatalf("sentinel message changed: %v", ErrRunnerDisabledOrRevoked)
	}
}
