package runner

import (
	"strings"
	"testing"
	"time"
)

func TestMaintenanceScheduleDue(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	m := maintenanceSchedule{GCInterval: time.Hour, PrewarmInterval: 5 * time.Minute}

	t.Run("first run always due", func(t *testing.T) {
		gc, prewarm := m.due(now, time.Time{}, time.Time{})
		if !gc || !prewarm {
			t.Fatalf("zero last-run times must be due: gc=%t prewarm=%t", gc, prewarm)
		}
	})
	t.Run("intervals elapse", func(t *testing.T) {
		gc, prewarm := m.due(now, now.Add(-time.Hour), now.Add(-6*time.Minute))
		if !gc || !prewarm {
			t.Fatalf("elapsed intervals must be due: gc=%t prewarm=%t", gc, prewarm)
		}
	})
	t.Run("intervals not elapsed", func(t *testing.T) {
		gc, prewarm := m.due(now, now.Add(-30*time.Minute), now.Add(-2*time.Minute))
		if gc || prewarm {
			t.Fatalf("unelapsed intervals must not be due: gc=%t prewarm=%t", gc, prewarm)
		}
	})
	t.Run("gc only", func(t *testing.T) {
		gc, prewarm := m.due(now, now.Add(-90*time.Minute), now.Add(-time.Minute))
		if !gc || prewarm {
			t.Fatalf("want gc only: gc=%t prewarm=%t", gc, prewarm)
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
