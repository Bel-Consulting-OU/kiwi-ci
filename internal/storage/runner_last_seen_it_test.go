package storage

// Real-PostgreSQL integration tests for last_seen ownership: only the narrow
// RunnerHeartbeatStore touch may write it, so a profile/admin write from a
// stale snapshot (re-registration, enable, drain) can never move it backward.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// lastSeenFixture seeds one runner whose last_seen is stale and returns both
// the committed row and the stale snapshot a profile writer would hold.
func lastSeenFixture(t *testing.T, st *PostgresStore, mutate func(*model.Runner)) (committed model.Runner, stale model.Runner) {
	t.Helper()
	ctx := context.Background()
	runnerID := pgITNewID(t)
	seed := model.Runner{ID: runnerID, Name: runnerID, Capacity: 4, Labels: []string{"container"}, LastSeen: time.Now().UTC().Add(-time.Hour)}
	if mutate != nil {
		mutate(&seed)
	}
	if err := st.UpsertRunner(ctx, seed); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	committed, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner: %v", err)
	}
	stale = committed
	return committed, stale
}

// commitHeartbeatTouch advances last_seen through the narrow capability and
// returns the committed instant.
func commitHeartbeatTouch(t *testing.T, st *PostgresStore, runnerID string) time.Time {
	t.Helper()
	// Ensure a measurable ordering gap between the stale snapshot and the
	// touch (Postgres clock resolution makes a same-microsecond write
	// possible otherwise).
	time.Sleep(5 * time.Millisecond)
	if err := st.TouchRunnerLastSeen(context.Background(), runnerID); err != nil {
		t.Fatalf("touch last seen: %v", err)
	}
	after, err := st.GetRunner(context.Background(), runnerID)
	if err != nil {
		t.Fatalf("get touched runner: %v", err)
	}
	return after.LastSeen
}

// assertLastSeenPreserved applies a stale profile write and asserts the
// committed last_seen is still the heartbeat's instant.
func assertLastSeenPreserved(t *testing.T, st *PostgresStore, stale model.Runner, touched time.Time) model.Runner {
	t.Helper()
	if err := st.UpdateRunnerProfileFields(context.Background(), stale); err != nil {
		t.Fatalf("profile write: %v", err)
	}
	after, err := st.GetRunner(context.Background(), stale.ID)
	if err != nil {
		t.Fatalf("get runner after profile write: %v", err)
	}
	if !after.LastSeen.Equal(touched) {
		t.Fatalf("profile write moved last_seen: %v -> %v (stale snapshot carried %v)", touched, after.LastSeen, stale.LastSeen)
	}
	return after
}

// TestIntegrationProfileUpdatePreservesConcurrentLastSeen pins the ownership
// rule for a plain profile edit: a write from a snapshot taken before a
// concurrent heartbeat must not roll last_seen back.
func TestIntegrationProfileUpdatePreservesConcurrentLastSeen(t *testing.T) {
	st := pgITStore(t)
	_, stale := lastSeenFixture(t, st, nil)
	touched := commitHeartbeatTouch(t, st, stale.ID)
	stale.Name = "admin-renamed"
	stale.Region = "eu-west-9"
	after := assertLastSeenPreserved(t, st, stale, touched)
	if after.Name != "admin-renamed" || after.Region != "eu-west-9" {
		t.Fatalf("profile edit did not apply: %+v", after)
	}
}

// TestIntegrationRunnerEnablePreservesConcurrentLastSeen pins the enable
// variant: re-enabling from a stale snapshot applies the admin change but
// leaves the heartbeat's last_seen alone.
func TestIntegrationRunnerEnablePreservesConcurrentLastSeen(t *testing.T) {
	st := pgITStore(t)
	_, stale := lastSeenFixture(t, st, func(r *model.Runner) { r.Disabled = true })
	touched := commitHeartbeatTouch(t, st, stale.ID)
	stale.Disabled = false
	after := assertLastSeenPreserved(t, st, stale, touched)
	if after.Disabled {
		t.Fatal("enable did not clear disabled")
	}
}

// TestIntegrationRunnerDrainPreservesConcurrentLastSeen pins the drain
// variant: draining from a stale snapshot applies the admin change but leaves
// the heartbeat's last_seen alone.
func TestIntegrationRunnerDrainPreservesConcurrentLastSeen(t *testing.T) {
	st := pgITStore(t)
	_, stale := lastSeenFixture(t, st, nil)
	touched := commitHeartbeatTouch(t, st, stale.ID)
	stale.Draining = true
	after := assertLastSeenPreserved(t, st, stale, touched)
	if !after.Draining {
		t.Fatal("drain did not set draining")
	}
}
