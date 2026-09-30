package server

// Real-PostgreSQL regression for last_seen ownership on (re-)registration:
// the registration path touches last_seen through the narrow capability after
// the profile write, and the guarded profile write preserves the committed
// instant, so a registration carrying a stale snapshot can never move
// last_seen backward.

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestIntegrationReregistrationDoesNotMoveLastSeenBackward(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	ctx := context.Background()

	runnerID := pgITServerRandomHex(t, 32)
	body := `{"id":"` + runnerID + `","name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2}`
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/register", "token", body, nil); w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	before, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get registered runner: %v", err)
	}
	if before.LastSeen.IsZero() {
		t.Fatal("registration did not stamp last_seen")
	}
	// Simulate a re-registration from a snapshot captured before the last
	// heartbeat (an hour behind): the guarded profile write must preserve the
	// committed instant and the registration touch advances it on the store
	// clock, never writing the stale application instant back.
	stale := before
	stale.LastSeen = before.LastSeen.Add(-time.Hour)
	stale.Name = "re-registered"
	if err := s.writeRunnerProfileDB(ctx, stale, before, true); err != nil {
		t.Fatalf("re-registration write: %v", err)
	}
	after, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get re-registered runner: %v", err)
	}
	if after.LastSeen.Before(before.LastSeen) {
		t.Fatalf("re-registration moved last_seen backward: %v -> %v (stale snapshot carried %v)", before.LastSeen, after.LastSeen, stale.LastSeen)
	}
	if after.Name != "re-registered" {
		t.Fatalf("re-registration did not apply the profile change: %+v", after)
	}
}
