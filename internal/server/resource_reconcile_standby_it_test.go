package server

// Real-PostgreSQL integration tests for the K2-C leader gate on the
// resource-ledger reconciliation: only the current leader may attempt the
// fenced rebuild, a standby's poll stays quiet and answers the normal
// not-leader rejection, and a leader whose reconciliation genuinely fails
// still refuses leases (fail closed). Gated on KIWI_TEST_POSTGRES_URL.

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// pgITFailingReconcileStore is the real store with the reconciliation
// contract forced to fail: every other method keeps the live PostgreSQL
// behavior, so the leader's readiness gate and the ledger itself stay real.
type pgITFailingReconcileStore struct {
	*storage.PostgresStore
	err error
}

func (p *pgITFailingReconcileStore) ReconcileResourceReservations(context.Context) (storage.ResourceReconcileResult, error) {
	return storage.ResourceReconcileResult{}, p.err
}

// TestIntegrationResourceReconcileStandbyPollQuietPostgres (K2-C): a standby
// replica polled for work must not attempt the leader-only ledger
// reconciliation. Before the fix its poll failed the fenced transaction with
// ErrStaleLeader and answered 503 "resource ledger not reconciled" with
// X-Kiwi-State: reconciling and an error-level "stale leader epoch" line;
// after the fix it answers the normal 503 "scheduler standby" with no
// reconcile attempt and no reconcile noise, while the leader's identical poll
// reconciles once, arms the gate, and answers 204.
func TestIntegrationResourceReconcileStandbyPollQuietPostgres(t *testing.T) {
	env := pgITServerSetup(t)
	sA, _ := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, sA)
	runnerID := pgITRegisterRunner(t, sA)

	sB, _ := pgITServerWithEnv(t, env, t.TempDir())
	if sB.Sched.IsLeader(context.Background()) {
		t.Fatal("second replica must start as standby while the first holds the claim")
	}
	var logs bytes.Buffer
	sB.Logger = logging.NewStructured(&logs)
	w := pgITDo(t, sB, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("standby next = %d, want 503: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "scheduler standby") {
		t.Fatalf("standby next body = %q, want the normal not-leader rejection", w.Body.String())
	}
	if got := w.Header().Get("X-Kiwi-State"); got != "" {
		t.Fatalf("standby next reported X-Kiwi-State %q, want none", got)
	}
	if sB.resourceReconciled.Load() {
		t.Fatal("standby poll armed the reconcile gate")
	}
	if noise := logs.String(); strings.Contains(noise, "resource ledger reconciliation") || strings.Contains(noise, "stale leader epoch") {
		t.Fatalf("standby poll produced reconcile noise: %s", noise)
	}
	// Nothing was reconciled by the standby: the durable ledger is untouched.
	if rows := pgITReservationRows(t, env); rows != 0 {
		t.Fatalf("standby poll wrote %d ledger rows, want 0", rows)
	}

	// The leader path is unchanged: its poll reconciles once, arms the gate
	// and answers 204 (no queued work).
	var leaderLogs bytes.Buffer
	sA.Logger = logging.NewStructured(&leaderLogs)
	if w := pgITDo(t, sA, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "", nil); w.Code != http.StatusNoContent {
		t.Fatalf("leader next = %d, want 204: %s", w.Code, w.Body.String())
	}
	if !sA.resourceReconciled.Load() {
		t.Fatal("leader poll did not arm the reconcile gate")
	}
	if !strings.Contains(leaderLogs.String(), "resource ledger reconciled") {
		t.Fatalf("leader reconcile not logged: %s", leaderLogs.String())
	}
	if rows := pgITReservationRows(t, env); rows != 0 {
		t.Fatalf("reconcile over an empty ledger wrote %d rows, want 0", rows)
	}
}

// TestIntegrationResourceReconcileLeaderFailureStill503Postgres (K2-C): the
// standby fix must not weaken the leader's fail-closed gate. A leader whose
// reconciliation fails for a real reason still refuses leases with the
// reconciling state and a raw ledger error.
func TestIntegrationResourceReconcileLeaderFailureStill503Postgres(t *testing.T) {
	env := pgITServerSetup(t)
	st := env.open(t)
	failing := &pgITFailingReconcileStore{PostgresStore: st, err: errors.New("reservation ledger unavailable")}
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(failing); err != nil {
		t.Fatal(err)
	}
	pgITServerAwaitLeadership(t, s)
	runnerID := pgITRegisterRunner(t, s)

	w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed-reconcile leader next = %d, want 503: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "resource ledger not reconciled") {
		t.Fatalf("failed-reconcile leader body = %q, want the reconciling refusal", w.Body.String())
	}
	if got := w.Header().Get("X-Kiwi-State"); got != "reconciling" {
		t.Fatalf("failed-reconcile leader X-Kiwi-State = %q, want reconciling", got)
	}
	if s.resourceReconciled.Load() {
		t.Fatal("failed reconciliation armed the gate")
	}
}
