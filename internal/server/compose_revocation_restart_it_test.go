package server

// Revocation x restart composition in DB mode, against a live PostgreSQL
// database created fresh for this test: a disable (certificate revocation +
// disabled flag), a consumed enrollment grant and an unused one are committed
// on one replica, then a NEW replica (new pool, new empty data dir, so no
// node-local CRL mirror) is started over the same database and must enforce
// the same state.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// TestComposeRevocationAndGrantStateSurviveReplicaRestartDB drives the same
// enroll -> consume -> disable flow as the FS test, then restarts the
// control plane as a fresh replica over the same database.
func TestComposeRevocationAndGrantStateSurviveReplicaRestartDB(t *testing.T) {
	composeFreshPGDatabase(t)
	env := pgITServerSetup(t)
	stA := env.open(t)
	ctx := context.Background()

	ca, err := runnerpki.NewCA("compose db revocation ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sA, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := sA.SwitchToDB(stA); err != nil {
		t.Fatalf("replica A SwitchToDB: %v", err)
	}
	sA.RunnerCA = ca
	// DB-mode runner IDs are the store's canonical 32-hex identifiers.
	runnerID := pgITServerRandomHex(t, 32)
	runnerBearer := runnerID + "-bearer"

	grantUsed, err := sA.CreateEnrollGrant(ctx, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert := composeEnrollRunner(t, sA, grantUsed, runnerID)
	serial := cert.SerialNumber.Text(16)
	if code := composeRegisterCert(t, sA, runnerID, "runner-tok", cert); code != http.StatusOK {
		t.Fatalf("replica A register = %d", code)
	}
	grantUnused, err := sA.CreateEnrollGrant(ctx, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, sA, http.MethodPost, "/api/v1/runners/"+runnerID+"/disable", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("replica A disable = %d: %s", w.Code, w.Body.String())
	}
	if revoked, err := stA.CertRevoked(ctx, serial); err != nil || !revoked {
		t.Fatalf("durable revocation after disable = (%v, %v), want revoked", revoked, err)
	}
	if w := pkiRequest(t, sA.Handler(), http.MethodPost, "/api/v1/runners/enroll",
		EnrollRequest{RunnerID: "nope"}, grantUsed, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("grant reuse before restart = %d, want 401", w.Code)
	}

	// Replica restart: a new pool and a fresh, empty data dir (so there is no
	// node-local CRL mirror to fall back on) over the same database.
	stB := env.open(t)
	dirB := t.TempDir()
	sB, err := NewPersistent("runner-tok", "admin-tok", dirB)
	if err != nil {
		t.Fatal(err)
	}
	if err := sB.SwitchToDB(stB); err != nil {
		t.Fatalf("replica B SwitchToDB: %v", err)
	}
	sB.RunnerCA = ca
	// Provision the per-runner bearer BEFORE the first runner-tier request so
	// the replica knows per-runner credentials exist (the shared token can no
	// longer impersonate the runner).
	if err := sB.ProvisionRunnerTokensDB(ctx, map[string]string{runnerID: auth.TokenDigest(runnerBearer)}); err != nil {
		t.Fatal(err)
	}

	if !crlRevoked(t, sB, serial) {
		t.Fatal("revocation did not survive the replica restart")
	}
	ri, err := stB.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if !ri.Disabled || ri.RevokedAt == nil || ri.CertSerial != serial {
		t.Fatalf("restarted replica runner = disabled=%v revoked_at=%v serial=%q", ri.Disabled, ri.RevokedAt, ri.CertSerial)
	}

	// No re-registration with the revoked serial and no lease on the fresh
	// replica: the identity gate rejects the certificate the database says is
	// revoked, before any leadership or scheduling decision.
	if w := pkiRequest(t, sB.Handler(), http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": runnerID, "name": runnerID, "capacity": 1, "protocol_min": 3, "protocol_max": 3},
		runnerBearer, cert); w.Code != http.StatusForbidden {
		t.Fatalf("revoked-cert re-registration on the restarted replica = %d: %s", w.Code, w.Body.String())
	}
	if w := pkiRequest(t, sB.Handler(), http.MethodPost, "/api/v1/runners/"+runnerID+"/next",
		map[string]any{}, runnerBearer, cert); w.Code != http.StatusForbidden {
		t.Fatalf("revoked-cert lease on the restarted replica = %d: %s", w.Code, w.Body.String())
	}
	// Re-registration without the revoked certificate succeeds (the runner
	// may come back with a new credential) but must NOT clear the disable.
	if w := pkiRequest(t, sB.Handler(), http.MethodPost, "/api/v1/runners/register",
		map[string]any{"id": runnerID, "name": runnerID, "capacity": 1, "protocol_min": 3, "protocol_max": 3},
		runnerBearer, nil); w.Code != http.StatusOK {
		t.Fatalf("bearer re-registration on the restarted replica = %d: %s", w.Code, w.Body.String())
	}
	ri, err = stB.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if !ri.Disabled {
		t.Fatal("re-registration on the restarted replica cleared the disable")
	}

	// Grants: the consumed one stays consumed, the unused one survives and is
	// single-use.
	if w := pkiRequest(t, sB.Handler(), http.MethodPost, "/api/v1/runners/enroll",
		EnrollRequest{RunnerID: "nope"}, grantUsed, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("consumed grant reused on the restarted replica = %d, want 401", w.Code)
	}
	composeEnrollRunner(t, sB, grantUnused, pgITServerRandomHex(t, 32))
	if w := pkiRequest(t, sB.Handler(), http.MethodPost, "/api/v1/runners/enroll",
		EnrollRequest{RunnerID: "nope"}, grantUnused, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("grant reused after one enrollment on the restarted replica = %d, want 401", w.Code)
	}
}
