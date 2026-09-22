package storage

// Cross-feature composition at the storage seam: the durable revocation and
// enrollment-grant state one control-plane replica commits must be the state a
// RESTARTED replica (a second pool, opened after the first is closed, with no
// process-local state) reads and enforces. Every test creates its own
// throwaway database on the server named by KIWI_TEST_POSTGRES_URL.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// composeStorageFreshDB creates a throwaway database and points this test's
// DSN at it, so the per-test throwaway schema helper and every pool opened
// through it live in a database no other test shares. The database is dropped
// (terminating its backends first) on cleanup.
func composeStorageFreshDB(t *testing.T) string {
	t.Helper()
	base := pgITDSN(t)
	ctx := context.Background()
	adminCfg, err := pgx.ParseConfig(base)
	if err != nil {
		t.Fatalf("parse KIWI_TEST_POSTGRES_URL: %v", err)
	}
	admin, err := pgx.ConnectConfig(ctx, adminCfg)
	if err != nil {
		t.Fatalf("connect to KIWI_TEST_POSTGRES_URL: %v", err)
	}
	dbName := "kiwi_compose_" + pgITRandomHex(t, 10)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create database %s: %v", dbName, err)
	}
	if err := admin.Close(ctx); err != nil {
		t.Fatalf("close admin connection: %v", err)
	}
	freshCfg, err := pgx.ParseConfig(base)
	if err != nil {
		t.Fatalf("re-parse KIWI_TEST_POSTGRES_URL: %v", err)
	}
	freshCfg.Database = dbName
	t.Setenv("KIWI_TEST_POSTGRES_URL", freshCfg.ConnString())
	t.Cleanup(func() {
		cctx := context.Background()
		c, cerr := pgx.ConnectConfig(cctx, adminCfg)
		if cerr != nil {
			t.Logf("drop database %s: connect: %v", dbName, cerr)
			return
		}
		defer func() { _ = c.Close(cctx) }()
		if _, terr := c.Exec(cctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()", dbName); terr != nil {
			t.Logf("terminate backends for %s: %v", dbName, terr)
		}
		if _, derr := c.Exec(cctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize()); derr != nil {
			t.Logf("drop database %s: %v", dbName, derr)
		}
	})
	return freshCfg.ConnString()
}

// TestComposeRevocationAndGrantStateSurvivePoolRestart commits a runner
// disable (certificate revocation included) and an enrollment-grant
// consumption on one pool, closes it, and proves a restarted replica pool sees
// and enforces exactly that state: the serial stays revoked, the runner stays
// disabled, the consumed grant stays consumed and an unused grant is still
// single-use.
func TestComposeRevocationAndGrantStateSurvivePoolRestart(t *testing.T) {
	composeStorageFreshDB(t)
	env := pgITSetup(t)
	stA := env.open(t)
	env.migrate(t, stA)
	ctx := context.Background()

	const serial = "c0mp0se-5er1al"
	runnerID := pgITNewID(t)
	if err := stA.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 1, CertSerial: serial}); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	if _, err := stA.DisableRunnerAndRevokeCert(ctx, runnerID, serial, "compose-tester"); err != nil {
		t.Fatalf("disable runner: %v", err)
	}
	consumedDigest := "compose-consumed-grant"
	if err := stA.PutEnrollGrant(ctx, consumedDigest, time.Now().UTC().Add(time.Hour), nil); err != nil {
		t.Fatalf("put consumed grant: %v", err)
	}
	if _, err := stA.ConsumeEnrollGrant(ctx, consumedDigest, "compose-tester"); err != nil {
		t.Fatalf("consume grant: %v", err)
	}
	unusedDigest := "compose-unused-grant"
	if err := stA.PutEnrollGrant(ctx, unusedDigest, time.Now().UTC().Add(time.Hour), nil); err != nil {
		t.Fatalf("put unused grant: %v", err)
	}
	if revoked, err := stA.CertRevoked(ctx, serial); err != nil || !revoked {
		t.Fatalf("revocation before restart = (%v, %v)", revoked, err)
	}

	// Replica restart: the first pool is closed outright.
	if err := stA.Close(); err != nil {
		t.Fatalf("close replica A: %v", err)
	}
	stB := env.open(t)

	revoked, err := stB.CertRevoked(ctx, serial)
	if err != nil || !revoked {
		t.Fatalf("revocation after restart = (%v, %v), want revoked", revoked, err)
	}
	ri, err := stB.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("runner after restart: %v", err)
	}
	if !ri.Disabled || ri.RevokedAt == nil {
		t.Fatalf("runner after restart = disabled=%v revoked_at=%v", ri.Disabled, ri.RevokedAt)
	}
	rec, found, err := stB.GetEnrollGrant(ctx, consumedDigest)
	if err != nil || !found || !rec.Consumed {
		t.Fatalf("consumed grant after restart = (%+v, %v, %v)", rec, found, err)
	}
	if _, err := stB.ConsumeEnrollGrant(ctx, consumedDigest, "compose-tester"); !errors.Is(err, ErrGrantConsumed) {
		t.Fatalf("consumed grant reuse after restart = %v, want ErrGrantConsumed", err)
	}
	if _, err := stB.ConsumeEnrollGrant(ctx, unusedDigest, "compose-tester"); err != nil {
		t.Fatalf("unused grant after restart: %v", err)
	}
	if _, err := stB.ConsumeEnrollGrant(ctx, unusedDigest, "compose-tester"); !errors.Is(err, ErrGrantConsumed) {
		t.Fatalf("unused grant second consume after restart = %v, want ErrGrantConsumed", err)
	}
}
