package app

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"github.com/jackc/pgx/v5"
)

var scratchDBCounter atomic.Int64

// scratchPostgresDSN creates a throwaway database on the configured test
// PostgreSQL instance and returns its DSN. The database is dropped on
// cleanup. Tests are skipped when KIWI_TEST_POSTGRES_URL is unset.
func scratchPostgresDSN(t *testing.T) string {
	t.Helper()
	base := testPostgresDSN()
	if base == "" {
		t.Skip("KIWI_TEST_POSTGRES_URL not set; skipping PostgreSQL integration test")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Skipf("cannot connect to KIWI_TEST_POSTGRES_URL: %v", err)
	}
	name := fmt.Sprintf("kiwi_app_cov_%d_%d", os.Getpid(), scratchDBCounter.Add(1))
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create scratch database: %v", err)
	}
	t.Cleanup(func() {
		dropCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = admin.Exec(dropCtx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		_ = admin.Close(dropCtx)
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse base DSN: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

// writeRunnerTokensFile writes a one-entry runner token map.
func writeRunnerTokensFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runner-tokens.json")
	if err := os.WriteFile(path, []byte(`{"runner-1":"`+strings.Repeat("ab", 32)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDatabaseMigrateAndStatusSchemaConflicts(t *testing.T) {
	dsn := scratchPostgresDSN(t)
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, "CREATE TABLE schema_migrations (version TEXT)"); err != nil {
		t.Fatal(err)
	}
	// The conflicting pre-existing table breaks migration 0001 and the
	// version probe.
	if err := DatabaseMigrate(ctx, []string{"--database-url", dsn}); err == nil {
		t.Fatal("DatabaseMigrate with a conflicting schema_migrations table succeeded")
	}
	if err := DatabaseStatus(ctx, []string{"--database-url", dsn}); err == nil {
		t.Fatal("DatabaseStatus with an incompatible schema_migrations table succeeded")
	}
}

func TestServerDBModeProvisioning(t *testing.T) {
	dsn := scratchPostgresDSN(t)
	dataDir := t.TempDir()
	clusterDir := filepath.Join(t.TempDir(), "cluster")
	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := startServer(t, ctx, "--listen", addr, "--database-url", dsn,
		"--data-dir", dataDir, "--cluster-key-dir", clusterDir,
		"--runner-tokens-file", writeRunnerTokensFile(t), "--database-max-connections", "3")
	waitTCPUp(t, addr, errCh, 15*time.Second)
	if err := stopServer(t, cancel, errCh); err != nil {
		t.Fatalf("DB-mode Server returned %v", err)
	}
	db, err := openDBForTest(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	has, err := hasProvisionedRunnerTokens(context.Background(), db)
	if err != nil || !has {
		t.Fatalf("provisioned runner tokens: has=%v err=%v", has, err)
	}
}

func TestServerDBModeWithoutDataDir(t *testing.T) {
	dsn := scratchPostgresDSN(t)
	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := startServer(t, ctx, "--listen", addr, "--database-url", dsn, "--admin-token", "admin")
	waitTCPUp(t, addr, errCh, 15*time.Second)
	if err := stopServer(t, cancel, errCh); err != nil {
		t.Fatalf("DB-mode Server without data-dir returned %v", err)
	}
}

func TestServerDBModeProductionUsesDBClusterKeyStore(t *testing.T) {
	// D3-C: production DB mode no longer accepts a node-local data-dir key
	// store, and no longer needs --cluster-key-dir either: the DB-backed
	// cluster key store is the preferred shared provider, so replicas share
	// every signing material through PostgreSQL. Startup must succeed and
	// the shared table must hold the material.
	dsn := scratchPostgresDSN(t)
	addr := freeTCPAddr(t)
	certFile, keyFile := writeSelfSignedTLS(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := startServer(t, ctx, "--listen", addr, "--database-url", dsn,
		"--mode", "production", "--external-url", "https://ci.example.com",
		"--tls-cert", certFile, "--tls-key", keyFile, "--admin-token", "admin",
		"--data-dir", t.TempDir(),
		"--runner-tokens-file", writeRunnerTokensFile(t))
	waitTCPUp(t, addr, errCh, 15*time.Second)
	if err := stopServer(t, cancel, errCh); err != nil {
		t.Fatalf("production DB-mode Server without --cluster-key-dir returned %v", err)
	}
	db, err := openDBForTest(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	blobs, ok := any(db).(storage.ClusterKeyBlobStore)
	if !ok {
		t.Fatal("SQL store does not implement ClusterKeyBlobStore")
	}
	for _, kind := range []string{"oidc", "lease", "provenance", "cache-signing", "web-session"} {
		b, found, gerr := blobs.GetClusterKey(context.Background(), kind)
		if gerr != nil || !found || len(b) == 0 {
			t.Fatalf("shared cluster key %q: found=%v len=%d err=%v", kind, found, len(b), gerr)
		}
	}
}

func TestServerDBModeProductionRunnerTokenOnlyWithProvisionedTokens(t *testing.T) {
	dsn := scratchPostgresDSN(t)
	// Seed per-runner credentials into runner_bearer_tokens through a dev
	// server (the provisioning path).
	seedAddr := freeTCPAddr(t)
	seedCtx, seedCancel := context.WithCancel(context.Background())
	seedCh := startServer(t, seedCtx, "--listen", seedAddr, "--database-url", dsn,
		"--data-dir", t.TempDir(), "--runner-tokens-file", writeRunnerTokensFile(t))
	waitTCPUp(t, seedAddr, seedCh, 15*time.Second)
	if err := stopServer(t, seedCancel, seedCh); err != nil {
		t.Fatalf("seeding server returned %v", err)
	}

	// D3-D: production with ONLY --runner-token (no mTLS, no tokens file)
	// starts because the durable store already holds per-runner credentials;
	// static validation must not reject it prematurely.
	certFile, keyFile := writeSelfSignedTLS(t)
	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := startServer(t, ctx, "--listen", addr, "--database-url", dsn,
		"--mode", "production", "--external-url", "https://ci.example.com",
		"--tls-cert", certFile, "--tls-key", keyFile,
		"--admin-token", "admin", "--runner-token", "shared-runner-token")
	waitTCPUp(t, addr, errCh, 15*time.Second)
	if err := stopServer(t, cancel, errCh); err != nil {
		t.Fatalf("production with --runner-token and provisioned bearer tokens returned %v", err)
	}
}

func TestServerDBModeProductionNoRunnerMechanismFailsPostDB(t *testing.T) {
	// D3-D: production with a shared token but no per-runner mechanism at
	// all fails the POST-DB credential check (not the static one) with a
	// clear message.
	dsn := scratchPostgresDSN(t)
	certFile, keyFile := writeSelfSignedTLS(t)
	err := Server(context.Background(), []string{"--listen", freeTCPAddr(t), "--database-url", dsn,
		"--mode", "production", "--external-url", "https://ci.example.com",
		"--tls-cert", certFile, "--tls-key", keyFile,
		"--admin-token", "admin", "--runner-token", "shared-runner-token"})
	if err == nil || !strings.Contains(err.Error(), "production requires runner mTLS or per-runner credentials") {
		t.Fatalf("production without runner credentials = %v", err)
	}
}

func TestServerDBModeAutoMigrateFailure(t *testing.T) {
	// A conflicting schema_migrations table makes the startup auto-migration
	// fail before the listener opens.
	dsn := scratchPostgresDSN(t)
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, "CREATE TABLE schema_migrations (version TEXT)"); err != nil {
		t.Fatal(err)
	}
	err = Server(ctx, []string{"--listen", freeTCPAddr(t), "--database-url", dsn})
	if err == nil || !strings.Contains(err.Error(), "auto-migrate") {
		t.Fatalf("Server with a broken schema = %v", err)
	}
}

func TestServerDBModeDataDirIsFile(t *testing.T) {
	dsn := scratchPostgresDSN(t)
	fileAsDir := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := Server(context.Background(), []string{"--listen", freeTCPAddr(t), "--database-url", dsn, "--data-dir", fileAsDir})
	if err == nil {
		t.Fatal("DB mode with a data-dir file succeeded")
	}
}

func TestServerAuthTokensFileFailure(t *testing.T) {
	err := Server(context.Background(), []string{"--listen", freeTCPAddr(t), "--tokens-file", filepath.Join(t.TempDir(), "missing.json")})
	if err == nil || !strings.Contains(err.Error(), "auth tokens file") {
		t.Fatalf("missing auth tokens file = %v", err)
	}
}

func TestServerDBModeProductionWithCluster(t *testing.T) {
	dsn := scratchPostgresDSN(t)
	addr := freeTCPAddr(t)
	certFile, keyFile := writeSelfSignedTLS(t)
	dataDir := t.TempDir()
	clusterDir := filepath.Join(t.TempDir(), "cluster")
	ctx, cancel := context.WithCancel(context.Background())
	errCh := startServer(t, ctx, "--listen", addr, "--database-url", dsn,
		"--mode", "production", "--external-url", "https://ci.example.com",
		"--tls-cert", certFile, "--tls-key", keyFile,
		"--data-dir", dataDir, "--cluster-key-dir", clusterDir, "--admin-token", "admin",
		"--runner-tokens-file", writeRunnerTokensFile(t))
	waitTCPUp(t, addr, errCh, 15*time.Second)
	if err := stopServer(t, cancel, errCh); err != nil {
		t.Fatalf("production DB-mode Server returned %v", err)
	}
}

func TestServerDBModeProductionChecksProvisionedTokens(t *testing.T) {
	dsn := scratchPostgresDSN(t)
	addr := freeTCPAddr(t)
	certFile, keyFile := writeSelfSignedTLS(t)
	dataDir := t.TempDir()
	clusterDir := filepath.Join(t.TempDir(), "cluster")
	// No credentials at all: --allow-shared-token satisfies the static
	// validation, then the DB probe finds no provisioned token rows and
	// refuses to start.
	err := Server(context.Background(), []string{"--listen", addr, "--database-url", dsn,
		"--mode", "production", "--external-url", "https://ci.example.com",
		"--tls-cert", certFile, "--tls-key", keyFile, "--allow-shared-token",
		"--data-dir", dataDir, "--cluster-key-dir", clusterDir})
	if err == nil || !strings.Contains(err.Error(), "production requires runner mTLS or per-runner credentials") {
		t.Fatalf("production without runner credentials = %v", err)
	}
	// Once tokens are provisioned into the same database, the probe passes
	// and the production server starts.
	seedAddr := freeTCPAddr(t)
	seedCtx, seedCancel := context.WithCancel(context.Background())
	seedCh := startServer(t, seedCtx, "--listen", seedAddr, "--database-url", dsn,
		"--data-dir", t.TempDir(), "--cluster-key-dir", filepath.Join(t.TempDir(), "c"),
		"--runner-tokens-file", writeRunnerTokensFile(t))
	waitTCPUp(t, seedAddr, seedCh, 15*time.Second)
	if err := stopServer(t, seedCancel, seedCh); err != nil {
		t.Fatalf("seeding server returned %v", err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	errCh := startServer(t, ctx2, "--listen", addr, "--database-url", dsn,
		"--mode", "production", "--external-url", "https://ci.example.com",
		"--tls-cert", certFile, "--tls-key", keyFile, "--allow-shared-token",
		"--data-dir", dataDir, "--cluster-key-dir", clusterDir)
	waitTCPUp(t, addr, errCh, 15*time.Second)
	if err := stopServer(t, cancel2, errCh); err != nil {
		t.Fatalf("production DB-mode Server with provisioned tokens returned %v", err)
	}
}

// openDBForTest opens a storage connection for assertions.
func openDBForTest(dsn string) (*storage.PostgresStore, error) {
	return storage.NewPostgres(context.Background(), dsn)
}
