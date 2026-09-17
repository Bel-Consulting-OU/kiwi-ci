package app

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// testPostgresDSN returns the integration DSN from the environment, or ""
// when the PostgreSQL lane is not configured.
func testPostgresDSN() string {
	return strings.TrimSpace(os.Getenv("KIWI_TEST_POSTGRES_URL"))
}

func TestDatabaseMigrateAndStatusAgainstPostgres(t *testing.T) {
	dsn := testPostgresDSN()
	if dsn == "" {
		t.Skip("KIWI_TEST_POSTGRES_URL not set; skipping PostgreSQL integration test")
	}
	ctx := context.Background()
	if err := DatabaseMigrate(ctx, []string{"--database-url", dsn}); err != nil {
		t.Fatalf("DatabaseMigrate: %v", err)
	}
	if err := DatabaseStatus(ctx, []string{"--database-url", dsn}); err != nil {
		t.Fatalf("DatabaseStatus: %v", err)
	}
	db, err := storage.NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.SchemaVersion(ctx); err != nil {
		t.Fatalf("SchemaVersion after migrate: %v", err)
	}
	has, err := hasProvisionedRunnerTokens(ctx, db)
	if err != nil {
		t.Fatalf("hasProvisionedRunnerTokens: %v", err)
	}
	_ = has
}

func TestDatabaseMigrateAndStatusErrors(t *testing.T) {
	ctx := context.Background()
	if err := DatabaseMigrate(ctx, nil); err == nil || !strings.Contains(err.Error(), "--database-url") {
		t.Fatalf("DatabaseMigrate without a URL = %v", err)
	}
	if err := DatabaseStatus(ctx, nil); err == nil || !strings.Contains(err.Error(), "--database-url") {
		t.Fatalf("DatabaseStatus without a URL = %v", err)
	}
	if err := DatabaseMigrate(ctx, []string{"--bogus"}); err == nil {
		t.Fatal("DatabaseMigrate with an unknown flag succeeded")
	}
	if err := DatabaseStatus(ctx, []string{"--bogus"}); err == nil {
		t.Fatal("DatabaseStatus with an unknown flag succeeded")
	}
	bad := "postgres://postgres@127.0.0.1:1/postgres?sslmode=disable"
	if err := DatabaseMigrate(ctx, []string{"--database-url", bad}); err == nil {
		t.Fatal("DatabaseMigrate against an unreachable database succeeded")
	}
	if err := DatabaseStatus(ctx, []string{"--database-url", bad}); err == nil {
		t.Fatal("DatabaseStatus against an unreachable database succeeded")
	}
	// A URL that does not even parse fails during pool configuration.
	if err := DatabaseStatus(ctx, []string{"--database-url", "postgres://u:p@%%%bad"}); err == nil {
		t.Fatal("DatabaseStatus with a malformed DSN succeeded")
	}
}

func TestDatabaseMigrateEnvFallback(t *testing.T) {
	dsn := testPostgresDSN()
	if dsn == "" {
		t.Skip("KIWI_TEST_POSTGRES_URL not set; skipping PostgreSQL integration test")
	}
	t.Setenv("KIWI_DATABASE_URL", dsn)
	if err := DatabaseStatus(context.Background(), nil); err != nil {
		t.Fatalf("DatabaseStatus with KIWI_DATABASE_URL: %v", err)
	}
}
