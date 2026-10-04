package storage

// Migration identity integration: recorded digests must match the binary and
// the recorded compatibility floor must be observable. Gated on
// KIWI_TEST_POSTGRES_URL like the rest of the integration lane.

import (
	"context"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// TestPostgresIntegrationMigrationDigestMismatchRefused: editing an applied
// migration's content (or tampering with the recorded digest) is schema
// history divergence and must abort Migrate; restoring the true digest makes
// the same database migrate cleanly again.
func TestPostgresIntegrationMigrationDigestMismatchRefused(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	all, err := migrations.All()
	if err != nil || len(all) == 0 {
		t.Fatalf("migrations: %v", err)
	}
	first := all[0]
	if _, err := st.pool.Exec(ctx, `UPDATE schema_migrations SET sha256='deadbeef' WHERE version=$1`, first.Version); err != nil {
		t.Fatal(err)
	}
	err = st.Migrate(ctx)
	if err == nil || !strings.Contains(err.Error(), "divergence") {
		t.Fatalf("Migrate with a tampered digest = %v, want divergence", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE schema_migrations SET sha256=$2 WHERE version=$1`, first.Version, first.Digest); err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate after restoring the digest: %v", err)
	}
}

// TestPostgresIntegrationSchemaCompatibilityFloor: every migration defaults
// its floor to its own version, so a fully migrated database reports the
// binary's max version; a newer floor recorded by a later release is reported
// verbatim (the readiness gate turns it into a 503).
func TestPostgresIntegrationSchemaCompatibilityFloor(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	floor, err := st.SchemaCompatibilityFloor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if floor != maxV {
		t.Fatalf("floor = %d, want %d", floor, maxV)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE schema_migrations SET compatible_from=$1 WHERE version=$2`, maxV+5, maxV); err != nil {
		t.Fatal(err)
	}
	floor, err = st.SchemaCompatibilityFloor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if floor != maxV+5 {
		t.Fatalf("floor = %d, want %d", floor, maxV+5)
	}
}
