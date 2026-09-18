package storage

// Integration coverage for the deploy-safety split of the versioned
// forge-delivery migration (0018 + 0019/0020). Two properties are pinned
// against a real server:
//
//  1. A database whose outbox already holds rows (the dead-letter backlog a
//     forge outage leaves behind) still migrates: the ADD COLUMNs and both
//     index builds succeed with data present, the backlog is untouched, and
//     the unique versioned identity is enforced afterwards.
//  2. The final schema of the split files is byte-for-byte the same schema as
//     the original single-file 0018: comparing information_schema.columns and
//     pg_indexes between a schema migrated with the legacy combined file and
//     one migrated through the split files must produce identical snapshots.
//     The legacy schema also proves the upgrade path: a deployment that
//     already recorded version 18 must accept 0019/0020 as no-ops (their
//     IF NOT EXISTS indexes already exist) without changing the schema.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// legacy0018OutboxForgeVersions is the original combined
// 0018_outbox_forge_versions.sql (before the deploy-safety split), kept
// verbatim as the reference DDL for the schema-diff test.
const legacy0018OutboxForgeVersions = `ALTER TABLE outbox ADD COLUMN IF NOT EXISTS logical_key TEXT;

ALTER TABLE outbox ADD COLUMN IF NOT EXISTS state_version BIGINT NOT NULL DEFAULT 0;

CREATE UNIQUE INDEX IF NOT EXISTS outbox_logical_version_idx
    ON outbox (logical_key, state_version)
    WHERE logical_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS outbox_logical_pending_idx
    ON outbox (logical_key, state_version)
    WHERE logical_key IS NOT NULL AND dead_lettered_at IS NULL;

CREATE TABLE IF NOT EXISTS forge_check_state (
    logical_key       TEXT PRIMARY KEY,
    delivered_version BIGINT NOT NULL DEFAULT 0,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);`

// pgITApplyThrough applies every embedded migration with version <= max
// through the same per-file transaction path as Migrate, so a test can stop
// at a historical schema and seed data before the next migration runs.
func pgITApplyThrough(t *testing.T, st *PostgresStore, max int) {
	t.Helper()
	all, err := migrations.All()
	if err != nil {
		t.Fatalf("migrations.All: %v", err)
	}
	for _, m := range all {
		if m.Version > max {
			continue
		}
		if err := st.applyMigration(context.Background(), m); err != nil {
			t.Fatalf("apply %s: %v", m.Name, err)
		}
	}
}

// pgITApplyLegacy0018 replays the original single-file migration exactly as
// the runner did (all statements plus the version record in one transaction).
func pgITApplyLegacy0018(t *testing.T, st *PostgresStore) {
	t.Helper()
	ctx := context.Background()
	tx, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin legacy 0018: %v", err)
	}
	defer tx.Rollback(ctx)
	for _, stmt := range migrations.SplitStatements(legacy0018OutboxForgeVersions) {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			t.Fatalf("legacy 0018 statement %q: %v", stmt, err)
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES (18)`); err != nil {
		t.Fatalf("record legacy 0018: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit legacy 0018: %v", err)
	}
}

// pgITSchemaSnapshot captures the migration-owned shape of outbox and
// forge_check_state: every column with type/nullability/default in ordinal
// order, and every index with its full pg_indexes definition (schema
// qualifiers stripped so snapshots from different schemas are comparable).
func pgITSchemaSnapshot(t *testing.T, st *PostgresStore, schema string) []string {
	t.Helper()
	ctx := context.Background()
	var out []string
	rows, err := st.pool.Query(ctx, `
		SELECT table_name || '.' || column_name || ':' || data_type ||
		       ':nullable=' || is_nullable || ':default=' || COALESCE(column_default, '')
		FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name IN ('outbox', 'forge_check_state')
		ORDER BY table_name, ordinal_position`)
	if err != nil {
		t.Fatalf("snapshot columns: %v", err)
	}
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			rows.Close()
			t.Fatalf("scan column: %v", err)
		}
		out = append(out, line)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("snapshot columns rows: %v", err)
	}
	rows, err = st.pool.Query(ctx, `
		SELECT tablename || '.' || indexname || ':' || indexdef
		FROM pg_indexes
		WHERE schemaname = current_schema() AND tablename IN ('outbox', 'forge_check_state')
		ORDER BY tablename, indexname`)
	if err != nil {
		t.Fatalf("snapshot indexes: %v", err)
	}
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			rows.Close()
			t.Fatalf("scan index: %v", err)
		}
		out = append(out, strings.ReplaceAll(line, schema+".", ""))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("snapshot indexes rows: %v", err)
	}
	return out
}

// pgITAssertSplitIndexDefs asserts the split-built indexes exist with the
// definitions the combined migration produced. Deparsing parenthesization of
// boolean predicates varies across PostgreSQL majors, so the WHERE clause is
// checked by its clauses; the byte-identical cross-version comparison against
// the legacy schema is TestPostgresIntegrationMigrationSplitFinalSchemaMatchesLegacySingleFile.
func pgITAssertSplitIndexDefs(t *testing.T, st *PostgresStore, schema string) {
	t.Helper()
	ctx := context.Background()
	for _, want := range []struct {
		name  string
		def   string
		where []string
	}{
		{
			name:  "outbox_logical_version_idx",
			def:   "CREATE UNIQUE INDEX outbox_logical_version_idx ON outbox USING btree (logical_key, state_version) WHERE (logical_key IS NOT NULL)",
			where: []string{"logical_key IS NOT NULL"},
		},
		{
			name:  "outbox_logical_pending_idx",
			def:   "CREATE INDEX outbox_logical_pending_idx ON outbox USING btree (logical_key, state_version)",
			where: []string{"logical_key IS NOT NULL", "dead_lettered_at IS NULL"},
		},
	} {
		var def string
		if err := st.pool.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1`, want.name).Scan(&def); err != nil {
			t.Fatalf("index %s missing: %v", want.name, err)
		}
		def = strings.ReplaceAll(def, schema+".", "")
		if !strings.HasPrefix(def, want.def) {
			t.Errorf("index %s def = %q, want prefix %q", want.name, def, want.def)
		}
		for _, clause := range want.where {
			if !strings.Contains(def, clause) {
				t.Errorf("index %s def %q lacks predicate %q", want.name, def, clause)
			}
		}
	}
}

// TestPostgresIntegrationMigrationSplitPrePopulatedOutbox migrates to the
// pre-0018 schema, seeds the outbox with the backlog a forge outage leaves
// behind, then lets the normal startup Migrate apply 0018/0019/0020. The
// migration must succeed with data present, keep the backlog intact, and
// leave the unique versioned identity enforced.
func TestPostgresIntegrationMigrationSplitPrePopulatedOutbox(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	ctx := context.Background()

	pgITApplyThrough(t, st, 17)
	if v, err := st.SchemaVersion(ctx); err != nil || v != 17 {
		t.Fatalf("SchemaVersion before split = %d, %v; want 17", v, err)
	}

	// Dead-letter backlog: rows created before logical_key existed.
	for i := 0; i < 5; i++ {
		if _, err := st.pool.Exec(ctx, `INSERT INTO outbox (id, kind, payload, created_at) VALUES ($1, 'github_check', '{"v":1}'::jsonb, now())`, fmt.Sprintf("backlog-%d", i)); err != nil {
			t.Fatalf("seed backlog row %d: %v", i, err)
		}
	}

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate with non-empty outbox: %v", err)
	}

	// 0018/0019/0020 recorded exactly once each, in order, after 1..17.
	rows, err := st.pool.Query(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	var versions []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			t.Fatalf("scan version: %v", err)
		}
		versions = append(versions, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("schema_migrations rows: %v", err)
	}
	all, err := migrations.All()
	if err != nil {
		t.Fatalf("migrations.All: %v", err)
	}
	max := all[len(all)-1].Version
	if len(versions) != max || versions[max-3] != 18 || versions[max-2] != 19 || versions[max-1] != 20 {
		t.Fatalf("schema_migrations = %v, want 1..%d with 18,19,20 last", versions, max)
	}

	// Backlog untouched: same row count, new columns at their defaults.
	var n, nullKeys int
	if err := st.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE logical_key IS NULL AND state_version = 0) FROM outbox`).Scan(&n, &nullKeys); err != nil {
		t.Fatalf("backlog count: %v", err)
	}
	if n != 5 || nullKeys != 5 {
		t.Fatalf("backlog after migration = %d rows (%d with NULL logical_key), want 5/5", n, nullKeys)
	}

	pgITAssertSplitIndexDefs(t, st, env.schema)

	// The unique (logical_key, state_version) identity is live for new rows.
	if _, err := st.pool.Exec(ctx, `INSERT INTO outbox (id, kind, payload, created_at, logical_key, state_version) VALUES ('dup-a', 'github_check', '{}'::jsonb, now(), 'check-key-1', 1), ('dup-b', 'github_check', '{}'::jsonb, now(), 'check-key-1', 1)`); err == nil {
		t.Fatal("duplicate (logical_key, state_version) insert succeeded")
	} else if !strings.Contains(err.Error(), "outbox_logical_version_idx") || !strings.Contains(err.Error(), "23505") {
		t.Fatalf("duplicate insert error = %v, want 23505 on outbox_logical_version_idx", err)
	}
	// Legacy NULL-key rows stay exempt from the partial unique index.
	if _, err := st.pool.Exec(ctx, `INSERT INTO outbox (id, kind, payload, created_at) VALUES ('backlog-5', 'github_check', '{}'::jsonb, now())`); err != nil {
		t.Fatalf("NULL logical_key insert after split: %v", err)
	}
}

// TestPostgresIntegrationMigrationSplitFinalSchemaMatchesLegacySingleFile
// proves the split is schema-preserving: a schema migrated with the original
// combined 0018 has exactly the columns and pg_indexes definitions of a
// schema migrated through the split files. It also proves the in-place
// upgrade path: Migrate over the legacy schema applies 0019/0020 as no-ops
// and leaves the snapshot unchanged.
func TestPostgresIntegrationMigrationSplitFinalSchemaMatchesLegacySingleFile(t *testing.T) {
	legacyEnv := pgITSetup(t)
	legacy := legacyEnv.open(t)
	pgITApplyThrough(t, legacy, 17)
	pgITApplyLegacy0018(t, legacy)
	legacyBefore := pgITSchemaSnapshot(t, legacy, legacyEnv.schema)

	splitEnv := pgITSetup(t)
	split := splitEnv.open(t)
	if err := split.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate through split files: %v", err)
	}
	splitSnapshot := pgITSchemaSnapshot(t, split, splitEnv.schema)

	if len(legacyBefore) != len(splitSnapshot) {
		t.Fatalf("schema entries differ: legacy %d, split %d\nlegacy:\n%s\nsplit:\n%s",
			len(legacyBefore), len(splitSnapshot), strings.Join(legacyBefore, "\n"), strings.Join(splitSnapshot, "\n"))
	}
	for i := range legacyBefore {
		if legacyBefore[i] != splitSnapshot[i] {
			t.Fatalf("schema entry %d differs after split:\n legacy: %s\n split:  %s", i, legacyBefore[i], splitSnapshot[i])
		}
	}

	// Upgrade path: the legacy database already recorded 18, so Migrate only
	// runs 0019/0020; their IF NOT EXISTS indexes already exist (created by
	// the combined file) and must no-op without touching the schema.
	if err := legacy.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate over legacy-completed schema: %v", err)
	}
	if v, err := legacy.SchemaVersion(context.Background()); err != nil || v != allMigrationsMaxVersion(t) {
		t.Fatalf("SchemaVersion after legacy upgrade = %d, %v; want %d", v, err, allMigrationsMaxVersion(t))
	}
	legacyAfter := pgITSchemaSnapshot(t, legacy, legacyEnv.schema)
	if strings.Join(legacyAfter, "\n") != strings.Join(legacyBefore, "\n") {
		t.Fatalf("legacy schema changed by 0019/0020:\nbefore:\n%s\nafter:\n%s",
			strings.Join(legacyBefore, "\n"), strings.Join(legacyAfter, "\n"))
	}
}

func allMigrationsMaxVersion(t *testing.T) int {
	t.Helper()
	all, err := migrations.All()
	if err != nil {
		t.Fatalf("migrations.All: %v", err)
	}
	return all[len(all)-1].Version
}
