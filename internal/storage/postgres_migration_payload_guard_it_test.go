package storage

// Real-PostgreSQL regression for the migration payload-cast guards (G5-A).
// Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go here.
//
// The defect: migrations 0009 (runners.disabled/draining booleans), 0010
// (artifacts.job_generation bigint) and 0022 (jobs.queue_deadline timestamptz)
// backfilled a derived column from an UNTRUSTED payload with a bare cast. A
// single malformed row raised inside the per-file migration transaction, which
// therefore rolled back WITHOUT recording its version, so every later startup
// retried and aborted the same way — the whole fleet's startup was blocked by
// one corrupt payload. The tests below migrate to the pre-migration schema,
// seed malformed rows, and then run the normal startup Migrate: it must apply
// cleanly and leave each bad row at the column default.

import (
	"context"
	"testing"
	"time"
)

// TestPostgresIntegrationMigrationPayloadCastsGuarded is the G5-A regression:
// abc/notabool booleans, abc/1e999/1.5/boolean bigints, and out-of-range or
// calendar-invalid timestamps must all default rather than abort the migration.
func TestPostgresIntegrationMigrationPayloadCastsGuarded(t *testing.T) {
	env := pgITSetupAtVersion(t, 8)
	st := env.open(t)
	ctx := context.Background()

	// Stop just before 0009 so the runner-bound disabled/draining columns do
	// not exist yet and the migration's UPDATE is the writer under test.
	pgITApplyThrough(t, st, 8)

	seed := func(query string, args ...any) {
		t.Helper()
		if _, err := st.pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}
	// A run is needed because jobs.run_id is a foreign key.
	seed(`INSERT INTO runs (id, status, created_at, payload) VALUES ('guard-run', 'queued', now(), '{}'::jsonb)`)

	// 0009: malformed/valid disabled/draining payload shapes.
	seed(`INSERT INTO runners (id, payload) VALUES
		('r-bad-bool', '{"disabled":"abc","draining":"notabool"}'::jsonb),
		('r-num',      '{"disabled":1,"draining":0}'::jsonb),
		('r-null',     '{"disabled":null,"draining":null}'::jsonb),
		('r-valid',    '{"disabled":true,"draining":false}'::jsonb)`)

	// 0010: malformed/valid job_generation payload shapes.
	seed(`INSERT INTO artifacts (id, run_id, name, created_at, payload) VALUES
		('a-bad-str', 'guard-run', 'art', now(), '{"lease_generation":"abc"}'::jsonb),
		('a-huge',    'guard-run', 'art', now(), '{"lease_generation":1e999}'::jsonb),
		('a-frac',    'guard-run', 'art', now(), '{"lease_generation":1.5}'::jsonb),
		('a-bool',    'guard-run', 'art', now(), '{"lease_generation":true}'::jsonb),
		('a-missing', 'guard-run', 'art', now(), '{}'::jsonb),
		('a-valid',   'guard-run', 'art', now(), '{"lease_generation":42}'::jsonb)`)

	// 0022: malformed/valid queue_deadline payload shapes.
	seed(`INSERT INTO jobs (id, run_id, key, status, created_at, payload) VALUES
		('j-bad-month', 'guard-run', 'build', 'queued', now(), '{"queue_deadline":"2024-13-45T99:99:99Z"}'::jsonb),
		('j-bad-feb',   'guard-run', 'build', 'queued', now(), '{"queue_deadline":"2024-02-30T00:00:00Z"}'::jsonb),
		('j-bad-leap',  'guard-run', 'build', 'queued', now(), '{"queue_deadline":"2023-02-29T00:00:00Z"}'::jsonb),
		('j-bad-str',   'guard-run', 'build', 'queued', now(), '{"queue_deadline":"abc"}'::jsonb),
		('j-bad-obj',   'guard-run', 'build', 'queued', now(), '{"queue_deadline":{"x":1}}'::jsonb),
		('j-bad-space', 'guard-run', 'build', 'queued', now(), '{"queue_deadline":"2024-01-02 15:04:05Z"}'::jsonb),
		('j-valid',     'guard-run', 'build', 'queued', now(), '{"queue_deadline":"2024-01-02T15:04:05Z"}'::jsonb),
		('j-valid-frac','guard-run', 'build', 'queued', now(), '{"queue_deadline":"2024-02-29T23:59:59.123Z"}'::jsonb)`)

	// The normal startup migration applies 0009/0010/0022 (and the rest). The
	// bare pre-fix casts raised here and blocked startup.
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate over malformed payload rows: %v", err)
	}
	if v, err := st.SchemaVersion(ctx); err != nil || v != pgITLatestVersion(t) {
		t.Fatalf("SchemaVersion = %d, %v; want %d", v, err, pgITLatestVersion(t))
	}

	// 0009: every unusable value defaulted to FALSE; the valid boolean stuck.
	for _, tc := range []struct {
		id       string
		disabled bool
		draining bool
	}{
		{"r-bad-bool", false, false},
		{"r-num", false, false},
		{"r-null", false, false},
		{"r-valid", true, false},
	} {
		var disabled, draining bool
		if err := st.pool.QueryRow(ctx, `SELECT disabled, draining FROM runners WHERE id=$1`, tc.id).Scan(&disabled, &draining); err != nil {
			t.Fatalf("read runner %s: %v", tc.id, err)
		}
		if disabled != tc.disabled || draining != tc.draining {
			t.Errorf("runner %s = disabled=%v draining=%v, want %v/%v", tc.id, disabled, draining, tc.disabled, tc.draining)
		}
	}

	// 0010: every unusable value defaulted to 0; the valid bigint stuck.
	for _, tc := range []struct {
		id   string
		want int64
	}{
		{"a-bad-str", 0},
		{"a-huge", 0},
		{"a-frac", 0},
		{"a-bool", 0},
		{"a-missing", 0},
		{"a-valid", 42},
	} {
		var got int64
		if err := st.pool.QueryRow(ctx, `SELECT job_generation FROM artifacts WHERE id=$1`, tc.id).Scan(&got); err != nil {
			t.Fatalf("read artifact %s: %v", tc.id, err)
		}
		if got != tc.want {
			t.Errorf("artifact %s job_generation = %d, want %d", tc.id, got, tc.want)
		}
	}

	// 0022: malformed timestamps stay NULL (served by the query fallback); the
	// canonical RFC3339 shapes are cast.
	for _, id := range []string{"j-bad-month", "j-bad-feb", "j-bad-leap", "j-bad-str", "j-bad-obj", "j-bad-space"} {
		var deadline *string
		if err := st.pool.QueryRow(ctx, `SELECT queue_deadline::text FROM jobs WHERE id=$1`, id).Scan(&deadline); err != nil {
			t.Fatalf("read job %s: %v", id, err)
		}
		if deadline != nil {
			t.Errorf("job %s queue_deadline = %q, want NULL", id, *deadline)
		}
	}
	for _, id := range []string{"j-valid", "j-valid-frac"} {
		var deadline *string
		if err := st.pool.QueryRow(ctx, `SELECT queue_deadline::text FROM jobs WHERE id=$1`, id).Scan(&deadline); err != nil {
			t.Fatalf("read job %s: %v", id, err)
		}
		if deadline == nil {
			t.Errorf("job %s queue_deadline = NULL, want the parsed timestamp", id)
		}
	}
	var valid time.Time
	if err := st.pool.QueryRow(ctx, `SELECT queue_deadline FROM jobs WHERE id='j-valid'`).Scan(&valid); err != nil {
		t.Fatalf("read j-valid deadline: %v", err)
	}
	if want := time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC); !valid.Equal(want) {
		t.Errorf("j-valid queue_deadline = %v, want %v", valid, want)
	}
}
