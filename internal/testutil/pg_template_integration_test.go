package testutil

// Real-PostgreSQL integration tests for the reusable template harness. They
// are gated on KIWI_TEST_POSTGRES_URL (skipped when unset) and drive the
// exported EnsureTemplate/CloneDatabase contract against a real server,
// including the failure and cleanup paths that the storage/server suites
// exercise only indirectly. The package cannot use storage's pgIT helpers
// (that would be an import cycle), so the tests speak pgx directly.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

// pgTemplateITDSN returns the integration DSN or skips the test.
func pgTemplateITDSN(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("postgres integration tests skipped in -short mode")
	}
	dsn := strings.TrimSpace(os.Getenv("KIWI_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("KIWI_TEST_POSTGRES_URL not set; skipping PostgreSQL integration tests")
	}
	return dsn
}

// recordingTB wraps a real testing.TB and records Fatalf/Logf calls instead
// of failing the real test, so the intentional failure paths of the harness
// (bad DSN, permission refusal, missing template) can be asserted without
// failing the surrounding test. The embedded TB keeps the private method and
// every other method delegated to the real test.
type recordingTB struct {
	testing.TB
	mu    sync.Mutex
	fatal []string
	logs  []string
}

func (r *recordingTB) Helper() {}

// fatalPanic is the control-flow signal recordingTB.Fatalf raises so the
// harness stops at the same point testing.T.Fatalf would, without failing the
// real test. itFatal recovers it.
type fatalPanic struct{ message string }

func (r *recordingTB) Fatalf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	r.mu.Lock()
	r.fatal = append(r.fatal, msg)
	r.mu.Unlock()
	panic(fatalPanic{message: msg})
}

// itFatal runs fn, absorbing the fatalPanic a recordingTB raises on an
// intentional harness failure. Any other panic propagates.
func itFatal(fn func()) {
	defer func() {
		if p := recover(); p != nil {
			if _, ok := p.(fatalPanic); ok {
				return
			}
			panic(p)
		}
	}()
	fn()
}

func (r *recordingTB) Logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, fmt.Sprintf(format, args...))
}

func (r *recordingTB) fatals() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.fatal...)
}

func (r *recordingTB) logged() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.logs...)
}

// itAdmin opens one admin connection on the base DSN and closes it on test
// cleanup.
func itAdmin(t *testing.T, baseDSN string) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, baseDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// itExec runs one statement and fails the test on error.
func itExec(t *testing.T, conn *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := conn.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

// itDatabaseCount returns how many databases carry exactly name.
func itDatabaseCount(t *testing.T, conn *pgx.Conn, name string) int {
	t.Helper()
	var n int
	if err := conn.QueryRow(context.Background(), `SELECT count(*) FROM pg_database WHERE datname = $1`, name).Scan(&n); err != nil {
		t.Fatalf("count database %s: %v", name, err)
	}
	return n
}

// itDatabaseName extracts the database name from a URL DSN.
func itDatabaseName(t *testing.T, dsn string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse clone dsn %q: %v", dsn, err)
	}
	name := strings.TrimPrefix(u.Path, "/")
	if name == "" {
		t.Fatalf("clone dsn %q has no database name", dsn)
	}
	return name
}

// itDSNAsUser rewrites a URL DSN so it authenticates as user/password,
// keeping the host and database.
func itDSNAsUser(t *testing.T, dsn, user, password string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn %q: %v", dsn, err)
	}
	u.User = url.UserPassword(user, password)
	return u.String()
}

// itMigrateProbe applies a minimal real schema to the freshly created
// template and closes every connection before returning, as the TemplateSpec
// contract demands.
func itMigrateProbe(ctx context.Context, dsn string) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(ctx, `CREATE TABLE probe_marker (id int primary key, note text)`); err != nil {
		return err
	}
	_, err = conn.Exec(ctx, `INSERT INTO probe_marker (id, note) VALUES (1, 'template')`)
	return err
}

// TestIntegrationTemplateBuildReuseCloneAndCleanup drives the full happy
// path: a fresh template is built and migrated, a second EnsureTemplate call
// reuses it (the marker row inserted behind its back survives), a clone is a
// byte-for-byte copy of the migrated template, and the registered cleanup
// drops the clone while the template stays.
func TestIntegrationTemplateBuildReuseCloneAndCleanup(t *testing.T) {
	base := pgTemplateITDSN(t)
	admin := itAdmin(t, base)
	suffix := randomHex(t, 10)
	template := "kiwi_tu_tmpl_" + suffix
	prefix := "kiwi_tu_clone_" + suffix + "_"
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP DATABASE IF EXISTS `+pgx.Identifier{template}.Sanitize()+` WITH (FORCE)`)
	})
	spec := TemplateSpec{BaseDSN: base, Name: template, Migrate: itMigrateProbe}

	EnsureTemplate(t, spec, prefix)
	if n := itDatabaseCount(t, admin, template); n != 1 {
		t.Fatalf("template databases = %d, want 1", n)
	}
	// A second call must reuse the once-built template, not rebuild it: a row
	// written directly into the template after the first build survives.
	tmplDSN, err := dsnWithDatabase(base, template)
	if err != nil {
		t.Fatalf("template dsn: %v", err)
	}
	tmplConn, err := pgx.Connect(context.Background(), tmplDSN)
	if err != nil {
		t.Fatalf("connect to template: %v", err)
	}
	if _, err := tmplConn.Exec(context.Background(), `INSERT INTO probe_marker (id, note) VALUES (2, 'reuse')`); err != nil {
		t.Fatalf("insert template marker: %v", err)
	}
	_ = tmplConn.Close(context.Background())
	EnsureTemplate(t, spec, prefix)
	tmplConn, err = pgx.Connect(context.Background(), tmplDSN)
	if err != nil {
		t.Fatalf("reconnect to template: %v", err)
	}
	var reuse int
	if err := tmplConn.QueryRow(context.Background(), `SELECT count(*) FROM probe_marker`).Scan(&reuse); err != nil {
		t.Fatalf("read template marker: %v", err)
	}
	_ = tmplConn.Close(context.Background())
	if reuse != 2 {
		t.Fatalf("marker rows after reuse = %d, want 2 (template must not be rebuilt)", reuse)
	}

	var cloneName string
	t.Run("clone", func(t *testing.T) {
		cloneDSN := CloneDatabase(t, base, template, prefix)
		cloneName = itDatabaseName(t, cloneDSN)
		if !strings.HasPrefix(cloneName, prefix) || len(cloneName) != len(prefix)+12 {
			t.Fatalf("clone name %q does not match %s+12 hex", cloneName, prefix)
		}
		conn, err := pgx.Connect(context.Background(), cloneDSN)
		if err != nil {
			t.Fatalf("connect to clone: %v", err)
		}
		defer func() { _ = conn.Close(context.Background()) }()
		var rows int
		if err := conn.QueryRow(context.Background(), `SELECT count(*) FROM probe_marker`).Scan(&rows); err != nil {
			t.Fatalf("read clone marker: %v", err)
		}
		if rows != 2 {
			t.Fatalf("clone marker rows = %d, want the template's 2", rows)
		}
	})
	// The subtest's registered cleanup has run: the clone is gone, and the
	// template (which must never be treated as a stale clone) remains.
	if n := itDatabaseCount(t, admin, cloneName); n != 0 {
		t.Fatalf("clone %s survived its cleanup", cloneName)
	}
	if n := itDatabaseCount(t, admin, template); n != 1 {
		t.Fatalf("template %s was dropped by the clone cleanup", template)
	}
}

// TestIntegrationTemplateMigrateFailureDropsTemplate proves a failing
// migration removes the half-built template so a rerun starts clean.
func TestIntegrationTemplateMigrateFailureDropsTemplate(t *testing.T) {
	base := pgTemplateITDSN(t)
	admin := itAdmin(t, base)
	suffix := randomHex(t, 10)
	template := "kiwi_tu_badmig_" + suffix
	spec := TemplateSpec{
		BaseDSN: base,
		Name:    template,
		Migrate: func(context.Context, string) error { return errors.New("migration exploded") },
	}
	rec := &recordingTB{TB: t}
	itFatal(func() { EnsureTemplate(rec, spec, "kiwi_tu_badmig_clone_"+suffix) })
	fatals := rec.fatals()
	if len(fatals) != 1 || !strings.Contains(fatals[0], "migrate template") {
		t.Fatalf("fatals = %v, want one migrate template failure", fatals)
	}
	if n := itDatabaseCount(t, admin, template); n != 0 {
		t.Fatalf("failed template %s was left behind", template)
	}
}

// TestIntegrationTemplateBadDSNFails covers the connect failure of the
// template builder: the harness reports it through the test's Fatalf without
// panicking.
func TestIntegrationTemplateBadDSNFails(t *testing.T) {
	// Gate on the integration DSN (skips without a database), even though
	// this particular subtest deliberately targets an unreachable port.
	_ = pgTemplateITDSN(t)
	bad := "postgres://postgres:postgres@127.0.0.1:1/kiwi_it?sslmode=disable&connect_timeout=1"
	rec := &recordingTB{TB: t}
	itFatal(func() {
		EnsureTemplate(rec, TemplateSpec{
			BaseDSN: bad,
			Name:    "kiwi_tu_unreachable_" + randomHex(t, 8),
			Migrate: func(context.Context, string) error { return nil },
		}, "kiwi_tu_unreachable_clone_"+randomHex(t, 8))
	})
	fatals := rec.fatals()
	if len(fatals) != 1 || !strings.Contains(fatals[0], "prepare template database") {
		t.Fatalf("fatals = %v, want one prepare template database failure", fatals)
	}
}

// TestIntegrationCloneDatabaseFailures covers the clone failures: an
// unreachable base DSN and a missing template both fail the calling test
// cleanly and create nothing.
func TestIntegrationCloneDatabaseFailures(t *testing.T) {
	base := pgTemplateITDSN(t)
	admin := itAdmin(t, base)
	suffix := randomHex(t, 10)

	t.Run("bad base dsn", func(t *testing.T) {
		rec := &recordingTB{TB: t}
		itFatal(func() {
			CloneDatabase(rec, "postgres://postgres:postgres@127.0.0.1:1/kiwi_it?sslmode=disable&connect_timeout=1", "whatever", "kiwi_tu_badbase_"+suffix)
		})
		fatals := rec.fatals()
		if len(fatals) != 1 || !strings.Contains(fatals[0], "connect to base dsn for clone") {
			t.Fatalf("fatals = %v, want a base dsn connect failure", fatals)
		}
	})

	t.Run("missing template", func(t *testing.T) {
		missing := "kiwi_tu_missing_" + randomHex(t, 10)
		prefix := "kiwi_tu_missclone_" + suffix + "_"
		rec := &recordingTB{TB: t}
		itFatal(func() { CloneDatabase(rec, base, missing, prefix) })
		fatals := rec.fatals()
		if len(fatals) != 1 || !strings.Contains(fatals[0], "clone template") {
			t.Fatalf("fatals = %v, want a clone template failure", fatals)
		}
		var stale int
		if err := admin.QueryRow(context.Background(),
			`SELECT count(*) FROM pg_database WHERE datname LIKE $1`, prefix+"%").Scan(&stale); err != nil {
			t.Fatalf("count stray clones: %v", err)
		}
		if stale != 0 {
			t.Fatalf("failed clone left %d stray database(s)", stale)
		}
	})
}

// TestIntegrationPermissionRefusalIsReported drives the two permission
// failures of the builder with a real non-superuser role: an existing
// database it does not own cannot be dropped (stale-template cleanup), and a
// database it may not create fails the template creation.
func TestIntegrationPermissionRefusalIsReported(t *testing.T) {
	base := pgTemplateITDSN(t)
	admin := itAdmin(t, base)
	suffix := randomHex(t, 8)
	role := "kiwi_tu_role_" + suffix
	basedb := itDatabaseName(t, base)

	itExec(t, admin, `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN PASSWORD 'kiwi-it-test'`)
	t.Cleanup(func() {
		cctx := context.Background()
		for _, db := range []string{"kiwi_tu_owned_" + suffix, "kiwi_tu_new_" + suffix} {
			_, _ = admin.Exec(cctx, `DROP DATABASE IF EXISTS `+pgx.Identifier{db}.Sanitize()+` WITH (FORCE)`)
		}
		_, _ = admin.Exec(cctx, `REVOKE CONNECT ON DATABASE `+pgx.Identifier{basedb}.Sanitize()+` FROM `+pgx.Identifier{role}.Sanitize())
		_, _ = admin.Exec(cctx, `DROP ROLE `+pgx.Identifier{role}.Sanitize())
	})
	itExec(t, admin, `GRANT CONNECT ON DATABASE `+pgx.Identifier{basedb}.Sanitize()+` TO `+pgx.Identifier{role}.Sanitize())
	roleDSN := itDSNAsUser(t, base, role, "kiwi-it-test")

	t.Run("drop refused on foreign database", func(t *testing.T) {
		// Owned by the superuser: the role's DROP DATABASE is refused.
		owned := "kiwi_tu_owned_" + suffix
		itExec(t, admin, `CREATE DATABASE `+pgx.Identifier{owned}.Sanitize())
		rec := &recordingTB{TB: t}
		itFatal(func() {
			EnsureTemplate(rec, TemplateSpec{
				BaseDSN: roleDSN,
				Name:    owned,
				Migrate: func(context.Context, string) error { return nil },
			}, "kiwi_tu_perm_"+suffix)
		})
		fatals := rec.fatals()
		if len(fatals) != 1 || !strings.Contains(fatals[0], "drop stale template") {
			t.Fatalf("fatals = %v, want a drop stale template refusal", fatals)
		}
		if n := itDatabaseCount(t, admin, owned); n != 1 {
			t.Fatalf("foreign database %s was dropped", owned)
		}
	})

	t.Run("create refused without CREATEDB", func(t *testing.T) {
		rec := &recordingTB{TB: t}
		itFatal(func() {
			EnsureTemplate(rec, TemplateSpec{
				BaseDSN: roleDSN,
				Name:    "kiwi_tu_new_" + suffix,
				Migrate: func(context.Context, string) error { return nil },
			}, "kiwi_tu_perm2_"+suffix)
		})
		fatals := rec.fatals()
		if len(fatals) != 1 || !strings.Contains(fatals[0], "create template") {
			t.Fatalf("fatals = %v, want a create template refusal", fatals)
		}
	})
}

// TestIntegrationStaleCloneCleanup drops a database left behind by a crashed
// run (the exact prefix+12-hex shape) on the first build for its prefix,
// while leaving look-alike names that do not match the generated shape alone.
func TestIntegrationStaleCloneCleanup(t *testing.T) {
	base := pgTemplateITDSN(t)
	admin := itAdmin(t, base)
	suffix := randomHex(t, 10)
	prefix := "kiwi_tu_stale_" + suffix + "_"
	template := "kiwi_tu_stale_tmpl_" + suffix
	stale := prefix + "0123456789ab"
	lookalike := prefix + "not-a-clone"
	itExec(t, admin, `CREATE DATABASE `+pgx.Identifier{stale}.Sanitize())
	itExec(t, admin, `CREATE DATABASE `+pgx.Identifier{lookalike}.Sanitize())
	t.Cleanup(func() {
		cctx := context.Background()
		for _, db := range []string{template, stale, lookalike} {
			_, _ = admin.Exec(cctx, `DROP DATABASE IF EXISTS `+pgx.Identifier{db}.Sanitize()+` WITH (FORCE)`)
		}
	})

	EnsureTemplate(t, TemplateSpec{BaseDSN: base, Name: template, Migrate: itMigrateProbe}, prefix)

	if n := itDatabaseCount(t, admin, stale); n != 0 {
		t.Fatalf("stale clone %s survived the first template build", stale)
	}
	if n := itDatabaseCount(t, admin, lookalike); n != 1 {
		t.Fatalf("non-clone look-alike %s was dropped by stale cleanup", lookalike)
	}
	if n := itDatabaseCount(t, admin, template); n != 1 {
		t.Fatalf("template %s was dropped by its own stale cleanup", template)
	}
}

// TestIntegrationCloneCleanupFailureIsLogged pins the teardown failure
// behaviour: when the clone can no longer be dropped by the DSN that created
// it (ownership moved), the cleanup logs the failure instead of failing the
// test, and the clone remains until an operator/admin removes it.
func TestIntegrationCloneCleanupFailureIsLogged(t *testing.T) {
	base := pgTemplateITDSN(t)
	admin := itAdmin(t, base)
	suffix := randomHex(t, 8)
	role := "kiwi_tu_owner_" + suffix
	basedb := itDatabaseName(t, base)
	template := "kiwi_tu_cleanup_tmpl_" + suffix
	prefix := "kiwi_tu_cleanup_" + suffix + "_"

	itExec(t, admin, `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN CREATEDB PASSWORD 'kiwi-it-test'`)
	t.Cleanup(func() {
		cctx := context.Background()
		_, _ = admin.Exec(cctx, `DROP DATABASE IF EXISTS `+pgx.Identifier{template}.Sanitize()+` WITH (FORCE)`)
		_, _ = admin.Exec(cctx, `REVOKE CONNECT ON DATABASE `+pgx.Identifier{basedb}.Sanitize()+` FROM `+pgx.Identifier{role}.Sanitize())
		_, _ = admin.Exec(cctx, `DROP ROLE `+pgx.Identifier{role}.Sanitize())
	})
	itExec(t, admin, `GRANT CONNECT ON DATABASE `+pgx.Identifier{basedb}.Sanitize()+` TO `+pgx.Identifier{role}.Sanitize())
	EnsureTemplate(t, TemplateSpec{BaseDSN: base, Name: template, Migrate: itMigrateProbe}, prefix)
	// The low-privilege role may clone the template only when it is marked as
	// a template; marking it does not change the schema copy semantics.
	itExec(t, admin, `ALTER DATABASE `+pgx.Identifier{template}.Sanitize()+` IS_TEMPLATE true`)
	itExec(t, admin, `GRANT CONNECT ON DATABASE `+pgx.Identifier{template}.Sanitize()+` TO `+pgx.Identifier{role}.Sanitize())

	var (
		cloneName string
		sub       *recordingTB
	)
	t.Run("clone cleanup refused", func(t *testing.T) {
		sub = &recordingTB{TB: t}
		roleBase := itDSNAsUser(t, base, role, "kiwi-it-test")
		cloneDSN := CloneDatabase(sub, roleBase, template, prefix)
		cloneName = itDatabaseName(t, cloneDSN)
		// Move ownership away before the subtest (hence its cleanup) ends:
		// the role's DROP DATABASE must be refused and logged.
		if _, err := admin.Exec(context.Background(), `ALTER DATABASE `+pgx.Identifier{cloneName}.Sanitize()+` OWNER TO postgres`); err != nil {
			t.Fatalf("move clone ownership: %v", err)
		}
	})
	// The clone cleanup ran at subtest end and failed (logged), so the clone
	// still exists.
	if n := itDatabaseCount(t, admin, cloneName); n != 1 {
		t.Fatalf("clone %s unexpectedly gone; its cleanup should have failed", cloneName)
	}
	logged := sub.logged()
	if len(logged) == 0 || !strings.Contains(strings.Join(logged, "\n"), "drop database "+cloneName) {
		t.Fatalf("cleanup logs = %v, want a drop database failure for %s", logged, cloneName)
	}
	itExec(t, admin, `DROP DATABASE IF EXISTS `+pgx.Identifier{cloneName}.Sanitize()+` WITH (FORCE)`)
}

// TestIntegrationCloneCleanupConnectFailureIsLogged covers the other teardown
// failure: the base server/database is gone by cleanup time, so the drop
// connect fails and is logged (never fatal) while the clone is reclaimed by
// the stale-clone sweep of a later run.
func TestIntegrationCloneCleanupConnectFailureIsLogged(t *testing.T) {
	base := pgTemplateITDSN(t)
	admin := itAdmin(t, base)
	suffix := randomHex(t, 8)
	template := "kiwi_tu_ccf_tmpl_" + suffix
	prefix := "kiwi_tu_ccf_" + suffix + "_"
	baseDB := "kiwi_tu_ccf_base_" + suffix
	itExec(t, admin, `CREATE DATABASE `+pgx.Identifier{baseDB}.Sanitize())
	t.Cleanup(func() {
		cctx := context.Background()
		_, _ = admin.Exec(cctx, `DROP DATABASE IF EXISTS `+pgx.Identifier{baseDB}.Sanitize()+` WITH (FORCE)`)
		_, _ = admin.Exec(cctx, `DROP DATABASE IF EXISTS `+pgx.Identifier{template}.Sanitize()+` WITH (FORCE)`)
	})
	EnsureTemplate(t, TemplateSpec{BaseDSN: base, Name: template, Migrate: itMigrateProbe}, prefix)
	baseDSN, err := dsnWithDatabase(base, baseDB)
	if err != nil {
		t.Fatalf("base dsn: %v", err)
	}

	var (
		sub       *recordingTB
		cloneName string
	)
	t.Run("cleanup after base is gone", func(t *testing.T) {
		sub = &recordingTB{TB: t}
		cloneDSN := CloneDatabase(sub, baseDSN, template, prefix)
		cloneName = itDatabaseName(t, cloneDSN)
		if n := itDatabaseCount(t, admin, cloneName); n != 1 {
			t.Fatalf("clone %s was not created", cloneName)
		}
		// Runs BEFORE the clone cleanup (LIFO), so the clone teardown can no
		// longer connect to the base database.
		sub.Cleanup(func() {
			_, _ = admin.Exec(context.Background(), `DROP DATABASE IF EXISTS `+pgx.Identifier{baseDB}.Sanitize()+` WITH (FORCE)`)
		})
	})
	logged := strings.Join(sub.logged(), "\n")
	if !strings.Contains(logged, "drop database "+cloneName+": connect") {
		t.Fatalf("cleanup logs = %v, want the base connect failure for %s", sub.logged(), cloneName)
	}
	if n := itDatabaseCount(t, admin, cloneName); n != 1 {
		t.Fatalf("clone %s unexpectedly gone; the failed cleanup cannot drop it", cloneName)
	}
	itExec(t, admin, `DROP DATABASE IF EXISTS `+pgx.Identifier{cloneName}.Sanitize()+` WITH (FORCE)`)
}
