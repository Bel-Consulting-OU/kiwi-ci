package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
)

// This file provides the PostgreSQL integration harness a reusable, migrated
// TEMPLATE database. The heavyweight cost of a real-PostgreSQL integration
// test is building the schema: applying the full migration set (hundreds of
// relations) once per test dominated the suite (storage alone: ~47 min for
// ~220 tests). PostgreSQL cannot clone a schema, but it can clone a whole
// database with `CREATE DATABASE ... TEMPLATE`, which copies the on-disk
// catalog in tens of milliseconds.
//
// The strategy is therefore:
//
//  1. Before the first test that needs a database, build ONE template
//     database on the server and run the real migration path against it.
//     The template is recreated from scratch on every process start, so a
//     crashed run can never leave a stale schema behind.
//  2. Every test gets its OWN database cloned from the template. A cloned
//     database is a full, byte-for-byte copy: each test's data is untouched
//     by any other test, parallel tests cannot observe each other, and the
//     schema still comes from the production migrations (applied once).
//  3. Cleanup DROP DATABASE ... WITH (FORCE) is registered through
//     testing.TB.Cleanup, so it runs on failure too and forcibly terminates
//     any pool a failing test left open.
//
// Coverage is preserved rather than traded away: the migration statements run
// in the test process (inside the template build), so -coverpkg instrumentation
// still counts them, and the owning package keeps dedicated tests that run the
// real migration path against a fresh, un-templated database.

// TemplateSpec describes a reusable migrated template database.
type TemplateSpec struct {
	// BaseDSN is any DSN on the target server; the template is created as a
	// sibling database on the same server.
	BaseDSN string
	// Name is the template database name. Callers needing several historical
	// schemas use one distinct name per schema.
	Name string
	// Migrate applies the real schema to the freshly created template
	// database named by the DSN it receives. It must close every connection
	// it opens before returning: PostgreSQL refuses to clone a template while
	// another session is connected to it.
	Migrate func(ctx context.Context, dsn string) error
}

var (
	pgTemplateMu   sync.Mutex
	pgTemplateOnce = map[string]*sync.Once{}
	pgTemplateErr  = map[string]error{}

	pgCleanupMu   sync.Mutex
	pgCleanupOnce = map[string]*sync.Once{}
)

// EnsureTemplate builds spec exactly once per process and fails the calling
// test if the template could not be created. Concurrent callers for the same
// spec block until the first build finishes.
func EnsureTemplate(t testing.TB, spec TemplateSpec, clonePrefix string) {
	t.Helper()
	key := spec.BaseDSN + "\x00" + spec.Name
	pgTemplateMu.Lock()
	once, ok := pgTemplateOnce[key]
	if !ok {
		once = &sync.Once{}
		pgTemplateOnce[key] = once
	}
	pgTemplateMu.Unlock()

	once.Do(func() {
		pgTemplateErr[key] = buildTemplate(spec, clonePrefix)
	})
	if err := pgTemplateErr[key]; err != nil {
		t.Fatalf("prepare template database %s: %v", spec.Name, err)
	}
}

// CloneDatabase creates a throwaway database from template on the server named
// by baseDSN, registers its teardown (which runs even when the test fails),
// and returns a DSN pointing at the clone. The clone's name is prefix plus
// random hex, so stale clones from a crashed run are recognisable.
func CloneDatabase(t testing.TB, baseDSN, template, prefix string) string {
	t.Helper()
	ctx := context.Background()
	dbName := prefix + randomHex(t, 12)
	admin, err := pgx.Connect(ctx, baseDSN)
	if err != nil {
		t.Fatalf("connect to base dsn for clone: %v", err)
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{dbName}.Sanitize()+` TEMPLATE `+pgx.Identifier{template}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("clone template %s into %s: %v", template, dbName, err)
	}
	if err := admin.Close(ctx); err != nil {
		t.Fatalf("close admin connection after clone: %v", err)
	}
	t.Cleanup(func() {
		cctx := context.Background()
		c, cerr := pgx.Connect(cctx, baseDSN)
		if cerr != nil {
			t.Logf("drop database %s: connect: %v", dbName, cerr)
			return
		}
		defer func() { _ = c.Close(cctx) }()
		// FORCE terminates any backend a failing test left behind before the
		// drop, so cleanup cannot itself fail on a leaked pool.
		if _, derr := c.Exec(cctx, `DROP DATABASE IF EXISTS `+pgx.Identifier{dbName}.Sanitize()+` WITH (FORCE)`); derr != nil {
			t.Logf("drop database %s: %v", dbName, derr)
		}
	})
	dsn, err := dsnWithDatabase(baseDSN, dbName)
	if err != nil {
		t.Fatalf("derive dsn for %s: %v", dbName, err)
	}
	return dsn
}

// randomHex returns n random lowercase hex characters.
func randomHex(t testing.TB, n int) string {
	t.Helper()
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random bytes: %v", err)
	}
	return hex.EncodeToString(b)[:n]
}

// dsnWithDatabase rewrites the database component of dsn. It edits the DSN
// text directly rather than mutating pgx.Config.Database, because
// pgx.ConnConfig.ConnString() returns the ORIGINAL string that ParseConfig
// cached and therefore silently ignores field mutations.
func dsnWithDatabase(dsn, database string) (string, error) {
	dsn = strings.TrimSpace(dsn)
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", fmt.Errorf("parse dsn url: %w", err)
		}
		u.Path = "/" + database
		return u.String(), nil
	}
	// libpq keyword=value form.
	fields := strings.Fields(dsn)
	out := make([]string, 0, len(fields)+1)
	replaced := false
	for _, f := range fields {
		key := f
		if i := strings.IndexByte(f, '='); i >= 0 {
			key = f[:i]
		}
		if strings.EqualFold(key, "dbname") || strings.EqualFold(key, "database") {
			out = append(out, "dbname="+quoteDSNValue(database))
			replaced = true
			continue
		}
		out = append(out, f)
	}
	if !replaced {
		out = append(out, "dbname="+quoteDSNValue(database))
	}
	return strings.Join(out, " "), nil
}

// quoteDSNValue quotes a keyword=value parameter value when it contains a
// character that would otherwise end the value or split the field.
func quoteDSNValue(v string) string {
	if v == "" || strings.ContainsAny(v, " '\\") {
		return "'" + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), "'", `\'`) + "'"
	}
	return v
}

func buildTemplate(spec TemplateSpec, clonePrefix string) error {
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, spec.BaseDSN)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = admin.Close(ctx) }()

	// Drop any stale template from a previous (possibly crashed) run, then any
	// per-test clones it left behind, so a rerun starts from a clean slate.
	if _, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS `+pgx.Identifier{spec.Name}.Sanitize()+` WITH (FORCE)`); err != nil {
		return fmt.Errorf("drop stale template: %w", err)
	}
	// Stale-clone cleanup runs at most once per prefix, on the first template
	// build (which always precedes the first clone). Later template builds —
	// e.g. a lazily built historical-schema template — must NOT scan for
	// stale clones, because a clone created by the currently running test is
	// live and must not be dropped.
	cleanupStaleClonesOnce(ctx, admin, clonePrefix, spec.Name)
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{spec.Name}.Sanitize()); err != nil {
		return fmt.Errorf("create template: %w", err)
	}

	tmplDSN, err := dsnWithDatabase(spec.BaseDSN, spec.Name)
	if err != nil {
		return err
	}
	if err := spec.Migrate(ctx, tmplDSN); err != nil {
		_, _ = admin.Exec(ctx, `DROP DATABASE IF EXISTS `+pgx.Identifier{spec.Name}.Sanitize()+` WITH (FORCE)`)
		return fmt.Errorf("migrate template: %w", err)
	}
	return nil
}

// cleanupStaleClonesOnce runs dropStaleClones on the first template build for
// clonePrefix only (see buildTemplate).
func cleanupStaleClonesOnce(ctx context.Context, admin *pgx.Conn, prefix, template string) {
	pgCleanupMu.Lock()
	once, ok := pgCleanupOnce[prefix]
	if !ok {
		once = &sync.Once{}
		pgCleanupOnce[prefix] = once
	}
	pgCleanupMu.Unlock()
	once.Do(func() { dropStaleClones(ctx, admin, prefix, template) })
}

// dropStaleClones removes per-test databases named prefix+12-hex that a
// previous crashed run left behind. It never touches the template itself or
// any database that does not match the exact generated shape, so it cannot
// delete an unrelated database that merely shares the prefix.
func dropStaleClones(ctx context.Context, admin *pgx.Conn, prefix, template string) {
	pattern := `^` + regexp.QuoteMeta(prefix) + `[0-9a-f]{12}$`
	re := regexp.MustCompile(pattern)
	rows, err := admin.Query(ctx, `SELECT datname FROM pg_database WHERE datname LIKE $1`, prefix+"%")
	if err != nil {
		return
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return
		}
		names = append(names, n)
	}
	rows.Close()
	for _, n := range names {
		if n == template || !re.MatchString(n) {
			continue
		}
		_, _ = admin.Exec(ctx, `DROP DATABASE IF EXISTS `+pgx.Identifier{n}.Sanitize()+` WITH (FORCE)`)
	}
}
