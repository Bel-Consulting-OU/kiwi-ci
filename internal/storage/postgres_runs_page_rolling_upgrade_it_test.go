package storage

// Real-PostgreSQL rolling-upgrade regression (G5-B / R3-A). Gated on
// KIWI_TEST_POSTGRES_URL like every *_it_test.go here.
//
// The defect: migration 0033 added the materialized normalized identity
// columns and 0034 backfilled them, but a PRE-0034 replica still running
// during a rolling upgrade inserts a run through the old INSERT and leaves
// both columns NULL. The authorized collection predicate compared the columns
// by equality, so every arm evaluated to NULL for such a row and it was
// PERMANENTLY invisible to ListRunsPageAuthorized — even to a global read.
// The fix makes the page predicate NULL-tolerant (COALESCE with the shared
// IMMUTABLE derivation), and migration 0036 re-stamps legacy NULL rows. The
// tests below write exactly the old-binary row (payload only, NULL columns)
// and assert visibility, canonical-function parity and the re-backfill.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITInsertRunPayloadOnly is the pre-0034 write shape: only the columns that
// existed before migration 0033, so repo_identity_normalized and
// repo_full_name_normalized stay NULL.
func pgITInsertRunPayloadOnly(t *testing.T, st *PostgresStore, id, payload string) {
	t.Helper()
	if _, err := st.pool.Exec(context.Background(),
		`INSERT INTO runs (id, status, created_at, payload) VALUES ($1, 'success', $2, $3::jsonb)`,
		id, time.Now().UTC().Truncate(time.Microsecond), payload); err != nil {
		t.Fatalf("old-binary insert %s: %v", id, err)
	}
}

// pgITNormalizedColumnsNULL asserts both materialized columns are NULL, the
// exact condition a pre-0034 writer leaves behind.
func pgITNormalizedColumnsNULL(t *testing.T, st *PostgresStore, id string) {
	t.Helper()
	var identityNull, fullNull bool
	if err := st.pool.QueryRow(context.Background(),
		`SELECT repo_identity_normalized IS NULL, repo_full_name_normalized IS NULL FROM runs WHERE id=$1`,
		id).Scan(&identityNull, &fullNull); err != nil {
		t.Fatalf("read normalized columns %s: %v", id, err)
	}
	if !identityNull || !fullNull {
		t.Fatalf("run %s normalized columns not NULL (identityNull=%v fullNull=%v)", id, identityNull, fullNull)
	}
}

// TestPostgresIntegrationRunsPageAuthorizedRollingUpgradeNULLColumns is the
// G5-B regression.
func TestPostgresIntegrationRunsPageAuthorizedRollingUpgradeNULLColumns(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	const (
		canonicalRepo = "github.com/o/upgraded"
		bareRepo      = "acme/legacy"
	)
	canonicalRun := fmt.Sprintf("%032x", 1)
	bareRun := fmt.Sprintf("%032x", 2)
	pgITInsertRunPayloadOnly(t, st, canonicalRun,
		`{"policy_repo_id":"`+canonicalRepo+`","repo_full_name":"o/upgraded"}`)
	pgITInsertRunPayloadOnly(t, st, bareRun,
		`{"repo_id":"`+bareRepo+`","repo_full_name":"acme/legacy"}`)
	pgITNormalizedColumnsNULL(t, st, canonicalRun)
	pgITNormalizedColumnsNULL(t, st, bareRun)

	// Canonical-function parity: the effective expression the predicate reads
	// is byte-identical to the shared IMMUTABLE derivation on a NULL row.
	for _, id := range []string{canonicalRun, bareRun} {
		var ok bool
		if err := st.pool.QueryRow(ctx,
			`SELECT COALESCE(repo_identity_normalized, `+normalizedRunRepoIdentityFunctionName+`(payload,'repo'))
			      = `+normalizedRunRepoIdentityFunctionName+`(payload,'repo')
			  FROM runs WHERE id=$1`, id).Scan(&ok); err != nil {
			t.Fatalf("effective identity parity %s: %v", id, err)
		}
		if !ok {
			t.Fatalf("run %s effective identity != shared function derivation", id)
		}
	}
	// And the derivation equals the Go materialized pair (the predicate's
	// memory half reads RepoIDForRun).
	var dbIdentity, dbFull string
	if err := st.pool.QueryRow(ctx,
		`SELECT COALESCE(repo_identity_normalized, `+normalizedRunRepoIdentityFunctionName+`(payload,'repo')),
		        COALESCE(repo_full_name_normalized, `+normalizedRunRepoFullNameFunctionName+`(payload,'repo'))
		 FROM runs WHERE id=$1`, canonicalRun).Scan(&dbIdentity, &dbFull); err != nil {
		t.Fatalf("read effective columns: %v", err)
	}
	wantIdentity, wantFull := normalizedRepoColumns(canonicalRepo)
	if dbIdentity != wantIdentity || dbFull != wantFull {
		t.Fatalf("effective columns = (%q,%q), want (%q,%q)", dbIdentity, dbFull, wantIdentity, wantFull)
	}

	// The canonical grant authorizes the NULL-column canonical run (the
	// pre-fix page returned nothing), and the bare grant its bare run.
	canonicalPolicy := authzITPolicy(map[string]auth.RepositoryPermission{canonicalRepo: {Read: true}})
	page, err := st.ListRunsPageAuthorized(ctx, canonicalPolicy, time.Time{}, "", 10)
	if err != nil {
		t.Fatalf("canonical authorized page: %v", err)
	}
	if !containsID(runsPageIDs(page), canonicalRun) {
		t.Fatalf("canonical NULL-column run invisible: page = %v", runsPageIDs(page))
	}
	if containsID(runsPageIDs(page), bareRun) {
		t.Fatalf("canonical page leaked the bare run: %v", runsPageIDs(page))
	}

	barePolicy := authzITPolicy(map[string]auth.RepositoryPermission{bareRepo: {Read: true}})
	page, err = st.ListRunsPageAuthorized(ctx, barePolicy, time.Time{}, "", 10)
	if err != nil {
		t.Fatalf("bare authorized page: %v", err)
	}
	if !containsID(runsPageIDs(page), bareRun) {
		t.Fatalf("bare NULL-column run invisible: page = %v", runsPageIDs(page))
	}

	// Global read sees both NULL-column rows.
	globalPolicy := authzITPolicy(nil, auth.RoleRead)
	page, err = st.ListRunsPageAuthorized(ctx, globalPolicy, time.Time{}, "", 10)
	if err != nil {
		t.Fatalf("global authorized page: %v", err)
	}
	if !containsID(runsPageIDs(page), canonicalRun) || !containsID(runsPageIDs(page), bareRun) {
		t.Fatalf("global page missed a NULL-column run: %v", runsPageIDs(page))
	}

	// Memory parity: the same rows modeled in memory page identically.
	mem := runsPageMemoryStore(t, []model.Run{
		{ID: canonicalRun, Status: model.StatusSuccess, CreatedAt: time.Now().UTC(), PolicyRepoID: canonicalRepo},
		{ID: bareRun, Status: model.StatusSuccess, CreatedAt: time.Now().UTC(), PolicyRepoID: bareRepo},
	})
	memPage, err := mem.ListRunsPageAuthorized(ctx, globalPolicy, time.Time{}, "", 10)
	if err != nil {
		t.Fatalf("memory global page: %v", err)
	}
	if len(memPage.Runs) != 2 {
		t.Fatalf("memory global page = %d rows, want 2", len(memPage.Runs))
	}

	// The maintenance re-backfill (migration 0036's statement, itself the
	// idempotent 0034 backfill) materializes the NULL rows; they stay visible
	// and the columns now match the effective values.
	if _, err := st.pool.Exec(ctx, normalizedRunRepoBackfillSQL()); err != nil {
		t.Fatalf("maintenance re-backfill: %v", err)
	}
	var identity, full string
	if err := st.pool.QueryRow(ctx,
		`SELECT repo_identity_normalized, repo_full_name_normalized FROM runs WHERE id=$1`, canonicalRun).Scan(&identity, &full); err != nil {
		t.Fatalf("read backfilled columns: %v", err)
	}
	if identity != wantIdentity || full != wantFull {
		t.Fatalf("backfilled columns = (%q,%q), want (%q,%q)", identity, full, wantIdentity, wantFull)
	}
	page, err = st.ListRunsPageAuthorized(ctx, canonicalPolicy, time.Time{}, "", 10)
	if err != nil {
		t.Fatalf("canonical page after re-backfill: %v", err)
	}
	if !containsID(runsPageIDs(page), canonicalRun) {
		t.Fatalf("backfilled run invisible: %v", runsPageIDs(page))
	}
}
