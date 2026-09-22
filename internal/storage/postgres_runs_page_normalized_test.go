package storage

// Unit tests (no PostgreSQL required) for the materialized run repository
// identity: the migration-0033/0034 DDL is pinned to the Go SQL renderers so
// the write path, the backfill and the parity corpus can never drift, and the
// authorized page predicate is pinned to simple equality over the indexed
// normalized columns (no JSONB parsing inside the page predicate).

import (
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// TestNormalizedRunRepoSQLMatchesMigrations pins migration 0033 (the two
// metadata-only normalized columns) and migration 0034 (the IMMUTABLE
// canonicalization functions, the backfill and the two keyset indexes) to the
// Go renderers that the runs write path and the tests use. The bodies must be
// byte-identical: the write path stamps SQL-computed values, so a drift here
// would silently desynchronize a written row from a backfilled legacy row.
func TestNormalizedRunRepoSQLMatchesMigrations(t *testing.T) {
	all, err := migrations.All()
	if err != nil {
		t.Fatalf("migrations.All: %v", err)
	}
	byVersion := map[int]migrations.Migration{}
	for _, m := range all {
		byVersion[m.Version] = m
	}
	m33, ok := byVersion[33]
	if !ok || m33.Name != "0033_normalized_run_repo_identity_columns.sql" {
		t.Fatalf("migration 0033 missing or misnamed: %+v", m33)
	}
	if len(m33.Statements) != 2 {
		t.Fatalf("0033 statements = %d, want the 2 metadata-only ADD COLUMNs", len(m33.Statements))
	}
	for _, want := range []string{
		"ALTER TABLE runs ADD COLUMN IF NOT EXISTS " + normalizedRunRepoIdentityColumn + " TEXT",
		"ALTER TABLE runs ADD COLUMN IF NOT EXISTS " + normalizedRunRepoFullNameColumn + " TEXT",
	} {
		found := false
		for _, s := range m33.Statements {
			if strings.Contains(s, want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("0033 %q missing", want)
		}
		for _, s := range m33.Statements {
			if strings.Contains(s, "CREATE INDEX") || strings.Contains(s, "CREATE OR REPLACE FUNCTION") || strings.Contains(s, "UPDATE runs") {
				t.Fatalf("0033 must stay metadata-only, has %q", s)
			}
		}
	}

	m34, ok := byVersion[34]
	if !ok || m34.Name != "0034_normalized_run_repo_identity_backfill_index.sql" {
		t.Fatalf("migration 0034 missing or misnamed: %+v", m34)
	}
	if len(m34.Statements) != 6 {
		t.Fatalf("0034 statements = %d, want 3 functions + backfill + 2 indexes", len(m34.Statements))
	}
	raw, err := migrations.FS.ReadFile(m34.Name)
	if err != nil {
		t.Fatalf("read 0034: %v", err)
	}
	sql := string(raw)
	for name, body := range map[string]string{
		canonicalHostFunctionName:             canonicalHostFunctionBody(),
		normalizedRunRepoIdentityFunctionName: normalizedRunRepoIdentityFunctionBody(),
		normalizedRunRepoFullNameFunctionName: normalizedRunRepoFullNameFunctionBody(),
	} {
		if want := "AS $$SELECT " + body + "$$"; !strings.Contains(sql, want) {
			t.Fatalf("0034 function %s body drifted from the Go renderer (want %s)", name, want)
		}
	}
	if want := normalizedRunRepoBackfillSQL() + ";"; !strings.Contains(sql, want) {
		t.Fatalf("0034 backfill drifted from normalizedRunRepoBackfillSQL (%s)", want)
	}
	for _, want := range []string{
		normalizedRunRepoIdentityKeysetIndexDDL() + ";",
		normalizedRunRepoFullNameKeysetIndexDDL() + ";",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("0034 index definition missing %q", want)
		}
	}
	if !strings.Contains(sql, "CREATE INDEX IF NOT EXISTS runs_repo_identity_normalized_keyset_idx") ||
		!strings.Contains(sql, "CREATE INDEX IF NOT EXISTS runs_repo_full_name_normalized_keyset_idx") {
		t.Fatal("0034 does not create both normalized keyset indexes")
	}
}

// TestAuthorizedRunsPageSQLUsesNormalizedColumns pins that the shipped
// authorized page predicate reads the materialized columns by equality and
// contains NO JSONB identity parsing — the R1-B defect (SUBSTRING / STRPOS /
// CASE / LOWER / REGEXP_REPLACE inside the page predicate forced a long walk
// of the created-at index for a sparse tenant).
func TestAuthorizedRunsPageSQLUsesNormalizedColumns(t *testing.T) {
	cases := []struct {
		name   string
		policy RunAuthzPolicy
	}{
		{"simplified canonical read", authzPolicyFor(map[string]auth.RepositoryPermission{"github.com/o/repo-a": {Read: true}})},
		{"bare alias", authzPolicyFor(map[string]auth.RepositoryPermission{"o/repo-a": {Read: true}})},
		{"global read", authzPolicyFor(nil, auth.RoleRead)},
		{"global read with deny", authzPolicyFor(map[string]auth.RepositoryPermission{"github.com/o/repo-b": {Read: false}}, auth.RoleRead)},
		{"conflict", authzPolicyFor(map[string]auth.RepositoryPermission{
			"github.com/o/repo-b": {Read: true},
			"GitHub.com/o/repo-b": {Read: true, Run: true},
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			query, _ := authorizedRunsPageSQL(tc.policy, time.Time{}, "", 25)
			// runCols legitimately selects the payload column; only the
			// predicate must be free of JSONB identity parsing.
			predicate := query
			if i := strings.Index(predicate, " FROM runs WHERE "); i >= 0 {
				predicate = predicate[i+len(" FROM runs WHERE "):]
			}
			for _, forbidden := range []string{"payload", "SUBSTRING", "STRPOS", "REGEXP_REPLACE", "LOWER(", "canonicalHostSQL"} {
				if strings.Contains(predicate, forbidden) {
					t.Fatalf("authorized page predicate still parses identity (%q):\n%s", forbidden, predicate)
				}
			}
			if tc.policy.IsUnrestricted() {
				if !strings.Contains(predicate, "TRUE") {
					t.Fatalf("unrestricted predicate is not TRUE:\n%s", predicate)
				}
				return
			}
			if !strings.Contains(query, normalizedRunRepoIdentityColumn) {
				t.Fatalf("authorized page query does not read the normalized identity column:\n%s", query)
			}
		})
	}
}

// TestNormalizedRepoColumnsMirrorPositionalRule pins the Go mirror of the SQL
// normalized-column functions: the canonical "host/full" identity for a
// canonical candidate (host canonicalized), ” for a bare one, and the full
// name as the remainder/whole.
func TestNormalizedRepoColumnsMirrorPositionalRule(t *testing.T) {
	cases := []struct {
		repoID    string
		wantIdent string
		wantFull  string
	}{
		{"github.com/o/repo", "github.com/o/repo", "o/repo"},
		{"GitHub.com:443/o/repo", "github.com/o/repo", "o/repo"},
		{"github.com./o/repo", "github.com/o/repo", "o/repo"},
		{"gitlab.com/group/sub/repo", "gitlab.com/group/sub/repo", "group/sub/repo"},
		{"[::1]:443/o/repo", "::1/o/repo", "o/repo"},
		{"[::1:443]/o/repo", "::1:443/o/repo", "o/repo"},
		{"::1:443/o/repo", "::1:443/o/repo", "o/repo"},
		{"2001:db8::22/o/repo", "2001:db8::22/o/repo", "o/repo"},
		{"o/repo", "", "o/repo"},
		{"", "", ""},
	}
	for _, tc := range cases {
		ident, full := normalizedRepoColumns(tc.repoID)
		if ident != tc.wantIdent || full != tc.wantFull {
			t.Errorf("normalizedRepoColumns(%q) = (%q, %q), want (%q, %q)", tc.repoID, ident, full, tc.wantIdent, tc.wantFull)
		}
	}
}

// TestNormalizedRunRepoWriteFragments pins the write-path fragments the runs
// INSERT/UPDATE statements splice in, so the maintained columns always derive
// from the same functions the migration backfills with.
func TestNormalizedRunRepoWriteFragments(t *testing.T) {
	if got, want := normalizedRunRepoIdentitySQL("$6"), normalizedRunRepoIdentityFunctionName+"($6, 'repo')"; got != want {
		t.Fatalf("identity write fragment = %q, want %q", got, want)
	}
	if got, want := normalizedRunRepoFullNameSQL("$6"), normalizedRunRepoFullNameFunctionName+"($6, 'repo')"; got != want {
		t.Fatalf("full-name write fragment = %q, want %q", got, want)
	}
}
