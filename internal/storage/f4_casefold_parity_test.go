package storage

// F4-A parity: repository PATH case is folded onto ONE canonical form in the
// Go identity and in the SQL kiwi_canonical_repo_id / kiwi_normalize_* the
// materialized columns use, so a mixed-case clone URL can never bypass a
// lowercase deny or repository policy. The unit test pins the Go mirror; the
// PostgreSQL integration test executes the SHIPPED SQL against a mixed-case
// corpus and requires byte equality plus the same authorization decision.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestMixedCasePathFoldGoMirror pins the Go normalized-column derivation on
// mixed-case paths: the host is canonicalized and the full name folded, for
// both stored canonical IDs and URL-derived identities.
func TestMixedCasePathFoldGoMirror(t *testing.T) {
	cases := []struct {
		repoID    string
		wantIdent string
		wantFull  string
	}{
		{"github.com/Acme/Backend", "github.com/acme/backend", "acme/backend"},
		{"GitHub.com/Acme/Backend", "github.com/acme/backend", "acme/backend"},
		{"github.com/ACME/BACKEND", "github.com/acme/backend", "acme/backend"},
		{"gitlab.com/Group/Sub/Repo", "gitlab.com/group/sub/repo", "group/sub/repo"},
		{"Acme/Backend", "", "acme/backend"},
		{"github.com/acme/backend", "github.com/acme/backend", "acme/backend"},
	}
	for _, tc := range cases {
		ident, full := normalizedRepoColumns(tc.repoID)
		if ident != tc.wantIdent || full != tc.wantFull {
			t.Errorf("normalizedRepoColumns(%q) = (%q,%q), want (%q,%q)", tc.repoID, ident, full, tc.wantIdent, tc.wantFull)
		}
	}

	// A stored mixed-case canonical ID: RepoIDForRun keeps the stored value
	// verbatim (the documented storage contract), but the NORMALIZED identity
	// folds, so policy/RBAC/SQL all see one form and the explicit lowercase
	// deny matches.
	run := model.Run{RepoID: "github.com/Acme/Backend", RepoFullName: "Acme/Backend"}
	if got := RepoIDForRun(run); got != "github.com/Acme/Backend" {
		t.Fatalf("RepoIDForRun(stored) = %q, want the stored value verbatim", got)
	}
	if ident, full := normalizedRepoColumns(RepoIDForRun(run)); ident != "github.com/acme/backend" || full != "acme/backend" {
		t.Fatalf("normalized stored mixed-case identity = (%q,%q), want (github.com/acme/backend, acme/backend)", ident, full)
	}

	// An explicit lowercase deny matches every path-case variant, so the run
	// is denied rather than falling through to the global read role.
	deny := RunAuthzPolicyForPrincipal(&auth.Principal{
		Roles:        []auth.Role{auth.RoleRead},
		Repositories: map[string]auth.RepositoryPermission{"github.com/acme/backend": {Read: false}},
	})
	for _, repo := range []string{"github.com/Acme/Backend", "GitHub.com/ACME/BACKEND"} {
		if deny.Allows(repo) {
			t.Fatalf("path-case variant %q bypassed the explicit lowercase deny", repo)
		}
	}

	// Tagged r1:/a1: payloads are case-significant and are never folded.
	tagged := string(auth.RepoAliasPrefix) + "QUJD"
	if _, full := normalizedRepoColumns(tagged); full != tagged {
		t.Fatalf("normalizedRepoColumns(%q) folded a tagged payload to %q", tagged, full)
	}
}

// TestPostgresIntegrationMixedCasePathFoldParity executes the shipped SQL
// identity functions against a mixed-case corpus and requires the materialized
// columns, kiwi_canonical_repo_id and the authorized page to agree with Go.
func TestPostgresIntegrationMixedCasePathFoldParity(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Microsecond)

	mixed := []string{
		"github.com/Acme/Backend",
		"GitHub.com/Acme/Backend",
		"github.com/ACME/BACKEND",
		"gitlab.com/Group/Sub/Repo",
	}
	runs := make([]model.Run, 0, len(mixed)+1)
	for i, id := range mixed {
		runs = append(runs, model.Run{
			ID:           fmt.Sprintf("%032x", i+1),
			Status:       model.StatusSuccess,
			CreatedAt:    base.Add(time.Duration(i) * time.Second),
			PolicyRepoID: id,
		})
	}
	// Legacy URL-only mixed-case PATH row (no stored ID): exercises the
	// kiwi_canonical_repo_id clone-URL + repo_full_name derivation and fold.
	legacy := model.Run{
		ID:           fmt.Sprintf("%032x", len(mixed)+1),
		Status:       model.StatusSuccess,
		CreatedAt:    base.Add(time.Duration(len(mixed)) * time.Second),
		Repo:         "https://github.com/Acme/Backend.git",
		RepoFullName: "Acme/Backend",
	}
	runs = append(runs, legacy)
	authzITSeed(t, st, runs)

	for _, run := range runs {
		var dbIdent, dbFull string
		if err := st.pool.QueryRow(ctx, `SELECT `+normalizedRunRepoIdentityColumn+`, `+normalizedRunRepoFullNameColumn+` FROM runs WHERE id=$1`, run.ID).Scan(&dbIdent, &dbFull); err != nil {
			t.Fatalf("read normalized columns for %s: %v", run.ID, err)
		}
		wantIdent, wantFull := normalizedRepoColumns(RepoIDForRun(run))
		if dbIdent != wantIdent || dbFull != wantFull {
			t.Errorf("run %s: SQL normalized columns = (%q,%q), Go = (%q,%q) [policy_repo_id=%q repo=%q full=%q]",
				run.ID, dbIdent, dbFull, wantIdent, wantFull, run.PolicyRepoID, run.Repo, run.RepoFullName)
		}
	}

	// kiwi_canonical_repo_id on the legacy mixed-case row must equal the Go
	// canonical derivation of the same URL + full name.
	var sqlID, goID string
	if err := st.pool.QueryRow(ctx, `SELECT `+canonicalRepoIDFunctionName+`(payload, 'repo') FROM runs WHERE id=$1`, legacy.ID).Scan(&sqlID); err != nil {
		t.Fatalf("kiwi_canonical_repo_id: %v", err)
	}
	goID = RepoIDForRun(legacy)
	if sqlID != goID || sqlID != "github.com/acme/backend" {
		t.Fatalf("kiwi_canonical_repo_id(legacy) = %q, Go = %q, want github.com/acme/backend", sqlID, goID)
	}

	// Authorization parity: an explicit lowercase deny defeats the global read
	// role for every path-case variant; a lowercase grant admits them.
	mem := runsPageMemoryStore(t, runs)

	grantMixedGithub := len(mixed) - 1 // the last mixed entry is the gitlab repo
	grant := authzITPolicy(map[string]auth.RepositoryPermission{"github.com/acme/backend": {Read: true}})
	page, err := st.ListRunsPageAuthorized(ctx, grant, time.Time{}, "", 100)
	if err != nil {
		t.Fatalf("grant page: %v", err)
	}
	visible := map[string]bool{}
	for _, r := range page.Runs {
		visible[r.ID] = true
	}
	for i := 0; i < grantMixedGithub; i++ {
		if !visible[runs[i].ID] {
			t.Errorf("mixed-case run %s not visible under the folded lowercase grant", runs[i].ID)
		}
	}
	if !visible[legacy.ID] {
		t.Errorf("legacy mixed-case URL run not visible under the folded lowercase grant")
	}

	deny := authzITPolicy(map[string]auth.RepositoryPermission{"github.com/acme/backend": {Read: false}}, auth.RoleRead)
	pgPage, err := st.ListRunsPageAuthorized(ctx, deny, time.Time{}, "", 100)
	if err != nil {
		t.Fatalf("deny page: %v", err)
	}
	memPage, err := mem.ListRunsPageAuthorized(ctx, deny, time.Time{}, "", 100)
	if err != nil {
		t.Fatalf("deny memory page: %v", err)
	}
	if ids := runsPageIDs(pgPage); isAnyID(ids, append(runs[:grantMixedGithub:grantMixedGithub], legacy)) {
		t.Fatalf("explicit lowercase deny did not exclude mixed-case github runs: %v", ids)
	}
	if fmt.Sprint(runsPageIDs(pgPage)) != fmt.Sprint(runsPageIDs(memPage)) {
		t.Fatalf("SQL page %v != memory page %v", runsPageIDs(pgPage), runsPageIDs(memPage))
	}
}

// isAnyID reports whether any id in runs is contained in ids.
func isAnyID(ids []string, runs []model.Run) bool {
	for _, r := range runs {
		for _, id := range ids {
			if id == r.ID {
				return true
			}
		}
	}
	return false
}

// TestPostgresIntegrationFold0035UpgradeRefoldsRows proves the upgrade path:
// on a schema already at 0034, a row whose materialized normalized columns
// were computed with the unfolded derivation (and whose stored identity is
// mixed-case) is re-stamped onto the folded form by migration 0035.
func TestPostgresIntegrationFold0035UpgradeRefoldsRows(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	pgITApplyThrough(t, st, 34)
	ctx := context.Background()
	id := fmt.Sprintf("%032x", 1)
	payload := `{"id":"` + id + `","status":"success","created_at":"2026-01-01T00:00:00Z","repo_id":"github.com/Acme/Backend","repo_full_name":"Acme/Backend"}`
	// Simulate the pre-0035 materialization: stale unfolded normalized columns.
	if _, err := st.pool.Exec(ctx, `INSERT INTO runs (id, status, started_at, finished_at, created_at, payload, `+
		normalizedRunRepoIdentityColumn+`, `+normalizedRunRepoFullNameColumn+`) VALUES ($1,'success',now(),now(),now(),$2,'github.com/Acme/Backend','Acme/Backend')`,
		id, payload); err != nil {
		t.Fatalf("seed stale row: %v", err)
	}

	// Apply migration 0035 (the next embedded migration) on top.
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("apply 0035: %v", err)
	}

	var ident, full string
	if err := st.pool.QueryRow(ctx, `SELECT `+normalizedRunRepoIdentityColumn+`, `+normalizedRunRepoFullNameColumn+` FROM runs WHERE id=$1`, id).Scan(&ident, &full); err != nil {
		t.Fatalf("read refolded columns: %v", err)
	}
	if ident != "github.com/acme/backend" || full != "acme/backend" {
		t.Fatalf("0035 did not re-fold stale row: (%q,%q), want (github.com/acme/backend, acme/backend)", ident, full)
	}

	// The re-created identity index is present and the function is folded.
	var def string
	if err := st.pool.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname='runs_repo_identity_idx'`).Scan(&def); err != nil {
		t.Fatalf("runs_repo_identity_idx missing after 0035: %v", err)
	}
	if !strings.Contains(def, canonicalRepoIDFunctionName) {
		t.Fatalf("runs_repo_identity_idx not rebuilt on the canonical function: %s", def)
	}
}
