package storage

// Real-PostgreSQL integration tests for the repository-identity repair
// (R2-B). Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go here: a
// fresh throwaway schema is migrated and seeded with the legacy identity
// shapes, then the repair runs in REPORT mode (no writes) and APPLY mode
// (rewrites + quarantine) and is re-run to prove idempotency.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
)

// pgITIdentityPayload renders a runs/jobs payload carrying only the identity
// fields the repair reads.
func pgITIdentityPayload(t *testing.T, repoID, policyID, url, full string) string {
	t.Helper()
	payload := map[string]any{}
	if repoID != "" {
		payload["repo_id"] = repoID
	}
	if policyID != "" {
		payload["policy_repo_id"] = policyID
	}
	if url != "" {
		payload["repo"] = url
		payload["repo_url"] = url
	}
	if full != "" {
		payload["repo_full_name"] = full
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return string(raw)
}

func pgITInsertRunIdentity(t *testing.T, st *PostgresStore, runID, repoID, policyID, url, full string) {
	t.Helper()
	_, err := st.pool.Exec(context.Background(),
		`INSERT INTO runs (id, status, created_at, payload) VALUES ($1, 'queued', now(), $2::jsonb)`,
		runID, pgITIdentityPayload(t, repoID, policyID, url, full))
	if err != nil {
		t.Fatalf("insert run %s: %v", runID, err)
	}
}

func pgITInsertJobIdentity(t *testing.T, st *PostgresStore, runID, jobID, repoID, policyID, url, full string) {
	t.Helper()
	_, err := st.pool.Exec(context.Background(),
		`INSERT INTO jobs (id, run_id, key, status, created_at, payload) VALUES ($1, $2, 'build', 'queued', now(), $3::jsonb)`,
		jobID, runID, pgITIdentityPayload(t, repoID, policyID, url, full))
	if err != nil {
		t.Fatalf("insert job %s: %v", jobID, err)
	}
}

func pgITRunIdentity(t *testing.T, st *PostgresStore, runID string) (repoID, policyID string) {
	t.Helper()
	if err := st.pool.QueryRow(context.Background(),
		`SELECT COALESCE(payload->>'repo_id',''), COALESCE(payload->>'policy_repo_id','') FROM runs WHERE id=$1`,
		runID).Scan(&repoID, &policyID); err != nil {
		t.Fatalf("read run identity %s: %v", runID, err)
	}
	return repoID, policyID
}

func pgITJobIdentity(t *testing.T, st *PostgresStore, jobID string) (repoID, policyID string) {
	t.Helper()
	if err := st.pool.QueryRow(context.Background(),
		`SELECT COALESCE(payload->>'repo_id',''), COALESCE(payload->>'policy_repo_id','') FROM jobs WHERE id=$1`,
		jobID).Scan(&repoID, &policyID); err != nil {
		t.Fatalf("read job identity %s: %v", jobID, err)
	}
	return repoID, policyID
}

// TestPostgresIntegrationRepoIdentityRepair proves the migration/repair pass:
// a URL-bearing canonical row is left alone; a legacy URL-less nested row and
// its job are rewritten to the explicit a1: alias; an unprovable nested row is
// quarantined to the reserved host and recorded; a fork's base policy_repo_id
// is untouched; and a second apply pass changes nothing.
func TestPostgresIntegrationRepoIdentityRepair(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	canonicalRun := pgITNewID(t)
	legacyNestedRun := pgITNewID(t)
	legacyNestedJob := pgITNewID(t)
	unprovableRun := pgITNewID(t)
	forkRun := pgITNewID(t)
	plainAliasRun := pgITNewID(t)

	pgITInsertRunIdentity(t, st, canonicalRun,
		"gitlab.company.com/group/sub/project", "gitlab.company.com/group/sub/project",
		"https://gitlab.company.com/group/sub/project.git", "group/sub/project")
	pgITInsertRunIdentity(t, st, legacyNestedRun,
		"group/sub/project", "group/sub/project", "", "group/sub/project")
	pgITInsertJobIdentity(t, st, legacyNestedRun, legacyNestedJob,
		"group/sub/project", "group/sub/project", "", "group/sub/project")
	pgITInsertRunIdentity(t, st, unprovableRun, "group/sub/project", "group/sub/project", "", "")
	pgITInsertRunIdentity(t, st, forkRun,
		"github.com/acme/head", "gitlab.example/acme/base",
		"https://github.com/acme/head.git", "acme/head")
	pgITInsertRunIdentity(t, st, plainAliasRun, "acme/backend", "acme/backend", "", "acme/backend")

	a1Nested := auth.RepoAlias{FullName: "group/sub/project"}.Serialized()

	// REPORT mode: the plan is complete and nothing is written.
	report, err := st.RepairRepoIdentities(ctx, RepoIdentityRepairReport)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if report.Scanned != 6 || report.Rewritten != 2 || report.Quarantined != 1 || report.Unchanged != 3 {
		t.Fatalf("report = scanned=%d rewritten=%d quarantined=%d unchanged=%d, want 6/2/1/3",
			report.Scanned, report.Rewritten, report.Quarantined, report.Unchanged)
	}
	if got, _ := pgITRunIdentity(t, st, legacyNestedRun); got != "group/sub/project" {
		t.Fatalf("report mode wrote the legacy row: %q", got)
	}

	// APPLY mode: rewrites and quarantines.
	applied, err := st.RepairRepoIdentities(ctx, RepoIdentityRepairApply)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if applied.Rewritten != 2 || applied.Quarantined != 1 || applied.Unchanged != 3 {
		t.Fatalf("apply = rewritten=%d quarantined=%d unchanged=%d, want 2/1/3",
			applied.Rewritten, applied.Quarantined, applied.Unchanged)
	}
	// Canonical URL row untouched.
	if got, gotPolicy := pgITRunIdentity(t, st, canonicalRun); got != "gitlab.company.com/group/sub/project" || gotPolicy != got {
		t.Fatalf("canonical row = %q/%q, want unchanged", got, gotPolicy)
	}
	// Legacy URL-less nested run and job rewritten to the explicit alias.
	gotRepo, gotPolicy := pgITRunIdentity(t, st, legacyNestedRun)
	if gotRepo != a1Nested || gotPolicy != a1Nested {
		t.Fatalf("legacy nested run = %q/%q, want %q", gotRepo, gotPolicy, a1Nested)
	}
	jobRepo, jobPolicy := pgITJobIdentity(t, st, legacyNestedJob)
	if jobRepo != a1Nested || jobPolicy != a1Nested {
		t.Fatalf("legacy nested job = %q/%q, want %q", jobRepo, jobPolicy, a1Nested)
	}
	// Unprovable row quarantined to the reserved canonical identity.
	wantQuarantine := "quarantine.invalid/quarantined/" + base64.RawURLEncoding.EncodeToString([]byte("group/sub/project"))
	quarRepo, quarPolicy := pgITRunIdentity(t, st, unprovableRun)
	if quarRepo != wantQuarantine || quarPolicy != wantQuarantine {
		t.Fatalf("quarantined row = %q/%q, want %q", quarRepo, quarPolicy, wantQuarantine)
	}
	var quarantined int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM repo_identity_quarantine WHERE kind='run' AND record_id=$1`, unprovableRun).Scan(&quarantined); err != nil {
		t.Fatalf("read quarantine log: %v", err)
	}
	if quarantined != 1 {
		t.Fatalf("quarantine log rows = %d, want 1", quarantined)
	}
	// A fork's BASE policy_repo_id is not touched.
	forkRepo, forkPolicy := pgITRunIdentity(t, st, forkRun)
	if forkRepo != "github.com/acme/head" || forkPolicy != "gitlab.example/acme/base" {
		t.Fatalf("fork row = %q/%q, want repo kept and base policy kept", forkRepo, forkPolicy)
	}
	// A plain alias is already explicit.
	if got, _ := pgITRunIdentity(t, st, plainAliasRun); got != "acme/backend" {
		t.Fatalf("plain alias row = %q, want acme/backend", got)
	}

	// Idempotent: a second apply changes nothing.
	second, err := st.RepairRepoIdentities(ctx, RepoIdentityRepairApply)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if second.Rewritten != 0 || second.Quarantined != 0 || second.Unchanged != 6 {
		t.Fatalf("second apply = rewritten=%d quarantined=%d unchanged=%d, want 0/0/6",
			second.Rewritten, second.Quarantined, second.Unchanged)
	}
}
