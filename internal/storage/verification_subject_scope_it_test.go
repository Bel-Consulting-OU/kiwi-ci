package storage_test

// Real-PostgreSQL proof of the P7 subject/scope source-of-truth contract:
// after any sequence of inserts and UPSERT upgrades, the normalized columns
// and the JSONB payload of every verification row agree. The write-all path
// derives both from one value in one statement (verifystore.subject_scope),
// so a successful write cannot leave them diverged. A forced out-of-band
// payload edit is then read back with the COLUMNS as authority.
//
// Named with Integration so the pg lane guard and `-run Integration` select
// it. Shared fixtures come from verification_store_it_test.go in this
// package.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/verifystore"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/verifyapi"
)

// verificationITScopeStore opens a store on its own throwaway clone and
// returns the clone DSN so a test can run raw SQL against the same database.
// The template is created by the standard verificationITStore path.
func verificationITScopeStore(t *testing.T) (*verifystore.PostgresStore, string) {
	t.Helper()
	// Creates the migrated template once per process.
	_ = verificationITStore(t)
	base := verificationITBaseDSN(t)
	clone := testutil.CloneDatabase(t, base, "kiwi_verif_tmpl", verificationITClonePrefix)
	st, err := verifystore.NewPostgres(context.Background(), clone)
	if err != nil {
		t.Fatalf("open verification store: %v", err)
	}
	key, err := verifyapi.NewHMACAcceptanceKey("it-scope-acceptance", []byte("it-scope-acceptance-secret-32bytes"))
	if err != nil {
		t.Fatalf("acceptance key: %v", err)
	}
	st.WithAcceptanceKey(key)
	t.Cleanup(st.Close)
	return st, clone
}

// verificationITScopedObligation builds an obligation under a full authority
// subject so every scope dimension is exercised.
func verificationITScopedObligation(t *testing.T) verifyapi.VerificationObligation {
	t.Helper()
	ob := verificationITObligation(t)
	ob.SubjectRef = &verifyapi.SubjectRef{
		AuthorityNamespace: "forge.example",
		TenantID:           "tenant-" + verificationITID(t),
		ProjectID:          "proj-1",
		RepositoryID:       "repo-1",
	}
	return ob
}

// verificationITObligationColumns is the raw column projection of one
// verification_obligations row.
type verificationITObligationColumns struct {
	Subject            string
	AuthorityNamespace string
	TenantID           string
	ProjectID          string
	RepositoryID       string
	Payload            []byte
}

// verificationITOutcomeColumns is the raw column projection of one
// verification_outcomes row.
type verificationITOutcomeColumns struct {
	GroupID            string
	CandidateID        string
	StartedAt          time.Time
	CompletedAt        time.Time
	AuthorityNamespace string
	TenantID           string
	ProjectID          string
	RepositoryID       string
	Claim              []byte
}

// readObligationColumns loads the normalized columns and the payload of one
// obligation row for the consistency assertions below.
func readObligationColumns(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id string) verificationITObligationColumns {
	t.Helper()
	var row verificationITObligationColumns
	err := pool.QueryRow(ctx, `
		SELECT subject, authority_namespace, tenant_id, project_id, repository_id, payload
		FROM verification_obligations WHERE obligation_id = $1`, id).
		Scan(&row.Subject, &row.AuthorityNamespace, &row.TenantID, &row.ProjectID, &row.RepositoryID, &row.Payload)
	if err != nil {
		t.Fatalf("read obligation columns: %v", err)
	}
	return row
}

// readOutcomeColumns loads the normalized index/scope columns and the claim
// payload of one outcome row.
func readOutcomeColumns(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id string) verificationITOutcomeColumns {
	t.Helper()
	var row verificationITOutcomeColumns
	err := pool.QueryRow(ctx, `
		SELECT group_id, candidate_id, started_at, completed_at,
		       authority_namespace, tenant_id, project_id, repository_id, claim
		FROM verification_outcomes WHERE verification_id = $1`, id).
		Scan(&row.GroupID, &row.CandidateID, &row.StartedAt, &row.CompletedAt,
			&row.AuthorityNamespace, &row.TenantID, &row.ProjectID, &row.RepositoryID, &row.Claim)
	if err != nil {
		t.Fatalf("read outcome columns: %v", err)
	}
	return row
}

// assertObligationRowConsistent pins the P7 invariant on one row: the
// normalized subject/scope columns and the JSONB payload cannot diverge
// after any successful write.
func assertObligationRowConsistent(t *testing.T, row verificationITObligationColumns) verifyapi.VerificationObligation {
	t.Helper()
	var payload verifyapi.VerificationObligation
	if err := json.Unmarshal(row.Payload, &payload); err != nil {
		t.Fatalf("decode obligation payload: %v", err)
	}
	sc := verifystore.SubjectScope{
		Subject:            row.Subject,
		AuthorityNamespace: row.AuthorityNamespace,
		TenantID:           row.TenantID,
		ProjectID:          row.ProjectID,
		RepositoryID:       row.RepositoryID,
	}
	if !verifystore.ScopeConsistent(payload, sc) {
		t.Fatalf("obligation payload and columns diverged: payload subject=%q ref=%v columns=%+v",
			payload.Subject, payload.SubjectReference(), sc)
	}
	return payload
}

// assertOutcomeRowConsistent pins the P7 invariant on one outcome row: the
// index columns are denormalized from the CLAIM payload and the scope
// columns from the obligation, so neither can drift from the payload.
func assertOutcomeRowConsistent(t *testing.T, row verificationITOutcomeColumns, ob verifyapi.VerificationObligation) verifyapi.VerificationOutcome {
	t.Helper()
	var claim verifyapi.VerificationOutcome
	if err := json.Unmarshal(row.Claim, &claim); err != nil {
		t.Fatalf("decode claim payload: %v", err)
	}
	idx := verifystore.ClaimIndex{
		GroupID:     row.GroupID,
		CandidateID: row.CandidateID,
		StartedAt:   row.StartedAt.UTC(),
		CompletedAt: row.CompletedAt.UTC(),
	}
	if !verifystore.ClaimIndexConsistent(claim, idx) {
		t.Fatalf("outcome index columns and claim payload diverged: claim resources=%+v window=%v-%v columns=%+v",
			claim.Resources, claim.StartedAt, claim.CompletedAt, idx)
	}
	wantScope := verifystore.ScopeOfObligation(ob)
	if row.AuthorityNamespace != wantScope.AuthorityNamespace ||
		row.TenantID != wantScope.TenantID ||
		row.ProjectID != wantScope.ProjectID ||
		row.RepositoryID != wantScope.RepositoryID {
		t.Fatalf("outcome scope columns %+v diverged from obligation scope %+v", row, wantScope)
	}
	return claim
}

// TestIntegrationVerificationSubjectScopeUpsertCannotDiverge is the P7
// headline: claim write, verified upgrade, and idempotent retries all leave
// payload and index/scope columns in lockstep on a real PostgreSQL UPSERT
// surface.
func TestIntegrationVerificationSubjectScopeUpsertCannotDiverge(t *testing.T) {
	st, dsn := verificationITScopeStore(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open raw pool: %v", err)
	}
	defer pool.Close()

	ob := verificationITScopedObligation(t)
	if err := st.SubmitObligation(ctx, ob); err != nil {
		t.Fatalf("SubmitObligation = %v", err)
	}
	// Idempotent resubmit is the insert-race UPSERT path.
	if err := st.SubmitObligation(ctx, ob); err != nil {
		t.Fatalf("idempotent SubmitObligation = %v", err)
	}
	obRow := readObligationColumns(t, ctx, pool, ob.ObligationID)
	assertObligationRowConsistent(t, obRow)

	v := verificationITOutcome(t, ob)
	v.Resources.CandidateID = "cand-a"
	if err := st.RecordOutcome(ctx, v); err != nil {
		t.Fatalf("RecordOutcome = %v", err)
	}
	outRow := readOutcomeColumns(t, ctx, pool, v.VerificationID)
	assertOutcomeRowConsistent(t, outRow, ob)

	// Verified upgrade (the DO UPDATE UPSERT path): the claim payload is
	// preserved and the columns follow it, even though the derived outcome
	// is a different record.
	vo := verificationITSeal(t, ob, v)
	if err := st.RecordVerifiedOutcome(ctx, vo); err != nil {
		t.Fatalf("RecordVerifiedOutcome = %v", err)
	}
	// Claim retry after verify is another no-op success and must not
	// disturb the row.
	if err := st.RecordOutcome(ctx, v); err != nil {
		t.Fatalf("claim retry after verify = %v", err)
	}
	outRow2 := readOutcomeColumns(t, ctx, pool, v.VerificationID)
	claim := assertOutcomeRowConsistent(t, outRow2, ob)
	if claim.VerificationID != v.VerificationID {
		t.Fatalf("claim identity = %q", claim.VerificationID)
	}
	if outRow2.GroupID != outRow.GroupID || outRow2.CandidateID != outRow.CandidateID {
		t.Fatalf("index identity changed across upgrade: %+v vs %+v", outRow2, outRow)
	}
	// The claim window (and therefore the index window) is stable across
	// the upgrade: the index follows the claim, not the derived outcome.
	if !outRow2.StartedAt.Equal(outRow.StartedAt) || !outRow2.CompletedAt.Equal(outRow.CompletedAt) {
		t.Fatalf("index window changed across upgrade: %v-%v vs %v-%v",
			outRow2.StartedAt, outRow2.CompletedAt, outRow.StartedAt, outRow.CompletedAt)
	}

	// A second obligation under a different tenant keeps its own columns.
	other := verificationITScopedObligation(t)
	other.SubjectRef = &verifyapi.SubjectRef{
		AuthorityNamespace: "forge.example",
		TenantID:           "tenant-other-" + verificationITID(t),
		ProjectID:          "proj-1",
		RepositoryID:       "repo-1",
	}
	if err := st.SubmitObligation(ctx, other); err != nil {
		t.Fatalf("SubmitObligation other = %v", err)
	}
	otherRow := readObligationColumns(t, ctx, pool, other.ObligationID)
	assertObligationRowConsistent(t, otherRow)
	if otherRow.TenantID == obRow.TenantID {
		t.Fatal("distinct tenants must keep distinct scope columns")
	}
}

// TestIntegrationVerificationSubjectScopeColumnsWinOverTamperedPayload
// forces a payload/column divergence with direct SQL and proves the read
// path treats the COLUMNS as authoritative (P7): GetObligation restores the
// subject from the columns, so a smuggled subject_ref in the JSONB cannot
// present a different authority subject than the row indexes.
func TestIntegrationVerificationSubjectScopeColumnsWinOverTamperedPayload(t *testing.T) {
	st, dsn := verificationITScopeStore(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open raw pool: %v", err)
	}
	defer pool.Close()

	ob := verificationITScopedObligation(t)
	if err := st.SubmitObligation(ctx, ob); err != nil {
		t.Fatalf("SubmitObligation = %v", err)
	}

	// Out-of-band edit: rewrite the payload's subject and subject_ref to
	// an attacker tenant while leaving the normalized columns alone.
	attacker := verifyapi.SubjectRef{
		AuthorityNamespace: "forge.example",
		TenantID:           "attacker-tenant",
	}
	tampered := ob
	tampered.Subject = "attacker-subject"
	tampered.SubjectRef = &attacker
	raw, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE verification_obligations SET payload = $2 WHERE obligation_id = $1`,
		ob.ObligationID, raw); err != nil {
		t.Fatalf("tamper payload: %v", err)
	}

	// The row is now inconsistent; the read path must restore from the
	// columns rather than trust the payload.
	row := readObligationColumns(t, ctx, pool, ob.ObligationID)
	if verifystore.ScopeConsistent(mustDecodeObligation(t, row.Payload), verifystore.SubjectScope{
		Subject: row.Subject, AuthorityNamespace: row.AuthorityNamespace,
		TenantID: row.TenantID, ProjectID: row.ProjectID, RepositoryID: row.RepositoryID,
	}) {
		t.Fatal("forced divergence must be visible before the read-path restore")
	}
	got, err := st.GetObligation(ctx, ob.ObligationID)
	if err != nil {
		t.Fatalf("GetObligation = %v", err)
	}
	if got.Subject != ob.Subject {
		t.Fatalf("subject = %q, want column subject %q (payload said %q)", got.Subject, ob.Subject, tampered.Subject)
	}
	if got.SubjectReference().TenantID != ob.SubjectRef.TenantID {
		t.Fatalf("tenant = %q, want column tenant %q (payload said %q)",
			got.SubjectReference().TenantID, ob.SubjectRef.TenantID, attacker.TenantID)
	}
}

// mustDecodeObligation decodes a raw obligation payload for a consistency
// assertion.
func mustDecodeObligation(t *testing.T, raw []byte) verifyapi.VerificationObligation {
	t.Helper()
	var o verifyapi.VerificationObligation
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatalf("decode obligation payload: %v", err)
	}
	return o
}
