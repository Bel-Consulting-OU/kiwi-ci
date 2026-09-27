package storage

// Real-PostgreSQL integration tests for the transactional OIDC issuance
// commit (Y1-A). Gated on KIWI_TEST_POSTGRES_URL exactly like the other
// storage integration tests: each test owns a throwaway database, and the
// barrier tests hold the job row lock in an outer transaction so a
// cancellation acquires/commits BETWEEN the handler's preliminary auth and
// the final issuance transaction.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const oidcITAudience = "https://aud.example.com"

// oidcITLeasedJob enqueues one run with one trusted, OIDC-enabled job and
// acquires a running lease for it, returning the authoritative stored job.
func oidcITLeasedJob(t *testing.T, st *PostgresStore) (runID, jobID, runnerID string, j model.Job) {
	t.Helper()
	ctx := context.Background()
	runID, jobID = pgITNewID(t), pgITNewID(t)
	job := pgITJob(runID, jobID, pgITRepo)
	job.Trusted = true
	job.OIDCAllowed = true
	job.OIDCAudiences = []string{oidcITAudience}
	// Production-shaped compiled run coordinates: the locked job payload
	// carries them and the issued token must describe them.
	job.Ref = "refs/heads/main"
	job.SHA = "abc123def456"
	job.Event = "push"
	job.Environment = "production"
	req := InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{jobID: job},
	}
	if err := st.InsertCompiledRun(ctx, req); err != nil {
		t.Fatalf("enqueue %s/%s: %v", runID, jobID, err)
	}
	runnerID = pgITNewID(t)
	leased, err := st.AcquireLease(ctx, jobID, runnerID, []byte("lease-hash"), 1, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("AcquireLease(%s): %v", jobID, err)
	}
	return runID, jobID, runnerID, leased
}

// oidcITRequest builds the candidate issuance for the leased job.
func oidcITRequest(j model.Job, audience string) OIDCIssuance {
	now := time.Now().UTC()
	req := OIDCIssuance{
		JobID: j.ID, RunnerID: j.LeaseRunnerID, LeaseGeneration: j.LeaseGeneration,
		LeaseTokenHash: j.LeaseTokenHash, Audience: audience,
		KID: "kid-1", JTI: "jti-1", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		Claims: map[string]string{
			OIDCClaimJobID:        j.ID,
			OIDCClaimRunID:        j.RunID,
			OIDCClaimJob:          j.Key,
			OIDCClaimRepositoryID: RepoIDForJob(j),
			OIDCClaimRepository:   j.RepoFullName,
			OIDCClaimRef:          j.Ref,
			OIDCClaimSHA:          j.SHA,
			OIDCClaimEvent:        j.Event,
			OIDCClaimEnvironment:  j.Environment,
			OIDCClaimTrusted:      "true",
			OIDCClaimAudience:     audience,
		},
	}
	return req
}

// oidcITIssuedAudits counts the durable oidc.issued rows for one job.
func oidcITIssuedAudits(t *testing.T, st *PostgresStore, jobID string) int {
	t.Helper()
	var n int
	if err := st.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action='oidc.issued' AND job_id=$1`, jobID).Scan(&n); err != nil {
		t.Fatalf("count oidc.issued audits: %v", err)
	}
	return n
}

// TestIntegrationOIDCIssuanceCommitLive proves the happy path on a real
// database: a live lease commits the issuance and appends the durable
// oidc.issued audit row in the same transaction, returning the identity
// derived from the locked job.
func TestIntegrationOIDCIssuanceCommitLive(t *testing.T) {
	st := pgITStore(t)
	runID, jobID, runnerID, j := oidcITLeasedJob(t, st)
	locked, err := st.CommitOIDCIssuance(context.Background(), oidcITRequest(j, oidcITAudience))
	if err != nil {
		t.Fatalf("CommitOIDCIssuance: %v", err)
	}
	if locked.JobID != jobID || locked.RunID != runID || locked.JobKey != j.Key {
		t.Fatalf("locked identity = %+v", locked)
	}
	if locked.RepoID != RepoIDForJob(j) || !locked.Trusted || !locked.OIDCAllowed {
		t.Fatalf("locked repository/trust = %+v", locked)
	}
	if locked.LeaseRunnerID != runnerID || locked.LeaseGeneration != j.LeaseGeneration {
		t.Fatalf("locked lease = %+v", locked)
	}
	// Every identity-bearing field of the locked identity describes the row,
	// and the authoritative claim set (the ONLY source the token is built
	// from) equals those locked values.
	ident := locked.AuthoritativeIdentity()
	wantClaims := map[string]any{
		"sub":           "repo:" + RepoIDForJob(j) + ":ref:" + j.Ref + ":job:" + j.Key,
		"repository":    j.RepoFullName,
		"repository_id": RepoIDForJob(j),
		"ref":           j.Ref,
		"sha":           j.SHA,
		"event":         j.Event,
		"run_id":        j.RunID,
		"job_id":        j.ID,
		"job":           j.Key,
		"environment":   j.Environment,
		"trusted":       true,
	}
	claims := ident.TokenClaims("https://issuer.example.com", oidcITAudience, "jti-it", oidcITRequest(j, oidcITAudience).IssuedAt, oidcITRequest(j, oidcITAudience).ExpiresAt)
	for key, want := range wantClaims {
		if claims[key] != want {
			t.Fatalf("token claim %q = %v, want the locked value %v", key, claims[key], want)
		}
	}
	if n := oidcITIssuedAudits(t, st, jobID); n != 1 {
		t.Fatalf("oidc.issued audits = %d, want 1", n)
	}
	events, err := st.ReadAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "oidc.issued" && e.JobID == jobID {
			found = true
			if e.RunID != runID || e.Actor != runnerID || e.Metadata["audience"] != oidcITAudience || e.Metadata["kid"] != "kid-1" {
				t.Fatalf("oidc.issued audit = %+v", e)
			}
		}
	}
	if !found {
		t.Fatal("no oidc.issued audit row for the committed issuance")
	}
}

// TestIntegrationOIDCIssuanceCommitRevocations is the Y1-A fresh-DB
// regression: every revocation applied to the live database before the commit
// returns its typed refusal and persists NOTHING (no audit row).
func TestIntegrationOIDCIssuanceCommitRevocations(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	cases := []struct {
		name   string
		sql    string
		mutate func(*OIDCIssuance)
		want   error
	}{
		{name: "cancelled", sql: `UPDATE jobs SET status='cancelled', lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL WHERE id=$1`, want: ErrOIDCIssuanceRevoked},
		{name: "completed", sql: `UPDATE jobs SET status='success', lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL WHERE id=$1`, want: ErrOIDCIssuanceRevoked},
		{name: "expired", sql: `UPDATE jobs SET lease_expires_at = now() - interval '1 second' WHERE id=$1`, want: ErrOIDCIssuanceExpired},
		{name: "generation replaced", sql: `UPDATE jobs SET lease_generation = lease_generation + 1 WHERE id=$1`, want: ErrOIDCIssuanceGeneration},
		{name: "runner replaced", sql: `UPDATE jobs SET lease_runner_id = 'someone-else' WHERE id=$1`, want: ErrOIDCIssuanceRunner},
		{name: "token replaced", sql: `UPDATE jobs SET lease_token_hash = 'other' WHERE id=$1`, want: ErrOIDCIssuanceToken},
		{name: "untrusted", sql: `UPDATE jobs SET payload = payload || '{"trusted":false}'::jsonb WHERE id=$1`, want: ErrOIDCIssuanceUntrusted},
		{name: "id_token revoked", sql: `UPDATE jobs SET payload = payload || '{"oidc_allowed":false}'::jsonb WHERE id=$1`, want: ErrOIDCIssuanceNotAllowed},
		{name: "audience narrowed", sql: `UPDATE jobs SET payload = payload || '{"oidc_audiences":["https://other.example.com"]}'::jsonb WHERE id=$1`, want: ErrOIDCIssuanceAudience},
		{name: "claim identity changed", mutate: func(r *OIDCIssuance) { r.Claims[OIDCClaimRepositoryID] = "github.com/other/repo" }, want: ErrOIDCIssuanceIdentity},
		// Every identity-bearing field changed between the candidate's
		// preliminary read and the commit is refused, including the revision
		// and environment claims that previously rode the token unchecked.
		{name: "ref changed", sql: `UPDATE jobs SET payload = payload || '{"ref":"refs/heads/other"}'::jsonb WHERE id=$1`, want: ErrOIDCIssuanceIdentity},
		{name: "sha changed", sql: `UPDATE jobs SET payload = payload || '{"sha":"ffff"}'::jsonb WHERE id=$1`, want: ErrOIDCIssuanceIdentity},
		{name: "event changed", sql: `UPDATE jobs SET payload = payload || '{"event":"schedule"}'::jsonb WHERE id=$1`, want: ErrOIDCIssuanceIdentity},
		{name: "environment changed", sql: `UPDATE jobs SET payload = payload || '{"environment":"staging"}'::jsonb WHERE id=$1`, want: ErrOIDCIssuanceIdentity},
		{name: "claim ref changed", mutate: func(r *OIDCIssuance) { r.Claims[OIDCClaimRef] = "refs/heads/other" }, want: ErrOIDCIssuanceIdentity},
		{name: "claim environment changed", mutate: func(r *OIDCIssuance) { r.Claims[OIDCClaimEnvironment] = "staging" }, want: ErrOIDCIssuanceIdentity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, jobID, _, j := oidcITLeasedJob(t, st)
			if tc.sql != "" {
				if _, err := st.pool.Exec(ctx, tc.sql, jobID); err != nil {
					t.Fatalf("apply revocation: %v", err)
				}
			}
			req := oidcITRequest(j, oidcITAudience)
			if tc.mutate != nil {
				tc.mutate(&req)
			}
			if _, err := st.CommitOIDCIssuance(ctx, req); !errors.Is(err, tc.want) {
				t.Fatalf("CommitOIDCIssuance = %v, want %v", err, tc.want)
			}
			if n := oidcITIssuedAudits(t, st, jobID); n != 0 {
				t.Fatalf("refused issuance appended %d audit rows", n)
			}
		})
	}
}

// TestIntegrationOIDCIssuanceCommitConcurrentCancelBarrier is the core race
// regression with real PostgreSQL locking: an outer transaction owns the job
// row lock (the cancellation "in flight" between preliminary auth and the
// issuance transaction), the commit blocks on it, and after the cancellation
// commits the blocked issuance observes the cancelled row, returns
// ErrOIDCIssuanceRevoked and writes no audit row. Barrier channels hand off
// the phases deterministically.
func TestIntegrationOIDCIssuanceCommitConcurrentCancelBarrier(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, _, j := oidcITLeasedJob(t, st)

	tx, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT 1 FROM jobs WHERE id=$1 FOR UPDATE`, jobID); err != nil {
		t.Fatalf("lock job row: %v", err)
	}

	commitStarted := make(chan struct{})
	commitDone := make(chan error, 1)
	go func() {
		close(commitStarted)
		_, err := st.CommitOIDCIssuance(ctx, oidcITRequest(j, oidcITAudience))
		commitDone <- err
	}()
	<-commitStarted
	// The commit holds no lock of its own yet: it must be blocked on the
	// outer transaction's job-row lock. Let it reach the lock before the
	// cancellation commits, then release.
	select {
	case err := <-commitDone:
		t.Fatalf("commit finished before the cancellation committed: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status='cancelled', lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL WHERE id=$1`, jobID); err != nil {
		t.Fatalf("cancel inside lock: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit cancellation: %v", err)
	}
	if err := <-commitDone; !errors.Is(err, ErrOIDCIssuanceRevoked) {
		t.Fatalf("commit after concurrent cancel = %v, want ErrOIDCIssuanceRevoked", err)
	}
	if n := oidcITIssuedAudits(t, st, jobID); n != 0 {
		t.Fatalf("cancelled issuance appended %d audit rows", n)
	}
}

// TestIntegrationOIDCIssuanceCommitConcurrentReplacementBarrier is the
// generation-fenced twin: a replacement lease acquired while the commit waits
// on the row lock makes the blocked issuance observe the new generation and
// refuse with ErrOIDCIssuanceGeneration.
func TestIntegrationOIDCIssuanceCommitConcurrentReplacementBarrier(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, _, j := oidcITLeasedJob(t, st)

	tx, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT 1 FROM jobs WHERE id=$1 FOR UPDATE`, jobID); err != nil {
		t.Fatalf("lock job row: %v", err)
	}
	commitStarted := make(chan struct{})
	commitDone := make(chan error, 1)
	go func() {
		close(commitStarted)
		_, err := st.CommitOIDCIssuance(ctx, oidcITRequest(j, oidcITAudience))
		commitDone <- err
	}()
	<-commitStarted
	select {
	case err := <-commitDone:
		t.Fatalf("commit finished before the replacement committed: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	// Same lease holder, new generation: the generation fence is what refuses
	// the blocked issuance, not the holder comparison.
	if _, err := tx.Exec(ctx, `UPDATE jobs SET lease_generation = lease_generation + 1 WHERE id=$1`, jobID); err != nil {
		t.Fatalf("replace lease inside lock: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit replacement: %v", err)
	}
	if err := <-commitDone; !errors.Is(err, ErrOIDCIssuanceGeneration) {
		t.Fatalf("commit after concurrent replacement = %v, want ErrOIDCIssuanceGeneration", err)
	}
	if n := oidcITIssuedAudits(t, st, jobID); n != 0 {
		t.Fatalf("replaced issuance appended %d audit rows", n)
	}
}

// TestIntegrationOIDCIssuanceCommitBarrierLeaseExpiry is the W2-A race
// regression on real PostgreSQL: the handler authenticated the lease while it
// was live (the request's IssuedAt precedes the expiry), then the signer/
// key-ring stall (the outer transaction's row lock) outlasts the lease expiry
// WITHOUT any row change. The blocked issuance must judge the expiry at the
// database commit clock (clock_timestamp() evaluated after the lock is
// acquired), refuse with ErrOIDCIssuanceExpired and write no audit row. The
// pre-fix predicate compared the expiry to the stale IssuedAt and would have
// committed a token here.
func TestIntegrationOIDCIssuanceCommitBarrierLeaseExpiry(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, _, j := oidcITLeasedJob(t, st)

	// The lease expires 500ms after it is shortened; the request's IssuedAt is
	// taken now, BEFORE that expiry.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET lease_expires_at = clock_timestamp() + interval '500 milliseconds' WHERE id=$1`, jobID); err != nil {
		t.Fatalf("shorten lease: %v", err)
	}
	req := oidcITRequest(j, oidcITAudience)

	tx, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT 1 FROM jobs WHERE id=$1 FOR UPDATE`, jobID); err != nil {
		t.Fatalf("lock job row: %v", err)
	}

	commitStarted := make(chan struct{})
	commitDone := make(chan error, 1)
	go func() {
		close(commitStarted)
		_, err := st.CommitOIDCIssuance(ctx, req)
		commitDone <- err
	}()
	<-commitStarted
	// Hold the row lock past the lease expiry: the commit is still waiting on
	// it, so the only thing that changes is the wall clock.
	select {
	case err := <-commitDone:
		t.Fatalf("commit finished before the lease expiry: %v", err)
	case <-time.After(800 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("release the row lock: %v", err)
	}
	if err := <-commitDone; !errors.Is(err, ErrOIDCIssuanceExpired) {
		t.Fatalf("commit after the lease expired under the barrier = %v, want ErrOIDCIssuanceExpired", err)
	}
	if n := oidcITIssuedAudits(t, st, jobID); n != 0 {
		t.Fatalf("expired issuance appended %d audit rows", n)
	}
}

// TestIntegrationOIDCIssuanceCommitRefusesElapsedLifetime pins the second
// commit-clock condition on real PostgreSQL: a candidate whose intended
// lifetime already elapsed (exp before the database commit clock) is refused
// with the same typed expiry, even though the lease is still live and the
// stale IssuedAt comparison would have accepted it.
func TestIntegrationOIDCIssuanceCommitRefusesElapsedLifetime(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, _, j := oidcITLeasedJob(t, st)

	req := oidcITRequest(j, oidcITAudience)
	now := time.Now().UTC()
	req.IssuedAt = now.Add(-2 * time.Hour)
	req.ExpiresAt = now.Add(-time.Hour)
	if _, err := st.CommitOIDCIssuance(ctx, req); !errors.Is(err, ErrOIDCIssuanceExpired) {
		t.Fatalf("commit with an elapsed requested lifetime = %v, want ErrOIDCIssuanceExpired", err)
	}
	if n := oidcITIssuedAudits(t, st, jobID); n != 0 {
		t.Fatalf("expired-lifetime issuance appended %d audit rows", n)
	}
}

// oidcITFixedRand replays a fixed byte sequence so the audit event id is
// predictable; it implements the randReader seam.
type oidcITFixedRand struct{ b []byte }

func (r *oidcITFixedRand) Read(p []byte) (int, error) {
	n := copy(p, r.b)
	return n, nil
}

// TestIntegrationOIDCIssuanceAuditFailureRollsBack proves the audit append is
// INSIDE the issuance transaction: when the audit INSERT fails (here: a
// duplicate id planted before the commit), the commit returns an error and
// the issuance is not acknowledged. Restoring the entropy source lets the
// same issuance commit and append exactly one audit row.
func TestIntegrationOIDCIssuanceAuditFailureRollsBack(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, _, j := oidcITLeasedJob(t, st)

	// Plant a row whose id will collide with the audit event id the commit
	// mints: hex of the 16 fixed bytes below.
	raw := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	colliding := "deadbeef00112233445566778899aabb"
	if _, err := st.pool.Exec(ctx, `INSERT INTO audit_events (id, action, actor, created_at) VALUES ($1, 'planted', 'test', now())`, colliding); err != nil {
		t.Fatalf("plant colliding audit row: %v", err)
	}
	old := randReader
	randReader = &oidcITFixedRand{b: raw}
	_, err := st.CommitOIDCIssuance(ctx, oidcITRequest(j, oidcITAudience))
	randReader = old
	if err == nil {
		t.Fatal("commit with a colliding audit id = nil error")
	}
	if n := oidcITIssuedAudits(t, st, jobID); n != 0 {
		t.Fatalf("failed audit committed %d oidc.issued rows", n)
	}

	// The entropy source is restored: the same issuance commits and audits.
	if _, err := st.CommitOIDCIssuance(ctx, oidcITRequest(j, oidcITAudience)); err != nil {
		t.Fatalf("commit after entropy recovery: %v", err)
	}
	if n := oidcITIssuedAudits(t, st, jobID); n != 1 {
		t.Fatalf("oidc.issued audits after recovery = %d, want 1", n)
	}
}
