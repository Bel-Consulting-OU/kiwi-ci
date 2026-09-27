package storage

// Real-PostgreSQL integration tests for the transactional secret-delivery
// commit. Gated on KIWI_TEST_POSTGRES_URL exactly like the other storage
// integration tests: each test owns a throwaway database, and the barrier
// tests hold the job row lock in an outer transaction so a cancellation or
// lease replacement commits BETWEEN the handler's preliminary auth and the
// final issuance transaction.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// secretITLeasedJob enqueues one run with one trusted job declaring TOKEN and
// acquires a running lease for it, returning the authoritative stored job.
func secretITLeasedJob(t *testing.T, st *PostgresStore) (runID, jobID, runnerID string, j model.Job) {
	t.Helper()
	ctx := context.Background()
	runID, jobID = pgITNewID(t), pgITNewID(t)
	job := pgITJob(runID, jobID, pgITRepo)
	job.Trusted = true
	job.DeclaredSecrets = []string{"TOKEN"}
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

// secretITRequest builds the commit request for the leased job.
func secretITRequest(j model.Job, name string) SecretIssuance {
	return SecretIssuance{
		JobID: j.ID, RunnerID: j.LeaseRunnerID, LeaseGeneration: j.LeaseGeneration,
		LeaseTokenHash: j.LeaseTokenHash, SecretName: name, IssuedAt: time.Now().UTC(),
	}
}

// secretITClaimCount counts the durable once-only claims for one job/secret.
func secretITClaimCount(t *testing.T, st *PostgresStore, jobID, name string) int {
	t.Helper()
	var n int
	if err := st.pool.QueryRow(context.Background(), `SELECT count(*) FROM secret_claims WHERE job_id=$1 AND secret_name=$2`, jobID, name).Scan(&n); err != nil {
		t.Fatalf("count secret_claims: %v", err)
	}
	return n
}

// secretITIssuedAudits counts the durable secret.issued rows for one job.
func secretITIssuedAudits(t *testing.T, st *PostgresStore, jobID string) int {
	t.Helper()
	var n int
	if err := st.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action='secret.issued' AND job_id=$1`, jobID).Scan(&n); err != nil {
		t.Fatalf("count secret.issued audits: %v", err)
	}
	return n
}

// TestIntegrationSecretIssuanceCommitLive proves the happy path on a real
// database: a live lease commits the delivery, inserting the once-only claim
// and the durable secret.issued audit row in the same transaction; a replay
// refuses typed and writes nothing further.
func TestIntegrationSecretIssuanceCommitLive(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID, runnerID, j := secretITLeasedJob(t, st)
	if err := st.CommitSecretIssuance(ctx, secretITRequest(j, "TOKEN")); err != nil {
		t.Fatalf("CommitSecretIssuance: %v", err)
	}
	if n := secretITClaimCount(t, st, jobID, "TOKEN"); n != 1 {
		t.Fatalf("claims = %d, want 1", n)
	}
	if n := secretITIssuedAudits(t, st, jobID); n != 1 {
		t.Fatalf("secret.issued audits = %d, want 1", n)
	}
	events, err := st.ReadAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "secret.issued" && e.JobID == jobID {
			found = true
			if e.RunID != runID || e.Actor != runnerID || e.Metadata["secret"] != "TOKEN" || e.Metadata["generation"] != "1" {
				t.Fatalf("secret.issued audit = %+v", e)
			}
		}
	}
	if !found {
		t.Fatal("no secret.issued audit row for the committed delivery")
	}
	if err := st.CommitSecretIssuance(ctx, secretITRequest(j, "TOKEN")); !errors.Is(err, ErrSecretIssuanceDuplicate) {
		t.Fatalf("replay = %v, want ErrSecretIssuanceDuplicate", err)
	}
	if n := secretITClaimCount(t, st, jobID, "TOKEN"); n != 1 {
		t.Fatalf("claims after replay = %d, want 1", n)
	}
	if n := secretITIssuedAudits(t, st, jobID); n != 1 {
		t.Fatalf("audits after replay = %d, want 1", n)
	}
}

// TestIntegrationSecretIssuanceCommitRefusals is the fresh-DB regression:
// every revocation applied to the live database before the commit returns its
// typed refusal and persists NOTHING (no claim, no audit row).
func TestIntegrationSecretIssuanceCommitRefusals(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	cases := []struct {
		name   string
		sql    string
		mutate func(*SecretIssuance)
		want   error
	}{
		{name: "cancelled", sql: `UPDATE jobs SET status='cancelled', lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL WHERE id=$1`, want: ErrSecretIssuanceRevoked},
		{name: "completed", sql: `UPDATE jobs SET status='success', lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL WHERE id=$1`, want: ErrSecretIssuanceRevoked},
		{name: "expired", sql: `UPDATE jobs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id=$1`, want: ErrSecretIssuanceExpired},
		{name: "generation replaced", sql: `UPDATE jobs SET lease_generation = lease_generation + 1 WHERE id=$1`, want: ErrSecretIssuanceGeneration},
		{name: "runner replaced", sql: `UPDATE jobs SET lease_runner_id = 'someone-else' WHERE id=$1`, want: ErrSecretIssuanceRunner},
		{name: "token replaced", sql: `UPDATE jobs SET lease_token_hash = 'other' WHERE id=$1`, want: ErrSecretIssuanceToken},
		{name: "untrusted", sql: `UPDATE jobs SET payload = payload || '{"trusted":false}'::jsonb WHERE id=$1`, want: ErrSecretIssuanceUntrusted},
		{name: "undeclared", sql: `UPDATE jobs SET payload = payload || '{"declared_secrets":["OTHER"]}'::jsonb WHERE id=$1`, want: ErrSecretIssuanceNotDeclared},
		{name: "invalid request", mutate: func(r *SecretIssuance) { r.SecretName = "" }, want: ErrSecretIssuanceInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, jobID, _, j := secretITLeasedJob(t, st)
			if tc.sql != "" {
				if _, err := st.pool.Exec(ctx, tc.sql, jobID); err != nil {
					t.Fatalf("apply revocation: %v", err)
				}
			}
			req := secretITRequest(j, "TOKEN")
			if tc.mutate != nil {
				tc.mutate(&req)
			}
			if err := st.CommitSecretIssuance(ctx, req); !errors.Is(err, tc.want) {
				t.Fatalf("CommitSecretIssuance = %v, want %v", err, tc.want)
			}
			if n := secretITClaimCount(t, st, jobID, "TOKEN"); n != 0 {
				t.Fatalf("refused delivery recorded %d claims", n)
			}
			if n := secretITIssuedAudits(t, st, jobID); n != 0 {
				t.Fatalf("refused delivery recorded %d audit rows", n)
			}
		})
	}
}

// TestIntegrationSecretIssuanceCommitConcurrentCancelBarrier is the core race
// regression with real PostgreSQL locking: an outer transaction owns the job
// row lock (the cancellation "in flight" between preliminary auth and the
// issuance transaction), the commit blocks on it, and after the cancellation
// commits the blocked delivery observes the cancelled row, returns
// ErrSecretIssuanceRevoked and writes no claim and no audit row.
func TestIntegrationSecretIssuanceCommitConcurrentCancelBarrier(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, _, j := secretITLeasedJob(t, st)

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
		commitDone <- st.CommitSecretIssuance(ctx, secretITRequest(j, "TOKEN"))
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
	if err := <-commitDone; !errors.Is(err, ErrSecretIssuanceRevoked) {
		t.Fatalf("commit after concurrent cancel = %v, want ErrSecretIssuanceRevoked", err)
	}
	if n := secretITClaimCount(t, st, jobID, "TOKEN"); n != 0 {
		t.Fatalf("cancelled delivery recorded %d claims", n)
	}
	if n := secretITIssuedAudits(t, st, jobID); n != 0 {
		t.Fatalf("cancelled delivery recorded %d audit rows", n)
	}
}

// TestIntegrationSecretIssuanceCommitConcurrentGenerationBarrier is the
// generation-fenced twin: a replacement lease acquired while the commit waits
// on the row lock makes the blocked delivery observe the new generation and
// refuse with ErrSecretIssuanceGeneration, writing nothing.
func TestIntegrationSecretIssuanceCommitConcurrentGenerationBarrier(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, _, j := secretITLeasedJob(t, st)
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
		commitDone <- st.CommitSecretIssuance(ctx, secretITRequest(j, "TOKEN"))
	}()
	<-commitStarted
	select {
	case err := <-commitDone:
		t.Fatalf("commit finished before the replacement committed: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET lease_generation = lease_generation + 1 WHERE id=$1`, jobID); err != nil {
		t.Fatalf("replace lease inside lock: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit replacement: %v", err)
	}
	if err := <-commitDone; !errors.Is(err, ErrSecretIssuanceGeneration) {
		t.Fatalf("commit after concurrent replacement = %v, want ErrSecretIssuanceGeneration", err)
	}
	if n := secretITClaimCount(t, st, jobID, "TOKEN"); n != 0 {
		t.Fatalf("replaced delivery recorded %d claims", n)
	}
	if n := secretITIssuedAudits(t, st, jobID); n != 0 {
		t.Fatalf("replaced delivery recorded %d audit rows", n)
	}
}

// TestIntegrationSecretIssuanceCommitBarrierLeaseExpiry is the commit-clock
// race regression on real PostgreSQL: the handler authenticated the lease
// while it was live, then the delivery commit stalls on the job row lock (a
// concurrent slow transaction) until AFTER the lease expiry, with no row ever
// modified. The blocked delivery must judge the expiry at the DATABASE clock
// sampled after the lock is acquired, refuse with ErrSecretIssuanceExpired and
// write no claim and no audit row. A target-list clock_timestamp() would be
// evaluated during the scan, BEFORE LockRows, and the pre-fix query would have
// committed the delivery against the stale timestamp.
func TestIntegrationSecretIssuanceCommitBarrierLeaseExpiry(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, _, j := secretITLeasedJob(t, st)

	// The lease expires 500ms from now; the request is built now, BEFORE
	// that expiry, so only the commit clock can tell the difference.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET lease_expires_at = clock_timestamp() + interval '500 milliseconds' WHERE id=$1`, jobID); err != nil {
		t.Fatalf("shorten lease: %v", err)
	}
	req := secretITRequest(j, "TOKEN")

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
		commitDone <- st.CommitSecretIssuance(ctx, req)
	}()
	<-commitStarted
	// Hold the row lock past the lease expiry: the commit is still waiting on
	// it, so the only thing that changes is the wall clock.
	select {
	case err := <-commitDone:
		t.Fatalf("commit finished before the lease expired: %v", err)
	case <-time.After(800 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("release the row lock: %v", err)
	}
	if err := <-commitDone; !errors.Is(err, ErrSecretIssuanceExpired) {
		t.Fatalf("commit after the lease expired under the barrier = %v, want ErrSecretIssuanceExpired", err)
	}
	if n := secretITClaimCount(t, st, jobID, "TOKEN"); n != 0 {
		t.Fatalf("expired delivery recorded %d claims", n)
	}
	if n := secretITIssuedAudits(t, st, jobID); n != 0 {
		t.Fatalf("expired delivery recorded %d audit rows", n)
	}
}

// TestIntegrationSecretIssuanceCommitConcurrentSingleClaim proves the
// once-only arbitration on real PostgreSQL: two concurrent commits of the same
// (job, generation, secret) produce exactly one success and one duplicate,
// with exactly one claim and one audit row.
func TestIntegrationSecretIssuanceCommitConcurrentSingleClaim(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, _, j := secretITLeasedJob(t, st)
	req := secretITRequest(j, "TOKEN")
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			results <- st.CommitSecretIssuance(ctx, req)
		}()
	}
	close(start)
	var okCount, dupCount int
	for i := 0; i < 2; i++ {
		switch err := <-results; {
		case err == nil:
			okCount++
		case errors.Is(err, ErrSecretIssuanceDuplicate):
			dupCount++
		default:
			t.Fatalf("concurrent commit = %v", err)
		}
	}
	if okCount != 1 || dupCount != 1 {
		t.Fatalf("concurrent commits = %d ok / %d duplicate, want 1/1", okCount, dupCount)
	}
	if n := secretITClaimCount(t, st, jobID, "TOKEN"); n != 1 {
		t.Fatalf("claims = %d, want 1", n)
	}
	if n := secretITIssuedAudits(t, st, jobID); n != 1 {
		t.Fatalf("secret.issued audits = %d, want 1", n)
	}
}

// secretITFixedRand replays a fixed byte sequence so the audit event id is
// predictable; it implements the randReader seam.
type secretITFixedRand struct{ b []byte }

func (r *secretITFixedRand) Read(p []byte) (int, error) {
	n := copy(p, r.b)
	return n, nil
}

// TestIntegrationSecretIssuanceAuditFailureRollsBackClaim proves the claim and
// the audit are in ONE transaction: when the audit INSERT fails (here: a
// duplicate id planted before the commit), the commit returns an error and the
// claim is rolled back too. Restoring the entropy source lets the same
// delivery commit, recording exactly one claim and one audit row.
func TestIntegrationSecretIssuanceAuditFailureRollsBackClaim(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, _, j := secretITLeasedJob(t, st)

	raw := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	colliding := "deadbeef00112233445566778899aabb"
	if _, err := st.pool.Exec(ctx, `INSERT INTO audit_events (id, action, actor, created_at) VALUES ($1, 'planted', 'test', now())`, colliding); err != nil {
		t.Fatalf("plant colliding audit row: %v", err)
	}
	old := randReader
	randReader = &secretITFixedRand{b: raw}
	err := st.CommitSecretIssuance(ctx, secretITRequest(j, "TOKEN"))
	randReader = old
	if err == nil {
		t.Fatal("commit with a colliding audit id = nil error")
	}
	if n := secretITClaimCount(t, st, jobID, "TOKEN"); n != 0 {
		t.Fatalf("failed audit left %d claims behind", n)
	}
	if n := secretITIssuedAudits(t, st, jobID); n != 0 {
		t.Fatalf("failed audit committed %d secret.issued rows", n)
	}

	if err := st.CommitSecretIssuance(ctx, secretITRequest(j, "TOKEN")); err != nil {
		t.Fatalf("commit after entropy recovery: %v", err)
	}
	if n := secretITClaimCount(t, st, jobID, "TOKEN"); n != 1 {
		t.Fatalf("claims after recovery = %d, want 1", n)
	}
	if n := secretITIssuedAudits(t, st, jobID); n != 1 {
		t.Fatalf("audits after recovery = %d, want 1", n)
	}
}
