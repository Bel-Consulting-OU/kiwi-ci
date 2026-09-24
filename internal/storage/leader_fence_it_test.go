package storage

// Real-PostgreSQL integration coverage for the leadership-epoch fence
// (migration 0025): the mechanism that lets a throttled cached leadership
// claim survive lock loss without letting a stale leader mutate anything.
//
// Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go here. The two-store
// tests are two pools over ONE schema, mirroring two control-plane replicas
// of one deployment.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestPostgresIntegrationLeaderFenceStaleLeaderMutatesNothing is the core
// fencing regression. A acquires the leadership claim (epoch e1) and retains
// it; A's dedicated session is then killed (the exact failure the cached
// claim can briefly outlive); B acquires the freed lock and publishes a
// strictly greater epoch e2. A invokes EVERY leader-fenced operation class
// with its stale epoch: each must return ErrStaleLeader and mutate nothing.
// B's same operations, with the current epoch, must succeed. Before the
// fence, A's stale store mutated normally in exactly this window.
func TestPostgresIntegrationLeaderFenceStaleLeaderMutatesNothing(t *testing.T) {
	env := pgITSetup(t)
	a := env.open(t)
	env.migrate(t, a)
	b := env.open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	leaderKey := "kiwi-it-fence-" + pgITRandomHex(t, 8)

	if got, err := a.TryAcquireLeadership(ctx, leaderKey, time.Minute); err != nil || !got {
		t.Fatalf("A acquire = %v, %v", got, err)
	}
	epochA, ok := a.LeaderEpoch()
	if !ok || epochA < 1 {
		t.Fatalf("A retained epoch = %d/%v; want a published epoch", epochA, ok)
	}
	// Kill A's session the way a crashed backend does: the advisory lock dies
	// server-side while A still retains epochA (its cached claim is exactly
	// what the fence must neutralize).
	if a.leaderConn == nil {
		t.Fatal("A has no dedicated leader session to kill")
	}
	_ = a.leaderConn.Close(ctx)

	var epochB int64
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := b.TryAcquireLeadership(ctx, leaderKey, time.Minute)
		if err != nil {
			t.Fatalf("B acquire = %v, %v", got, err)
		}
		if got {
			epochB, ok = b.LeaderEpoch()
			if !ok {
				t.Fatal("B acquired but retained no epoch")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("B never acquired the lock A's dead session released")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if epochB <= epochA {
		t.Fatalf("epoch after hand-over = %d; want strictly greater than A's %d", epochB, epochA)
	}

	// --- Seed one row per fenced operation class, enough that a stale
	// mutation would be observable. -------------------------------------
	recRun, recJob := pgITNewID(t), pgITNewID(t)
	rec := pgITJob(recRun, recJob, pgITRepo)
	rec.MaxInfraRetries = 2
	pgITRecSeedRun(t, a, recRun, model.StatusRunning, map[string]model.Job{recJob: rec})
	recRunner := pgITNewID(t)
	pgITSeedRunner(t, a, recRunner, 1, 0, 0)
	pgITRecLease(t, a, recJob, recRunner, 3, now.Add(-time.Minute))

	toRun, toJob := pgITNewID(t), pgITNewID(t)
	deadlineAt := now.Add(-time.Minute)
	toJobObj := pgITJob(toRun, toJob, pgITRepo)
	toJobObj.QueueDeadline = &deadlineAt
	pgITRecSeedRun(t, a, toRun, model.StatusQueued, map[string]model.Job{toJob: toJobObj})

	if err := a.OutboxAppend(ctx, OutboxItem{ID: "fence-claim", Kind: "test", CreatedAt: now}); err != nil {
		t.Fatalf("append claim row: %v", err)
	}
	if err := a.OutboxAppend(ctx, OutboxItem{ID: "fence-ack", Kind: "test", CreatedAt: now}); err != nil {
		t.Fatalf("append ack row: %v", err)
	}

	pendingJob := pgITNewID(t)
	if err := a.RememberPendingSidecar(ctx, pendingJob, 4, "bin", ArtifactSidecarKindSBOM, strings.Repeat("e", 64)); err != nil {
		t.Fatalf("remember pending sidecar: %v", err)
	}
	if _, err := a.pool.Exec(ctx, `UPDATE artifact_pending_sidecars SET created_at = now() - interval '2 hours' WHERE job_id=$1`, pendingJob); err != nil {
		t.Fatalf("age pending sidecar: %v", err)
	}

	downJob := pgITNewID(t)
	oldReserved := now.Add(-2 * time.Hour)
	if err := a.InsertDownstreamLink(ctx, DownstreamLink{
		ParentJobID: downJob, TargetRepo: "kiwi-it/child", TargetRef: "refs/heads/main",
		LaunchToken: "tok", Reserved: true, ReservedAt: &oldReserved, CreatedAt: now.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("insert downstream link: %v", err)
	}

	scheduleID := "fence-schedule-" + pgITRandomHex(t, 8)
	if err := a.UpsertSchedule(ctx, Schedule{ID: scheduleID, Repository: "kiwi-it/repo", RepoID: pgITRepoID, RepoURL: pgITRepo, Enabled: true, Spec: "*/5 * * * *", CreatedAt: now}); err != nil {
		t.Fatalf("upsert schedule: %v", err)
	}
	nominal := now.Truncate(time.Minute)
	occurrenceRun, occurrenceJob := pgITNewID(t), pgITNewID(t)

	// --- Typed rejection helper. The FIRST stale rejection also clears A's
	// retained epoch, so later ones fail closed locally; every one must still
	// be the typed error. ------------------------------------------------
	wantStale := func(op string, err error) {
		t.Helper()
		if !errors.Is(err, ErrStaleLeader) {
			t.Fatalf("%s with A's stale epoch = %v; want ErrStaleLeader", op, err)
		}
	}

	// 1. Recovery sweep applier: expired running lease.
	wantStale("RecoverExpiredLease", a.RecoverExpiredLease(ctx, recJob, 3, now))
	if j, err := a.GetJob(ctx, recJob); err != nil || j.Status != model.StatusRunning {
		t.Fatalf("stale RecoverExpiredLease mutated: job = %+v err=%v", j, err)
	}
	if err := b.RecoverExpiredLease(ctx, recJob, 3, now); err != nil {
		t.Fatalf("B RecoverExpiredLease = %v", err)
	}
	if j, err := b.GetJob(ctx, recJob); err != nil || j.Status != model.StatusQueued {
		t.Fatalf("B recovery did not requeue: job = %+v err=%v", j, err)
	}

	// 2. Queue-timeout sweep applier.
	wantStale("ExpireQueuedJob", a.ExpireQueuedJob(ctx, toJob, deadlineAt))
	if j, err := a.GetJob(ctx, toJob); err != nil || j.Status != model.StatusQueued {
		t.Fatalf("stale ExpireQueuedJob mutated: job = %+v err=%v", j, err)
	}
	if err := b.ExpireQueuedJob(ctx, toJob, deadlineAt); err != nil {
		t.Fatalf("B ExpireQueuedJob = %v", err)
	}
	if j, err := b.GetJob(ctx, toJob); err != nil || j.Status != model.StatusCancelled {
		t.Fatalf("B queue timeout did not cancel: job = %+v err=%v", j, err)
	}

	// 3. Outbox claim.
	if claimed, err := a.ClaimOutbox(ctx, "a-flusher", 10); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("stale ClaimOutbox = %d/%v; want ErrStaleLeader", len(claimed), err)
	}
	assertClaim := func(id, want string) {
		t.Helper()
		var claimer *string
		if err := a.pool.QueryRow(ctx, `SELECT claimed_by FROM outbox WHERE id=$1`, id).Scan(&claimer); err != nil {
			t.Fatalf("read claim %s: %v", id, err)
		}
		got := ""
		if claimer != nil {
			got = *claimer
		}
		if got != want {
			t.Fatalf("claim on %s = %q; want %q", id, got, want)
		}
	}
	assertClaim("fence-claim", "")
	claimed, err := b.ClaimOutbox(ctx, "b-flusher", 10)
	if err != nil || len(claimed) != 2 {
		t.Fatalf("B ClaimOutbox = %d/%v; want 2/nil", len(claimed), err)
	}
	assertClaim("fence-claim", "b-flusher")
	assertClaim("fence-ack", "b-flusher")

	// 4. Outbox ACK (leader-only dispatch completion).
	if err := b.ReleaseOutboxClaim(ctx, "fence-ack", "b-flusher"); err != nil {
		t.Fatalf("B release before ack: %v", err)
	}
	wantStale("OutboxAck", a.OutboxAck(ctx, "fence-ack"))
	var remaining int
	if err := a.pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE id='fence-ack'`).Scan(&remaining); err != nil || remaining != 1 {
		t.Fatalf("stale OutboxAck mutated: rows=%d err=%v", remaining, err)
	}
	if err := b.OutboxAck(ctx, "fence-ack"); err != nil {
		t.Fatalf("B OutboxAck = %v", err)
	}
	if err := a.pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE id='fence-ack'`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("B ack left the row: rows=%d err=%v", remaining, err)
	}

	// 5. Outbox claim release (single).
	wantStale("ReleaseOutboxClaim", a.ReleaseOutboxClaim(ctx, "fence-claim", "b-flusher"))
	assertClaim("fence-claim", "b-flusher")
	if err := b.ReleaseOutboxClaim(ctx, "fence-claim", "b-flusher"); err != nil {
		t.Fatalf("B ReleaseOutboxClaim = %v", err)
	}
	assertClaim("fence-claim", "")

	// 6. Outbox claim release (batch).
	if _, err := b.ClaimOutbox(ctx, "b-flusher-2", 10); err != nil {
		t.Fatalf("B re-claim: %v", err)
	}
	if n, err := a.ReleaseOutboxClaims(ctx, []string{"fence-claim"}, "b-flusher-2"); !errors.Is(err, ErrStaleLeader) || n != 0 {
		t.Fatalf("stale ReleaseOutboxClaims = %d/%v; want 0/ErrStaleLeader", n, err)
	}
	assertClaim("fence-claim", "b-flusher-2")
	if n, err := b.ReleaseOutboxClaims(ctx, []string{"fence-claim"}, "b-flusher-2"); err != nil || n != 1 {
		t.Fatalf("B ReleaseOutboxClaims = %d/%v; want 1/nil", n, err)
	}
	assertClaim("fence-claim", "")

	// 7. GC pass durable delete (pending sidecar prune).
	if n, err := a.PrunePendingSidecars(ctx, now.Add(-time.Hour)); !errors.Is(err, ErrStaleLeader) || n != 0 {
		t.Fatalf("stale PrunePendingSidecars = %d/%v; want 0/ErrStaleLeader", n, err)
	}
	if err := a.pool.QueryRow(ctx, `SELECT count(*) FROM artifact_pending_sidecars WHERE job_id=$1`, pendingJob).Scan(&remaining); err != nil || remaining != 1 {
		t.Fatalf("stale prune mutated: rows=%d err=%v", remaining, err)
	}
	if n, err := b.PrunePendingSidecars(ctx, now.Add(-time.Hour)); err != nil || n != 1 {
		t.Fatalf("B PrunePendingSidecars = %d/%v; want 1/nil", n, err)
	}

	// 8. Downstream reservation recovery sweep.
	if n, err := a.ExpireDownstreamReservations(ctx, now.Add(-time.Hour)); !errors.Is(err, ErrStaleLeader) || n != 0 {
		t.Fatalf("stale ExpireDownstreamReservations = %d/%v; want 0/ErrStaleLeader", n, err)
	}
	var reserved bool
	if err := a.pool.QueryRow(ctx, `SELECT reserved FROM downstream_links WHERE parent_job_id=$1`, downJob).Scan(&reserved); err != nil || !reserved {
		t.Fatalf("stale reservation expiry mutated: reserved=%v err=%v", reserved, err)
	}
	if n, err := b.ExpireDownstreamReservations(ctx, now.Add(-time.Hour)); err != nil || n != 1 {
		t.Fatalf("B ExpireDownstreamReservations = %d/%v; want 1/nil", n, err)
	}

	// 9. Schedule occurrence insertion (the standalone claim path).
	occurrenceCount := func() int {
		t.Helper()
		var n int
		if err := a.pool.QueryRow(ctx, `SELECT count(*) FROM schedule_occurrences WHERE schedule_id=$1`, scheduleID).Scan(&n); err != nil {
			t.Fatalf("count occurrences: %v", err)
		}
		return n
	}
	if ok, err := a.ClaimScheduleOccurrence(ctx, scheduleID, nominal, occurrenceRun); !errors.Is(err, ErrStaleLeader) || ok {
		t.Fatalf("stale ClaimScheduleOccurrence = %v/%v; want false/ErrStaleLeader", ok, err)
	}
	if n := occurrenceCount(); n != 0 {
		t.Fatalf("stale occurrence claim inserted %d rows", n)
	}
	if ok, err := b.ClaimScheduleOccurrence(ctx, scheduleID, nominal, occurrenceRun); err != nil || !ok {
		t.Fatalf("B ClaimScheduleOccurrence = %v/%v; want true/nil", ok, err)
	}
	if n := occurrenceCount(); n != 1 {
		t.Fatalf("B occurrence claim left %d rows; want 1", n)
	}

	// 10. Schedule marker advance.
	lastRun := func() *time.Time {
		t.Helper()
		var lr *time.Time
		if err := a.pool.QueryRow(ctx, `SELECT last_run FROM schedules WHERE id=$1`, scheduleID).Scan(&lr); err != nil {
			t.Fatalf("read last_run: %v", err)
		}
		return lr
	}
	wantStale("AdvanceScheduleLastRun", a.AdvanceScheduleLastRun(ctx, scheduleID, nominal.Add(5*time.Minute)))
	if lr := lastRun(); lr != nil {
		t.Fatalf("stale advance moved last_run to %v", lr)
	}
	if err := b.AdvanceScheduleLastRun(ctx, scheduleID, nominal.Add(5*time.Minute)); err != nil {
		t.Fatalf("B AdvanceScheduleLastRun = %v", err)
	}
	if lr := lastRun(); lr == nil || !lr.Equal(nominal.Add(5*time.Minute)) {
		t.Fatalf("B advance left last_run = %v", lr)
	}

	// 11. Occurrence insertion committed with the fired run (the leader-only
	// branch of the atomic enqueue).
	claim := &ScheduleClaim{ScheduleID: scheduleID, Nominal: nominal.Add(10 * time.Minute)}
	staleReq := InsertCompiledRunRequest{
		Run:           model.Run{ID: occurrenceRun, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: now},
		Jobs:          map[string]model.Job{occurrenceJob: pgITJob(occurrenceRun, occurrenceJob, pgITRepo)},
		ScheduleClaim: claim,
	}
	if err := a.InsertCompiledRun(ctx, staleReq); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("stale schedule enqueue = %v; want ErrStaleLeader", err)
	}
	var runRows int
	if err := a.pool.QueryRow(ctx, `SELECT count(*) FROM runs WHERE id=$1`, occurrenceRun).Scan(&runRows); err != nil || runRows != 0 {
		t.Fatalf("stale schedule enqueue inserted %d runs (err=%v)", runRows, err)
	}
	if err := b.InsertCompiledRun(ctx, staleReq); err != nil {
		t.Fatalf("B schedule enqueue = %v", err)
	}
	if err := a.pool.QueryRow(ctx, `SELECT count(*) FROM runs WHERE id=$1`, occurrenceRun).Scan(&runRows); err != nil || runRows != 1 {
		t.Fatalf("B schedule enqueue inserted %d runs (err=%v)", runRows, err)
	}

	// 12. CAS GC pass admission (the collector lease transaction is fenced).
	if _, held, err := a.TryAcquireCASGCLease(ctx, "kiwi-cas-gc"); !errors.Is(err, ErrStaleLeader) || held {
		t.Fatalf("stale TryAcquireCASGCLease = held=%v err=%v; want false/ErrStaleLeader", held, err)
	}
	bLease, held, err := b.TryAcquireCASGCLease(ctx, "kiwi-cas-gc")
	if err != nil || !held {
		t.Fatalf("B TryAcquireCASGCLease = held=%v err=%v; want true/nil", held, err)
	}
	if err := bLease.Release(ctx); err != nil {
		t.Fatalf("B release CAS GC lease: %v", err)
	}

	// A's retained epoch was invalidated by the fence: it presents none now.
	if epoch, ok := a.LeaderEpoch(); ok {
		t.Fatalf("stale store still retains epoch %d", epoch)
	}
}

// TestPostgresIntegrationLeaderEpochAtomicity pins the acquisition
// atomicity contract: a lost contention cannot advance the epoch, and an
// acquisition whose epoch publish fails (the connection would die before
// commit) publishes nothing, retains nothing, and leaks no advisory lock.
func TestPostgresIntegrationLeaderEpochAtomicity(t *testing.T) {
	env := pgITSetup(t)
	a := env.open(t)
	env.migrate(t, a)
	b := env.open(t)
	c := env.open(t)
	ctx := context.Background()
	key := "kiwi-it-epoch-atomic-" + pgITRandomHex(t, 8)

	before, err := a.ReadLeaderEpoch(ctx)
	if err != nil {
		t.Fatalf("read initial epoch: %v", err)
	}

	if got, err := a.TryAcquireLeadership(ctx, key, time.Minute); err != nil || !got {
		t.Fatalf("A acquire = %v, %v", got, err)
	}
	afterAcquire, err := a.ReadLeaderEpoch(ctx)
	if err != nil || afterAcquire != before+1 {
		t.Fatalf("epoch after acquisition = %d/%v; want %d", afterAcquire, err, before+1)
	}

	// A failed acquisition (the lock is held by A) must not advance it.
	if got, err := b.TryAcquireLeadership(ctx, key, time.Minute); err != nil || got {
		t.Fatalf("contended B acquire = %v, %v; want false/nil", got, err)
	}
	if got, err := b.ReadLeaderEpoch(ctx); err != nil || got != afterAcquire {
		t.Fatalf("epoch after failed acquisition = %d/%v; want %d", got, err, afterAcquire)
	}
	if _, ok := b.LeaderEpoch(); ok {
		t.Fatal("failed acquisition retained an epoch")
	}

	// Crash mid-acquisition: block the epoch publish at the database so C
	// takes the advisory lock, fails to publish, and must publish nothing and
	// release the lock. The trigger simulates the connection dying before
	// commit; the observable contract is identical.
	if _, err := c.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION kiwi_it_block_fence() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'fence publish blocked'; END; $$ LANGUAGE plpgsql`); err != nil {
		t.Fatalf("create trigger function: %v", err)
	}
	if _, err := c.pool.Exec(ctx, `CREATE TRIGGER kiwi_it_block_fence BEFORE UPDATE ON leader_fence FOR EACH ROW EXECUTE FUNCTION kiwi_it_block_fence()`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	// Release A's live claim first: the advisory lock is database-wide, so C
	// can only take it once A lets go.
	if err := a.ReleaseLeadership(ctx, key); err != nil {
		t.Fatalf("A release: %v", err)
	}
	if got, err := c.TryAcquireLeadership(ctx, key, time.Minute); err == nil || got {
		t.Fatalf("blocked acquisition = %v/%v; want false with a publish error", got, err)
	}
	if got, err := c.ReadLeaderEpoch(ctx); err != nil || got != afterAcquire {
		t.Fatalf("epoch after blocked acquisition = %d/%v; want %d (unchanged)", got, err, afterAcquire)
	}
	if _, ok := c.LeaderEpoch(); ok {
		t.Fatal("blocked acquisition retained an epoch")
	}
	if _, err := c.pool.Exec(ctx, `DROP TRIGGER kiwi_it_block_fence ON leader_fence`); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	// The lock was released with the failed session: another replica can
	// acquire immediately and publishes a greater epoch.
	if got, err := b.TryAcquireLeadership(ctx, key, time.Minute); err != nil || !got {
		t.Fatalf("B acquire after blocked publish = %v, %v (the lock leaked)", got, err)
	}
	if got, err := b.ReadLeaderEpoch(ctx); err != nil || got != afterAcquire+1 {
		t.Fatalf("epoch after recovery acquisition = %d/%v; want %d", got, err, afterAcquire+1)
	}
}

// TestPostgresIntegrationLeaderFenceMigration pins migration 0025 on a fresh
// schema and on an upgrade over existing rows: the singleton row exists at
// its initial epoch, the table constrains itself to that single row, an
// advanced epoch survives re-migration, and unrelated pre-existing rows are
// untouched by the upgrade.
func TestPostgresIntegrationLeaderFenceMigration(t *testing.T) {
	env := pgITSetupAtVersion(t, 24)
	st := env.open(t)
	ctx := context.Background()

	// Upgrade path: a database at 0024 with live rows.
	pgITApplyThrough(t, st, 24)
	runID := pgITNewID(t)
	if _, err := st.pool.Exec(ctx, `INSERT INTO runs (id, status, created_at, payload) VALUES ($1, 'queued', now(), '{}'::jsonb)`, runID); err != nil {
		t.Fatalf("insert pre-upgrade run: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `INSERT INTO outbox (id, kind, payload, created_at) VALUES ('pre-0025', 'test', '{}'::jsonb, now())`); err != nil {
		t.Fatalf("insert pre-upgrade outbox row: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate over v24 with data: %v", err)
	}
	wantVersion := pgITLatestVersion(t)
	if v, err := st.SchemaVersion(ctx); err != nil || v != wantVersion {
		t.Fatalf("SchemaVersion = %d/%v; want %d", v, err, wantVersion)
	}
	epoch, err := st.ReadLeaderEpoch(ctx)
	if err != nil || epoch != 1 {
		t.Fatalf("seeded epoch = %d/%v; want 1", epoch, err)
	}
	var holder *string
	if err := st.pool.QueryRow(ctx, `SELECT holder FROM leader_fence WHERE id='singleton'`).Scan(&holder); err != nil || holder != nil {
		t.Fatalf("seeded holder = %v/%v; want NULL", holder, err)
	}
	var runs int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM runs WHERE id=$1`, runID).Scan(&runs); err != nil || runs != 1 {
		t.Fatalf("upgrade lost the pre-existing run: rows=%d err=%v", runs, err)
	}
	var outboxRows int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE id='pre-0025'`).Scan(&outboxRows); err != nil || outboxRows != 1 {
		t.Fatalf("upgrade lost the pre-existing outbox row: rows=%d err=%v", outboxRows, err)
	}

	// The singleton constraint rejects any other id.
	if _, err := st.pool.Exec(ctx, `INSERT INTO leader_fence (id, epoch) VALUES ('second', 1)`); err == nil {
		t.Fatal("leader_fence accepted a second row")
	}

	// An advanced epoch survives a re-run of Migrate (the seed is
	// ON CONFLICT DO NOTHING): acquisition bumps it, Migrate leaves it.
	if got, err := st.TryAcquireLeadership(ctx, "kiwi-it-migration-"+pgITRandomHex(t, 8), time.Minute); err != nil || !got {
		t.Fatalf("acquire: %v, %v", got, err)
	}
	advanced, err := st.ReadLeaderEpoch(ctx)
	if err != nil || advanced != 2 {
		t.Fatalf("advanced epoch = %d/%v; want 2", advanced, err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("re-Migrate: %v", err)
	}
	if got, err := st.ReadLeaderEpoch(ctx); err != nil || got != advanced {
		t.Fatalf("re-Migrate reset the epoch: %d/%v; want %d", got, err, advanced)
	}

	// Fresh-schema bootstrap: a new schema applies 0001..0025 and seeds the
	// row through the same migration.
	fresh := pgITStore(t)
	if got, err := fresh.ReadLeaderEpoch(context.Background()); err != nil || got != 1 {
		t.Fatalf("fresh schema epoch = %d/%v; want 1", got, err)
	}
}
