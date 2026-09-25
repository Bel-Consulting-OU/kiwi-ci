package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// PostgresStore is the durable SQL implementation of Store, backed by a
// pgxpool. Hot-path columns (status, lease, counters, timestamps) are real
// relational columns; the full model struct lives in a jsonb payload column.
// Reads merge the real columns over the payload so both views never diverge.
type PostgresStore struct {
	pool *pgxpool.Pool

	// fencePool is a SEPARATE connection pool used exclusively for
	// advisory locks (CAS digest fences and the collector lease). Holding a
	// lock on the operational pool would deadlock fenced operations that
	// then need the same pool for their own reads/writes: at
	// max_connections=1 the writer would hold its lock connection and block
	// forever committing its reference, and the collector needs a lock
	// connection plus a references connection plus its fence connection.
	// Sized independently and small; created from the same DSN.
	fencePoolOnce sync.Once
	fencePool     *pgxpool.Pool
	// fencePoolErr records the FIRST advisory-pool initialization failure.
	// A sync.Once body is skipped on later calls, so an error held only in a
	// closure-local variable would vanish and callers would observe a nil
	// pool with no error.
	fencePoolErr error

	// leaderMu guards the cached leader-session fields only. It is never held
	// across a network round-trip: the liveness probe, the candidate
	// connect/try-lock and the close of a dropped session all run outside it
	// (see TryAcquireLeadership), so one black-holed connection cannot
	// serialize every leadership caller behind a single mutex.
	leaderMu        sync.Mutex
	leaderConn      *pgx.Conn
	leaderKey       string
	leaderHeldUntil time.Time
	// leaderProbedAt is the time of the last successful proof that the cached
	// session is alive: the acquisition round-trip that took the advisory
	// lock, or a later liveness probe.
	leaderProbedAt time.Time
	// leaderProbeWait is non-nil while a liveness probe for the cached session
	// runs outside leaderMu; concurrent callers wait on it (and re-evaluate
	// the cache) instead of stacking duplicate probes.
	leaderProbeWait chan struct{}
	// leaderAcquireMu serializes candidate-session acquisition (connect plus
	// advisory try-lock). The cached hot path never takes it, so a slow or
	// black-holed acquisition cannot block cached leadership calls.
	leaderAcquireMu sync.Mutex
	// leaderEpoch is the leadership epoch this store retains from its own
	// successful advisory-lock acquisition (published on the SAME dedicated
	// session in one transaction, migration 0025). 0 means "retained none":
	// every leader-fenced operation then fails closed with ErrStaleLeader.
	// It is set only by acquisition and cleared on any loss (release, dead
	// session, key change, fence mismatch); it is never decremented, and the
	// durable epoch is only ever advanced with epoch + 1.
	leaderEpoch atomic.Int64

	// repoIdentityRepairHooks is a test-only seam for the repository-identity
	// repair pass (a deterministic barrier for concurrent-writer and
	// mid-batch-failure injection). Production leaves it nil. See
	// repo_identity_repair.go.
	repoIdentityRepairHooks *repoIdentityRepairTestHooks
}

var _ Store = (*PostgresStore)(nil)

// The leader-dispatch chain requires the fenced downstream contract; the
// server fails dispatch closed if a wired DB store does not provide it.
var _ DownstreamLeaderStore = (*PostgresStore)(nil)

// randReader and jsonMarshal are test-only seams over crypto/rand and
// encoding/json. Production always uses the standard library defaults below
// (the var values are never reassigned outside tests); tests override them to
// exercise the fail-closed error branches, which cannot be reached when the
// real randomness source and the real encoder always succeed.
var (
	randReader  io.Reader = rand.Reader
	jsonMarshal           = json.Marshal
)

var (
	_ OutboxStore           = (*PostgresStore)(nil)
	_ ScheduleStore         = (*PostgresStore)(nil)
	_ DeploymentStore       = (*PostgresStore)(nil)
	_ SnapshotStore         = (*PostgresStore)(nil)
	_ ArtifactContractStore = (*PostgresStore)(nil)
	_ QueueReasonStore      = (*PostgresStore)(nil)
	_ DynamicStore          = (*PostgresStore)(nil)
	_ DynamicStoreTx        = (*PostgresStore)(nil)
	_ DownstreamStore       = (*PostgresStore)(nil)
	_ UsageStore            = (*PostgresStore)(nil)
	_ RunDownstreamStore    = (*PostgresStore)(nil)
	_ ArtifactLookupStore   = (*PostgresStore)(nil)
	_ RunnerJobStore        = (*PostgresStore)(nil)
	_ RunEnqueueStore       = (*PostgresStore)(nil)
	_ AtomicLeaseStore      = (*PostgresStore)(nil)
	_ QuotaCounterStore     = (*PostgresStore)(nil)
	_ CacheManifestStore    = (*PostgresStore)(nil)
	_ ArtifactSidecarStore  = (*PostgresStore)(nil)
	_ SecretClaimStore      = (*PostgresStore)(nil)
	_ SecretClaimReleaser   = (*PostgresStore)(nil)
	_ OutboxDeadLetterStore = (*PostgresStore)(nil)
	_ ForgeCheckStateStore  = (*PostgresStore)(nil)
	_ RecoveryScanStore     = (*PostgresStore)(nil)
	_ OutboxClaimBatchStore = (*PostgresStore)(nil)
	_ LeaderFenceStore      = (*PostgresStore)(nil)
)

// NewPostgres opens a pool and verifies connectivity.
func NewPostgres(ctx context.Context, dsn string) (*PostgresStore, error) {
	return NewPostgresOpt(ctx, dsn)
}

// PostgresOption mutates the pool configuration before the pool opens.
type PostgresOption func(*pgxpool.Config)

// WithMaxConnections caps the connection pool size (wired from
// database.max_connections). Values <= 0 keep the pgxpool default.
func WithMaxConnections(n int) PostgresOption {
	return func(c *pgxpool.Config) {
		if n > 0 {
			c.MaxConns = int32(n)
		}
	}
}

// NewPostgresOpt opens a pool like NewPostgres but applies opts to the
// pool configuration first, and verifies connectivity.
func NewPostgresOpt(ctx context.Context, dsn string, opts ...PostgresOption) (*PostgresStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: parse dsn: %w", err)
	}
	for _, o := range opts {
		o(cfg)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("storage: open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("storage: ping: %w", err)
	}
	st := &PostgresStore{pool: pool}
	// Eager advisory-pool initialization: a startup failure surfaces here
	// instead of during the first fenced operation.
	if _, err := st.advisoryPool(); err != nil {
		pool.Close()
		return nil, err
	}
	return st, nil
}

// NewPostgresFromPool adopts an existing pool (tests, wiring). The fence
// pool is derived from the pool's DSN on first use.
func NewPostgresFromPool(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// advisoryPool returns the dedicated advisory-lock pool, creating it from
// the operational pool's configuration on first use. A dedicated pool can
// never be exhausted by ordinary operations.
//
// The advisory pool must connect EXACTLY like the operational pool: the
// leadership epoch is stored in leader_fence (a schema-qualified relation in
// production; a per-test search_path schema in integration tests) and the
// CAS GC lease transaction reads it, so the pool copies the operational
// ConnConfig (hosts, TLS, credentials, RuntimeParams such as search_path)
// rather than re-parsing the original DSN, which would silently drop
// programmatic connection settings.
func (s *PostgresStore) advisoryPool() (*pgxpool.Pool, error) {
	s.fencePoolOnce.Do(func() {
		dsn := ""
		if s.pool != nil && s.pool.Config() != nil {
			dsn = s.pool.Config().ConnString()
		}
		if dsn == "" {
			s.fencePoolErr = fmt.Errorf("storage: cannot derive a DSN for the advisory-lock pool")
			return
		}
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			s.fencePoolErr = fmt.Errorf("storage: parse dsn for advisory pool: %w", err)
			return
		}
		if src := s.pool.Config(); src != nil && src.ConnConfig != nil {
			cfg.ConnConfig = src.ConnConfig.Copy()
		}
		// Explicit cap: the lock pool exists to be INDEPENDENT of the
		// operational pool, not to mirror its size.
		cfg.MaxConns = 4
		cfg.MinConns = 1
		pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
		if err != nil {
			s.fencePoolErr = fmt.Errorf("storage: open advisory pool: %w", err)
			return
		}
		if err := pool.Ping(context.Background()); err != nil {
			pool.Close()
			s.fencePoolErr = fmt.Errorf("storage: ping advisory pool: %w", err)
			return
		}
		s.fencePool = pool
	})
	if s.fencePoolErr != nil {
		return nil, s.fencePoolErr
	}
	if s.fencePool == nil {
		return nil, fmt.Errorf("storage: advisory pool unavailable")
	}
	return s.fencePool, nil
}

func (s *PostgresStore) Close() error {
	if s.fencePool != nil {
		s.fencePool.Close()
		s.fencePool = nil
	}
	s.leaderMu.Lock()
	// Closing the session releases its advisory lock; clear the whole cache
	// first so a (mis)use after Close cannot observe a stale held-leadership
	// view. The close itself runs outside leaderMu under its own bound.
	conn := s.detachLeaderSessionLocked()
	s.leaderMu.Unlock()
	s.closeLeaderConn(conn)
	s.pool.Close()
	return nil
}

// ---------------------------------------------------------------------------
// column lists and scanners. The expression lists below are shared between
// SELECT and RETURNING so scanned jobs/runs/runners are always complete.
// ---------------------------------------------------------------------------

const jobCols = "id, run_id, key, status, dependency_status, priority, attempts, COALESCE(error, ''), COALESCE(outputs, '{}'::jsonb), COALESCE(lease_runner_id, ''), COALESCE(lease_token_hash, ''::bytea), lease_generation, lease_expires_at, started_at, finished_at, created_at, payload"

type jobScanner struct {
	id, runID, key        string
	status, depStatus     string
	priority, attempts    int
	errMsg                string
	outputsJSON           []byte
	leaseRunnerID         string
	leaseTokenHash        []byte
	leaseGeneration       int64
	leaseExpiresAt        *time.Time
	startedAt, finishedAt *time.Time
	createdAt             time.Time
	payload               []byte
}

// jobTargets returns the scan targets matching the jobCols expression list.
func jobTargets(js *jobScanner) []any {
	return []any{
		&js.id, &js.runID, &js.key, &js.status, &js.depStatus,
		&js.priority, &js.attempts,
		&js.errMsg, &js.outputsJSON,
		&js.leaseRunnerID, &js.leaseTokenHash, &js.leaseGeneration,
		&js.leaseExpiresAt, &js.startedAt, &js.finishedAt, &js.createdAt,
		&js.payload,
	}
}

func (js *jobScanner) job() (model.Job, error) {
	j := model.Job{}
	if err := json.Unmarshal(js.payload, &j); err != nil {
		return j, fmt.Errorf("storage: decode job payload: %w", err)
	}
	j.ID = js.id
	j.RunID = js.runID
	j.Key = js.key
	j.Status = model.Status(js.status)
	j.DependencyStatus = model.Status(js.depStatus)
	j.Priority = js.priority
	j.Attempts = js.attempts
	j.Error = js.errMsg
	j.LeaseRunnerID = js.leaseRunnerID
	j.LeaseTokenHash = js.leaseTokenHash
	if len(j.LeaseTokenHash) == 0 {
		j.LeaseTokenHash = nil
	}
	j.LeaseGeneration = js.leaseGeneration
	j.LeaseExpiresAt = js.leaseExpiresAt
	j.StartedAt = js.startedAt
	j.FinishedAt = js.finishedAt
	j.CreatedAt = js.createdAt
	if len(js.outputsJSON) > 0 {
		m := map[string]string{}
		if err := json.Unmarshal(js.outputsJSON, &m); err != nil {
			return j, fmt.Errorf("storage: decode job outputs: %w", err)
		}
		if len(m) > 0 {
			j.Outputs = m
		}
	}
	return j, nil
}

const runCols = "id, status, started_at, finished_at, created_at, payload"

func scanRun(row pgx.Row) (model.Run, error) {
	var (
		run        model.Run
		status     string
		startedAt  *time.Time
		finishedAt *time.Time
		payload    []byte
	)
	err := row.Scan(&run.ID, &status, &startedAt, &finishedAt, &run.CreatedAt, &payload)
	if err != nil {
		return run, err
	}
	if err := json.Unmarshal(payload, &run); err != nil {
		return run, fmt.Errorf("storage: decode run payload: %w", err)
	}
	run.Status = model.Status(status)
	run.StartedAt = startedAt
	run.FinishedAt = finishedAt
	return run, nil
}

const runnerCols = "id, busy, capacity, completed, failed, COALESCE(current_job, ''), COALESCE(active_jobs, '[]'::jsonb), registered, last_seen, payload"

type runnerScanner struct {
	id         string
	busy       bool
	capacity   int
	completed  int64
	failed     int64
	currentJob string
	activeJSON []byte
	registered *time.Time
	lastSeen   *time.Time
	payload    []byte
}

func (rs *runnerScanner) targets() []any {
	return []any{&rs.id, &rs.busy, &rs.capacity, &rs.completed, &rs.failed, &rs.currentJob, &rs.activeJSON, &rs.registered, &rs.lastSeen, &rs.payload}
}

func (rs *runnerScanner) runner() (model.Runner, error) {
	r := model.Runner{}
	if err := json.Unmarshal(rs.payload, &r); err != nil {
		return r, fmt.Errorf("storage: decode runner payload: %w", err)
	}
	r.ID = rs.id
	r.Busy = rs.busy
	r.Capacity = rs.capacity
	r.Completed = rs.completed
	r.Failed = rs.failed
	r.CurrentJob = rs.currentJob
	if len(rs.activeJSON) > 0 {
		var active []string
		if err := json.Unmarshal(rs.activeJSON, &active); err != nil {
			return r, fmt.Errorf("storage: decode runner active jobs: %w", err)
		}
		r.ActiveJobs = active
	}
	if rs.registered != nil {
		r.Registered = *rs.registered
	}
	if rs.lastSeen != nil {
		r.LastSeen = *rs.lastSeen
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// quota reservation counters
// ---------------------------------------------------------------------------

// quotaKeys derives the reservation counter keys for one canonical
// repository identity (legacy URL inputs derive the same pair), mirroring
// the server's team derivation. Deduplicated when both keys coincide.
func quotaKeys(repoID string) []string {
	return QuotaKeys(repoID)
}

// adjustQuotaTx shifts the reserved running/queued counters for one
// canonical repository identity inside a transaction. Counters clamp at
// zero; a missing reservation row (job predates quota accounting) is
// tolerated.
func (s *PostgresStore) adjustQuotaTx(ctx context.Context, tx pgx.Tx, repoID string, runningDelta, queuedDelta int) error {
	for _, key := range quotaKeys(repoID) {
		if _, err := tx.Exec(ctx, `UPDATE quota_reservations SET running = GREATEST(running + $2, 0), queued = GREATEST(queued + $3, 0), updated_at = now() WHERE key = $1`, key, runningDelta, queuedDelta); err != nil {
			return err
		}
	}
	return nil
}

// reserveQuotaTx locks the repo/team counter rows and increments the queued
// count by jobCount, then re-enforces the limits against the locked values
// (closing the check-then-reserve race). A violation returns
// *QuotaExceededError and rolls the transaction back.
func (s *PostgresStore) reserveQuotaTx(ctx context.Context, tx pgx.Tx, q *QuotaReservation) error {
	if q == nil {
		return nil
	}
	keys := []string{q.RepoKey}
	if q.TeamKey != "" && q.TeamKey != q.RepoKey {
		keys = append(keys, q.TeamKey)
	}
	jobCount := q.JobCount
	if jobCount < 0 {
		jobCount = 0
	}
	// Lock each row via the upsert and read the post-increment values.
	for _, key := range keys {
		var running, queued int
		if err := tx.QueryRow(ctx, `INSERT INTO quota_reservations (key, running, queued) VALUES ($1, 0, $2) ON CONFLICT (key) DO UPDATE SET queued = quota_reservations.queued + EXCLUDED.queued, updated_at = now() RETURNING running, queued`,
			key, jobCount).Scan(&running, &queued); err != nil {
			return err
		}
		limitCheck := func(isTeam bool) error {
			var runningLimit, queueLimit float64
			if isTeam {
				runningLimit, queueLimit = q.TeamConcurrency, q.TeamQueueDepth
			} else {
				runningLimit, queueLimit = q.RepoConcurrency, q.RepoQueueDepth
			}
			reason := "REPO_QUOTA"
			scope := "repository"
			if isTeam {
				reason = "TEAM_QUOTA"
				scope = "team"
			}
			if runningLimit > 0 && float64(running) >= runningLimit {
				return &QuotaExceededError{Reason: reason, Msg: fmt.Sprintf("%s already has %d running job(s), concurrency limit %g", scope, running, runningLimit)}
			}
			if queueLimit > 0 && float64(queued) > queueLimit {
				return &QuotaExceededError{Reason: reason, Msg: fmt.Sprintf("%s queue depth would reach %d, limit %g", scope, queued, queueLimit)}
			}
			return nil
		}
		if err := limitCheck(key == q.TeamKey); err != nil {
			return err
		}
	}
	return nil
}

// InsertCompiledRun implements the atomic enqueue: one transaction inserts
// the run, every job, the dependency edges, the artifact contracts, cancels
// the superseded jobs and runs with audit rows and dependent recomputation,
// and claims the delivery/quota/schedule/downstream-launch reservations. Any
// failure rolls everything back.
//
// Leadership fencing: a request carrying a ScheduleClaim or a
// DownstreamLaunch is leader-only work (a fired occurrence, a downstream
// child launch) and its transaction is epoch-FENCED before the first insert,
// so a stale leader commits none of it. A request carrying neither claim is
// an ordinary submission and is deliberately not fenced.
//
// Concurrency-group supersession is resolved INSIDE the transaction: when
// req.Supersede names a (repository, concurrency group) pair, the conflicting
// non-terminal runs are selected under a per-key advisory lock, so
// concurrent superseding enqueues serialize: the last committed run wins and
// every earlier one is cancelled in the same commit that publishes it.
func (s *PostgresStore) InsertCompiledRun(ctx context.Context, req InsertCompiledRunRequest) error {
	if err := ValidateRunID(req.Run.ID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Two kinds of claim make this enqueue leader-only work, so it is
	// epoch-FENCED before anything is inserted:
	//
	//   - a schedule occurrence claim: the fired run and its
	//     (schedule, nominal) occurrence commit together, so a stale leader
	//     fires no schedule;
	//   - a downstream launch claim: the child run, the link update
	//     (child_run_id + stable key, reservation consumed) and every other
	//     enqueue mutation commit together, so a stale leader launches no
	//     downstream child and cannot even create the child run.
	//
	// Ordinary submissions carry neither claim and are not leader-gated, so
	// they are deliberately not fenced.
	if req.ScheduleClaim != nil || req.DownstreamLaunch != nil {
		if err := s.fenceLeaderTx(ctx, tx); err != nil {
			return err
		}
	}

	// The downstream launch claim is resolved BEFORE the run row is
	// inserted: a link already launched with the SAME stable child ID
	// rolls the enqueue back with ErrDownstreamLaunched (the caller
	// re-reads the existing child run), while a conflicting child ID fails
	// closed.
	if req.DownstreamLaunch != nil {
		if err := s.claimDownstreamLaunchTx(ctx, tx, req.DownstreamLaunch, req.Run.ID); err != nil {
			return err
		}
	}
	if err := s.insertRunTx(ctx, tx, req.Run); err != nil {
		return err
	}
	for id, j := range req.Jobs {
		if err := ValidateJobID(id); err != nil {
			return err
		}
		if err := ValidateRunID(j.RunID); err != nil {
			return err
		}
		j.Needs = effectiveNeeds(id, j, req.Deps)
		if err := s.insertJobRowTx(ctx, tx, j); err != nil {
			return err
		}
	}
	for id, j := range req.Jobs {
		j.Needs = effectiveNeeds(id, j, req.Deps)
		if err := s.replaceDependenciesTx(ctx, tx, j); err != nil {
			return err
		}
	}
	for id, contracts := range req.Contracts {
		if err := ValidateJobID(id); err != nil {
			return err
		}
		cp, err := jsonMarshal(contracts)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE jobs SET payload = jsonb_set(payload, '{artifact_contracts}', $2::jsonb, true) WHERE id=$1`, id, cp); err != nil {
			return err
		}
	}
	if req.Supersede != nil {
		superseded, err := s.supersededJobIDsTx(ctx, tx, req.Supersede, req.Run.ID)
		if err != nil {
			return err
		}
		if err := s.cancelSupersededTx(ctx, tx, superseded, req.Run.ID); err != nil {
			return err
		}
	}
	if err := s.cancelSupersededTx(ctx, tx, req.CancelPrevious, req.Run.ID); err != nil {
		return err
	}
	if req.WebhookClaim != nil {
		if err := s.insertWebhookClaimTx(ctx, tx, req.WebhookClaim); err != nil {
			return err
		}
	}
	if err := s.reserveQuotaTx(ctx, tx, req.Quota); err != nil {
		return err
	}
	if req.ScheduleClaim != nil {
		if err := s.insertScheduleClaimTx(ctx, tx, req.ScheduleClaim, req.Run.ID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// advisoryLockKey derives a stable 64-bit PostgreSQL advisory-lock key for a
// logical resource: sha256 over the kind and the parts, each prefixed with a
// NUL separator, truncated to the first 8 digest bytes in big-endian order.
// The NULs only ever live inside the HASH INPUT, so the value bound to SQL is
// a plain int64: records or group names containing arbitrary bytes (including
// NUL, which the server rejects as text with SQLSTATE 22021) still serialize
// on a well-defined key. Distinct (kind, parts) tuples collide only with
// probability ~2^-64.
func advisoryLockKey(kind string, parts ...string) int64 {
	h := sha256.New()
	h.Write([]byte(kind))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	sum := h.Sum(nil)
	return int64(binary.BigEndian.Uint64(sum[:8]))
}

// canonicalRepoIDSQLExpr renders the SQL expression that resolves the
// canonical repository identity of a runs/jobs payload EXACTLY like
// RepoIDFor / RepoIDForRun / RepoIDForJob: the stored repo_id is
// authoritative; a legacy payload (no repo_id) derives "<host>/<full name>"
// from its clone URL — runs persist the clone URL as "repo", jobs as
// "repo_url" — plus repo_full_name, itself recovered from the URL path when
// the record carries none. The host/path extraction mirrors
// RepoHost/RepoFullNameFromURL for the scheme (https://host/o/r.git),
// ssh://git@host/o/r and scp-like (git@host:o/r) forms, so a row written
// before RepoID existed compares EQUAL to a modern row for the same
// repository even when the two spell the clone URL differently, and two
// repositories that merely share a name on different hosts or forges never
// compare equal. Host and full name are trimmed; an empty repo_id and an
// unparseable URL resolve to "".
//
// The expression is bound through the IMMUTABLE SQL function
// kiwi_canonical_repo_id(payload, url_key) created by migration 0027 (see
// canonicalRepoIDFunctionBody). The LONG form is deliberately not inlined:
// PostgreSQL's pg_index catalog row cannot hold the parsed expression tree
// (row is too big), so an expression INDEX must name the function while
// every query compares through the same call, keeping index and predicate
// expression-identical.
func canonicalRepoIDSQLExpr(urlKey string) string {
	return canonicalRepoIDSQLExprOn("payload", urlKey)
}

// canonicalRepoIDSQLExprOn is canonicalRepoIDSQLExpr parameterized on the
// jsonb COLUMN expression, so the same identity expression can be rendered
// against a qualified column (r.payload) inside a join. The column expression
// is emitted verbatim; callers pass either "payload" or a qualified name.
func canonicalRepoIDSQLExprOn(col, urlKey string) string {
	return canonicalRepoIDFunctionName + "(" + col + ", '" + urlKey + "')"
}

// canonicalRepoIDFunctionName is the SQL function created by migration 0027.
const canonicalRepoIDFunctionName = "kiwi_canonical_repo_id"

// canonicalRepoIDFunctionBody renders the body of the IMMUTABLE SQL function
// kiwi_canonical_repo_id(payload jsonb, url_key text): exactly the canonical
// repo_id/clone-URL derivation canonicalRepoIDSQLExprOn used to inline, with
// the URL json key bound to the function parameter. Migration 0027 embeds
// this text, so the index expression and every query expression resolve to
// one shape.
func canonicalRepoIDFunctionBody() string {
	return canonicalRepoIDBody("payload->>url_key")
}

// canonicalRepoIDBody is canonicalRepoIDFunctionBody parameterized on the URL
// json accessor so the migration generator and the tests can render it. The
// resolved identity is folded onto the one canonical PATH case (see
// foldRepoIdentitySQL / auth.FoldRepoFullName): the stored repo_id and the
// clone-URL + repo_full_name derivation both resolve to the folded form, so a
// row written from repo_url=https://github.com/Acme/Backend.git resolves to
// github.com/acme/backend and can never bypass an explicit lowercase deny.
func canonicalRepoIDBody(urlAccessor string) string {
	u := "COALESCE(" + urlAccessor + ", '')"
	f := "BTRIM(COALESCE(payload->>'repo_full_name', ''))"
	scpLike := "STRPOS(" + u + ", ':') > 0 AND (STRPOS(" + u + ", '/') = 0 OR STRPOS(" + u + ", '/') > STRPOS(" + u + ", ':'))"
	host := "CASE WHEN STRPOS(" + u + ", '://') > 0 " +
		"THEN REGEXP_REPLACE(SPLIT_PART(SUBSTRING(" + u + " FROM STRPOS(" + u + ", '://') + 3), '/', 1), '^.*@', '') " +
		"WHEN " + scpLike + " THEN REGEXP_REPLACE(SPLIT_PART(" + u + ", ':', 1), '^.*@', '') " +
		"ELSE REGEXP_REPLACE(SPLIT_PART(" + u + ", '/', 1), '^.*@', '') END"
	path := "BTRIM(REGEXP_REPLACE(CASE WHEN STRPOS(" + u + ", '://') > 0 " +
		"THEN COALESCE(SUBSTRING(SUBSTRING(" + u + " FROM STRPOS(" + u + ", '://') + 3) FROM '/(.*)$'), '') " +
		"WHEN " + scpLike + " THEN SUBSTRING(" + u + " FROM STRPOS(" + u + ", ':') + 1) " +
		"ELSE " + u + " END, '\\.git$', ''), '/')"
	full := "CASE WHEN " + f + " <> '' THEN " + f + " ELSE " + path + " END"
	base := "COALESCE(NULLIF(BTRIM(payload->>'repo_id'), ''), " +
		"CASE WHEN " + full + " = '' THEN '' " +
		"WHEN " + host + " = '' OR LEFT(" + full + ", LENGTH(" + host + ") + 1) = " + host + " || '/' THEN " + full + " " +
		"ELSE " + host + " || '/' || " + full + " END)"
	return foldRepoIdentitySQL(base)
}

// foldRepoIdentitySQL renders the SQL that folds a resolved repository
// identity onto the one canonical PATH case, mirroring auth.FoldRepoFullName:
// ASCII-lowercase the full-name portion while PRESERVING the forge host (which
// CanonicalHost canonicalizes separately), and never touch the explicit r1:/
// a1: serialized spellings (their base64url payload is case-significant). The
// positional rule is used, not dots: a value with two or more path segments is
// host/full and only the remainder is folded; a bare value is folded whole.
func foldRepoIdentitySQL(expr string) string {
	slash := "STRPOS(" + expr + ", '/')"
	suffix := "SUBSTRING(" + expr + " FROM " + slash + " + 1)"
	return "CASE WHEN LEFT(" + expr + ", 3) IN ('r1:', 'a1:') THEN " + expr +
		" WHEN " + slash + " = 0 THEN LOWER(" + expr + ")" +
		" WHEN STRPOS(" + suffix + ", '/') > 0 THEN LEFT(" + expr + ", " + slash + " - 1) || '/' || LOWER(" + suffix + ")" +
		" ELSE LOWER(" + expr + ") END"
}

// canonicalPolicyRepoIDSQLExpr renders the POLICY-FIRST canonical repository
// identity of a payload: the stored policy_repo_id (the BASE repository of a
// fork PR, which every authorization/quota/history decision uses) when
// present, otherwise canonicalRepoIDSQLExpr's repo_id/clone-URL derivation.
// It is the SQL mirror of RepoIDForRun / RepoIDForJob, so a row written
// before RepoID existed (only repo + repo_full_name) resolves to the same
// canonical ID as a modern row and is never silently excluded from an
// identity-scoped read or join. The expression is short enough to back the
// migration-0027 runs_repo_identity_idx expression index.
func canonicalPolicyRepoIDSQLExpr(urlKey string) string {
	return canonicalPolicyRepoIDSQLExprOn("payload", urlKey)
}

// canonicalPolicyRepoIDSQLExprOn is canonicalPolicyRepoIDSQLExpr
// parameterized on the jsonb column expression (see canonicalRepoIDSQLExprOn).
func canonicalPolicyRepoIDSQLExprOn(col, urlKey string) string {
	return "COALESCE(NULLIF(BTRIM(" + col + "->>'policy_repo_id'), ''), " + canonicalRepoIDSQLExprOn(col, urlKey) + ")"
}

// supersededJobIDsTx resolves the supersede policy to the concrete
// non-terminal job IDs of every conflicting run. The per-(canonical
// repository identity, concurrency group) advisory transaction lock is taken
// FIRST, so concurrent superseding enqueues of one group serialize: a
// transaction entering the section only sees runs whose insert already
// committed, and its cancellation commits atomically with its own run. The
// conflicting runs are selected by the CANONICAL repo_id of their payload
// (legacy rows: derived from the clone URL + full name, see
// canonicalRepoIDSQLExpr), so the same repository submitted via HTTPS and
// via SSH supersedes — a clone-URL comparison would not. The new run is
// excluded by ID (its jobs must never be cancelled by its own enqueue).
func (s *PostgresStore) supersededJobIDsTx(ctx context.Context, tx pgx.Tx, p *SupersedePolicy, newRunID string) ([]string, error) {
	repoID := strings.TrimSpace(p.RepoID)
	group := strings.TrimSpace(p.ConcurrencyGroup)
	if repoID == "" || group == "" {
		return nil, nil
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockKey("kiwi-supersede", repoID, group)); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT id FROM runs WHERE id<>$3 AND `+canonicalRepoIDSQLExpr("repo")+`=$1 AND payload->>'concurrency_group'=$2 AND NOT (status IN ('success', 'failure', 'cancelled', 'skipped', 'blocked')) ORDER BY created_at ASC, id ASC`,
		repoID, group, newRunID)
	if err != nil {
		return nil, err
	}
	runIDs := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		runIDs = append(runIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	jobIDs := []string{}
	for _, runID := range runIDs {
		jrows, err := tx.Query(ctx, `SELECT id FROM jobs WHERE run_id=$1 AND NOT (status IN ('success', 'failure', 'cancelled', 'skipped', 'blocked')) ORDER BY id ASC`, runID)
		if err != nil {
			return nil, err
		}
		for jrows.Next() {
			var id string
			if err := jrows.Scan(&id); err != nil {
				jrows.Close()
				return nil, err
			}
			jobIDs = append(jobIDs, id)
		}
		jrows.Close()
		if err := jrows.Err(); err != nil {
			return nil, err
		}
	}
	return jobIDs, nil
}

// insertRunTx inserts the run row inside an open transaction.
func (s *PostgresStore) insertRunTx(ctx context.Context, tx pgx.Tx, run model.Run) error {
	payload, err := jsonMarshal(run)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO runs (id, status, started_at, finished_at, created_at, `+normalizedRunRepoIdentityColumn+`, `+normalizedRunRepoFullNameColumn+`, payload) VALUES ($1, $2, $3, $4, $5, `+normalizedRunRepoIdentitySQL("$6")+`, `+normalizedRunRepoFullNameSQL("$6")+`, $6)`,
		run.ID, string(run.Status), run.StartedAt, run.FinishedAt, run.CreatedAt, payload)
	return err
}

// cancelSupersededTx cancels the superseded jobs (concurrency-group
// cancel-in-progress) with audit rows, inside the enqueue transaction. Every
// cancelled job's dependents are re-evaluated in the same transaction
// (blocked when their condition does not allow the cancelled outcome,
// mirroring the in-memory cancel-then-schedule pass), and the superseded
// runs themselves are marked cancelled in the same commit, so supersession
// is never observable as "jobs cancelled but run still active".
func (s *PostgresStore) cancelSupersededTx(ctx context.Context, tx pgx.Tx, jobIDs []string, newRunID string) error {
	now := time.Now().UTC()
	cancelledRuns := map[string]struct{}{}
	cancelled := make([]string, 0, len(jobIDs))
	for _, id := range jobIDs {
		if err := ValidateJobID(id); err != nil {
			return err
		}
		var (
			payload       []byte
			status        string
			runID         string
			key           string
			leaseRunnerID string
		)
		err := tx.QueryRow(ctx, `SELECT payload, status, run_id, key, COALESCE(lease_runner_id, '') FROM jobs WHERE id=$1 FOR UPDATE`, id).Scan(&payload, &status, &runID, &key, &leaseRunnerID)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if model.Status(status).Terminal() {
			continue
		}
		var j model.Job
		if err := json.Unmarshal(payload, &j); err != nil {
			return err
		}
		reason := "superseded by run " + newRunID
		wasRunning := model.Status(status) == model.StatusRunning
		// The lease_runner_id COLUMN is authoritative (the same source
		// CompleteJob, CancelRunJobs and ListJobsByRunner read); the payload
		// copy is only a legacy fallback for rows written before the column
		// existed, since the lease paths update the column without rewriting
		// the payload.
		runnerID := leaseRunnerID
		if runnerID == "" {
			runnerID = j.LeaseRunnerID
		}
		j.Status = model.StatusCancelled
		j.Error = reason
		j.FinishedAt = &now
		j.LeaseRunnerID = ""
		j.LeaseTokenHash = nil
		j.LeaseExpiresAt = nil
		jp, err := jsonMarshal(j)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE jobs SET status='cancelled', error=$2, finished_at=$3, lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL, payload=$4 WHERE id=$1`,
			id, reason, now, jp); err != nil {
			return err
		}
		// The cancelled job releases its runner slot in the SAME
		// transaction: a superseded running job must never leave its
		// runner's active_jobs entry behind. Its resource reservation is
		// released in the same step (idempotent no-op for queued jobs).
		if err := releaseResourcesTx(ctx, tx, id); err != nil {
			return err
		}
		if wasRunning && runnerID != "" {
			if err := s.releaseRunnerSlotTx(ctx, tx, runnerID, id); err != nil {
				return err
			}
		}
		auditID, err := newID()
		if err != nil {
			return err
		}
		meta := []byte(`{"job":` + strconv.Quote(key) + `}`)
		if _, err := tx.Exec(ctx, `INSERT INTO audit_events (id, action, actor, run_id, job_id, message, metadata, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			auditID, "job.superseded", "scheduler", runID, id, "cancelled", meta, now); err != nil {
			return err
		}
		// The cancelled job releases its quota slot (running or queued).
		if wasRunning {
			if err := s.adjustQuotaTx(ctx, tx, RepoIDForJob(j), -1, 0); err != nil {
				return err
			}
		} else {
			if err := s.adjustQuotaTx(ctx, tx, RepoIDForJob(j), 0, -1); err != nil {
				return err
			}
		}
		cancelled = append(cancelled, id)
		if runID != "" {
			cancelledRuns[runID] = struct{}{}
		}
	}
	// Dependents recomputed per existing cancel semantics: a queued job
	// needing a superseded job is re-evaluated against the fresh outcome
	// and blocked when its condition does not allow it.
	for _, id := range cancelled {
		if err := s.recomputeDependentsTx(ctx, tx, id, now); err != nil {
			return err
		}
	}
	// The superseded run rows are cancelled in the same commit (mirroring
	// CancelRunJobs), so a superseded run is never left non-terminal while
	// all of its jobs are cancelled.
	for runID := range cancelledRuns {
		if err := s.cancelSupersededRunTx(ctx, tx, runID, now); err != nil {
			return err
		}
	}
	return nil
}

// cancelSupersededRunTx marks one superseded run cancelled inside the
// caller's transaction, preserving its existing start time. A missing or
// already-terminal run row is tolerated.
func (s *PostgresStore) cancelSupersededRunTx(ctx context.Context, tx pgx.Tx, runID string, now time.Time) error {
	var (
		payload []byte
		status  string
	)
	err := tx.QueryRow(ctx, `SELECT payload, status FROM runs WHERE id=$1 FOR UPDATE`, runID).Scan(&payload, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if model.Status(status).Terminal() {
		return nil
	}
	var run model.Run
	if err := json.Unmarshal(payload, &run); err != nil {
		return err
	}
	run.Status = model.StatusCancelled
	run.FinishedAt = &now
	rp, err := jsonMarshal(run)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE runs SET status=$2, finished_at=$3, payload=$4, `+normalizedRunRepoIdentityColumn+`=`+normalizedRunRepoIdentitySQL("$4")+`, `+normalizedRunRepoFullNameColumn+`=`+normalizedRunRepoFullNameSQL("$4")+` WHERE id=$1`, runID, string(model.StatusCancelled), now, rp)
	return err
}

// insertWebhookClaimTx inserts the delivery-dedupe claim with ON CONFLICT
// DO NOTHING; a conflict means the delivery was already processed and the
// transaction fails with ErrDeliveryDuplicate.
func (s *PostgresStore) insertWebhookClaimTx(ctx context.Context, tx pgx.Tx, c *WebhookClaim) error {
	if c.Forge == "" || c.DeliveryID == "" {
		return fmt.Errorf("storage: incomplete webhook claim")
	}
	if err := ValidateRunID(c.RunID); err != nil {
		return err
	}
	ct, err := tx.Exec(ctx, `INSERT INTO webhook_deliveries (forge, delivery_id, run_id, payload_digest) VALUES ($1, $2, $3, $4) ON CONFLICT (forge, delivery_id) DO NOTHING`,
		c.Forge, c.DeliveryID, c.RunID, nullText(c.PayloadDigest))
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrDeliveryDuplicate
	}
	return nil
}

// insertScheduleClaimTx inserts the schedule occurrence claim in the same
// transaction as the run; a conflicting run ID fails the enqueue with
// ErrScheduleClaimLost so only a committed run consumes the nominal.
func (s *PostgresStore) insertScheduleClaimTx(ctx context.Context, tx pgx.Tx, c *ScheduleClaim, runID string) error {
	if c.ScheduleID == "" {
		return fmt.Errorf("storage: empty schedule id")
	}
	ct, err := tx.Exec(ctx, `INSERT INTO schedule_occurrences (schedule_id, nominal, run_id) VALUES ($1, $2, $3) ON CONFLICT (schedule_id, nominal) DO NOTHING`,
		c.ScheduleID, c.Nominal, runID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 1 {
		return nil
	}
	var existing string
	if err := tx.QueryRow(ctx, `SELECT run_id FROM schedule_occurrences WHERE schedule_id=$1 AND nominal=$2`, c.ScheduleID, c.Nominal).Scan(&existing); err != nil {
		return err
	}
	if existing != runID {
		return ErrScheduleClaimLost
	}
	return nil
}

// claimDownstreamLaunchTx resolves the downstream launch claim inside the
// enqueue transaction. The link row is locked FOR UPDATE: an unlaunched
// link is marked launched with the stable child ID (reservation consumed);
// a link already launched with the SAME child ID returns
// ErrDownstreamLaunched so the caller can return the existing run; any
// other state fails closed (the claim was lost to a concurrent flusher).
func (s *PostgresStore) claimDownstreamLaunchTx(ctx context.Context, tx pgx.Tx, c *DownstreamLaunchClaim, childRunID string) error {
	parts := strings.Split(c.LinkKey, "\x00")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return fmt.Errorf("storage: malformed downstream launch claim")
	}
	if len(c.StableChildID) != 64 {
		return fmt.Errorf("storage: malformed downstream stable child id")
	}
	parentJobID, targetRepo, targetRef := parts[0], parts[1], parts[2]
	if err := ValidateJobID(parentJobID); err != nil {
		return err
	}
	if err := ValidateRunID(childRunID); err != nil {
		return err
	}
	var existing string
	err := tx.QueryRow(ctx, `SELECT COALESCE(child_run_id, '') FROM downstream_links WHERE parent_job_id=$1 AND target_repo=$2 AND target_ref=$3 FOR UPDATE`,
		parentJobID, targetRepo, targetRef).Scan(&existing)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("storage: downstream launch claim link missing")
	}
	if err != nil {
		return err
	}
	if existing != "" {
		if existing == childRunID {
			return ErrDownstreamLaunched
		}
		return fmt.Errorf("storage: downstream launch claim lost")
	}
	_, err = tx.Exec(ctx, `UPDATE downstream_links SET child_run_id=$4, stable_child_id=$5, reserved=FALSE, reserved_at=NULL WHERE parent_job_id=$1 AND target_repo=$2 AND target_ref=$3 AND (child_run_id IS NULL OR child_run_id='')`,
		parentJobID, targetRepo, targetRef, childRunID, c.StableChildID)
	return err
}

// ---------------------------------------------------------------------------
// runs
// ---------------------------------------------------------------------------

func (s *PostgresStore) InsertRun(ctx context.Context, run model.Run) error {
	if err := ValidateRunID(run.ID); err != nil {
		return err
	}
	payload, err := jsonMarshal(run)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO runs (id, status, started_at, finished_at, created_at, `+normalizedRunRepoIdentityColumn+`, `+normalizedRunRepoFullNameColumn+`, payload) VALUES ($1, $2, $3, $4, $5, `+normalizedRunRepoIdentitySQL("$6")+`, `+normalizedRunRepoFullNameSQL("$6")+`, $6)`,
		run.ID, string(run.Status), run.StartedAt, run.FinishedAt, run.CreatedAt, payload)
	return err
}

func (s *PostgresStore) GetRun(ctx context.Context, id string) (model.Run, error) {
	if err := ValidateRunID(id); err != nil {
		return model.Run{}, err
	}
	run, err := scanRun(s.pool.QueryRow(ctx, `SELECT `+runCols+` FROM runs WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Run{}, ErrNotFound
	}
	return run, err
}

func (s *PostgresStore) UpdateRunStatus(ctx context.Context, id string, status model.Status, startedAt, finishedAt *time.Time) error {
	if err := ValidateRunID(id); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var payload []byte
	err = tx.QueryRow(ctx, `UPDATE runs SET status=$2, started_at=CASE WHEN $3::timestamptz IS NULL THEN started_at ELSE $3 END, finished_at=CASE WHEN $4::timestamptz IS NULL THEN finished_at ELSE $4 END WHERE id=$1 RETURNING payload`,
		id, string(status), startedAt, finishedAt).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	var run model.Run
	if err := json.Unmarshal(payload, &run); err != nil {
		return err
	}
	run.Status = status
	if startedAt != nil {
		run.StartedAt = startedAt
	}
	if finishedAt != nil {
		run.FinishedAt = finishedAt
	}
	rp, err := jsonMarshal(run)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE runs SET payload=$2, `+normalizedRunRepoIdentityColumn+`=`+normalizedRunRepoIdentitySQL("$2")+`, `+normalizedRunRepoFullNameColumn+`=`+normalizedRunRepoFullNameSQL("$2")+` WHERE id=$1`, id, rp); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) ListRuns(ctx context.Context, limit int) ([]model.Run, error) {
	if limit <= 0 || limit > 10000 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT `+runCols+` FROM runs ORDER BY created_at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Run{}
	for rows.Next() {
		var (
			run        model.Run
			status     string
			startedAt  *time.Time
			finishedAt *time.Time
			payload    []byte
		)
		if err := rows.Scan(&run.ID, &status, &startedAt, &finishedAt, &run.CreatedAt, &payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &run); err != nil {
			return nil, err
		}
		run.Status = model.Status(status)
		run.StartedAt = startedAt
		run.FinishedAt = finishedAt
		out = append(out, run)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// jobs
// ---------------------------------------------------------------------------

// jobWriteArgs marshals a job into the real-column + payload argument list
// used by both INSERT and the upsert path of UpdateJob. queue_deadline is a
// DERIVED index of the payload's QueueDeadline (migration 0021): stamping it
// here keeps the bounded queue-timeout discovery (ListQueueTimedOutJobs, via
// jobs_queue_deadline_recovery_idx) in sync with the authoritative payload
// without touching the payload itself.
func jobWriteArgs(j model.Job) ([]any, error) {
	payload, err := jsonMarshal(j)
	if err != nil {
		return nil, err
	}
	var outputsJSON []byte
	if len(j.Outputs) > 0 {
		if outputsJSON, err = jsonMarshal(j.Outputs); err != nil {
			return nil, err
		}
	}
	return []any{
		j.ID, j.RunID, j.Key, string(j.Status), string(j.DependencyStatus),
		j.Priority, j.Attempts,
		nullText(j.Error), outputsJSON,
		nullText(j.LeaseRunnerID), nullBytes(j.LeaseTokenHash), j.LeaseGeneration,
		j.LeaseExpiresAt, j.StartedAt, j.FinishedAt, j.CreatedAt, j.QueueDeadline, payload,
	}, nil
}

func (s *PostgresStore) insertJobTx(ctx context.Context, tx pgx.Tx, j model.Job) error {
	if err := s.insertJobRowTx(ctx, tx, j); err != nil {
		return err
	}
	return s.replaceDependenciesTx(ctx, tx, j)
}

// insertJobRowTx inserts only the job row (no dependency edges) so the
// atomic enqueue can insert every job before wiring the dependency graph,
// avoiding foreign-key failures when dependency edges are inserted in
// arbitrary map order.
func (s *PostgresStore) insertJobRowTx(ctx context.Context, tx pgx.Tx, j model.Job) error {
	args, err := jobWriteArgs(j)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO jobs (id, run_id, key, status, dependency_status, priority, attempts, error, outputs, lease_runner_id, lease_token_hash, lease_generation, lease_expires_at, started_at, finished_at, created_at, queue_deadline, payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, args...)
	return err
}

func (s *PostgresStore) replaceDependenciesTx(ctx context.Context, tx pgx.Tx, j model.Job) error {
	if _, err := tx.Exec(ctx, `DELETE FROM job_dependencies WHERE job_id=$1`, j.ID); err != nil {
		return err
	}
	for _, dep := range j.Needs {
		if _, err := tx.Exec(ctx, `INSERT INTO job_dependencies (job_id, depends_on) VALUES ($1, $2)`, j.ID, dep); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresStore) InsertJob(ctx context.Context, job model.Job) error {
	if err := ValidateJobID(job.ID); err != nil {
		return err
	}
	if err := ValidateRunID(job.RunID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := s.insertJobTx(ctx, tx, job); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) GetJob(ctx context.Context, id string) (model.Job, error) {
	if err := ValidateJobID(id); err != nil {
		return model.Job{}, err
	}
	js := jobScanner{}
	err := s.pool.QueryRow(ctx, `SELECT `+jobCols+` FROM jobs WHERE id=$1`, id).Scan(jobTargets(&js)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Job{}, ErrNotFound
	}
	if err != nil {
		return model.Job{}, err
	}
	return js.job()
}

func (s *PostgresStore) ListJobsByRun(ctx context.Context, runID string) ([]model.Job, error) {
	if err := ValidateRunID(runID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+jobCols+` FROM jobs WHERE run_id=$1 ORDER BY priority DESC, created_at ASC, id ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Job{}
	for rows.Next() {
		js := jobScanner{}
		if err := rows.Scan(jobTargets(&js)...); err != nil {
			return nil, err
		}
		j, err := js.job()
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// CountRunningJobs returns the number of jobs holding a running lease. One
// aggregate query: the drain count never depends on ListRuns pagination or on
// per-run scans that could be skipped on error, so a DB-mode drain cannot
// conclude "zero active jobs" from an incomplete view.
func (s *PostgresStore) CountRunningJobs(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE status='running'`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// ListJobsByEnvironment returns every job holding one (canonical repository
// identity, environment) key. Jobs are matched on the canonical repo_id of
// their payload; legacy rows without one derive the identity from their
// clone URL + full name (see canonicalRepoIDSQLExpr), so HTTPS and SSH
// spellings of one repository return the same set while same-named
// repositories on different hosts do not.
func (s *PostgresStore) ListJobsByEnvironment(ctx context.Context, repoID, environment string) ([]model.Job, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+jobCols+` FROM jobs WHERE `+canonicalRepoIDSQLExpr("repo_url")+`=$1 AND payload->>'environment'=$2 ORDER BY created_at ASC, id ASC`, repoID, environment)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Job{}
	for rows.Next() {
		js := jobScanner{}
		if err := rows.Scan(jobTargets(&js)...); err != nil {
			return nil, err
		}
		j, err := js.job()
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ListQueuedJobs(ctx context.Context) ([]model.Job, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+jobCols+` FROM jobs WHERE status='queued' ORDER BY priority DESC, created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Job{}
	for rows.Next() {
		js := jobScanner{}
		if err := rows.Scan(jobTargets(&js)...); err != nil {
			return nil, err
		}
		j, err := js.job()
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ListJobsByRunner(ctx context.Context, runnerID string) ([]model.Job, error) {
	if err := ValidateRunnerID(runnerID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+jobCols+` FROM jobs WHERE lease_runner_id=$1 AND status='running' ORDER BY created_at ASC, id ASC`, runnerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Job{}
	for rows.Next() {
		js := jobScanner{}
		if err := rows.Scan(jobTargets(&js)...); err != nil {
			return nil, err
		}
		j, err := js.job()
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateJob(ctx context.Context, job model.Job) error {
	if err := ValidateJobID(job.ID); err != nil {
		return err
	}
	if err := ValidateRunID(job.RunID); err != nil {
		return err
	}
	args, err := jobWriteArgs(job)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO jobs (id, run_id, key, status, dependency_status, priority, attempts, error, outputs, lease_runner_id, lease_token_hash, lease_generation, lease_expires_at, started_at, finished_at, created_at, queue_deadline, payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) ON CONFLICT (id) DO UPDATE SET run_id=EXCLUDED.run_id, key=EXCLUDED.key, status=EXCLUDED.status, dependency_status=EXCLUDED.dependency_status, priority=EXCLUDED.priority, attempts=EXCLUDED.attempts, error=EXCLUDED.error, outputs=EXCLUDED.outputs, lease_runner_id=EXCLUDED.lease_runner_id, lease_token_hash=EXCLUDED.lease_token_hash, lease_generation=EXCLUDED.lease_generation, lease_expires_at=EXCLUDED.lease_expires_at, started_at=EXCLUDED.started_at, finished_at=EXCLUDED.finished_at, created_at=EXCLUDED.created_at, queue_deadline=EXCLUDED.queue_deadline, payload=EXCLUDED.payload`, args...); err != nil {
		return err
	}
	if err := s.replaceDependenciesTx(ctx, tx, job); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ApproveJob approves an environment-gated job in ONE transaction under the
// job row lock. It writes only the approval-owned payload fields and, while
// the job is waiting_approval, the waiting_approval -> queued status; it never
// touches a lease column and never rewrites the whole row from a caller model.
// That makes approve-vs-claim safe: a concurrent AcquireLeaseAtomic either
// commits first (the job is running, so the approval only (re)records the
// approver and the lease, runner slot, quota reservation and resource
// reservation stay consistent) or waits on the lock and then sees the queued
// job.
func (s *PostgresStore) ApproveJob(ctx context.Context, jobID, actor string) (model.Job, error) {
	if err := ValidateJobID(jobID); err != nil {
		return model.Job{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Job{}, err
	}
	defer tx.Rollback(ctx)
	js := jobScanner{}
	err = tx.QueryRow(ctx, `SELECT `+jobCols+` FROM jobs WHERE id=$1 FOR UPDATE`, jobID).Scan(jobTargets(&js)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Job{}, ErrNotFound
	}
	if err != nil {
		return model.Job{}, err
	}
	j, err := js.job()
	if err != nil {
		return model.Job{}, err
	}
	if !j.ApprovalRequired {
		return model.Job{}, ErrApprovalNotRequired
	}
	if j.Status.Terminal() {
		return model.Job{}, ErrJobTerminal
	}
	j.ApprovedBy = actor
	if j.Status == model.StatusWaitingApproval {
		j.Status = model.StatusQueued
		j.WaitingSince = nil
	}
	newPayload, err := jsonMarshal(j)
	if err != nil {
		return model.Job{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status=$2, payload=$3 WHERE id=$1`, jobID, string(j.Status), newPayload); err != nil {
		return model.Job{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Job{}, err
	}
	return j, nil
}

var _ JobApprovalStore = (*PostgresStore)(nil)

// ---------------------------------------------------------------------------
// leases
// ---------------------------------------------------------------------------

// AcquireLease is the non-atomic claim used only by callers whose store has
// no AtomicLeaseStore contract: it flips the job row without touching the
// runner, so it reserves NO resource capacity (there is no runner row lock
// to make a check-and-reserve atomic). Every bundled store implements
// AtomicLeaseStore; the scheduler therefore always claims through
// AcquireLeaseAtomic, where the reservation protocol lives.
func (s *PostgresStore) AcquireLease(ctx context.Context, jobID, runnerID string, tokenHash []byte, generation int64, expiresAt time.Time) (model.Job, error) {
	if err := ValidateJobID(jobID); err != nil {
		return model.Job{}, err
	}
	if runnerID == "" {
		return model.Job{}, fmt.Errorf("storage: empty runner id")
	}
	js := jobScanner{}
	// attempts increments exactly once per lease; started_at is stamped on
	// the FIRST lease only (COALESCE) so requeues and lost-runner re-leases
	// preserve the original start time. A quarantined job is denied here too:
	// the durable flag is checked in the claim statement itself.
	err := s.pool.QueryRow(ctx, `UPDATE jobs SET status='running', attempts = attempts + 1, started_at = COALESCE(started_at, now()), lease_runner_id=$2, lease_token_hash=$3, lease_generation=$4, lease_expires_at=$5 WHERE id=$1 AND status='queued' AND COALESCE(payload->>'repo_identity_quarantined','') <> 'true' AND `+LeaseParentRunEligibleSQL+` AND (lease_expires_at IS NULL OR lease_expires_at < now()) RETURNING `+jobCols,
		jobID, runnerID, tokenHash, generation, expiresAt).Scan(jobTargets(&js)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Job{}, ErrLeaseConflict
	}
	if err != nil {
		return model.Job{}, err
	}
	return js.job()
}

// validateClaimText rejects a claim string that cannot be persisted as a
// bound text/jsonb parameter (a NUL byte is invalid in every text parameter
// and in jsonb), before any statement touches the database. The previous
// runner-slot UPDATE failed incidentally when a NUL runtime was bound; this
// keeps that fail-fast behavior explicit now that the runtime is no longer
// bound.
func validateClaimText(field, value string) error {
	if strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("storage: claim %s contains a NUL byte", field)
	}
	return nil
}

// claimQuotaTx moves one reservation slot from queued to running for the
// repository and team keys, CONDITIONALLY: the UPDATE only matches while the
// row is below the configured concurrency limit (limit <= 0 means
// unlimited), so a concurrent claim can never push running over the limit.
// Zero matched rows rolls the caller's lease back with ErrQuotaExceeded.
func (s *PostgresStore) claimQuotaTx(ctx context.Context, tx pgx.Tx, repoID string, repoLimit, teamLimit float64) error {
	keys := quotaKeys(repoID)
	for i, key := range keys {
		limit := repoLimit
		reason, scope := "REPO_QUOTA", "repository"
		if i > 0 {
			limit = teamLimit
			reason, scope = "TEAM_QUOTA", "team"
		}
		// Ensure the counter row exists so the conditional UPDATE has a row
		// to evaluate; the row is then locked by the UPDATE for the rest of
		// the transaction.
		if _, err := tx.Exec(ctx, `INSERT INTO quota_reservations (key, running, queued) VALUES ($1, 0, 0) ON CONFLICT (key) DO NOTHING`, key); err != nil {
			return err
		}
		ct, err := tx.Exec(ctx, `UPDATE quota_reservations SET running = running + 1, queued = GREATEST(queued - 1, 0), updated_at = now() WHERE key = $1 AND ($2::double precision <= 0 OR running < $2::double precision)`,
			key, limit)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return &QuotaExceededError{Reason: reason, Msg: fmt.Sprintf("%s %s already holds the maximum %g running job(s)", scope, key, limit)}
		}
	}
	return nil
}

// AcquireLeaseAtomic claims a queued job and reserves the runner capacity
// slot in ONE transaction. Lock order is job row first, then runner row —
// the same order CompleteJob uses — so lease and completion can never
// deadlock. Inside the transaction:
//
//  1. the environment concurrency slot is reserved under a per-key advisory
//     lock with an in-transaction running-count check;
//  2. the job row is locked and claimed (queued only) with attempts
//     incremented once and started_at stamped on the first lease only;
//  3. the runner row is locked and its live admin state (disabled/draining,
//     capacity, cert serial, registered rates) is read;
//  4. the LIVE profile is resolved through the shared precedence
//     (cert_profile_links when the runner presents a registered serial,
//     runner_profile_links otherwise) so a profile edit takes effect on the
//     next lease for mTLS AND per-runner bearer identities, and its
//     capacity/repo ACL/capabilities/labels/region/rates replace the
//     registration snapshot;
//  5. the frozen usage rates are written into the job payload;
//  6. the job's requested resources are CHECKED AND RESERVED against the
//     runner's remaining resource capacity (live profile max_* first, the
//     registration snapshot second; a zero dimension is unconstrained) and
//     the reservation row is inserted in the same transaction;
//  7. the quota queued->running transition is conditional;
//  8. the runner slot update appends the job and re-asserts disabled/draining,
//     capacity > 0 and the capacity bound in SQL. The scheduling predicates
//     (labels, canonical repository ACL, runtime capability, region) were
//     evaluated in Go over the SAME effective runner view the in-memory claim
//     uses (ClaimAllowsRunner) while this transaction held the runner row
//     lock, so SQL and memory cannot diverge.
//
// Any failed predicate rolls every step back and returns the matching
// sentinel error (ErrNoCapacity, ErrEnvConcurrency, ErrQuotaExceeded,
// ErrResourceCapacity, ErrLeaseConflict).
func (s *PostgresStore) AcquireLeaseAtomic(ctx context.Context, claim LeaseClaim) (model.Job, error) {
	if err := ValidateJobID(claim.JobID); err != nil {
		return model.Job{}, err
	}
	if claim.RunnerID == "" {
		return model.Job{}, fmt.Errorf("storage: empty runner id")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Job{}, err
	}
	defer tx.Rollback(ctx)

	// Reject claim text that cannot be persisted (a NUL byte is invalid in
	// every bound text/jsonb parameter) before touching the database, so a
	// malformed claim fails the same way the previous runner-slot UPDATE did.
	if err := validateClaimText("runtime", claim.Runtime); err != nil {
		return model.Job{}, err
	}
	if err := validateClaimText("canonical repository id", claim.CanonRepoID); err != nil {
		return model.Job{}, err
	}
	if err := validateClaimText("repository full name", claim.RepoFullName); err != nil {
		return model.Job{}, err
	}
	if err := validateClaimText("environment", claim.Environment); err != nil {
		return model.Job{}, err
	}
	for _, l := range claim.RequiredLabels {
		if err := validateClaimText("required label", l); err != nil {
			return model.Job{}, err
		}
	}
	for _, r := range claim.PlacementRegions {
		if err := validateClaimText("placement region", r); err != nil {
			return model.Job{}, err
		}
	}

	// Step 1: lock the job row first (job -> runner ordering, matching
	// CompleteJob) and fail fast when the job is not queued. The durable
	// repo_identity_quarantined payload flag AND the parent-run eligibility
	// predicate are read under the SAME row lock, so a quarantined job — or a
	// queued child of a cancelled/quarantined run — can never be leased even
	// if the claim's Quarantined field was not populated by a direct caller
	// (R1-6/T1-3).
	var (
		jobStatus      string
		jobQuarantined bool
		runEligible    bool
	)
	err = tx.QueryRow(ctx, `SELECT status, COALESCE(payload->>'repo_identity_quarantined','') = 'true', `+LeaseParentRunEligibleSQL+` FROM jobs WHERE id=$1 FOR UPDATE`, claim.JobID).
		Scan(&jobStatus, &jobQuarantined, &runEligible)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Job{}, ErrLeaseConflict
	}
	if err != nil {
		return model.Job{}, err
	}
	if model.Status(jobStatus) != model.StatusQueued {
		return model.Job{}, ErrLeaseConflict
	}
	if jobQuarantined || claim.Quarantined || !runEligible {
		return model.Job{}, ErrNoCapacity
	}

	// Step 2: environment concurrency is reserved inside this transaction:
	// the per-key advisory lock serializes concurrent claims of the same
	// (CANONICAL repository identity, environment) key, and the running count
	// is read after taking the lock, so two polls can never both win the last
	// slot. The count matches the canonical repo_id of each running job
	// (legacy rows: derived from the clone URL + full name), so an HTTPS
	// submission and an SSH submission of one repository share one slot pool.
	if envKey := claim.EnvKey(); envKey != "" && claim.EnvironmentConcurrency > 0 {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockKey("kiwi-env", envKey)); err != nil {
			return model.Job{}, err
		}
		var running int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE status='running' AND `+canonicalRepoIDSQLExpr("repo_url")+`=$1 AND payload->>'environment'=$2 AND id<>$3`,
			claim.CanonRepoID, claim.Environment, claim.JobID).Scan(&running); err != nil {
			return model.Job{}, err
		}
		if running >= claim.EnvironmentConcurrency {
			return model.Job{}, ErrEnvConcurrency
		}
	}

	// Step 3: lock the runner row and read its full registration snapshot
	// (the same model the in-memory store holds) plus its live admin state.
	// The snapshot is the fallback scheduling view for an unlinked runner;
	// reading the whole payload is what lets the claim enforce the SAME
	// snapshot labels/capabilities/region/repository ACL the in-memory claim
	// enforces instead of skipping them when no profile is linked.
	var (
		runnerPayload  []byte
		runnerCapacity int
		runnerDisabled bool
		runnerDraining bool
		activeJSON     []byte
	)
	err = tx.QueryRow(ctx, `SELECT payload, capacity, (disabled OR COALESCE(payload->>'disabled','false') = 'true') AS disabled, (draining OR COALESCE(payload->>'draining','false') = 'true') AS draining, COALESCE(active_jobs, '[]'::jsonb) FROM runners WHERE id=$1 FOR UPDATE`, claim.RunnerID).
		Scan(&runnerPayload, &runnerCapacity, &runnerDisabled, &runnerDraining, &activeJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Job{}, ErrNoCapacity
	}
	if err != nil {
		return model.Job{}, err
	}
	if runnerDisabled || runnerDraining {
		return model.Job{}, ErrNoCapacity
	}
	snapshot := model.Runner{}
	if uerr := json.Unmarshal(runnerPayload, &snapshot); uerr != nil {
		return model.Job{}, fmt.Errorf("storage: decode runner payload: %w", uerr)
	}
	snapshot.ID = claim.RunnerID
	snapshot.Capacity = runnerCapacity
	snapshot.Disabled = runnerDisabled
	snapshot.Draining = runnerDraining
	if uerr := json.Unmarshal(activeJSON, &snapshot.ActiveJobs); uerr != nil {
		return model.Job{}, fmt.Errorf("storage: decode runner active jobs: %w", uerr)
	}

	// Step 4: resolve the LIVE profile through the ONE shared precedence
	// (the explicit certificate-serial binding when the runner presents a
	// registered serial, then the runner_profile_links runner-ID binding,
	// then the registration snapshot) and overlay it onto the registration
	// snapshot. Both bindings are resolved in ONE statement
	// (liveProfileResolutionTx) while the job and runner rows are locked, and
	// the raw states are decided by the same shared precedence helper the
	// scheduler prefilter and the fleet view use. A dangling
	// certificate-serial OR runner-ID binding fails the claim closed; a
	// profile DELETE can therefore neither resurrect a deleted profile nor
	// fail a runner whose snapshot registration already admitted it (the
	// snapshot is never larger than what the binding granted).
	resolution, err := liveProfileResolutionTx(ctx, tx, claim.RunnerID, snapshot.CertSerial)
	if err != nil {
		return model.Job{}, err
	}
	if resolution.DeniesLease() {
		// A runner whose explicitly bound profile vanished takes no work:
		// fail closed.
		return model.Job{}, ErrNoCapacity
	}
	// The EFFECTIVE scheduling view is resolved through the SAME shared
	// overlay the in-memory store uses: the live profile for a linked runner,
	// the registration snapshot unchanged otherwise. The ONE typed predicate
	// (ClaimAllowsRunner -> RepoAllowed/labels/capabilities/region) is then
	// evaluated over it, so an unlinked runner's snapshot restrictions — and
	// the typed positional allowlist rule, "r1:" spellings included — bind the
	// SQL claim exactly as they bind memory.
	effective := ResolveRunnerProfile(snapshot, resolution.Profile, resolution.Applies())
	if !ClaimAllowsRunner(effective, claim) {
		return model.Job{}, ErrNoCapacity
	}
	capacity := effective.Capacity
	// The runner's effective resource capacity: the LIVE profile's max_*
	// columns when linked, the runner row's registration snapshot
	// (payload.resource_capacity) otherwise. Zero dimensions are
	// unconstrained (documented default), so a runner with no configured
	// capacities admits every job exactly as before.
	resourceCapacity := effective.ResourceCapacity
	costRate, powerWatts := effective.CostPerHour, effective.PowerWatts

	// Step 5: claim the job (queued -> running) with attempts/started_at.
	js := jobScanner{}
	err = tx.QueryRow(ctx, `UPDATE jobs SET status='running', attempts = attempts + 1, started_at = COALESCE(started_at, now()), lease_runner_id=$2, lease_token_hash=$3, lease_generation=$4, lease_expires_at=$5 WHERE id=$1 AND status='queued' AND (lease_expires_at IS NULL OR lease_expires_at < now()) RETURNING `+jobCols,
		claim.JobID, claim.RunnerID, claim.TokenHash, claim.Generation, claim.ExpiresAt).Scan(jobTargets(&js)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Job{}, ErrLeaseConflict
	}
	if err != nil {
		return model.Job{}, err
	}
	j, err := js.job()
	if err != nil {
		return model.Job{}, err
	}
	// The job row is held by this transaction: freeze the live usage rates
	// into the payload, and mirror them on the returned job.
	if _, err := tx.Exec(ctx, `UPDATE jobs SET payload = jsonb_set(jsonb_set(payload, '{cost_rate}', to_jsonb($2::double precision), true), '{power_watts}', to_jsonb($3::double precision), true) WHERE id=$1`,
		claim.JobID, costRate, powerWatts); err != nil {
		return model.Job{}, err
	}
	j.CostRate = costRate
	j.PowerWatts = powerWatts

	// Step 6: check-and-reserve the job's requested resources against the
	// runner's remaining capacity. The runner row is locked above, so the
	// reservation SUM cannot move under a concurrent claim for this runner;
	// a failure rolls the whole lease back with ErrResourceCapacity.
	if err := reserveResourcesTx(ctx, tx, claim, resourceCapacity); err != nil {
		return model.Job{}, err
	}

	// Step 7: conditional queued -> running quota transition.
	if err := s.claimQuotaTx(ctx, tx, RepoIDForJob(j), claim.RepoConcurrency, claim.TeamConcurrency); err != nil {
		return model.Job{}, err
	}

	// Step 8: reserve the runner slot. Every scheduling predicate was already
	// evaluated in Go over the locked runner row by ClaimAllowsRunner above
	// (the SAME typed predicate the in-memory claim uses), so this statement
	// is the atomic reservation: it appends the job under the row lock and
	// re-asserts the admin state and the capacity bound. Keeping the capacity
	// comparison in SQL means a peer transaction can never overrun the count
	// between the Go decision and the append.
	ct, err := tx.Exec(ctx, `UPDATE runners SET active_jobs = COALESCE(active_jobs, '[]'::jsonb) || to_jsonb($1::text), busy = TRUE, current_job = CASE WHEN COALESCE(current_job, '') = '' THEN $1 ELSE current_job END, last_seen = now() WHERE id = $2 AND disabled = FALSE AND draining = FALSE AND COALESCE(payload->>'disabled','false') <> 'true' AND COALESCE(payload->>'draining','false') <> 'true' AND $3 > 0 AND jsonb_array_length(COALESCE(active_jobs, '[]'::jsonb)) < $3`,
		claim.JobID, claim.RunnerID, capacity)
	if err != nil {
		return model.Job{}, err
	}
	if ct.RowsAffected() == 0 {
		return model.Job{}, ErrNoCapacity
	}
	if err := tx.Commit(ctx); err != nil {
		return model.Job{}, err
	}
	return j, nil
}

func (s *PostgresStore) HeartbeatLease(ctx context.Context, jobID string, runnerID string, generation int64, expiresAt time.Time) error {
	if err := ValidateJobID(jobID); err != nil {
		return err
	}
	ct, err := s.pool.Exec(ctx, `UPDATE jobs SET lease_expires_at=$4 WHERE id=$1 AND status='running' AND lease_runner_id=$2 AND lease_generation=$3`, jobID, runnerID, generation, expiresAt)
	if err != nil {
		return err
	}
	if ct.RowsAffected() > 0 {
		return nil
	}
	var (
		curGen    int64
		curRunner string
		curStatus string
	)
	err = s.pool.QueryRow(ctx, `SELECT COALESCE(lease_runner_id, ''), lease_generation, status FROM jobs WHERE id=$1`, jobID).Scan(&curRunner, &curGen, &curStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if curGen != generation {
		return ErrGenerationMismatch
	}
	return ErrLeaseConflict
}

// completionReceiptPruneBatch bounds how many receipt rows one prune deletes,
// so the retention cleanup attached to a completion or receipt insert is a
// bounded operation instead of an unbounded table sweep.
const completionReceiptPruneBatch = 1000

// completionReceiptTTLSeconds is CompletionReceiptTTL expressed the way
// make_interval(secs => ...) expects it. Derived from the shared constant so
// there is a single retention source of truth.
var completionReceiptTTLSeconds = CompletionReceiptTTL.Seconds()

// Completion receipt retention is shared with the fs store (see
// CompletionReceiptTTL and MaxCompletionReceipts in fs.go): a receipt is
// honored for replay detection only while it is younger than the TTL, and the
// durable set is bounded to the newest MaxCompletionReceipts entries. Reads
// filter on created_at (using the database clock, the same clock that stamped
// the row) so an aged-out receipt is indistinguishable from a missing one: a
// replayed completion is rejected as a stale lease instead of being
// acknowledged and reconciled, matching fs mode. Writes reclaim expired rows
// opportunistically through the completion_receipts_created_at_idx index.
//
// pruneCompletionReceiptsTx is idempotent and safe under concurrency and
// multi-replica operation: both sweeps are bounded by completionReceiptPruneBatch
// and take FOR UPDATE SKIP LOCKED, so a peer replica deleting the same stale
// rows never blocks this transaction. The TTL sweep runs on every completion
// and receipt insert; the cap sweep runs only when the planner's live-row
// estimate exceeds MaxCompletionReceipts, so the common case pays a cheap
// catalog estimate instead of an OFFSET walk. reltuples is maintained by
// autovacuum ANALYZE, so the cap is enforced within a vacuum cycle rather than
// instantly, and the TTL (the behavior-affecting bound) is enforced exactly.
func pruneCompletionReceiptsTx(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `DELETE FROM completion_receipts WHERE ctid IN (
		SELECT ctid FROM completion_receipts WHERE created_at < now() - make_interval(secs => $1) ORDER BY created_at LIMIT $2 FOR UPDATE SKIP LOCKED
	)`, completionReceiptTTLSeconds, completionReceiptPruneBatch); err != nil {
		return fmt.Errorf("storage: prune completion receipts: %w", err)
	}
	var estimate int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT reltuples::bigint FROM pg_class WHERE oid = to_regclass('completion_receipts')), 0)`).Scan(&estimate); err != nil {
		return fmt.Errorf("storage: completion receipt row estimate: %w", err)
	}
	if estimate <= MaxCompletionReceipts {
		return nil
	}
	if _, err := tx.Exec(ctx, `DELETE FROM completion_receipts WHERE ctid IN (
		SELECT ctid FROM completion_receipts ORDER BY created_at DESC OFFSET $1 LIMIT $2 FOR UPDATE SKIP LOCKED
	)`, MaxCompletionReceipts, completionReceiptPruneBatch); err != nil {
		return fmt.Errorf("storage: cap completion receipts: %w", err)
	}
	return nil
}

// completionReceiptHashTx reads the stored result_hash of the live receipt
// for (jobID, generation, runnerID). The TTL predicate is the same shared
// retention filter HasCompletionReceipt applies: an aged-out receipt reads as
// absent. It returns ("", false, nil) when no live receipt exists. The
// caller must be inside the completion transaction so the read observes the
// same snapshot as the insert/update it guards.
func completionReceiptHashTx(ctx context.Context, tx pgx.Tx, jobID string, generation int64, runnerID string) (string, bool, error) {
	var hash string
	err := tx.QueryRow(ctx, `SELECT result_hash FROM completion_receipts WHERE job_id=$1 AND generation=$2 AND runner_id=$3 AND created_at >= now() - make_interval(secs => $4)`,
		jobID, generation, runnerID, completionReceiptTTLSeconds).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return hash, true, nil
}

// CompleteJob implements the audit item 5 transaction: lock the job FOR
// UPDATE, verify generation+runner+status running, insert the receipt ON
// CONFLICT DO NOTHING, update the job, update runner counters, recompute
// dependent jobs and the run status, and record the audit event.
func (s *PostgresStore) CompleteJob(ctx context.Context, jobID string, generation int64, runnerID string, status model.Status, errMsg string, outputs map[string]string, receipt model.CompletionReceipt) error {
	if err := ValidateJobID(jobID); err != nil {
		return err
	}
	if generation < 0 {
		return fmt.Errorf("storage: invalid lease generation %d", generation)
	}
	// The receipt identity must match the completion identity: the receipt
	// row key is what makes a replay idempotent, so a mismatched receipt
	// would break replay detection instead of failing closed.
	if receipt.JobID != jobID || receipt.Generation != generation || receipt.RunnerID != runnerID {
		return fmt.Errorf("storage: completion receipt identity mismatch")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var (
		curRunID  string
		curKey    string
		curRunner string
		curGen    int64
		curStatus string
		payload   []byte
	)
	err = tx.QueryRow(ctx, `SELECT run_id, key, COALESCE(lease_runner_id, ''), lease_generation, status, payload FROM jobs WHERE id=$1 FOR UPDATE`, jobID).
		Scan(&curRunID, &curKey, &curRunner, &curGen, &curStatus, &payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}

	// Idempotent replay: the exact completion (job, generation, runner) was
	// already applied and its receipt persisted with the SAME result_hash and
	// still within the shared retention TTL; acknowledge it again. An
	// existing receipt with a DIFFERENT result_hash is a conflicting
	// completion of the same lease (two racers, one success and one failure)
	// and fails closed with ErrCompletionConflict instead of letting the
	// loser be acked as a replay. An aged-out receipt is treated as absent
	// (live false) and falls through to the stale-lease errors, matching fs
	// mode.
	if curGen != generation || curRunner != runnerID || curStatus != string(model.StatusRunning) {
		storedHash, live, err := completionReceiptHashTx(ctx, tx, jobID, generation, runnerID)
		if err != nil {
			return err
		}
		if live {
			if storedHash == receipt.ResultHash {
				return tx.Commit(ctx)
			}
			return ErrCompletionConflict
		}
		if curGen != generation || curRunner != runnerID {
			return ErrGenerationMismatch
		}
		return ErrLeaseConflict
	}

	var j model.Job
	if err := json.Unmarshal(payload, &j); err != nil {
		return err
	}
	st := status
	if st != model.StatusSuccess && st != model.StatusFailure && st != model.StatusCancelled && st != model.StatusSkipped {
		st = model.StatusFailure
	}
	// Required-artifact verification INSIDE the completion transaction: a
	// successful completion must have an artifact row for every contract
	// entry with Required=true. A missing artifact fails closed: the whole
	// completion rolls back (the job stays running, not terminal) with
	// ErrRequiredArtifactMissing so the runner can upload the artifact and
	// retry. A read/decode error also rolls the completion back.
	if st == model.StatusSuccess {
		if missing, err := s.requiredArtifactMissingTx(ctx, tx, jobID, generation, payload); err != nil {
			return err
		} else if missing != "" {
			return fmt.Errorf("%w: %s", ErrRequiredArtifactMissing, missing)
		}
	}
	now := time.Now().UTC()
	j.Status = st
	j.Error = errMsg
	j.Outputs = outputs
	j.FinishedAt = &now
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	newPayload, err := jsonMarshal(j)
	if err != nil {
		return err
	}
	outputsJSON, err := jsonMarshal(outputs)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status=$2, error=$3, outputs=$4, finished_at=$5, lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL, payload=$6 WHERE id=$1`,
		jobID, string(st), nullText(errMsg), outputsJSON, now, newPayload); err != nil {
		return err
	}
	// The completed job releases its reserved running slot and its resource
	// reservation (idempotent; a replayed completion never re-inserted one).
	if err := s.adjustQuotaTx(ctx, tx, RepoIDForJob(j), -1, 0); err != nil {
		return err
	}
	if err := releaseResourcesTx(ctx, tx, jobID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO completion_receipts (job_id, generation, runner_id, result_hash) VALUES ($1, $2, $3, $4) ON CONFLICT (job_id, generation, runner_id) DO NOTHING`,
		receipt.JobID, receipt.Generation, receipt.RunnerID, receipt.ResultHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// The receipt identity already exists. Losing the ON CONFLICT race is
		// only an idempotent success when the STORED result_hash equals the
		// incoming one; a different hash means two completions of the same
		// lease disagree, so the whole transaction rolls back with
		// ErrCompletionConflict instead of acking a conflicting result.
		storedHash, live, err := completionReceiptHashTx(ctx, tx, receipt.JobID, receipt.Generation, receipt.RunnerID)
		if err != nil {
			return err
		}
		if live {
			if storedHash == receipt.ResultHash {
				// Exact replay: the previous completion (and all its effects)
				// already committed; discard this transaction's partial
				// updates and acknowledge.
				return nil
			}
			return ErrCompletionConflict
		}
		// The conflicting row has aged out of the retention TTL and would
		// have been reclaimed by pruneCompletionReceiptsTx below: treat it as
		// absent, reclaim it, and retry the insert once.
		if _, err := tx.Exec(ctx, `DELETE FROM completion_receipts WHERE job_id=$1 AND generation=$2 AND runner_id=$3 AND created_at < now() - make_interval(secs => $4)`,
			receipt.JobID, receipt.Generation, receipt.RunnerID, completionReceiptTTLSeconds); err != nil {
			return err
		}
		tag, err = tx.Exec(ctx, `INSERT INTO completion_receipts (job_id, generation, runner_id, result_hash) VALUES ($1, $2, $3, $4) ON CONFLICT (job_id, generation, runner_id) DO NOTHING`,
			receipt.JobID, receipt.Generation, receipt.RunnerID, receipt.ResultHash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			// A concurrent writer re-occupied the key inside this
			// transaction (impossible while the job row is locked): fail
			// closed rather than ack an unverified result.
			return ErrCompletionConflict
		}
	}
	// Reclaim receipts past the shared retention TTL (and, eventually, past
	// the cap) in the same transaction that adds this one.
	if err := pruneCompletionReceiptsTx(ctx, tx); err != nil {
		return err
	}
	if err := s.completeRunnerTx(ctx, tx, runnerID, jobID, st, now); err != nil {
		return err
	}
	if err := s.recomputeDependentsTx(ctx, tx, jobID, now); err != nil {
		return err
	}
	if err := s.recomputeRunTx(ctx, tx, curRunID); err != nil {
		return err
	}
	auditID, err := newID()
	if err != nil {
		return err
	}
	meta := []byte(`{"job":` + strconv.Quote(curKey) + `}`)
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events (id, action, actor, run_id, job_id, message, metadata, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		auditID, "job.completed", runnerID, curRunID, jobID, string(st), meta, now); err != nil {
		return err
	}
	// Post-transaction completion effects ride the SAME transaction as
	// durable outbox intents: downstream dispatch recording, deployment
	// finishing, usage accounting, run aggregation and forge status
	// publishing are triggered by the outbox flush (and the defensive
	// receipt replay), each guarded by its own durable marker.
	if err := s.insertCompletionEffectsTx(ctx, tx, jobID, curRunID, generation, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// insertCompletionEffectsTx inserts the completion's durable effect intents
// inside the caller's transaction: ONE completion_reconcile row (internal
// consistency: markers/effects, retried without dead-lettering until they
// converge) and ONE forge_delivery row (external forge publication, with its
// own backoff/dead-letter policy). Splitting them keeps a persistently
// failing forge from retiring the internal consistency row.
func (s *PostgresStore) insertCompletionEffectsTx(ctx context.Context, tx pgx.Tx, jobID, runID string, generation int64, now time.Time) error {
	payload, err := jsonMarshal(CompletionEffectsPayload{JobID: jobID, RunID: runID})
	if err != nil {
		return err
	}
	kinds := NewCompletionEffectKinds()
	if len(kinds) != CompletionEffectIntentCount {
		// Fail closed instead of silently persisting a different intent set
		// than the contract (and the server's deterministic local copies)
		// promises: the completion transaction is the durability boundary for
		// exactly these rows.
		return fmt.Errorf("storage: completion effect kind table has %d entries, want CompletionEffectIntentCount=%d", len(kinds), CompletionEffectIntentCount)
	}
	// Strict insert: the receipt check inside this transaction already
	// rejects replays, so an occupied reconcile ID means foreign state under
	// a deterministic key — a hard invariant failure that rolls back.
	for _, kind := range kinds {
		if _, err := tx.Exec(ctx, `INSERT INTO outbox (id, kind, payload, created_at) VALUES ($1, $2, $3, $4)`,
			CompletionEffectID(jobID, generation, kind), kind, payload, now); err != nil {
			return err
		}
	}
	return nil
}

// requiredArtifactMissingTx checks the completing job's artifact contracts
// (the payload jsonb key artifact_contracts) against the artifacts table
// inside the caller's transaction and returns the name of the first
// Required contract entry without a matching artifact row FOR THIS LEASE
// GENERATION, or "" when every required artifact is present. The generation
// is part of the artifact idempotency key (job_id, job_generation, name), so
// an artifact uploaded under an earlier generation can no longer satisfy a
// later lease's completion.
func (s *PostgresStore) requiredArtifactMissingTx(ctx context.Context, tx pgx.Tx, jobID string, generation int64, payload []byte) (string, error) {
	var wrapper struct {
		ArtifactContracts map[string]ArtifactContract `json:"artifact_contracts"`
	}
	if err := json.Unmarshal(payload, &wrapper); err != nil {
		return "", err
	}
	for name, c := range wrapper.ArtifactContracts {
		if !c.Required {
			continue
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM artifacts WHERE job_id=$1 AND COALESCE(NULLIF(job_generation,0), CASE WHEN jsonb_typeof(payload->'lease_generation')='number' AND (payload->>'lease_generation') ~ '^[0-9]{1,18}$' THEN (payload->>'lease_generation')::bigint ELSE 0 END) = $2 AND name=$3)`, jobID, generation, name).Scan(&exists); err != nil {
			return "", err
		}
		if !exists {
			return name, nil
		}
	}
	return "", nil
}

// completeRunnerTx updates the completing runner's counters and drops the
// finished job from its active set. A missing runner is tolerated (it may
// have deregistered between the lease and the completion).
func (s *PostgresStore) completeRunnerTx(ctx context.Context, tx pgx.Tx, runnerID, jobID string, st model.Status, now time.Time) error {
	var (
		payload    []byte
		activeJSON []byte
		capacity   int
		completed  int64
		failed     int64
	)
	err := tx.QueryRow(ctx, `SELECT payload, COALESCE(active_jobs, '[]'::jsonb), capacity, completed, failed FROM runners WHERE id=$1 FOR UPDATE`, runnerID).
		Scan(&payload, &activeJSON, &capacity, &completed, &failed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var r model.Runner
	if err := json.Unmarshal(payload, &r); err != nil {
		return err
	}
	var active []string
	if err := json.Unmarshal(activeJSON, &active); err != nil {
		return err
	}
	active = removeString(active, jobID)
	// Capacity 0 means "take no work" and must survive completion: the
	// clamp to 1 is deliberately gone. A zero-capacity runner reports
	// non-busy (it has no leased work) but is never leased a new job.
	r.ActiveJobs = active
	r.CurrentJob = ""
	if len(active) > 0 {
		r.CurrentJob = active[0]
	}
	r.Busy = capacity > 0 && len(active) >= capacity
	r.Capacity = capacity
	if st == model.StatusSuccess {
		completed++
	} else if st == model.StatusFailure {
		failed++
	}
	r.Completed = completed
	r.Failed = failed
	r.LastSeen = now
	rp, err := jsonMarshal(r)
	if err != nil {
		return err
	}
	aj, err := jsonMarshal(active)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE runners SET payload=$2, active_jobs=$3, busy=$4, completed=$5, failed=$6, current_job=$7, last_seen=$8 WHERE id=$1`,
		runnerID, rp, aj, r.Busy, completed, failed, r.CurrentJob, now)
	return err
}

// recomputeDependentsTx finds every job that needs the completed job and
// marks it blocked or leaves it queued per the dependency outcome and its
// condition expression.
func (s *PostgresStore) recomputeDependentsTx(ctx context.Context, tx pgx.Tx, jobID string, now time.Time) error {
	rows, err := tx.Query(ctx, `SELECT job_id FROM job_dependencies WHERE depends_on=$1 ORDER BY job_id`, jobID)
	if err != nil {
		return err
	}
	defer rows.Close()
	depIDs := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		depIDs = append(depIDs, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, depID := range depIDs {
		if err := s.recomputeDependentTx(ctx, tx, depID, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresStore) recomputeDependentTx(ctx context.Context, tx pgx.Tx, depID string, now time.Time) error {
	var (
		payload   []byte
		curStatus string
	)
	err := tx.QueryRow(ctx, `SELECT payload, status FROM jobs WHERE id=$1 FOR UPDATE`, depID).Scan(&payload, &curStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var d model.Job
	if err := json.Unmarshal(payload, &d); err != nil {
		return err
	}
	if d.Status != model.StatusQueued && d.Status != model.StatusWaitingApproval {
		return nil
	}
	// Need statuses are plain reads: terminal jobs never leave their
	// terminal state, and the dependent's row lock above serializes
	// competing completions that touch the same dependent.
	statuses := map[string]model.Status{}
	nrows, err := tx.Query(ctx, `SELECT id, status FROM jobs WHERE id = ANY($1)`, d.Needs)
	if err != nil {
		return err
	}
	for nrows.Next() {
		var id, st string
		if err := nrows.Scan(&id, &st); err != nil {
			nrows.Close()
			return err
		}
		statuses[id] = model.Status(st)
	}
	nrows.Close()
	if err := nrows.Err(); err != nil {
		return err
	}
	ready, outcome := dependencyOutcome(statuses, d.Needs)
	if !ready {
		return nil
	}
	d.DependencyStatus = outcome
	if outcome != model.StatusSuccess && !dependencyConditionAllows(d.Condition, outcome) {
		fin := now
		d.Status = model.StatusBlocked
		d.Error = "dependency failed"
		d.FinishedAt = &fin
	}
	dp, err := jsonMarshal(d)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE jobs SET status=$2, dependency_status=$3, error=$4, finished_at=$5, payload=$6 WHERE id=$1`,
		depID, string(d.Status), string(d.DependencyStatus), nullText(d.Error), d.FinishedAt, dp)
	return err
}

type jobState struct {
	status     model.Status
	startedAt  *time.Time
	finishedAt *time.Time
}

// recomputeRunTx recomputes the run's status from its jobs, mirroring the
// in-memory refreshRunLocked. The run row lock serializes concurrent
// completions of jobs in the same run so the last committer always sees the
// previous committer's job update.
func (s *PostgresStore) recomputeRunTx(ctx context.Context, tx pgx.Tx, runID string) error {
	_, err := tx.Exec(ctx, `SELECT id FROM runs WHERE id=$1 FOR UPDATE`, runID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // orphan job tolerated
	}
	if err != nil {
		return err
	}
	jrows, err := tx.Query(ctx, `SELECT status, started_at, finished_at FROM jobs WHERE run_id=$1`, runID)
	if err != nil {
		return err
	}
	defer jrows.Close()
	states := []jobState{}
	for jrows.Next() {
		var (
			st         string
			startedAt  *time.Time
			finishedAt *time.Time
		)
		if err := jrows.Scan(&st, &startedAt, &finishedAt); err != nil {
			return err
		}
		states = append(states, jobState{status: model.Status(st), startedAt: startedAt, finishedAt: finishedAt})
	}
	if err := jrows.Err(); err != nil {
		return err
	}
	var (
		payload   []byte
		curStatus string
	)
	err = tx.QueryRow(ctx, `SELECT payload, status FROM runs WHERE id=$1`, runID).Scan(&payload, &curStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var run model.Run
	if err := json.Unmarshal(payload, &run); err != nil {
		return err
	}
	if !recomputeRunStatus(&run, states) {
		return nil
	}
	rp, err := jsonMarshal(run)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE runs SET status=$2, started_at=$3, finished_at=$4, payload=$5, `+normalizedRunRepoIdentityColumn+`=`+normalizedRunRepoIdentitySQL("$5")+`, `+normalizedRunRepoFullNameColumn+`=`+normalizedRunRepoFullNameSQL("$5")+` WHERE id=$1`,
		runID, string(run.Status), run.StartedAt, run.FinishedAt, rp)
	return err
}

// recomputeRunStatus mirrors the server's refreshRunLocked and reports
// whether the run changed.
func recomputeRunStatus(run *model.Run, states []jobState) bool {
	if len(states) == 0 {
		return false
	}
	beforeStatus := run.Status
	beforeStart := run.StartedAt
	beforeFinish := run.FinishedAt
	if run.Status == model.StatusCancelled {
		return false
	}
	var total, terminal int
	var anyRunning, anyFailure, anyCancelled, anyWaiting bool
	var firstStart, lastFinish *time.Time
	for _, st := range states {
		total++
		if st.startedAt != nil && (firstStart == nil || st.startedAt.Before(*firstStart)) {
			firstStart = st.startedAt
		}
		if st.status.Terminal() {
			terminal++
			if st.finishedAt != nil && (lastFinish == nil || st.finishedAt.After(*lastFinish)) {
				lastFinish = st.finishedAt
			}
		}
		switch st.status {
		case model.StatusRunning:
			anyRunning = true
		case model.StatusFailure, model.StatusBlocked:
			anyFailure = true
		case model.StatusCancelled:
			anyCancelled = true
		case model.StatusWaitingApproval:
			anyWaiting = true
		}
	}
	switch {
	case terminal == total:
		switch {
		case anyFailure:
			run.Status = model.StatusFailure
		case anyCancelled:
			run.Status = model.StatusCancelled
		default:
			run.Status = model.StatusSuccess
		}
		run.FinishedAt = lastFinish
		if run.FinishedAt == nil {
			n := time.Now().UTC()
			run.FinishedAt = &n
		}
	case anyRunning:
		run.Status = model.StatusRunning
	case anyWaiting:
		run.Status = model.StatusWaitingApproval
	default:
		run.Status = model.StatusQueued
	}
	if run.StartedAt == nil && firstStart != nil {
		run.StartedAt = firstStart
	}
	return run.Status != beforeStatus || !equalTimePtr(run.FinishedAt, beforeFinish) || (beforeStart == nil && run.StartedAt != nil)
}

func equalTimePtr(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// dependencyOutcome mirrors the server's dependencyOutcomeLocked.
func dependencyOutcome(statuses map[string]model.Status, needs []string) (bool, model.Status) {
	outcome := model.StatusSuccess
	for _, depID := range needs {
		d, ok := statuses[depID]
		if !ok {
			return true, model.StatusFailure
		}
		if !d.Terminal() {
			return false, model.StatusPending
		}
		switch d {
		case model.StatusFailure, model.StatusBlocked:
			outcome = model.StatusFailure
		case model.StatusCancelled:
			if outcome != model.StatusFailure {
				outcome = model.StatusCancelled
			}
		}
	}
	return true, outcome
}

// dependencyConditionAllows delegates to the unified pipeline condition
// evaluator so SQL-computed dependency outcomes match server and executor
// semantics exactly (audit item 7).
func dependencyConditionAllows(expr string, status model.Status) bool {
	return pipeline.ConditionAllows(expr, status)
}

// JobCancelCause selects the cancellation variant performed by cancelJobTx.
// It exists so the SAME per-job cancellation transaction serves the operator
// CancelRunJobs path (its exact historical behavior) and the identity-repair
// drain/quarantine path, which additionally recomputes dependents, appends an
// audit event and recomputes the run aggregation (T1-2).
type JobCancelCause int

const (
	// JobCancelOperator is the CancelRunJobs cancellation: clear the lease,
	// release the runner slot, the resource reservation and the quota counter
	// under the PRE-cancellation identity. The additive steps (7)-(9) are left
	// to the caller's run-level update exactly as before, so refactoring
	// CancelRunJobs onto cancelJobTx changes no behavior.
	JobCancelOperator JobCancelCause = iota
	// JobCancelRepairDrain is the --cancel-active identity repair: the full
	// canonical cancellation, including dependent recomputation, an audit
	// event and run aggregation.
	JobCancelRepairDrain
	// JobCancelQuarantine is JobCancelRepairDrain plus the durable
	// repo_identity_quarantined flag, so a cascaded child of a quarantined run
	// stays inert even if it is ever requeued.
	JobCancelQuarantine
)

// additive reports whether the cause performs steps (7)-(9): dependent
// recomputation, audit append and run aggregation.
func (c JobCancelCause) additive() bool { return c != JobCancelOperator }

// auditAction is the audit action recorded for the cause.
func (c JobCancelCause) auditAction() string {
	if c == JobCancelQuarantine {
		return "job.quarantined"
	}
	return "job.cancelled"
}

// cancelJobTx is the ONE transactional job cancellation.
//
//  1. lock the job FOR UPDATE;
//  2. capture its PRE-cancellation repository identity (RepoIDForJob);
//  3. clear lease_runner_id/lease_token_hash/lease_expires_at (row AND
//     payload);
//  4. delete its job_resource_reservations row;
//  5. remove it from the runner's active_jobs and repair current_job/busy;
//  6. decrement the quota counters under the OLD identity keys;
//
// and, for an additive cause,
//
//  7. recompute its dependent jobs;
//  8. append the cancellation audit event;
//  9. recompute the run aggregation.
//
// Using the OLD identity for the quota release is mandatory: the identity
// repair performs the guarded rewrite in a LATER statement, so decrementing
// after a rewrite would release the NEW repository's counter and leak the
// original reservation (finding 7). A terminal (or missing) job is a no-op.
func (s *PostgresStore) cancelJobTx(ctx context.Context, tx pgx.Tx, jobID, reason string, cause JobCancelCause) (bool, error) {
	var (
		runID    string
		runnerID string
		payload  []byte
		status   string
	)
	err := tx.QueryRow(ctx, `SELECT run_id, COALESCE(lease_runner_id,''), payload, status FROM jobs WHERE id=$1 FOR UPDATE`, jobID).
		Scan(&runID, &runnerID, &payload, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	st := model.Status(status)
	if st.Terminal() {
		return false, nil
	}
	var j model.Job
	if err := json.Unmarshal(payload, &j); err != nil {
		return false, err
	}
	// (2) the identity the quota was reserved under, captured BEFORE any
	// rewrite.
	oldRepoID := RepoIDForJob(j)
	now := time.Now().UTC()
	j.Status = model.StatusCancelled
	j.Error = reason
	j.FinishedAt = &now
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	if cause == JobCancelQuarantine {
		j.RepoIdentityQuarantined = true
	}
	jp, err := jsonMarshal(j)
	if err != nil {
		return false, err
	}
	// (3) clear the lease columns on the row as well as in the payload.
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status='cancelled', error=$2, finished_at=$3, lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL, payload=$4 WHERE id=$1`,
		jobID, reason, now, jp); err != nil {
		return false, err
	}
	// (4) the resource reservation (no-op for a queued job, which never
	// acquired one).
	if err := releaseResourcesTx(ctx, tx, jobID); err != nil {
		return false, err
	}
	// (5)/(6) the runner slot and the quota counter, under the OLD identity.
	if st == model.StatusRunning {
		if err := s.adjustQuotaTx(ctx, tx, oldRepoID, -1, 0); err != nil {
			return false, err
		}
		if runnerID != "" {
			if err := s.releaseRunnerSlotTx(ctx, tx, runnerID, jobID); err != nil {
				return false, err
			}
		}
	} else {
		if err := s.adjustQuotaTx(ctx, tx, oldRepoID, 0, -1); err != nil {
			return false, err
		}
	}
	if !cause.additive() {
		return true, nil
	}
	// (7) dependents.
	if err := s.recomputeDependentsTx(ctx, tx, jobID, now); err != nil {
		return false, err
	}
	// (8) audit.
	auditID, err := newID()
	if err != nil {
		return false, err
	}
	meta := []byte(`{"job":` + strconv.Quote(j.Key) + `}`)
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events (id, action, actor, run_id, job_id, message, metadata, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		auditID, cause.auditAction(), "operator", runID, jobID, reason, meta, now); err != nil {
		return false, err
	}
	// (9) run aggregation.
	if err := s.recomputeRunTx(ctx, tx, runID); err != nil {
		return false, err
	}
	return true, nil
}

// cancelRunRowTx locks the run row and marks it cancelled (a terminal or
// missing run is a no-op). The run row is locked AFTER any child jobs; see
// cancelRunTx for the documented lock order.
func (s *PostgresStore) cancelRunRowTx(ctx context.Context, tx pgx.Tx, runID, reason string, cause JobCancelCause) (bool, error) {
	var (
		payload   []byte
		curStatus string
	)
	err := tx.QueryRow(ctx, `SELECT payload, status FROM runs WHERE id=$1 FOR UPDATE`, runID).Scan(&payload, &curStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if model.Status(curStatus).Terminal() {
		return false, nil
	}
	var run model.Run
	if err := json.Unmarshal(payload, &run); err != nil {
		return false, err
	}
	now := time.Now().UTC()
	run.Status = model.StatusCancelled
	run.FinishedAt = &now
	rp, err := jsonMarshal(run)
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE runs SET status=$2, finished_at=$3, payload=$4, `+normalizedRunRepoIdentityColumn+`=`+normalizedRunRepoIdentitySQL("$4")+`, `+normalizedRunRepoFullNameColumn+`=`+normalizedRunRepoFullNameSQL("$4")+` WHERE id=$1`,
		runID, string(model.StatusCancelled), now, rp); err != nil {
		return false, err
	}
	if cause.additive() {
		auditID, err := newID()
		if err != nil {
			return false, err
		}
		action := "run.cancelled"
		if cause == JobCancelQuarantine {
			action = "run.quarantined"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_events (id, action, actor, run_id, message, created_at) VALUES ($1, $2, $3, $4, $5, $6)`,
			auditID, action, "operator", runID, reason, now); err != nil {
			return false, err
		}
	}
	return true, nil
}

// cancelRunChildrenTx cancels every non-terminal child job of a run through
// cancelJobTx, in the caller's transaction, without touching the run row. It
// reports whether any child was actually cancelled. The child jobs are locked
// (SELECT ... FOR UPDATE) FIRST, in id order, and the run row is never locked
// here: that keeps the job -> run order AcquireLeaseAtomic (job -> runner) and
// CompleteJob (job -> run through recomputeRunTx) use, so a cascade can never
// deadlock against a completion that already holds the job row.
func (s *PostgresStore) cancelRunChildrenTx(ctx context.Context, tx pgx.Tx, runID, reason string, cause JobCancelCause) (bool, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM jobs WHERE run_id=$1 AND NOT (status IN ('success', 'failure', 'cancelled', 'skipped', 'blocked')) ORDER BY id FOR UPDATE`, runID)
	if err != nil {
		return false, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return false, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	cancelled := false
	for _, id := range ids {
		ok, err := s.cancelJobTx(ctx, tx, id, reason, cause)
		if err != nil {
			return false, err
		}
		if ok {
			cancelled = true
		}
	}
	return cancelled, nil
}

// cancelRunTx cancels a run and every non-terminal child job through
// cancelJobTx, in the caller's transaction, and reports whether the RUN row
// was transitioned. It is the run-level cancellation used by the repair
// quarantine cascade and by --cancel-active.
//
// LOCK ORDER: cancelRunChildrenTx locks and cancels the non-terminal child
// jobs FIRST; the run row is locked LAST by cancelRunRowTx. That is job -> run
// (see cancelRunChildrenTx).
func (s *PostgresStore) cancelRunTx(ctx context.Context, tx pgx.Tx, runID, reason string, cause JobCancelCause) (bool, error) {
	if _, err := s.cancelRunChildrenTx(ctx, tx, runID, reason, cause); err != nil {
		return false, err
	}
	return s.cancelRunRowTx(ctx, tx, runID, reason, cause)
}

// CancelRunJobs cancels every non-terminal job of the run and the run
// itself in one transaction. Every cancelled RUNNING job releases its
// runner's active_jobs slot (and its quota running slot) in the SAME
// transaction, so a cancelled run can never leak a runner slot. It delegates
// each job to cancelJobTx (T1-2); the operator cause preserves the historical
// behavior (no per-job audit/dependent/aggregation side effects).
func (s *PostgresStore) CancelRunJobs(ctx context.Context, runID string, reason string) ([]string, error) {
	if err := ValidateRunID(runID); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// Phase 1: lock and collect the target rows. The cursor is closed before
	// any tx.Exec so this never nests a query on an open cursor.
	rows, err := tx.Query(ctx, `SELECT id FROM jobs WHERE run_id=$1 AND NOT (status IN ('success', 'failure', 'cancelled', 'skipped', 'blocked')) ORDER BY id FOR UPDATE`, runID)
	if err != nil {
		return nil, err
	}
	targets := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		targets = append(targets, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Phase 2: cancel each target in the same transaction.
	ids := []string{}
	for _, id := range targets {
		cancelled, err := s.cancelJobTx(ctx, tx, id, reason, JobCancelOperator)
		if err != nil {
			return nil, err
		}
		if cancelled {
			ids = append(ids, id)
		}
	}
	// Cancel the run itself, mirroring the in-memory cancelRunLocked.
	if _, err := s.cancelRunRowTx(ctx, tx, runID, reason, JobCancelOperator); err != nil {
		return nil, err
	}
	return ids, tx.Commit(ctx)
}

// ---------------------------------------------------------------------------
// runners
// ---------------------------------------------------------------------------

// mergeRunnerProfile overlays the caller's PROFILE/ADMIN fields onto an
// existing runner row while preserving the fields the lease/transition
// transactions own (active_jobs, busy, current_job, completed, failed) and the
// original registration time. busy is recomputed from the preserved active
// set and the caller's capacity, so a capacity edit cannot leave a stale busy
// flag.
func mergeRunnerProfile(caller, existing model.Runner) model.Runner {
	merged := caller
	merged.ActiveJobs = append([]string(nil), existing.ActiveJobs...)
	merged.CurrentJob = existing.CurrentJob
	merged.Completed = existing.Completed
	merged.Failed = existing.Failed
	if !existing.Registered.IsZero() {
		merged.Registered = existing.Registered
	}
	merged.Busy = merged.Capacity > 0 && len(merged.ActiveJobs) >= merged.Capacity
	return merged
}

// UpsertRunner registers or re-registers a runner. On an existing row it
// merges only the profile/admin fields under the runner row lock: the
// LEASE-OWNED fields (active_jobs, busy, current_job) and the completed/failed
// counters are preserved, so a re-registration from a stale snapshot — the
// server's Get-then-Upsert registration path — can never drop a slot that a
// concurrent AcquireLeaseAtomic just reserved. A brand-new runner row is the
// only path that seeds those fields. UpdateRunnerProfileFields is the same
// guarded merge for callers that must not create a runner.
func (s *PostgresStore) UpsertRunner(ctx context.Context, runner model.Runner) error {
	if err := ValidateRunnerID(runner.ID); err != nil {
		return err
	}
	return s.writeRunnerProfile(ctx, runner, false)
}

// UpdateRunnerProfileFields updates only the profile/admin fields of an
// EXISTING runner (see the contract on RunnerProfileUpdateStore). It is the
// explicit guarded operation registration/drain/enable adopt so their
// in-memory model never has to carry active_jobs at all.
func (s *PostgresStore) UpdateRunnerProfileFields(ctx context.Context, runner model.Runner) error {
	if err := ValidateRunnerID(runner.ID); err != nil {
		return err
	}
	return s.writeRunnerProfile(ctx, runner, true)
}

// writeRunnerProfile is the ONE guarded runner write. It locks the runner row
// (if any) and, on an existing row, writes the caller's profile/admin fields
// while preserving the lease-owned fields; requireExisting fails closed with
// ErrNotFound instead of creating a row.
func (s *PostgresStore) writeRunnerProfile(ctx context.Context, runner model.Runner, requireExisting bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	rs := runnerScanner{}
	err = tx.QueryRow(ctx, `SELECT `+runnerCols+` FROM runners WHERE id=$1 FOR UPDATE`, runner.ID).Scan(rs.targets()...)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if requireExisting {
			return ErrNotFound
		}
		// A fresh registration seeds the supplied fields: there is no lease
		// state to preserve.
		if err := s.insertRunnerRowTx(ctx, tx, runner); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		existing, err := rs.runner()
		if err != nil {
			return err
		}
		if err := s.updateRunnerProfileRowTx(ctx, tx, mergeRunnerProfile(runner, existing)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) insertRunnerRowTx(ctx context.Context, tx pgx.Tx, runner model.Runner) error {
	args, err := runnerWriteArgs(runner)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO runners (id, busy, capacity, completed, failed, current_job, active_jobs, registered, last_seen, payload, disabled, draining) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`, args...)
	return err
}

func (s *PostgresStore) updateRunnerProfileRowTx(ctx context.Context, tx pgx.Tx, runner model.Runner) error {
	args, err := runnerWriteArgs(runner)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE runners SET busy=$2, capacity=$3, completed=$4, failed=$5, current_job=$6, active_jobs=$7, registered=$8, last_seen=$9, payload=$10, disabled=$11, draining=$12 WHERE id=$1`, args...)
	return err
}

// runnerWriteArgs marshals a runner for the runner-row INSERT/UPDATE. It is
// shared by both so the two statements can never drift.
func runnerWriteArgs(runner model.Runner) ([]any, error) {
	payload, err := jsonMarshal(runner)
	if err != nil {
		return nil, err
	}
	activeJSON, err := jsonMarshal(runner.ActiveJobs)
	if err != nil {
		return nil, err
	}
	if len(activeJSON) == 0 || string(activeJSON) == "null" {
		activeJSON = []byte("[]")
	}
	var registered any
	if !runner.Registered.IsZero() {
		registered = runner.Registered
	}
	var lastSeen any
	if !runner.LastSeen.IsZero() {
		lastSeen = runner.LastSeen
	}
	return []any{
		runner.ID, runner.Busy, runner.Capacity, runner.Completed, runner.Failed,
		nullText(runner.CurrentJob), activeJSON, registered, lastSeen, payload,
		runner.Disabled, runner.Draining,
	}, nil
}

var _ RunnerProfileUpdateStore = (*PostgresStore)(nil)

func (s *PostgresStore) GetRunner(ctx context.Context, id string) (model.Runner, error) {
	if err := ValidateRunnerID(id); err != nil {
		return model.Runner{}, err
	}
	rs := runnerScanner{}
	err := s.pool.QueryRow(ctx, `SELECT `+runnerCols+` FROM runners WHERE id=$1`, id).Scan(rs.targets()...)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Runner{}, ErrNotFound
	}
	if err != nil {
		return model.Runner{}, err
	}
	return rs.runner()
}

func (s *PostgresStore) ListRunners(ctx context.Context) ([]model.Runner, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+runnerCols+` FROM runners ORDER BY payload->>'name' ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Runner{}
	for rows.Next() {
		rs := runnerScanner{}
		if err := rows.Scan(rs.targets()...); err != nil {
			return nil, err
		}
		r, err := rs.runner()
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ReleaseRunnerJob(ctx context.Context, runnerID, jobID string, status model.Status) error {
	if err := ValidateRunnerID(runnerID); err != nil {
		return err
	}
	if err := ValidateJobID(jobID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var (
		payload    []byte
		activeJSON []byte
		capacity   int
		completed  int64
		failed     int64
	)
	err = tx.QueryRow(ctx, `SELECT payload, COALESCE(active_jobs, '[]'::jsonb), capacity, completed, failed FROM runners WHERE id=$1 FOR UPDATE`, runnerID).
		Scan(&payload, &activeJSON, &capacity, &completed, &failed)
	if errors.Is(err, pgx.ErrNoRows) {
		// The runner row is gone (deregistered): the reserved quota slot is
		// repository-scoped, so it is released regardless of the missing
		// runner row. The release still reports the missing runner. The
		// resource reservation is keyed by job, so it is released too.
		if qerr := s.releaseJobQuotaTx(ctx, tx, jobID); qerr != nil {
			return qerr
		}
		if rerr := releaseResourcesTx(ctx, tx, jobID); rerr != nil {
			return rerr
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return cerr
		}
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	var r model.Runner
	if err := json.Unmarshal(payload, &r); err != nil {
		return err
	}
	var active []string
	if err := json.Unmarshal(activeJSON, &active); err != nil {
		return err
	}
	active = removeString(active, jobID)
	// Capacity 0 survives release: zero means "take no work", so the
	// runner stays non-leasable instead of being clamped back to 1.
	r.ActiveJobs = active
	r.CurrentJob = ""
	if len(active) > 0 {
		r.CurrentJob = active[0]
	}
	r.Busy = capacity > 0 && len(active) >= capacity
	r.Capacity = capacity
	if status == model.StatusSuccess {
		completed++
	} else if status == model.StatusFailure {
		failed++
	}
	r.Completed = completed
	r.Failed = failed
	r.LastSeen = time.Now().UTC()
	rp, err := jsonMarshal(r)
	if err != nil {
		return err
	}
	aj, err := jsonMarshal(active)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE runners SET payload=$2, active_jobs=$3, busy=$4, completed=$5, failed=$6, current_job=$7, last_seen=$8 WHERE id=$1`,
		runnerID, rp, aj, r.Busy, completed, failed, r.CurrentJob, r.LastSeen); err != nil {
		return err
	}
	// The released job was running: release the running slot and, when the
	// job was requeued (recovery/kill switch), re-reserve the queued slot.
	if err := s.releaseJobQuotaTx(ctx, tx, jobID); err != nil {
		return err
	}
	// Release the job's resource reservation in the same transaction.
	if err := releaseResourcesTx(ctx, tx, jobID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// releaseJobQuotaTx releases one job's reserved quota slot inside the
// caller's transaction: the running slot always, plus a fresh queued slot
// when the job was requeued. A missing job row is tolerated.
func (s *PostgresStore) releaseJobQuotaTx(ctx context.Context, tx pgx.Tx, jobID string) error {
	var (
		jobStatus   string
		jobRepoID   string
		jobRepoURL  string
		jobFullName string
	)
	if err := tx.QueryRow(ctx, `SELECT status, COALESCE(payload->>'repo_id', ''), COALESCE(payload->>'repo_url', ''), COALESCE(payload->>'repo_full_name', '') FROM jobs WHERE id=$1`, jobID).Scan(&jobStatus, &jobRepoID, &jobRepoURL, &jobFullName); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	queuedDelta := 0
	if model.Status(jobStatus) == model.StatusQueued {
		queuedDelta = 1
	}
	return s.adjustQuotaTx(ctx, tx, RepoIDFor(jobRepoID, jobRepoURL, jobFullName), -1, queuedDelta)
}

// releaseRunnerSlotTx splices one job ID out of a runner's active_jobs set
// inside the caller's transaction, recomputing busy and current_job from the
// remaining set. Capacity 0 survives (busy stays false: a zero-capacity
// runner holds no leasable work). Missing runners are tolerated.
func (s *PostgresStore) releaseRunnerSlotTx(ctx context.Context, tx pgx.Tx, runnerID, jobID string) error {
	_, err := tx.Exec(ctx, `WITH kept AS (
    SELECT COALESCE(jsonb_agg(e), '[]'::jsonb) AS active
    FROM jsonb_array_elements(COALESCE((SELECT active_jobs FROM runners WHERE id=$2), '[]'::jsonb)) e
    WHERE e <> to_jsonb($1::text)
)
UPDATE runners SET
    active_jobs = (SELECT active FROM kept),
    busy = CASE WHEN capacity > 0 THEN jsonb_array_length((SELECT active FROM kept)) >= capacity ELSE FALSE END,
    current_job = CASE WHEN jsonb_array_length((SELECT active FROM kept)) > 0 THEN (SELECT active FROM kept)->>0 ELSE NULL END,
    last_seen = now()
WHERE id = $2`, jobID, runnerID)
	return err
}

// ---------------------------------------------------------------------------
// secret delivery claims
// ---------------------------------------------------------------------------

// ClaimSecretDelivery reserves the (job, generation, secret name) once-only
// secret delivery claim. The INSERT ... ON CONFLICT DO NOTHING is the
// arbitration: exactly one concurrent or replayed delivery reports true.
func (s *PostgresStore) ClaimSecretDelivery(ctx context.Context, jobID string, generation int64, secretName string) (bool, error) {
	if err := ValidateJobID(jobID); err != nil {
		return false, err
	}
	if generation < 0 {
		return false, fmt.Errorf("storage: invalid lease generation %d", generation)
	}
	if strings.TrimSpace(secretName) == "" {
		return false, fmt.Errorf("storage: empty secret name")
	}
	ct, err := s.pool.Exec(ctx, `INSERT INTO secret_claims (job_id, generation, secret_name) VALUES ($1, $2, $3) ON CONFLICT (job_id, generation, secret_name) DO NOTHING`,
		jobID, generation, secretName)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() == 1, nil
}

// ReleaseSecretDelivery drops a claim whose resolution failed, so a failed
// resolution never consumes the once-only delivery.
func (s *PostgresStore) ReleaseSecretDelivery(ctx context.Context, jobID string, generation int64, secretName string) error {
	if err := ValidateJobID(jobID); err != nil {
		return err
	}
	if generation < 0 {
		return fmt.Errorf("storage: invalid lease generation %d", generation)
	}
	if strings.TrimSpace(secretName) == "" {
		return fmt.Errorf("storage: empty secret name")
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM secret_claims WHERE job_id=$1 AND generation=$2 AND secret_name=$3`,
		jobID, generation, secretName)
	return err
}

// ---------------------------------------------------------------------------
// artifacts, reports, logs, audit, deliveries, receipts
// ---------------------------------------------------------------------------

func (s *PostgresStore) InsertArtifact(ctx context.Context, a model.ArtifactRecord) error {
	if err := ValidateID(a.ID); err != nil {
		return err
	}
	if err := ValidateRunID(a.RunID); err != nil {
		return err
	}
	payload, err := jsonMarshal(a)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO artifacts (id, run_id, job_id, job_key, name, size, sha256, created_at, expires_at, job_generation, payload) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		a.ID, a.RunID, nullText(a.JobID), nullText(a.JobKey), a.Name, a.Size, nullText(a.SHA256), a.CreatedAt, a.ExpiresAt, a.LeaseGeneration, payload)
	return err
}

// InsertArtifactOnce is the authoritative idempotent artifact insert: the
// (job_id, job_generation, name) unique index arbitrates concurrent replicas
// staging the same artifact name. A conflict returns the STORED record with
// created=false (same digest) or ErrArtifactDigestConflict (different
// digest); the stored record is never overwritten and no second row is
// created.
func (s *PostgresStore) InsertArtifactOnce(ctx context.Context, a model.ArtifactRecord) (model.ArtifactRecord, bool, error) {
	if err := ValidateID(a.ID); err != nil {
		return model.ArtifactRecord{}, false, err
	}
	if err := ValidateRunID(a.RunID); err != nil {
		return model.ArtifactRecord{}, false, err
	}
	payload, err := jsonMarshal(a)
	if err != nil {
		return model.ArtifactRecord{}, false, err
	}
	ct, err := s.pool.Exec(ctx, `INSERT INTO artifacts (id, run_id, job_id, job_key, name, size, sha256, created_at, expires_at, job_generation, payload) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT (job_id, job_generation, name) DO NOTHING`,
		a.ID, a.RunID, nullText(a.JobID), nullText(a.JobKey), a.Name, a.Size, nullText(a.SHA256), a.CreatedAt, a.ExpiresAt, a.LeaseGeneration, payload)
	if err != nil {
		return model.ArtifactRecord{}, false, err
	}
	if ct.RowsAffected() == 1 {
		return a, true, nil
	}
	// A conflicting row exists (a NULL job_id never conflicts, so JobID is
	// non-empty on this path).
	existing, err := s.artifactByGenerationKey(ctx, a.JobID, a.LeaseGeneration, a.Name)
	if err != nil {
		return model.ArtifactRecord{}, false, err
	}
	if existing.SHA256 != a.SHA256 {
		return existing, false, ErrArtifactDigestConflict
	}
	return existing, false, nil
}

// artifactByGenerationKey reads the artifact row under the idempotency key.
func (s *PostgresStore) artifactByGenerationKey(ctx context.Context, jobID string, generation int64, name string) (model.ArtifactRecord, error) {
	var payload []byte
	err := s.pool.QueryRow(ctx, `SELECT payload FROM artifacts WHERE job_id=$1 AND COALESCE(NULLIF(job_generation,0), CASE WHEN jsonb_typeof(payload->'lease_generation')='number' AND (payload->>'lease_generation') ~ '^[0-9]{1,18}$' THEN (payload->>'lease_generation')::bigint ELSE 0 END) = $2 AND name=$3 LIMIT 1`,
		jobID, generation, name).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.ArtifactRecord{}, ErrNotFound
	}
	if err != nil {
		return model.ArtifactRecord{}, err
	}
	var a model.ArtifactRecord
	if err := json.Unmarshal(payload, &a); err != nil {
		return model.ArtifactRecord{}, err
	}
	return a, nil
}

func (s *PostgresStore) ListArtifacts(ctx context.Context, runID string) ([]model.ArtifactRecord, error) {
	if err := ValidateRunID(runID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT payload FROM artifacts WHERE run_id=$1 ORDER BY created_at ASC, id ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ArtifactRecord{}
	for rows.Next() {
		var (
			payload []byte
			a       model.ArtifactRecord
		)
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetArtifact resolves one artifact record by ID.
func (s *PostgresStore) GetArtifact(ctx context.Context, id string) (model.ArtifactRecord, error) {
	if err := ValidateID(id); err != nil {
		return model.ArtifactRecord{}, err
	}
	var (
		payload []byte
		a       model.ArtifactRecord
	)
	err := s.pool.QueryRow(ctx, `SELECT payload FROM artifacts WHERE id=$1`, id).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.ArtifactRecord{}, ErrNotFound
	}
	if err != nil {
		return model.ArtifactRecord{}, err
	}
	if err := json.Unmarshal(payload, &a); err != nil {
		return model.ArtifactRecord{}, err
	}
	return a, nil
}

func (s *PostgresStore) InsertTestReport(ctx context.Context, rep model.TestReport) error {
	if err := ValidateID(rep.ID); err != nil {
		return err
	}
	if err := ValidateRunID(rep.RunID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := insertTestReportRowsTx(ctx, tx, rep); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) ListTestReports(ctx context.Context, runID string) ([]model.TestReport, error) {
	if err := ValidateRunID(runID); err != nil {
		return nil, err
	}
	return s.listTestReports(ctx, `SELECT payload FROM test_results WHERE run_id=$1 ORDER BY created_at ASC, id ASC`, runID)
}

func (s *PostgresStore) ListTestReportsAll(ctx context.Context) ([]model.TestReport, error) {
	return s.listTestReports(ctx, `SELECT payload FROM test_results ORDER BY created_at ASC, id ASC`)
}

func (s *PostgresStore) listTestReports(ctx context.Context, query string, args ...any) ([]model.TestReport, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.TestReport{}
	for rows.Next() {
		var (
			payload []byte
			rep     model.TestReport
		)
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &rep); err != nil {
			return nil, err
		}
		out = append(out, rep)
	}
	return out, rows.Err()
}

// AppendLog inserts one log line into the identity-sequenced log_entries
// table. The caller-supplied e.Seq is ignored: the sequence is allocated by
// Postgres inside the insert transaction (INSERT ... RETURNING seq), so
// appends stay strictly increasing regardless of clock ordering across
// replicas or restarts.
func (s *PostgresStore) AppendLog(ctx context.Context, e model.LogEntry) error {
	if err := ValidateRunID(e.RunID); err != nil {
		return err
	}
	err := s.pool.QueryRow(ctx, `INSERT INTO log_entries (run_id, job_id, job_key, step, line, created_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING seq`,
		e.RunID, nullText(e.JobID), nullText(e.JobKey), nullText(e.Step), e.Line, e.CreatedAt).Scan(&e.Seq)
	return err
}

func (s *PostgresStore) ReadLogs(ctx context.Context, runID string, after int64, limit int) ([]model.LogEntry, error) {
	if err := ValidateRunID(runID); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 10000 {
		limit = 2000
	}
	rows, err := s.pool.Query(ctx, `SELECT COALESCE(job_id, ''), COALESCE(job_key, ''), COALESCE(step, ''), seq, line, created_at FROM log_entries WHERE run_id=$1 AND seq>$2 ORDER BY seq ASC LIMIT $3`, runID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.LogEntry{}
	for rows.Next() {
		var e model.LogEntry
		if err := rows.Scan(&e.JobID, &e.JobKey, &e.Step, &e.Seq, &e.Line, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.RunID = runID
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *PostgresStore) AppendAudit(ctx context.Context, e model.AuditEvent) error {
	if err := ValidateID(e.ID); err != nil {
		return err
	}
	var meta []byte
	if len(e.Metadata) > 0 {
		m, err := jsonMarshal(e.Metadata)
		if err != nil {
			return err
		}
		meta = m
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO audit_events (id, action, actor, run_id, job_id, message, metadata, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		e.ID, e.Action, nullText(e.Actor), nullText(e.RunID), nullText(e.JobID), nullText(e.Message), meta, e.CreatedAt)
	return err
}

func (s *PostgresStore) ReadAudit(ctx context.Context, limit int) ([]model.AuditEvent, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx, `SELECT id, action, COALESCE(actor, ''), COALESCE(run_id, ''), COALESCE(job_id, ''), COALESCE(message, ''), COALESCE(metadata, '{}'::jsonb), created_at FROM (SELECT * FROM audit_events ORDER BY created_at DESC, id DESC LIMIT $1) sub ORDER BY created_at ASC, id ASC`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AuditEvent{}
	for rows.Next() {
		var (
			e    model.AuditEvent
			meta []byte
		)
		if err := rows.Scan(&e.ID, &e.Action, &e.Actor, &e.RunID, &e.JobID, &e.Message, &meta, &e.CreatedAt); err != nil {
			return nil, err
		}
		if len(meta) > 0 && string(meta) != "{}" {
			if err := json.Unmarshal(meta, &e.Metadata); err != nil {
				return nil, err
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// InsertCompletionReceipt persists one completion idempotency receipt and
// then applies the shared retention prune in the same transaction, so the
// receipt set stays bounded by the fs-mode contract. The semantic is
// FIRST-WINS: the first receipt for a (job, generation, runner) identity is
// authoritative and a later insert never overwrites it (ON CONFLICT DO
// NOTHING), matching the in-memory store. The receipt records what the lease's
// completion actually was, so a second, conflicting insert must not silently
// rewrite it; callers that must detect the conflict compare the stored
// ResultHash. A prune failure rolls the whole transaction back, leaving the
// receipt absent; a retry re-applies both.
func (s *PostgresStore) InsertCompletionReceipt(ctx context.Context, r model.CompletionReceipt) error {
	if err := ValidateJobID(r.JobID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO completion_receipts (job_id, generation, runner_id, result_hash) VALUES ($1, $2, $3, $4) ON CONFLICT (job_id, generation, runner_id) DO NOTHING`,
		r.JobID, r.Generation, r.RunnerID, r.ResultHash); err != nil {
		return err
	}
	if err := pruneCompletionReceiptsTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// HasCompletionReceipt reports the exact receipt only while it is within the
// shared CompletionReceiptTTL; an aged-out row reads as absent even before a
// write-path prune reclaims it, so replay behavior does not depend on when the
// last completion happened to run.
func (s *PostgresStore) HasCompletionReceipt(ctx context.Context, jobID string, generation int64, runnerID string) (model.CompletionReceipt, bool, error) {
	if err := ValidateJobID(jobID); err != nil {
		return model.CompletionReceipt{}, false, err
	}
	var (
		rec  model.CompletionReceipt
		hash string
	)
	err := s.pool.QueryRow(ctx, `SELECT result_hash FROM completion_receipts WHERE job_id=$1 AND generation=$2 AND runner_id=$3 AND created_at >= now() - make_interval(secs => $4)`, jobID, generation, runnerID, completionReceiptTTLSeconds).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.CompletionReceipt{}, false, nil
	}
	if err != nil {
		return model.CompletionReceipt{}, false, err
	}
	rec = model.CompletionReceipt{JobID: jobID, Generation: generation, RunnerID: runnerID, ResultHash: hash}
	return rec, true, nil
}

func (s *PostgresStore) UpsertDelivery(ctx context.Context, forge, deliveryID string, runID string, payloadDigest string) error {
	if forge == "" || deliveryID == "" {
		return fmt.Errorf("storage: empty forge or delivery id")
	}
	if err := ValidateRunID(runID); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO webhook_deliveries (forge, delivery_id, run_id, payload_digest) VALUES ($1, $2, $3, $4) ON CONFLICT (forge, delivery_id) DO UPDATE SET payload_digest=EXCLUDED.payload_digest`,
		forge, deliveryID, runID, nullText(payloadDigest))
	return err
}

func (s *PostgresStore) FindDelivery(ctx context.Context, forge, deliveryID string) (string, bool, error) {
	var runID string
	err := s.pool.QueryRow(ctx, `SELECT run_id FROM webhook_deliveries WHERE forge=$1 AND delivery_id=$2`, forge, deliveryID).Scan(&runID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return runID, true, nil
}

// ---------------------------------------------------------------------------
// outbox
// ---------------------------------------------------------------------------

func (s *PostgresStore) OutboxAppend(ctx context.Context, e OutboxItem) error {
	if e.ID == "" {
		id, err := newID()
		if err != nil {
			return err
		}
		e.ID = id
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	payload := e.Payload
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	// Deterministic IDs make appends idempotent: a replay after a lost ACK
	// must converge on ONE row. An ID reused with DIFFERENT content is an
	// invariant failure (the deterministic key would map two distinct
	// operations onto one durable intent), so it is rejected loudly.
	var existingKind string
	var existingPayload []byte
	var existingKey *string
	var existingVersion int64
	err := s.pool.QueryRow(ctx, `SELECT kind, payload, logical_key, state_version FROM outbox WHERE id=$1`, e.ID).
		Scan(&existingKind, &existingPayload, &existingKey, &existingVersion)
	switch {
	case err == nil:
		if existingKind != e.Kind || !jsonPayloadEqual(existingPayload, payload) ||
			nullableText(existingKey) != e.LogicalKey || existingVersion != e.StateVersion {
			return fmt.Errorf("storage: outbox id %s reused with different content", e.ID)
		}
		return nil
	case errors.Is(err, pgx.ErrNoRows):
	default:
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO outbox (id, kind, payload, created_at, logical_key, state_version) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING`,
		e.ID, e.Kind, payload, e.CreatedAt, nullText(e.LogicalKey), e.StateVersion)
	if err != nil {
		return err
	}
	// Re-verify after the race-safe insert.
	err = s.pool.QueryRow(ctx, `SELECT kind, payload, logical_key, state_version FROM outbox WHERE id=$1`, e.ID).
		Scan(&existingKind, &existingPayload, &existingKey, &existingVersion)
	if err != nil {
		return err
	}
	if existingKind != e.Kind || !jsonPayloadEqual(existingPayload, payload) ||
		nullableText(existingKey) != e.LogicalKey || existingVersion != e.StateVersion {
		return fmt.Errorf("storage: outbox id %s reused with different content", e.ID)
	}
	return nil
}

// nullableText dereferences an optional text column.
func nullableText(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// jsonPayloadEqual compares two payloads SEMANTICALLY: the outbox column is
// jsonb, which normalizes key order and whitespace on read, so a
// byte-for-byte comparison would reject every legitimate replay. Falls back
// to bytes.Equal when either side is not JSON.
func jsonPayloadEqual(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &y); err != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// OutboxAck removes a successfully dispatched row (clearing any claim). It is
// the durable ACK of the leader-only outbox flush, so it runs in a
// transaction FENCED by the store's leadership epoch: a stale leader's ACK is
// rejected with ErrStaleLeader and the row stays durable for the retry.
func (s *PostgresStore) OutboxAck(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("storage: empty outbox id")
	}
	// Deleting the row clears its claim atomically with the ack: a claimed
	// but crash-stranded row can only be reclaimed for OutboxClaimTTL.
	//
	// For a versioned row the delivered watermark advances in the SAME
	// statement (a single CTE, so it is atomic under concurrent acks): the
	// watermark can never lag an acknowledged delivery, and it outlives the
	// row deletion. GREATEST keeps the watermark monotonic when two replicas
	// ack different versions of one logical key concurrently.
	tx, err := s.beginFencedTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `WITH deleted AS (
			DELETE FROM outbox WHERE id=$1
			RETURNING logical_key, state_version
		)
		INSERT INTO forge_check_state (logical_key, delivered_version, updated_at)
		SELECT logical_key, state_version, now() FROM deleted WHERE logical_key IS NOT NULL
		ON CONFLICT (logical_key) DO UPDATE
			SET delivered_version = GREATEST(forge_check_state.delivered_version, EXCLUDED.delivered_version),
			    updated_at = now()`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// OutboxMarkDelivered advances the durable delivered watermark for one
// logical key after a successful publication. Legacy pre-0018 rows carry no
// logical_key/state_version columns, so their OutboxAck cannot advance the
// watermark; the dispatcher derives the identity from the payload and calls
// this after the forge accepted the state. GREATEST keeps it monotonic under
// concurrent publications of different versions.
//
// Deliberately not epoch-fenced, together with OutboxRetry: both are per-row
// bookkeeping for a claim the caller already owns (the claim itself, the ACK
// and the release ARE fenced), they are monotonic/idempotent, and OutboxRetry
// is also reachable from the operator/CLI paths, so fencing them would reject
// non-leader callers without protecting anything the claim fence does not.
func (s *PostgresStore) OutboxMarkDelivered(ctx context.Context, logicalKey string, version int64) error {
	if logicalKey == "" || version <= 0 {
		return fmt.Errorf("storage: mark delivered requires a logical key and a positive version")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO forge_check_state (logical_key, delivered_version, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (logical_key) DO UPDATE
			SET delivered_version = GREATEST(forge_check_state.delivered_version, EXCLUDED.delivered_version),
			    updated_at = now()`, logicalKey, version)
	return err
}

// OutboxEnqueueVersioned durably inserts one versioned forge-delivery intent
// and supersedes every older pending version of the same logical key in ONE
// transaction:
//
//  1. A per-logical-key transaction advisory lock serializes concurrent
//     enqueues of the same logical key across replicas.
//  2. The forge_check_state row is locked (upsert with a no-op update) and
//     its delivered_version is read. A version at or below the watermark is
//     already delivered: nothing is inserted and VersionedSuperseded is
//     returned, so a stale state can never regress a delivered one.
//  3. Every older PENDING row of the logical key is deleted (dead letters are
//     terminal and operator-visible, so they are left for the operator path;
//     they can no longer block a newer version because IDs are versioned).
//  4. The new row is inserted under ID logical_key || '#' || version. A
//     conflict can only be an equal-version dead letter, which is reported as
//     superseded (the operator requeue path re-arms it, and the dispatcher
//     guard retires it if a newer version wins first).
func (s *PostgresStore) OutboxEnqueueVersioned(ctx context.Context, e OutboxItem) (VersionedEnqueueOutcome, error) {
	if e.LogicalKey == "" || e.StateVersion <= 0 {
		return VersionedEnqueued, fmt.Errorf("storage: versioned outbox enqueue requires a logical key and a positive version")
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	payload := e.Payload
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return VersionedEnqueued, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockKey(OutboxVersionLockNamespace, e.LogicalKey)); err != nil {
		return VersionedEnqueued, err
	}
	var delivered int64
	if err := tx.QueryRow(ctx, `INSERT INTO forge_check_state (logical_key) VALUES ($1)
		ON CONFLICT (logical_key) DO UPDATE SET logical_key = EXCLUDED.logical_key
		RETURNING delivered_version`, e.LogicalKey).Scan(&delivered); err != nil {
		return VersionedEnqueued, err
	}
	if e.StateVersion <= delivered {
		return VersionedSuperseded, tx.Commit(ctx)
	}
	// A NEWER pending version wins even when this enqueue arrives after it
	// (out-of-order replicas): the newer state will publish the newest
	// remote result, so inserting this older state would only add work the
	// dispatcher guard then retires. Equal versions fall through: the
	// payload is refreshed in place (supersede-range delete + insert).
	var maxPending int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(state_version),0) FROM outbox WHERE logical_key=$1 AND dead_lettered_at IS NULL`, e.LogicalKey).Scan(&maxPending); err != nil {
		return VersionedEnqueued, err
	}
	if e.StateVersion < maxPending {
		return VersionedSuperseded, tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM outbox WHERE logical_key=$1 AND state_version <= $2 AND dead_lettered_at IS NULL`,
		e.LogicalKey, e.StateVersion); err != nil {
		return VersionedEnqueued, err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO outbox (id, kind, payload, created_at, logical_key, state_version) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING`,
		e.ID, e.Kind, payload, e.CreatedAt, e.LogicalKey, e.StateVersion)
	if err != nil {
		return VersionedEnqueued, err
	}
	if err := tx.Commit(ctx); err != nil {
		return VersionedEnqueued, err
	}
	if tag.RowsAffected() == 0 {
		return VersionedSuperseded, nil
	}
	return VersionedEnqueued, nil
}

// OutboxVersionGuard is the dispatcher's durable publish gate for one
// versioned row: publish only while the row still exists, no higher version
// has been delivered, and no higher version is pending (a pending newer
// version will publish the newer state, so publishing this one is redundant
// and could arrive late). A read failure is returned so dispatch fails
// closed instead of publishing without the guard.
func (s *PostgresStore) OutboxVersionGuard(ctx context.Context, id, logicalKey string, version int64) (bool, error) {
	if logicalKey == "" || version <= 0 {
		return true, nil
	}
	var alive, newerPending bool
	var delivered int64
	err := s.pool.QueryRow(ctx, `SELECT
			EXISTS (SELECT 1 FROM outbox WHERE id=$1),
			COALESCE((SELECT delivered_version FROM forge_check_state WHERE logical_key=$2), 0),
			EXISTS (SELECT 1 FROM outbox WHERE logical_key=$2 AND state_version > $3 AND dead_lettered_at IS NULL)`,
		id, logicalKey, version).Scan(&alive, &delivered, &newerPending)
	if err != nil {
		return false, err
	}
	return alive && delivered < version && !newerPending, nil
}

func (s *PostgresStore) OutboxHas(ctx context.Context, id string) (bool, error) {
	if id == "" {
		return false, fmt.Errorf("storage: empty outbox id")
	}
	var one int
	err := s.pool.QueryRow(ctx, `SELECT 1 FROM outbox WHERE id=$1`, id).Scan(&one)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// OutboxPending returns the active (not dead-lettered) outbox rows in FIFO
// order for startup replay. Dead-lettered rows are operator-visible through
// OutboxDeadLetters and must never be replayed or treated as pending work.
func (s *PostgresStore) OutboxPending(ctx context.Context) ([]OutboxItem, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, kind, payload, created_at, logical_key, state_version FROM outbox WHERE dead_lettered_at IS NULL ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OutboxItem{}
	for rows.Next() {
		var it OutboxItem
		var key *string
		if err := rows.Scan(&it.ID, &it.Kind, &it.Payload, &it.CreatedAt, &key, &it.StateVersion); err != nil {
			return nil, err
		}
		it.LogicalKey = nullableText(key)
		out = append(out, it)
	}
	return out, rows.Err()
}

// OutboxDeadLetters lists the retired (dead-lettered) outbox rows in FIFO
// order with the operator context (attempts, last error, retirement time) and
// the versioned delivery identity for triage.
func (s *PostgresStore) OutboxDeadLetters(ctx context.Context) ([]OutboxDeadLetter, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, kind, payload, created_at, attempts, last_error, dead_lettered_at, logical_key, state_version FROM outbox WHERE dead_lettered_at IS NOT NULL ORDER BY dead_lettered_at ASC, created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OutboxDeadLetter{}
	for rows.Next() {
		var it OutboxDeadLetter
		var key *string
		if err := rows.Scan(&it.ID, &it.Kind, &it.Payload, &it.CreatedAt, &it.Attempts, &it.LastError, &it.DeadLetteredAt, &key, &it.StateVersion); err != nil {
			return nil, err
		}
		it.LogicalKey = nullableText(key)
		out = append(out, it)
	}
	return out, rows.Err()
}

// OutboxRequeue resets one dead-lettered row to a fresh retry budget and an
// immediately due schedule, so the next claim picks it up. The WHERE guard
// keeps the operator action scoped to dead letters: a live row is never
// disturbed by a requeue.
func (s *PostgresStore) OutboxRequeue(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("storage: empty outbox id")
	}
	tag, err := s.pool.Exec(ctx, `UPDATE outbox SET attempts=0, last_error='', next_attempt_at=now(), claimed_at=NULL, claimed_by=NULL, dead_lettered_at=NULL WHERE id=$1 AND dead_lettered_at IS NOT NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// OutboxDelete removes one dead-lettered row. Like OutboxRequeue it is scoped
// to dead letters, so a live intent can never be discarded through the
// operator API.
func (s *PostgresStore) OutboxDelete(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("storage: empty outbox id")
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM outbox WHERE id=$1 AND dead_lettered_at IS NOT NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClaimOutbox atomically claims up to limit dispatchable rows for claimer:
// rows that are unclaimed or whose claim is older than OutboxClaimTTL are
// selected in FIFO order with FOR UPDATE SKIP LOCKED, so concurrent flushers
// on different replicas claim disjoint batches and never double-dispatch.
// The claim runs in a transaction FENCED by the store's leadership epoch: the
// leader-only outbox flush rejects a stale leader with ErrStaleLeader before
// claiming anything.
func (s *PostgresStore) ClaimOutbox(ctx context.Context, claimer string, limit int) ([]OutboxItem, error) {
	if strings.TrimSpace(claimer) == "" {
		return nil, fmt.Errorf("storage: empty outbox claimer")
	}
	if limit <= 0 {
		return nil, nil
	}
	tx, err := s.beginFencedTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	cutoff := time.Now().UTC().Add(-OutboxClaimTTL)
	rows, err := tx.Query(ctx, `UPDATE outbox o SET claimed_at = now(), claimed_by = $1
		FROM (
			SELECT id FROM outbox
			WHERE dead_lettered_at IS NULL
			  AND next_attempt_at <= now()
			  AND (claimed_at IS NULL OR claimed_at < $3)
			ORDER BY next_attempt_at ASC, created_at ASC, id ASC
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		) c
		WHERE o.id = c.id
		RETURNING o.id, o.kind, o.payload, o.created_at, o.logical_key, o.state_version`, claimer, limit, cutoff)
	if err != nil {
		return nil, err
	}
	out := []OutboxItem{}
	for rows.Next() {
		var it OutboxItem
		var key *string
		if err := rows.Scan(&it.ID, &it.Kind, &it.Payload, &it.CreatedAt, &key, &it.StateVersion); err != nil {
			rows.Close()
			return nil, err
		}
		it.LogicalKey = nullableText(key)
		out = append(out, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Commit releases the claimed rows to the caller: the claim is durable
	// (claimed_at/claimed_by), not transaction-scoped.
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// ReleaseOutboxClaim drops a claim the caller made but did not dispatch, so a
// retry can claim the row again immediately instead of waiting out the TTL.
// Only the claiming flusher can release: a stale claim is reclaimed by TTL.
// Fenced like the rest of the leader-only outbox claim lifecycle.
func (s *PostgresStore) ReleaseOutboxClaim(ctx context.Context, id, claimer string) error {
	if id == "" {
		return fmt.Errorf("storage: empty outbox id")
	}
	tx, err := s.beginFencedTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE outbox SET claimed_at = NULL, claimed_by = NULL WHERE id=$1 AND claimed_by=$2`, id, claimer); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ReleaseOutboxClaims drops every claim of the batch that is still owned by
// claimer in ONE statement (see OutboxClaimBatchStore): the id list is bound
// as an array and the claimer match makes the operation idempotent and safe
// against a concurrent re-claim — a row another flusher claimed in the
// meantime no longer matches claimed_by and is left untouched. It returns the
// number of rows actually released. Fenced like the rest of the leader-only
// outbox claim lifecycle.
func (s *PostgresStore) ReleaseOutboxClaims(ctx context.Context, ids []string, claimer string) (int, error) {
	if strings.TrimSpace(claimer) == "" {
		return 0, fmt.Errorf("storage: empty outbox claimer")
	}
	if len(ids) == 0 {
		return 0, nil
	}
	tx, err := s.beginFencedTx(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE outbox SET claimed_at = NULL, claimed_by = NULL WHERE id = ANY($1) AND claimed_by = $2`, ids, claimer)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// ---------------------------------------------------------------------------
// schedules
// ---------------------------------------------------------------------------

func (s *PostgresStore) UpsertSchedule(ctx context.Context, sc Schedule) error {
	if sc.ID == "" {
		return fmt.Errorf("storage: empty schedule id")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO schedules (id, repository, repo_id, repo_url, forge, trusted, spec, enabled, last_run, created_at, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT (id) DO UPDATE SET repository=EXCLUDED.repository, repo_id=EXCLUDED.repo_id, repo_url=EXCLUDED.repo_url, forge=EXCLUDED.forge, trusted=EXCLUDED.trusted, spec=EXCLUDED.spec, enabled=EXCLUDED.enabled, last_run=EXCLUDED.last_run, created_by=EXCLUDED.created_by`,
		sc.ID, sc.Repository, sc.RepoID, sc.RepoURL, sc.Forge, sc.Trusted, sc.Spec, sc.Enabled, sc.LastRun, sc.CreatedAt, sc.CreatedBy)
	return err
}

// GetSchedule reads one authoritative schedule row by ID.
func (s *PostgresStore) GetSchedule(ctx context.Context, id string) (Schedule, bool, error) {
	var sc Schedule
	err := s.pool.QueryRow(ctx, `SELECT id, repository, COALESCE(repo_id, ''), COALESCE(repo_url, ''), COALESCE(forge, ''), trusted, spec, enabled, last_run, created_at, COALESCE(created_by, '') FROM schedules WHERE id=$1`, id).
		Scan(&sc.ID, &sc.Repository, &sc.RepoID, &sc.RepoURL, &sc.Forge, &sc.Trusted, &sc.Spec, &sc.Enabled, &sc.LastRun, &sc.CreatedAt, &sc.CreatedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Schedule{}, false, nil
		}
		return Schedule{}, false, err
	}
	return sc, true, nil
}

func (s *PostgresStore) ListSchedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, repository, COALESCE(repo_id, ''), COALESCE(repo_url, ''), COALESCE(forge, ''), trusted, spec, enabled, last_run, created_at, COALESCE(created_by, '') FROM schedules ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Schedule{}
	for rows.Next() {
		var sc Schedule
		if err := rows.Scan(&sc.ID, &sc.Repository, &sc.RepoID, &sc.RepoURL, &sc.Forge, &sc.Trusted, &sc.Spec, &sc.Enabled, &sc.LastRun, &sc.CreatedAt, &sc.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// ClaimScheduleOccurrence atomically reserves the (schedule, nominal) firing
// for runID. The INSERT ... ON CONFLICT DO NOTHING makes concurrent claims
// race-free: exactly one caller wins the row. Re-claiming the same nominal
// for the same runID is idempotent and reports true. Occurrence insertion is
// leader-only, so the claim runs in a transaction FENCED by the store's
// leadership epoch (a stale leader claims no occurrence).
func (s *PostgresStore) ClaimScheduleOccurrence(ctx context.Context, scheduleID string, nominal time.Time, runID string) (bool, error) {
	if scheduleID == "" || runID == "" {
		return false, fmt.Errorf("storage: empty schedule or run id")
	}
	tx, err := s.beginFencedTx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	ct, err := tx.Exec(ctx, `INSERT INTO schedule_occurrences (schedule_id, nominal, run_id) VALUES ($1, $2, $3) ON CONFLICT (schedule_id, nominal) DO NOTHING`,
		scheduleID, nominal, runID)
	if err != nil {
		return false, err
	}
	if ct.RowsAffected() == 1 {
		if err := tx.Commit(ctx); err != nil {
			return false, err
		}
		return true, nil
	}
	var existing string
	err = tx.QueryRow(ctx, `SELECT run_id FROM schedule_occurrences WHERE schedule_id=$1 AND nominal=$2`, scheduleID, nominal).Scan(&existing)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// The insert reported no row and the follow-up read found none: a
		// concurrent claim rolled back, so retrying is safe and this call
		// reports the claim as won (the caller's transaction owns the
		// nominal).
		existing = runID
	case err != nil:
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return existing == runID, nil
}

func (s *PostgresStore) ListOccurrences(ctx context.Context, scheduleID string) ([]Occurrence, error) {
	if scheduleID == "" {
		return nil, fmt.Errorf("storage: empty schedule id")
	}
	rows, err := s.pool.Query(ctx, `SELECT schedule_id, nominal, run_id FROM schedule_occurrences WHERE schedule_id=$1 ORDER BY nominal ASC`, scheduleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Occurrence{}
	for rows.Next() {
		var o Occurrence
		if err := rows.Scan(&o.ScheduleID, &o.Nominal, &o.RunID); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// deployments
// ---------------------------------------------------------------------------

func (s *PostgresStore) InsertDeployment(ctx context.Context, d model.Deployment) error {
	if err := ValidateID(d.ID); err != nil {
		return err
	}
	if err := ValidateRunID(d.RunID); err != nil {
		return err
	}
	payload, err := jsonMarshal(d)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO deployments (id, run_id, job_id, environment, created_at, payload) VALUES ($1, $2, $3, $4, $5, $6)`,
		d.ID, d.RunID, nullText(d.JobID), d.Environment, d.CreatedAt, payload)
	return err
}

func (s *PostgresStore) ListDeploymentsByRun(ctx context.Context, runID string) ([]model.Deployment, error) {
	if err := ValidateRunID(runID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT payload FROM deployments WHERE run_id=$1 ORDER BY created_at ASC, id ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Deployment{}
	for rows.Next() {
		var (
			payload []byte
			d       model.Deployment
		)
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// UpdateDeploymentStatus locks the deployment row, rewrites status and
// finished_at inside the payload, and commits. A missing deployment returns
// ErrNotFound.
func (s *PostgresStore) UpdateDeploymentStatus(ctx context.Context, id string, status model.Status, finishedAt *time.Time) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var payload []byte
	err = tx.QueryRow(ctx, `SELECT payload FROM deployments WHERE id=$1 FOR UPDATE`, id).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	var d model.Deployment
	if err := json.Unmarshal(payload, &d); err != nil {
		return err
	}
	d.Status = status
	if finishedAt != nil {
		d.FinishedAt = finishedAt
	}
	dp, err := jsonMarshal(d)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE deployments SET payload=$2 WHERE id=$1`, id, dp); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---------------------------------------------------------------------------
// workspace snapshots
// ---------------------------------------------------------------------------

func (s *PostgresStore) InsertSnapshotRecord(ctx context.Context, rec model.SnapshotRecord) error {
	if err := ValidateID(rec.ID); err != nil {
		return err
	}
	if err := ValidateRunID(rec.RunID); err != nil {
		return err
	}
	payload, err := jsonMarshal(rec)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO workspace_snapshots (id, run_id, job_id, created_at, payload) VALUES ($1, $2, $3, $4, $5)`,
		rec.ID, rec.RunID, nullText(rec.JobID), rec.CreatedAt, payload)
	return err
}

func (s *PostgresStore) ListSnapshotsByRun(ctx context.Context, runID string) ([]model.SnapshotRecord, error) {
	if err := ValidateRunID(runID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT payload FROM workspace_snapshots WHERE run_id=$1 ORDER BY created_at ASC, id ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.SnapshotRecord{}
	for rows.Next() {
		var (
			payload []byte
			rec     model.SnapshotRecord
		)
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// artifact contracts
// ---------------------------------------------------------------------------

// InsertJobContracts overwrites the job's artifact_contracts jsonb key with
// the marshaled contract set. The update is a single jsonb_set so concurrent
// job updates cannot lose unrelated payload fields.
func (s *PostgresStore) InsertJobContracts(ctx context.Context, jobID string, contracts map[string]ArtifactContract) error {
	if err := ValidateJobID(jobID); err != nil {
		return err
	}
	cp, err := jsonMarshal(contracts)
	if err != nil {
		return err
	}
	ct, err := s.pool.Exec(ctx, `UPDATE jobs SET payload = jsonb_set(payload, '{artifact_contracts}', $2::jsonb, true) WHERE id=$1`, jobID, cp)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) GetJobContracts(ctx context.Context, jobID string) (map[string]ArtifactContract, bool, error) {
	if err := ValidateJobID(jobID); err != nil {
		return nil, false, err
	}
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT payload->'artifact_contracts' FROM jobs WHERE id=$1`, jobID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(raw) == 0 {
		return nil, false, nil
	}
	out := map[string]ArtifactContract{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// ---------------------------------------------------------------------------
// queue reasons
// ---------------------------------------------------------------------------

// SetQueueReasons persists each job's scheduling queue reason with one
// jsonb_set per job inside a single transaction. An empty reason removes the
// queue_reason key so reads never observe a stale reason; missing jobs are
// skipped (the scheduling pass may have raced a cancellation).
func (s *PostgresStore) SetQueueReasons(ctx context.Context, reasons map[string]string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for id, reason := range reasons {
		if err := ValidateJobID(id); err != nil {
			return err
		}
		if reason == "" {
			if _, err := tx.Exec(ctx, `UPDATE jobs SET payload = payload - 'queue_reason' WHERE id=$1`, id); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE jobs SET payload = jsonb_set(payload, '{queue_reason}', to_jsonb($2::text), true) WHERE id=$1`, id, reason); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ---------------------------------------------------------------------------
// dynamic pipeline generation
// ---------------------------------------------------------------------------

// InsertGeneratedJobs atomically inserts a generated job fragment uploaded
// by a runner under an active lease. Each job is fully compiled by the
// server (IDs, needs resolved); the transaction makes the whole fragment
// visible or nothing, so a partial fragment can never be scheduled.
func (s *PostgresStore) InsertGeneratedJobs(ctx context.Context, parentJobID string, depth int, jobs map[string]model.Job, deps map[string][]string) error {
	if err := ValidateJobID(parentJobID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for id, j := range jobs {
		if err := ValidateJobID(id); err != nil {
			return err
		}
		if err := s.insertJobTx(ctx, tx, j); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// GetGeneratedFragment reads one fragment idempotency receipt. found=false
// means the fragment was never admitted under this (parent, generation,
// fragment id) triple.
func (s *PostgresStore) GetGeneratedFragment(ctx context.Context, parentJobID string, generation int64, fragmentID string) (GeneratedFragmentReceipt, bool, error) {
	if err := ValidateJobID(parentJobID); err != nil {
		return GeneratedFragmentReceipt{}, false, err
	}
	if fragmentID == "" {
		return GeneratedFragmentReceipt{}, false, error(fmt.Errorf("storage: empty fragment id"))
	}
	var (
		raw []byte
		ts  time.Time
	)
	err := s.pool.QueryRow(ctx, `SELECT children, created_at FROM generated_fragments WHERE parent_job_id=$1 AND lease_generation=$2 AND fragment_id=$3`,
		parentJobID, generation, fragmentID).Scan(&raw, &ts)
	if errors.Is(err, pgx.ErrNoRows) {
		return GeneratedFragmentReceipt{}, false, nil
	}
	if err != nil {
		return GeneratedFragmentReceipt{}, false, err
	}
	rec := GeneratedFragmentReceipt{ParentJobID: parentJobID, LeaseGeneration: generation, FragmentID: fragmentID, CreatedAt: ts}
	if err := json.Unmarshal(raw, &rec.Children); err != nil {
		return GeneratedFragmentReceipt{}, false, err
	}
	return rec, true, nil
}

// InsertGeneratedFragmentTx inserts the fragment and its idempotency receipt
// and runs the verification closure in the SAME transaction:
//
//  1. a committed receipt for the same (parent, generation, fragment id) is
//     returned with replayed=true and nothing is inserted (the lost-response
//     replay path);
//  2. the parent job is locked FOR UPDATE and the run's current job count is
//     read inside the transaction, then the verifier re-checks {job, runner,
//     generation, token, expiry} and the max-jobs-per-run bound against that
//     fresh state;
//  3. the child jobs, dependency edges, artifact contracts and the receipt
//     commit together — a generated job with a Required artifact has its
//     contract row present before any completion can run, and a crash can
//     never leave a receipt without its children (or children without a
//     receipt).
//
// A concurrent duplicate insert that loses the receipt race rolls its own
// job rows back and returns the winner's receipt, so exactly one fragment is
// ever visible.
func (s *PostgresStore) InsertGeneratedFragmentTx(ctx context.Context, req GeneratedFragmentRequest, verify GeneratedJobVerifier) (GeneratedFragmentReceipt, bool, error) {
	if err := ValidateJobID(req.ParentJobID); err != nil {
		return GeneratedFragmentReceipt{}, false, err
	}
	if req.FragmentID == "" {
		return GeneratedFragmentReceipt{}, false, fmt.Errorf("storage: empty fragment id")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return GeneratedFragmentReceipt{}, false, err
	}
	defer tx.Rollback(ctx)
	// Replay fast path inside the transaction.
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT children FROM generated_fragments WHERE parent_job_id=$1 AND lease_generation=$2 AND fragment_id=$3 FOR UPDATE`,
		req.ParentJobID, req.LeaseGeneration, req.FragmentID).Scan(&raw)
	if err == nil {
		rec := GeneratedFragmentReceipt{ParentJobID: req.ParentJobID, LeaseGeneration: req.LeaseGeneration, FragmentID: req.FragmentID}
		if err := json.Unmarshal(raw, &rec.Children); err != nil {
			return GeneratedFragmentReceipt{}, false, err
		}
		return rec, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return GeneratedFragmentReceipt{}, false, err
	}
	js := jobScanner{}
	err = tx.QueryRow(ctx, `SELECT `+jobCols+` FROM jobs WHERE id=$1 FOR UPDATE`, req.ParentJobID).Scan(jobTargets(&js)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return GeneratedFragmentReceipt{}, false, ErrNotFound
	}
	if err != nil {
		return GeneratedFragmentReceipt{}, false, err
	}
	parent, err := js.job()
	if err != nil {
		return GeneratedFragmentReceipt{}, false, err
	}
	var runJobCount int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM jobs WHERE run_id=$1`, parent.RunID).Scan(&runJobCount); err != nil {
		return GeneratedFragmentReceipt{}, false, err
	}
	if verify != nil {
		if err := verify(parent, runJobCount); err != nil {
			return GeneratedFragmentReceipt{}, false, err
		}
	}
	for _, j := range req.Jobs {
		if err := ValidateJobID(j.ID); err != nil {
			return GeneratedFragmentReceipt{}, false, err
		}
		if err := s.insertJobRowTx(ctx, tx, j); err != nil {
			return GeneratedFragmentReceipt{}, false, err
		}
	}
	for _, j := range req.Jobs {
		if err := s.replaceDependenciesTx(ctx, tx, j); err != nil {
			return GeneratedFragmentReceipt{}, false, err
		}
	}
	for id, cs := range req.Contracts {
		if err := ValidateJobID(id); err != nil {
			return GeneratedFragmentReceipt{}, false, err
		}
		cp, err := jsonMarshal(cs)
		if err != nil {
			return GeneratedFragmentReceipt{}, false, err
		}
		if _, err := tx.Exec(ctx, `UPDATE jobs SET payload = jsonb_set(payload, '{artifact_contracts}', $2::jsonb, true) WHERE id=$1`, id, cp); err != nil {
			return GeneratedFragmentReceipt{}, false, err
		}
	}
	now := time.Now().UTC()
	// Canonical order contract: the caller passes Children in sorted-key
	// order (the same order its response reported).
	children := append([]GeneratedFragmentChild(nil), req.Children...)
	cb, err := jsonMarshal(children)
	if err != nil {
		return GeneratedFragmentReceipt{}, false, err
	}
	ct, err := tx.Exec(ctx, `INSERT INTO generated_fragments (parent_job_id, lease_generation, fragment_id, children, created_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (parent_job_id, lease_generation, fragment_id) DO NOTHING`,
		req.ParentJobID, req.LeaseGeneration, req.FragmentID, cb, now)
	if err != nil {
		return GeneratedFragmentReceipt{}, false, err
	}
	if ct.RowsAffected() == 0 {
		// A concurrent duplicate committed first: discard this transaction's
		// job rows and return the winner's receipt.
		var winner []byte
		if err := tx.QueryRow(ctx, `SELECT children FROM generated_fragments WHERE parent_job_id=$1 AND lease_generation=$2 AND fragment_id=$3`,
			req.ParentJobID, req.LeaseGeneration, req.FragmentID).Scan(&winner); err != nil {
			return GeneratedFragmentReceipt{}, false, err
		}
		rec := GeneratedFragmentReceipt{ParentJobID: req.ParentJobID, LeaseGeneration: req.LeaseGeneration, FragmentID: req.FragmentID}
		if err := json.Unmarshal(winner, &rec.Children); err != nil {
			return GeneratedFragmentReceipt{}, false, err
		}
		return rec, true, nil
	}
	if err := tx.Commit(ctx); err != nil {
		return GeneratedFragmentReceipt{}, false, err
	}
	return GeneratedFragmentReceipt{ParentJobID: req.ParentJobID, LeaseGeneration: req.LeaseGeneration, FragmentID: req.FragmentID, Children: children, CreatedAt: now}, false, nil
}

// ---------------------------------------------------------------------------
// downstream dispatch claims
// ---------------------------------------------------------------------------

// InsertDownstreamLink records one downstream launch claim. Re-inserting the
// same (parent, repo, ref) keeps the existing claim (ON CONFLICT DO NOTHING)
// so a replayed completion can never reset an already-launched link.
func (s *PostgresStore) InsertDownstreamLink(ctx context.Context, l DownstreamLink) error {
	if err := ValidateJobID(l.ParentJobID); err != nil {
		return err
	}
	if l.TargetRepo == "" || l.TargetRef == "" || l.LaunchToken == "" {
		return fmt.Errorf("storage: incomplete downstream link")
	}
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now().UTC()
	}
	var reservedAt any
	if l.ReservedAt != nil {
		reservedAt = l.ReservedAt
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO downstream_links (parent_job_id, target_repo, target_ref, launch_token, child_run_id, reserved, reserved_at, target_forge, target_base_url, target_repo_id, stable_child_id, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT (parent_job_id, target_repo, target_ref) DO NOTHING`,
		l.ParentJobID, l.TargetRepo, l.TargetRef, l.LaunchToken, l.ChildRunID, l.Reserved, reservedAt, l.TargetForge, l.TargetBaseURL, l.TargetRepoID, l.StableChildID, l.CreatedAt)
	return err
}

// GetDownstreamLink reads one downstream launch claim.
func (s *PostgresStore) GetDownstreamLink(ctx context.Context, parentJobID, targetRepo, targetRef string) (DownstreamLink, bool, error) {
	if err := ValidateJobID(parentJobID); err != nil {
		return DownstreamLink{}, false, err
	}
	var l DownstreamLink
	err := s.pool.QueryRow(ctx, `SELECT parent_job_id, target_repo, target_ref, launch_token, COALESCE(child_run_id, ''), reserved, reserved_at, COALESCE(target_forge, ''), COALESCE(target_base_url, ''), COALESCE(target_repo_id, ''), COALESCE(stable_child_id, ''), created_at FROM downstream_links WHERE parent_job_id=$1 AND target_repo=$2 AND target_ref=$3`,
		parentJobID, targetRepo, targetRef).Scan(&l.ParentJobID, &l.TargetRepo, &l.TargetRef, &l.LaunchToken, &l.ChildRunID, &l.Reserved, &l.ReservedAt, &l.TargetForge, &l.TargetBaseURL, &l.TargetRepoID, &l.StableChildID, &l.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DownstreamLink{}, false, nil
	}
	if err != nil {
		return DownstreamLink{}, false, err
	}
	return l, true, nil
}

// validateDownstreamReservation validates the reservation coordinates shared
// by the operator and leader-dispatch reservation variants.
func validateDownstreamReservation(parentJobID, targetRepo, targetRef, launchToken string) error {
	if err := ValidateJobID(parentJobID); err != nil {
		return err
	}
	if targetRepo == "" || targetRef == "" || launchToken == "" {
		return fmt.Errorf("storage: incomplete downstream reservation")
	}
	return nil
}

// ReserveDownstreamLaunch is the UNFENCED operator/compatibility variant of
// the downstream reservation. It is NOT the leader-dispatch path: the server's
// downstream dispatch (internal/server/downstream.go) calls the epoch-fenced
// ReserveDownstreamLaunchLeader, so a stale leader cannot claim a link.
//
// This method carries no leader authority: reserving a link does not launch
// anything, because the child can only be created by the child enqueue
// (InsertCompiledRun with a DownstreamLaunch claim), which is itself fenced.
// It remains for operator tooling and non-Postgres test doubles and keeps
// working without a leadership epoch.
func (s *PostgresStore) ReserveDownstreamLaunch(ctx context.Context, parentJobID, targetRepo, targetRef, launchToken string) (bool, error) {
	if err := validateDownstreamReservation(parentJobID, targetRepo, targetRef, launchToken); err != nil {
		return false, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	return s.reserveDownstreamLaunchTx(ctx, tx, parentJobID, targetRepo, targetRef, launchToken)
}

// ReserveDownstreamLaunchLeader is the leader-dispatch variant of the
// reservation: it runs in a transaction FENCED by the store's leadership
// epoch, so a replica whose cached claim outlived its advisory-lock session
// gets ErrStaleLeader and reserves nothing. The leader-owned downstream
// dispatch chain uses exactly this variant.
func (s *PostgresStore) ReserveDownstreamLaunchLeader(ctx context.Context, parentJobID, targetRepo, targetRef, launchToken string) (bool, error) {
	if err := validateDownstreamReservation(parentJobID, targetRepo, targetRef, launchToken); err != nil {
		return false, err
	}
	tx, err := s.beginFencedTx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	return s.reserveDownstreamLaunchTx(ctx, tx, parentJobID, targetRepo, targetRef, launchToken)
}

// reserveDownstreamLaunchTx atomically reserves the link inside tx BEFORE the
// child run is enqueued: the reservation UPDATE wins exactly once, and a
// missing row (restart dropped the in-memory copy) is created reserved.
// Returns true only when this call made the reservation.
func (s *PostgresStore) reserveDownstreamLaunchTx(ctx context.Context, tx pgx.Tx, parentJobID, targetRepo, targetRef, launchToken string) (bool, error) {
	var got string
	err := tx.QueryRow(ctx, `UPDATE downstream_links SET reserved=TRUE, reserved_at=now(), launch_token=$4 WHERE parent_job_id=$1 AND target_repo=$2 AND target_ref=$3 AND NOT reserved AND (child_run_id IS NULL OR child_run_id='') RETURNING parent_job_id`,
		parentJobID, targetRepo, targetRef, launchToken).Scan(&got)
	if err == nil {
		return true, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	var (
		child    string
		reserved bool
	)
	err = tx.QueryRow(ctx, `SELECT COALESCE(child_run_id, ''), reserved FROM downstream_links WHERE parent_job_id=$1 AND target_repo=$2 AND target_ref=$3`,
		parentJobID, targetRepo, targetRef).Scan(&child, &reserved)
	if err == nil {
		// Already launched or reserved by another flusher: not ours.
		return false, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	ct, err := tx.Exec(ctx, `INSERT INTO downstream_links (parent_job_id, target_repo, target_ref, launch_token, child_run_id, reserved, reserved_at, created_at) VALUES ($1, $2, $3, $4, '', TRUE, now(), now()) ON CONFLICT (parent_job_id, target_repo, target_ref) DO NOTHING`,
		parentJobID, targetRepo, targetRef, launchToken)
	if err != nil {
		return false, err
	}
	if ct.RowsAffected() == 1 {
		return true, tx.Commit(ctx)
	}
	return false, tx.Commit(ctx)
}

// MarkDownstreamLaunched atomically records the child run ID on a reserved
// link and consumes the reservation. It is an UNFENCED operator/compatibility
// method: the leader-owned downstream dispatch chain no longer calls it — the
// launch result is written inside the fenced child enqueue by
// claimDownstreamLaunchTx (InsertCompiledRun with a DownstreamLaunch claim),
// which commits child_run_id, stable_child_id and the consumed reservation
// together with the child run. With no leader-dispatch caller, this method
// carries no leader authority and deliberately works without an epoch (admin
// tooling and non-Postgres doubles).
func (s *PostgresStore) MarkDownstreamLaunched(ctx context.Context, parentJobID, targetRepo, targetRef, childRunID string) error {
	if err := ValidateJobID(parentJobID); err != nil {
		return err
	}
	if childRunID == "" {
		return fmt.Errorf("storage: empty child run id")
	}
	_, err := s.pool.Exec(ctx, `UPDATE downstream_links SET child_run_id=$4, reserved=FALSE, reserved_at=NULL WHERE parent_job_id=$1 AND target_repo=$2 AND target_ref=$3 AND (child_run_id IS NULL OR child_run_id='')`,
		parentJobID, targetRepo, targetRef, childRunID)
	return err
}

// ReleaseDownstreamReservation is the UNFENCED safety/operator variant: it
// clears a reservation whose launch failed so a retried dispatch can
// re-reserve the link. It is a SAFETY RELEASE, not leader authority — it can
// only transition reserved→unreserved on a link that has no child run, so it
// can neither launch nor prevent a launch (the next dispatch must still win
// the reservation and pass the fenced child enqueue). Operator triage and
// manual recovery use this variant; the leader-owned dispatch chain uses the
// fenced ReleaseDownstreamReservationLeader.
func (s *PostgresStore) ReleaseDownstreamReservation(ctx context.Context, parentJobID, targetRepo, targetRef string) error {
	if err := ValidateJobID(parentJobID); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `UPDATE downstream_links SET reserved=FALSE, reserved_at=NULL WHERE parent_job_id=$1 AND target_repo=$2 AND target_ref=$3 AND reserved AND (child_run_id IS NULL OR child_run_id='')`,
		parentJobID, targetRepo, targetRef)
	return err
}

// ReleaseDownstreamReservationLeader is the leader-dispatch failure/cleanup
// variant of the release: it runs in a transaction FENCED by the store's
// leadership epoch, so a replica that lost leadership while its launch was in
// flight gets ErrStaleLeader and leaves the reservation to the leader-only
// ExpireDownstreamReservations sweep (which re-opens the link for the current
// leader's retry). Nothing is mutated by a stale leader.
func (s *PostgresStore) ReleaseDownstreamReservationLeader(ctx context.Context, parentJobID, targetRepo, targetRef string) error {
	if err := ValidateJobID(parentJobID); err != nil {
		return err
	}
	tx, err := s.beginFencedTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE downstream_links SET reserved=FALSE, reserved_at=NULL WHERE parent_job_id=$1 AND target_repo=$2 AND target_ref=$3 AND reserved AND (child_run_id IS NULL OR child_run_id='')`,
		parentJobID, targetRepo, targetRef); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ExpireDownstreamReservations releases reservations older than the cutoff
// whose child never launched (crash recovery): the next dispatch can
// re-reserve and launch them. Returns the number of expired reservations.
// This is the leader-only reservation-recovery sweep, so it runs in a
// transaction FENCED by the store's leadership epoch: a stale leader expires
// nothing.
func (s *PostgresStore) ExpireDownstreamReservations(ctx context.Context, olderThan time.Time) (int, error) {
	tx, err := s.beginFencedTx(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	ct, err := tx.Exec(ctx, `UPDATE downstream_links SET reserved=FALSE, reserved_at=NULL WHERE reserved AND (child_run_id IS NULL OR child_run_id='') AND (reserved_at IS NULL OR reserved_at < $1)`,
		olderThan)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return int(ct.RowsAffected()), nil
}

// ---------------------------------------------------------------------------
// usage accounting
// ---------------------------------------------------------------------------

// RecentUsage sums the cost and energy recorded on jobs finished since the
// cutoff (the trailing 24h daily-budget window). Cost/energy are persisted
// inside the jobs payload (payload->>'cost', payload->>'energy_wh'); jobs
// that predate usage accounting contribute zero.
func (s *PostgresStore) RecentUsage(ctx context.Context, since time.Time) (cost, energy float64, err error) {
	err = s.pool.QueryRow(ctx, `SELECT COALESCE(SUM(COALESCE((payload->>'cost')::float8, 0)), 0), COALESCE(SUM(COALESCE((payload->>'energy_wh')::float8, 0)), 0) FROM jobs WHERE finished_at >= $1`,
		since).Scan(&cost, &energy)
	return cost, energy, err
}

// AdjustQuotaCounter shifts the reserved running/queued counters for the
// repo/team key pair. Counters clamp at zero; missing rows are tolerated.
func (s *PostgresStore) AdjustQuotaCounter(ctx context.Context, repoKey, teamKey string, runningDelta, queuedDelta int) error {
	if repoKey == "" && teamKey == "" {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, key := range []string{repoKey, teamKey} {
		if key == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE quota_reservations SET running = GREATEST(running + $2, 0), queued = GREATEST(queued + $3, 0), updated_at = now() WHERE key = $1`, key, runningDelta, queuedDelta); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// QuotaCounts reads the reserved running/queued counters for the key pair.
// Missing rows read as zero.
func (s *PostgresStore) QuotaCounts(ctx context.Context, repoKey, teamKey string) (running, queued int, err error) {
	for _, key := range []string{repoKey, teamKey} {
		if key == "" {
			continue
		}
		var kr, kq int
		qerr := s.pool.QueryRow(ctx, `SELECT running, queued FROM quota_reservations WHERE key=$1`, key).Scan(&kr, &kq)
		if qerr == nil {
			running += kr
			queued += kq
		} else if !errors.Is(qerr, pgx.ErrNoRows) {
			return 0, 0, qerr
		}
	}
	return running, queued, nil
}

// ---------------------------------------------------------------------------
// shared cache manifests
// ---------------------------------------------------------------------------

// PutCacheManifest stores a signed shared-cache manifest row keyed by
// (repo, trust_domain, logical_key), overwriting an existing entry for the
// same namespace. The full record (including the signed envelope) lives in
// the payload column; hot-path columns are real.
func (s *PostgresStore) PutCacheManifest(ctx context.Context, rec CacheManifestRecord) error {
	if rec.Repo == "" || rec.TrustDomain == "" || rec.LogicalKey == "" {
		return fmt.Errorf("storage: incomplete cache manifest namespace")
	}
	if len(rec.BlobSHA256) != 64 {
		return fmt.Errorf("storage: invalid cache manifest blob digest")
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	payload, err := jsonMarshal(rec)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO cache_manifests (repo, trust_domain, logical_key, blob_sha256, blob_size, producer_run, producer_job, created_at, payload) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (repo, trust_domain, logical_key) DO UPDATE SET blob_sha256=EXCLUDED.blob_sha256, blob_size=EXCLUDED.blob_size, producer_run=EXCLUDED.producer_run, producer_job=EXCLUDED.producer_job, created_at=EXCLUDED.created_at, payload=EXCLUDED.payload`,
		rec.Repo, rec.TrustDomain, rec.LogicalKey, rec.BlobSHA256, rec.BlobSize, nullText(rec.ProducerRun), nullText(rec.ProducerJob), rec.CreatedAt, payload)
	return err
}

// GetCacheManifest resolves the manifest row for a namespace.
func (s *PostgresStore) GetCacheManifest(ctx context.Context, repo, trustDomain, logicalKey string) (CacheManifestRecord, bool, error) {
	var (
		payload []byte
		rec     CacheManifestRecord
	)
	err := s.pool.QueryRow(ctx, `SELECT payload FROM cache_manifests WHERE repo=$1 AND trust_domain=$2 AND logical_key=$3`, repo, trustDomain, logicalKey).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return CacheManifestRecord{}, false, nil
	}
	if err != nil {
		return CacheManifestRecord{}, false, err
	}
	if err := json.Unmarshal(payload, &rec); err != nil {
		return CacheManifestRecord{}, false, err
	}
	return rec, true, nil
}

// SetArtifactSidecars and the pending artifact-sidecar store methods live in
// postgres_sidecars.go (generation-qualified artifact-sidecar contract).

// AppendDownstreamRun is the UNFENCED operator/compatibility variant of the
// parent→child edge append. It is NOT the leader-dispatch path: the wait=true
// downstream append in internal/server/downstream.go calls the epoch-fenced
// AppendDownstreamRunLeader. With no leader-dispatch caller this method
// carries no leader authority and deliberately works without an epoch
// (admin tooling and non-Postgres doubles).
func (s *PostgresStore) AppendDownstreamRun(ctx context.Context, runID, childRunID string) error {
	if err := ValidateRunID(runID); err != nil {
		return err
	}
	if childRunID == "" {
		return fmt.Errorf("storage: empty child run id")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	return s.appendDownstreamRunTx(ctx, tx, runID, childRunID)
}

// AppendDownstreamRunLeader is the leader-dispatch variant of the wait=true
// parent→child edge append: it runs in a transaction FENCED by the store's
// leadership epoch, so a stale leader cannot record a child edge on the
// parent run (and therefore cannot re-open or finalize aggregation for a
// child it never launched).
func (s *PostgresStore) AppendDownstreamRunLeader(ctx context.Context, runID, childRunID string) error {
	if err := ValidateRunID(runID); err != nil {
		return err
	}
	if childRunID == "" {
		return fmt.Errorf("storage: empty child run id")
	}
	tx, err := s.beginFencedTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	return s.appendDownstreamRunTx(ctx, tx, runID, childRunID)
}

// appendDownstreamRunTx appends childRunID to the parent run's
// downstream_runs payload key inside tx exactly once (idempotent): the row is
// locked FOR UPDATE and the append is skipped when the ID is already present.
func (s *PostgresStore) appendDownstreamRunTx(ctx context.Context, tx pgx.Tx, runID, childRunID string) error {
	var payload []byte
	err := tx.QueryRow(ctx, `SELECT payload FROM runs WHERE id=$1 FOR UPDATE`, runID).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	var run model.Run
	if err := json.Unmarshal(payload, &run); err != nil {
		return err
	}
	for _, id := range run.DownstreamRuns {
		if id == childRunID {
			return tx.Commit(ctx)
		}
	}
	run.DownstreamRuns = append(run.DownstreamRuns, childRunID)
	rp, err := jsonMarshal(run)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE runs SET payload=$2, `+normalizedRunRepoIdentityColumn+`=`+normalizedRunRepoIdentitySQL("$2")+`, `+normalizedRunRepoFullNameColumn+`=`+normalizedRunRepoFullNameSQL("$2")+` WHERE id=$1`, runID, rp); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ReopenRunForChildren marks a terminal-success run as running again while
// wait=true downstream children are still in flight. The real status column
// and the payload status field are updated together and finished_at is
// cleared.
func (s *PostgresStore) ReopenRunForChildren(ctx context.Context, runID string) error {
	if err := ValidateRunID(runID); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `UPDATE runs SET status='running', finished_at=NULL, payload = jsonb_set(payload, '{status}', '"running"', true), `+normalizedRunRepoIdentityColumn+`=`+normalizedRunRepoIdentitySQL("payload")+`, `+normalizedRunRepoFullNameColumn+`=`+normalizedRunRepoFullNameSQL("payload")+` WHERE id=$1 AND status='success'`, runID)
	return err
}

// LoadTestHistory reads the cached test-history aggregates and their
// version (migration 0008). A missing row reports version 0 with empty
// stats so a fresh database behaves like an empty history file.
func (s *PostgresStore) LoadTestHistory(ctx context.Context) (int64, []byte, error) {
	var (
		version int64
		stats   []byte
	)
	err := s.pool.QueryRow(ctx, `SELECT version, stats::text FROM test_history WHERE id=1`).Scan(&version, &stats)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	if string(stats) == "{}" {
		stats = nil
	}
	return version, stats, nil
}

// SaveTestHistory writes the serialized history aggregates and bumps the
// cache version atomically in the same statement, so every committed upload
// advances the version exactly once and replicas reload on the next read.
func (s *PostgresStore) SaveTestHistory(ctx context.Context, stats []byte) (int64, error) {
	if len(stats) == 0 {
		stats = []byte("{}")
	}
	var version int64
	err := s.pool.QueryRow(ctx, `INSERT INTO test_history (id, version, stats) VALUES (1, 1, $1::jsonb) ON CONFLICT (id) DO UPDATE SET version = test_history.version + 1, stats = EXCLUDED.stats, updated_at = now() RETURNING version`,
		string(stats)).Scan(&version)
	return version, err
}

// leaderProbeTimeout bounds the cached-session liveness probe (which runs
// outside leaderMu), ReleaseLeadership's unlock round-trip, and the close of a
// session or rejected candidate this store is dropping.
const leaderProbeTimeout = 2 * time.Second

// leaderAcquireTimeout bounds the connect plus advisory try-lock round-trips
// of a fresh candidate session; the caller's context still applies when
// shorter. It is a var only so tests can shrink the bound — production never
// reassigns it (same seam convention as randReader/jsonMarshal above).
var leaderAcquireTimeout = 2 * time.Second

// leaderProbeInterval returns how long a successful liveness proof is trusted
// before a cached call has to re-prove the session: min(1s, ttl/5), so the
// window in which a dead session could still be reported true stays at most
// one second and never exceeds a fifth of the claim's own renewal window.
func leaderProbeInterval(ttl time.Duration) time.Duration {
	if d := ttl / 5; d > 0 && d <= time.Second {
		return d
	}
	return time.Second
}

// leaderProbeFn performs the liveness round-trip that proves a cached leader
// session still exists. Production pings the cached connection itself (Ping
// opens no new connection); tests override it to inject a slow or failing
// probe. Like randReader/jsonMarshal above it is only reassigned by tests.
var leaderProbeFn = func(ctx context.Context, conn *pgx.Conn) error {
	return conn.Ping(ctx)
}

// Leadership invariant: leaderConn is the ONLY proof of leadership this store
// exposes. Its session-level advisory lock lives exactly as long as that
// PostgreSQL session, so the cached leaderKey/leaderHeldUntil pair is never
// trusted on its own. A cached success is renewed only while the last
// successful proof (the acquisition round-trip that took the lock, or a later
// liveness probe on the SAME connection) is younger than leaderProbeInterval;
// beyond that a probe must succeed first. Any failed proof — or a locally
// closed session, detected without I/O — clears the cache and falls through
// to a real acquisition attempt instead of returning true.
//
// The throttle is still a window: a dead session can be reported true for up
// to min(1s, ttl/5) without touching PostgreSQL, and no amount of health
// checking can close that TOCTOU because the advisory lock lives on a
// different connection than the mutations. The window is closed by the
// leadership EPOCH instead (migration 0025): acquisition publishes a
// strictly-greater epoch on the SAME dedicated session and this store retains
// it; every leader-only mutation re-validates that epoch inside its own
// transaction (assertLeaderEpoch) and fails closed with ErrStaleLeader
// otherwise. A cached true can therefore briefly survive lock loss, but a
// stale leader can complete none of its mutations: the epoch it presents is
// no longer the durable one, so its transactions abort having mutated
// nothing. Loss (release, dead session, key change, fence mismatch) clears
// the retained epoch.
//
// Locking: leaderMu guards the cached fields only and is never held across a
// round-trip. Fresh cached calls do no I/O at all; the probe runs OUTSIDE the
// lock, single-flight (leaderProbeWait), so one slow or dead connection
// cannot pin the mutex or the cached hot path; the candidate connect plus
// try-lock runs outside the lock under leaderAcquireTimeout, serialized on
// leaderAcquireMu (which the cached hot path never takes). The same rule
// drives the lifecycle: a session is only closed after
// detachLeaderSessionLocked cleared every cached field BEFORE any I/O, and
// ReleaseLeadership clears the cache even when the unlock round-trip fails (a
// failed unlock on a live session leaves the lock held, so the session is
// closed to release it deterministically).
//
// TryAcquireLeadership takes a session-level Postgres advisory lock on a
// dedicated connection held outside the pool. Advisory locks die with the
// connection, so a crashed leader's lease is released automatically.
func (s *PostgresStore) TryAcquireLeadership(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if key == "" {
		return false, fmt.Errorf("storage: empty leadership key")
	}
	if ttl <= 0 {
		return false, fmt.Errorf("storage: non-positive leadership ttl")
	}
	interval := leaderProbeInterval(ttl)
	for {
		s.leaderMu.Lock()
		if s.leaderConn != nil && s.leaderKey == key && time.Now().Before(s.leaderHeldUntil) {
			conn := s.leaderConn
			if !conn.IsClosed() && s.leaderEpoch.Load() > 0 {
				if time.Since(s.leaderProbedAt) < interval {
					// The last successful proof is still fresh: renew the
					// soft window and return without any round-trip. This is
					// the scheduler hot path (every runner poll, twice per
					// Maintain tick). Serving the cached true here is safe
					// because every leader-only mutation is epoch-fenced:
					// see the invariant above.
					s.leaderHeldUntil = time.Now().Add(ttl)
					s.leaderMu.Unlock()
					return true, nil
				}
				if waiter := s.leaderProbeWait; waiter != nil {
					// A probe for this session is already in flight: wait for
					// its bounded result (or this caller's cancellation) and
					// re-evaluate the cache instead of stacking duplicate
					// probes.
					s.leaderMu.Unlock()
					select {
					case <-waiter:
					case <-ctx.Done():
						return false, ctx.Err()
					}
					continue
				}
				// Proof is stale: probe OUTSIDE leaderMu, single-flight, so a
				// slow or dead connection cannot pin the mutex or the cached
				// hot path.
				waiter := make(chan struct{})
				s.leaderProbeWait = waiter
				s.leaderMu.Unlock()

				probeErr := s.probeLeaderConn(ctx, conn)

				s.leaderMu.Lock()
				close(waiter)
				s.leaderProbeWait = nil
				stillCached := s.leaderConn == conn && s.leaderKey == key && time.Now().Before(s.leaderHeldUntil)
				if stillCached && probeErr == nil {
					now := time.Now()
					s.leaderProbedAt = now
					s.leaderHeldUntil = now.Add(ttl)
					s.leaderMu.Unlock()
					return true, nil
				}
				if stillCached {
					// The session (and with it the advisory lock) is gone:
					// another replica may already hold the key. Drop the
					// stale cache and run the normal acquisition path; never
					// report the cached true.
					deadConn := s.detachLeaderSessionLocked()
					s.leaderMu.Unlock()
					s.closeLeaderConn(deadConn)
					continue
				}
				s.leaderMu.Unlock()
				continue
			}
			// The session is locally closed (the advisory lock died with it)
			// or this store retains no epoch (a fenced mutation observed a
			// newer durable epoch, so the cached proof cannot mutate). Drop
			// it and re-enter the loop for a real acquisition.
			deadConn := s.detachLeaderSessionLocked()
			s.leaderMu.Unlock()
			s.closeLeaderConn(deadConn)
			continue
		}
		if s.leaderConn != nil {
			// Key change or elapsed local TTL: the old session must not stay
			// cached as proof for a key it does not hold.
			deadConn := s.detachLeaderSessionLocked()
			s.leaderMu.Unlock()
			s.closeLeaderConn(deadConn)
			continue
		}
		s.leaderMu.Unlock()

		// No cached leadership: acquire a candidate session. Acquisition is
		// serialized on leaderAcquireMu and its round-trips run outside
		// leaderMu under a bounded context.
		got, done, err := s.acquireLeaderSession(ctx, key, ttl, interval)
		if done {
			return got, err
		}
		// A concurrent caller cached a live session while this one waited to
		// acquire; re-evaluate it through the cached path above.
	}
}

// probeLeaderConn runs the cached-session liveness round-trip OUTSIDE
// leaderMu, bounded by leaderProbeTimeout and detached from the caller's
// cancellation: a canceled caller must not tear down a live leader session,
// while a dead session is detected and dropped regardless.
func (s *PostgresStore) probeLeaderConn(ctx context.Context, conn *pgx.Conn) error {
	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), leaderProbeTimeout)
	defer cancel()
	return leaderProbeFn(probeCtx, conn)
}

// acquireLeaderSession opens a fresh dedicated session and attempts the
// advisory lock for key, returning done=false when a concurrent caller cached
// a live session while this one waited on leaderAcquireMu, so the caller
// re-evaluates the cache instead of opening a duplicate session. Everything
// runs outside leaderMu; the caller's context (capped at
// leaderAcquireTimeout) bounds the connect and try-lock so a black-holed
// database cannot block for the driver's multi-minute default connect
// timeout.
func (s *PostgresStore) acquireLeaderSession(ctx context.Context, key string, ttl, interval time.Duration) (got, done bool, err error) {
	s.leaderAcquireMu.Lock()
	defer s.leaderAcquireMu.Unlock()

	// Re-check the cache: a concurrent acquisition may have cached the key
	// while this call waited. A fresh proof is reused; a stale one is left to
	// the caller's cached path so the throttle and probe rules still apply.
	s.leaderMu.Lock()
	if s.leaderConn != nil && s.leaderKey == key && time.Now().Before(s.leaderHeldUntil) && !s.leaderConn.IsClosed() && s.leaderEpoch.Load() > 0 {
		if time.Since(s.leaderProbedAt) < interval {
			s.leaderHeldUntil = time.Now().Add(ttl)
			s.leaderMu.Unlock()
			return true, true, nil
		}
		s.leaderMu.Unlock()
		return false, false, nil
	}
	// A session for another key (or a locally closed or unfenced one) must not
	// outlive this acquisition: the store keeps at most one cached leader
	// session. The detach also clears the retained epoch.
	oldConn := s.detachLeaderSessionLocked()
	s.leaderMu.Unlock()
	s.closeLeaderConn(oldConn)

	if s.pool == nil {
		return false, true, fmt.Errorf("storage: pool unavailable")
	}
	cc := s.pool.Config().ConnConfig
	if cc == nil {
		return false, true, fmt.Errorf("storage: pool has no conn config")
	}
	actx, cancel := context.WithTimeout(ctx, leaderAcquireTimeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(actx, cc)
	if err != nil {
		return false, true, err
	}
	var acquired bool
	if err := conn.QueryRow(actx, `SELECT pg_try_advisory_lock(hashtext($1))`, key).Scan(&acquired); err != nil {
		s.closeLeaderConn(conn)
		return false, true, err
	}
	if !acquired {
		s.closeLeaderConn(conn)
		return false, true, nil
	}
	// The advisory lock is held. Publish the strictly-greater epoch on THIS
	// same session: the increment is one transaction, so a connection that
	// dies before commit publishes nothing, and the lock died with that same
	// session — no replica can ever observe a leader that holds the lock
	// without having published its epoch. A publish failure therefore closes
	// the session (releasing the lock) and reports the error instead of
	// caching a lock holder with no fence.
	epoch, err := s.publishLeaderEpoch(actx, conn)
	if err != nil {
		s.closeLeaderConn(conn)
		return false, true, fmt.Errorf("storage: publish leadership epoch: %w", err)
	}
	now := time.Now()
	// Retain the epoch BEFORE caching the session: a concurrent fenced
	// operation must never see the new session with the old (now-stale)
	// retained epoch. clearLeaderEpochIf only clears the value it compared
	// against, so a racing detection cannot clobber this fresh epoch.
	s.leaderEpoch.Store(epoch)
	s.leaderMu.Lock()
	s.leaderConn = conn
	s.leaderKey = key
	s.leaderProbedAt = now
	s.leaderHeldUntil = now.Add(ttl)
	s.leaderMu.Unlock()
	return true, true, nil
}

// detachLeaderSessionLocked removes the cached leader session and returns its
// connection, clearing every cached field BEFORE any I/O so no concurrent
// reader can observe a released session as a held-leadership proof. The
// retained leadership epoch is cleared with it: once this store no longer
// holds (or cannot prove) the claim, every leader-fenced operation must fail
// closed until a fresh acquisition publishes a new epoch. The caller holds
// leaderMu and must close the returned connection outside the lock
// (closeLeaderConn). Returns nil when nothing was cached.
func (s *PostgresStore) detachLeaderSessionLocked() *pgx.Conn {
	conn := s.leaderConn
	s.leaderConn = nil
	s.leaderKey = ""
	s.leaderHeldUntil = time.Time{}
	s.leaderProbedAt = time.Time{}
	s.leaderEpoch.Store(0)
	return conn
}

// closeLeaderConn closes a session connection that was already detached from
// the cache (a dropped leader session or a rejected acquisition candidate).
// Closing the PostgreSQL session releases every session-level advisory lock it
// holds, so no separate unlock round-trip is needed on the drop path. The
// close is bounded and best-effort, and runs outside leaderMu.
func (s *PostgresStore) closeLeaderConn(conn *pgx.Conn) {
	if conn == nil {
		return
	}
	cctx, cancel := context.WithTimeout(context.Background(), leaderProbeTimeout)
	defer cancel()
	_ = conn.Close(cctx)
}

func (s *PostgresStore) ReleaseLeadership(ctx context.Context, key string) error {
	s.leaderMu.Lock()
	if s.leaderConn == nil || s.leaderKey != key {
		s.leaderMu.Unlock()
		return nil
	}
	conn := s.detachLeaderSessionLocked()
	s.leaderMu.Unlock()
	// The unlock round-trip runs outside leaderMu, bounded by the caller's
	// context capped at leaderProbeTimeout, and its error is returned: a
	// failed unlock on a live session leaves the lock held and the close
	// below releases it deterministically; on an already-dead session the
	// failed round-trip is the contract this method reports.
	uctx, cancel := context.WithTimeout(ctx, leaderProbeTimeout)
	defer cancel()
	_, err := conn.Exec(uctx, `SELECT pg_advisory_unlock(hashtext($1))`, key)
	s.closeLeaderConn(conn)
	return err
}

// ---------------------------------------------------------------------------
// schema
// ---------------------------------------------------------------------------

// Migrate applies pending migrations in version order, each inside its own
// transaction guarded by a transaction-scoped advisory lock so concurrent
// instances cannot apply the same migration twice.
func (s *PostgresStore) Migrate(ctx context.Context) error {
	all, err := migrations.All()
	if err != nil {
		return err
	}
	for _, m := range all {
		if err := s.applyMigration(ctx, m); err != nil {
			return fmt.Errorf("storage: migrate %s: %w", m.Name, err)
		}
	}
	return nil
}

func (s *PostgresStore) applyMigration(ctx context.Context, m migrations.Migration) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('kiwi_schema_migrations'))`); err != nil {
		return err
	}
	// schema_migrations may not exist yet (fresh schema, migration 0001).
	// Resolve the table with to_regclass BEFORE touching it: a plain EXISTS
	// probe would raise undefined_table (42P01) inside this transaction,
	// aborting it (25P02) and making Migrate unable to bootstrap a fresh
	// database. to_regclass answers "present?" without an error.
	var haveTable bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&haveTable); err != nil {
		return err
	}
	applied := false
	if haveTable {
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=$1)`, m.Version).Scan(&applied); err != nil {
			return err
		}
	}
	if applied {
		return tx.Commit(ctx)
	}
	for _, stmt := range m.Statements {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, m.Version); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) SchemaVersion(ctx context.Context) (int, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname=current_schema() AND tablename='schema_migrations')`).Scan(&exists); err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	var v int
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// runner profiles, per-runner tokens, revocations, enrollment grants
// (migration 0006)
// ---------------------------------------------------------------------------

var (
	_ ProfileStore        = (*PostgresStore)(nil)
	_ RunnerTokenStore    = (*PostgresStore)(nil)
	_ CertRevocationStore = (*PostgresStore)(nil)
	_ EnrollGrantStore    = (*PostgresStore)(nil)
	_ TestHistoryStore    = (*PostgresStore)(nil)
)

// scanProfile reads one runner_profiles row into a model.RunnerProfile.
// The resource capacity columns (migration 0030) default to 0 = unconstrained
// for every pre-0030 row and for profiles created without them.
func scanProfile(row pgx.Row) (model.RunnerProfile, error) {
	var (
		p           model.RunnerProfile
		labels      []byte
		region      string
		repos       []byte
		caps        []byte
		maxCapacity int
		maxCPU      float64
		maxMemory   int64
		maxDisk     int64
		maxPIDs     int
		cost        float64
		watts       float64
	)
	err := row.Scan(&p.ID, &labels, &region, &repos, &caps, &maxCapacity, &maxCPU, &maxMemory, &maxDisk, &maxPIDs, &cost, &watts, &p.CreatedAt)
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(labels, &p.Labels); err != nil {
		return p, fmt.Errorf("storage: decode profile labels: %w", err)
	}
	if err := json.Unmarshal(repos, &p.Repositories); err != nil {
		return p, fmt.Errorf("storage: decode profile repositories: %w", err)
	}
	if err := json.Unmarshal(caps, &p.Capabilities); err != nil {
		return p, fmt.Errorf("storage: decode profile capabilities: %w", err)
	}
	p.Region = region
	p.MaxCapacity = maxCapacity
	p.MaxCPU = maxCPU
	p.MaxMemory = maxMemory
	p.MaxDisk = maxDisk
	p.MaxPIDs = maxPIDs
	p.CostPerHour = cost
	p.PowerWatts = watts
	return p, nil
}

const profileCols = "id, labels, region, repositories, capabilities, max_capacity, max_cpu, max_memory, max_disk, max_pids, cost_per_hour, power_watts, created_at"

// profileColsAliased is profileCols qualified with a table alias for the
// cert_profile_links join; the two lists MUST stay in the same order.
const profileColsAliased = "rp.id, rp.labels, rp.region, rp.repositories, rp.capabilities, rp.max_capacity, rp.max_cpu, rp.max_memory, rp.max_disk, rp.max_pids, rp.cost_per_hour, rp.power_watts, rp.created_at"

func (s *PostgresStore) UpsertProfile(ctx context.Context, p model.RunnerProfile) error {
	if p.ID == "" {
		return fmt.Errorf("storage: profile id is required")
	}
	labels, err := jsonMarshal(p.Labels)
	if err != nil {
		return err
	}
	if len(labels) == 0 || string(labels) == "null" {
		labels = []byte("[]")
	}
	repos, err := jsonMarshal(p.Repositories)
	if err != nil {
		return err
	}
	if len(repos) == 0 || string(repos) == "null" {
		repos = []byte("[]")
	}
	caps, err := jsonMarshal(p.Capabilities)
	if err != nil {
		return err
	}
	if len(caps) == 0 || string(caps) == "null" {
		caps = []byte("[]")
	}
	created := p.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO runner_profiles (id, labels, region, repositories, capabilities, max_capacity, max_cpu, max_memory, max_disk, max_pids, cost_per_hour, power_watts, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT (id) DO UPDATE SET labels=EXCLUDED.labels, region=EXCLUDED.region, repositories=EXCLUDED.repositories, capabilities=EXCLUDED.capabilities, max_capacity=EXCLUDED.max_capacity, max_cpu=EXCLUDED.max_cpu, max_memory=EXCLUDED.max_memory, max_disk=EXCLUDED.max_disk, max_pids=EXCLUDED.max_pids, cost_per_hour=EXCLUDED.cost_per_hour, power_watts=EXCLUDED.power_watts`,
		p.ID, labels, p.Region, repos, caps, p.MaxCapacity, p.MaxCPU, p.MaxMemory, p.MaxDisk, p.MaxPIDs, p.CostPerHour, p.PowerWatts, created)
	return err
}

func (s *PostgresStore) GetProfile(ctx context.Context, id string) (model.RunnerProfile, error) {
	p, err := scanProfile(s.pool.QueryRow(ctx, `SELECT `+profileCols+` FROM runner_profiles WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.RunnerProfile{}, ErrNotFound
	}
	return p, err
}

func (s *PostgresStore) ListProfiles(ctx context.Context) ([]model.RunnerProfile, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+profileCols+` FROM runner_profiles ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.RunnerProfile{}
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *PostgresStore) BindCertProfile(ctx context.Context, serial, profileID string) error {
	if serial == "" {
		return fmt.Errorf("storage: certificate serial is required")
	}
	if profileID == "" {
		return fmt.Errorf("storage: profile id is required")
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO cert_profile_links (serial, profile_id) VALUES ($1,$2) ON CONFLICT (serial) DO UPDATE SET profile_id=EXCLUDED.profile_id`, serial, profileID); err != nil {
		return err
	}
	return nil
}

func (s *PostgresStore) ProfileForSerial(ctx context.Context, serial string) (model.RunnerProfile, bool, error) {
	if serial == "" {
		return model.RunnerProfile{}, false, nil
	}
	p, err := scanProfile(s.pool.QueryRow(ctx, `SELECT `+profileColsAliased+` FROM cert_profile_links cl JOIN runner_profiles rp ON rp.id = cl.profile_id WHERE cl.serial=$1`, serial))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.RunnerProfile{}, false, nil
	}
	if err != nil {
		return model.RunnerProfile{}, false, err
	}
	return p, true, nil
}

func (s *PostgresStore) UpsertRunnerToken(ctx context.Context, runnerID, tokenDigest string) error {
	if runnerID == "" {
		return fmt.Errorf("storage: runner id is required")
	}
	if tokenDigest == "" {
		return fmt.Errorf("storage: token digest is required")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO runner_bearer_tokens (runner_id, token_digest) VALUES ($1,$2) ON CONFLICT (runner_id) DO UPDATE SET token_digest=EXCLUDED.token_digest`, runnerID, tokenDigest)
	return err
}

func (s *PostgresStore) RunnerIDForToken(ctx context.Context, tokenDigest string) (string, bool, error) {
	if tokenDigest == "" {
		return "", false, nil
	}
	var id string
	err := s.pool.QueryRow(ctx, `SELECT runner_id FROM runner_bearer_tokens WHERE token_digest=$1`, tokenDigest).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return id, true, nil
}

func (s *PostgresStore) HasRunnerTokens(ctx context.Context) (bool, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM runner_bearer_tokens LIMIT 1)`).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

func (s *PostgresStore) CertRevoked(ctx context.Context, serial string) (bool, error) {
	if serial == "" {
		return false, nil
	}
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cert_revocations WHERE serial=$1)`, serial).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

func (s *PostgresStore) PutEnrollGrant(ctx context.Context, digest string, expiresAt time.Time, boundLabels []string) error {
	if digest == "" {
		return fmt.Errorf("storage: enroll grant digest is required")
	}
	labels, err := jsonMarshal(boundLabels)
	if err != nil {
		return err
	}
	if len(labels) == 0 || string(labels) == "null" {
		labels = []byte("[]")
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO enrollment_grants (digest, expires_at, bound_labels) VALUES ($1,$2,$3) ON CONFLICT (digest) DO NOTHING`, digest, expiresAt, labels)
	return err
}

func (s *PostgresStore) GetEnrollGrant(ctx context.Context, digest string) (EnrollGrantRecord, bool, error) {
	if digest == "" {
		return EnrollGrantRecord{}, false, nil
	}
	var (
		rec        EnrollGrantRecord
		labelsJSON []byte
		consumedAt *time.Time
	)
	err := s.pool.QueryRow(ctx, `SELECT expires_at, bound_labels, consumed_at FROM enrollment_grants WHERE digest=$1`, digest).
		Scan(&rec.ExpiresAt, &labelsJSON, &consumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return EnrollGrantRecord{}, false, nil
	}
	if err != nil {
		return EnrollGrantRecord{}, false, err
	}
	if err := json.Unmarshal(labelsJSON, &rec.BoundLabels); err != nil {
		return EnrollGrantRecord{}, false, fmt.Errorf("storage: decode grant bound labels: %w", err)
	}
	rec.Consumed = consumedAt != nil
	return rec, true, nil
}

// ConsumeEnrollGrant is the atomic single-use claim: the conditional UPDATE
// matches only rows with consumed_at IS NULL and expires_at in the future,
// so two concurrent enrollments of the same grant yield exactly one winner.
// On no match the row state is re-read to report the precise failure reason
// (unknown vs consumed vs expired).
func (s *PostgresStore) ConsumeEnrollGrant(ctx context.Context, digest string, consumedBy string) (EnrollGrantRecord, error) {
	if digest == "" {
		return EnrollGrantRecord{}, ErrNotFound
	}
	var rec EnrollGrantRecord
	var labelsJSON []byte
	err := s.pool.QueryRow(ctx, `UPDATE enrollment_grants SET consumed_at=now(), consumed_by=$2 WHERE digest=$1 AND consumed_at IS NULL AND expires_at > now() RETURNING expires_at, bound_labels`, digest, consumedBy).
		Scan(&rec.ExpiresAt, &labelsJSON)
	if err == nil {
		if uerr := json.Unmarshal(labelsJSON, &rec.BoundLabels); uerr != nil {
			return EnrollGrantRecord{}, fmt.Errorf("storage: decode grant bound labels: %w", uerr)
		}
		rec.Consumed = true
		return rec, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return EnrollGrantRecord{}, err
	}
	// No row matched: distinguish unknown vs consumed vs expired.
	existing, ok, gerr := s.GetEnrollGrant(ctx, digest)
	if gerr != nil {
		return EnrollGrantRecord{}, gerr
	}
	if !ok {
		return EnrollGrantRecord{}, ErrNotFound
	}
	if existing.Consumed {
		return EnrollGrantRecord{}, ErrGrantConsumed
	}
	return EnrollGrantRecord{}, ErrGrantExpired
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func nullText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func removeString(in []string, v string) []string {
	out := in[:0]
	for _, x := range in {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

func containsString(in []string, v string) bool {
	for _, x := range in {
		if x == v {
			return true
		}
	}
	return false
}

// OutboxRetry records a failed dispatch attempt: the attempt counter grows,
// the error is retained for operators, and the next attempt is scheduled
// with bounded exponential backoff + jitter. After maxAttempts the row is
// DEAD-LETTERED, so a permanently broken integration (revoked credentials,
// invalid payload) cannot hot-loop forever.
func (s *PostgresStore) OutboxRetry(ctx context.Context, id string, dispatchErr error, maxAttempts int) error {
	if id == "" {
		return fmt.Errorf("storage: empty outbox id")
	}
	msg := ""
	if dispatchErr != nil {
		msg = dispatchErr.Error()
	}
	backoff := time.Second
	var attempts int
	if err := s.pool.QueryRow(ctx, `SELECT attempts FROM outbox WHERE id=$1`, id).Scan(&attempts); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	for i := 0; i < attempts && backoff < time.Minute; i++ {
		backoff *= 2
	}
	jitter := time.Duration(time.Now().UnixNano() % int64(backoff/4+1))
	if maxAttempts > 0 && attempts+1 >= maxAttempts {
		_, err := s.pool.Exec(ctx, `UPDATE outbox SET attempts=attempts+1, last_error=$2, claimed_at=NULL, claimed_by=NULL, dead_lettered_at=now() WHERE id=$1`, id, msg)
		return err
	}
	_, err := s.pool.Exec(ctx, `UPDATE outbox SET attempts=attempts+1, last_error=$2, claimed_at=NULL, claimed_by=NULL, next_attempt_at=now()+$3 WHERE id=$1`, id, msg, backoff+jitter)
	return err
}

// OutboxPendingItems returns rows that are pending, not dead-lettered and
// due, for startup replay.
func (s *PostgresStore) OutboxDue(ctx context.Context) ([]OutboxItem, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, kind, payload, created_at, logical_key, state_version FROM outbox WHERE dead_lettered_at IS NULL AND next_attempt_at <= now() ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OutboxItem{}
	for rows.Next() {
		var it OutboxItem
		var key *string
		if err := rows.Scan(&it.ID, &it.Kind, &it.Payload, &it.CreatedAt, &key, &it.StateVersion); err != nil {
			return nil, err
		}
		it.LogicalKey = nullableText(key)
		out = append(out, it)
	}
	return out, rows.Err()
}
