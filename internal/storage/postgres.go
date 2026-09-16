package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

	leaderMu        sync.Mutex
	leaderConn      *pgx.Conn
	leaderKey       string
	leaderHeldUntil time.Time
}

var _ Store = (*PostgresStore)(nil)

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
	return &PostgresStore{pool: pool}, nil
}

// NewPostgresFromPool adopts an existing pool (tests, wiring).
func NewPostgresFromPool(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) Close() error {
	s.leaderMu.Lock()
	if s.leaderConn != nil {
		_ = s.leaderConn.Close(context.Background())
		s.leaderConn = nil
	}
	s.leaderMu.Unlock()
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

// quotaKeys derives the reservation counter keys for one repository URL: the
// repository key is the URL itself and the team key is the host plus the
// first path segment, mirroring the server's team derivation. Deduplicated
// when both keys coincide.
func quotaKeys(repoURL string) []string {
	repo := strings.TrimSpace(repoURL)
	if repo == "" {
		return nil
	}
	team := repo
	if u, err := url.Parse(repo); err == nil && u.Host != "" {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) > 0 && parts[0] != "" {
			team = u.Host + "/" + parts[0]
		} else {
			team = u.Host
		}
	}
	if team == repo {
		return []string{repo}
	}
	return []string{repo, team}
}

// adjustQuotaTx shifts the reserved running/queued counters for one
// repository URL inside a transaction. Counters clamp at zero; a missing
// reservation row (job predates quota accounting) is tolerated.
func (s *PostgresStore) adjustQuotaTx(ctx context.Context, tx pgx.Tx, repoURL string, runningDelta, queuedDelta int) error {
	for _, key := range quotaKeys(repoURL) {
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
// the superseded jobs with audit rows, and claims the delivery/quota/
// schedule/downstream-launch reservations. Any failure rolls everything
// back.
func (s *PostgresStore) InsertCompiledRun(ctx context.Context, req InsertCompiledRunRequest) error {
	if err := ValidateRunID(req.Run.ID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

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
		if err := s.insertJobRowTx(ctx, tx, j); err != nil {
			return err
		}
	}
	for _, j := range req.Jobs {
		if err := s.replaceDependenciesTx(ctx, tx, j); err != nil {
			return err
		}
	}
	for id, contracts := range req.Contracts {
		if err := ValidateJobID(id); err != nil {
			return err
		}
		cp, err := json.Marshal(contracts)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE jobs SET payload = jsonb_set(payload, '{artifact_contracts}', $2::jsonb, true) WHERE id=$1`, id, cp); err != nil {
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

// insertRunTx inserts the run row inside an open transaction.
func (s *PostgresStore) insertRunTx(ctx context.Context, tx pgx.Tx, run model.Run) error {
	payload, err := json.Marshal(run)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO runs (id, status, started_at, finished_at, created_at, payload) VALUES ($1, $2, $3, $4, $5, $6)`,
		run.ID, string(run.Status), run.StartedAt, run.FinishedAt, run.CreatedAt, payload)
	return err
}

// cancelSupersededTx cancels the superseded jobs (concurrency-group
// cancel-in-progress) with audit rows, inside the enqueue transaction.
func (s *PostgresStore) cancelSupersededTx(ctx context.Context, tx pgx.Tx, jobIDs []string, newRunID string) error {
	now := time.Now().UTC()
	for _, id := range jobIDs {
		if err := ValidateJobID(id); err != nil {
			return err
		}
		var (
			payload []byte
			status  string
			runID   string
			key     string
		)
		err := tx.QueryRow(ctx, `SELECT payload, status, run_id, key FROM jobs WHERE id=$1 FOR UPDATE`, id).Scan(&payload, &status, &runID, &key)
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
		j.Status = model.StatusCancelled
		j.Error = reason
		j.FinishedAt = &now
		j.LeaseRunnerID = ""
		j.LeaseTokenHash = nil
		j.LeaseExpiresAt = nil
		jp, err := json.Marshal(j)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE jobs SET status='cancelled', error=$2, finished_at=$3, lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL, payload=$4 WHERE id=$1`,
			id, reason, now, jp); err != nil {
			return err
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
		wasRunning := model.Status(status) == model.StatusRunning
		if wasRunning {
			if err := s.adjustQuotaTx(ctx, tx, j.RepoURL, -1, 0); err != nil {
				return err
			}
		} else {
			if err := s.adjustQuotaTx(ctx, tx, j.RepoURL, 0, -1); err != nil {
				return err
			}
		}
	}
	return nil
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
	payload, err := json.Marshal(run)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO runs (id, status, started_at, finished_at, created_at, payload) VALUES ($1, $2, $3, $4, $5, $6)`,
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
	rp, err := json.Marshal(run)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE runs SET payload=$2 WHERE id=$1`, id, rp); err != nil {
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
// used by both INSERT and the upsert path of UpdateJob.
func jobWriteArgs(j model.Job) ([]any, error) {
	payload, err := json.Marshal(j)
	if err != nil {
		return nil, err
	}
	var outputsJSON []byte
	if len(j.Outputs) > 0 {
		if outputsJSON, err = json.Marshal(j.Outputs); err != nil {
			return nil, err
		}
	}
	return []any{
		j.ID, j.RunID, j.Key, string(j.Status), string(j.DependencyStatus),
		j.Priority, j.Attempts,
		nullText(j.Error), outputsJSON,
		nullText(j.LeaseRunnerID), nullBytes(j.LeaseTokenHash), j.LeaseGeneration,
		j.LeaseExpiresAt, j.StartedAt, j.FinishedAt, j.CreatedAt, payload,
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
	_, err = tx.Exec(ctx, `INSERT INTO jobs (id, run_id, key, status, dependency_status, priority, attempts, error, outputs, lease_runner_id, lease_token_hash, lease_generation, lease_expires_at, started_at, finished_at, created_at, payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, args...)
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

func (s *PostgresStore) ListJobsByEnvironment(ctx context.Context, repoURL, environment string) ([]model.Job, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+jobCols+` FROM jobs WHERE payload->>'repo_url'=$1 AND payload->>'environment'=$2 ORDER BY created_at ASC, id ASC`, repoURL, environment)
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
	if _, err := tx.Exec(ctx, `INSERT INTO jobs (id, run_id, key, status, dependency_status, priority, attempts, error, outputs, lease_runner_id, lease_token_hash, lease_generation, lease_expires_at, started_at, finished_at, created_at, payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) ON CONFLICT (id) DO UPDATE SET run_id=EXCLUDED.run_id, key=EXCLUDED.key, status=EXCLUDED.status, dependency_status=EXCLUDED.dependency_status, priority=EXCLUDED.priority, attempts=EXCLUDED.attempts, error=EXCLUDED.error, outputs=EXCLUDED.outputs, lease_runner_id=EXCLUDED.lease_runner_id, lease_token_hash=EXCLUDED.lease_token_hash, lease_generation=EXCLUDED.lease_generation, lease_expires_at=EXCLUDED.lease_expires_at, started_at=EXCLUDED.started_at, finished_at=EXCLUDED.finished_at, created_at=EXCLUDED.created_at, payload=EXCLUDED.payload`, args...); err != nil {
		return err
	}
	if err := s.replaceDependenciesTx(ctx, tx, job); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---------------------------------------------------------------------------
// leases
// ---------------------------------------------------------------------------

func (s *PostgresStore) AcquireLease(ctx context.Context, jobID, runnerID string, tokenHash []byte, generation int64, expiresAt time.Time) (model.Job, error) {
	if err := ValidateJobID(jobID); err != nil {
		return model.Job{}, err
	}
	if runnerID == "" {
		return model.Job{}, fmt.Errorf("storage: empty runner id")
	}
	js := jobScanner{}
	err := s.pool.QueryRow(ctx, `UPDATE jobs SET status='running', lease_runner_id=$2, lease_token_hash=$3, lease_generation=$4, lease_expires_at=$5 WHERE id=$1 AND status='queued' AND (lease_expires_at IS NULL OR lease_expires_at < now()) RETURNING `+jobCols,
		jobID, runnerID, tokenHash, generation, expiresAt).Scan(jobTargets(&js)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Job{}, ErrLeaseConflict
	}
	if err != nil {
		return model.Job{}, err
	}
	return js.job()
}

// AcquireLeaseAtomic claims a queued job and reserves the runner capacity
// slot in ONE transaction: the job UPDATE takes the lease, the runner
// UPDATE appends the job to active_jobs guarded by the capacity predicate,
// and the quota counters move one slot from queued to running. When the
// runner is at capacity the job lease is rolled back and ErrNoCapacity is
// returned.
func (s *PostgresStore) AcquireLeaseAtomic(ctx context.Context, jobID, runnerID string, tokenHash []byte, generation int64, expiresAt time.Time, runnerCapacity int) (model.Job, error) {
	if err := ValidateJobID(jobID); err != nil {
		return model.Job{}, err
	}
	if runnerID == "" {
		return model.Job{}, fmt.Errorf("storage: empty runner id")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return model.Job{}, err
	}
	defer tx.Rollback(ctx)
	js := jobScanner{}
	err = tx.QueryRow(ctx, `UPDATE jobs SET status='running', lease_runner_id=$2, lease_token_hash=$3, lease_generation=$4, lease_expires_at=$5 WHERE id=$1 AND status='queued' AND (lease_expires_at IS NULL OR lease_expires_at < now()) RETURNING `+jobCols,
		jobID, runnerID, tokenHash, generation, expiresAt).Scan(jobTargets(&js)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Job{}, ErrLeaseConflict
	}
	if err != nil {
		return model.Job{}, err
	}
	ct, err := tx.Exec(ctx, `UPDATE runners SET active_jobs = COALESCE(active_jobs, '[]'::jsonb) || to_jsonb($1::text), busy = TRUE, current_job = CASE WHEN COALESCE(current_job, '') = '' THEN $1 ELSE current_job END, last_seen = now() WHERE id = $2 AND ($3 <= 0 OR jsonb_array_length(COALESCE(active_jobs, '[]'::jsonb)) < $3)`,
		jobID, runnerID, runnerCapacity)
	if err != nil {
		return model.Job{}, err
	}
	if ct.RowsAffected() == 0 {
		return model.Job{}, ErrNoCapacity
	}
	j, err := js.job()
	if err != nil {
		return model.Job{}, err
	}
	if err := s.adjustQuotaTx(ctx, tx, j.RepoURL, 1, -1); err != nil {
		return model.Job{}, err
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
	// already applied and its receipt persisted; acknowledge it again.
	if curGen != generation || curRunner != runnerID || curStatus != string(model.StatusRunning) {
		var recExists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM completion_receipts WHERE job_id=$1 AND generation=$2 AND runner_id=$3)`, jobID, generation, runnerID).Scan(&recExists); err != nil {
			return err
		}
		if recExists {
			return tx.Commit(ctx)
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
		if missing, err := s.requiredArtifactMissingTx(ctx, tx, jobID, payload); err != nil {
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
	newPayload, err := json.Marshal(j)
	if err != nil {
		return err
	}
	outputsJSON, err := json.Marshal(outputs)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status=$2, error=$3, outputs=$4, finished_at=$5, lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL, payload=$6 WHERE id=$1`,
		jobID, string(st), nullText(errMsg), outputsJSON, now, newPayload); err != nil {
		return err
	}
	// The completed job releases its reserved running slot.
	if err := s.adjustQuotaTx(ctx, tx, j.RepoURL, -1, 0); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO completion_receipts (job_id, generation, runner_id, result_hash) VALUES ($1, $2, $3, $4) ON CONFLICT (job_id, generation, runner_id) DO NOTHING`,
		receipt.JobID, receipt.Generation, receipt.RunnerID, receipt.ResultHash); err != nil {
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

// insertCompletionEffectsTx inserts one durable outbox intent per completion
// effect kind inside the caller's transaction. IDs are the deterministic
// CompletionEffectID values so the completing server can queue and ack the
// very rows this transaction created.
func (s *PostgresStore) insertCompletionEffectsTx(ctx context.Context, tx pgx.Tx, jobID, runID string, generation int64, now time.Time) error {
	payload, err := json.Marshal(CompletionEffectsPayload{JobID: jobID, RunID: runID})
	if err != nil {
		return err
	}
	for _, kind := range CompletionEffectKinds() {
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
// Required contract entry without a matching artifact row, or "" when every
// required artifact is present.
func (s *PostgresStore) requiredArtifactMissingTx(ctx context.Context, tx pgx.Tx, jobID string, payload []byte) (string, error) {
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
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM artifacts WHERE job_id=$1 AND name=$2)`, jobID, name).Scan(&exists); err != nil {
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
	if capacity < 1 {
		capacity = 1
	}
	r.ActiveJobs = active
	r.CurrentJob = ""
	if len(active) > 0 {
		r.CurrentJob = active[0]
	}
	r.Busy = len(active) >= capacity
	r.Capacity = capacity
	if st == model.StatusSuccess {
		completed++
	} else if st == model.StatusFailure {
		failed++
	}
	r.Completed = completed
	r.Failed = failed
	r.LastSeen = now
	rp, err := json.Marshal(r)
	if err != nil {
		return err
	}
	aj, err := json.Marshal(active)
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
	dp, err := json.Marshal(d)
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
	rp, err := json.Marshal(run)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE runs SET status=$2, started_at=$3, finished_at=$4, payload=$5 WHERE id=$1`,
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

func (s *PostgresStore) CancelRunJobs(ctx context.Context, runID string, reason string) ([]string, error) {
	if err := ValidateRunID(runID); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	ids := []string{}
	rows, err := tx.Query(ctx, `SELECT id, payload FROM jobs WHERE run_id=$1 AND NOT (status IN ('success', 'failure', 'cancelled', 'skipped', 'blocked')) ORDER BY id FOR UPDATE`, runID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var (
			id      string
			payload []byte
		)
		if err := rows.Scan(&id, &payload); err != nil {
			rows.Close()
			return nil, err
		}
		var j model.Job
		if err := json.Unmarshal(payload, &j); err != nil {
			rows.Close()
			return nil, err
		}
		wasRunning := j.Status == model.StatusRunning
		j.Status = model.StatusCancelled
		j.Error = reason
		j.FinishedAt = &now
		j.LeaseRunnerID = ""
		j.LeaseTokenHash = nil
		j.LeaseExpiresAt = nil
		jp, err := json.Marshal(j)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE jobs SET status='cancelled', error=$2, finished_at=$3, lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL, payload=$4 WHERE id=$1`,
			id, reason, now, jp); err != nil {
			rows.Close()
			return nil, err
		}
		// The cancelled job releases its reserved slot (running or queued).
		if wasRunning {
			err = s.adjustQuotaTx(ctx, tx, j.RepoURL, -1, 0)
		} else {
			err = s.adjustQuotaTx(ctx, tx, j.RepoURL, 0, -1)
		}
		if err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Cancel the run itself, mirroring the in-memory cancelRunLocked.
	var (
		payload   []byte
		curStatus string
	)
	err = tx.QueryRow(ctx, `SELECT payload, status FROM runs WHERE id=$1 FOR UPDATE`, runID).Scan(&payload, &curStatus)
	if err == nil {
		var run model.Run
		if err := json.Unmarshal(payload, &run); err != nil {
			return nil, err
		}
		if !run.Status.Terminal() {
			run.Status = model.StatusCancelled
			run.FinishedAt = &now
			rp, err := json.Marshal(run)
			if err != nil {
				return nil, err
			}
			if _, err := tx.Exec(ctx, `UPDATE runs SET status=$2, finished_at=$3, payload=$4 WHERE id=$1`, runID, string(model.StatusCancelled), now, rp); err != nil {
				return nil, err
			}
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	return ids, tx.Commit(ctx)
}

// ---------------------------------------------------------------------------
// runners
// ---------------------------------------------------------------------------

func (s *PostgresStore) UpsertRunner(ctx context.Context, runner model.Runner) error {
	if err := ValidateRunnerID(runner.ID); err != nil {
		return err
	}
	payload, err := json.Marshal(runner)
	if err != nil {
		return err
	}
	activeJSON, err := json.Marshal(runner.ActiveJobs)
	if err != nil {
		return err
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
	_, err = s.pool.Exec(ctx, `INSERT INTO runners (id, busy, capacity, completed, failed, current_job, active_jobs, registered, last_seen, payload) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (id) DO UPDATE SET busy=EXCLUDED.busy, capacity=EXCLUDED.capacity, completed=EXCLUDED.completed, failed=EXCLUDED.failed, current_job=EXCLUDED.current_job, active_jobs=EXCLUDED.active_jobs, registered=EXCLUDED.registered, last_seen=EXCLUDED.last_seen, payload=EXCLUDED.payload`,
		runner.ID, runner.Busy, runner.Capacity, runner.Completed, runner.Failed, nullText(runner.CurrentJob), activeJSON, registered, lastSeen, payload)
	return err
}

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
	if capacity < 1 {
		capacity = 1
	}
	r.ActiveJobs = active
	r.CurrentJob = ""
	if len(active) > 0 {
		r.CurrentJob = active[0]
	}
	r.Busy = len(active) >= capacity
	r.Capacity = capacity
	if status == model.StatusSuccess {
		completed++
	} else if status == model.StatusFailure {
		failed++
	}
	r.Completed = completed
	r.Failed = failed
	r.LastSeen = time.Now().UTC()
	rp, err := json.Marshal(r)
	if err != nil {
		return err
	}
	aj, err := json.Marshal(active)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE runners SET payload=$2, active_jobs=$3, busy=$4, completed=$5, failed=$6, current_job=$7, last_seen=$8 WHERE id=$1`,
		runnerID, rp, aj, r.Busy, completed, failed, r.CurrentJob, r.LastSeen); err != nil {
		return err
	}
	// The released job was running: release the running slot and, when the
	// job was requeued (recovery/kill switch), re-reserve the queued slot.
	var (
		jobStatus string
		jobRepo   string
	)
	if err := tx.QueryRow(ctx, `SELECT status, COALESCE(payload->>'repo_url', '') FROM jobs WHERE id=$1`, jobID).Scan(&jobStatus, &jobRepo); err == nil {
		queuedDelta := 0
		if model.Status(jobStatus) == model.StatusQueued {
			queuedDelta = 1
		}
		if err := s.adjustQuotaTx(ctx, tx, jobRepo, -1, queuedDelta); err != nil {
			return err
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return tx.Commit(ctx)
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
	payload, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO artifacts (id, run_id, job_id, job_key, name, size, sha256, created_at, expires_at, payload) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		a.ID, a.RunID, nullText(a.JobID), nullText(a.JobKey), a.Name, a.Size, nullText(a.SHA256), a.CreatedAt, a.ExpiresAt, payload)
	return err
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
	payload, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO test_results (id, run_id, job_id, job_key, path, tests, failures, duration, created_at, payload) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		rep.ID, rep.RunID, nullText(rep.JobID), nullText(rep.JobKey), nullText(rep.Path), rep.Tests, rep.Failures, rep.Duration, rep.CreatedAt, payload); err != nil {
		return err
	}
	for _, c := range rep.Cases {
		caseID, err := newID()
		if err != nil {
			return err
		}
		cp, err := json.Marshal(c)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO test_cases (id, report_id, name, class, duration, passed, message, payload) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			caseID, rep.ID, c.Name, nullText(c.Class), c.Duration, c.Passed, nullText(c.Message), cp); err != nil {
			return err
		}
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
		m, err := json.Marshal(e.Metadata)
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

func (s *PostgresStore) InsertCompletionReceipt(ctx context.Context, r model.CompletionReceipt) error {
	if err := ValidateJobID(r.JobID); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO completion_receipts (job_id, generation, runner_id, result_hash) VALUES ($1, $2, $3, $4) ON CONFLICT (job_id, generation, runner_id) DO NOTHING`,
		r.JobID, r.Generation, r.RunnerID, r.ResultHash)
	return err
}

func (s *PostgresStore) HasCompletionReceipt(ctx context.Context, jobID string, generation int64, runnerID string) (model.CompletionReceipt, bool, error) {
	if err := ValidateJobID(jobID); err != nil {
		return model.CompletionReceipt{}, false, err
	}
	var (
		rec  model.CompletionReceipt
		hash string
	)
	err := s.pool.QueryRow(ctx, `SELECT result_hash FROM completion_receipts WHERE job_id=$1 AND generation=$2 AND runner_id=$3`, jobID, generation, runnerID).Scan(&hash)
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
	_, err := s.pool.Exec(ctx, `INSERT INTO outbox (id, kind, payload, created_at) VALUES ($1, $2, $3, $4)`,
		e.ID, e.Kind, payload, e.CreatedAt)
	return err
}

func (s *PostgresStore) OutboxAck(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("storage: empty outbox id")
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM outbox WHERE id=$1`, id)
	return err
}

func (s *PostgresStore) OutboxPending(ctx context.Context) ([]OutboxItem, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, kind, payload, created_at FROM outbox ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OutboxItem{}
	for rows.Next() {
		var it OutboxItem
		if err := rows.Scan(&it.ID, &it.Kind, &it.Payload, &it.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// schedules
// ---------------------------------------------------------------------------

func (s *PostgresStore) UpsertSchedule(ctx context.Context, sc Schedule) error {
	if sc.ID == "" {
		return fmt.Errorf("storage: empty schedule id")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO schedules (id, repository, repo_id, repo_url, forge, trusted, spec, enabled, last_run, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (id) DO UPDATE SET repository=EXCLUDED.repository, repo_id=EXCLUDED.repo_id, repo_url=EXCLUDED.repo_url, forge=EXCLUDED.forge, trusted=EXCLUDED.trusted, spec=EXCLUDED.spec, enabled=EXCLUDED.enabled, last_run=EXCLUDED.last_run`,
		sc.ID, sc.Repository, sc.RepoID, sc.RepoURL, sc.Forge, sc.Trusted, sc.Spec, sc.Enabled, sc.LastRun, sc.CreatedAt)
	return err
}

func (s *PostgresStore) ListSchedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, repository, COALESCE(repo_id, ''), COALESCE(repo_url, ''), COALESCE(forge, ''), trusted, spec, enabled, last_run, created_at FROM schedules ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Schedule{}
	for rows.Next() {
		var sc Schedule
		if err := rows.Scan(&sc.ID, &sc.Repository, &sc.RepoID, &sc.RepoURL, &sc.Forge, &sc.Trusted, &sc.Spec, &sc.Enabled, &sc.LastRun, &sc.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// ClaimScheduleOccurrence atomically reserves the (schedule, nominal) firing
// for runID. The INSERT ... ON CONFLICT DO NOTHING makes concurrent claims
// race-free: exactly one caller wins the row. Re-claiming the same nominal
// for the same runID is idempotent and reports true.
func (s *PostgresStore) ClaimScheduleOccurrence(ctx context.Context, scheduleID string, nominal time.Time, runID string) (bool, error) {
	if scheduleID == "" || runID == "" {
		return false, fmt.Errorf("storage: empty schedule or run id")
	}
	ct, err := s.pool.Exec(ctx, `INSERT INTO schedule_occurrences (schedule_id, nominal, run_id) VALUES ($1, $2, $3) ON CONFLICT (schedule_id, nominal) DO NOTHING`,
		scheduleID, nominal, runID)
	if err != nil {
		return false, err
	}
	if ct.RowsAffected() == 1 {
		return true, nil
	}
	var existing string
	err = s.pool.QueryRow(ctx, `SELECT run_id FROM schedule_occurrences WHERE schedule_id=$1 AND nominal=$2`, scheduleID, nominal).Scan(&existing)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
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
	payload, err := json.Marshal(d)
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
	dp, err := json.Marshal(d)
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
	payload, err := json.Marshal(rec)
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
	cp, err := json.Marshal(contracts)
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

// InsertGeneratedJobsTx inserts the fragment and runs the verification
// closure in the SAME transaction: the parent job is locked FOR UPDATE and
// the run's current job count is read inside the transaction, then the
// verifier re-checks {job, runner, generation, token, expiry} and the
// max-jobs-per-run bound against that fresh state. The fragment's artifact
// contracts commit in the same transaction as the jobs, so a generated job
// with a Required artifact has its contract row present before any
// completion can run. A rejected verification (or a failed contract write)
// rolls the whole fragment back.
func (s *PostgresStore) InsertGeneratedJobsTx(ctx context.Context, parentJobID string, depth int, jobs map[string]model.Job, deps map[string][]string, contracts map[string]map[string]ArtifactContract, verify GeneratedJobVerifier) error {
	if err := ValidateJobID(parentJobID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	js := jobScanner{}
	err = tx.QueryRow(ctx, `SELECT `+jobCols+` FROM jobs WHERE id=$1 FOR UPDATE`, parentJobID).Scan(jobTargets(&js)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	parent, err := js.job()
	if err != nil {
		return err
	}
	var runJobCount int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM jobs WHERE run_id=$1`, parent.RunID).Scan(&runJobCount); err != nil {
		return err
	}
	if verify != nil {
		if err := verify(parent, runJobCount); err != nil {
			return err
		}
	}
	for _, j := range jobs {
		if err := ValidateJobID(j.ID); err != nil {
			return err
		}
		if err := s.insertJobRowTx(ctx, tx, j); err != nil {
			return err
		}
	}
	for _, j := range jobs {
		if err := s.replaceDependenciesTx(ctx, tx, j); err != nil {
			return err
		}
	}
	for id, cs := range contracts {
		if err := ValidateJobID(id); err != nil {
			return err
		}
		cp, err := json.Marshal(cs)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE jobs SET payload = jsonb_set(payload, '{artifact_contracts}', $2::jsonb, true) WHERE id=$1`, id, cp); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
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

// ReserveDownstreamLaunch atomically reserves the link for the calling
// flusher BEFORE the child run is enqueued: the reservation UPDATE wins
// exactly once, and a missing row (restart dropped the in-memory copy) is
// created reserved. Returns true only when this call made the reservation.
func (s *PostgresStore) ReserveDownstreamLaunch(ctx context.Context, parentJobID, targetRepo, targetRef, launchToken string) (bool, error) {
	if err := ValidateJobID(parentJobID); err != nil {
		return false, err
	}
	if targetRepo == "" || targetRef == "" || launchToken == "" {
		return false, fmt.Errorf("storage: incomplete downstream reservation")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var got string
	err = tx.QueryRow(ctx, `UPDATE downstream_links SET reserved=TRUE, reserved_at=now(), launch_token=$4 WHERE parent_job_id=$1 AND target_repo=$2 AND target_ref=$3 AND NOT reserved AND (child_run_id IS NULL OR child_run_id='') RETURNING parent_job_id`,
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
// link and consumes the reservation.
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

// ReleaseDownstreamReservation clears a reservation whose launch failed so
// a retried dispatch can re-reserve the link.
func (s *PostgresStore) ReleaseDownstreamReservation(ctx context.Context, parentJobID, targetRepo, targetRef string) error {
	if err := ValidateJobID(parentJobID); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `UPDATE downstream_links SET reserved=FALSE, reserved_at=NULL WHERE parent_job_id=$1 AND target_repo=$2 AND target_ref=$3 AND reserved AND (child_run_id IS NULL OR child_run_id='')`,
		parentJobID, targetRepo, targetRef)
	return err
}

// ExpireDownstreamReservations releases reservations older than the cutoff
// whose child never launched (crash recovery): the next dispatch can
// re-reserve and launch them. Returns the number of expired reservations.
func (s *PostgresStore) ExpireDownstreamReservations(ctx context.Context, olderThan time.Time) (int, error) {
	ct, err := s.pool.Exec(ctx, `UPDATE downstream_links SET reserved=FALSE, reserved_at=NULL WHERE reserved AND (child_run_id IS NULL OR child_run_id='') AND (reserved_at IS NULL OR reserved_at < $1)`,
		olderThan)
	if err != nil {
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
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO cache_manifests (repo, trust_domain, logical_key, blob_sha256, blob_size, producer_run, producer_job, created_at, payload) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (repo, trust_domain, logical_key) DO UPDATE SET blob_sha256=EXCLUDED.blob_sha256, blob_size=EXCLUDED.blob_size, producer_run=EXCLUDED.producer_run, producer_job=EXCLUDED.producer_job, payload=EXCLUDED.payload`,
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

// SetArtifactSidecars updates an artifact record's sidecar references
// (non-empty values only) with one jsonb_set per field.
func (s *PostgresStore) SetArtifactSidecars(ctx context.Context, id, sbomPath, sbomSHA256, sigstorePath, sigstoreSHA256 string) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if sbomPath != "" {
		if _, err := tx.Exec(ctx, `UPDATE artifacts SET payload = jsonb_set(payload, '{sbom_path}', to_jsonb($2::text), true) WHERE id=$1`, id, sbomPath); err != nil {
			return err
		}
	}
	if sbomSHA256 != "" {
		if _, err := tx.Exec(ctx, `UPDATE artifacts SET payload = jsonb_set(payload, '{sbom_sha256}', to_jsonb($2::text), true) WHERE id=$1`, id, sbomSHA256); err != nil {
			return err
		}
	}
	if sigstorePath != "" {
		if _, err := tx.Exec(ctx, `UPDATE artifacts SET payload = jsonb_set(payload, '{sigstore_path}', to_jsonb($2::text), true) WHERE id=$1`, id, sigstorePath); err != nil {
			return err
		}
	}
	if sigstoreSHA256 != "" {
		if _, err := tx.Exec(ctx, `UPDATE artifacts SET payload = jsonb_set(payload, '{sigstore_sha256}', to_jsonb($2::text), true) WHERE id=$1`, id, sigstoreSHA256); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// AppendDownstreamRun appends childRunID to the parent run's downstream_runs
// payload key exactly once (idempotent): the row is locked FOR UPDATE and
// the append is skipped when the ID is already present.
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
	var payload []byte
	err = tx.QueryRow(ctx, `SELECT payload FROM runs WHERE id=$1 FOR UPDATE`, runID).Scan(&payload)
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
	rp, err := json.Marshal(run)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE runs SET payload=$2 WHERE id=$1`, runID, rp); err != nil {
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
	_, err := s.pool.Exec(ctx, `UPDATE runs SET status='running', finished_at=NULL, payload = jsonb_set(payload, '{status}', '"running"', true) WHERE id=$1 AND status='success'`, runID)
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
	err := s.pool.QueryRow(ctx, `INSERT INTO test_history (id, version, stats) VALUES (1, 1, $2::jsonb) ON CONFLICT (id) DO UPDATE SET version = test_history.version + 1, stats = EXCLUDED.stats, updated_at = now() RETURNING version`,
		version, string(stats)).Scan(&version)
	return version, err
}

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
	s.leaderMu.Lock()
	defer s.leaderMu.Unlock()
	if s.leaderConn != nil && s.leaderKey == key && time.Now().Before(s.leaderHeldUntil) {
		s.leaderHeldUntil = time.Now().Add(ttl)
		return true, nil
	}
	if s.leaderConn != nil {
		_, _ = s.leaderConn.Exec(ctx, `SELECT pg_advisory_unlock(hashtext($1))`, s.leaderKey)
		_ = s.leaderConn.Close(ctx)
		s.leaderConn = nil
		s.leaderKey = ""
		s.leaderHeldUntil = time.Time{}
	}
	cc := s.pool.Config().ConnConfig
	if cc == nil {
		return false, fmt.Errorf("storage: pool has no conn config")
	}
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return false, err
	}
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtext($1))`, key).Scan(&got); err != nil {
		_ = conn.Close(ctx)
		return false, err
	}
	if !got {
		_ = conn.Close(ctx)
		return false, nil
	}
	s.leaderConn = conn
	s.leaderKey = key
	s.leaderHeldUntil = time.Now().Add(ttl)
	return true, nil
}

func (s *PostgresStore) ReleaseLeadership(ctx context.Context, key string) error {
	s.leaderMu.Lock()
	defer s.leaderMu.Unlock()
	if s.leaderConn == nil || s.leaderKey != key {
		return nil
	}
	if _, err := s.leaderConn.Exec(ctx, `SELECT pg_advisory_unlock(hashtext($1))`, key); err != nil {
		return err
	}
	err := s.leaderConn.Close(ctx)
	s.leaderConn = nil
	s.leaderKey = ""
	s.leaderHeldUntil = time.Time{}
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
	applied := false
	err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=$1)`, m.Version).Scan(&applied)
	if err != nil {
		// Before migration 1 the schema_migrations table does not exist yet.
		if !isUndefinedTable(err) {
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

func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
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
func scanProfile(row pgx.Row) (model.RunnerProfile, error) {
	var (
		p           model.RunnerProfile
		labels      []byte
		region      string
		repos       []byte
		caps        []byte
		maxCapacity int
		cost        float64
		watts       float64
	)
	err := row.Scan(&p.ID, &labels, &region, &repos, &caps, &maxCapacity, &cost, &watts, &p.CreatedAt)
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
	p.CostPerHour = cost
	p.PowerWatts = watts
	return p, nil
}

const profileCols = "id, labels, region, repositories, capabilities, max_capacity, cost_per_hour, power_watts, created_at"

func (s *PostgresStore) UpsertProfile(ctx context.Context, p model.RunnerProfile) error {
	if p.ID == "" {
		return fmt.Errorf("storage: profile id is required")
	}
	labels, err := json.Marshal(p.Labels)
	if err != nil {
		return err
	}
	if len(labels) == 0 || string(labels) == "null" {
		labels = []byte("[]")
	}
	repos, err := json.Marshal(p.Repositories)
	if err != nil {
		return err
	}
	if len(repos) == 0 || string(repos) == "null" {
		repos = []byte("[]")
	}
	caps, err := json.Marshal(p.Capabilities)
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
	_, err = s.pool.Exec(ctx, `INSERT INTO runner_profiles (id, labels, region, repositories, capabilities, max_capacity, cost_per_hour, power_watts, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO UPDATE SET labels=EXCLUDED.labels, region=EXCLUDED.region, repositories=EXCLUDED.repositories, capabilities=EXCLUDED.capabilities, max_capacity=EXCLUDED.max_capacity, cost_per_hour=EXCLUDED.cost_per_hour, power_watts=EXCLUDED.power_watts`,
		p.ID, labels, p.Region, repos, caps, p.MaxCapacity, p.CostPerHour, p.PowerWatts, created)
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
	var (
		p           model.RunnerProfile
		labels      []byte
		region      string
		repos       []byte
		caps        []byte
		maxCapacity int
		cost        float64
		watts       float64
	)
	err := s.pool.QueryRow(ctx, `SELECT rp.id, rp.labels, rp.region, rp.repositories, rp.capabilities, rp.max_capacity, rp.cost_per_hour, rp.power_watts, rp.created_at FROM cert_profile_links cl JOIN runner_profiles rp ON rp.id = cl.profile_id WHERE cl.serial=$1`, serial).
		Scan(&p.ID, &labels, &region, &repos, &caps, &maxCapacity, &cost, &watts, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.RunnerProfile{}, false, nil
	}
	if err != nil {
		return model.RunnerProfile{}, false, err
	}
	if err := json.Unmarshal(labels, &p.Labels); err != nil {
		return model.RunnerProfile{}, false, fmt.Errorf("storage: decode profile labels: %w", err)
	}
	if err := json.Unmarshal(repos, &p.Repositories); err != nil {
		return model.RunnerProfile{}, false, fmt.Errorf("storage: decode profile repositories: %w", err)
	}
	if err := json.Unmarshal(caps, &p.Capabilities); err != nil {
		return model.RunnerProfile{}, false, fmt.Errorf("storage: decode profile capabilities: %w", err)
	}
	p.Region = region
	p.MaxCapacity = maxCapacity
	p.CostPerHour = cost
	p.PowerWatts = watts
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

func (s *PostgresStore) RevokeCert(ctx context.Context, serial, runnerID, reason string) error {
	if serial == "" {
		return fmt.Errorf("storage: certificate serial is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO cert_revocations (serial, revoked_at, reason, runner_id) VALUES ($1, now(), $2, $3) ON CONFLICT (serial) DO NOTHING`, serial, reason, runnerID); err != nil {
		return err
	}
	// The runner row's revoked_at mirrors the durable revocation so the
	// disable flow and identity verification see the same state.
	if runnerID != "" {
		if _, err := tx.Exec(ctx, `UPDATE runners SET payload = jsonb_set(payload, '{revoked_at}', to_jsonb(now()::text), true) WHERE id=$1`, runnerID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
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
	labels, err := json.Marshal(boundLabels)
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
	if _, err := rand.Read(b); err != nil {
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
