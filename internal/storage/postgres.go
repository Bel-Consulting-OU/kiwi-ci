package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
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
	_ DownstreamStore       = (*PostgresStore)(nil)
	_ UsageStore            = (*PostgresStore)(nil)
	_ RunDownstreamStore    = (*PostgresStore)(nil)
	_ ArtifactLookupStore   = (*PostgresStore)(nil)
)

// NewPostgres opens a pool and verifies connectivity.
func NewPostgres(ctx context.Context, dsn string) (*PostgresStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: parse dsn: %w", err)
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
	args, err := jobWriteArgs(j)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO jobs (id, run_id, key, status, dependency_status, priority, attempts, error, outputs, lease_runner_id, lease_token_hash, lease_generation, lease_expires_at, started_at, finished_at, created_at, payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, args...); err != nil {
		return err
	}
	return s.replaceDependenciesTx(ctx, tx, j)
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
	return tx.Commit(ctx)
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
	return tx.Commit(ctx)
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

func (s *PostgresStore) AppendLog(ctx context.Context, e model.LogEntry) error {
	if err := ValidateRunID(e.RunID); err != nil {
		return err
	}
	id, err := newID()
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO log_chunks (id, run_id, job_id, job_key, step, seq, line, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, e.RunID, nullText(e.JobID), nullText(e.JobKey), nullText(e.Step), e.Seq, e.Line, e.CreatedAt)
	return err
}

func (s *PostgresStore) ReadLogs(ctx context.Context, runID string, after int64, limit int) ([]model.LogEntry, error) {
	if err := ValidateRunID(runID); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 10000 {
		limit = 2000
	}
	rows, err := s.pool.Query(ctx, `SELECT COALESCE(job_id, ''), COALESCE(job_key, ''), COALESCE(step, ''), seq, line, created_at FROM log_chunks WHERE run_id=$1 AND seq>$2 ORDER BY seq ASC LIMIT $3`, runID, after, limit)
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
	_, err := s.pool.Exec(ctx, `INSERT INTO schedules (id, repository, spec, enabled, last_run, created_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO UPDATE SET repository=EXCLUDED.repository, spec=EXCLUDED.spec, enabled=EXCLUDED.enabled, last_run=EXCLUDED.last_run`,
		sc.ID, sc.Repository, sc.Spec, sc.Enabled, sc.LastRun, sc.CreatedAt)
	return err
}

func (s *PostgresStore) ListSchedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, repository, spec, enabled, last_run, created_at FROM schedules ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Schedule{}
	for rows.Next() {
		var sc Schedule
		if err := rows.Scan(&sc.ID, &sc.Repository, &sc.Spec, &sc.Enabled, &sc.LastRun, &sc.CreatedAt); err != nil {
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
	_, err := s.pool.Exec(ctx, `INSERT INTO downstream_links (parent_job_id, target_repo, target_ref, launch_token, child_run_id, created_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (parent_job_id, target_repo, target_ref) DO NOTHING`,
		l.ParentJobID, l.TargetRepo, l.TargetRef, l.LaunchToken, l.ChildRunID, l.CreatedAt)
	return err
}

// GetDownstreamLink reads one downstream launch claim.
func (s *PostgresStore) GetDownstreamLink(ctx context.Context, parentJobID, targetRepo, targetRef string) (DownstreamLink, bool, error) {
	if err := ValidateJobID(parentJobID); err != nil {
		return DownstreamLink{}, false, err
	}
	var l DownstreamLink
	err := s.pool.QueryRow(ctx, `SELECT parent_job_id, target_repo, target_ref, launch_token, COALESCE(child_run_id, ''), created_at FROM downstream_links WHERE parent_job_id=$1 AND target_repo=$2 AND target_ref=$3`,
		parentJobID, targetRepo, targetRef).Scan(&l.ParentJobID, &l.TargetRepo, &l.TargetRef, &l.LaunchToken, &l.ChildRunID, &l.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DownstreamLink{}, false, nil
	}
	if err != nil {
		return DownstreamLink{}, false, err
	}
	return l, true, nil
}

// MarkDownstreamLaunched atomically sets the child run ID on a link whose
// claim is still open (child_run_id empty). A concurrent claim wins the
// row and the loser's update affects zero rows; callers re-read the link
// to learn the winning child run ID.
func (s *PostgresStore) MarkDownstreamLaunched(ctx context.Context, parentJobID, targetRepo, targetRef, childRunID string) error {
	if err := ValidateJobID(parentJobID); err != nil {
		return err
	}
	if childRunID == "" {
		return fmt.Errorf("storage: empty child run id")
	}
	_, err := s.pool.Exec(ctx, `UPDATE downstream_links SET child_run_id=$4 WHERE parent_job_id=$1 AND target_repo=$2 AND target_ref=$3 AND (child_run_id IS NULL OR child_run_id='')`,
		parentJobID, targetRepo, targetRef, childRunID)
	return err
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
