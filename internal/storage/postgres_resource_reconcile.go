package storage

// Leader-promotion reconciliation of the durable resource reservation
// ledger (migration 0030) and the shared repair entry point around it.
//
// The ledger is populated exclusively by the atomic lease claim, so a
// database that predates the feature (or was mid-upgrade while an
// OLD-version leader kept claiming jobs) can hold RUNNING leased jobs with
// ZERO reservation rows. A new-version replica that becomes leader would then
// sum an empty ledger and admit work the runner cannot hold — the
// rolling-upgrade over-admission window. ReconcileResourceReservations closes
// it: it derives the ledger from the authoritative persisted lease state
// (status=running + lease_runner_id + lease_generation + the payload's
// request fields), repairs stale rows, and must complete BEFORE the promoting
// leader issues any lease (Server.ensureResourceReconciled).
//
// The operation is idempotent and safe to re-run concurrently: the whole
// reconcile runs in ONE transaction, serialized by a transaction-scoped
// advisory lock, and leader-fenced by the store's retained epoch, so a stale
// leader mutates nothing (ErrStaleLeader) and two promoting replicas cannot
// interleave their DELETE/UPSERT phases. Reservation rows written
// concurrently by a claim are protected by the (job_id) primary key and the
// generation guard below: reconcile never downgrades a freshly claimed
// generation.
//
// The reconstructed quantities are the job's TOTAL reservation: its own
// request PLUS the aggregate service envelope persisted in the payload
// (service_envelope_request.cpu/memory/pids), the same total the claim's
// reserveResourcesTx writes, so a rolling upgrade cannot under-reserve a
// running job with services. Two legacy shapes are handled WITHOUT aborting
// the pass: a payload whose request values are unrepresentable or negative
// contributes zero per field (magnitude-safe guards, see resourceRequestSQL),
// and a payload that declares services but predates the envelope field is
// charged its own request a second time as a conservative envelope
// (legacyServiceEnvelopeSQL) instead of a zero envelope that would let a
// promoted leader oversubscribe the runner.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// ResourceReconcileResult reports what one reconciliation pass observed and
// changed. Repeated passes on unchanged data report the same Running count
// and zero Deleted rows (idempotence), while Upserted counts the ledger rows
// (re)written for live leases.
type ResourceReconcileResult struct {
	// Running is the number of running jobs holding a live lease that the
	// pass scanned (the authoritative source rows).
	Running int
	// Upserted is the number of ledger rows written for those jobs.
	Upserted int
	// Deleted is the number of ledger rows removed because they no longer
	// describe a live running lease (job not running, no lease runner, or a
	// stale generation).
	Deleted int
}

// ResourceReconcileStore is the leader-only reconciliation contract behind
// the promotion hook and the operator repair path. PostgresStore enforces it
// inside one leader-fenced transaction; the in-memory store rebuilds its
// reservation map under its own mutex (single-process semantics).
//
// A store that does not implement the contract cannot have diverged from its
// own claim path (the ledger is derived from it), so callers treat the
// absence as "nothing to reconcile".
type ResourceReconcileStore interface {
	// ReconcileResourceReservations rebuilds the runner resource reservation
	// ledger from the running jobs' live leases: it upserts one reservation
	// per running leased job (job, runner, generation, requested resources)
	// and deletes every row that does not correspond to such a job.
	ReconcileResourceReservations(ctx context.Context) (ResourceReconcileResult, error)
}

// ReconcileResourceReservations implements ResourceReconcileStore for the
// SQL ledger. See the file comment for the ordering contract (BEFORE lease
// issuance on promotion) and the concurrency argument.
func (s *PostgresStore) ReconcileResourceReservations(ctx context.Context) (ResourceReconcileResult, error) {
	tx, err := s.beginFencedTx(ctx)
	if err != nil {
		return ResourceReconcileResult{}, err
	}
	defer tx.Rollback(ctx)

	// One reconcile at a time across replicas: a promoting leader and a
	// repair pass (or two racing promotions) serialize here instead of
	// interleaving their DELETE/UPSERT phases.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockKey("kiwi-resource-reconcile", "global")); err != nil {
		return ResourceReconcileResult{}, err
	}

	res := ResourceReconcileResult{}
	// Phase 1: drop rows that do not describe a live lease. This covers
	// both "job no longer running" and "stale generation" rows; the upsert
	// below re-creates the row for a running job whose generation matches.
	deleted, err := deleteStaleReservationsTx(ctx, tx)
	if err != nil {
		return ResourceReconcileResult{}, err
	}
	res.Deleted += deleted

	// Phase 2: the authoritative request of every running leased job is
	// derived from the persisted job row (status + lease identity) and its
	// payload, never from a caller-supplied value. The generation guard
	// keeps a concurrent re-lease's fresh row authoritative. The payload
	// reads are type-guarded: a corrupt request value contributes zero
	// instead of failing the whole pass (a corrupt payload cannot be leased
	// again — it is terminally recovered by the expiry sweep — so zero is
	// the only knowable answer, and the pass must not wedge lease issuance).
	rows, err := tx.Query(ctx, `INSERT INTO job_resource_reservations (job_id, runner_id, generation, cpu, memory, disk, pids)
		SELECT j.id, j.lease_runner_id, j.lease_generation, `+resourceRequestSQL+`
		FROM jobs j
		WHERE j.status = 'running' AND COALESCE(j.lease_runner_id, '') <> ''
		ON CONFLICT (job_id) DO UPDATE
			SET runner_id = EXCLUDED.runner_id,
			    generation = EXCLUDED.generation,
			    cpu = EXCLUDED.cpu,
			    memory = EXCLUDED.memory,
			    disk = EXCLUDED.disk,
			    pids = EXCLUDED.pids
			WHERE job_resource_reservations.generation <= EXCLUDED.generation
		RETURNING job_id`)
	if err != nil {
		return ResourceReconcileResult{}, err
	}
	for rows.Next() {
		var jobID string
		if err := rows.Scan(&jobID); err != nil {
			rows.Close()
			return ResourceReconcileResult{}, err
		}
		res.Upserted++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ResourceReconcileResult{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE status = 'running' AND COALESCE(lease_runner_id, '') <> ''`).Scan(&res.Running); err != nil {
		return ResourceReconcileResult{}, err
	}

	// Phase 3: repeat the stale sweep. A completion/recovery that committed
	// between phases 1 and 2 is invisible to phase 1 and could have its row
	// re-created by phase 2 from the stale snapshot; this second sweep sees
	// the committed state and removes it. The symmetric interleavings are
	// covered by the concurrent transaction's own release DELETE.
	deleted, err = deleteStaleReservationsTx(ctx, tx)
	if err != nil {
		return ResourceReconcileResult{}, err
	}
	res.Deleted += deleted

	if err := tx.Commit(ctx); err != nil {
		return ResourceReconcileResult{}, err
	}
	return res, nil
}

// resourceRequestSQL renders the four request values of a running job row
// (alias j) from its payload, defaulting an absent or unparseable value to
// zero. The job's OWN request and its aggregate service envelope
// (service_envelope_request) are summed here, matching
// LeaseClaim.RequestedResources / model.Job.ReservedResources exactly, so the
// promoted leader's ledger equals what the claim would have written.
//
// MAGNITUDE-SAFE, NON-NEGATIVE GUARDS (K6-A): the values are decoded from an
// untrusted payload, and a cast of an out-of-range value RAISES inside the
// reconcile transaction — the pass then aborts, the promotion gate never
// arms, and every lease poll fleet-wide answers 503 until the offending
// job's lease ends. Each read is therefore guarded in two nested steps:
//
//  1. `jsonb_typeof(...) = 'number'` rejects strings, booleans, objects,
//     arrays and null outright (the old character-class regex accepted the
//     TEXT of any scalar and then raised on the cast).
//  2. the numeric value is bounded with an exact `numeric` comparison against
//     the ledger column's domain (and, for the integer dimensions, must be a
//     plain non-negative digit string, mirroring Go's int decoding): a
//     negative value, `1e999` (1000 canonical digits), an over-long pid
//     count or a fractional integer request falls through to the 0 default
//     instead of raising. PostgreSQL stores jsonb numbers as `numeric`, so
//     the comparison itself can never overflow.
//
// The four bounds are the ledger's own column domains — double precision for
// cpu, BIGINT for memory/disk, INTEGER for pids — so a value that passes the
// guard is always representable in the row the upsert writes.
//
// LEGACY SERVICE JOBS (K6-C): a job enqueued before the envelope field
// declares services without `service_envelope_request`, so a promoted leader
// would reconstruct a zero envelope and oversubscribe the runner. Such a
// payload is charged CONSERVATIVELY: when the envelope KEY is absent and the
// persisted compiled job declares at least one service its runtime would
// start (legacyServiceEnvelopeSQL), the job's own request is charged a second
// time as the envelope. That is an upper bound on the pre-envelope
// under-charge (the executor's fair split allocates the services out of the
// job's own resources), it is self-limiting — the rule stops applying as soon
// as the legacy jobs end — and it keeps the promotion gate ARMED instead of
// refusing to schedule until the last legacy job finishes. The key's ABSENCE
// is a reliable legacy marker: encoding/json's omitempty does not drop a
// struct, so every payload the current binary writes carries the key (as
// `{}` at minimum) and is charged exactly its persisted envelope. A payload
// that carries the key with a corrupt value still contributes zero (the
// documented corrupt-value behavior).
var resourceRequestSQL = buildResourceRequestSQL()

// resourceLedgerMaxInt64 / resourceLedgerMaxInt32 are the largest values the
// reservation ledger's BIGINT (memory, disk) and INTEGER (pids) columns can
// hold: a request beyond them is unrepresentable in the ledger, so it
// contributes zero rather than aborting the pass.
const (
	resourceLedgerMaxInt64 = "9223372036854775807"
	resourceLedgerMaxInt32 = "2147483647"
	// resourceLedgerMaxFloat64 is the largest finite float64, the CPU
	// column's domain: Go's json decode rejects anything above it, so the
	// guard falls through to the same zero default.
	resourceLedgerMaxFloat64 = "1.7976931348623157e308"
)

// guardedResourceFloatSQL renders one non-negative, magnitude-safe
// double-precision read of a payload value. The nested CASE is deliberate:
// the jsonb->numeric comparison only evaluates after jsonb_typeof proved the
// value is a JSON number, and the numeric comparison only promotes to
// double precision when the value is inside float64's domain, so no cast in
// the expression can raise on any persisted payload.
func guardedResourceFloatSQL(jsonExpr, _ string) string {
	return fmt.Sprintf(`CASE WHEN jsonb_typeof(%[1]s) = 'number'
				THEN CASE WHEN (%[1]s)::numeric BETWEEN 0 AND %[2]s
					THEN (%[1]s)::double precision
				END
			END`, jsonExpr, resourceLedgerMaxFloat64)
}

// guardedResourceIntSQL renders one non-negative, magnitude-safe integer read
// of a payload value into the ledger column domain [0, maxValue]. The text
// form must be a plain digit string (no sign, fraction or exponent), exactly
// the literal shape Go's json decoding accepts for an integer field; a
// jsonb-stored number always renders in plain decimal form, so this rejects
// only values the Go formula would have rejected (or that the ledger column
// cannot hold).
func guardedResourceIntSQL(maxValue, cast string) func(jsonExpr, textExpr string) string {
	return func(jsonExpr, textExpr string) string {
		return fmt.Sprintf(`CASE WHEN jsonb_typeof(%[1]s) = 'number' AND (%[2]s) ~ '^[0-9]+$'
				THEN CASE WHEN (%[1]s)::numeric BETWEEN 0 AND %[3]s
					THEN (%[2]s)::%[4]s
				END
			END`, jsonExpr, textExpr, maxValue, cast)
	}
}

// compiledServiceServicesRef is the persisted reference to the compiled
// job's declared services: model.Job.CompiledJobPayload.EffectiveJob is the
// canonical pipeline.CompiledJob JSON (see internal/server/enqueue.go), whose
// Job.Services array is the declaration a pre-envelope payload carries.
const compiledServiceServicesRef = `j.payload #> '{compiled_job_payload,effective_job,job,services}'`

// compiledServiceRuntimeRef is the persisted reference to the compiled job's
// runtime, the same field executor.RuntimeRunsServices gates service
// execution on (only "container" runs services).
const compiledServiceRuntimeRef = `j.payload #>> '{compiled_job_payload,effective_job,job,runtime}'`

// legacyServiceEnvelopeSQL is TRUE exactly when the payload declares at least
// one service container that its runtime would actually start (container),
// but carries no service_envelope_request field — i.e. the payload was
// enqueued before the envelope field existed (or its computed envelope was
// entirely zero, which models as the same absent key). The CASE keeps
// jsonb_array_length from ever seeing a non-array value; the runtime arm
// mirrors the enqueue-time gate so a native/tart job, whose declared services
// are never started, is never over-charged.
var legacyServiceEnvelopeSQL = fmt.Sprintf(`(NOT (j.payload ? 'service_envelope_request')
			AND %[2]s = 'container'
			AND CASE WHEN jsonb_typeof(%[1]s) = 'array'
				THEN jsonb_array_length(%[1]s) > 0
				ELSE FALSE
			END)`, compiledServiceServicesRef, compiledServiceRuntimeRef)

// envelopeContributionSQL renders one dimension's service-envelope charge:
// the persisted envelope when the key is present (a corrupt value contributes
// zero), the conservatively re-charged own request for a legacy
// services-without-envelope payload, and zero otherwise.
func envelopeContributionSQL(envelopeSQL, ownSQL string) string {
	return fmt.Sprintf(`CASE WHEN j.payload ? 'service_envelope_request' THEN COALESCE(%[1]s, 0)
				WHEN %[3]s THEN COALESCE(%[2]s, 0)
				ELSE 0
			END`, envelopeSQL, ownSQL, legacyServiceEnvelopeSQL)
}

// jobRunsDeclaredServices reports whether the persisted compiled job declares
// at least one service its runtime would actually start (container), the
// mem-mode form of the services and runtime arms of
// legacyServiceEnvelopeSQL. The effective compiled job is decoded from the
// same shapes JobRuntime accepts (raw JSON, bytes, a JSON string, or an
// in-process struct), so a value kept in memory and a JSON-round-tripped one
// answer identically.
func jobRunsDeclaredServices(j model.Job) bool {
	if j.CompiledJobPayload == nil || j.CompiledJobPayload.EffectiveJob == nil {
		return false
	}
	var raw []byte
	switch v := j.CompiledJobPayload.EffectiveJob.(type) {
	case json.RawMessage:
		raw = v
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		b, err := jsonMarshal(v)
		if err != nil {
			return false
		}
		raw = b
	}
	var cj struct {
		Job struct {
			Runtime  string     `json:"runtime"`
			Services []struct{} `json:"services"`
		} `json:"job"`
	}
	if err := json.Unmarshal(raw, &cj); err != nil {
		return false
	}
	return cj.Job.Runtime == "container" && len(cj.Job.Services) > 0
}

// legacyServiceEnvelopeCharge returns the job's OWN request as the
// conservatively re-charged envelope when the payload is the legacy shape the
// SQL policy defines (services declared, runtime container, envelope absent),
// and ok=false otherwise. The mem store has no key-presence bit after
// decoding the payload into model.Job, so the zero envelope struct is its
// only representation of "absent": a mem job whose computed envelope is
// entirely zero — only the oversubscribed-plan case, where the executor fails
// the job closed before starting any service — is therefore over-charged by
// the same rule, which is conservative (never more work admitted than the
// claim's own-request charge) and bounded. Negative dimensions are clamped to
// zero so the answer matches the SQL guards.
func legacyServiceEnvelopeCharge(j model.Job) (model.ResourceCapacity, bool) {
	if j.ServiceEnvelopeRequest != (model.ResourceCapacity{}) {
		return model.ResourceCapacity{}, false
	}
	if !jobRunsDeclaredServices(j) {
		return model.ResourceCapacity{}, false
	}
	return nonNegativeCapacity(j.ResourceRequest()), true
}

// nonNegativeCapacity clamps every negative dimension to zero: the SQL
// reservation guards refuse a negative payload value (charging it would
// INFLATE the runner's remaining capacity), so the mem reconciliation clamps
// to the same answer instead of mirroring the negative value.
func nonNegativeCapacity(c model.ResourceCapacity) model.ResourceCapacity {
	if c.CPU < 0 {
		c.CPU = 0
	}
	if c.Memory < 0 {
		c.Memory = 0
	}
	if c.Disk < 0 {
		c.Disk = 0
	}
	if c.PIDs < 0 {
		c.PIDs = 0
	}
	return c
}

// buildResourceRequestSQL assembles the four ledger dimensions in the
// column order of job_resource_reservations (cpu, memory, disk, pids).
func buildResourceRequestSQL() string {
	own := func(jsonPath string, guard func(jsonExpr, textExpr string) string) string {
		return guard("j.payload->'"+jsonPath+"'", "j.payload->>'"+jsonPath+"'")
	}
	envelope := func(key string, guard func(jsonExpr, textExpr string) string) string {
		return guard("j.payload->'service_envelope_request'->'"+key+"'", "j.payload->'service_envelope_request'->>'"+key+"'")
	}
	dimension := func(jsonPath, envelopeKey string, guard func(jsonExpr, textExpr string) string) string {
		ownSQL := own(jsonPath, guard)
		return "COALESCE(" + ownSQL + `, 0)
	       + ` + envelopeContributionSQL(envelope(envelopeKey, guard), ownSQL)
	}
	return strings.Join([]string{
		dimension("cpu_request", "cpu", guardedResourceFloatSQL),
		dimension("memory_request", "memory", guardedResourceIntSQL(resourceLedgerMaxInt64, "bigint")),
		dimension("disk_request", "disk", guardedResourceIntSQL(resourceLedgerMaxInt64, "bigint")),
		dimension("pids_request", "pids", guardedResourceIntSQL(resourceLedgerMaxInt32, "int")),
	}, ",\n\t       ")
}

// deleteStaleReservationsTx removes every ledger row that no longer describes
// a live lease (job id, runner, generation) — the exact negation of
// liveReservationExistsSQL, the predicate the capacity SUM counts by — and
// returns the number of rows deleted.
func deleteStaleReservationsTx(ctx context.Context, tx pgx.Tx) (int, error) {
	ct, err := tx.Exec(ctx, `DELETE FROM job_resource_reservations AS r WHERE NOT `+liveReservationExistsSQL)
	if err != nil {
		return 0, err
	}
	return int(ct.RowsAffected()), nil
}

var _ ResourceReconcileStore = (*PostgresStore)(nil)
