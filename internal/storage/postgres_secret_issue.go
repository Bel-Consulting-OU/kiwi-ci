package storage

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/jackc/pgx/v5"
)

// SecretIssuance is one candidate secret delivery: the lease coordinates the
// handler AUTHENTICATED from its preliminary read, the secret name the runner
// asked for, and the issuance instant. It is the request of the commit-time
// authority (SecretIssuanceStore.CommitSecretIssuance): the store re-evaluates
// the whole issuance predicate against the LOCKED job — status, lease
// holder/generation/token hash, lease expiry against the DATABASE clock, trust
// and the secret declaration in the locked payload — and, in the same
// transaction, inserts the once-only secret_claims row and appends the durable
// secret.issued audit event before committing.
//
// The sealed envelope travels WITH the request so it can be persisted inside
// the same transaction as the claim: the value never leaves the broker, and
// the claim + envelope + audit are the only durable state a delivery leaves.
type SecretIssuance struct {
	JobID           string
	RunnerID        string
	LeaseGeneration int64
	LeaseTokenHash  []byte
	SecretName      string
	IssuedAt        time.Time

	// RecipientPublic is the runner's ephemeral X25519 request public key the
	// envelope was sealed for. It is the replay identity of the delivery: a
	// retry that presents the same key replays the stored envelope, any other
	// key stays a duplicate refusal.
	RecipientPublic []byte
	// EphemeralPublic, Ciphertext and Nonce are the sealed envelope persisted
	// with the claim inside the same transaction, so an identical retry can be
	// answered 200 with the exact same bytes instead of minting a second
	// delivery. All three are set together by the handler.
	EphemeralPublic []byte
	Ciphertext      []byte
	Nonce           []byte
}

// SealedSecretDelivery is one sealed secret envelope: the AEAD ciphertext,
// the server's ephemeral X25519 public key the value was sealed under, and
// the AEAD nonce. It is exactly what the runner needs to open the delivery
// and what a retry of a committed delivery replays byte-for-byte.
type SealedSecretDelivery struct {
	Ciphertext      []byte
	EphemeralPublic []byte
	Nonce           []byte
}

// StoredSecretIssuance is the durable state of one committed delivery: the
// runner's request public key the envelope was sealed for (the replay
// identity) and the sealed envelope itself. A stored record whose envelope is
// incomplete (a legacy row from before the envelope columns) is never
// replayable; it still refuses a second delivery.
type StoredSecretIssuance struct {
	RecipientPublic []byte
	Envelope        SealedSecretDelivery
}

// ReplayableSecretIssuance is the ONE replay predicate shared by the
// PostgreSQL store, the memory store and the server's fs-mode journal: a
// duplicate delivery is a replay only when the stored record carries a
// complete sealed envelope AND the runner presented the exact same ephemeral
// public key the envelope was sealed for. Anything else (a different key, a
// legacy row without an envelope) is a hard duplicate refusal, so a replay
// can never mint a new envelope for a key that did not receive the original.
func ReplayableSecretIssuance(stored StoredSecretIssuance, req SecretIssuance) bool {
	return len(stored.RecipientPublic) > 0 && len(req.RecipientPublic) > 0 &&
		bytes.Equal(stored.RecipientPublic, req.RecipientPublic) &&
		len(stored.Envelope.EphemeralPublic) > 0 &&
		len(stored.Envelope.Ciphertext) > 0 &&
		len(stored.Envelope.Nonce) > 0
}

// LockedSecretLease is the authoritative lease/declaration state of the job
// row the issuance transaction locked: every field comes from the locked row
// (or, in memory/fs mode, from the job mutated under the store lock), never
// from the credentials the caller presented.
type LockedSecretLease struct {
	Status          model.Status
	LeaseRunnerID   string
	LeaseGeneration int64
	LeaseTokenHash  []byte
	LeaseExpiresAt  time.Time
	Trusted         bool
	DeclaredSecrets []string
}

// Typed commit-time refusals. Every lease/declaration refusal is a 409 (the
// same semantics as a stale lease at request start), a vanished job is
// ErrNotFound (404), and a duplicate is a 409 (the once-only claim was taken
// by a concurrent or replayed delivery). The error taxonomy is what lets the
// handler answer precisely without re-reading anything itself.
var (
	// ErrSecretIssuanceRevoked reports that the job is no longer running: it
	// was cancelled, completed, failed or otherwise left the running state
	// between the preliminary read and the commit.
	ErrSecretIssuanceRevoked = errors.New("storage: secret issuance refused: job is no longer running")
	// ErrSecretIssuanceRunner reports that the lease holder changed.
	ErrSecretIssuanceRunner = errors.New("storage: secret issuance refused: lease holder changed")
	// ErrSecretIssuanceGeneration reports that the lease generation changed (a
	// replacement lease was acquired).
	ErrSecretIssuanceGeneration = errors.New("storage: secret issuance refused: lease generation changed")
	// ErrSecretIssuanceToken reports that the lease token hash changed.
	ErrSecretIssuanceToken = errors.New("storage: secret issuance refused: lease token changed")
	// ErrSecretIssuanceExpired reports that the lease had already expired by
	// the transaction's database clock.
	ErrSecretIssuanceExpired = errors.New("storage: secret issuance refused: lease expired")
	// ErrSecretIssuanceUntrusted reports that the locked job is untrusted.
	ErrSecretIssuanceUntrusted = errors.New("storage: secret issuance refused: job is untrusted")
	// ErrSecretIssuanceNotDeclared reports that the secret is no longer in the
	// locked job's compiled declaration allowlist.
	ErrSecretIssuanceNotDeclared = errors.New("storage: secret issuance refused: secret not declared")
	// ErrSecretIssuanceDuplicate reports that the once-only claim for this
	// (job, generation, secret) already exists: a concurrent or replayed
	// delivery won the arbitration.
	ErrSecretIssuanceDuplicate = errors.New("storage: secret issuance refused: already delivered")
	// ErrSecretIssuanceInvalid reports a malformed request (missing
	// coordinates, empty token hash or secret name, or a zero issuance time).
	ErrSecretIssuanceInvalid = errors.New("storage: invalid secret issuance request")
)

// SecretIssuanceStore is the transactional commit-time delivery contract.
//
// issueSecret authenticates the lease and the declaration with a cheap
// preliminary read, then may spend seconds resolving the broker and sealing
// the envelope. A late handler-side re-check followed by a separate claim and
// audit append would not close that window: a concurrent cancel/complete/
// expiry/replacement can still commit in between, so the handler could return
// a secret after the lease ceased. This method evaluates the ENTIRE issuance
// predicate and inserts the once-only secret_claims row together with the
// durable secret.issued audit event in the SAME transaction (PostgreSQL: under
// a row lock on the job), so a concurrent revocation either commits first (and
// fails the predicate) or waits for the issuance commit. Only a successful
// commit authorizes the handler to write the sealed envelope; refusal is a
// typed error from the ErrSecretIssuance* set and commits NOTHING.
//
// The returned envelope is the sealed delivery to serve: on a first commit it
// is the request's own envelope; on a same-key replay (replayed=true) it is
// the stored envelope of the original commit, and NOTHING new is written (no
// second claim, no second audit). A duplicate whose presented key differs
// from the stored one is still ErrSecretIssuanceDuplicate.
type SecretIssuanceStore interface {
	CommitSecretIssuance(ctx context.Context, req SecretIssuance) (SealedSecretDelivery, bool, error)
	// LookupSecretIssuance reads the stored record of an already committed
	// delivery. found=false means no commit exists. It exists so the handler
	// can answer an identical retry from the stored envelope WITHOUT
	// re-resolving the broker or touching the commit path at all.
	LookupSecretIssuance(ctx context.Context, jobID string, generation int64, secretName string) (StoredSecretIssuance, bool, error)
}

var (
	_ SecretIssuanceStore = (*PostgresStore)(nil)
	_ SecretIssuanceStore = (*memStore)(nil)
	_ SecretIssuanceStore = (*FaultyStore)(nil)
)

// secretIssuanceErrorf wraps a typed refusal with the offending values.
func secretIssuanceErrorf(base error, format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{base}, args...)...)
}

// ValidateSecretIssuanceRequest is the shape contract of the commit request:
// the predicate addresses exactly one job by id and runner, needs the
// presented lease coordinates and the requested secret name. The coordinate
// strings are checked for presence, not canonical 32-hex shape: they always
// come from authenticated server state (the route's job id and the validated
// lease record), and the in-memory modes address their map keys directly.
func ValidateSecretIssuanceRequest(req SecretIssuance) error {
	if strings.TrimSpace(req.JobID) == "" {
		return secretIssuanceErrorf(ErrSecretIssuanceInvalid, "empty job id")
	}
	if strings.TrimSpace(req.RunnerID) == "" {
		return secretIssuanceErrorf(ErrSecretIssuanceInvalid, "job %s: empty runner id", req.JobID)
	}
	if req.LeaseGeneration < 0 {
		return secretIssuanceErrorf(ErrSecretIssuanceInvalid, "job %s: negative lease generation %d", req.JobID, req.LeaseGeneration)
	}
	if len(req.LeaseTokenHash) == 0 {
		return secretIssuanceErrorf(ErrSecretIssuanceInvalid, "job %s: empty lease token hash", req.JobID)
	}
	if strings.TrimSpace(req.SecretName) == "" {
		return secretIssuanceErrorf(ErrSecretIssuanceInvalid, "job %s: empty secret name", req.JobID)
	}
	if req.IssuedAt.IsZero() {
		return secretIssuanceErrorf(ErrSecretIssuanceInvalid, "job %s: zero issuance time", req.JobID)
	}
	return nil
}

// LockedSecretLeaseForJob derives the authoritative locked lease/declaration
// state from an in-memory job record whose lease fields are protected by the
// caller's lock. PostgreSQL fills the same struct from the FOR UPDATE row;
// this helper keeps memStore and the server's in-process mode on the identical
// derivation.
func LockedSecretLeaseForJob(j model.Job) LockedSecretLease {
	var expires time.Time
	if j.LeaseExpiresAt != nil {
		expires = *j.LeaseExpiresAt
	}
	return LockedSecretLease{
		Status:          j.Status,
		LeaseRunnerID:   j.LeaseRunnerID,
		LeaseGeneration: j.LeaseGeneration,
		LeaseTokenHash:  j.LeaseTokenHash,
		LeaseExpiresAt:  expires,
		Trusted:         j.Trusted,
		DeclaredSecrets: append([]string(nil), j.DeclaredSecrets...),
	}
}

// ValidateSecretIssuance is the ONE issuance predicate: it evaluates the
// locked lease state against the candidate request and returns the typed
// refusal the handler maps onto 409. The caller supplies commitNow — the
// transaction's DATABASE clock in PostgreSQL mode, the store/server clock in
// memory mode — and the lease must be strictly unexpired at that instant.
// PostgreSQL (row-locked), memStore and the server's in-process commit path
// all call it, so the three can never drift.
func ValidateSecretIssuance(locked LockedSecretLease, req SecretIssuance, commitNow time.Time) error {
	switch {
	case locked.Status != model.StatusRunning:
		return secretIssuanceErrorf(ErrSecretIssuanceRevoked, "job %s status %q", req.JobID, locked.Status)
	case locked.LeaseRunnerID != req.RunnerID:
		return secretIssuanceErrorf(ErrSecretIssuanceRunner, "job %s lease holder %q, presented %q", req.JobID, locked.LeaseRunnerID, req.RunnerID)
	case locked.LeaseGeneration != req.LeaseGeneration:
		return secretIssuanceErrorf(ErrSecretIssuanceGeneration, "job %s lease generation %d, presented %d", req.JobID, locked.LeaseGeneration, req.LeaseGeneration)
	case subtle.ConstantTimeCompare(locked.LeaseTokenHash, req.LeaseTokenHash) != 1:
		return secretIssuanceErrorf(ErrSecretIssuanceToken, "job %s lease token mismatch", req.JobID)
	case locked.LeaseExpiresAt.IsZero() || !locked.LeaseExpiresAt.After(commitNow):
		return secretIssuanceErrorf(ErrSecretIssuanceExpired, "job %s lease expired at %s", req.JobID, locked.LeaseExpiresAt.UTC().Format(time.RFC3339Nano))
	case !locked.Trusted:
		return secretIssuanceErrorf(ErrSecretIssuanceUntrusted, "job %s", req.JobID)
	case !containsString(locked.DeclaredSecrets, req.SecretName):
		return secretIssuanceErrorf(ErrSecretIssuanceNotDeclared, "job %s secret %q", req.JobID, req.SecretName)
	}
	return nil
}

// SecretIssuanceAuditEvent builds the secret.issued audit event for a request
// that has been validated against the locked lease. It is the ONE event shape
// both the store implementations and the server's in-process commit path
// write, so the audit trail is identical across modes. The audit never carries
// the value, only the secret name and lease generation.
func SecretIssuanceAuditEvent(req SecretIssuance, runID, id string) model.AuditEvent {
	return model.AuditEvent{
		ID:        id,
		Action:    "secret.issued",
		Actor:     req.RunnerID,
		RunID:     runID,
		JobID:     req.JobID,
		Message:   "secret delivered",
		Metadata:  map[string]string{"secret": req.SecretName, "generation": strconv.FormatInt(req.LeaseGeneration, 10)},
		CreatedAt: req.IssuedAt.UTC(),
	}
}

// CommitSecretIssuance is the PostgreSQL commit-time delivery authority. It
// locks the job row FOR UPDATE, re-reads the authoritative lease/declaration
// fields plus the database clock, evaluates the shared predicate, inserts the
// once-only secret_claims row carrying the sealed envelope and the
// secret.issued audit row, and commits, all in one transaction. Any refusal
// returns a typed error and rolls the transaction back: no claim, no audit
// row, no envelope.
//
// A duplicate whose stored recipient public key equals the presented one is a
// REPLAY: the transaction rolls back (it wrote nothing) and returns the
// stored envelope with replayed=true, so the caller answers 200 with the
// exact original bytes and never a second claim or audit. A duplicate with a
// different key stays ErrSecretIssuanceDuplicate (409). The lease predicate is
// evaluated BEFORE the duplicate check, so a stale generation is refused by
// lease validation and can never replay.
//
// The clock must be read ONLY after the row lock is held: a plain
// target-list clock_timestamp() is evaluated during the scan, BEFORE
// LockRows acquires the lock, and would therefore be stale by exactly the
// stall this commit fences (a delivery that outlives its lease while waiting
// for a concurrent cancellation's row lock). The CTE below keeps the
// FOR UPDATE clause in a materialized sub-plan (a CTE with a locking clause
// is never inlined), so the outer clock_timestamp() is evaluated after the
// lock has been acquired — the same construction CommitOIDCIssuance uses.
func (s *PostgresStore) CommitSecretIssuance(ctx context.Context, req SecretIssuance) (SealedSecretDelivery, bool, error) {
	if err := ValidateSecretIssuanceRequest(req); err != nil {
		return SealedSecretDelivery{}, false, err
	}
	tx, err := s.beginSchemaCompatibleTx(ctx)
	if err != nil {
		return SealedSecretDelivery{}, false, err
	}
	defer tx.Rollback(ctx)
	var (
		runID           string
		status          string
		leaseRunnerID   string
		leaseGeneration int64
		leaseTokenHash  []byte
		leaseExpiresAt  *time.Time
		declaredJSON    []byte
		trusted         bool
		commitNow       time.Time
	)
	err = tx.QueryRow(ctx, `WITH locked AS (
		SELECT run_id, status, COALESCE(lease_runner_id, '') AS lease_runner_id, lease_generation,
			COALESCE(lease_token_hash, ''::bytea) AS lease_token_hash, lease_expires_at,
			CASE WHEN jsonb_typeof(payload->'trusted') = 'boolean' THEN (payload->>'trusted')::boolean ELSE FALSE END AS trusted,
			COALESCE(payload->'declared_secrets', '[]'::jsonb) AS declared_secrets
		FROM jobs WHERE id = $1 FOR UPDATE
	)
	SELECT run_id, status, lease_runner_id, lease_generation, lease_token_hash, lease_expires_at,
		trusted, declared_secrets, clock_timestamp()
	FROM locked`, req.JobID).Scan(
		&runID, &status, &leaseRunnerID, &leaseGeneration, &leaseTokenHash, &leaseExpiresAt, &trusted, &declaredJSON, &commitNow)
	if errors.Is(err, pgx.ErrNoRows) {
		return SealedSecretDelivery{}, false, ErrNotFound
	}
	if err != nil {
		return SealedSecretDelivery{}, false, err
	}
	var declared []string
	if len(declaredJSON) > 0 && string(declaredJSON) != "null" {
		if err := json.Unmarshal(declaredJSON, &declared); err != nil {
			return SealedSecretDelivery{}, false, fmt.Errorf("storage: decode job declared_secrets: %w", err)
		}
	}
	locked := LockedSecretLease{
		Status:          model.Status(status),
		LeaseRunnerID:   leaseRunnerID,
		LeaseGeneration: leaseGeneration,
		LeaseTokenHash:  leaseTokenHash,
		Trusted:         trusted,
		DeclaredSecrets: declared,
	}
	if leaseExpiresAt != nil {
		locked.LeaseExpiresAt = *leaseExpiresAt
	}
	if err := ValidateSecretIssuance(locked, req, commitNow); err != nil {
		return SealedSecretDelivery{}, false, err
	}
	ct, err := tx.Exec(ctx, `INSERT INTO secret_claims (job_id, generation, secret_name, recipient_public, ephemeral_public, ciphertext, nonce, sealed_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (job_id, generation, secret_name) DO NOTHING`,
		req.JobID, req.LeaseGeneration, req.SecretName,
		nullBytes(req.RecipientPublic), nullBytes(req.EphemeralPublic), nullBytes(req.Ciphertext), nullBytes(req.Nonce), req.IssuedAt)
	if err != nil {
		return SealedSecretDelivery{}, false, err
	}
	if ct.RowsAffected() != 1 {
		stored, found, err := queryStoredSecretIssuance(ctx, tx, req.JobID, req.LeaseGeneration, req.SecretName)
		if err != nil {
			return SealedSecretDelivery{}, false, err
		}
		if found && ReplayableSecretIssuance(stored, req) {
			return stored.Envelope, true, nil
		}
		return SealedSecretDelivery{}, false, secretIssuanceErrorf(ErrSecretIssuanceDuplicate, "job %s generation %d secret %q", req.JobID, req.LeaseGeneration, req.SecretName)
	}
	auditID, err := newID()
	if err != nil {
		return SealedSecretDelivery{}, false, err
	}
	ev := SecretIssuanceAuditEvent(req, runID, auditID)
	var meta []byte
	if len(ev.Metadata) > 0 {
		meta, err = jsonMarshal(ev.Metadata)
		if err != nil {
			return SealedSecretDelivery{}, false, err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events (id, action, actor, run_id, job_id, message, metadata, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		ev.ID, ev.Action, nullText(ev.Actor), nullText(ev.RunID), nullText(ev.JobID), nullText(ev.Message), meta, ev.CreatedAt); err != nil {
		return SealedSecretDelivery{}, false, err
	}
	// secret.issued is one transaction with the claim and the audit: a
	// failed append rolls the delivery back, so the envelope is never
	// returned without its stream evidence. Only the NAME and generation
	// travel in the event.
	if err := appendExecutionEventTx(ctx, tx, ExecutionEventSecretIssued(req, runID)); err != nil {
		return SealedSecretDelivery{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return SealedSecretDelivery{}, false, err
	}
	return SealedSecretDelivery{
		Ciphertext:      cloneSecretBytes(req.Ciphertext),
		EphemeralPublic: cloneSecretBytes(req.EphemeralPublic),
		Nonce:           cloneSecretBytes(req.Nonce),
	}, false, nil
}

// LookupSecretIssuance reads the durable record of an already committed
// delivery (PostgreSQL: the secret_claims row). found=false means no commit
// exists. It is the read side of the replay protocol: the handler uses it to
// answer an identical retry from the stored envelope without re-resolving the
// broker or entering the commit path.
func (s *PostgresStore) LookupSecretIssuance(ctx context.Context, jobID string, generation int64, secretName string) (StoredSecretIssuance, bool, error) {
	if err := ValidateJobID(jobID); err != nil {
		return StoredSecretIssuance{}, false, err
	}
	if generation < 0 {
		return StoredSecretIssuance{}, false, fmt.Errorf("storage: invalid lease generation %d", generation)
	}
	if strings.TrimSpace(secretName) == "" {
		return StoredSecretIssuance{}, false, fmt.Errorf("storage: empty secret name")
	}
	return queryStoredSecretIssuance(ctx, s.pool, jobID, generation, secretName)
}

// secretIssuanceQueryer is the shared single-row read surface of pgx.Tx and
// pgxpool.Pool, so the commit transaction and the standalone lookup decode the
// stored envelope through ONE query.
type secretIssuanceQueryer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// queryStoredSecretIssuance reads and decodes one secret_claims row.
func queryStoredSecretIssuance(ctx context.Context, q secretIssuanceQueryer, jobID string, generation int64, secretName string) (StoredSecretIssuance, bool, error) {
	var recipient, ephemeralPublic, ciphertext, nonce []byte
	err := q.QueryRow(ctx, `SELECT recipient_public, ephemeral_public, ciphertext, nonce FROM secret_claims WHERE job_id=$1 AND generation=$2 AND secret_name=$3`,
		jobID, generation, secretName).Scan(&recipient, &ephemeralPublic, &ciphertext, &nonce)
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredSecretIssuance{}, false, nil
	}
	if err != nil {
		return StoredSecretIssuance{}, false, err
	}
	return StoredSecretIssuance{
		RecipientPublic: cloneSecretBytes(recipient),
		Envelope: SealedSecretDelivery{
			Ciphertext:      cloneSecretBytes(ciphertext),
			EphemeralPublic: cloneSecretBytes(ephemeralPublic),
			Nonce:           cloneSecretBytes(nonce),
		},
	}, true, nil
}

// cloneSecretBytes copies a sealed-envelope byte slice so no caller can
// mutate state that another caller still observes.
func cloneSecretBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}
