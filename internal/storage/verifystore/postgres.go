// Package verifystore is the production durable implementation of
// verifyapi.VerificationStore on PostgreSQL. It lives outside
// internal/storage because storage cannot import verifyapi (verifyapi's
// provenance adapter pulls internal/version, which already imports storage);
// this package is the sanctioned seam that may depend on both.
package verifystore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/verifyapi"
)

// PostgresStore is the durable SQL implementation of
// verifyapi.VerificationStore. Hot-path identity columns (ids, content
// digests, claim/verified flags, group/candidate dimensions, subject/scope,
// timestamps) are real relational columns; the full wire structs live in
// JSONB payloads so reads round-trip byte-faithful claim identities.
//
// Source of truth (P7): the normalized subject/scope and index columns are
// AUTHORITATIVE. The JSONB payload is the wire-faithful encoding. Every
// write emits columns and payload together in one write-all statement,
// derived from the same Go value (subject_scope.go), so a successful write
// cannot leave them diverged; reads restore subject/scope from the columns.
//
// The schema is created by internal/storage/migrations (0057+) and applied
// by storage.PostgresStore.Migrate; this package only owns the read/write
// contract.
type PostgresStore struct {
	// recipes resolves recipe-bound obligations at accept/restore time so
	// the demand digest is the recipe's rule set (never weaker inline rules).
	recipes *verifyapi.RecipeRegistry
	pool    *pgxpool.Pool
	// now reads the store clock for freshness binding at record time.
	// Production leaves it nil (time.Now); tests may override it.
	now func() time.Time
	// acceptanceKeyring seals and verifies durable acceptance records. It is
	// REQUIRED for RecordVerifiedOutcome and for QueryOutcome of a verified
	// row: a store without it refuses both (fail closed) instead of
	// restoring authority from a bare database row. The keyring is
	// deliberately separate from the runner evidence keys used to resolve
	// attestations. Old records verify under their own KeyID; new records
	// are sealed under the keyring's current signing key (rotation).
	acceptanceKeyring *verifyapi.AcceptanceKeyring
}

// WithAcceptanceKey sets a single acceptance key this store uses to seal and
// verify durable acceptance records. Required before any verified write or
// read; without it both are refused with verifyapi.ErrAcceptance.
func (s *PostgresStore) WithAcceptanceKey(key verifyapi.AcceptanceKey) *PostgresStore {
	if key == nil {
		s.acceptanceKeyring = nil
		return s
	}
	ring, err := verifyapi.NewSingleKeyring(key)
	if err != nil {
		// A key that cannot form a keyring is unusable; leave the store
		// unarmed so both write and read refuse (fail closed).
		s.acceptanceKeyring = nil
		return s
	}
	s.acceptanceKeyring = ring
	return s
}

// WithAcceptanceKeyring arms the store with a rotation-aware keyring. New
// records are sealed under the keyring's current signing key; persisted
// records verify under the key id they were sealed with. Required before any
// verified write or read.
// WithRecipes installs the recipe registry used to resolve recipe-bound
// obligations at accept and restore. Required before persisting or loading
// any record whose obligation pins a RecipeDigest.
func (s *PostgresStore) WithRecipes(r *verifyapi.RecipeRegistry) *PostgresStore {
	s.recipes = r
	return s
}

func (s *PostgresStore) WithAcceptanceKeyring(ring *verifyapi.AcceptanceKeyring) *PostgresStore {
	s.acceptanceKeyring = ring
	return s
}

// compile-time proof that PostgresStore implements the durable contract.
var _ verifyapi.VerificationStore = (*PostgresStore)(nil)

// NewPostgres opens a pool on dsn and verifies connectivity.
func NewPostgres(ctx context.Context, dsn string) (*PostgresStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("verifystore: parse dsn: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("verifystore: open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("verifystore: ping: %w", err)
	}
	return &PostgresStore{pool: pool}, nil
}

// NewPostgresFromPool adopts an existing pgxpool (tests, shared wiring).
func NewPostgresFromPool(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// Close releases the pool opened by NewPostgres. A store built from an
// adopted pool must not close it — close the owner instead.
func (s *PostgresStore) Close() {
	if s == nil || s.pool == nil {
		return
	}
	s.pool.Close()
}

// isUniqueViolation reports whether err is PostgreSQL SQLSTATE 23505
// (unique_violation) — the signal that an idempotency key already has a
// durable row.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// contentDigest is the lowercase hex SHA-256 of a canonical JSON encoding.
func contentDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// canonicalJSON marshals v with map keys sorted (encoding/json) so two equal
// values always produce identical bytes. Times must already be UTC-
// normalized by the callers below: claim identity is instant equality
// (see claimContentDigest), not location-tag equality.
func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("verifystore: encode payload: %w", err)
	}
	return raw, nil
}

// utcTime normalizes a timestamp to UTC so Equal instants hash equal.
func utcTime(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.UTC()
}

// utcFreshness normalizes the optional freshness timestamps.
func utcFreshness(p verifyapi.FreshnessPolicy) verifyapi.FreshnessPolicy {
	if p.NotBefore != nil {
		t := utcTime(*p.NotBefore)
		p.NotBefore = &t
	}
	if p.NotAfter != nil {
		t := utcTime(*p.NotAfter)
		p.NotAfter = &t
	}
	return p
}

// ObligationContentDigest is the SubmitObligation idempotency identity: the
// canonical encoding of the whole obligation. An identical resubmit hashes
// equal; any different content under the same obligation_id does not.
func ObligationContentDigest(o verifyapi.VerificationObligation) (string, error) {
	n := o
	n.IssuedAt = utcTime(n.IssuedAt)
	n.Freshness = utcFreshness(n.Freshness)
	raw, err := canonicalJSON(n)
	if err != nil {
		return "", err
	}
	return contentDigest(raw), nil
}

// ClaimContentDigest is the RecordOutcome / RecordVerifiedOutcome
// idempotency identity: the claim-equivalent encoding of the outcome, with
// substrate-derived Measured facts stripped (they are refilled at record
// time and never participate in identity), timestamps UTC-normalized, and
// ExecutionIDs canonicalized as a sorted set. Under Model A the submitted
// claim is stored as-is and its ExecutionIDs stay DISTINCT from the
// evidence-derived set forever, so evidence-derived id upgrades never enter
// this digest; sorting + de-duplicating only canonicalizes retries that
// reorder or repeat the same raw claim ids (not a different claim).
func ClaimContentDigest(v verifyapi.VerificationOutcome) (string, error) {
	n := v
	n.StartedAt = utcTime(n.StartedAt)
	n.CompletedAt = utcTime(n.CompletedAt)
	n.Resources.Measured = nil
	n.ExecutionIDs = canonicalExecutionIDs(n.ExecutionIDs)
	raw, err := canonicalJSON(n)
	if err != nil {
		return "", err
	}
	return contentDigest(raw), nil
}

// canonicalExecutionIDs returns the id list as a sorted set: order and
// duplicates are not claim identity (see ClaimContentDigest / Model A).
func canonicalExecutionIDs(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// GroupContentDigest is the RegisterGroup idempotency identity.
func GroupContentDigest(g verifyapi.SpeculativeGroup) (string, error) {
	raw, err := canonicalJSON(g)
	if err != nil {
		return "", err
	}
	return contentDigest(raw), nil
}

// verifyNow reads the store clock used for freshness binding at record time.
func (s *PostgresStore) verifyNow() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now().UTC()
}

// SubmitObligation records a new claim obligation. ObligationID is the
// idempotency key: an identical resubmit is a no-op success; a different
// payload under the same key is refused with verifyapi.ErrExists.
func (s *PostgresStore) SubmitObligation(ctx context.Context, o verifyapi.VerificationObligation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := o.Validate(); err != nil {
		return err
	}
	digest, err := ObligationContentDigest(o)
	if err != nil {
		return err
	}
	payload, err := canonicalJSON(o)
	if err != nil {
		return err
	}
	// Write-all: subject/scope columns and the payload come from the same
	// obligation value in the same statement (subject_scope.go).
	sc := ScopeOfObligation(o)
	_, err = s.pool.Exec(ctx, `
		INSERT INTO verification_obligations (
			obligation_id, content_digest, payload,
			subject, authority_namespace, tenant_id, project_id, repository_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		o.ObligationID, digest, payload,
		sc.Subject, sc.AuthorityNamespace, sc.TenantID, sc.ProjectID, sc.RepositoryID)
	if err == nil {
		return nil
	}
	if !isUniqueViolation(err) {
		return fmt.Errorf("verifystore: submit obligation %q: %w", o.ObligationID, err)
	}
	return s.idempotentConflict(ctx,
		`SELECT content_digest FROM verification_obligations WHERE obligation_id = $1`,
		o.ObligationID, digest, "obligation", o.ObligationID)
}

// idempotentConflict resolves a unique-violation race after the insert was
// refused: an identical content digest is the already-accepted submission
// (success); any other content is a genuine conflict (verifyapi.ErrExists).
func (s *PostgresStore) idempotentConflict(ctx context.Context, query, id, wantDigest, kind, label string) error {
	var got string
	err := s.pool.QueryRow(ctx, query, id).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		// Deleted between the insert attempt and the read — treat as a
		// refusal rather than inventing success.
		return fmt.Errorf("%w: %s %q", verifyapi.ErrExists, kind, label)
	}
	if err != nil {
		return fmt.Errorf("verifystore: read %s %q after conflict: %w", kind, label, err)
	}
	if got == wantDigest {
		return nil
	}
	return fmt.Errorf("%w: %s %q", verifyapi.ErrExists, kind, label)
}

// RecordOutcome records a submitted outcome as a CLAIM. VerificationID is
// the idempotency key. The outcome is validated and bound under the same
// rules as the in-process registry; Measured resource facts are filled at
// record time. A claim is never authoritative.
func (s *PostgresStore) RecordOutcome(ctx context.Context, v verifyapi.VerificationOutcome) error {
	return s.recordOutcomeTx(ctx, v, v, nil, nil)
}

// RecordVerifiedOutcome records a verifier-produced VerifiedOutcome as the
// authoritative result. VerificationID is the idempotency key; an identical
// resubmit (or an upgrade of an equivalent claim) is a no-op success, a
// different submission under the same key is verifyapi.ErrExists. An
// unsealed value is refused with verifyapi.ErrUnverified.
//
// Model A: the SUBMITTED claim is stored as-is (claim column, and the
// idempotency digest is the claim's) so evidence-derived id upgrades never
// fork or fail the claim record; the derived Outcome and Evidence travel
// together in the evidence payload, and the AcceptanceRecord computed here
// is persisted in the acceptance column so the read path can re-check the
// exact triple (see QueryOutcome / verifyapi.RestoreVerifiedOutcome).
func (s *PostgresStore) RecordVerifiedOutcome(ctx context.Context, v verifyapi.VerifiedOutcome) error {
	if !v.Sealed() {
		return fmt.Errorf("%w: RecordVerifiedOutcome requires a verifier-produced record", verifyapi.ErrUnverified)
	}
	if s.acceptanceKeyring == nil {
		return fmt.Errorf("%w: store has no acceptance keyring; refusing to persist unsealed authority", verifyapi.ErrAcceptance)
	}
	ob, err := s.GetObligation(ctx, v.SubmittedClaim.ObligationID)
	if err != nil {
		return err
	}
	var recipe *verifyapi.Recipe
	if ob.RecipeDigest != "" {
		if s.recipes == nil {
			return fmt.Errorf("%w: store has no recipe registry; cannot accept a recipe-bound record", verifyapi.ErrBinding)
		}
		r, err := s.recipes.ByDigest(ob.RecipeDigest)
		if err != nil {
			return err
		}
		recipe = &r
		// The recipe's evidence floor is not only a service-path concern: a
		// direct store write must enforce it before the acceptance record is
		// minted, or the floor could be bypassed by calling the store
		// without the service wrapper.
		if err := recipe.EvidenceMin.Check(v.Evidence); err != nil {
			return fmt.Errorf("%w: record fails the recipe evidence floor: %v", verifyapi.ErrEvidence, err)
		}
	}
	rec, err := verifyapi.AcceptWithRecipe(ob, v, nil, s.acceptanceKeyring, recipe, s.verifyNow())
	if err != nil {
		return err
	}
	payload := verifiedPayload{Outcome: v.Outcome, Evidence: v.Evidence}
	return s.recordOutcomeTx(ctx, v.SubmittedClaim, v.Outcome, &payload, &rec)
}

// verifiedPayload is the evidence-column shape of a verified row: the
// derived authoritative outcome plus the resolved evidence behind it. The
// submitted claim lives in the claim column (Model A keeps the two distinct).
// The acceptance record is NOT embedded here: its column is the single
// source of truth for the integrity record (and the idempotency predicate
// reads it from there).
type verifiedPayload struct {
	Outcome  verifyapi.VerificationOutcome `json:"outcome"`
	Evidence verifyapi.VerifiedEvidence    `json:"evidence"`
}

// recordOutcomeTx writes one outcome row (claim-only when payload is nil,
// claim+verified otherwise) inside a single transaction: the obligation and
// optional group are bound first, then the insert/upgrade is decided by the
// content digest so retries never fork the durable record. claim is the
// SUBMITTED claim (the idempotency identity); bound is the outcome Bind
// checks (the derived outcome on a verified write). acceptance is the
// integrity record of a verified write and lives only in its own column.
func (s *PostgresStore) recordOutcomeTx(ctx context.Context, claim, bound verifyapi.VerificationOutcome, payload *verifiedPayload, acceptance *verifyapi.AcceptanceRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := claim.Validate(); err != nil {
		return err
	}
	if err := bound.Validate(); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("verifystore: begin record outcome: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var obJSON []byte
	var obScope SubjectScope
	err = tx.QueryRow(ctx, `
		SELECT payload, subject, authority_namespace, tenant_id, project_id, repository_id
		FROM verification_obligations WHERE obligation_id = $1`, claim.ObligationID).
		Scan(&obJSON, &obScope.Subject, &obScope.AuthorityNamespace, &obScope.TenantID, &obScope.ProjectID, &obScope.RepositoryID)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: obligation %q", verifyapi.ErrNotFound, claim.ObligationID)
	}
	if err != nil {
		return fmt.Errorf("verifystore: load obligation %q: %w", claim.ObligationID, err)
	}
	var ob verifyapi.VerificationObligation
	if err := json.Unmarshal(obJSON, &ob); err != nil {
		return fmt.Errorf("verifystore: decode obligation %q: %w", claim.ObligationID, err)
	}
	// Columns are authoritative (P7): bind against the obligation with its
	// subject/scope restored from the normalized columns.
	ob = ApplyScope(ob, obScope)
	if err := verifyapi.Bind(ob, bound, s.verifyNow()); err != nil {
		return err
	}
	if bound.Resources.Speculative {
		g, err := loadGroupTx(ctx, tx, bound.Resources.VerificationGroupID)
		if err != nil {
			return err
		}
		if err := verifyapi.BindGroup(g, &ob, bound); err != nil {
			return err
		}
	}

	// Measured facts are substrate-derived/attested, never caller-asserted.
	// The claim column keeps the SUBMITTED claim as-is (Model A) with only
	// the derived Measured subset filled; the idempotency digest is the
	// claim's, so a verified write upgrades a claim-only row instead of
	// conflicting on evidence-derived id differences.
	stored := claim
	stored.Resources.Measured = verifyapi.DeriveMeasuredFacts(claim, nil)
	digest, err := ClaimContentDigest(stored)
	if err != nil {
		return err
	}
	claimJSON, err := canonicalJSON(stored)
	if err != nil {
		return err
	}
	var evidenceJSON []byte
	var acceptanceJSON []byte
	if payload != nil {
		evidenceJSON, err = canonicalJSON(*payload)
		if err != nil {
			return err
		}
		if acceptance == nil {
			return fmt.Errorf("%w: verified write requires an acceptance record", verifyapi.ErrAcceptance)
		}
		acceptanceJSON, err = canonicalJSON(*acceptance)
		if err != nil {
			return err
		}
	}

	// Write-all (P7): the index columns are denormalized from the CLAIM
	// payload (the JSONB written here), and the subject/scope columns from
	// the obligation loaded above — both derived from the same values as
	// the JSONB in this one statement, so the columns and the payload
	// cannot diverge after any insert or upgrade.
	idx := ClaimIndexOf(stored)
	sc := ScopeOfObligation(ob)

	// Insert, or upgrade an equivalent claim/row. The DO UPDATE predicate
	// is the idempotency gate: it only fires when the content digest
	// matches, a verified write never downgrades is_verified, and a verified
	// write never overwrites an already-verified row whose acceptance
	// identity (OutcomeDigest + VerifiedEvidenceDigest) differs — that is a
	// different derivation under the same claim and is refused with
	// ErrExists rather than silently replacing the sealed record.
	var written string
	if payload != nil {
		err = tx.QueryRow(ctx, `
			INSERT INTO verification_outcomes (
				verification_id, obligation_id, is_verified, content_digest,
				claim, evidence, acceptance, group_id, candidate_id, started_at, completed_at, verified_at,
				authority_namespace, tenant_id, project_id, repository_id)
			VALUES ($1, $2, TRUE, $3, $4, $5, $6, $7, $8, $9, $10, now(), $11, $12, $13, $14)
			ON CONFLICT (verification_id) DO UPDATE SET
				is_verified = TRUE,
				claim = EXCLUDED.claim,
				evidence = EXCLUDED.evidence,
				acceptance = EXCLUDED.acceptance,
				group_id = EXCLUDED.group_id,
				candidate_id = EXCLUDED.candidate_id,
				started_at = EXCLUDED.started_at,
				completed_at = EXCLUDED.completed_at,
				authority_namespace = EXCLUDED.authority_namespace,
				tenant_id = EXCLUDED.tenant_id,
				project_id = EXCLUDED.project_id,
				repository_id = EXCLUDED.repository_id,
				verified_at = COALESCE(verification_outcomes.verified_at, now())
			WHERE verification_outcomes.content_digest = EXCLUDED.content_digest
				AND (
					verification_outcomes.is_verified = FALSE
					OR (
						verification_outcomes.acceptance->>'outcome_digest' = $15
						AND verification_outcomes.acceptance->>'verified_evidence_digest' = $16
					)
				)
			RETURNING verification_id`,
			claim.VerificationID, claim.ObligationID, digest, claimJSON, evidenceJSON, acceptanceJSON,
			idx.GroupID, idx.CandidateID, idx.StartedAt, idx.CompletedAt,
			sc.AuthorityNamespace, sc.TenantID, sc.ProjectID, sc.RepositoryID,
			string(acceptance.OutcomeDigest), string(acceptance.VerifiedEvidenceDigest)).Scan(&written)
	} else {
		err = tx.QueryRow(ctx, `
			INSERT INTO verification_outcomes (
				verification_id, obligation_id, is_verified, content_digest,
				claim, evidence, group_id, candidate_id, started_at, completed_at,
				authority_namespace, tenant_id, project_id, repository_id)
			VALUES ($1, $2, FALSE, $3, $4, NULL, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (verification_id) DO UPDATE SET
				claim = EXCLUDED.claim,
				group_id = EXCLUDED.group_id,
				candidate_id = EXCLUDED.candidate_id,
				started_at = EXCLUDED.started_at,
				completed_at = EXCLUDED.completed_at,
				authority_namespace = EXCLUDED.authority_namespace,
				tenant_id = EXCLUDED.tenant_id,
				project_id = EXCLUDED.project_id,
				repository_id = EXCLUDED.repository_id
			WHERE verification_outcomes.content_digest = EXCLUDED.content_digest
				AND verification_outcomes.is_verified = FALSE
			RETURNING verification_id`,
			claim.VerificationID, claim.ObligationID, digest, claimJSON,
			idx.GroupID, idx.CandidateID, idx.StartedAt, idx.CompletedAt,
			sc.AuthorityNamespace, sc.TenantID, sc.ProjectID, sc.RepositoryID).Scan(&written)
	}
	if err == nil && written != "" {
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("verifystore: commit record outcome %q: %w", claim.VerificationID, err)
		}
		return nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("verifystore: record outcome %q: %w", claim.VerificationID, err)
	}

	// Conflict path: the row exists with this verification id. Identical
	// claim content is the already-accepted submission (a verified row
	// answering a claim retry). A verified write against an already-verified
	// row must also agree on the acceptance identity — a different
	// OutcomeDigest / VerifiedEvidenceDigest under the same claim is a
	// different derivation and is refused with ErrExists.
	var gotDigest string
	var gotVerified bool
	var gotAcceptance []byte
	err = tx.QueryRow(ctx,
		`SELECT content_digest, is_verified, acceptance FROM verification_outcomes WHERE verification_id = $1`,
		claim.VerificationID).Scan(&gotDigest, &gotVerified, &gotAcceptance)
	if err != nil {
		return fmt.Errorf("verifystore: read outcome %q after conflict: %w", claim.VerificationID, err)
	}
	if gotDigest != digest {
		return fmt.Errorf("%w: outcome %q", verifyapi.ErrExists, claim.VerificationID)
	}
	if gotVerified && payload != nil {
		var gotAcc verifyapi.AcceptanceRecord
		if len(gotAcceptance) > 0 {
			if err := json.Unmarshal(gotAcceptance, &gotAcc); err != nil {
				return fmt.Errorf("verifystore: decode acceptance %q after conflict: %w", claim.VerificationID, err)
			}
		}
		if gotAcc.OutcomeDigest != acceptance.OutcomeDigest ||
			gotAcc.VerifiedEvidenceDigest != acceptance.VerifiedEvidenceDigest {
			return fmt.Errorf("%w: outcome %q", verifyapi.ErrExists, claim.VerificationID)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("verifystore: commit record outcome %q: %w", claim.VerificationID, err)
	}
	return nil
}

// loadGroupTx fetches a speculative group inside an open transaction.
func loadGroupTx(ctx context.Context, tx pgx.Tx, id string) (verifyapi.SpeculativeGroup, error) {
	if id == "" {
		return verifyapi.SpeculativeGroup{}, fmt.Errorf("%w: group %q", verifyapi.ErrGroupBinding, id)
	}
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT payload FROM verification_groups WHERE verification_group_id = $1`, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return verifyapi.SpeculativeGroup{}, fmt.Errorf("%w: group %q", verifyapi.ErrGroupBinding, id)
	}
	if err != nil {
		return verifyapi.SpeculativeGroup{}, fmt.Errorf("verifystore: load group %q: %w", id, err)
	}
	var g verifyapi.SpeculativeGroup
	if err := json.Unmarshal(raw, &g); err != nil {
		return verifyapi.SpeculativeGroup{}, fmt.Errorf("verifystore: decode group %q: %w", id, err)
	}
	return g, nil
}

// GetObligation fetches a stored obligation by id. The normalized
// subject/scope columns are authoritative (P7): the returned obligation has
// its Subject and SubjectRef restored from the columns, so a tampered
// payload cannot present a different authority subject than the row indexes.
func (s *PostgresStore) GetObligation(ctx context.Context, id string) (verifyapi.VerificationObligation, error) {
	if err := ctx.Err(); err != nil {
		return verifyapi.VerificationObligation{}, err
	}
	var raw []byte
	var sc SubjectScope
	err := s.pool.QueryRow(ctx, `
		SELECT payload, subject, authority_namespace, tenant_id, project_id, repository_id
		FROM verification_obligations WHERE obligation_id = $1`, id).
		Scan(&raw, &sc.Subject, &sc.AuthorityNamespace, &sc.TenantID, &sc.ProjectID, &sc.RepositoryID)
	if errors.Is(err, pgx.ErrNoRows) {
		return verifyapi.VerificationObligation{}, fmt.Errorf("%w: obligation %q", verifyapi.ErrNotFound, id)
	}
	if err != nil {
		return verifyapi.VerificationObligation{}, fmt.Errorf("verifystore: get obligation %q: %w", id, err)
	}
	var o verifyapi.VerificationObligation
	if err := json.Unmarshal(raw, &o); err != nil {
		return verifyapi.VerificationObligation{}, fmt.Errorf("verifystore: decode obligation %q: %w", id, err)
	}
	return ApplyScope(o, sc), nil
}

// GetOutcome fetches any stored outcome (claim or verified) by id. It is
// not proof of verification.
func (s *PostgresStore) GetOutcome(ctx context.Context, id string) (verifyapi.VerificationOutcome, error) {
	if err := ctx.Err(); err != nil {
		return verifyapi.VerificationOutcome{}, err
	}
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT claim FROM verification_outcomes WHERE verification_id = $1`, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return verifyapi.VerificationOutcome{}, fmt.Errorf("%w: outcome %q", verifyapi.ErrNotFound, id)
	}
	if err != nil {
		return verifyapi.VerificationOutcome{}, fmt.Errorf("verifystore: get outcome %q: %w", id, err)
	}
	var v verifyapi.VerificationOutcome
	if err := json.Unmarshal(raw, &v); err != nil {
		return verifyapi.VerificationOutcome{}, fmt.Errorf("verifystore: decode outcome %q: %w", id, err)
	}
	return v, nil
}

// QueryOutcome fetches the authoritative verified record. A claim-only id
// returns verifyapi.ErrUnverified; an unknown id returns verifyapi.ErrNotFound.
//
// P1-B integrity path: a database row is NEVER authority on its own. The
// stored acceptance record must re-check — canonical digests of the exact
// (obligation, outcome, evidence) triple plus the acceptance MAC under the
// store's acceptance key — before a seal is restored. An unsigned row, a
// tampered payload, a flipped verified flag or a wrong MAC can never produce
// ProvenPass.
func (s *PostgresStore) QueryOutcome(ctx context.Context, id string) (verifyapi.VerifiedOutcome, error) {
	if err := ctx.Err(); err != nil {
		return verifyapi.VerifiedOutcome{}, err
	}
	var claimJSON, evidenceJSON, acceptanceJSON []byte
	var isVerified bool
	var obligationID string
	err := s.pool.QueryRow(ctx,
		`SELECT obligation_id, claim, evidence, acceptance, is_verified FROM verification_outcomes WHERE verification_id = $1`,
		id).Scan(&obligationID, &claimJSON, &evidenceJSON, &acceptanceJSON, &isVerified)
	if errors.Is(err, pgx.ErrNoRows) {
		return verifyapi.VerifiedOutcome{}, fmt.Errorf("%w: outcome %q", verifyapi.ErrNotFound, id)
	}
	if err != nil {
		return verifyapi.VerifiedOutcome{}, fmt.Errorf("verifystore: query outcome %q: %w", id, err)
	}
	if !isVerified || evidenceJSON == nil {
		return verifyapi.VerifiedOutcome{}, fmt.Errorf("%w: outcome %q is an unverified claim", verifyapi.ErrUnverified, id)
	}
	if len(acceptanceJSON) == 0 {
		return verifyapi.VerifiedOutcome{}, fmt.Errorf("%w: outcome %q has no acceptance record", verifyapi.ErrAcceptance, id)
	}
	if s.acceptanceKeyring == nil {
		return verifyapi.VerifiedOutcome{}, fmt.Errorf("%w: store has no acceptance keyring; refusing to restore authority from a row", verifyapi.ErrAcceptance)
	}
	// Model A: the claim column is the SUBMITTED claim; the evidence column
	// carries the derived outcome plus the resolved evidence.
	var submitted verifyapi.VerificationOutcome
	if err := json.Unmarshal(claimJSON, &submitted); err != nil {
		return verifyapi.VerifiedOutcome{}, fmt.Errorf("verifystore: decode outcome %q: %w", id, err)
	}
	var payload verifiedPayload
	if err := json.Unmarshal(evidenceJSON, &payload); err != nil {
		return verifyapi.VerifiedOutcome{}, fmt.Errorf("verifystore: decode evidence %q: %w", id, err)
	}
	var acceptance verifyapi.AcceptanceRecord
	if err := json.Unmarshal(acceptanceJSON, &acceptance); err != nil {
		return verifyapi.VerifiedOutcome{}, fmt.Errorf("verifystore: decode acceptance %q: %w", id, err)
	}
	ob, err := s.GetObligation(ctx, obligationID)
	if err != nil {
		return verifyapi.VerifiedOutcome{}, err
	}
	// The seal cannot be serialized; restore it ONLY through the acceptance
	// integrity check (verifyapi.RestoreVerifiedOutcome). The keyring
	// resolves the record's KeyID so a record sealed under a rotated-out
	// key still verifies while that key remains in the keyring.
	var recipe *verifyapi.Recipe
	if ob.RecipeDigest != "" {
		if s.recipes == nil {
			return verifyapi.DerivedVerifiedOutcome{}, fmt.Errorf("%w: store has no recipe registry; cannot restore a recipe-bound record", verifyapi.ErrBinding)
		}
		r, err := s.recipes.ByDigest(ob.RecipeDigest)
		if err != nil {
			return verifyapi.DerivedVerifiedOutcome{}, err
		}
		recipe = &r
	}
	return verifyapi.RestoreVerifiedOutcomeWithRecipe(verifyapi.PersistedVerified{
		Obligation:     ob,
		SubmittedClaim: submitted,
		Outcome:        payload.Outcome,
		Evidence:       payload.Evidence,
		Acceptance:     acceptance,
	}, nil, s.acceptanceKeyring, recipe)
}

// OutcomesForObligation lists every recorded outcome answering the
// obligation, ordered by verification id.
func (s *PostgresStore) OutcomesForObligation(ctx context.Context, obligationID string) ([]verifyapi.VerificationOutcome, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx,
		`SELECT claim FROM verification_outcomes WHERE obligation_id = $1 ORDER BY verification_id`,
		obligationID)
	if err != nil {
		return nil, fmt.Errorf("verifystore: list outcomes for obligation %q: %w", obligationID, err)
	}
	defer rows.Close()
	out := []verifyapi.VerificationOutcome{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("verifystore: scan outcome for obligation %q: %w", obligationID, err)
		}
		var v verifyapi.VerificationOutcome
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("verifystore: decode outcome for obligation %q: %w", obligationID, err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("verifystore: list outcomes for obligation %q: %w", obligationID, err)
	}
	return out, nil
}

// RegisterGroup records a speculative group. Idempotent on
// VerificationGroupID when the candidate set is identical.
func (s *PostgresStore) RegisterGroup(ctx context.Context, g verifyapi.SpeculativeGroup) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := g.Validate(); err != nil {
		return err
	}
	digest, err := GroupContentDigest(g)
	if err != nil {
		return err
	}
	payload, err := canonicalJSON(g)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO verification_groups (verification_group_id, content_digest, payload)
		VALUES ($1, $2, $3)`,
		g.VerificationGroupID, digest, payload)
	if err == nil {
		return nil
	}
	if !isUniqueViolation(err) {
		return fmt.Errorf("verifystore: register group %q: %w", g.VerificationGroupID, err)
	}
	return s.idempotentConflict(ctx,
		`SELECT content_digest FROM verification_groups WHERE verification_group_id = $1`,
		g.VerificationGroupID, digest, "group", g.VerificationGroupID)
}

// GetGroup fetches a stored speculative group by id.
func (s *PostgresStore) GetGroup(ctx context.Context, id string) (verifyapi.SpeculativeGroup, error) {
	if err := ctx.Err(); err != nil {
		return verifyapi.SpeculativeGroup{}, err
	}
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT payload FROM verification_groups WHERE verification_group_id = $1`, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return verifyapi.SpeculativeGroup{}, fmt.Errorf("%w: group %q", verifyapi.ErrNotFound, id)
	}
	if err != nil {
		return verifyapi.SpeculativeGroup{}, fmt.Errorf("verifystore: get group %q: %w", id, err)
	}
	var g verifyapi.SpeculativeGroup
	if err := json.Unmarshal(raw, &g); err != nil {
		return verifyapi.SpeculativeGroup{}, fmt.Errorf("verifystore: decode group %q: %w", id, err)
	}
	return g, nil
}

// groupAttempt is one recorded outcome of a speculative-group candidate,
// tagged with whether the row carries a sealed derived record.
type groupAttempt struct {
	outcome  verifyapi.VerificationOutcome
	verified bool
}

// betterAttempt is the canonical-attempt order documented on
// verifyapi.CompareGroup: a verified attempt always outranks a claim, then
// latest completed_at wins, ties break by ascending verification id.
func betterAttempt(a, b groupAttempt) bool {
	if a.verified != b.verified {
		return a.verified
	}
	if !a.outcome.CompletedAt.Equal(b.outcome.CompletedAt) {
		return a.outcome.CompletedAt.After(b.outcome.CompletedAt)
	}
	return a.outcome.VerificationID < b.outcome.VerificationID
}

// claimAuthoritativeOutcome projects a caller claim onto the outcome a
// consumer may treat as the row's standing: a claim never projects to a
// plain pass (claimed pass → partial).
func claimAuthoritativeOutcome(claimed verifyapi.Outcome) verifyapi.Outcome {
	if claimed == verifyapi.OutcomePass {
		return verifyapi.OutcomePartial
	}
	return claimed
}

// CompareGroup lines up the resource facts of a speculative group. Rows are
// ordered by candidate id; one canonical attempt per candidate (verified
// outranks claim, then latest completed_at). When a row is verified, the
// DERIVED outcome from the evidence payload is used — never the claim's
// self-reported Outcome. Claim rows carry Authority "claim" and are never
// projected into a plain pass.
func (s *PostgresStore) CompareGroup(ctx context.Context, groupID string) (verifyapi.GroupComparison, error) {
	if err := ctx.Err(); err != nil {
		return verifyapi.GroupComparison{}, err
	}
	g, err := s.GetGroup(ctx, groupID)
	if err != nil {
		return verifyapi.GroupComparison{}, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT claim, evidence, is_verified FROM verification_outcomes
		WHERE group_id = $1
		ORDER BY verification_id`,
		groupID)
	if err != nil {
		return verifyapi.GroupComparison{}, fmt.Errorf("verifystore: compare group %q: %w", groupID, err)
	}
	defer rows.Close()
	byCandidate := map[string]groupAttempt{}
	for rows.Next() {
		var claimRaw, evidenceRaw []byte
		var isVerified bool
		if err := rows.Scan(&claimRaw, &evidenceRaw, &isVerified); err != nil {
			return verifyapi.GroupComparison{}, fmt.Errorf("verifystore: scan group outcome %q: %w", groupID, err)
		}
		var claim verifyapi.VerificationOutcome
		if err := json.Unmarshal(claimRaw, &claim); err != nil {
			return verifyapi.GroupComparison{}, fmt.Errorf("verifystore: decode group outcome %q: %w", groupID, err)
		}
		attempt := groupAttempt{outcome: claim, verified: false}
		if isVerified {
			// Read the DERIVED outcome from the evidence payload; a
			// verified row whose payload is missing or undecodable fails
			// closed rather than falling back to the claim's Outcome.
			if len(evidenceRaw) == 0 {
				return verifyapi.GroupComparison{}, fmt.Errorf("verifystore: group outcome %q is verified but has no evidence payload", claim.VerificationID)
			}
			var payload verifiedPayload
			if err := json.Unmarshal(evidenceRaw, &payload); err != nil {
				return verifyapi.GroupComparison{}, fmt.Errorf("verifystore: decode group evidence %q: %w", groupID, err)
			}
			attempt.outcome = payload.Outcome
			attempt.verified = true
		}
		// Fail closed on rows that are not comparable to this group
		// (BindGroup is the single comparability rule).
		if err := verifyapi.BindGroup(g, nil, attempt.outcome); err != nil {
			return verifyapi.GroupComparison{}, err
		}
		prev, exists := byCandidate[attempt.outcome.Resources.CandidateID]
		if !exists || betterAttempt(attempt, prev) {
			byCandidate[attempt.outcome.Resources.CandidateID] = attempt
		}
	}
	if err := rows.Err(); err != nil {
		return verifyapi.GroupComparison{}, fmt.Errorf("verifystore: compare group %q: %w", groupID, err)
	}

	ids := make([]string, 0, len(g.CandidateDigests))
	for id := range g.CandidateDigests {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	candidates := make([]verifyapi.CandidateFacts, 0, len(ids))
	for _, id := range ids {
		row := verifyapi.CandidateFacts{
			CandidateID:     id,
			CandidateDigest: g.CandidateDigests[id],
		}
		if att, ok := byCandidate[id]; ok {
			row.VerificationID = att.outcome.VerificationID
			row.Resources = att.outcome.Resources
			if att.verified {
				row.Authority = verifyapi.RowAuthorityVerified
				row.Outcome = att.outcome.Outcome
			} else {
				row.Authority = verifyapi.RowAuthorityClaim
				row.Outcome = claimAuthoritativeOutcome(att.outcome.Outcome)
			}
		}
		candidates = append(candidates, row)
	}
	return verifyapi.GroupComparison{
		VerificationGroupID: g.VerificationGroupID,
		BaseSnapshotDigest:  g.BaseSnapshotDigest,
		SchemaVersion:       verifyapi.SchemaVersion,
		Candidates:          candidates,
	}, nil
}
