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
// digests, claim/verified flags, group/candidate dimensions, timestamps)
// are real relational columns; the full wire structs live in JSONB payloads
// so reads round-trip byte-faithful claim identities.
//
// The schema is created by internal/storage/migrations (0057+) and applied
// by storage.PostgresStore.Migrate; this package only owns the read/write
// contract.
type PostgresStore struct {
	pool *pgxpool.Pool
	// now reads the store clock for freshness binding at record time.
	// Production leaves it nil (time.Now); tests may override it.
	now func() time.Time
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
// time and never participate in identity) and timestamps UTC-normalized.
func ClaimContentDigest(v verifyapi.VerificationOutcome) (string, error) {
	n := v
	n.StartedAt = utcTime(n.StartedAt)
	n.CompletedAt = utcTime(n.CompletedAt)
	n.Resources.Measured = nil
	raw, err := canonicalJSON(n)
	if err != nil {
		return "", err
	}
	return contentDigest(raw), nil
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
	_, err = s.pool.Exec(ctx, `
		INSERT INTO verification_obligations (obligation_id, content_digest, payload)
		VALUES ($1, $2, $3)`,
		o.ObligationID, digest, payload)
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
	return s.recordOutcomeTx(ctx, v, nil)
}

// RecordVerifiedOutcome records a verifier-produced VerifiedOutcome as the
// authoritative result. VerificationID is the idempotency key; an identical
// resubmit (or an upgrade of an equivalent claim) is a no-op success, a
// different submission under the same key is verifyapi.ErrExists. An
// unsealed value is refused with verifyapi.ErrUnverified.
func (s *PostgresStore) RecordVerifiedOutcome(ctx context.Context, v verifyapi.VerifiedOutcome) error {
	if !v.Sealed() {
		return fmt.Errorf("%w: RecordVerifiedOutcome requires a verifier-produced record", verifyapi.ErrUnverified)
	}
	evidence := v.Evidence
	return s.recordOutcomeTx(ctx, v.Outcome, &evidence)
}

// recordOutcomeTx writes one outcome row (claim-only when evidence is nil,
// claim+verified otherwise) inside a single transaction: the obligation and
// optional group are bound first, then the insert/upgrade is decided by the
// content digest so retries never fork the durable record.
func (s *PostgresStore) recordOutcomeTx(ctx context.Context, v verifyapi.VerificationOutcome, evidence *verifyapi.VerifiedEvidence) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := v.Validate(); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("verifystore: begin record outcome: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var obJSON []byte
	err = tx.QueryRow(ctx, `SELECT payload FROM verification_obligations WHERE obligation_id = $1`, v.ObligationID).Scan(&obJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: obligation %q", verifyapi.ErrNotFound, v.ObligationID)
	}
	if err != nil {
		return fmt.Errorf("verifystore: load obligation %q: %w", v.ObligationID, err)
	}
	var ob verifyapi.VerificationObligation
	if err := json.Unmarshal(obJSON, &ob); err != nil {
		return fmt.Errorf("verifystore: decode obligation %q: %w", v.ObligationID, err)
	}
	if err := verifyapi.Bind(ob, v, s.verifyNow()); err != nil {
		return err
	}
	if v.Resources.Speculative {
		g, err := loadGroupTx(ctx, tx, v.Resources.VerificationGroupID)
		if err != nil {
			return err
		}
		if err := verifyapi.BindGroup(g, v); err != nil {
			return err
		}
	}

	// Measured facts are substrate-derived/attested, never caller-asserted.
	stored := v
	var attested *verifyapi.AttestedResourceFacts
	if evidence != nil {
		attested = evidence.Attested
	}
	stored.Resources.Measured = verifyapi.DeriveMeasuredFacts(stored, attested)
	digest, err := ClaimContentDigest(stored)
	if err != nil {
		return err
	}
	claimJSON, err := canonicalJSON(stored)
	if err != nil {
		return err
	}
	var evidenceJSON []byte
	if evidence != nil {
		evidenceJSON, err = canonicalJSON(*evidence)
		if err != nil {
			return err
		}
	}

	// Insert, or upgrade an equivalent claim/row. The DO UPDATE predicate
	// is the idempotency gate: it only fires when the content digest
	// matches, and a verified write never downgrades is_verified.
	var written string
	if evidence != nil {
		err = tx.QueryRow(ctx, `
			INSERT INTO verification_outcomes (
				verification_id, obligation_id, is_verified, content_digest,
				claim, evidence, group_id, candidate_id, started_at, completed_at, verified_at)
			VALUES ($1, $2, TRUE, $3, $4, $5, $6, $7, $8, $9, now())
			ON CONFLICT (verification_id) DO UPDATE SET
				is_verified = TRUE,
				claim = EXCLUDED.claim,
				evidence = EXCLUDED.evidence,
				verified_at = COALESCE(verification_outcomes.verified_at, now())
			WHERE verification_outcomes.content_digest = EXCLUDED.content_digest
			RETURNING verification_id`,
			v.VerificationID, v.ObligationID, digest, claimJSON, evidenceJSON,
			v.Resources.VerificationGroupID, v.Resources.CandidateID,
			utcTime(stored.StartedAt), utcTime(stored.CompletedAt)).Scan(&written)
	} else {
		err = tx.QueryRow(ctx, `
			INSERT INTO verification_outcomes (
				verification_id, obligation_id, is_verified, content_digest,
				claim, evidence, group_id, candidate_id, started_at, completed_at)
			VALUES ($1, $2, FALSE, $3, $4, NULL, $5, $6, $7, $8)
			ON CONFLICT (verification_id) DO UPDATE SET
				claim = EXCLUDED.claim
			WHERE verification_outcomes.content_digest = EXCLUDED.content_digest
				AND verification_outcomes.is_verified = FALSE
			RETURNING verification_id`,
			v.VerificationID, v.ObligationID, digest, claimJSON,
			v.Resources.VerificationGroupID, v.Resources.CandidateID,
			utcTime(stored.StartedAt), utcTime(stored.CompletedAt)).Scan(&written)
	}
	if err == nil && written != "" {
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("verifystore: commit record outcome %q: %w", v.VerificationID, err)
		}
		return nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("verifystore: record outcome %q: %w", v.VerificationID, err)
	}

	// Conflict path: the row exists with this verification id. Identical
	// content is the already-accepted submission (a verified row answering
	// a claim retry, or a replay of a verified write whose DO UPDATE was
	// skipped because it was already verified).
	var gotDigest string
	err = tx.QueryRow(ctx, `SELECT content_digest FROM verification_outcomes WHERE verification_id = $1`,
		v.VerificationID).Scan(&gotDigest)
	if err != nil {
		return fmt.Errorf("verifystore: read outcome %q after conflict: %w", v.VerificationID, err)
	}
	if gotDigest == digest {
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("verifystore: commit record outcome %q: %w", v.VerificationID, err)
		}
		return nil
	}
	return fmt.Errorf("%w: outcome %q", verifyapi.ErrExists, v.VerificationID)
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

// GetObligation fetches a stored obligation by id.
func (s *PostgresStore) GetObligation(ctx context.Context, id string) (verifyapi.VerificationObligation, error) {
	if err := ctx.Err(); err != nil {
		return verifyapi.VerificationObligation{}, err
	}
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT payload FROM verification_obligations WHERE obligation_id = $1`, id).Scan(&raw)
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
	return o, nil
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
func (s *PostgresStore) QueryOutcome(ctx context.Context, id string) (verifyapi.VerifiedOutcome, error) {
	if err := ctx.Err(); err != nil {
		return verifyapi.VerifiedOutcome{}, err
	}
	var claimJSON, evidenceJSON []byte
	var isVerified bool
	err := s.pool.QueryRow(ctx,
		`SELECT claim, evidence, is_verified FROM verification_outcomes WHERE verification_id = $1`,
		id).Scan(&claimJSON, &evidenceJSON, &isVerified)
	if errors.Is(err, pgx.ErrNoRows) {
		return verifyapi.VerifiedOutcome{}, fmt.Errorf("%w: outcome %q", verifyapi.ErrNotFound, id)
	}
	if err != nil {
		return verifyapi.VerifiedOutcome{}, fmt.Errorf("verifystore: query outcome %q: %w", id, err)
	}
	if !isVerified || evidenceJSON == nil {
		return verifyapi.VerifiedOutcome{}, fmt.Errorf("%w: outcome %q is an unverified claim", verifyapi.ErrUnverified, id)
	}
	var claim verifyapi.VerificationOutcome
	if err := json.Unmarshal(claimJSON, &claim); err != nil {
		return verifyapi.VerifiedOutcome{}, fmt.Errorf("verifystore: decode outcome %q: %w", id, err)
	}
	var evidence verifyapi.VerifiedEvidence
	if err := json.Unmarshal(evidenceJSON, &evidence); err != nil {
		return verifyapi.VerifiedOutcome{}, fmt.Errorf("verifystore: decode evidence %q: %w", id, err)
	}
	// The seal cannot be serialized; restore it from the accepted row.
	return verifyapi.RestoreVerifiedOutcome(claim, evidence)
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

// betterAttempt is the canonical-attempt order documented on
// verifyapi.CompareGroup: latest completed_at wins, ties break by ascending
// verification id.
func betterAttempt(a, b verifyapi.VerificationOutcome) bool {
	if !a.CompletedAt.Equal(b.CompletedAt) {
		return a.CompletedAt.After(b.CompletedAt)
	}
	return a.VerificationID < b.VerificationID
}

// CompareGroup lines up the resource facts of a speculative group. Rows are
// ordered by candidate id; one canonical attempt per candidate.
func (s *PostgresStore) CompareGroup(ctx context.Context, groupID string) (verifyapi.GroupComparison, error) {
	if err := ctx.Err(); err != nil {
		return verifyapi.GroupComparison{}, err
	}
	g, err := s.GetGroup(ctx, groupID)
	if err != nil {
		return verifyapi.GroupComparison{}, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT claim FROM verification_outcomes
		WHERE group_id = $1
		ORDER BY verification_id`,
		groupID)
	if err != nil {
		return verifyapi.GroupComparison{}, fmt.Errorf("verifystore: compare group %q: %w", groupID, err)
	}
	defer rows.Close()
	byCandidate := map[string]verifyapi.VerificationOutcome{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return verifyapi.GroupComparison{}, fmt.Errorf("verifystore: scan group outcome %q: %w", groupID, err)
		}
		var v verifyapi.VerificationOutcome
		if err := json.Unmarshal(raw, &v); err != nil {
			return verifyapi.GroupComparison{}, fmt.Errorf("verifystore: decode group outcome %q: %w", groupID, err)
		}
		// Fail closed on rows that are not comparable to this group
		// (BindGroup is the single comparability rule).
		if err := verifyapi.BindGroup(g, v); err != nil {
			return verifyapi.GroupComparison{}, err
		}
		prev, exists := byCandidate[v.Resources.CandidateID]
		if !exists || betterAttempt(v, prev) {
			byCandidate[v.Resources.CandidateID] = v
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
		if v, ok := byCandidate[id]; ok {
			row.VerificationID = v.VerificationID
			row.Outcome = v.Outcome
			row.Resources = v.Resources
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
