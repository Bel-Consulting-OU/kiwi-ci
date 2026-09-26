package storage

import (
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

// OIDCIssuance is one candidate job id_token issuance: the credentials and
// coordinates the handler AUTHENTICATED from its preliminary read and the
// candidate JWT it already signed. It is the request of the commit-time
// authority (LeaseOIDCIssueStore.CommitOIDCIssuance): the store re-evaluates
// the whole issuance predicate against the LOCKED job — status, lease
// holder/generation/token hash, lease expiry, trust, id_token permission and
// the audience allowlist — and cross-checks the candidate claims against the
// locked identity before it appends the oidc.issued audit row and commits.
//
// Claims carries the identity-bearing JWT claims as strings (see the
// OIDCClaim* keys) so the commit can prove the signed token describes the
// LOCKED job, not the possibly stale record the handler read.
type OIDCIssuance struct {
	JobID           string
	RunnerID        string
	LeaseGeneration int64
	LeaseTokenHash  []byte
	Audience        string
	KID             string
	JTI             string
	IssuedAt        time.Time
	ExpiresAt       time.Time
	Claims          map[string]string
}

// Claim keys the commit-time identity binding understands. They are exported
// so the handler builds the candidate map with the same spelling the storage
// predicate validates.
const (
	OIDCClaimJobID        = "job_id"
	OIDCClaimRunID        = "run_id"
	OIDCClaimJob          = "job"
	OIDCClaimRepository   = "repository"
	OIDCClaimRepositoryID = "repository_id"
	OIDCClaimTrusted      = "trusted"
	OIDCClaimAudience     = "aud"
)

// LockedOIDCIdentity is the authoritative identity of the job row the
// issuance transaction locked: every field comes from the locked row (or, in
// memory/fs mode, from the job mutated under the store/server lock), never
// from the credentials or claims the caller presented.
type LockedOIDCIdentity struct {
	JobID  string
	RunID  string
	JobKey string
	RepoID string // canonical resolved identity (PolicyRepoID first)
	// PolicyRepoID/RepoURL/RepoFullName are the raw locked repository fields
	// the identity was resolved from; RepoFullName is the human-readable
	// claim value.
	PolicyRepoID     string
	RepoURL          string
	RepoFullName     string
	Trusted          bool
	OIDCAllowed      bool
	AllowedAudiences []string
	Status           model.Status
	LeaseRunnerID    string
	LeaseGeneration  int64
	LeaseTokenHash   []byte
	LeaseExpiresAt   time.Time
}

// Typed commit-time refusals. The handler maps them onto HTTP statuses:
// audience/trust/permission refusals are 403, every lease/identity refusal is
// 409 (the same semantics as a stale lease at request start), and a vanished
// job is ErrNotFound (404). The error taxonomy is what lets the handler answer
// precisely without re-reading anything itself.
var (
	// ErrOIDCIssuanceRevoked reports that the job is no longer running under
	// any lease: it was cancelled, completed, failed or otherwise left the
	// running state between authentication and commit.
	ErrOIDCIssuanceRevoked = errors.New("storage: OIDC issuance refused: job is no longer running")
	// ErrOIDCIssuanceRunner reports that the lease holder changed.
	ErrOIDCIssuanceRunner = errors.New("storage: OIDC issuance refused: lease holder changed")
	// ErrOIDCIssuanceGeneration reports that the lease generation changed (a
	// replacement lease was acquired).
	ErrOIDCIssuanceGeneration = errors.New("storage: OIDC issuance refused: lease generation changed")
	// ErrOIDCIssuanceToken reports that the lease token hash changed.
	ErrOIDCIssuanceToken = errors.New("storage: OIDC issuance refused: lease token changed")
	// ErrOIDCIssuanceExpired reports that the lease had expired by IssuedAt.
	ErrOIDCIssuanceExpired = errors.New("storage: OIDC issuance refused: lease expired")
	// ErrOIDCIssuanceUntrusted reports that the locked job is untrusted.
	ErrOIDCIssuanceUntrusted = errors.New("storage: OIDC issuance refused: job is untrusted")
	// ErrOIDCIssuanceNotAllowed reports that the locked job does not carry the
	// permissions.id_token grant.
	ErrOIDCIssuanceNotAllowed = errors.New("storage: OIDC issuance refused: job lacks the id_token permission")
	// ErrOIDCIssuanceAudience reports that the requested audience is not in
	// the locked job's allowlist.
	ErrOIDCIssuanceAudience = errors.New("storage: OIDC issuance refused: audience not allowed")
	// ErrOIDCIssuanceIdentity reports that the candidate claims disagree with
	// the locked job's identity (job/run/key/repository/trust/audience). The
	// already-signed JWT must be discarded.
	ErrOIDCIssuanceIdentity = errors.New("storage: OIDC issuance refused: claim identity mismatch")
	// ErrOIDCIssuanceInvalid reports a malformed request (missing coordinates,
	// empty token hash, empty audience/kid/jti or a non-positive lifetime).
	ErrOIDCIssuanceInvalid = errors.New("storage: invalid OIDC issuance request")
)

// LeaseOIDCIssueStore is the transactional commit-time issuance contract.
//
// issueOIDC authenticates the lease, the job's OIDC permission, trust and
// audience with a cheap preliminary read, then may spend seconds on shared
// key-ring/fence work before signing a 5-minute JWT. A late handler-side
// re-check would not close that window: it is a read followed by a separate
// audit append, so a concurrent cancel/complete/revoke/replacement can still
// commit in between and mint a credential after the lease ceased. This method
// evaluates the ENTIRE issuance predicate and appends the durable oidc.issued
// audit row in the SAME transaction (PostgreSQL: under a row lock on the
// job), so a concurrent revocation either commits first (and fails the
// predicate) or waits for the issuance commit. It returns the authoritative
// locked identity on success; refusal is a typed error from the ErrOIDCIssuance*
// set and commits NOTHING, so no credential can leave the server without the
// durable audit.
type LeaseOIDCIssueStore interface {
	CommitOIDCIssuance(ctx context.Context, req OIDCIssuance) (LockedOIDCIdentity, error)
}

var (
	_ LeaseOIDCIssueStore = (*PostgresStore)(nil)
	_ LeaseOIDCIssueStore = (*memStore)(nil)
	_ LeaseOIDCIssueStore = (*FaultyStore)(nil)
)

// oidcIssuanceErrorf wraps a typed refusal with the offending values.
func oidcIssuanceErrorf(base error, format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{base}, args...)...)
}

// ValidateOIDCIssuanceRequest is the shape contract of the commit request:
// the predicate addresses exactly one job by id and runner, needs the
// presented lease coordinates and the candidate token metadata. The
// coordinate strings are checked for presence, not canonical 32-hex shape:
// they always come from authenticated server state (the route's job id and
// the validated lease record), and the in-memory modes address their map keys
// directly.
func ValidateOIDCIssuanceRequest(req OIDCIssuance) error {
	if strings.TrimSpace(req.JobID) == "" {
		return oidcIssuanceErrorf(ErrOIDCIssuanceInvalid, "empty job id")
	}
	if strings.TrimSpace(req.RunnerID) == "" {
		return oidcIssuanceErrorf(ErrOIDCIssuanceInvalid, "job %s: empty runner id", req.JobID)
	}
	if req.LeaseGeneration < 0 {
		return oidcIssuanceErrorf(ErrOIDCIssuanceInvalid, "job %s: negative lease generation %d", req.JobID, req.LeaseGeneration)
	}
	if len(req.LeaseTokenHash) == 0 {
		return oidcIssuanceErrorf(ErrOIDCIssuanceInvalid, "job %s: empty lease token hash", req.JobID)
	}
	if strings.TrimSpace(req.Audience) == "" {
		return oidcIssuanceErrorf(ErrOIDCIssuanceInvalid, "job %s: empty audience", req.JobID)
	}
	if req.KID == "" || req.JTI == "" {
		return oidcIssuanceErrorf(ErrOIDCIssuanceInvalid, "job %s: missing kid/jti", req.JobID)
	}
	if req.IssuedAt.IsZero() || !req.ExpiresAt.After(req.IssuedAt) {
		return oidcIssuanceErrorf(ErrOIDCIssuanceInvalid, "job %s: invalid lifetime", req.JobID)
	}
	if req.Claims == nil {
		return oidcIssuanceErrorf(ErrOIDCIssuanceInvalid, "job %s: missing claims", req.JobID)
	}
	return nil
}

// LockedOIDCIdentityForJob derives the authoritative locked identity from an
// in-memory job record whose lease fields are protected by the caller's lock.
// PostgreSQL fills the same struct from the FOR UPDATE row; this helper keeps
// memStore and the server's in-process mode on the identical derivation.
func LockedOIDCIdentityForJob(j model.Job) LockedOIDCIdentity {
	var expires time.Time
	if j.LeaseExpiresAt != nil {
		expires = *j.LeaseExpiresAt
	}
	return LockedOIDCIdentity{
		JobID:            j.ID,
		RunID:            j.RunID,
		JobKey:           j.Key,
		RepoID:           RepoIDForJob(j),
		PolicyRepoID:     j.PolicyRepoID,
		RepoURL:          j.RepoURL,
		RepoFullName:     j.RepoFullName,
		Trusted:          j.Trusted,
		OIDCAllowed:      j.OIDCAllowed,
		AllowedAudiences: append([]string(nil), j.OIDCAudiences...),
		Status:           j.Status,
		LeaseRunnerID:    j.LeaseRunnerID,
		LeaseGeneration:  j.LeaseGeneration,
		LeaseTokenHash:   j.LeaseTokenHash,
		LeaseExpiresAt:   expires,
	}
}

// ValidateOIDCIssuance is the ONE issuance predicate: it evaluates the locked
// identity against the candidate request and returns the typed refusal the
// handler maps onto 409/403. It also cross-checks every identity-bearing
// claim against the locked row, so a JWT signed for one job can never be
// returned for another. PostgreSQL (row-locked), memStore and the server's
// in-process commit path all call it, so the three can never drift.
func ValidateOIDCIssuance(locked LockedOIDCIdentity, req OIDCIssuance) error {
	switch {
	case locked.Status != model.StatusRunning:
		return oidcIssuanceErrorf(ErrOIDCIssuanceRevoked, "job %s status %q", req.JobID, locked.Status)
	case locked.LeaseRunnerID != req.RunnerID:
		return oidcIssuanceErrorf(ErrOIDCIssuanceRunner, "job %s lease holder %q, presented %q", req.JobID, locked.LeaseRunnerID, req.RunnerID)
	case locked.LeaseGeneration != req.LeaseGeneration:
		return oidcIssuanceErrorf(ErrOIDCIssuanceGeneration, "job %s lease generation %d, presented %d", req.JobID, locked.LeaseGeneration, req.LeaseGeneration)
	case subtle.ConstantTimeCompare(locked.LeaseTokenHash, req.LeaseTokenHash) != 1:
		return oidcIssuanceErrorf(ErrOIDCIssuanceToken, "job %s lease token mismatch", req.JobID)
	case locked.LeaseExpiresAt.IsZero() || !locked.LeaseExpiresAt.After(req.IssuedAt):
		return oidcIssuanceErrorf(ErrOIDCIssuanceExpired, "job %s lease expired at %s", req.JobID, locked.LeaseExpiresAt.UTC().Format(time.RFC3339Nano))
	case !locked.Trusted:
		return oidcIssuanceErrorf(ErrOIDCIssuanceUntrusted, "job %s", req.JobID)
	case !locked.OIDCAllowed:
		return oidcIssuanceErrorf(ErrOIDCIssuanceNotAllowed, "job %s", req.JobID)
	case len(locked.AllowedAudiences) > 0 && !containsString(locked.AllowedAudiences, req.Audience):
		return oidcIssuanceErrorf(ErrOIDCIssuanceAudience, "job %s audience %q", req.JobID, req.Audience)
	}
	// The claims the JWT already carries must describe the LOCKED job. A
	// mismatch means the token in hand was built from a record that changed
	// between the preliminary read and this commit: it must be discarded.
	claims := req.Claims
	for _, c := range []struct {
		key  string
		want string
	}{
		{OIDCClaimJobID, locked.JobID},
		{OIDCClaimRunID, locked.RunID},
		{OIDCClaimJob, locked.JobKey},
		{OIDCClaimRepositoryID, locked.RepoID},
		{OIDCClaimRepository, locked.RepoFullName},
		{OIDCClaimTrusted, strconv.FormatBool(locked.Trusted)},
		{OIDCClaimAudience, req.Audience},
	} {
		if claims[c.key] != c.want {
			return oidcIssuanceErrorf(ErrOIDCIssuanceIdentity, "job %s claim %q = %q, locked %q", req.JobID, c.key, claims[c.key], c.want)
		}
	}
	return nil
}

// OIDCIssuanceAuditEvent builds the oidc.issued audit event for a request
// that has been validated against the locked identity. It is the ONE event
// shape both the store implementations and the server's in-process commit
// path write, so the audit trail is identical across modes. The audit never
// carries the token, only the job/audience/kid metadata.
func OIDCIssuanceAuditEvent(req OIDCIssuance, id string) model.AuditEvent {
	return model.AuditEvent{
		ID:        id,
		Action:    "oidc.issued",
		Actor:     req.RunnerID,
		RunID:     req.Claims[OIDCClaimRunID],
		JobID:     req.JobID,
		Message:   "OIDC id_token issued",
		Metadata:  map[string]string{"job": req.Claims[OIDCClaimJob], "audience": req.Audience, "kid": req.KID},
		CreatedAt: req.IssuedAt.UTC(),
	}
}

// CommitOIDCIssuance is the PostgreSQL commit-time issuance authority. It
// locks the job row FOR UPDATE, re-reads the authoritative lease/OIDC fields,
// evaluates the shared predicate (so a concurrent cancel/complete/revoke/
// replacement either commits before the lock — and fails the predicate — or
// waits for this transaction), cross-checks the candidate claims, appends the
// oidc.issued audit row and commits, all in one transaction. Any refusal
// returns a typed error and rolls the transaction back: no audit row, no
// credential.
func (s *PostgresStore) CommitOIDCIssuance(ctx context.Context, req OIDCIssuance) (LockedOIDCIdentity, error) {
	if err := ValidateOIDCIssuanceRequest(req); err != nil {
		return LockedOIDCIdentity{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LockedOIDCIdentity{}, err
	}
	defer tx.Rollback(ctx)
	var (
		runID, key      string
		leaseRunnerID   string
		leaseGeneration int64
		leaseTokenHash  []byte
		leaseExpiresAt  *time.Time
		status          string
		trusted         bool
		oidcAllowed     bool
		audiencesJSON   []byte
		repoID          string
		policyRepoID    string
		repoURL         string
		repoFullName    string
	)
	err = tx.QueryRow(ctx, `SELECT run_id, COALESCE(key, ''),
		COALESCE(lease_runner_id, ''), lease_generation, COALESCE(lease_token_hash, ''::bytea), lease_expires_at, status,
		CASE WHEN jsonb_typeof(payload->'trusted') = 'boolean' THEN (payload->>'trusted')::boolean ELSE FALSE END,
		CASE WHEN jsonb_typeof(payload->'oidc_allowed') = 'boolean' THEN (payload->>'oidc_allowed')::boolean ELSE FALSE END,
		COALESCE(payload->'oidc_audiences', '[]'::jsonb),
		COALESCE(payload->>'repo_id', ''), COALESCE(payload->>'policy_repo_id', ''),
		COALESCE(payload->>'repo_url', ''), COALESCE(payload->>'repo_full_name', '')
		FROM jobs WHERE id = $1 FOR UPDATE`, req.JobID).Scan(
		&runID, &key, &leaseRunnerID, &leaseGeneration, &leaseTokenHash, &leaseExpiresAt, &status,
		&trusted, &oidcAllowed, &audiencesJSON, &repoID, &policyRepoID, &repoURL, &repoFullName)
	if errors.Is(err, pgx.ErrNoRows) {
		return LockedOIDCIdentity{}, ErrNotFound
	}
	if err != nil {
		return LockedOIDCIdentity{}, err
	}
	var audiences []string
	if len(audiencesJSON) > 0 && string(audiencesJSON) != "null" {
		if err := json.Unmarshal(audiencesJSON, &audiences); err != nil {
			return LockedOIDCIdentity{}, fmt.Errorf("storage: decode job oidc_audiences: %w", err)
		}
	}
	locked := LockedOIDCIdentityForJob(model.Job{
		ID: req.JobID, RunID: runID, Key: key, RepoID: repoID, PolicyRepoID: policyRepoID,
		RepoURL: repoURL, RepoFullName: repoFullName, Trusted: trusted, OIDCAllowed: oidcAllowed,
		OIDCAudiences: audiences, Status: model.Status(status),
		LeaseRunnerID: leaseRunnerID, LeaseGeneration: leaseGeneration, LeaseTokenHash: leaseTokenHash,
		LeaseExpiresAt: leaseExpiresAt,
	})
	if err := ValidateOIDCIssuance(locked, req); err != nil {
		return LockedOIDCIdentity{}, err
	}
	auditID, err := newID()
	if err != nil {
		return LockedOIDCIdentity{}, err
	}
	ev := OIDCIssuanceAuditEvent(req, auditID)
	var meta []byte
	if len(ev.Metadata) > 0 {
		meta, err = jsonMarshal(ev.Metadata)
		if err != nil {
			return LockedOIDCIdentity{}, err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events (id, action, actor, run_id, job_id, message, metadata, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		ev.ID, ev.Action, nullText(ev.Actor), nullText(ev.RunID), nullText(ev.JobID), nullText(ev.Message), meta, ev.CreatedAt); err != nil {
		return LockedOIDCIdentity{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LockedOIDCIdentity{}, err
	}
	return locked, nil
}
