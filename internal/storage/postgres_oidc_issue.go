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
// coordinates the handler AUTHENTICATED from its preliminary read, plus the
// only values a candidate may choose — the requested audience, the generated
// JTI, the signer KID and the intended lifetime. It is the request of the
// commit-time authority (LeaseOIDCIssueStore.CommitOIDCIssuance): the store
// re-evaluates the whole issuance predicate against the LOCKED job at its own
// commit clock — status, lease holder/generation/token hash, lease and token
// lifetime expiry, trust, id_token permission and the audience allowlist —
// and cross-checks the candidate claims against the locked identity before it
// appends the oidc.issued audit row and commits.
//
// Claims carries the identity-bearing claims the handler AUTHENTICATED as its
// preliminary identity (see the OIDCClaim* keys). They are ASSERTIONS, never
// token input: the commit proves every one of them equals the LOCKED row and
// refuses on any mismatch; the JWT that is finally returned is built from the
// locked identity the commit returns (LockedOIDCIdentity.AuthoritativeIdentity
// / OIDCAuthoritativeIdentity.TokenClaims), so no identity claim can ever
// reach the token from the stale preliminary object.
type OIDCIssuance struct {
	JobID           string
	RunnerID        string
	LeaseGeneration int64
	LeaseTokenHash  []byte
	Audience        string
	KID             string
	JTI             string
	// TTL is the requested token lifetime. The commit derives the absolute
	// IssuedAt/ExpiresAt from its OWN clock (PostgreSQL: the post-lock
	// clock_timestamp(); memory/fs: the store clock under the server lock),
	// exactly like lease liveness. Callers never supply absolute instants,
	// so a skewed serving replica cannot move the JWT window forward or
	// backward.
	TTL    time.Duration
	Claims map[string]string
}

// OIDCIssuanceResult is the committed credential identity plus the lifetime
// the store actually issued: IssuedAt is the commit clock, ExpiresAt is that
// instant plus the requested TTL. The handler builds the JWT and the audit
// record from these values, so the credential timestamps live in the same
// clock domain as the lease predicate that authorized them.
type OIDCIssuanceResult struct {
	Identity  LockedOIDCIdentity
	IssuedAt  time.Time
	ExpiresAt time.Time
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
	OIDCClaimRef          = "ref"
	OIDCClaimSHA          = "sha"
	OIDCClaimEvent        = "event"
	OIDCClaimEnvironment  = "environment"
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
	PolicyRepoID string
	RepoURL      string
	RepoFullName string
	// Ref/SHA/Event/Environment come from the locked job's own compiled
	// payload (the enqueue-time copy of the run coordinates), so the
	// corresponding JWT claims can never describe a different revision than
	// the locked job row.
	Ref              string
	SHA              string
	Event            string
	Environment      string
	Trusted          bool
	OIDCAllowed      bool
	AllowedAudiences []string
	Status           model.Status
	LeaseRunnerID    string
	LeaseGeneration  int64
	LeaseTokenHash   []byte
	LeaseExpiresAt   time.Time
}

// OIDCAuthoritativeIdentity is the canonical identity-bearing claim set of an
// issued job id_token, derived exclusively from the locked job row. Every
// identity claim the token carries comes from here; a candidate may influence
// only the issuer, audience, JTI, signer KID and lifetime. The subject is the
// canonical repo:<RepoID>:ref:<Ref>:job:<JobKey> coordinate.
type OIDCAuthoritativeIdentity struct {
	Subject      string
	Repository   string
	RepositoryID string
	Ref          string
	SHA          string
	Event        string
	RunID        string
	JobID        string
	JobKey       string
	Environment  string
	Trusted      bool
}

// AuthoritativeIdentity projects the locked row onto the canonical identity
// claim set the returned JWT must describe. It is the ONLY source the server
// builds token claims from, so a stale preliminary read cannot leak a single
// identity claim into a credential.
func (l LockedOIDCIdentity) AuthoritativeIdentity() OIDCAuthoritativeIdentity {
	return OIDCAuthoritativeIdentity{
		Subject:      "repo:" + l.RepoID + ":ref:" + l.Ref + ":job:" + l.JobKey,
		Repository:   l.RepoFullName,
		RepositoryID: l.RepoID,
		Ref:          l.Ref,
		SHA:          l.SHA,
		Event:        l.Event,
		RunID:        l.RunID,
		JobID:        l.JobID,
		JobKey:       l.JobKey,
		Environment:  l.Environment,
		Trusted:      l.Trusted,
	}
}

// oidcClockSkew is the nbf backdate issued tokens carry so a verifier whose
// clock trails the issuing server's by a few seconds still accepts them.
const oidcClockSkew = 5 * time.Second

// TokenClaims builds the complete JWT claim set for this identity plus the
// caller-chosen issuer, audience, JTI and lifetime. issuedAt/expiresAt are the
// intended lifetime the candidate supplied; every OTHER claim is derived from
// the locked identity.
func (a OIDCAuthoritativeIdentity) TokenClaims(issuer, audience, jti string, issuedAt, expiresAt time.Time) map[string]any {
	return map[string]any{
		"iss":           issuer,
		"sub":           a.Subject,
		"aud":           audience,
		"iat":           issuedAt.Unix(),
		"nbf":           issuedAt.Add(-oidcClockSkew).Unix(),
		"exp":           expiresAt.Unix(),
		"jti":           jti,
		"repository":    a.Repository,
		"repository_id": a.RepositoryID,
		"ref":           a.Ref,
		"sha":           a.SHA,
		"event":         a.Event,
		"run_id":        a.RunID,
		"job_id":        a.JobID,
		"job":           a.JobKey,
		"environment":   a.Environment,
		"trusted":       a.Trusted,
	}
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
// locked identity plus the credential lifetime derived from the commit clock
// on success; refusal is a typed error from the ErrOIDCIssuance* set and
// commits NOTHING, so no credential can leave the server without the durable
// audit.
type LeaseOIDCIssueStore interface {
	CommitOIDCIssuance(ctx context.Context, req OIDCIssuance) (OIDCIssuanceResult, error)
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
	if req.TTL <= 0 {
		return oidcIssuanceErrorf(ErrOIDCIssuanceInvalid, "job %s: non-positive token ttl", req.JobID)
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
		Ref:              j.Ref,
		SHA:              j.SHA,
		Event:            j.Event,
		Environment:      j.Environment,
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

// ValidateOIDCIssuance evaluates the issuance predicate against this
// process's clock. It exists only for callers that hold no storage commit
// clock (unit tests and diagnostics): every issuance COMMIT must call
// ValidateOIDCIssuanceAt with the storage clock, otherwise the stale-clock
// window reopens — a lease that expires during signer/key-store work would
// still pass.
func ValidateOIDCIssuance(locked LockedOIDCIdentity, req OIDCIssuance) error {
	return ValidateOIDCIssuanceAt(locked, req, time.Now().UTC())
}

// ValidateOIDCIssuanceAt is the ONE issuance predicate: it evaluates the
// locked identity against the candidate request AT THE STORAGE COMMIT CLOCK
// and returns the typed refusal the handler maps onto 409/403. commitNow must
// come from the same clock domain that persisted the lease expiry (PostgreSQL:
// clock_timestamp() read after the row lock; memory/fs: time.Now() under the
// store lock), so no application/DB skew can launder an expired lease. The
// requested token lifetime is a TTL validated for positivity here; its
// absolute window is derived from commitNow by the caller (OIDCIssuanceResult),
// so the credential cannot claim a different clock domain than the lease
// check.
//
// It also cross-checks every identity-bearing claim against the locked row, so
// a JWT built for one revision/job can never be returned for another.
// PostgreSQL (row-locked), memStore and the server's in-process commit path
// all call it, so the three can never drift.
func ValidateOIDCIssuanceAt(locked LockedOIDCIdentity, req OIDCIssuance, commitNow time.Time) error {
	switch {
	case locked.Status != model.StatusRunning:
		return oidcIssuanceErrorf(ErrOIDCIssuanceRevoked, "job %s status %q", req.JobID, locked.Status)
	case locked.LeaseRunnerID != req.RunnerID:
		return oidcIssuanceErrorf(ErrOIDCIssuanceRunner, "job %s lease holder %q, presented %q", req.JobID, locked.LeaseRunnerID, req.RunnerID)
	case locked.LeaseGeneration != req.LeaseGeneration:
		return oidcIssuanceErrorf(ErrOIDCIssuanceGeneration, "job %s lease generation %d, presented %d", req.JobID, locked.LeaseGeneration, req.LeaseGeneration)
	case subtle.ConstantTimeCompare(locked.LeaseTokenHash, req.LeaseTokenHash) != 1:
		return oidcIssuanceErrorf(ErrOIDCIssuanceToken, "job %s lease token mismatch", req.JobID)
	case locked.LeaseExpiresAt.IsZero() || !locked.LeaseExpiresAt.After(commitNow):
		return oidcIssuanceErrorf(ErrOIDCIssuanceExpired, "job %s lease expired at %s (commit %s)", req.JobID, locked.LeaseExpiresAt.UTC().Format(time.RFC3339Nano), commitNow.UTC().Format(time.RFC3339Nano))
	case req.TTL <= 0:
		return oidcIssuanceErrorf(ErrOIDCIssuanceInvalid, "job %s: non-positive token ttl", req.JobID)
	case !locked.Trusted:
		return oidcIssuanceErrorf(ErrOIDCIssuanceUntrusted, "job %s", req.JobID)
	case !locked.OIDCAllowed:
		return oidcIssuanceErrorf(ErrOIDCIssuanceNotAllowed, "job %s", req.JobID)
	case len(locked.AllowedAudiences) > 0 && !containsString(locked.AllowedAudiences, req.Audience):
		return oidcIssuanceErrorf(ErrOIDCIssuanceAudience, "job %s audience %q", req.JobID, req.Audience)
	}
	// EVERY identity-bearing claim must describe the LOCKED job. A mismatch
	// means the candidate authenticated a record that changed between the
	// preliminary read and this commit: the issuance is refused and no token
	// is built.
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
		{OIDCClaimRef, locked.Ref},
		{OIDCClaimSHA, locked.SHA},
		{OIDCClaimEvent, locked.Event},
		{OIDCClaimEnvironment, locked.Environment},
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
// path write, so the audit trail is identical across modes. issuedAt is the
// STORE's commit-clock issuance instant (OIDCIssuanceResult.IssuedAt), never a
// caller-captured application time. The audit never carries the token, only
// the job/audience/kid metadata.
func OIDCIssuanceAuditEvent(req OIDCIssuance, id string, issuedAt time.Time) model.AuditEvent {
	return model.AuditEvent{
		ID:        id,
		Action:    "oidc.issued",
		Actor:     req.RunnerID,
		RunID:     req.Claims[OIDCClaimRunID],
		JobID:     req.JobID,
		Message:   "OIDC id_token issued",
		Metadata:  map[string]string{"job": req.Claims[OIDCClaimJob], "audience": req.Audience, "kid": req.KID},
		CreatedAt: issuedAt.UTC(),
	}
}

// CommitOIDCIssuance is the PostgreSQL commit-time issuance authority. It
// locks the job row FOR UPDATE, re-reads the authoritative lease/OIDC/identity
// fields, evaluates the shared predicate at the DATABASE commit clock
// (clock_timestamp(), the same clock domain that persists lease_expires_at, so
// no app/DB skew can launder an expired lease), cross-checks the candidate
// claims, appends the oidc.issued audit row and commits, all in one
// transaction. Any refusal returns a typed error and rolls the transaction
// back: no audit row, no credential.
//
// The clock must be read ONLY after the row lock is held: a plain
// target-list clock_timestamp() is evaluated during the scan, BEFORE
// LockRows acquires the lock, and would therefore be stale by exactly the
// stall this commit fences. The CTE below keeps the FOR UPDATE clause in a
// materialized sub-plan (a CTE with a locking clause is never inlined), so the
// outer clock_timestamp() is evaluated after the lock has been acquired —
// verified on PostgreSQL 14.
func (s *PostgresStore) CommitOIDCIssuance(ctx context.Context, req OIDCIssuance) (OIDCIssuanceResult, error) {
	if err := ValidateOIDCIssuanceRequest(req); err != nil {
		return OIDCIssuanceResult{}, err
	}
	tx, err := s.beginSchemaCompatibleTx(ctx)
	if err != nil {
		return OIDCIssuanceResult{}, err
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
		ref             string
		sha             string
		event           string
		environment     string
		commitNow       time.Time
	)
	err = tx.QueryRow(ctx, `WITH locked AS (
		SELECT run_id, COALESCE(key, '') AS key,
			COALESCE(lease_runner_id, '') AS lease_runner_id, lease_generation,
			COALESCE(lease_token_hash, ''::bytea) AS lease_token_hash, lease_expires_at, status,
			CASE WHEN jsonb_typeof(payload->'trusted') = 'boolean' THEN (payload->>'trusted')::boolean ELSE FALSE END AS trusted,
			CASE WHEN jsonb_typeof(payload->'oidc_allowed') = 'boolean' THEN (payload->>'oidc_allowed')::boolean ELSE FALSE END AS oidc_allowed,
			COALESCE(payload->'oidc_audiences', '[]'::jsonb) AS oidc_audiences,
			COALESCE(payload->>'repo_id', '') AS repo_id, COALESCE(payload->>'policy_repo_id', '') AS policy_repo_id,
			COALESCE(payload->>'repo_url', '') AS repo_url, COALESCE(payload->>'repo_full_name', '') AS repo_full_name,
			COALESCE(payload->>'ref', '') AS ref, COALESCE(payload->>'sha', '') AS sha,
			COALESCE(payload->>'event', '') AS event, COALESCE(payload->>'environment', '') AS environment
		FROM jobs WHERE id = $1 FOR UPDATE
	)
	SELECT run_id, key, lease_runner_id, lease_generation, lease_token_hash, lease_expires_at, status,
		trusted, oidc_allowed, oidc_audiences, repo_id, policy_repo_id, repo_url, repo_full_name,
		ref, sha, event, environment, clock_timestamp()
	FROM locked`, req.JobID).Scan(
		&runID, &key, &leaseRunnerID, &leaseGeneration, &leaseTokenHash, &leaseExpiresAt, &status,
		&trusted, &oidcAllowed, &audiencesJSON, &repoID, &policyRepoID, &repoURL, &repoFullName,
		&ref, &sha, &event, &environment, &commitNow)
	if errors.Is(err, pgx.ErrNoRows) {
		return OIDCIssuanceResult{}, ErrNotFound
	}
	if err != nil {
		return OIDCIssuanceResult{}, err
	}
	var audiences []string
	if len(audiencesJSON) > 0 && string(audiencesJSON) != "null" {
		if err := json.Unmarshal(audiencesJSON, &audiences); err != nil {
			return OIDCIssuanceResult{}, fmt.Errorf("storage: decode job oidc_audiences: %w", err)
		}
	}
	locked := LockedOIDCIdentityForJob(model.Job{
		ID: req.JobID, RunID: runID, Key: key, RepoID: repoID, PolicyRepoID: policyRepoID,
		RepoURL: repoURL, RepoFullName: repoFullName, Ref: ref, SHA: sha, Event: event,
		Environment: environment, Trusted: trusted, OIDCAllowed: oidcAllowed,
		OIDCAudiences: audiences, Status: model.Status(status),
		LeaseRunnerID: leaseRunnerID, LeaseGeneration: leaseGeneration, LeaseTokenHash: leaseTokenHash,
		LeaseExpiresAt: leaseExpiresAt,
	})
	if err := ValidateOIDCIssuanceAt(locked, req, commitNow); err != nil {
		return OIDCIssuanceResult{}, err
	}
	auditID, err := newID()
	if err != nil {
		return OIDCIssuanceResult{}, err
	}
	ev := OIDCIssuanceAuditEvent(req, auditID, commitNow)
	var meta []byte
	if len(ev.Metadata) > 0 {
		meta, err = jsonMarshal(ev.Metadata)
		if err != nil {
			return OIDCIssuanceResult{}, err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events (id, action, actor, run_id, job_id, message, metadata, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		ev.ID, ev.Action, nullText(ev.Actor), nullText(ev.RunID), nullText(ev.JobID), nullText(ev.Message), meta, ev.CreatedAt); err != nil {
		return OIDCIssuanceResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return OIDCIssuanceResult{}, err
	}
	return OIDCIssuanceResult{Identity: locked, IssuedAt: commitNow.UTC(), ExpiresAt: commitNow.UTC().Add(req.TTL)}, nil
}
