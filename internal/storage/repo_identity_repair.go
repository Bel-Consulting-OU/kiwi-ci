package storage

// Repository-identity repair and migration (R2-B).
//
// WHAT IS WRONG (before this repair): a URL-less legacy submission stored a
// host-less repository name by calling auth.CanonicalRepoID("", fullName), so
// a nested group path persisted as the PLAIN nested string
// "group/sub/project". The typed positional rule used by every reader
// (auth.ParseStoredRepoID) reads a value with three or more path segments as a
// canonical identity whose FIRST segment is the host, so "group/sub/project"
// is silently reinterpreted as host "group" + full name "sub/project". The
// row then no longer matches its own repository and can be scoped/authorized
// as a different one.
//
// WHAT THIS FILE DOES:
//   - PlanStoredRepoIdentity classifies one stored identity against the row's
//     clone URL and repository full name and decides the EXPLICIT stored form
//     to persist:
//   - a clone URL proves the canonical identity "host/<full-name>" (the
//     storage spelling, auth.RepoIdentity.ID()); the host is never guessed
//     from the name;
//   - with no URL, a repository full name proves a HOST-LESS record, stored
//     as the explicit alias spelling "owner/name" (one slash) or
//     "a1:<base64url(full_name)>" (nested group path). A plain nested string
//     is never produced again;
//   - a row where neither interpretation can be proven (an untagged nested
//     value with no URL and no full name) is QUARANTINED, never guessed: its
//     repo_id/policy_repo_id are replaced with a reserved
//     "quarantine.invalid/quarantined/<base64url(original)>" identity that no
//     policy or RBAC grant can match (fail closed) and the original is
//     recorded in repo_identity_quarantine for operator review.
//
// MIGRATION/UPGRADE: operators run
//
//	kiwi storage repair-repo-identities [--database-url URL] [--apply]
//
// without --apply it only LISTS the rows that would be rewritten or
// quarantined; with --apply it rewrites the provable rows and quarantines the
// unprovable ones. The pass is idempotent: an explicit a1:/host-full value is
// left as is, and quarantined rows are stable (the reserved host is not
// re-derived).
//
// SCOPE: runs and jobs, whose repo_id/policy_repo_id are written by
// bindSubmissionRepoIdentity and its webhook/schedule/downstream siblings. A
// row's policy_repo_id is only rewritten when it is the SAME value as
// repo_id; a fork PR's policy_repo_id is the BASE repository (a different,
// legitimately canonical identity) and is deliberately left untouched.
// Schedules always require a repo_url at create time (a bare name without a
// forge host is rejected), so they never carry the URL-less nested defect.

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
)

// RepoIdentityRepairAction is the outcome of classifying one stored identity.
type RepoIdentityRepairAction int

const (
	// RepoIdentityKeep: the stored value is already an unambiguous explicit
	// form (or there is nothing to store); no write is needed.
	RepoIdentityKeep RepoIdentityRepairAction = iota
	// RepoIdentityRewrite: the clone URL or the host-less full name proves the
	// explicit form the row must carry.
	RepoIdentityRewrite
	// RepoIdentityQuarantine: neither interpretation can be proven; the row
	// must fail closed and be surfaced for operator review.
	RepoIdentityQuarantine
)

// String renders the action for operator output.
func (a RepoIdentityRepairAction) String() string {
	switch a {
	case RepoIdentityRewrite:
		return "rewrite"
	case RepoIdentityQuarantine:
		return "quarantine"
	default:
		return "keep"
	}
}

// RepoIdentityPlan is the classification of one stored repository identity.
type RepoIdentityPlan struct {
	// Explicit is the value to persist. It is set for Keep (the existing
	// value, possibly empty) and Rewrite (the proven explicit form), and is
	// the reserved quarantine identity for Quarantine.
	Explicit string
	// Action is the classification.
	Action RepoIdentityRepairAction
	// Reason explains a Rewrite or Quarantine to the operator.
	Reason string
}

// RepoIdentityQuarantineHost is the reserved host of a quarantined row's
// replacement identity. It is a syntactically valid host that no operator
// configures, so every policy/RBAC grant misses the quarantined repository
// (fail closed) while the identity stays a well-formed canonical storage value.
const RepoIdentityQuarantineHost = "quarantine.invalid"

// QuarantinedRepoIdentity renders the reserved replacement identity for an
// unprovable stored value. It is an untagged canonical "host/full-name"
// identity (three path segments), so the typed positional rule classifies it
// exactly like every other stored canonical ID, and the base64url tail keeps
// the original value recoverable for audit without embedding slashes.
func QuarantinedRepoIdentity(original string) string {
	enc := base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(original)))
	return RepoIdentityQuarantineHost + "/quarantined/" + enc
}

// PlanStoredRepoIdentity classifies the repository identity a run/job row
// carries and returns the EXPLICIT stored form it should carry, using the
// row's clone URL and repository full name as evidence. See the file comment
// for the rules.
func PlanStoredRepoIdentity(storedID, repoURL, repoFullName string) RepoIdentityPlan {
	stored := strings.TrimSpace(storedID)
	url := strings.TrimSpace(repoURL)
	full := strings.TrimSpace(repoFullName)

	// A row already carrying the reserved quarantine identity is stable: it
	// was quarantined by an earlier repair and must not be re-classified.
	if stored == "" || strings.HasPrefix(stored, RepoIdentityQuarantineHost+"/") {
		return RepoIdentityPlan{Explicit: stored, Action: RepoIdentityKeep}
	}

	// The serialized ACL forms are already explicit. a1: is THE explicit
	// nested-alias spelling, so keep it; an r1: identity is normalized to the
	// storage spelling "host/full-name".
	if strings.HasPrefix(stored, auth.RepoAliasPrefix) {
		if _, err := auth.ParseRepoAlias(stored); err != nil {
			return RepoIdentityPlan{Explicit: QuarantinedRepoIdentity(stored), Action: RepoIdentityQuarantine, Reason: "malformed a1: alias"}
		}
		return RepoIdentityPlan{Explicit: stored, Action: RepoIdentityKeep}
	}
	if strings.HasPrefix(stored, auth.RepoIdentityPrefix) {
		if _, err := auth.ParseRepoIdentity(stored); err != nil {
			return RepoIdentityPlan{Explicit: QuarantinedRepoIdentity(stored), Action: RepoIdentityQuarantine, Reason: "malformed r1: identity"}
		}
		// An r1: value is already explicit and typed. It is left as is rather
		// than rewritten to "host/full-name": stripping the explicit tag
		// would make a later pass (with no URL) unable to prove the value is
		// a canonical identity again. The live writers persist "host/full";
		// this path only preserves a value that predates them.
		return RepoIdentityPlan{Explicit: stored, Action: RepoIdentityKeep}
	}

	// A clone URL proves the canonical identity. Only a genuinely URL-shaped
	// value contributes a host: a bare owner/name stored in the URL field
	// (legacy) must never be read as "host = first segment".
	var host, path string
	if strings.Contains(url, "://") || strings.Contains(url, "@") {
		host = auth.CanonicalHost(url)
		path = RepoFullNameFromURL(url)
		if path == "" {
			path = full
		}
	}
	if host != "" && path != "" {
		proven := auth.CanonicalRepoID(host, path)
		switch {
		case stored == proven:
			return RepoIdentityPlan{Explicit: proven, Action: RepoIdentityKeep}
		default:
			return RepoIdentityPlan{Explicit: proven, Action: RepoIdentityRewrite, Reason: "the clone URL proves the canonical checkout identity"}
		}
	}

	// No URL host. A full name proves a HOST-LESS record.
	if full != "" {
		alias, err := auth.CanonicalHostAlias(full)
		if err != nil {
			return RepoIdentityPlan{Explicit: QuarantinedRepoIdentity(stored), Action: RepoIdentityQuarantine, Reason: "unparseable repository full name"}
		}
		proven := alias.Serialized()
		switch {
		case stored == proven:
			return RepoIdentityPlan{Explicit: proven, Action: RepoIdentityKeep}
		case stored == full:
			// The legacy URL-less defect stored the bare full name verbatim
			// (auth.CanonicalRepoID("", full) == full), so a nested name
			// persisted as the plain nested string. It is provably host-less
			// (there is no URL): store the explicit alias form.
			return RepoIdentityPlan{Explicit: proven, Action: RepoIdentityRewrite, Reason: "store the explicit host-less alias form for a legacy URL-less nested name"}
		default:
			// A stored value that reads as a CANONICAL identity while the
			// record carries no URL cannot be proven to be the same
			// repository as the host-less full name (a host-bearing value
			// implies a forge this row no longer names). Fail closed.
			if grant, err := auth.ParseStoredRepoID(stored); err == nil && grant.IsIdentity() {
				return RepoIdentityPlan{Explicit: QuarantinedRepoIdentity(stored), Action: RepoIdentityQuarantine, Reason: "stored identity disagrees with the host-less repository full name"}
			}
			return RepoIdentityPlan{Explicit: proven, Action: RepoIdentityRewrite, Reason: "store the explicit host-less alias form"}
		}
	}

	// No URL and no full name. Only an already-unambiguous value may stay.
	grant, err := auth.ParseStoredRepoID(stored)
	if err != nil {
		return RepoIdentityPlan{Explicit: QuarantinedRepoIdentity(stored), Action: RepoIdentityQuarantine, Reason: "unparseable stored identity"}
	}
	if grant.IsAlias() {
		return RepoIdentityPlan{Explicit: stored, Action: RepoIdentityKeep}
	}
	return RepoIdentityPlan{
		Explicit: QuarantinedRepoIdentity(stored),
		Action:   RepoIdentityQuarantine,
		Reason:   "untagged nested identity with no clone URL or full name to prove host vs bare nested",
	}
}

// RepoIdentityRepairMode selects report-only or mutating repair.
type RepoIdentityRepairMode int

const (
	// RepoIdentityRepairReport lists what would change without writing.
	RepoIdentityRepairReport RepoIdentityRepairMode = iota
	// RepoIdentityRepairApply rewrites provable rows and quarantines the
	// unprovable ones.
	RepoIdentityRepairApply
)

// RepoIdentityRepairEntry is one run/job row the repair rewrote or quarantined.
type RepoIdentityRepairEntry struct {
	Kind     string                   // "run" or "job"
	ID       string                   // run/job id
	Stored   string                   // the repo_id before the repair
	Repaired string                   // the repo_id after the repair
	Action   RepoIdentityRepairAction // rewrite or quarantine
	Reason   string
}

// RepoIdentityRepairResult is the operator-facing outcome of a repair pass.
type RepoIdentityRepairResult struct {
	Mode        RepoIdentityRepairMode
	Scanned     int
	Rewritten   int
	Quarantined int
	Unchanged   int
	Entries     []RepoIdentityRepairEntry
}

// repoIdentityQuarantineSchemaSQL creates the quarantine log. Like the
// cluster-key schema it is deliberately outside the numbered migrations
// (additive, created idempotently by the operator command, no foreign keys).
const repoIdentityQuarantineSchemaSQL = `
CREATE TABLE IF NOT EXISTS repo_identity_quarantine (
    kind                  text NOT NULL,
    record_id             text NOT NULL,
    stored_repo_id        text NOT NULL,
    stored_policy_repo_id text NOT NULL DEFAULT '',
    repo_url              text NOT NULL DEFAULT '',
    repo_full_name        text NOT NULL DEFAULT '',
    reason                text NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, record_id)
)`

// ErrRepoIdentityRepairRequiresPool reports a repair attempted without an open
// pool.
var ErrRepoIdentityRepairRequiresPool = errors.New("storage: repository identity repair requires an open pool")

// RepairRepoIdentities scans every run and job payload, classifies its stored
// repo_id with PlanStoredRepoIdentity and (in apply mode) persists the explicit
// form and quarantines the unprovable rows. It is idempotent and safe to run
// repeatedly.
//
// The whole pass runs in one transaction: the report a dry run prints is the
// exact work apply mode performs. Each UPDATE is additionally guarded on the
// repo_id it classified, so a concurrently rewritten row is skipped rather
// than clobbered.
func (s *PostgresStore) RepairRepoIdentities(ctx context.Context, mode RepoIdentityRepairMode) (RepoIdentityRepairResult, error) {
	result := RepoIdentityRepairResult{Mode: mode}
	if s.pool == nil {
		return result, ErrRepoIdentityRepairRequiresPool
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	if mode == RepoIdentityRepairApply {
		// Serialize the quarantine-table bootstrap with migrations and other
		// bootstraps (the established package pattern; see
		// postgres_cluster_keys.go).
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('kiwi_schema_migrations'))`); err != nil {
			return result, err
		}
		if _, err := tx.Exec(ctx, repoIdentityQuarantineSchemaSQL); err != nil {
			return result, err
		}
	}

	for _, table := range []struct {
		kind, sql string
	}{
		{"run", `SELECT id, COALESCE(payload->>'repo_id',''), COALESCE(payload->>'policy_repo_id',''), COALESCE(payload->>'repo',''), COALESCE(payload->>'repo_full_name','') FROM runs ORDER BY created_at ASC, id ASC`},
		{"job", `SELECT id, COALESCE(payload->>'repo_id',''), COALESCE(payload->>'policy_repo_id',''), COALESCE(payload->>'repo_url',''), COALESCE(payload->>'repo_full_name','') FROM jobs ORDER BY created_at ASC, id ASC`},
	} {
		rows, err := tx.Query(ctx, table.sql)
		if err != nil {
			return result, err
		}
		var records []repoIdentityRepairRow
		for rows.Next() {
			var r repoIdentityRepairRow
			if err := rows.Scan(&r.id, &r.repoID, &r.policyID, &r.url, &r.full); err != nil {
				rows.Close()
				return result, err
			}
			records = append(records, r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return result, err
		}
		rows.Close()

		for _, r := range records {
			result.Scanned++
			plan := PlanStoredRepoIdentity(r.repoID, r.url, r.full)
			switch plan.Action {
			case RepoIdentityKeep:
				result.Unchanged++
				continue
			case RepoIdentityQuarantine:
				result.Quarantined++
			case RepoIdentityRewrite:
				result.Rewritten++
			}
			// A fork PR's policy_repo_id is the BASE repository: only rewrite
			// it when it is the same value as the checkout identity.
			repairedPolicy := plan.Explicit
			if strings.TrimSpace(r.policyID) != strings.TrimSpace(r.repoID) {
				repairedPolicy = r.policyID
			}
			result.Entries = append(result.Entries, RepoIdentityRepairEntry{
				Kind:     table.kind,
				ID:       r.id,
				Stored:   r.repoID,
				Repaired: plan.Explicit,
				Action:   plan.Action,
				Reason:   plan.Reason,
			})
			if mode != RepoIdentityRepairApply {
				continue
			}
			if err := s.applyRepoIdentityRepair(ctx, tx, table.kind, r, plan, repairedPolicy); err != nil {
				return result, err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return result, err
	}
	return result, nil
}

// repoIdentityRepairRow is one runs/jobs payload's identity fields.
type repoIdentityRepairRow struct {
	id, repoID, policyID, url, full string
}

// applyRepoIdentityRepair persists one planned repair inside the pass
// transaction. The UPDATE is guarded on the classified repo_id so a row
// rewritten concurrently (or already repaired) is skipped, and a quarantined
// row's original values are recorded first.
func (s *PostgresStore) applyRepoIdentityRepair(ctx context.Context, tx pgx.Tx, table string, r repoIdentityRepairRow, plan RepoIdentityPlan, repairedPolicy string) error {
	if plan.Action == RepoIdentityQuarantine {
		if _, err := tx.Exec(ctx,
			`INSERT INTO repo_identity_quarantine (kind, record_id, stored_repo_id, stored_policy_repo_id, repo_url, repo_full_name, reason)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)
			 ON CONFLICT (kind, record_id) DO UPDATE SET stored_repo_id=EXCLUDED.stored_repo_id, stored_policy_repo_id=EXCLUDED.stored_policy_repo_id, repo_url=EXCLUDED.repo_url, repo_full_name=EXCLUDED.repo_full_name, reason=EXCLUDED.reason`,
			table, r.id, r.repoID, r.policyID, r.url, r.full, plan.Reason); err != nil {
			return err
		}
	}
	tableName := "runs"
	if table == "job" {
		tableName = "jobs"
	}
	// Write repo_id and, when it was the checkout identity (repairedPolicy
	// differs from the original), policy_repo_id as well.
	query := `UPDATE ` + tableName + ` SET payload = jsonb_set(jsonb_set(payload, '{repo_id}', to_jsonb($2::text), true), '{policy_repo_id}', to_jsonb($3::text), true) WHERE id=$1 AND COALESCE(payload->>'repo_id','')=$4`
	if _, err := tx.Exec(ctx, query, r.id, plan.Explicit, repairedPolicy, r.repoID); err != nil {
		return err
	}
	return nil
}
