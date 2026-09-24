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
//     from the name. The URL proof has PRECEDENCE over every other branch,
//     including the EMPTY stored value: a row with repo_id="" and a valid
//     clone URL is repaired to the URL-proven canonical identity rather than
//     being left identity-less (R1-3);
//   - with no URL, a repository full name proves a HOST-LESS record, stored
//     as the explicit alias spelling "owner/name" (one slash) or
//     "a1:<base64url(full_name)>" (nested group path). A plain nested string
//     is never produced again.
//   - a row where neither interpretation can be proven (an untagged nested
//     value with no URL and no full name) is QUARANTINED, never guessed: its
//     repo_id/policy_repo_id are replaced with a reserved
//     "quarantine.invalid/quarantined/<sha256-hex(original)>" identity that no
//     policy or RBAC grant can match (fail closed) and the original is
//     recorded verbatim in repo_identity_quarantine for operator review. The
//     identifier is a fixed-size lowercase hex digest of the ORIGINAL value,
//     so it is collision-resistant and unaffected by the path case-folding
//     every reader applies (R1-2); the original is recoverable from the
//     quarantine table, never from the identity itself.
//
// MIGRATION/UPGRADE: operators run
//
//	kiwi storage repair-repo-identities [--database-url URL] [--apply] [--batch-size N]
//
// without --apply it only LISTS the rows that would be rewritten or
// quarantined; with --apply it rewrites the provable rows and quarantines the
// unprovable ones. The pass is keyset-batched (ORDER BY created_at, id with a
// (created_at, id) > cursor bounds and a configurable LIMIT), one transaction
// per batch, committing each batch before advancing the cursor: a mid-run
// failure leaves the earlier batches committed and a re-run resumes from the
// start without duplicating work (the transformation is idempotent), and the
// memory footprint never scales with the table size (R1-5). It is idempotent:
// an explicit a1:/host-full value is left as is, and quarantined rows are
// stable (the reserved host is not re-derived).
//
// Every guarded UPDATE checks that it actually matched the classified row. A
// concurrent writer that makes it match zero rows is re-read/re-planned under
// the same transaction and either applied with the fresh plan or recorded as a
// distinct conflict; a counter is never incremented without a successful
// UPDATE (R1-4). A quarantined queued/running row additionally gets the
// durable payload flag repo_identity_quarantined=true and is transitioned to
// cancelled in the same statement, so it is operationally inert even under an
// allow-everything repository policy (R1-6).
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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

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
	// RepoIdentityConflict is an APPLY-time outcome, never a plan: the guarded
	// UPDATE matched no row and a re-read/re-plan under the same transaction
	// still could not claim it (a concurrent writer kept moving the row). It
	// is reported distinctly so the operator never reads a phantom repair.
	RepoIdentityConflict
)

// String renders the action for operator output.
func (a RepoIdentityRepairAction) String() string {
	switch a {
	case RepoIdentityRewrite:
		return "rewrite"
	case RepoIdentityQuarantine:
		return "quarantine"
	case RepoIdentityConflict:
		return "conflict"
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

// RepoIdentityQuarantinedFlag is the durable payload key a quarantined row
// carries. It is read by LeasePredicate.Allows/ClaimAllowsRunner to deny every
// lease of a quarantined queued job independently of the repository ACL.
const RepoIdentityQuarantinedFlag = "repo_identity_quarantined"

// RepoIdentityQuarantineReason is the operator-facing reason recorded on the
// cancelled status of a quarantined queued/running job.
const RepoIdentityQuarantineReason = "repository identity quarantined by operator repair"

// QuarantinedRepoIdentity renders the reserved replacement identity for an
// unprovable stored value. It is an untagged canonical "host/full-name"
// identity (three path segments), so the typed positional rule classifies it
// exactly like every other stored canonical ID. The tail is the lowercase
// SHA-256 hex digest of the ORIGINAL (trimmed) value: a fixed-size,
// collision-resistant identifier that cannot collide after the path
// case-folding every reader applies (the previous base64url tail was
// case-significant and could), and that never embeds the original slash path.
// The original value is preserved verbatim in repo_identity_quarantine for
// operator review.
func QuarantinedRepoIdentity(original string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(original)))
	return RepoIdentityQuarantineHost + "/quarantined/" + hex.EncodeToString(sum[:])
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
	if strings.HasPrefix(stored, RepoIdentityQuarantineHost+"/") {
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

	// R1-3: the URL proof has PRECEDENCE over every other branch, including
	// the empty stored value. The pre-fix code returned Keep for
	// stored == "" BEFORE consulting the URL evidence, so a row with
	// repo_id="" plus a valid clone URL and full name was left with no
	// repository identity at all instead of the URL-proven canonical one.
	if host != "" && path != "" {
		proven := auth.CanonicalRepoID(host, path)
		if stored == proven {
			return RepoIdentityPlan{Explicit: proven, Action: RepoIdentityKeep}
		}
		return RepoIdentityPlan{Explicit: proven, Action: RepoIdentityRewrite, Reason: "the clone URL proves the canonical checkout identity"}
	}

	// No URL host. An EMPTY stored identity with a repository full name is the
	// hole a later early return would leave: with no URL host the full name
	// proves a HOST-LESS record — the legacy URL-less submission stored
	// auth.CanonicalRepoID("", full) == full verbatim — so stamp the explicit
	// alias form (plain "owner/name", or the nested "a1:..." spelling).
	if stored == "" {
		if full != "" {
			alias, err := auth.CanonicalHostAlias(full)
			if err != nil {
				return RepoIdentityPlan{Explicit: stored, Action: RepoIdentityKeep}
			}
			return RepoIdentityPlan{Explicit: alias.Serialized(), Action: RepoIdentityRewrite, Reason: "stamp the explicit host-less alias form for an empty stored identity"}
		}
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

// RepoIdentityRepairEntry is one run/job row the repair rewrote, quarantined
// or could not claim.
type RepoIdentityRepairEntry struct {
	Kind     string                   // "run" or "job"
	ID       string                   // run/job id
	Stored   string                   // the repo_id before the repair
	Repaired string                   // the repo_id after the repair
	Action   RepoIdentityRepairAction // rewrite, quarantine or conflict
	Reason   string
}

// RepoIdentityRepairResult is the operator-facing outcome of a repair pass.
type RepoIdentityRepairResult struct {
	Mode        RepoIdentityRepairMode
	Scanned     int
	Rewritten   int
	Quarantined int
	Unchanged   int
	// Conflicts counts rows the guarded UPDATE could not claim even after a
	// same-transaction re-read/re-plan (a concurrent writer kept moving them).
	// They are NOT counted as repaired or quarantined.
	Conflicts int
	Entries   []RepoIdentityRepairEntry
}

// RepoIdentityRepairOptions tunes one repair pass. The zero value is the
// operator default.
type RepoIdentityRepairOptions struct {
	// BatchSize is the keyset page size (the LIMIT of each batch). <= 0 uses
	// KIWI_REPO_IDENTITY_REPAIR_BATCH_SIZE when it parses to a positive value,
	// otherwise defaultRepoIdentityRepairBatchSize; it is clamped to the
	// documented 500..2000 operator range for values that exceed it.
	BatchSize int
}

const (
	// defaultRepoIdentityRepairBatchSize is the operator default: within the
	// documented 500..2000 range, large enough to keep the batch count small
	// and small enough that memory never scales with the table size.
	defaultRepoIdentityRepairBatchSize = 1000
	// maxRepoIdentityRepairBatchSize caps an explicit override at the top of
	// the documented range.
	maxRepoIdentityRepairBatchSize = 2000
)

// repoIdentityQuarantineSchemaSQL creates the quarantine log. Like the
// cluster-key schema it is deliberately outside the numbered migrations
// (additive, created idempotently by the operator command, no foreign keys).
// It holds the ORIGINAL (pre-repair) identity verbatim because the reserved
// replacement identity is a one-way digest (R1-2).
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

// repoIdentityRepairTestHooks is a test-only seam. Production leaves it nil;
// tests install it to inject a concurrent writer or a mid-run failure without
// sleeps (a deterministic barrier).
type repoIdentityRepairTestHooks struct {
	// BeforeBatch runs after one batch is read and before it is processed; a
	// returned error aborts the pass with the earlier batches committed.
	BeforeBatch func(batchIndex int, records []repoIdentityRepairRow) error
	// BeforeApply runs before each record's guarded UPDATE.
	BeforeApply func(kind, id string) error
}

// repoIdentityRepairTable bundles the per-kind SQL fragments.
type repoIdentityRepairTable struct {
	kind       string // "run" or "job"
	table      string // "runs" or "jobs"
	oldURLExpr string // payload field carrying the clone URL
	batchSQL   string
	recordSQL  string
}

func newRepoIdentityRepairTables() []repoIdentityRepairTable {
	run := repoIdentityRepairTable{
		kind:       "run",
		table:      "runs",
		oldURLExpr: "payload->>'repo'",
		batchSQL: `SELECT id, COALESCE(payload->>'repo_id',''), COALESCE(payload->>'policy_repo_id',''), ` +
			`COALESCE(payload->>'repo',''), COALESCE(payload->>'repo_full_name',''), created_at ` +
			`FROM runs WHERE (created_at, id) > ($1::timestamptz, $2::text) ` +
			`ORDER BY created_at ASC, id ASC LIMIT $3`,
		recordSQL: `SELECT id, COALESCE(payload->>'repo_id',''), COALESCE(payload->>'policy_repo_id',''), ` +
			`COALESCE(payload->>'repo',''), COALESCE(payload->>'repo_full_name',''), created_at ` +
			`FROM runs WHERE id=$1`,
	}
	job := repoIdentityRepairTable{
		kind:       "job",
		table:      "jobs",
		oldURLExpr: "payload->>'repo_url'",
		batchSQL: `SELECT id, COALESCE(payload->>'repo_id',''), COALESCE(payload->>'policy_repo_id',''), ` +
			`COALESCE(payload->>'repo_url',''), COALESCE(payload->>'repo_full_name',''), created_at ` +
			`FROM jobs WHERE (created_at, id) > ($1::timestamptz, $2::text) ` +
			`ORDER BY created_at ASC, id ASC LIMIT $3`,
		recordSQL: `SELECT id, COALESCE(payload->>'repo_id',''), COALESCE(payload->>'policy_repo_id',''), ` +
			`COALESCE(payload->>'repo_url',''), COALESCE(payload->>'repo_full_name',''), created_at ` +
			`FROM jobs WHERE id=$1`,
	}
	return []repoIdentityRepairTable{run, job}
}

// repoIdentityRepairQueryer is the shared read seam over the pool and a
// transaction.
type repoIdentityRepairQueryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// RepairRepoIdentities scans every run and job payload, classifies its stored
// repo_id with PlanStoredRepoIdentity and (in apply mode) persists the explicit
// form and quarantines the unprovable rows. It is idempotent and safe to run
// repeatedly. See RepairRepoIdentitiesWithOptions for the batching contract.
func (s *PostgresStore) RepairRepoIdentities(ctx context.Context, mode RepoIdentityRepairMode) (RepoIdentityRepairResult, error) {
	return s.RepairRepoIdentitiesWithOptions(ctx, mode, RepoIdentityRepairOptions{})
}

// RepairRepoIdentitiesWithOptions is RepairRepoIdentities with an explicit
// batch size. The pass walks runs then jobs in (created_at, id) keyset batches
// with one transaction per batch: each batch commits before the next cursor is
// read, so a mid-run failure leaves the earlier batches committed and a re-run
// resumes from the beginning without duplicating work (the transformation is
// idempotent). Memory is bounded by the batch size, not the table size.
func (s *PostgresStore) RepairRepoIdentitiesWithOptions(ctx context.Context, mode RepoIdentityRepairMode, opts RepoIdentityRepairOptions) (RepoIdentityRepairResult, error) {
	result := RepoIdentityRepairResult{Mode: mode}
	if s.pool == nil {
		return result, ErrRepoIdentityRepairRequiresPool
	}
	batchSize := opts.BatchSize
	if batchSize <= 0 {
		// Operator knob without a code change: an explicit positive
		// KIWI_REPO_IDENTITY_REPAIR_BATCH_SIZE overrides the default (the
		// options field remains the programmatic override).
		if env := strings.TrimSpace(os.Getenv("KIWI_REPO_IDENTITY_REPAIR_BATCH_SIZE")); env != "" {
			if n, perr := strconv.Atoi(env); perr == nil {
				batchSize = n
			}
		}
	}
	if batchSize <= 0 {
		batchSize = defaultRepoIdentityRepairBatchSize
	}
	if batchSize > maxRepoIdentityRepairBatchSize {
		batchSize = maxRepoIdentityRepairBatchSize
	}
	if mode == RepoIdentityRepairApply {
		if err := s.ensureRepoIdentityQuarantineSchema(ctx); err != nil {
			return result, err
		}
	}
	for _, table := range newRepoIdentityRepairTables() {
		if err := s.repairRepoIdentityTable(ctx, mode, table, batchSize, &result); err != nil {
			return result, err
		}
	}
	return result, nil
}

// ensureRepoIdentityQuarantineSchema creates the quarantine log once, under the
// shared schema-migrations advisory lock (the established package pattern; see
// postgres_cluster_keys.go), before the batch loop.
func (s *PostgresStore) ensureRepoIdentityQuarantineSchema(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('kiwi_schema_migrations'))`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, repoIdentityQuarantineSchemaSQL); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// repairRepoIdentityTable walks one table in keyset batches.
func (s *PostgresStore) repairRepoIdentityTable(ctx context.Context, mode RepoIdentityRepairMode, table repoIdentityRepairTable, batchSize int, result *RepoIdentityRepairResult) error {
	var (
		cursor     time.Time
		cursorID   string
		batchIndex int
	)
	for {
		var records []repoIdentityRepairRow
		if mode == RepoIdentityRepairApply {
			tx, err := s.pool.Begin(ctx)
			if err != nil {
				return err
			}
			records, err = readRepoIdentityRepairBatch(ctx, tx, table, cursor, cursorID, batchSize)
			if err == nil {
				err = s.runRepoIdentityRepairBatch(ctx, tx, table, records, batchIndex, result)
			}
			if err != nil {
				_ = tx.Rollback(ctx)
				return err
			}
			if err := tx.Commit(ctx); err != nil {
				return err
			}
		} else {
			var err error
			records, err = readRepoIdentityRepairBatch(ctx, s.pool, table, cursor, cursorID, batchSize)
			if err != nil {
				return err
			}
			if err := s.runRepoIdentityRepairBatch(ctx, nil, table, records, batchIndex, result); err != nil {
				return err
			}
		}
		if len(records) == 0 {
			return nil
		}
		cursor = records[len(records)-1].createdAt
		cursorID = records[len(records)-1].id
		batchIndex++
		if len(records) < batchSize {
			return nil
		}
	}
}

// runRepoIdentityRepairBatch classifies (report) or applies (apply) one batch.
// tx is nil in report mode.
func (s *PostgresStore) runRepoIdentityRepairBatch(ctx context.Context, tx pgx.Tx, table repoIdentityRepairTable, records []repoIdentityRepairRow, batchIndex int, result *RepoIdentityRepairResult) error {
	if len(records) == 0 {
		return nil
	}
	if h := s.repoIdentityRepairHooks; h != nil && h.BeforeBatch != nil {
		if err := h.BeforeBatch(batchIndex, records); err != nil {
			return err
		}
	}
	for _, r := range records {
		result.Scanned++
		if tx == nil {
			plan := PlanStoredRepoIdentity(r.repoID, r.url, r.full)
			if plan.Action == RepoIdentityKeep {
				result.Unchanged++
				continue
			}
			if plan.Action == RepoIdentityQuarantine {
				result.Quarantined++
			} else {
				result.Rewritten++
			}
			result.Entries = append(result.Entries, RepoIdentityRepairEntry{
				Kind: table.kind, ID: r.id, Stored: r.repoID, Repaired: plan.Explicit,
				Action: plan.Action, Reason: plan.Reason,
			})
			continue
		}
		if err := s.applyRepoIdentityRecord(ctx, tx, table, r, result); err != nil {
			return err
		}
	}
	return nil
}

// applyRepoIdentityRecord claims one row with the guarded UPDATE. When the
// guard matches zero rows it re-reads the row under the SAME transaction,
// re-plans and applies the fresh plan once; if that also loses, it records a
// distinct conflict. Counters move only after a successful UPDATE (R1-4).
func (s *PostgresStore) applyRepoIdentityRecord(ctx context.Context, tx pgx.Tx, table repoIdentityRepairTable, r repoIdentityRepairRow, result *RepoIdentityRepairResult) error {
	plan := PlanStoredRepoIdentity(r.repoID, r.url, r.full)
	if plan.Action == RepoIdentityKeep {
		result.Unchanged++
		return nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		if h := s.repoIdentityRepairHooks; h != nil && h.BeforeApply != nil {
			if err := h.BeforeApply(table.kind, r.id); err != nil {
				return err
			}
		}
		// A fork PR's policy_repo_id is the BASE repository: only rewrite it
		// when it is the same value as the checkout identity.
		repairedPolicy := plan.Explicit
		if strings.TrimSpace(r.policyID) != strings.TrimSpace(r.repoID) {
			repairedPolicy = r.policyID
		}
		oldVals, applied, err := applyGuardedRepoIdentity(ctx, tx, table, r, plan, repairedPolicy)
		if err != nil {
			return err
		}
		if applied {
			if plan.Action == RepoIdentityQuarantine {
				if err := insertRepoIdentityQuarantine(ctx, tx, table.kind, r.id, oldVals, plan.Reason); err != nil {
					return err
				}
				result.Quarantined++
			} else {
				result.Rewritten++
			}
			result.Entries = append(result.Entries, RepoIdentityRepairEntry{
				Kind: table.kind, ID: r.id, Stored: r.repoID, Repaired: plan.Explicit,
				Action: plan.Action, Reason: plan.Reason,
			})
			return nil
		}
		// The guard matched zero rows: a concurrent writer moved the row
		// between the batch read and the UPDATE. Re-read the committed state
		// under the same transaction and re-plan.
		fresh, found, err := readRepoIdentityRepairRecord(ctx, tx, table, r.id)
		if err != nil {
			return err
		}
		if !found {
			result.Conflicts++
			result.Entries = append(result.Entries, RepoIdentityRepairEntry{
				Kind: table.kind, ID: r.id, Stored: r.repoID, Repaired: plan.Explicit,
				Action: RepoIdentityConflict, Reason: "row disappeared before the repair could claim it",
			})
			return nil
		}
		r = fresh
		plan = PlanStoredRepoIdentity(r.repoID, r.url, r.full)
		if plan.Action == RepoIdentityKeep {
			result.Unchanged++
			return nil
		}
	}
	result.Conflicts++
	result.Entries = append(result.Entries, RepoIdentityRepairEntry{
		Kind: table.kind, ID: r.id, Stored: r.repoID, Repaired: plan.Explicit,
		Action: RepoIdentityConflict, Reason: "concurrent writer kept changing the row; re-run the repair",
	})
	return nil
}

// readRepoIdentityRepairBatch reads one keyset page.
func readRepoIdentityRepairBatch(ctx context.Context, q repoIdentityRepairQueryer, table repoIdentityRepairTable, after time.Time, afterID string, limit int) ([]repoIdentityRepairRow, error) {
	rows, err := q.Query(ctx, table.batchSQL, after, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []repoIdentityRepairRow
	for rows.Next() {
		var r repoIdentityRepairRow
		if err := rows.Scan(&r.id, &r.repoID, &r.policyID, &r.url, &r.full, &r.createdAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// readRepoIdentityRepairRecord re-reads one row by id.
func readRepoIdentityRepairRecord(ctx context.Context, q repoIdentityRepairQueryer, table repoIdentityRepairTable, id string) (repoIdentityRepairRow, bool, error) {
	var r repoIdentityRepairRow
	rows, err := q.Query(ctx, table.recordSQL, id)
	if err != nil {
		return r, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return r, false, err
		}
		return r, false, nil
	}
	if err := rows.Scan(&r.id, &r.repoID, &r.policyID, &r.url, &r.full, &r.createdAt); err != nil {
		return r, false, err
	}
	return r, true, rows.Err()
}

// applyGuardedRepoIdentity executes the guarded, single-statement UPDATE for
// one row and returns the pre-update values it replaced. The statement builds
// the new payload in a CTE (PostgreSQL cannot reuse a SET alias), restamps the
// run's materialized identity columns from the NEW payload in the SAME
// statement (R1-1), and — for a quarantine — writes the durable flag and, for
// queued/running work, transitions it to cancelled (R1-6). The guarded UPDATE
// is the data-modifying CTE, so a zero-row match is observable (applied=false)
// and no counter can advance on a phantom repair (R1-4).
func applyGuardedRepoIdentity(ctx context.Context, tx pgx.Tx, table repoIdentityRepairTable, r repoIdentityRepairRow, plan RepoIdentityPlan, repairedPolicy string) (repoIdentityRepairRow, bool, error) {
	sql := repoIdentityRepairGuardedUpdateSQL(table, plan.Action == RepoIdentityQuarantine)
	args := []any{r.id, plan.Explicit, repairedPolicy, r.repoID}
	if plan.Action == RepoIdentityQuarantine && table.kind == "job" {
		args = append(args, RepoIdentityQuarantineReason)
	}
	var old repoIdentityRepairRow
	err := tx.QueryRow(ctx, sql, args...).Scan(&old.repoID, &old.policyID, &old.url, &old.full)
	if errors.Is(err, pgx.ErrNoRows) {
		return repoIdentityRepairRow{}, false, nil
	}
	if err != nil {
		return repoIdentityRepairRow{}, false, err
	}
	old.id = r.id
	return old, true, nil
}

// repoIdentityRepairGuardedUpdateSQL renders the single guarded UPDATE. The
// data-modifying CTE returns the PRE-update values (from the locked current
// row) so a quarantine audit row always matches what was actually replaced.
func repoIdentityRepairGuardedUpdateSQL(table repoIdentityRepairTable, quarantine bool) string {
	newPayload := "jsonb_set(jsonb_set(payload, '{repo_id}', to_jsonb($2::text), true), '{policy_repo_id}', to_jsonb($3::text), true)"
	if quarantine {
		newPayload = "jsonb_set(" + newPayload + ", '{" + RepoIdentityQuarantinedFlag + "}', to_jsonb(true), true)"
	}
	set := "payload = np.payload"
	if table.kind == "run" {
		set += ", repo_identity_normalized = " + normalizedRunRepoIdentitySQL("np.payload") +
			", repo_full_name_normalized = " + normalizedRunRepoFullNameSQL("np.payload")
	}
	if quarantine {
		set += ", status = CASE WHEN r.status IN ('queued','running') THEN 'cancelled' ELSE r.status END" +
			", finished_at = CASE WHEN r.status IN ('queued','running') THEN COALESCE(r.finished_at, now()) ELSE r.finished_at END"
		if table.kind == "job" {
			set += ", error = CASE WHEN r.status IN ('queued','running') AND COALESCE(r.error,'') = '' THEN $5::text ELSE r.error END"
		}
	}
	cur := "SELECT id, payload, " +
		"COALESCE(payload->>'repo_id','') AS old_repo_id, " +
		"COALESCE(payload->>'policy_repo_id','') AS old_policy_id, " +
		"COALESCE(" + table.oldURLExpr + ",'') AS old_url, " +
		"COALESCE(payload->>'repo_full_name','') AS old_full " +
		"FROM " + table.table + " WHERE id=$1 AND COALESCE(payload->>'repo_id','')=$4 FOR UPDATE"
	np := "SELECT id, old_repo_id, old_policy_id, old_url, old_full, " + newPayload + " AS payload FROM cur"
	return "WITH cur AS (" + cur + "), np AS (" + np + "), " +
		"upd AS (UPDATE " + table.table + " r SET " + set + " FROM np WHERE r.id = np.id " +
		"RETURNING np.old_repo_id, np.old_policy_id, np.old_url, np.old_full) " +
		"SELECT old_repo_id, old_policy_id, old_url, old_full FROM upd"
}

// insertRepoIdentityQuarantine records the ORIGINAL pre-repair values of a
// quarantined row, as returned by the guarded UPDATE, for operator review.
func insertRepoIdentityQuarantine(ctx context.Context, tx pgx.Tx, kind, recordID string, old repoIdentityRepairRow, reason string) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO repo_identity_quarantine (kind, record_id, stored_repo_id, stored_policy_repo_id, repo_url, repo_full_name, reason)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 ON CONFLICT (kind, record_id) DO UPDATE SET stored_repo_id=EXCLUDED.stored_repo_id, stored_policy_repo_id=EXCLUDED.stored_policy_repo_id, repo_url=EXCLUDED.repo_url, repo_full_name=EXCLUDED.repo_full_name, reason=EXCLUDED.reason`,
		kind, recordID, old.repoID, old.policyID, old.url, old.full, reason)
	return err
}

// repoIdentityRepairRow is one runs/jobs payload's identity fields plus its
// keyset position.
type repoIdentityRepairRow struct {
	id, repoID, policyID, url, full string
	createdAt                       time.Time
}
