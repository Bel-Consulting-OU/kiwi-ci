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
//	kiwi storage repair-repo-identities [--database-url URL] [--apply] [--cancel-active]
//
// without --apply it only LISTS the rows that would change; with --apply it
// rewrites the provable rows and quarantines the unprovable ones.
//
// The planner classifies every row as keep | rewrite_terminal |
// quarantine_terminal | active_requires_drain | conflict (T1-1). The
// lifecycle rule is what makes an identity IMMUTABLE for the lifetime of a
// lease: a TERMINAL row may be rewritten/quarantined in place, but a
// NON-terminal row (pending/queued/waiting_approval/running) whose effective
// identity would change is active_requires_drain and is NEVER rewritten by
// default — a lease/queue slot admitted under A must not silently become B
// accounting while post-lease privileged operations (OIDC issuance, the cache
// namespace, artifact provenance) resolve identity from the CURRENT record.
// Such a row is reported; --cancel-active then, for those rows only, FIRST
// performs the canonical cancellation (cancelJobTx per child job and
// cancelRunRowTx for the run row: lease cleared, runner slot freed, resource
// reservation deleted, quota released under the OLD identity, dependents
// recomputed, audit appended, run aggregation recomputed) and only THEN
// rewrites/quarantines the identity. Quarantining a run cascades to its
// non-terminal child jobs in the same transaction, so a child is never left
// queued under a cancelled+quarantined parent (T1-3).
//
// The pass is keyset-batched (ORDER BY created_at, id with a (created_at, id)
// > cursor bounds and a configurable LIMIT), one transaction per batch,
// committing each batch before advancing the cursor: a mid-run failure leaves
// the earlier batches committed and a re-run resumes from the start without
// duplicating work (the transformation is idempotent), and the memory
// footprint never scales with the table size (R1-5). It is idempotent: an
// explicit a1:/host-full value is left as is, and quarantined rows are stable
// (the reserved host is not re-derived).
//
// Every guarded UPDATE checks that it actually matched the classified row. The
// row (and, for a run, its child jobs) is locked before classification, so a
// concurrent writer can neither move the row between the locked read and the
// UPDATE nor make the guard match zero rows; a zero-row match can only be
// foreign/inconsistent state and is recorded as a distinct conflict. A counter
// is never incremented without a successful UPDATE (R1-4). A quarantined row
// additionally gets the durable payload flag
// repo_identity_quarantined=true, and an already-cancelled active row keeps
// its cancelled status, so it is operationally inert even under an
// allow-everything repository policy (R1-6). The lease-acquisition predicates
// additionally deny a queued job whose PARENT run is cancelled/quarantined,
// independently of the job's own flag (T1-3).
//
// LOCK ORDER: the repair obeys the established job -> run order, so it can
// never deadlock against CompleteJob (job -> run through recomputeRunTx) or
// AcquireLeaseAtomic. A JOB is locked on its own row. A RUN is locked only
// AFTER its non-terminal child jobs, in deterministic id order (ORDER BY id
// ASC), and the run's hasActiveChildren flag — the one that decides whether a
// plain apply may rewrite the run at all — is derived from those LOCKED child
// rows, never from an unlocked snapshot. The drain then cancels exactly the
// child jobs locked before the run row; it never re-scans for a job to lock
// while holding the run lock. A concurrent CompleteJob that already holds a
// child job row therefore always wins or waits at the child lock, and the
// repair can never form the run -> job / job -> run cycle PostgreSQL aborts
// with SQLSTATE 40P01.
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
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// RepoIdentityRepairAction is the outcome of classifying one stored identity.
//
// The classification is a function of BOTH the provable identity change and
// the row's lifecycle state (T1-1). A TERMINAL row may be rewritten or
// quarantined in place. A NON-terminal row (pending/queued/waiting_approval/
// running) whose effective identity would change is NEVER rewritten in place:
// its lease generation/token/runner was admitted under the OLD identity while
// every post-lease privileged operation (OIDC issuance via repoIDForRun, the
// cache namespace via repoIDForJob, artifact provenance) resolves identity
// from the CURRENT record, so an in-place A->B rewrite would let a lease
// admitted under A obtain B-scoped tokens/cache/provenance. Such a row is
// reported as active_requires_drain and only the explicit --cancel-active
// option cancels it first (through the canonical cancellation transaction) and
// then rewrites it.
type RepoIdentityRepairAction int

const (
	// RepoIdentityKeep: the stored value is already an unambiguous explicit
	// form (or there is nothing to store); no write is needed.
	RepoIdentityKeep RepoIdentityRepairAction = iota
	// RepoIdentityRewriteTerminal: a terminal row whose provable identity may
	// be restamped in place.
	RepoIdentityRewriteTerminal
	// RepoIdentityQuarantineTerminal: a terminal row whose identity cannot be
	// proven; fail closed and surface it for operator review.
	RepoIdentityQuarantineTerminal
	// RepoIdentityActiveRequiresDrain: a non-terminal row whose effective
	// identity would change. Reported, never rewritten unless the operator
	// passes --cancel-active.
	RepoIdentityActiveRequiresDrain
	// RepoIdentityConflict is an APPLY-time outcome, never a plan: the row
	// could not be locked (it disappeared) or the guarded UPDATE matched no
	// row against the locked value, or the run gained a child job outside the
	// locked set. It is reported distinctly so the operator never reads a
	// phantom repair.
	RepoIdentityConflict

	// RepoIdentityRewrite and RepoIdentityQuarantine are the identity-only
	// planner's spelling of the terminal outcomes (PlanStoredRepoIdentity has
	// no status argument). They are aliases so the identity rules and their
	// tests keep reading naturally; the status-aware ClassifyRepoIdentity
	// turns a non-terminal row's outcome into RepoIdentityActiveRequiresDrain.
	RepoIdentityRewrite    = RepoIdentityRewriteTerminal
	RepoIdentityQuarantine = RepoIdentityQuarantineTerminal
)

// String renders the action for operator output.
func (a RepoIdentityRepairAction) String() string {
	switch a {
	case RepoIdentityRewriteTerminal:
		return "rewrite_terminal"
	case RepoIdentityQuarantineTerminal:
		return "quarantine_terminal"
	case RepoIdentityActiveRequiresDrain:
		return "active_requires_drain"
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
	// Action is the classification. For a non-terminal row it is
	// RepoIdentityActiveRequiresDrain; see Desired for the change that a
	// --cancel-active pass would apply.
	Action RepoIdentityRepairAction
	// Desired is the identity change the row WOULD receive (always
	// RewriteTerminal or QuarantineTerminal when Action is anything other
	// than Keep, including ActiveRequiresDrain). It is the action applied
	// after an active row has been cancelled.
	Desired RepoIdentityRepairAction
	// Reason explains a Rewrite or Quarantine to the operator.
	Reason string
}

// ClassifyRepoIdentity applies the lifecycle rule on top of the identity-only
// planner: an identity change on a terminal row is classified as
// rewrite_terminal/quarantine_terminal, while the SAME change on a
// non-terminal (pending/queued/waiting_approval/running) row is classified as
// active_requires_drain. The Desired field always carries the terminal action
// so a --cancel-active pass knows what to apply after cancelling.
// ClassifyRepoIdentityWithChildren additionally treats a TERMINAL run that
// still owns non-terminal children as active_requires_drain: the operation can
// cascade into those children, so the run's own status is not sufficient to
// decide that a plain rewrite is safe.
func ClassifyRepoIdentityWithChildren(storedID, repoURL, repoFullName string, status model.Status, hasActiveChildren bool) RepoIdentityPlan {
	plan := ClassifyRepoIdentity(storedID, repoURL, repoFullName, status)
	if !hasActiveChildren {
		return plan
	}
	switch plan.Action {
	case RepoIdentityRewriteTerminal, RepoIdentityQuarantineTerminal:
		plan.Desired = plan.Action
		plan.Action = RepoIdentityActiveRequiresDrain
		if plan.Reason == "" {
			plan.Reason = "run owns non-terminal child jobs"
		}
	}
	return plan
}

func ClassifyRepoIdentity(storedID, repoURL, repoFullName string, status model.Status) RepoIdentityPlan {
	plan := PlanStoredRepoIdentity(storedID, repoURL, repoFullName)
	if plan.Action == RepoIdentityKeep {
		plan.Desired = RepoIdentityKeep
		return plan
	}
	plan.Desired = plan.Action
	if !status.Terminal() {
		plan.Action = RepoIdentityActiveRequiresDrain
	}
	return plan
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
// cancelled status of a quarantined active run/job.
const RepoIdentityQuarantineReason = "repository identity quarantined by operator repair"

// RepoIdentityDrainReason is the operator-facing reason recorded on the
// cancelled status of an active run/job drained by --cancel-active before its
// identity is rewritten.
const RepoIdentityDrainReason = "repository identity repair: drained active work before the identity change"

// QuarantinedRepoIdentity renders the reserved replacement identity for an
// unprovable stored value. It is an untagged canonical "host/full-name"
// identity (three path segments), so the typed positional rule classifies it
// exactly like every other stored canonical ID. The tail is the lowercase
// SHA-256 hex digest of the RAW stored value (T1-4): a fixed-size,
// collision-resistant identifier that cannot collide after the path
// case-folding every reader applies (the previous base64url tail was
// case-significant and could), and that never embeds the original slash path.
//
// The digest is taken over the RAW value, never a trimmed copy: two rows whose
// stored identities differ only by surrounding whitespace are DIFFERENT stored
// values and must not collapse to the same quarantine identity (trimming first
// would silently merge them). Trimming is used only for CLASSIFICATION
// (PlanStoredRepoIdentity compares the trimmed form); the original, raw value
// is preserved verbatim in repo_identity_quarantine for operator review.
func QuarantinedRepoIdentity(original string) string {
	sum := sha256.Sum256([]byte(original))
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
			return RepoIdentityPlan{Explicit: QuarantinedRepoIdentity(storedID), Action: RepoIdentityQuarantine, Reason: "malformed a1: alias"}
		}
		return RepoIdentityPlan{Explicit: stored, Action: RepoIdentityKeep}
	}
	if strings.HasPrefix(stored, auth.RepoIdentityPrefix) {
		if _, err := auth.ParseRepoIdentity(stored); err != nil {
			return RepoIdentityPlan{Explicit: QuarantinedRepoIdentity(storedID), Action: RepoIdentityQuarantine, Reason: "malformed r1: identity"}
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
			return RepoIdentityPlan{Explicit: QuarantinedRepoIdentity(storedID), Action: RepoIdentityQuarantine, Reason: "unparseable repository full name"}
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
				return RepoIdentityPlan{Explicit: QuarantinedRepoIdentity(storedID), Action: RepoIdentityQuarantine, Reason: "stored identity disagrees with the host-less repository full name"}
			}
			return RepoIdentityPlan{Explicit: proven, Action: RepoIdentityRewrite, Reason: "store the explicit host-less alias form"}
		}
	}

	// No URL and no full name. Only an already-unambiguous value may stay.
	grant, err := auth.ParseStoredRepoID(stored)
	if err != nil {
		return RepoIdentityPlan{Explicit: QuarantinedRepoIdentity(storedID), Action: RepoIdentityQuarantine, Reason: "unparseable stored identity"}
	}
	if grant.IsAlias() {
		return RepoIdentityPlan{Explicit: stored, Action: RepoIdentityKeep}
	}
	return RepoIdentityPlan{
		Explicit: QuarantinedRepoIdentity(storedID),
		Action:   RepoIdentityQuarantine,
		Reason:   "untagged nested identity with no clone URL or full name to prove host vs bare nested",
	}
}

// RepoIdentityRepairMode selects report-only or mutating repair.
type RepoIdentityRepairMode int

const (
	// RepoIdentityRepairReport lists what would change without writing.
	RepoIdentityRepairReport RepoIdentityRepairMode = iota
	// RepoIdentityRepairApply rewrites terminal provable rows and quarantines
	// the terminal unprovable ones. Non-terminal rows whose identity would
	// change are reported as active_requires_drain and left untouched unless
	// RepoIdentityRepairOptions.CancelActive is set.
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
	// ActiveRequiresDrain counts non-terminal run/job rows whose effective
	// identity would change but which were NOT touched because --cancel-active
	// was not requested. In report mode they are a subset of Scanned; in apply
	// mode they are the rows the operator still has to drain.
	ActiveRequiresDrain int
	// Drained counts rows the --cancel-active pass actually cancelled before
	// applying their identity change.
	Drained int
	// Conflicts counts rows the guarded UPDATE could not claim under the row
	// lock (a disappeared row, a guard that matched nothing, or a run that
	// gained a child job outside the locked set). They are NOT counted as
	// repaired or quarantined.
	Conflicts int
	Entries   []RepoIdentityRepairEntry
}

// RepoIdentityRepairOptions tunes one repair pass. The zero value is the
// operator default.
type RepoIdentityRepairOptions struct {
	// BatchSize is the keyset page size (the LIMIT of each batch). <= 0 uses
	// KIWI_REPO_IDENTITY_REPAIR_BATCH_SIZE when it parses to a positive value,
	// otherwise defaultRepoIdentityRepairBatchSize. An explicit positive value
	// is clamped to the documented [minRepoIdentityRepairBatchSize,
	// maxRepoIdentityRepairBatchSize] contract; see
	// clampRepoIdentityRepairBatchSize for the operator semantics.
	BatchSize int
	// CancelActive enables the explicit drain-then-rewrite path for a
	// non-terminal run/job whose effective identity would change. Without it
	// such a row is reported as active_requires_drain and left untouched (see
	// the file comment).
	CancelActive bool
}

const (
	// defaultRepoIdentityRepairBatchSize is the operator default: inside the
	// recommended 500..2000 range, large enough to keep the batch count small
	// and small enough that memory never scales with the table size.
	defaultRepoIdentityRepairBatchSize = 1000
	// minRepoIdentityRepairBatchSize is the documented low clamp. The
	// RECOMMENDED operator range is 500..2000 (each batch is one transaction,
	// so a smaller page means more commits and a slower pass, while a larger
	// one holds more row locks per transaction); values below the floor of 1
	// are not a meaningful page size. Small explicit values are honored
	// (rather than raised to 500) so tests and diagnostics can drive the
	// keyset/batch contract deterministically. This is a deliberate change to
	// the earlier "500..2000 only" wording: the hard contract is [1, 2000].
	minRepoIdentityRepairBatchSize = 1
	// maxRepoIdentityRepairBatchSize caps an explicit override at the top of
	// the documented range.
	maxRepoIdentityRepairBatchSize = 2000
)

// clampRepoIdentityRepairBatchSize applies the documented batch-size contract.
// A caller therefore always observes batchSize in
// [minRepoIdentityRepairBatchSize, maxRepoIdentityRepairBatchSize] for every
// input (the caller resolves env/default first), and the operator semantics
// are "one transaction per batch, recommended 500..2000".
func clampRepoIdentityRepairBatchSize(batchSize int) int {
	if batchSize < minRepoIdentityRepairBatchSize {
		return minRepoIdentityRepairBatchSize
	}
	if batchSize > maxRepoIdentityRepairBatchSize {
		return maxRepoIdentityRepairBatchSize
	}
	return batchSize
}

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

// repoIdentityRepairNonTerminalJobsSQL is the shared run-child predicate: the
// child jobs a run's cancellation/classification touches. It matches the
// lease-acquisition predicate's terminal set.
const repoIdentityRepairNonTerminalJobsSQL = `status NOT IN ('success','failure','cancelled','skipped','blocked')`

// repoIdentityRepairChildLockSQL is the run-child lock statement of the repair:
// every non-terminal child job of the run, locked in deterministic id order
// (ORDER BY id ASC, the canonical run-cancellation order) and always BEFORE the
// run row itself (lockRepoIdentityRepairRunTx). It deliberately does not touch
// the run row, so the run lock is never taken ahead of a job lock.
const repoIdentityRepairChildLockSQL = `SELECT id FROM jobs WHERE run_id=$1 AND ` + repoIdentityRepairNonTerminalJobsSQL + ` ORDER BY id ASC FOR UPDATE`

// repoIdentityRepairTable bundles the per-kind SQL fragments.
type repoIdentityRepairTable struct {
	kind       string // "run" or "job"
	table      string // "runs" or "jobs"
	oldURLExpr string // payload field carrying the clone URL
	batchSQL   string
	// lockedSQL is the FOR UPDATE re-read of one row by id. A JOB row is
	// locked on its own (a job lock is the FIRST lock of every job->run
	// transaction, so there is nothing to order it against). A RUN row omits
	// the hasActiveChildren EXISTS on purpose: the run's non-terminal child
	// jobs are locked BEFORE the run (lockRepoIdentityRepairRunTx) and the
	// flag is derived from those locked rows, so no job lock is ever taken
	// after the run lock.
	lockedSQL string
}

func newRepoIdentityRepairTables() []repoIdentityRepairTable {
	run := repoIdentityRepairTable{
		kind:       "run",
		table:      "runs",
		oldURLExpr: "payload->>'repo'",
		batchSQL: `SELECT id, COALESCE(payload->>'repo_id',''), COALESCE(payload->>'policy_repo_id',''), ` +
			`COALESCE(payload->>'repo',''), COALESCE(payload->>'repo_full_name',''), COALESCE(status,''), created_at, ` +
			`EXISTS(SELECT 1 FROM jobs j WHERE j.run_id = runs.id AND j.` + repoIdentityRepairNonTerminalJobsSQL + `) ` +
			`FROM runs WHERE (created_at, id) > ($1::timestamptz, $2::text) ` +
			`ORDER BY created_at ASC, id ASC LIMIT $3`,
		lockedSQL: `SELECT id, COALESCE(payload->>'repo_id',''), COALESCE(payload->>'policy_repo_id',''), ` +
			`COALESCE(payload->>'repo',''), COALESCE(payload->>'repo_full_name',''), COALESCE(status,''), created_at ` +
			`FROM runs WHERE id=$1 FOR UPDATE`,
	}
	job := repoIdentityRepairTable{
		kind:       "job",
		table:      "jobs",
		oldURLExpr: "payload->>'repo_url'",
		batchSQL: `SELECT id, COALESCE(payload->>'repo_id',''), COALESCE(payload->>'policy_repo_id',''), ` +
			`COALESCE(payload->>'repo_url',''), COALESCE(payload->>'repo_full_name',''), COALESCE(status,''), created_at, FALSE ` +
			`FROM jobs WHERE (created_at, id) > ($1::timestamptz, $2::text) ` +
			`ORDER BY created_at ASC, id ASC LIMIT $3`,
		lockedSQL: `SELECT id, COALESCE(payload->>'repo_id',''), COALESCE(payload->>'policy_repo_id',''), ` +
			`COALESCE(payload->>'repo_url',''), COALESCE(payload->>'repo_full_name',''), COALESCE(status,''), created_at, FALSE ` +
			`FROM jobs WHERE id=$1 FOR UPDATE`,
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
	batchSize = clampRepoIdentityRepairBatchSize(batchSize)
	if mode == RepoIdentityRepairApply {
		if err := s.ensureRepoIdentityQuarantineSchema(ctx); err != nil {
			return result, err
		}
	}
	for _, table := range newRepoIdentityRepairTables() {
		if err := s.repairRepoIdentityTable(ctx, mode, table, batchSize, opts.CancelActive, &result); err != nil {
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
func (s *PostgresStore) repairRepoIdentityTable(ctx context.Context, mode RepoIdentityRepairMode, table repoIdentityRepairTable, batchSize int, cancelActive bool, result *RepoIdentityRepairResult) error {
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
				err = s.runRepoIdentityRepairBatch(ctx, tx, table, records, batchIndex, cancelActive, result)
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
			if err := s.runRepoIdentityRepairBatch(ctx, nil, table, records, batchIndex, cancelActive, result); err != nil {
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
func (s *PostgresStore) runRepoIdentityRepairBatch(ctx context.Context, tx pgx.Tx, table repoIdentityRepairTable, records []repoIdentityRepairRow, batchIndex int, cancelActive bool, result *RepoIdentityRepairResult) error {
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
			plan := ClassifyRepoIdentityWithChildren(r.repoID, r.url, r.full, model.Status(r.status), r.hasActiveChildren)
			switch plan.Action {
			case RepoIdentityKeep:
				result.Unchanged++
				continue
			case RepoIdentityActiveRequiresDrain:
				result.ActiveRequiresDrain++
			case RepoIdentityQuarantineTerminal:
				result.Quarantined++
			default: // RepoIdentityRewriteTerminal
				result.Rewritten++
			}
			result.Entries = append(result.Entries, RepoIdentityRepairEntry{
				Kind: table.kind, ID: r.id, Stored: r.repoID, Repaired: plan.Explicit,
				Action: plan.Action, Reason: plan.Reason,
			})
			continue
		}
		if err := s.applyRepoIdentityRecord(ctx, tx, table, r, cancelActive, result); err != nil {
			return err
		}
	}
	return nil
}

// applyRepoIdentityRecord claims one row with the guarded UPDATE, classifying
// from the values it locked under the documented lock order: a run's
// non-terminal child jobs are locked first (deterministic id order), then the
// run row; a job is locked on its own row. Holding those locks, no concurrent
// writer can move the row between the locked read and the UPDATE, so the
// guarded UPDATE can only fail on foreign/inconsistent state — there is no
// optimistic re-read/re-plan loop to run, and a zero-row match is reported as
// a distinct conflict instead of a phantom repair. Counters move only after a
// successful UPDATE (R1-4).
//
// An active_requires_drain row is left untouched unless cancelActive is set,
// in which case it is cancelled through the canonical cancellation
// transaction (cancelJobTx/cancelRunRowTx, quota released under the OLD
// identity) BEFORE the guarded identity UPDATE (T1-1/T1-2).
func (s *PostgresStore) applyRepoIdentityRecord(ctx context.Context, tx pgx.Tx, table repoIdentityRepairTable, r repoIdentityRepairRow, cancelActive bool, result *RepoIdentityRepairResult) error {
	if h := s.repoIdentityRepairHooks; h != nil && h.BeforeApply != nil {
		if err := h.BeforeApply(table.kind, r.id); err != nil {
			return err
		}
	}
	// Finding 6: re-read and LOCK the current row(s) before any destructive
	// action, and classify from those locked values. A concurrent writer that
	// changed the row after the batch read must never be cancelled for an
	// identity it no longer carries.
	var (
		locked         repoIdentityRepairRow
		lockedChildren []string
		extraChildren  bool
		found          bool
		lerr           error
	)
	if table.kind == "run" {
		locked, lockedChildren, extraChildren, found, lerr = lockRepoIdentityRepairRunTx(ctx, tx, table, r.id)
	} else {
		locked, found, lerr = readRepoIdentityRepairRecordLocked(ctx, tx, table, r.id)
	}
	if lerr != nil {
		return lerr
	}
	if !found {
		result.Conflicts++
		result.Entries = append(result.Entries, RepoIdentityRepairEntry{
			Kind: table.kind, ID: r.id, Stored: r.repoID, Repaired: "",
			Action: RepoIdentityConflict, Reason: "row disappeared before the repair could lock it",
		})
		return nil
	}
	r = locked
	plan := ClassifyRepoIdentityWithChildren(r.repoID, r.url, r.full, model.Status(r.status), r.hasActiveChildren)
	if plan.Action == RepoIdentityKeep {
		result.Unchanged++
		return nil
	}
	active := plan.Action == RepoIdentityActiveRequiresDrain
	if active && !cancelActive {
		// Report only: never silently rewrite (or quarantine) a row whose
		// lease/queue slot was admitted under the old identity.
		result.ActiveRequiresDrain++
		result.Entries = append(result.Entries, RepoIdentityRepairEntry{
			Kind: table.kind, ID: r.id, Stored: r.repoID, Repaired: plan.Explicit,
			Action: RepoIdentityActiveRequiresDrain, Reason: plan.Reason,
		})
		return nil
	}
	if extraChildren {
		// A non-terminal child appeared between the child scan and the run
		// lock (a concurrent requeue of a terminal row, or a raw job insert).
		// Cancelling it now would take a job lock while the run lock is held —
		// the exact run -> job inversion the lock order forbids — so the row
		// is left untouched and reported as a conflict for the operator to
		// re-run. It is still classified from the locked values PLUS the extra
		// child (hasActiveChildren is true), so the plain apply path above can
		// never rewrite the run behind an active child's back.
		result.Conflicts++
		result.Entries = append(result.Entries, RepoIdentityRepairEntry{
			Kind: table.kind, ID: r.id, Stored: r.repoID, Repaired: plan.Explicit,
			Action: RepoIdentityConflict, Reason: "run gained a non-terminal child job while its children were being locked; re-run the repair",
		})
		return nil
	}
	desired := plan.Action
	if active {
		desired = plan.Desired
	}
	// Drain the active row (or cascade a run quarantine to its
	// non-terminal children) BEFORE the guarded identity UPDATE, so the
	// quota is released under the identity the row still carries. For a run
	// the cascade uses exactly the child rows locked before the run row.
	drained, err := s.drainRepoIdentityRowTx(ctx, tx, table, r, desired, lockedChildren)
	if err != nil {
		return err
	}
	// A fork PR's policy_repo_id is the BASE repository: only rewrite it
	// when it is the same value as the checkout identity.
	repairedPolicy := plan.Explicit
	if strings.TrimSpace(r.policyID) != strings.TrimSpace(r.repoID) {
		repairedPolicy = r.policyID
	}
	oldVals, applied, err := applyGuardedRepoIdentity(ctx, tx, table, r, desired, plan.Explicit, repairedPolicy)
	if err != nil {
		return err
	}
	if !applied {
		// The row is locked and the guard compares the identity against that
		// locked value, so a zero-row match means foreign/inconsistent state
		// (never a concurrent-writer race): report it rather than counting a
		// phantom repair.
		result.Conflicts++
		result.Entries = append(result.Entries, RepoIdentityRepairEntry{
			Kind: table.kind, ID: r.id, Stored: r.repoID, Repaired: plan.Explicit,
			Action: RepoIdentityConflict, Reason: "guarded identity UPDATE matched no row under the row lock; state is inconsistent",
		})
		return nil
	}
	if desired == RepoIdentityQuarantineTerminal {
		if err := insertRepoIdentityQuarantine(ctx, tx, table.kind, r.id, oldVals, plan.Reason); err != nil {
			return err
		}
		result.Quarantined++
	} else {
		result.Rewritten++
	}
	if drained && active {
		result.Drained++
	}
	result.Entries = append(result.Entries, RepoIdentityRepairEntry{
		Kind: table.kind, ID: r.id, Stored: r.repoID, Repaired: plan.Explicit,
		Action: desired, Reason: plan.Reason,
	})
	return nil
}

// drainRepoIdentityRowTx performs the cancellation half of an identity change
// for one row, inside the caller's transaction. The quota release therefore
// always happens under the identity the row still carries, before the guarded
// UPDATE rewrites it.
//
// A TERMINAL row needs no cancellation of its own: the guarded UPDATE writes
// the flag/identity under its own row lock, so touching the row here would only
// hold a lock the guarded UPDATE does not need. A terminal RUN may still have
// non-terminal children (an inconsistent but possible tree), so it cascades to
// the child jobs locked BEFORE the run row (lockedChildren); a terminal JOB is
// left to the guarded UPDATE. A non-terminal (active) row is cancelled through
// cancelJobTx/cancelRunRowTx exactly like CancelRunJobs.
//
// The RUN cascade never re-scans for child jobs: a re-scan under the held run
// lock could observe a concurrently requeued child and wait for its job lock
// AFTER the run lock, inverting the job -> run order this repair guarantees
// (see lockRepoIdentityRepairRunTx; such a child is reported as a conflict by
// applyRepoIdentityRecord instead).
func (s *PostgresStore) drainRepoIdentityRowTx(ctx context.Context, tx pgx.Tx, table repoIdentityRepairTable, r repoIdentityRepairRow, desired RepoIdentityRepairAction, lockedChildren []string) (bool, error) {
	reason := RepoIdentityDrainReason
	cause := JobCancelRepairDrain
	if desired == RepoIdentityQuarantineTerminal {
		reason = RepoIdentityQuarantineReason
		cause = JobCancelQuarantine
	}
	terminal := model.Status(r.status).Terminal()
	if table.kind == "job" {
		if terminal {
			return false, nil
		}
		return s.cancelJobTx(ctx, tx, r.id, reason, cause)
	}
	cancelledChildren, err := s.cancelRepoIdentityLockedChildrenTx(ctx, tx, lockedChildren, reason, cause)
	if err != nil {
		return false, err
	}
	if terminal {
		// The terminal run itself is quarantined/rewritten by the guarded
		// UPDATE; only its locked non-terminal children need the cascade.
		return cancelledChildren, nil
	}
	return s.cancelRunRowTx(ctx, tx, r.id, reason, cause)
}

// lockRepoIdentityRepairRunTx locks one run for an identity repair in the
// established job -> run order: FIRST the run's non-terminal child jobs in
// deterministic id order, THEN the run row. It returns the locked row, the
// child ids it locked, and whether a non-terminal child appeared outside that
// locked set (extraChildren).
//
// The run's hasActiveChildren flag is derived from the locked child rows plus
// the post-lock count, never from an unlocked snapshot, so the run is
// rewritten only when no active child can be left behind. Because the child
// scan precedes the run lock, the repair never waits for a job lock while
// holding the run lock: a concurrent CompleteJob (job -> run) either holds the
// child row and makes the repair wait at the child lock, or waits on the run
// lock after the repair committed — no lock cycle, no 40P01.
func lockRepoIdentityRepairRunTx(ctx context.Context, tx pgx.Tx, table repoIdentityRepairTable, runID string) (repoIdentityRepairRow, []string, bool, bool, error) {
	children, err := lockRepoIdentityRepairChildJobs(ctx, tx, runID)
	if err != nil {
		return repoIdentityRepairRow{}, nil, false, false, err
	}
	r, found, err := readRepoIdentityRepairRecordLocked(ctx, tx, table, runID)
	if err != nil || !found {
		return r, children, false, found, err
	}
	// The run row is locked now, so new rows cannot be inserted under it
	// (the FK key-share conflicts with FOR UPDATE); re-read the non-terminal
	// child set and treat any child outside the locked set as extra. Locked
	// children are still non-terminal (we hold their locks and have not
	// modified them), so the count is always >= len(children).
	var activeChildren int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM jobs WHERE run_id=$1 AND `+repoIdentityRepairNonTerminalJobsSQL, runID).Scan(&activeChildren); err != nil {
		return repoIdentityRepairRow{}, nil, false, false, err
	}
	r.hasActiveChildren = activeChildren > 0
	return r, children, activeChildren > len(children), true, nil
}

// lockRepoIdentityRepairChildJobs locks the run's non-terminal child jobs in
// deterministic id order (ORDER BY id ASC), the order the canonical run
// cancellation uses, and returns their ids. A terminal child is never locked
// (nothing to cancel); a child that turns terminal while the lock query waits
// is skipped by the FOR UPDATE predicate re-check.
func lockRepoIdentityRepairChildJobs(ctx context.Context, tx pgx.Tx, runID string) ([]string, error) {
	rows, err := tx.Query(ctx, repoIdentityRepairChildLockSQL, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// cancelRepoIdentityLockedChildrenTx cancels exactly the child job ids that
// were locked before the run row (lockRepoIdentityRepairRunTx) through the
// canonical cancelJobTx. Every id is already locked by this transaction, so no
// job lock is taken AFTER the run lock; a child that appeared after the run
// lock is left to the conflict report, never cancelled here. It reports
// whether any child was actually transitioned.
func (s *PostgresStore) cancelRepoIdentityLockedChildrenTx(ctx context.Context, tx pgx.Tx, jobIDs []string, reason string, cause JobCancelCause) (bool, error) {
	cancelled := false
	for _, id := range jobIDs {
		ok, err := s.cancelJobTx(ctx, tx, id, reason, cause)
		if err != nil {
			return false, err
		}
		if ok {
			cancelled = true
		}
	}
	return cancelled, nil
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
		if err := rows.Scan(&r.id, &r.repoID, &r.policyID, &r.url, &r.full, &r.status, &r.createdAt, &r.hasActiveChildren); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// applyGuardedRepoIdentity executes the guarded, single-statement UPDATE for
// one row and returns the pre-update values it replaced. The statement builds
// the new payload in a CTE (PostgreSQL cannot reuse a SET alias), restamps the
// run's materialized identity columns from the NEW payload in the SAME
// statement (R1-1), and — for a quarantine — writes the durable flag and, for
// queued/running work, transitions it to cancelled (R1-6). The guarded UPDATE
// is the data-modifying CTE, so a zero-row match is observable (applied=false)
// and no counter can advance on a phantom repair (R1-4).
func applyGuardedRepoIdentity(ctx context.Context, tx pgx.Tx, table repoIdentityRepairTable, r repoIdentityRepairRow, desired RepoIdentityRepairAction, explicit, repairedPolicy string) (repoIdentityRepairRow, bool, error) {
	quarantine := desired == RepoIdentityQuarantineTerminal
	sql := repoIdentityRepairGuardedUpdateSQL(table, quarantine)
	args := []any{r.id, explicit, repairedPolicy, r.repoID}
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

// readRepoIdentityRepairRecordLocked reads one row FOR UPDATE inside the
// caller's transaction so classification and any cancellation act on the
// committed, locked state rather than a stale batch snapshot. A JOB's
// hasActiveChildren column is the constant FALSE (a job has no children); a
// RUN's is derived by the caller from the child rows it locked first (see
// lockRepoIdentityRepairRunTx).
func readRepoIdentityRepairRecordLocked(ctx context.Context, tx pgx.Tx, table repoIdentityRepairTable, id string) (repoIdentityRepairRow, bool, error) {
	var r repoIdentityRepairRow
	dest := []any{&r.id, &r.repoID, &r.policyID, &r.url, &r.full, &r.status, &r.createdAt}
	if table.kind != "run" {
		dest = append(dest, &r.hasActiveChildren)
	}
	err := tx.QueryRow(ctx, table.lockedSQL, id).Scan(dest...)
	if errors.Is(err, pgx.ErrNoRows) {
		return repoIdentityRepairRow{}, false, nil
	}
	if err != nil {
		return repoIdentityRepairRow{}, false, err
	}
	return r, true, nil
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
	// Lifecycle (status, finished_at, error) is written ONLY by the canonical
	// cancellation transaction (cancelJobTx/cancelRunTx); the identity UPDATE
	// never mutates it, so a stale identity never cancels work by itself.
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

// repoIdentityRepairRow is one runs/jobs payload's identity fields, its
// lifecycle status, plus its keyset position.
type repoIdentityRepairRow struct {
	id, repoID, policyID, url, full, status string
	createdAt                               time.Time
	// hasActiveChildren is true when a RUN still owns a non-terminal child
	// job. A run's lifecycle cannot be judged from its own status alone when
	// the operation may cascade into jobs, so such a run is classified
	// active_requires_drain even when its own status is terminal.
	hasActiveChildren bool
}
