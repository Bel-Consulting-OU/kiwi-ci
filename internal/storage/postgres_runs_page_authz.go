package storage

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Authorized keyset pagination for the runs collection.
//
// GET /api/v1/runs spans every repository, so a caller must only ever observe
// runs of repositories it is authorized to read. The pre-fix handler paged
// the GLOBAL collection first and filtered per run afterwards: the page
// boundary (and therefore X-Kiwi-Next-Cursor) was derived from the last row
// of the UNFILTERED page, so a repository-scoped reader received short or
// empty pages whose cursor exposed the creation timestamp and run ID of a
// run they cannot read, and repeated paging leaked the density of
// inaccessible activity. RunPageAuthorizedStore is the store-level contract
// that closes this: the principal's permitted canonical repository predicate
// is applied INSIDE the SAME query that computes the keyset boundary, so
// every externally visible position (returned rows, HasMore,
// NextCreatedAt/NextID) is derived from an authorized row only.
//
// The authorization policy is normalized ONCE per request by
// RunAuthzPolicyForPrincipal from the principal's repository grants; the
// resulting predicate is pushed directly into the ordered, index-backed run
// query with LIMIT n+1. Nothing enumerates the repositories present in the
// collection: the query cost is O(page size + index traversal), not
// O(repository cardinality). The memory implementation applies the same
// normalized policy before paging (filter-before-paging), so the two modes
// agree run-for-run.
//
// The predicate compares the run's MATERIALIZED normalized identity columns
// (repo_identity_normalized / repo_full_name_normalized, stamped on every
// write and backfilled by migration 0034) through a NULL-tolerant COALESCE
// fallback to the shared IMMUTABLE derivation functions (migration 0036,
// rolling-upgrade gap R3-A), by simple equality, so the page is served by the
// (repo_identity_normalized, created_at DESC, id) /
// (repo_full_name_normalized, created_at DESC, id) indexes instead of
// re-deriving the identity from the JSONB payload row by row — the pre-fix
// predicate parsed identity with SUBSTRING/STRPOS/CASE/LOWER/REGEXP_REPLACE
// inside the page predicate, so a sparse tenant could force a long walk of
// the created-at index. The 0036 indexes are created on the identical COALESCE
// expression, so equality stays index-backed even for a NULL row written by a
// pre-0034 replica, which is otherwise permanently invisible.
//
// The predicate mirrors auth.CanReadRepo exactly for the canonical policy
// repository identity of a run (RepoIDForRun: stored policy_repo_id first,
// then repo_id / clone-URL + full-name):
//
//   - unrestricted global read (no principal, admin, or a global read role
//     with no repository entries) matches every run and bypasses the
//     predicate entirely;
//   - an exact canonical grant (same canonical host and full name) authorizes
//     its identity;
//   - an explicit bare alias authorizes the identity's full name on ANY forge
//     (a bare grant is host-agnostic), and never authorizes a bare candidate
//     through a canonical grant;
//   - an explicit entry for a repository is authoritative: a non-read entry
//     (Read=false) DENIES the repository instead of falling through to the
//     global read role;
//   - conflicting equivalent grant spellings (different permission sets for
//     the same canonical identity, or for the same bare name) fail closed:
//     the repository is denied outright and never falls through to roles.
//
// The cursor/order/limit contract is otherwise identical to RunPageStore (see
// postgres_runs_page.go).

// RunAuthzPolicy is the normalized repository-read visibility policy of one
// request: the typed grant sets a collection query can apply directly. It is
// built once per request by RunAuthzPolicyForPrincipal and is immutable
// thereafter. The zero value denies every run (it is a principal with no read
// capability at all); use RunAuthzPolicyForPrincipal(nil) for the
// unrestricted form. The fields are unexported so the only way to obtain a
// policy is the constructor, keeping SQL and memory rendering in lockstep.
type RunAuthzPolicy struct {
	// unrestricted matches every repository (no principal, admin role, or a
	// global read role with no repository entries). It short-circuits both
	// implementations to the unfiltered page.
	unrestricted bool
	// globalRead is the global read role: repositories with no explicit
	// entry are visible, but an explicit non-read entry still denies.
	globalRead bool

	// identityRead holds the canonical identity IDs ("host/full name") whose
	// effective entry grants Read. The remaining sets encode presence and
	// conflict so an explicit entry suppresses the alias/global fallback.
	identityRead     []string
	identityPresent  []string
	identityConflict []string

	// aliasRead holds the bare full names whose effective entry grants Read;
	// aliasPresent/aliasConflict mirror the identity sets for bare grants.
	aliasRead     []string
	aliasPresent  []string
	aliasConflict []string
}

// RunAuthzPolicyForPrincipal normalizes a principal's repository grants into
// a RunAuthzPolicy. A nil principal is the unrestricted form (the caller has
// already passed the coarse read gate); so are the admin role and a global
// read role with no repository entries (with no entry there is nothing that
// could deny a repository, so the decision is "everything"). Every other
// principal gets an exact policy; grants are parsed with the same typed
// positional rule auth.CanReadRepo uses (auth.ParseStoredRepoID), and
// conflicting equivalent spellings are recorded as conflicts (fail closed).
func RunAuthzPolicyForPrincipal(p *auth.Principal) RunAuthzPolicy {
	if p == nil || p.Has(auth.RoleAdmin) {
		return RunAuthzPolicy{unrestricted: true, globalRead: true}
	}
	pol := RunAuthzPolicy{globalRead: p.Has(auth.RoleRead)}
	if len(p.Repositories) == 0 {
		pol.unrestricted = pol.globalRead
		return pol
	}
	identPerm := map[string]auth.RepositoryPermission{}
	identConflict := map[string]bool{}
	aliasPerm := map[string]auth.RepositoryPermission{}
	aliasConflict := map[string]bool{}
	record := func(m map[string]auth.RepositoryPermission, conflicts map[string]bool, key string, perm auth.RepositoryPermission) {
		if prev, ok := m[key]; ok {
			if prev != perm {
				conflicts[key] = true
			}
			return
		}
		m[key] = perm
	}
	for key, perm := range p.Repositories {
		grant, err := auth.ParseStoredRepoID(key)
		if err != nil {
			// An unusable key can never match a repository; skip it.
			continue
		}
		if grant.IsAlias() {
			a, _ := grant.Alias()
			record(aliasPerm, aliasConflict, a.FullName, perm)
			continue
		}
		id, _ := grant.Identity()
		record(identPerm, identConflict, id.ID(), perm)
	}
	for id, perm := range identPerm {
		pol.identityPresent = append(pol.identityPresent, id)
		if identConflict[id] {
			pol.identityConflict = append(pol.identityConflict, id)
			continue
		}
		if perm.Read {
			pol.identityRead = append(pol.identityRead, id)
		}
	}
	for name, perm := range aliasPerm {
		pol.aliasPresent = append(pol.aliasPresent, name)
		if aliasConflict[name] {
			pol.aliasConflict = append(pol.aliasConflict, name)
			continue
		}
		if perm.Read {
			pol.aliasRead = append(pol.aliasRead, name)
		}
	}
	sort.Strings(pol.identityRead)
	sort.Strings(pol.identityPresent)
	sort.Strings(pol.identityConflict)
	sort.Strings(pol.aliasRead)
	sort.Strings(pol.aliasPresent)
	sort.Strings(pol.aliasConflict)
	return pol
}

// IsUnrestricted reports whether the policy matches every repository. The
// unfiltered ListRunsPage path is used for it, so the unrestricted read stays
// byte-identical to the historical contract.
func (p RunAuthzPolicy) IsUnrestricted() bool { return p.unrestricted }

// splitRepoCandidate classifies a canonical policy repository ID with the
// typed positional rule (auth.ParseStoredRepoID): two or more path segments
// (a slash after the first segment, dotted OR dotless host) is a canonical
// identity whose full name is the remainder; fewer segments is a bare alias
// whose full name is the whole value. The SQL mirror is the canonical
// policy-first expression in normalizedRunRepoFullNameFunctionBody (the same
// STRPOS/SUBSTRING rule), materialized into repo_full_name_normalized.
func splitRepoCandidate(repoID string) (canonical bool, fullName string) {
	i := strings.Index(repoID, "/")
	if i < 0 {
		return false, foldRepoCandidate(repoID)
	}
	suffix := repoID[i+1:]
	if strings.Contains(suffix, "/") {
		return true, foldRepoCandidate(suffix)
	}
	return false, foldRepoCandidate(repoID)
}

// foldRepoCandidate folds a candidate repository value onto the one canonical
// path case (auth.FoldRepoFullName) EXCEPT for the explicit r1:/a1: serialized
// spellings, whose base64url payload is case-significant and must never be
// lowercased. It is the Go mirror of the SQL fold in
// canonicalRepoIDBody / normalizedRunRepo*FunctionBody, so the materialized
// columns and the in-memory decision can never disagree on case.
func foldRepoCandidate(s string) string {
	if strings.HasPrefix(s, auth.RepoIdentityPrefix) || strings.HasPrefix(s, auth.RepoAliasPrefix) {
		return s
	}
	return auth.FoldRepoFullName(s)
}

// canonicalCandidateID canonicalizes the HOST segment of a canonical candidate
// identity exactly as auth.CanonicalHost does for the grant keys, so a legacy
// row whose persisted/derived host is spelled with different case, a trailing
// dot or the scheme's default port resolves to the same identity as its
// canonical grant (the pre-fix auth.CanReadRepo canonicalized the candidate;
// normalizedRunRepoIdentityFunctionBody mirrors this helper with the SQL
// canonicalHostSQL expression, materialized into repo_identity_normalized).
func canonicalCandidateID(repoID, fullName string) string {
	i := strings.Index(repoID, "/")
	if i < 0 {
		return repoID
	}
	host := auth.CanonicalHost(repoID[:i])
	if host == "" {
		return repoID
	}
	return host + "/" + foldRepoCandidate(fullName)
}

// Allows reports whether the policy authorizes repoID. It is the in-memory
// half of the predicate: PageRunsAuthorized filters with it and SQL renders
// the identical decision, so the memory and durable pages cannot disagree.
// The precedence matches RunAuthzPolicyForPrincipal's documented contract:
// conflict, then explicit canonical entry, then explicit bare entry, then the
// global read role; the empty identity has no entry and is decided by the
// global read role alone. A canonical candidate's host is canonicalized before
// the identity comparison, so legacy host spellings match their canonical
// grant; alias comparisons use the bare full name unchanged.
func (p RunAuthzPolicy) Allows(repoID string) bool {
	if p.unrestricted {
		return true
	}
	if repoID == "" {
		return p.globalRead
	}
	canonical, fullName := splitRepoCandidate(repoID)
	if canonical {
		id := canonicalCandidateID(repoID, fullName)
		if containsString(p.identityConflict, id) {
			return false
		}
		if containsString(p.identityPresent, id) {
			return containsString(p.identityRead, id)
		}
		if containsString(p.aliasConflict, fullName) {
			return false
		}
		if containsString(p.aliasPresent, fullName) {
			return containsString(p.aliasRead, fullName)
		}
		return p.globalRead
	}
	// Bare/alias candidate: splitRepoCandidate already folded the value onto
	// the canonical path case (untagged only), so the alias entry comparison
	// is case-insensitive exactly like the SQL full-name predicate.
	if containsString(p.aliasConflict, fullName) {
		return false
	}
	if containsString(p.aliasPresent, fullName) {
		return containsString(p.aliasRead, fullName)
	}
	return p.globalRead
}

// sqlPredicate renders the SQL equivalent of Allows against the EFFECTIVE
// normalized policy repository identity of a run: identityExpr is the
// NULL-tolerant repo_identity_normalized expression (the canonical "host/full"
// for a canonical identity, ” for a bare one) and fullNameExpr is the
// NULL-tolerant repo_full_name_normalized expression (the owner/name remainder
// for a canonical identity, the whole value for a bare one). Both are stamped
// on every run write and backfilled by migration 0034; the COALESCE fallback
// (migration 0036) derives them through the SAME IMMUTABLE functions for a row
// written by a pre-0034 replica during a rolling upgrade, which leaves the
// columns NULL. Because the fallback closes over the columns, the expression
// remains equality over an index — no SUBSTRING / STRPOS / CASE / LOWER /
// REGEXP_REPLACE parsing inside the page predicate, which is what made a
// sparse tenant walk the created-at index — and the migration-0036 keyset
// indexes are created on the identical COALESCE expression.
//
// It appends every bound array to args and returns a boolean expression. The
// unrestricted policy renders TRUE (the caller normally bypasses the
// predicate entirely). The canonical read-grant-only case (no aliases, no
// explicit denies, no conflicts, no global read) simplifies to one equality
// over the effective identity. Every other shape falls back to the fully
// general predicate; both are part of the single ordered keyset query with
// LIMIT n+1 and no collection-wide enumeration or DISTINCT. The Go half of
// each decision is Allows (and auth.CanReadRepo); the parity corpus IT pins
// them together.
func (p RunAuthzPolicy) sqlPredicate(identityExpr, fullNameExpr string, args *[]any) string {
	if p.unrestricted {
		return "TRUE"
	}
	// A canonical identity always carries its host, so its normalized identity
	// is non-empty; a bare identity has no canonical identity at all. This is
	// exactly splitRepoCandidate's >= 2 path segments rule.
	canonical := identityExpr + " <> ''"

	if !p.globalRead && len(p.aliasPresent) == 0 && len(p.aliasRead) == 0 && len(p.aliasConflict) == 0 &&
		len(p.identityConflict) == 0 && len(p.identityPresent) == len(p.identityRead) {
		if len(p.identityRead) == 0 {
			return "FALSE"
		}
		// A single granted identity is bound as a scalar equality rather than
		// `= ANY(array)`: a ScalarArrayOp index scan is not declared
		// order-preserving, so the planner would add a Sort, while `= $n`
		// walks the normalized keyset index directly in
		// (created_at DESC, id COLLATE "C" DESC) order. The decision is
		// identical.
		if len(p.identityRead) == 1 {
			*args = append(*args, p.identityRead[0])
			return "(" + canonical + " AND " + identityExpr + " = $" + strconv.Itoa(len(*args)) + ")"
		}
		return "(" + canonical + " AND " + identityExpr + " = ANY(" + textArrayArg(args, p.identityRead) + "))"
	}

	idRead := identityExpr + " = ANY(" + textArrayArg(args, p.identityRead) + ")"
	idPresent := identityExpr + " = ANY(" + textArrayArg(args, p.identityPresent) + ")"
	idConflict := identityExpr + " = ANY(" + textArrayArg(args, p.identityConflict) + ")"
	alRead := fullNameExpr + " = ANY(" + textArrayArg(args, p.aliasRead) + ")"
	alPresent := fullNameExpr + " = ANY(" + textArrayArg(args, p.aliasPresent) + ")"
	alConflict := fullNameExpr + " = ANY(" + textArrayArg(args, p.aliasConflict) + ")"

	// Canonical candidate: conflict, then explicit identity entry, then the
	// explicit bare entry fallback, then the global read role.
	canonicalRead := "(" + idRead + " OR (NOT " + idPresent + " AND (" + alRead +
		" OR (NOT " + alPresent + " AND " + sqlBool(p.globalRead) + "))))"
	canonicalConflict := "(" + idConflict + " OR (NOT " + idPresent + " AND " + alConflict + "))"
	canonicalArm := "(" + canonical + " AND " + canonicalRead + " AND NOT " + canonicalConflict + ")"

	// Bare-alias candidate: only explicit bare grants are consulted; a
	// canonical grant never authorizes another forge's repository.
	aliasArm := "(NOT " + canonical + " AND " + fullNameExpr + " <> '' AND NOT " + alConflict +
		" AND (" + alRead + " OR (NOT " + alPresent + " AND " + sqlBool(p.globalRead) + ")))"

	// The empty identity carries no repository identity, so only the global
	// read role decides it (auth.CanReadRepo rejects it as unparsable). A
	// canonical identity always has a non-empty full name, so an empty
	// normalized full name with no canonical identity is the empty candidate.
	emptyArm := "(NOT " + canonical + " AND " + fullNameExpr + " = '' AND " + sqlBool(p.globalRead) + ")"

	return "(" + canonicalArm + " OR " + aliasArm + " OR " + emptyArm + ")"
}

// canonicalHostSQL renders hostExpr canonicalized EXACTLY the way
// auth.CanonicalHost canonicalizes a bare (already URL-stripped) host:
// lowercased, one trailing dot stripped, and the scheme's default port
// (443/80/22) dropped. The R1-A defect this pins: the pre-fix expression
// stripped a default-port suffix from EVERY unbracketed host, so an
// UNBRACKETED IPv6 literal ending in :443/:80/:22 ("::1:443") was reduced to
// "::1" while auth.CanonicalHost preserved it (its legacy "host:port" split
// applies only to a spelling with EXACTLY ONE colon). The result was a
// SQL/Go authorization divergence: a run could be visible in the collection
// under a grant for a DIFFERENT forge than the per-run RBAC path authorized.
//
// The fix mirrors auth.CanonicalHost's branches (see canonHostPort /
// splitHostPort there):
//
//   - a bracketed literal loses its brackets, its host is lowercased and one
//     trailing dot is stripped, and a following default port is dropped (a
//     non-default one is kept; a non-port tail is discarded);
//   - an unbracketed value with EXACTLY ONE colon (not leading) splits into
//     host:port when the tail is numeric — default ports dropped, non-default
//     kept — and otherwise degenerates to the legacy "host:path" host alone;
//   - an unbracketed value with zero or several colons is treated as ONE host
//     (several colons means an IPv6 literal), lowercased with one trailing
//     dot stripped and NO port stripping.
func canonicalHostSQL(hostExpr string) string {
	lower := "LOWER(" + hostExpr + ")"
	trimDot := func(expr string) string {
		return "REGEXP_REPLACE(" + expr + ", '\\.$', '')"
	}

	// Bracketed IPv6 literal. The guard keeps a truncated literal ("[::1",
	// no closing bracket) verbatim instead of running SUBSTRING with a
	// negative length.
	bracketHost := trimDot("SUBSTRING(" + lower + " FROM 2 FOR STRPOS(" + hostExpr + ", ']') - 2)")
	bracketRest := "SUBSTRING(" + lower + " FROM STRPOS(" + hostExpr + ", ']') + 1)"
	bracketLiteral := "CASE WHEN STRPOS(" + hostExpr + ", ']') > 0 THEN " + bracketHost +
		" || CASE WHEN LEFT(" + bracketRest + ", 1) <> ':' OR SUBSTRING(" + bracketRest + " FROM 2) IN ('443', '80', '22') THEN '' ELSE " + bracketRest + " END " +
		"ELSE " + trimDot(lower) + " END"

	// Unbracketed. The legacy split applies only to a value with EXACTLY ONE
	// colon at position > 1; a numeric tail is the port, anything else is the
	// legacy host:path host.
	colonCount := "(LENGTH(" + hostExpr + ") - LENGTH(REPLACE(" + hostExpr + ", ':', '')))"
	colonPos := "STRPOS(" + hostExpr + ", ':')"
	beforeColon := trimDot("LEFT(" + lower + ", " + colonPos + " - 1)")
	tail := "SUBSTRING(" + lower + " FROM " + colonPos + " + 1)"
	singleColon := "CASE WHEN " + tail + " ~ '^[+-]?[0-9]+$' THEN " + beforeColon +
		" || CASE WHEN " + tail + " IN ('443', '80', '22') THEN '' ELSE ':' || " + tail + " END " +
		"ELSE " + beforeColon + " END"
	plain := "CASE WHEN " + colonCount + " = 1 AND " + colonPos + " > 1 THEN " + singleColon +
		" ELSE " + trimDot(lower) + " END"

	return "CASE WHEN " + hostExpr + " = '' THEN '' " +
		"WHEN LEFT(" + hostExpr + ", 1) = '[' THEN " + bracketLiteral + " " +
		"ELSE " + plain + " END"
}

// normalizedRunRepoIdentityColumn and normalizedRunRepoFullNameColumn are the
// materialized identity columns added by migration 0033. The page predicate
// compares them by equality; the write path and migration 0034's backfill
// derive them through the IMMUTABLE SQL functions below, whose bodies
// normalizedRunRepoIdentityFunctionBody / normalizedRunRepoFullNameFunctionBody
// render so Go and the database can never drift.
const (
	normalizedRunRepoIdentityColumn = "repo_identity_normalized"
	normalizedRunRepoFullNameColumn = "repo_full_name_normalized"

	// canonicalHostFunctionName is the IMMUTABLE SQL function created by
	// migration 0034: it is exactly canonicalHostSQL's expression, callable
	// from the normalized-column functions (and from the parity corpus IT,
	// which compares it to auth.CanonicalHost directly).
	canonicalHostFunctionName = "kiwi_canonical_host"

	normalizedRunRepoIdentityFunctionName = "kiwi_normalize_run_repo_identity"
	normalizedRunRepoFullNameFunctionName = "kiwi_normalize_run_repo_full_name"
)

// canonicalHostFunctionBody renders the body of the IMMUTABLE SQL function
// kiwi_canonical_host(host text): the auth.CanonicalHost normalizer as SQL.
func canonicalHostFunctionBody() string {
	return canonicalHostSQL("host")
}

// normalizedRunRepoIdentitySQL is the write-path expression that stamps
// repo_identity_normalized from a run payload bound to payloadExpr (a jsonb
// placeholder or column expression). It is the function the migration
// backfills with, so a row written through any INSERT/UPDATE and a legacy row
// backfilled by 0034 resolve identically.
func normalizedRunRepoIdentitySQL(payloadExpr string) string {
	return normalizedRunRepoIdentityFunctionName + "(" + payloadExpr + ", 'repo')"
}

// normalizedRunRepoFullNameSQL is the write-path expression that stamps
// repo_full_name_normalized.
func normalizedRunRepoFullNameSQL(payloadExpr string) string {
	return normalizedRunRepoFullNameFunctionName + "(" + payloadExpr + ", 'repo')"
}

// normalizedRunRepoIdentityEffectiveSQL / normalizedRunRepoFullNameEffectiveSQL
// render the NULL-tolerant identity expressions the authorized page predicate
// compares. COALESCE falls back to the SHARED IMMUTABLE function when the
// materialized column is NULL — the row a pre-0034 replica inserted during a
// rolling upgrade — so that row is classified exactly like a canonically
// written one. Migration 0036 indexes the identical expression, so equality
// on it stays index-backed. The expression is also the Go<->SQL seam the
// rolling-upgrade regression IT asserts against.
func normalizedRunRepoIdentityEffectiveSQL() string {
	return "COALESCE(" + normalizedRunRepoIdentityColumn + ", " + normalizedRunRepoIdentitySQL("payload") + ")"
}

func normalizedRunRepoFullNameEffectiveSQL() string {
	return "COALESCE(" + normalizedRunRepoFullNameColumn + ", " + normalizedRunRepoFullNameSQL("payload") + ")"
}

// normalizedRunRepoIdentityFunctionBody renders the body of the IMMUTABLE SQL
// function kiwi_normalize_run_repo_identity(payload jsonb, url_key text): the
// canonical "host/full" identity for a canonical policy repository identity
// (>= 2 path segments), ” for a bare/empty one. The host is canonicalized by
// canonicalHostSQL and the full name is the remainder; a host that
// canonicalizes to ” leaves the raw identity (the canonicalCandidateID
// contract).
func normalizedRunRepoIdentityFunctionBody() string {
	r := normalizedRunRepoRepoExpr()
	slash := "STRPOS(" + r + ", '/')"
	suffix := "SUBSTRING(" + r + " FROM " + slash + " + 1)"
	canonical := "(" + slash + " > 0 AND STRPOS(" + suffix + ", '/') > 0)"
	hostRaw := "CASE WHEN " + slash + " > 0 THEN LEFT(" + r + ", " + slash + " - 1) ELSE '' END"
	canonHost := canonicalHostFunctionName + "(" + hostRaw + ")"
	canonID := "CASE WHEN " + canonHost + " = '' THEN " + r + " ELSE " + canonHost + " || '/' || LOWER(" + suffix + ") END"
	return "CASE WHEN " + canonical + " THEN " + canonID + " ELSE '' END"
}

// normalizedRunRepoFullNameFunctionBody renders the body of the IMMUTABLE SQL
// function kiwi_normalize_run_repo_full_name(payload jsonb, url_key text): the
// owner/name remainder for a canonical identity, the whole value for a bare
// one, and ” for the empty identity. The full name is folded onto the one
// canonical PATH case (LOWER for untagged values; the explicit r1:/a1:
// spellings are left byte-identical because their base64url payload is
// case-significant), mirroring auth.FoldRepoFullName.
func normalizedRunRepoFullNameFunctionBody() string {
	r := normalizedRunRepoRepoExpr()
	slash := "STRPOS(" + r + ", '/')"
	suffix := "SUBSTRING(" + r + " FROM " + slash + " + 1)"
	canonical := "(" + slash + " > 0 AND STRPOS(" + suffix + ", '/') > 0)"
	bare := "CASE WHEN LEFT(" + r + ", 3) IN ('r1:', 'a1:') THEN " + r + " ELSE LOWER(" + r + ") END"
	return "CASE WHEN " + canonical + " THEN LOWER(" + suffix + ") ELSE " + bare + " END"
}

// normalizedRunRepoRepoExpr renders the canonical policy-first repository
// identity inside the normalized-column SQL functions: the stored
// policy_repo_id when present, otherwise the migration-0027
// kiwi_canonical_repo_id derivation. It is the SQL mirror of RepoIDForRun.
func normalizedRunRepoRepoExpr() string {
	return "COALESCE(NULLIF(BTRIM(payload->>'policy_repo_id'), ''), " + canonicalRepoIDFunctionName + "(payload, url_key))"
}

// normalizedRunRepoBackfillSQL renders the migration-0034 backfill UPDATE: it
// derives both normalized columns for every row that does not have them yet
// (legacy rows, and rows written by a pre-upgrade binary between 0033 and
// 0034), through the same functions the write path uses.
func normalizedRunRepoBackfillSQL() string {
	return "UPDATE runs SET " + normalizedRunRepoIdentityColumn + " = " + normalizedRunRepoIdentitySQL("payload") +
		", " + normalizedRunRepoFullNameColumn + " = " + normalizedRunRepoFullNameSQL("payload") +
		" WHERE " + normalizedRunRepoIdentityColumn + " IS NULL OR " + normalizedRunRepoFullNameColumn + " IS NULL"
}

// normalizedRunRepoIdentityKeysetIndexDDL and
// normalizedRunRepoFullNameKeysetIndexDDL render the two migration-0034
// composite indexes. The id key is COLLATE "C" DESC (the query's keyset order)
// so a fixed normalized identity is walked in exactly
// (created_at DESC, id COLLATE "C" DESC) order: the page is a bounded index
// range read with no sort.
func normalizedRunRepoIdentityKeysetIndexDDL() string {
	return "CREATE INDEX IF NOT EXISTS runs_repo_identity_normalized_keyset_idx\n    ON runs (" +
		normalizedRunRepoIdentityColumn + ", created_at DESC, id COLLATE \"C\" DESC)"
}

func normalizedRunRepoFullNameKeysetIndexDDL() string {
	return "CREATE INDEX IF NOT EXISTS runs_repo_full_name_normalized_keyset_idx\n    ON runs (" +
		normalizedRunRepoFullNameColumn + ", created_at DESC, id COLLATE \"C\" DESC)"
}

// normalizedRunRepoIdentityFallbackKeysetIndexDDL and
// normalizedRunRepoFullNameFallbackKeysetIndexDDL render the migration-0036
// replacement indexes: the same composite keyset shape as the 0034 indexes,
// but on the EFFECTIVE COALESCE expression the predicate now compares. The
// expression MUST be byte-identical to normalizedRunRepo*EffectiveSQL, or the
// planner cannot serve the predicate from the index (audit class: expression
// indexes that must match query predicates). The id key stays
// COLLATE "C" DESC (the query's keyset order) so a fixed effective identity is
// walked in exactly (created_at DESC, id COLLATE "C" DESC) order.
func normalizedRunRepoIdentityFallbackKeysetIndexDDL() string {
	return "CREATE INDEX IF NOT EXISTS runs_repo_identity_normalized_keyset_idx\n    ON runs (" +
		normalizedRunRepoIdentityEffectiveSQL() + ", created_at DESC, id COLLATE \"C\" DESC)"
}

func normalizedRunRepoFullNameFallbackKeysetIndexDDL() string {
	return "CREATE INDEX IF NOT EXISTS runs_repo_full_name_normalized_keyset_idx\n    ON runs (" +
		normalizedRunRepoFullNameEffectiveSQL() + ", created_at DESC, id COLLATE \"C\" DESC)"
}

// normalizedRepoColumns returns the (repo_identity_normalized,
// repo_full_name_normalized) pair for a canonical policy repository identity,
// mirroring the SQL function bodies above exactly. It is the Go half of the
// parity corpus: the write path stamps SQL-computed values, and this helper
// lets tests (and memory-mode reasoning) derive the expected pair.
func normalizedRepoColumns(repoID string) (identity, fullName string) {
	canonical, full := splitRepoCandidate(repoID)
	if !canonical {
		return "", full
	}
	return canonicalCandidateID(repoID, full), full
}

// textArrayArg binds vals as a text[] parameter and returns its placeholder.
// A nil slice is bound as the empty array so `= ANY(...)` is FALSE rather than
// NULL (which would silently drop rows under a negation).
func textArrayArg(args *[]any, vals []string) string {
	if vals == nil {
		vals = []string{}
	}
	*args = append(*args, vals)
	return "$" + strconv.Itoa(len(*args)) + "::text[]"
}

func sqlBool(b bool) string {
	if b {
		return "TRUE"
	}
	return "FALSE"
}

// RunPageAuthorizedStore is the authorized paged-read capability of a store.
// It is deliberately separate from RunPageStore: paging an unfiltered
// collection and filtering afterwards leaks the page boundary, so a caller
// must never fall back to RunPageStore — a store without this capability
// fails closed (the server answers an opaque 500).
type RunPageAuthorizedStore interface {
	// ListRunsPageAuthorized returns one keyset page of runs whose canonical
	// POLICY repository identity (RepoIDForRun) is authorized by policy,
	// newest-first and strictly older than the cursor position.
	ListRunsPageAuthorized(ctx context.Context, policy RunAuthzPolicy, afterCreatedAt time.Time, afterID string, limit int) (RunPage, error)
}

// PageRunsAuthorized applies the authorized page contract to an unordered
// in-memory run snapshot: a run must be authorized by policy BEFORE the
// keyset page is computed, so the returned boundary (HasMore,
// NextCreatedAt/NextID) can only ever describe a visible run. It is the
// memory half of the contract shared by the server's memory mode, memStore and
// test doubles; the SQL half is PostgresStore.ListRunsPageAuthorized. An
// unrestricted policy delegates to PageRuns, keeping the unfiltered read
// byte-identical to the historical contract.
func PageRunsAuthorized(runs []model.Run, policy RunAuthzPolicy, afterCreatedAt time.Time, afterID string, limit int) RunPage {
	if policy.unrestricted {
		return PageRuns(runs, afterCreatedAt, afterID, limit)
	}
	filtered := make([]model.Run, 0, len(runs))
	for _, run := range runs {
		if policy.Allows(RepoIDForRun(run)) {
			filtered = append(filtered, run)
		}
	}
	return PageRuns(filtered, afterCreatedAt, afterID, limit)
}

// ListRunsPageAuthorized implements RunPageAuthorizedStore for the durable
// store. The normalized policy predicate (canonicalPolicyRepoIDSQLExpr — the
// exact RepoIDForRun identity) is a WHERE clause of the single index-backed
// keyset query, so ORDER BY ... LIMIT and the returned boundary apply to the
// authorized rows alone. No repository is enumerated: the query reads at most
// limit+1 authorized rows. An unrestricted policy delegates to ListRunsPage,
// keeping the unrestricted read byte-identical to the existing contract.
func (s *PostgresStore) ListRunsPageAuthorized(ctx context.Context, policy RunAuthzPolicy, afterCreatedAt time.Time, afterID string, limit int) (RunPage, error) {
	if policy.unrestricted {
		return s.ListRunsPage(ctx, afterCreatedAt, afterID, limit)
	}
	query, args := authorizedRunsPageSQL(policy, afterCreatedAt, afterID, limit)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return RunPage{}, err
	}
	defer rows.Close()
	out := []model.Run{}
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			return RunPage{}, err
		}
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		return RunPage{}, err
	}
	return runsPageFromRows(out, NormalizeRunsPageLimit(limit)), nil
}

// authorizedRunsPageSQL renders the exact SQL (and bound arguments) of one
// authorized keyset page. It is the single query seam: the store executes it
// and tests EXPLAIN it, so the shipped plan is the asserted plan. The only
// aggregate over runs is none: there is no DISTINCT and no repository
// enumeration anywhere in the statement.
func authorizedRunsPageSQL(policy RunAuthzPolicy, afterCreatedAt time.Time, afterID string, limit int) (string, []any) {
	limit = NormalizeRunsPageLimit(limit)
	args := make([]any, 0, 8)
	conds := make([]string, 0, 2)
	conds = append(conds, policy.sqlPredicate(normalizedRunRepoIdentityEffectiveSQL(), normalizedRunRepoFullNameEffectiveSQL(), &args))
	if !afterCreatedAt.IsZero() || afterID != "" {
		args = append(args, afterCreatedAt, afterID)
		conds = append(conds, `(created_at, id COLLATE "C") < ($`+strconv.Itoa(len(args)-1)+`::timestamptz, $`+strconv.Itoa(len(args))+`::text COLLATE "C")`)
	}
	args = append(args, limit+1)
	query := `SELECT ` + runCols + ` FROM runs WHERE ` + strings.Join(conds, " AND ") +
		` ORDER BY created_at DESC, id COLLATE "C" DESC LIMIT $` + strconv.Itoa(len(args))
	return query, args
}

// runsPageFromRows applies the shared keyset boundary contract to the rows
// read by one page query (the SQL mirror of PageRuns' boundary logic).
func runsPageFromRows(out []model.Run, limit int) RunPage {
	page := RunPage{Runs: out}
	if len(out) > limit {
		page.Runs = out[:limit]
		page.HasMore = true
	}
	if page.HasMore {
		last := page.Runs[len(page.Runs)-1]
		page.NextCreatedAt = last.CreatedAt
		page.NextID = last.ID
	}
	return page
}

var (
	_ RunPageAuthorizedStore = (*PostgresStore)(nil)
	_ RunPageAuthorizedStore = (*memStore)(nil)
)
