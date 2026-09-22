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
// whose full name is the whole value. The SQL predicate mirrors this with
// STRPOS/SUBSTRING.
func splitRepoCandidate(repoID string) (canonical bool, fullName string) {
	i := strings.Index(repoID, "/")
	if i < 0 {
		return false, repoID
	}
	suffix := repoID[i+1:]
	if strings.Contains(suffix, "/") {
		return true, suffix
	}
	return false, repoID
}

// canonicalCandidateID canonicalizes the HOST segment of a canonical candidate
// identity exactly as auth.CanonicalHost does for the grant keys, so a legacy
// row whose persisted/derived host is spelled with different case, a trailing
// dot or the scheme's default port resolves to the same identity as its
// canonical grant (the pre-fix auth.CanReadRepo canonicalized the candidate;
// the SQL predicate mirrors this helper with canonicalHostSQL).
func canonicalCandidateID(repoID, fullName string) string {
	i := strings.Index(repoID, "/")
	if i < 0 {
		return repoID
	}
	host := auth.CanonicalHost(repoID[:i])
	if host == "" {
		return repoID
	}
	return host + "/" + fullName
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
	if containsString(p.aliasConflict, repoID) {
		return false
	}
	if containsString(p.aliasPresent, repoID) {
		return containsString(p.aliasRead, repoID)
	}
	return p.globalRead
}

// sqlPredicate renders the SQL equivalent of Allows against the canonical
// policy repository identity produced by repoExpr. It appends every bound
// array to args and returns a boolean expression. The unrestricted policy
// renders TRUE (the caller normally bypasses the predicate entirely).
//
// The canonical read-grant-only case (no aliases, no explicit denies, no
// conflicts, no global read) simplifies to one equality over the canonicalized
// identity. Every other shape falls back to the fully general predicate; both
// are part of the single ordered keyset query with LIMIT n+1 and no
// collection-wide enumeration or DISTINCT.
func (p RunAuthzPolicy) sqlPredicate(repoExpr string, args *[]any) string {
	if p.unrestricted {
		return "TRUE"
	}
	// suffix is the candidate after its first path segment; a slash inside it
	// means the candidate is a canonical identity (>= 2 path segments), which
	// is exactly auth.ParseStoredRepoID's positional rule.
	suffix := "SUBSTRING(" + repoExpr + " FROM STRPOS(" + repoExpr + ", '/') + 1)"
	canonical := "STRPOS(" + suffix + ", '/') > 0"
	fullName := "CASE WHEN " + canonical + " THEN " + suffix + " ELSE " + repoExpr + " END"
	hostRaw := "CASE WHEN STRPOS(" + repoExpr + ", '/') > 0 THEN LEFT(" + repoExpr + ", STRPOS(" + repoExpr + ", '/') - 1) ELSE '' END"
	canonID := canonicalHostSQL(hostRaw) + " || '/' || " + fullName

	if !p.globalRead && len(p.aliasPresent) == 0 && len(p.aliasRead) == 0 && len(p.aliasConflict) == 0 &&
		len(p.identityConflict) == 0 && len(p.identityPresent) == len(p.identityRead) {
		if len(p.identityRead) == 0 {
			return "FALSE"
		}
		return "(" + canonical + " AND " + canonID + " = ANY(" + textArrayArg(args, p.identityRead) + "))"
	}

	idRead := canonID + " = ANY(" + textArrayArg(args, p.identityRead) + ")"
	idPresent := canonID + " = ANY(" + textArrayArg(args, p.identityPresent) + ")"
	idConflict := canonID + " = ANY(" + textArrayArg(args, p.identityConflict) + ")"
	alRead := fullName + " = ANY(" + textArrayArg(args, p.aliasRead) + ")"
	alPresent := fullName + " = ANY(" + textArrayArg(args, p.aliasPresent) + ")"
	alConflict := fullName + " = ANY(" + textArrayArg(args, p.aliasConflict) + ")"

	// Canonical candidate: conflict, then explicit identity entry, then the
	// explicit bare entry fallback, then the global read role.
	canonicalRead := "(" + idRead + " OR (NOT " + idPresent + " AND (" + alRead +
		" OR (NOT " + alPresent + " AND " + sqlBool(p.globalRead) + "))))"
	canonicalConflict := "(" + idConflict + " OR (NOT " + idPresent + " AND " + alConflict + "))"
	canonicalArm := "(" + canonical + " AND " + canonicalRead + " AND NOT " + canonicalConflict + ")"

	// Bare-alias candidate: only explicit bare grants are consulted; a
	// canonical grant never authorizes another forge's repository.
	aliasArm := "(NOT " + canonical + " AND " + repoExpr + " <> '' AND NOT " + alConflict +
		" AND (" + alRead + " OR (NOT " + alPresent + " AND " + sqlBool(p.globalRead) + ")))"

	// The empty identity carries no repository identity, so only the global
	// read role decides it (auth.CanReadRepo rejects it as unparsable).
	emptyArm := "(" + repoExpr + " = '' AND " + sqlBool(p.globalRead) + ")"

	return "(" + canonicalArm + " OR " + aliasArm + " OR " + emptyArm + ")"
}

// canonicalHostSQL renders hostExpr canonicalized the way auth.CanonicalHost
// canonicalizes a bare (already URL-stripped) host: lowercased, one trailing
// dot stripped, and the scheme's default port (443/80/22) dropped. A bracketed
// IPv6 literal loses its brackets and a default port but keeps a non-default
// one. The SQL identity predicate uses it so a legacy row whose host is
// spelled "GitHub.com", "github.com." or "github.com:443" resolves to the
// same canonical grant as "github.com" — the behavior auth.CanReadRepo had
// before the policy was pushed into SQL.
func canonicalHostSQL(hostExpr string) string {
	lower := "LOWER(" + hostExpr + ")"
	// Bracketed literal: [::1] -> ::1, [::1]:443 -> ::1, [::1]:8443 -> ::1:8443.
	bracket := "CASE WHEN LEFT(" + hostExpr + ", 1) = '[' AND STRPOS(" + hostExpr + ", ']') > 0 THEN " +
		"SUBSTRING(" + lower + " FROM 2 FOR STRPOS(" + hostExpr + ", ']') - 2) || " +
		"CASE WHEN SUBSTRING(" + lower + " FROM STRPOS(" + hostExpr + ", ']') + 1) IN (':443', ':80', ':22') THEN '' " +
		"ELSE SUBSTRING(" + lower + " FROM STRPOS(" + hostExpr + ", ']') + 1) END " +
		"ELSE " + lower + " END"
	// Plain host: drop a default port, then one trailing dot.
	return "CASE WHEN " + hostExpr + " = '' THEN '' " +
		"WHEN LEFT(" + hostExpr + ", 1) = '[' THEN " + bracket + " " +
		"ELSE REGEXP_REPLACE(REGEXP_REPLACE(" + lower + ", ':(443|80|22)$', ''), '\\.$', '') END"
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
	conds = append(conds, policy.sqlPredicate(canonicalPolicyRepoIDSQLExpr("repo"), &args))
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
