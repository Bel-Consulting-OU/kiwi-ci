package storage

import (
	"context"
	"strconv"
	"strings"
	"time"

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
// inaccessible activity. RunPageForPrincipalStore is the store-level contract
// that closes this: the permitted canonical repository set is a predicate of
// the SAME query that computes the keyset boundary, so every externally
// visible position (returned rows, HasMore, NextCreatedAt/NextID) is derived
// from an authorized row only.
//
// The caller resolves the permitted set ONCE per request through the auth
// repository-grant resolution (auth.CanReadRepo) over the concrete canonical
// repository identities present in the collection — see RunRepoIDStore — so
// bare aliases, host case, default ports and the ambiguity fail-closed rule
// agree with every per-run read route. The cursor/order/limit contract is
// otherwise identical to RunPageStore (see postgres_runs_page.go).

// RunPageForPrincipalStore is the authorized paged-read capability of a
// store. It is deliberately separate from RunPageStore: paging an unfiltered
// collection and filtering afterwards leaks the page boundary, so a caller
// must never fall back to RunPageStore — a store without this capability
// fails closed (the server answers an opaque 500).
type RunPageForPrincipalStore interface {
	// ListRunsPageForAuthorizedRepos returns one keyset page of runs whose
	// canonical POLICY repository identity (RepoIDForRun: stored
	// policy_repo_id first, then repo_id / clone-URL + full-name) is a
	// member of allowedRepoIDs, newest-first and strictly older than the
	// cursor position. See the file comment for the authorization contract.
	//
	// allowedRepoIDs == nil means UNRESTRICTED (every repository): callers
	// pass nil only when they are authorized on the whole collection (no
	// principal, admin, or global read with no repository entries). A
	// non-nil slice is an EXACT allowlist — the empty slice matches nothing
	// and returns a terminal empty page, so a caller with no permitted
	// repository can never be served a row (or a cursor derived from one).
	ListRunsPageForAuthorizedRepos(ctx context.Context, allowedRepoIDs []string, afterCreatedAt time.Time, afterID string, limit int) (RunPage, error)
}

// RunRepoIDStore enumerates the candidate canonical repository identities of
// the collection. It is candidate DISCOVERY, never an authorization decision:
// the caller resolves every returned ID through the repository-grant
// resolution and passes the permitted subset to
// ListRunsPageForAuthorizedRepos. Enumeration is required for exactness
// because only the store knows which concrete (possibly legacy or
// canonically spelled) identities exist; the IDs are read from the same
// expression the page predicate compares, so authorization and filtering can
// never disagree about a spelling.
type RunRepoIDStore interface {
	// ListRunRepoIDs returns the distinct canonical policy repository
	// identities present in runs, ascending. The empty identity ("") is
	// included when rows cannot resolve one, so the caller decides its
	// visibility through the same repository-grant resolution as any other
	// candidate.
	ListRunRepoIDs(ctx context.Context) ([]string, error)
}

// PageRunsForAuthorizedRepos applies the authorized page contract to an
// unordered in-memory run snapshot: a run must belong to the authorized
// repository set BEFORE the keyset page is computed, so the returned
// boundary (HasMore, NextCreatedAt/NextID) can only ever describe a visible
// run. It is the memory half of the contract shared by the server's memory
// mode, memStore and test doubles; the SQL half is
// PostgresStore.ListRunsPageForAuthorizedRepos. See RunPageForPrincipalStore
// for the nil (unrestricted) / non-nil (exact) allowlist semantics.
func PageRunsForAuthorizedRepos(runs []model.Run, allowedRepoIDs []string, afterCreatedAt time.Time, afterID string, limit int) RunPage {
	if allowedRepoIDs == nil {
		return PageRuns(runs, afterCreatedAt, afterID, limit)
	}
	allowed := make(map[string]struct{}, len(allowedRepoIDs))
	for _, id := range allowedRepoIDs {
		allowed[id] = struct{}{}
	}
	filtered := make([]model.Run, 0, len(runs))
	for _, run := range runs {
		if _, ok := allowed[RepoIDForRun(run)]; ok {
			filtered = append(filtered, run)
		}
	}
	return PageRuns(filtered, afterCreatedAt, afterID, limit)
}

// ListRunsPageForAuthorizedRepos implements RunPageForPrincipalStore for the
// durable store. The authorized repository set (canonicalPolicyRepoIDSQLExpr:
// policy_repo_id first, then the canonical repo_id / clone-URL + full-name
// derivation — exactly RepoIDForRun) is a WHERE predicate of the single
// index-backed keyset query, so ORDER BY ... LIMIT and the returned boundary
// apply to the authorized rows alone. The nil allowlist delegates to
// ListRunsPage, keeping the unrestricted read byte-identical to the existing
// contract. An empty allowlist renders WHERE FALSE: a terminal empty page
// without touching a single run row.
func (s *PostgresStore) ListRunsPageForAuthorizedRepos(ctx context.Context, allowedRepoIDs []string, afterCreatedAt time.Time, afterID string, limit int) (RunPage, error) {
	if allowedRepoIDs == nil {
		return s.ListRunsPage(ctx, afterCreatedAt, afterID, limit)
	}
	limit = NormalizeRunsPageLimit(limit)
	conds := make([]string, 0, 2)
	args := make([]any, 0, 3)
	if len(allowedRepoIDs) > 0 {
		args = append(args, allowedRepoIDs)
		conds = append(conds, canonicalPolicyRepoIDSQLExpr("repo")+" = ANY($"+strconv.Itoa(len(args))+"::text[])")
	} else {
		conds = append(conds, "FALSE")
	}
	if !afterCreatedAt.IsZero() || afterID != "" {
		args = append(args, afterCreatedAt, afterID)
		conds = append(conds, `(created_at, id COLLATE "C") < ($`+strconv.Itoa(len(args)-1)+`::timestamptz, $`+strconv.Itoa(len(args))+`::text COLLATE "C")`)
	}
	args = append(args, limit+1)
	rows, err := s.pool.Query(ctx,
		`SELECT `+runCols+` FROM runs WHERE `+strings.Join(conds, " AND ")+
			` ORDER BY created_at DESC, id COLLATE "C" DESC LIMIT $`+strconv.Itoa(len(args)), args...)
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
	return page, nil
}

// ListRunRepoIDs implements RunRepoIDStore for the durable store: the
// distinct canonical policy repository identities of all runs, ascending.
// The query is backed by the migration-0027 runs_repo_identity_idx
// expression index, which is created on EXACTLY the expression rendered
// here, so discovery and the authorized page predicate share one identity
// definition. Candidate discovery only; see RunRepoIDStore.
func (s *PostgresStore) ListRunRepoIDs(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT `+canonicalPolicyRepoIDSQLExpr("repo")+` FROM runs ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

var (
	_ RunPageForPrincipalStore = (*PostgresStore)(nil)
	_ RunRepoIDStore           = (*PostgresStore)(nil)
)
