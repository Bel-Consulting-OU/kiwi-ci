package storage

// Mutation-wide schema-fence architecture guard (P1 Finding 3).
//
// Finding 3: only a handful of mutations used beginSchemaCompatibleTx, while
// the rest wrote through s.pool.Exec / s.pool.QueryRow or a plain s.pool.Begin
// transaction — so an old replica could commit N-era assumptions after
// migration N+1 committed. The audit converted every production mutation to
// one of the central primitives (withSchemaCompatibleTx / execSchemaFenced /
// queryRowSchemaCompatible, and beginFencedTx for the leader-epoch paths).
//
// This test is the mutation-wide guard: it parses every non-test .go file in
// this package with go/ast and collects PostgresStore methods whose bodies
// call s.pool.Exec(, s.pool.QueryRow(, or s.pool.Begin(. Any collected method
// must be on exactly one explicit allowlist:
//
//   - rawReadAllowlist: SELECT-only single-row pool reads. Reads mutate
//     nothing and deliberately do not take the schema lock.
//   - rawMutationAllowlist: the fence helpers themselves plus the documented
//     exemptions (the migrator, additive bootstrap DDL, the repair quarantine
//     DDL). It must stay EMPTY of business mutations.
//
// If someone adds a raw write to an existing method or a new one, the test
// fails and names the offending method, so the fence cannot silently erode.
// The go/ast walk mirrors internal/server/tiers_scope_test.go.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// rawReadAllowlist is the exhaustive set of PostgresStore methods that read
// through the raw operational pool with s.pool.QueryRow. SELECT-only: each
// entry's raw calls are reads, so they need no schema fence. Adding a raw
// write to one of these methods moves it into the mutation check and fails
// the test.
var rawReadAllowlist = map[string]bool{
	"GetCheckRun":              true,
	"ReadLeaderEpoch":          true,
	"CountSnapshotsForJob":     true,
	"FindRunIdempotency":       true,
	"GetRun":                   true,
	"GetJob":                   true,
	"CountRunningJobs":         true,
	"LeaseLive":                true,
	"classifyHeartbeatMiss":    true,
	"Now":                      true,
	"GetRunner":                true,
	"artifactByGenerationKey":  true,
	"GetArtifact":              true,
	"HasCompletionReceipt":     true,
	"FindDelivery":             true,
	"OutboxAppend":             true, // INSERT is execSchemaFenced; the two re-reads are SELECTs
	"OutboxVersionGuard":       true,
	"OutboxHas":                true,
	"GetSchedule":              true,
	"GetJobContracts":          true,
	"GetGeneratedFragment":     true,
	"GetDownstreamLink":        true,
	"RecentUsage":              true,
	"QuotaCounts":              true,
	"GetCacheManifest":         true,
	"LoadTestHistory":          true,
	"maxAppliedMigration":      true,
	"SchemaCompatibilityFloor": true,
	"SchemaVersion":            true,
	"GetProfile":               true,
	"ProfileForSerial":         true,
	"RunnerIDForToken":         true,
	"HasRunnerTokens":          true,
	"CertRevoked":              true,
	"EnrollGrantLive":          true,
	"GetEnrollGrant":           true,
	"GetClusterKey":            true,
	"ClusterKeyVersion":        true,
	"RunnerSlotTotals":         true,
	"ProfileForRunnerID":       true,
	"PendingSidecar":           true,
	"GetSnapshot":              true,
	"LoadRepoTestHistory":      true,
	"TestReportTotals":         true,
}

// rawMutationAllowlist is the exhaustive set of PostgresStore methods allowed
// to open a raw pool transaction or execute a raw pool write. Every entry is
// a fence helper or a documented exemption; NONE is a business mutation.
var rawMutationAllowlist = map[string]string{
	// Fence helpers: they open the very transaction the fence is applied to.
	"beginSchemaCompatibleTx": "fence helper (opens and fences the transaction)",
	"beginFencedTx":           "fence helper (leader-epoch + schema fence)",
	// Migrator: holds the EXCLUSIVE schema advisory lock and writes the
	// compatibility floor; fencing it against itself would deadlock.
	"applyMigration": "migrator (exclusive schema lock owner, writes the floor)",
	// Additive bootstrap DDL under the same exclusive schema lock.
	"EnsureClusterKeySchema": "additive bootstrap DDL (cluster_keys)",
	// Additive repair DDL under the same exclusive schema lock.
	"ensureRepoIdentityQuarantineSchema": "additive repair DDL (repo-identity quarantine log)",
}

// rawPoolCall is the classification of one method's raw-pool usage.
type rawPoolCall struct {
	read     bool
	mutation bool
}

// methodLeadingSQLText reconstructs the literal prefix of an SQL argument
// expression (string literal concatenations only). Unknown nodes stop the
// walk: the caller treats an empty/unknown prefix as mutating (fail closed)
// so a variable statement can never sneak past the guard.
func methodLeadingSQLText(e ast.Expr) string {
	var b strings.Builder
	var walk func(ast.Expr) bool
	walk = func(n ast.Expr) bool {
		if b.Len() >= 64 {
			return false
		}
		switch v := n.(type) {
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return false
			}
			s, err := strconv.Unquote(v.Value)
			if err != nil {
				return false
			}
			b.WriteString(s)
			return b.Len() < 64
		case *ast.BinaryExpr:
			if v.Op == token.ADD {
				return walk(v.X) && walk(v.Y)
			}
			return false
		case *ast.ParenExpr:
			return walk(v.X)
		default:
			return false
		}
	}
	walk(e)
	return b.String()
}

// sqlIsMutation reports whether an SQL literal prefix starts with a mutating
// verb. An empty prefix (unknown SQL) is mutating: fail closed.
func sqlIsMutation(sql string) bool {
	fields := strings.Fields(sql)
	if len(fields) == 0 {
		return true
	}
	switch strings.ToUpper(fields[0]) {
	case "INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE", "ALTER", "CREATE", "DROP":
		return true
	}
	return false
}

// scanSchemaFenceRawPoolCalls walks every non-test file in this package and
// classifies each PostgresStore method by its raw pool calls.
func scanSchemaFenceRawPoolCalls(t *testing.T) map[string]rawPoolCall {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	dir := filepath.Dir(file)
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob storage sources: %v", err)
	}
	out := map[string]rawPoolCall{}
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil || fn.Name == nil {
				continue
			}
			if len(fn.Recv.List) != 1 {
				continue
			}
			recv := fn.Recv.List[0].Type
			star, ok := recv.(*ast.StarExpr)
			if !ok {
				continue
			}
			ident, ok := star.X.(*ast.Ident)
			if !ok || ident.Name != "PostgresStore" {
				continue
			}
			call := out[fn.Name.Name]
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pool, ok := sel.X.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				recv, ok := pool.X.(*ast.Ident)
				if !ok || recv.Name != "s" || pool.Sel.Name != "pool" {
					return true
				}
				switch sel.Sel.Name {
				case "Begin":
					call.mutation = true
				case "Exec", "QueryRow":
					sql := ""
					if len(ce.Args) >= 2 {
						sql = methodLeadingSQLText(ce.Args[1])
					}
					if sqlIsMutation(sql) {
						call.mutation = true
					} else {
						call.read = true
					}
				}
				return true
			})
			out[fn.Name.Name] = call
		}
	}
	return out
}

// TestPostgresRawPoolWritesAreFenced is the mutation-wide architecture guard.
func TestPostgresRawPoolWritesAreFenced(t *testing.T) {
	calls := scanSchemaFenceRawPoolCalls(t)
	if len(calls) == 0 {
		t.Fatal("no PostgresStore methods parsed; the AST walk is broken")
	}
	var offendingMutations, unexpectedReads, staleAllowlist []string
	for name, call := range calls {
		if call.mutation {
			if _, ok := rawMutationAllowlist[name]; !ok {
				offendingMutations = append(offendingMutations, name)
			}
		}
		if call.read {
			if !rawReadAllowlist[name] {
				unexpectedReads = append(unexpectedReads, name)
			}
		}
	}
	for name := range rawMutationAllowlist {
		if !calls[name].mutation {
			staleAllowlist = append(staleAllowlist, "mutation:"+name)
		}
	}
	for name := range rawReadAllowlist {
		if !calls[name].read {
			staleAllowlist = append(staleAllowlist, "read:"+name)
		}
	}
	sort.Strings(offendingMutations)
	sort.Strings(unexpectedReads)
	sort.Strings(staleAllowlist)
	if len(offendingMutations) > 0 {
		t.Errorf("raw pool WRITES outside the fence allowlist (convert them to withSchemaCompatibleTx/execSchemaFenced/queryRowSchemaCompatible or beginFencedTx): %s",
			strings.Join(offendingMutations, ", "))
	}
	if len(unexpectedReads) > 0 {
		t.Errorf("new raw pool reads are not classified; add them to rawReadAllowlist only if the raw call is SELECT-only: %s",
			strings.Join(unexpectedReads, ", "))
	}
	if len(staleAllowlist) > 0 {
		t.Errorf("allowlist entries no longer match the code (remove them): %s", strings.Join(staleAllowlist, ", "))
	}
	// The mutation allowlist is documented and must stay tiny: fence helpers
	// plus the three documented exemption categories.
	if len(rawMutationAllowlist) > 8 {
		t.Errorf("rawMutationAllowlist grew to %d entries; a business mutation is not a fence exemption", len(rawMutationAllowlist))
	}
}
