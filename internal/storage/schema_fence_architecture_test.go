package storage

// Schema-fence architecture guard (P1 Finding 3, hardened by the Round-11
// audit).
//
// Finding 3: only a handful of mutations used beginSchemaCompatibleTx, while
// the rest wrote through s.pool.Exec / s.pool.QueryRow or a plain s.pool.Begin
// transaction — so an old replica could commit N-era assumptions after
// migration N+1 committed. The audit converted every production mutation to
// one of the central primitives (withSchemaCompatibleTx / execSchemaFenced /
// queryRowSchemaCompatible, and beginFencedTx for the leader-epoch paths).
//
// This test is a HEURISTIC architecture guard, not a proof of mutation-wide
// coverage. It parses every non-test .go file in this package with go/ast and
// flags a PostgresStore method when its body reaches the raw operational pool
// through:
//
//   - s.pool.Begin( / s.pool.BeginTx( / s.pool.SendBatch( / s.pool.CopyFrom( /
//     s.pool.Acquire( — always a raw resource acquisition or batch/transaction
//     open, so always flagged;
//   - s.pool.Exec( / s.pool.QueryRow(, classified by the leading statement of
//     the literal SQL argument; and
//   - conn.Exec( / conn.QueryRow( where conn is a local variable assigned
//     from an Acquire call (on any pool), classified the same way.
//
// The leading-statement classification is classifySQLMutation (schema_fence.go):
// it strips leading SQL comments, treats INSERT/UPDATE/DELETE/MERGE/TRUNCATE
// and DDL (and any unrecognized text) as mutations, recognizes data-modifying
// CTEs (WITH ... INSERT/UPDATE/DELETE/MERGE), and only calls a statement a
// read when it is SELECT-only (including WITH ... SELECT). A concatenated
// statement that is incomplete at the AST level and starts with WITH is
// treated as a mutation (fail closed); a literal built from a variable is the
// empty string and fails closed.
//
// Every flagged method must be on exactly one explicit allowlist:
//
//   - rawReadAllowlist: SELECT-only raw reads (s.pool.QueryRow reads and the
//     advisory-pool acquired-conn SELECTs). Reads mutate nothing and
//     deliberately do not take the schema lock.
//   - rawMutationAllowlist: the fence helpers themselves plus the documented
//     exemptions (the migrator, additive bootstrap DDL, the repair quarantine
//     DDL). It must stay EMPTY of business mutations.
//
// What this guard does NOT prove:
//
//   - It does not resolve SQL built through helper functions, variables or
//     non-literal expressions: those classify as the empty string and fail
//     closed as mutations, which is safe but imprecise.
//   - It does not detect a mutation hidden behind a leading SELECT in a
//     multi-statement string ("SELECT ...; UPDATE ..."), nor one inside a
//     string literal that follows a leading SELECT.
//   - It does not follow SQL executed through receivers it cannot recognize
//     (e.g. a tx from a non-allowlisted Begin is caught at the Begin, but a
//     connection reached through an arbitrary helper is not).
//   - It therefore cannot prove that no unfenced mutation exists anywhere in
//     the package; it proves that the enumerated raw-pool shapes are fenced
//     or explicitly exempted.
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
// through a raw pool handle: s.pool.QueryRow SELECTs plus the acquired-conn
// Exec SELECTs of the advisory-fence primitives. SELECT-only: each entry's
// raw calls are reads, so they need no schema fence. Adding a raw write to one
// of these methods moves it into the mutation check and fails the test.
var rawReadAllowlist = map[string]bool{
	// The acquired session issues only SELECT pg_advisory_lock (the session
	// lock is the fence, not a schema mutation), and it comes from the
	// dedicated advisory pool, never the operational pool.
	"AcquireDigestFence":       true,
	"AcquireNamedFence":        true,
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

// methodLeadingSQLText reconstructs the literal text of an SQL argument
// expression (string literal concatenations only) and reports whether the
// whole expression was literal. Unknown nodes stop the walk with
// complete=false: the caller fails closed for a WITH statement whose
// mutation may hide behind a concatenated variable, and an empty text fails
// closed for every other shape.
func methodLeadingSQLText(e ast.Expr) (string, bool) {
	var b strings.Builder
	complete := true
	var walk func(ast.Expr)
	walk = func(n ast.Expr) {
		switch v := n.(type) {
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				complete = false
				return
			}
			s, err := strconv.Unquote(v.Value)
			if err != nil {
				complete = false
				return
			}
			b.WriteString(s)
		case *ast.BinaryExpr:
			if v.Op != token.ADD {
				complete = false
				return
			}
			walk(v.X)
			walk(v.Y)
		case *ast.ParenExpr:
			walk(v.X)
		default:
			complete = false
		}
	}
	walk(e)
	return b.String(), complete
}

// isSPool reports whether sel is a call selector of the form s.pool.<name>.
func isSPool(sel *ast.SelectorExpr) bool {
	pool, ok := sel.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	recv, ok := pool.X.(*ast.Ident)
	return ok && recv.Name == "s" && pool.Sel.Name == "pool"
}

// acquiredConnNames returns the local variable names bound to an Acquire call
// on ANY pool inside fn's body (conn, err := pool.Acquire(ctx) and friends).
// A PostgresStore method that acquires a pool resource and then runs raw SQL
// on it must be fenced like any other raw write; tracking the name lets the
// walker classify conn.Exec/conn.QueryRow by their leading statement.
func acquiredConnNames(fn *ast.FuncDecl) map[string]bool {
	names := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) == 0 {
			return true
		}
		for _, rhs := range as.Rhs {
			ce, ok := rhs.(*ast.CallExpr)
			if !ok {
				continue
			}
			sel, ok := ce.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Acquire" {
				continue
			}
			if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
				names[id.Name] = true
			}
			break
		}
		return true
	})
	return names
}

// classifyRawPoolCalls classifies one PostgresStore method body: direct
// s.pool resource acquisitions (Begin/BeginTx/SendBatch/CopyFrom/Acquire) are
// mutations, raw Exec/QueryRow statements (on s.pool or on a connection
// acquired through any pool) are classified by their leading statement.
func classifyRawPoolCalls(fn *ast.FuncDecl) rawPoolCall {
	var call rawPoolCall
	conns := acquiredConnNames(fn)
	// recordSQL classifies one raw Exec/QueryRow statement.
	recordSQL := func(expr ast.Expr) {
		sql, complete := methodLeadingSQLText(expr)
		mutation, readOnly := classifySQLMutation(sql)
		switch {
		case mutation:
			call.mutation = true
		case !complete && sqlLeadingKeyword(sql) == "WITH":
			// A data-modifying CTE can hide after a concatenated variable:
			// fail closed.
			call.mutation = true
		case readOnly:
			call.read = true
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "Exec", "QueryRow":
			rawPool := isSPool(sel)
			if id, ok := sel.X.(*ast.Ident); ok && conns[id.Name] {
				rawPool = true
			}
			if !rawPool {
				return true
			}
			if len(ce.Args) >= 2 {
				recordSQL(ce.Args[1])
			} else {
				// No SQL argument at all: fail closed.
				call.mutation = true
			}
		case "Begin", "BeginTx", "SendBatch", "CopyFrom", "Acquire":
			if isSPool(sel) {
				call.mutation = true
			}
		}
		return true
	})
	return call
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
			out[fn.Name.Name] = classifyRawPoolCalls(fn)
		}
	}
	return out
}

// TestClassifySQLMutation pins the pure classification helper: leading
// comments and whitespace are stripped, mutation verbs and data-modifying
// CTEs are mutations, SELECT-only statements (including read-only CTEs) are
// reads, and anything unrecognizable (including non-SQL text that merely
// starts with "with") fails closed as a mutation.
func TestClassifySQLMutation(t *testing.T) {
	cases := []struct {
		name     string
		sql      string
		mutation bool
		readOnly bool
	}{
		{"insert", "INSERT INTO t (a) VALUES (1)", true, false},
		{"insert lowercase", "insert into t (a) values (1)", true, false},
		{"select", "SELECT a FROM t WHERE id = $1", false, true},
		{"update", "UPDATE t SET a = 1 WHERE id = 2", true, false},
		{"delete", "DELETE FROM t WHERE id = 2", true, false},
		{"truncate", "TRUNCATE TABLE t", true, false},
		{"ddl", "ALTER TABLE t ADD COLUMN b int", true, false},
		{"cte update", "WITH x AS (SELECT id FROM t) UPDATE t SET a = 1 FROM x WHERE t.id = x.id", true, false},
		{"cte delete", "with x as (select 1) delete from t where id in (select * from x)", true, false},
		{"cte select", "WITH x AS (SELECT 1 AS one) SELECT * FROM x", false, true},
		{"cte recursive select", "WITH RECURSIVE x AS (SELECT 1) SELECT * FROM x", false, true},
		{"line comment update", "-- comment\n UPDATE t SET a = 1", true, false},
		{"line comment no newline", "-- comment", true, false},
		{"block comment insert", "/* c */ INSERT INTO t VALUES (1)", true, false},
		{"block comment select", "/* c */\nSELECT 1", false, true},
		{"both comment kinds", "/* a */ -- b\n DELETE FROM t", true, false},
		{"leading whitespace select", "\n\t  SELECT 1", false, true},
		{"empty", "", true, false},
		{"blank", "   \n\t", true, false},
		{"non-sql words", "hello world", true, false},
		{"non-sql with prefix", "with great power comes great responsibility", true, false},
		{"keyword as identifier prefix", "INSERTED_AT = now()", true, false},
		{"select prefix without select", "SELECTION of items", true, false},
		{"word boundary in cte", "WITH insert_log AS (SELECT 1) SELECT * FROM insert_log", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutation, readOnly := classifySQLMutation(tc.sql)
			if mutation != tc.mutation || readOnly != tc.readOnly {
				t.Fatalf("classifySQLMutation(%q) = (mutation=%t, readOnly=%t), want (%t, %t)",
					tc.sql, mutation, readOnly, tc.mutation, tc.readOnly)
			}
		})
	}
}

// TestPostgresRawPoolWritesAreFenced is the heuristic architecture guard.
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

// classifySynthetic parses a synthetic source file and returns each
// PostgresStore method's raw-pool classification, so the hardened detection
// shapes can be exercised without adding raw calls to the package.
func classifySynthetic(t *testing.T, src string) map[string]rawPoolCall {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic source: %v", err)
	}
	out := map[string]rawPoolCall{}
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Body == nil {
			continue
		}
		if star, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
			if ident, ok := star.X.(*ast.Ident); ok && ident.Name == "PostgresStore" {
				out[fn.Name.Name] = classifyRawPoolCalls(fn)
			}
		}
	}
	return out
}

// TestRawPoolCallClassification proves the hardened AST shapes are detected:
// BeginTx/SendBatch/CopyFrom/Acquire, acquired-conn Exec/QueryRow, and
// comment/CTE-aware statement classification (including the fail-closed
// concatenated-WITH case).
func TestRawPoolCallClassification(t *testing.T) {
	src := `package storage

func (s *PostgresStore) mExecMutation() { s.pool.Exec(ctx, "UPDATE t SET a = 1") }
func (s *PostgresStore) mExecSelect() { s.pool.QueryRow(ctx, "SELECT a FROM t") }
func (s *PostgresStore) mBegin() { s.pool.Begin(ctx) }
func (s *PostgresStore) mBeginTx() { s.pool.BeginTx(ctx, nil) }
func (s *PostgresStore) mSendBatch() { s.pool.SendBatch(ctx, b) }
func (s *PostgresStore) mCopyFrom() { s.pool.CopyFrom(ctx, table, cols, src) }
func (s *PostgresStore) mAcquire() { s.pool.Acquire(ctx) }
func (s *PostgresStore) mAcquireConnUpdate() {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return
	}
	conn.Exec(ctx, "UPDATE t SET a = 1")
}
func (s *PostgresStore) mAcquireConnSelect() {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return
	}
	conn.QueryRow(ctx, "SELECT 1")
}
func (s *PostgresStore) mWithUpdate() { s.pool.Exec(ctx, "WITH x AS (SELECT 1) UPDATE t SET a = 1") }
func (s *PostgresStore) mWithSelect() { s.pool.Exec(ctx, "WITH x AS (SELECT 1) SELECT * FROM x") }
func (s *PostgresStore) mWithConcat() { s.pool.Exec(ctx, "WITH x AS (SELECT 1) "+suffix) }
func (s *PostgresStore) mCommentUpdate() { s.pool.QueryRow(ctx, "-- c\nUPDATE t SET a = 1") }
func (s *PostgresStore) mBlockCommentInsert() { s.pool.Exec(ctx, "/* c */ INSERT INTO t VALUES (1)") }
func (s *PostgresStore) mNoSQLArg() { s.pool.Exec(ctx) }
`
	got := classifySynthetic(t, src)
	want := map[string]rawPoolCall{
		"mExecMutation":       {mutation: true},
		"mExecSelect":         {read: true},
		"mBegin":              {mutation: true},
		"mBeginTx":            {mutation: true},
		"mSendBatch":          {mutation: true},
		"mCopyFrom":           {mutation: true},
		"mAcquire":            {mutation: true},
		"mAcquireConnUpdate":  {mutation: true},
		"mAcquireConnSelect":  {read: true},
		"mWithUpdate":         {mutation: true},
		"mWithSelect":         {read: true},
		"mWithConcat":         {mutation: true},
		"mCommentUpdate":      {mutation: true},
		"mBlockCommentInsert": {mutation: true},
		"mNoSQLArg":           {mutation: true},
	}
	if len(got) != len(want) {
		t.Fatalf("classified %d methods, want %d: %+v", len(got), len(want), got)
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("classify %s = %+v, want %+v (all: %+v)", name, got[name], w, got)
		}
	}
}
