// Package migrations embeds the numbered SQL schema migrations applied by
// PostgresStore.Migrate. Files are named NNNN_name.sql and must contain plain
// semicolon-terminated statements (no procedural bodies) so statement
// splitting is deterministic.
package migrations

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

// FS holds the migration files. 0001_init.sql creates every table.
//
//go:embed *.sql
var FS embed.FS

// Migration is one numbered schema migration.
type Migration struct {
	Version    int
	Name       string
	Statements []string
}

// All returns the embedded migrations sorted by version.
func All() ([]Migration, error) {
	return load(FS)
}

// load reads migrations from fsys. All uses the embedded FS; the indirection
// keeps the error handling for malformed trees testable.
func load(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("migrations: read dir: %w", err)
	}
	out := make([]Migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		version, err := versionOf(e.Name())
		if err != nil {
			return nil, err
		}
		raw, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("migrations: read %s: %w", e.Name(), err)
		}
		stmts := SplitStatements(string(raw))
		if len(stmts) == 0 {
			return nil, fmt.Errorf("migrations: %s has no statements", e.Name())
		}
		out = append(out, Migration{Version: version, Name: e.Name(), Statements: stmts})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// versionOf parses the leading numeric version of a migration filename.
func versionOf(name string) (int, error) {
	base := strings.TrimSuffix(name, ".sql")
	idx := strings.IndexByte(base, '_')
	if idx <= 0 {
		return 0, fmt.Errorf("migrations: %s: expected NNNN_name.sql", name)
	}
	v, err := strconv.Atoi(base[:idx])
	if err != nil {
		return 0, fmt.Errorf("migrations: %s: bad version: %w", name, err)
	}
	return v, nil
}

// SplitStatements splits raw SQL on semicolons, drops comment-only lines,
// and trims whitespace. It assumes statements contain no semicolons inside
// string literals.
func SplitStatements(sql string) []string {
	var out []string
	for _, part := range strings.Split(sql, ";") {
		stmt := strings.TrimSpace(stripSQLComments(part))
		if stmt != "" {
			out = append(out, stmt)
		}
	}
	return out
}

func stripSQLComments(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			lines[i] = ""
		}
	}
	return strings.Join(lines, "\n")
}
