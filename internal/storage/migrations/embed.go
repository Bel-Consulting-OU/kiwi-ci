// Package migrations embeds the numbered SQL schema migrations applied by
// PostgresStore.Migrate. Files are named NNNN_name.sql and must contain plain
// semicolon-terminated statements (no procedural bodies) so statement
// splitting is deterministic.
package migrations

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
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
	Version int
	Name    string
	// Digest is the SHA-256 of the immutable raw migration content: the
	// database records it at apply time, so editing an already-applied
	// migration is detected as schema-history divergence instead of being
	// silently skipped because the version row exists.
	Digest string
	// CompatibleFrom is the oldest binary schema that may keep operating
	// after this migration is applied. A file may declare
	// `-- kiwi:compatible-from N` (expand/contract migrations that old
	// binaries still tolerate); the default is the file's own version, which
	// requires older binaries to drain before mutating.
	CompatibleFrom int
	Statements     []string
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
		sum := sha256.Sum256(raw)
		compatibleFrom, err := compatibleFromOf(string(raw), version)
		if err != nil {
			return nil, fmt.Errorf("migrations: %s: %w", e.Name(), err)
		}
		out = append(out, Migration{
			Version:        version,
			Name:           e.Name(),
			Digest:         hex.EncodeToString(sum[:]),
			CompatibleFrom: compatibleFrom,
			Statements:     stmts,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i := 1; i < len(out); i++ {
		if out[i].Version == out[i-1].Version {
			// Two files for one version would silently skip one of them
			// (the version row already exists), producing schema drift that
			// only shows up in production.
			return nil, fmt.Errorf("migrations: duplicate version %d (%s and %s)", out[i].Version, out[i-1].Name, out[i].Name)
		}
	}
	return out, nil
}

// compatibleFromOf extracts the optional `-- kiwi:compatible-from N`
// directive. The default floor is the migration's own version: applying it
// requires binaries that know the new shape. A declared floor must be
// positive and no newer than the migration itself.
func compatibleFromOf(raw string, version int) (int, error) {
	floor := version
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		const prefix = "-- kiwi:compatible-from"
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := strings.TrimPrefix(line, prefix)
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
			// A word continuing the marker is an ordinary comment, not a
			// directive (e.g. "-- kiwi:compatible-from-notes").
			continue
		}
		v, err := strconv.Atoi(strings.TrimSpace(rest))
		if err != nil || v <= 0 {
			return 0, fmt.Errorf("invalid compatible-from directive %q", line)
		}
		if v > version {
			return 0, fmt.Errorf("compatible-from %d is newer than the migration version %d", v, version)
		}
		floor = v
	}
	return floor, nil
}

// MaxVersion returns the newest embedded migration version (0 when none).
func MaxVersion() (int, error) {
	all, err := All()
	if err != nil {
		return 0, err
	}
	if len(all) == 0 {
		return 0, nil
	}
	return all[len(all)-1].Version, nil
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

// SplitStatements splits raw SQL on semicolons that appear OUTSIDE string
// literals, quoted identifiers, line comments, block comments (which nest,
// per PostgreSQL) and dollar-quoted bodies, then drops comment-only lines and
// trims whitespace.
// The dollar-quote awareness is what lets a migration carry a PL/pgSQL
// trigger function whose body contains semicolons: the body is one
// statement, exactly as PostgreSQL sees it. Comment-only lines are stripped
// AFTER splitting so a semicolon inside a comment can no longer cut the
// comment in half.
func SplitStatements(sql string) []string {
	var out []string
	var b strings.Builder
	i, n := 0, len(sql)
	for i < n {
		c := sql[i]
		switch {
		case c == '\'':
			j := scanQuoted(sql, i, '\'')
			b.WriteString(sql[i:j])
			i = j
		case c == '"':
			j := scanQuoted(sql, i, '"')
			b.WriteString(sql[i:j])
			i = j
		case c == '-' && i+1 < n && sql[i+1] == '-':
			j := strings.IndexByte(sql[i:], '\n')
			if j < 0 {
				j = n - i
			}
			b.WriteString(sql[i : i+j])
			i += j
		case c == '/' && i+1 < n && sql[i+1] == '*':
			j := scanBlockComment(sql, i)
			b.WriteString(sql[i:j])
			i = j
		case c == '$':
			if tag, ok := dollarQuoteTag(sql[i:]); ok {
				end := strings.Index(sql[i+len(tag):], tag)
				if end < 0 {
					b.WriteString(sql[i:])
					i = n
					break
				}
				j := i + len(tag) + end + len(tag)
				b.WriteString(sql[i:j])
				i = j
				break
			}
			b.WriteByte(c)
			i++
		case c == ';':
			stmt := strings.TrimSpace(stripSQLComments(b.String()))
			if stmt != "" {
				out = append(out, stmt)
			}
			b.Reset()
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	if stmt := strings.TrimSpace(stripSQLComments(b.String())); stmt != "" {
		out = append(out, stmt)
	}
	return out
}

// scanBlockComment returns the index just past the closing */ of the block
// comment starting at i. PostgreSQL block comments NEST: an inner /* ... */
// pair is part of the outer comment (its semicolons must not split a
// statement), so the scan tracks depth instead of stopping at the first */.
// An unterminated comment consumes the rest of the input, exactly like an
// unterminated quote: PostgreSQL reports the syntax error when it executes
// the statement.
func scanBlockComment(sql string, i int) int {
	depth := 0
	j := i
	for j < len(sql) {
		switch {
		case j+1 < len(sql) && sql[j] == '/' && sql[j+1] == '*':
			depth++
			j += 2
		case j+1 < len(sql) && sql[j] == '*' && sql[j+1] == '/':
			depth--
			j += 2
			if depth == 0 {
				return j
			}
		default:
			j++
		}
	}
	return len(sql)
}

// scanQuoted returns the index just past the closing quote of the literal or
// quoted identifier starting at i, honoring the doubled-quote escape. An
// unterminated quote consumes the rest of the input (PostgreSQL reports the
// syntax error when it executes the statement).
func scanQuoted(sql string, i int, quote byte) int {
	j := i + 1
	for j < len(sql) {
		if sql[j] != quote {
			j++
			continue
		}
		if j+1 < len(sql) && sql[j+1] == quote {
			j += 2
			continue
		}
		return j + 1
	}
	return len(sql)
}

// dollarQuoteTag reports whether s starts a dollar-quoted string ($tag$) and
// returns the full delimiter. A bare $ followed by a digit or punctuation is
// not a tag (it is a bind-parameter-looking token, which migrations do not
// use, or money); such input is emitted verbatim.
func dollarQuoteTag(s string) (string, bool) {
	if len(s) < 2 || s[0] != '$' {
		return "", false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '$' {
			return s[:i+1], true
		}
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 1 && c >= '0' && c <= '9') {
			continue
		}
		return "", false
	}
	return "", false
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
