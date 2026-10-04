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
		const prefix = "-- kiwi:compatible-from "
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, prefix)))
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
