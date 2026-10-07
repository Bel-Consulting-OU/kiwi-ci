package migrations

import (
	"strings"
	"testing"
)

// hasTopLevelSemicolon reports whether s still contains a semicolon outside
// string literals, quoted identifiers and dollar-quoted bodies. A
// dollar-quoted PL/pgSQL function body legitimately contains semicolons — it
// is ONE PostgreSQL statement — so the well-formedness guard ignores them
// exactly like SplitStatements does, while a genuinely unsplit statement
// still fails.
func hasTopLevelSemicolon(s string) bool {
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		switch {
		case c == '\'' || c == '"':
			i = scanQuoted(s, i, c)
		case c == '$':
			tag, ok := dollarQuoteTag(s[i:])
			if !ok {
				i++
				continue
			}
			end := strings.Index(s[i+len(tag):], tag)
			if end < 0 {
				return false
			}
			i += len(tag) + end + len(tag)
		case c == ';':
			return true
		default:
			i++
		}
	}
	return false
}

func TestAllMigrationsAreWellFormed(t *testing.T) {
	ms, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) < 12 {
		t.Fatalf("embedded migrations = %d, want at least 12", len(ms))
	}
	prev := 0
	for _, m := range ms {
		if m.Version <= prev {
			t.Fatalf("migrations not sorted by version: %d after %d", m.Version, prev)
		}
		prev = m.Version
		if !strings.HasSuffix(m.Name, ".sql") {
			t.Fatalf("migration name %q", m.Name)
		}
		if len(m.Statements) == 0 {
			t.Fatalf("migration %s has no statements", m.Name)
		}
		for _, s := range m.Statements {
			if strings.TrimSpace(s) == "" || hasTopLevelSemicolon(s) {
				t.Fatalf("migration %s has an unsplit statement %q", m.Name, s)
			}
		}
	}
	if ms[0].Version != 1 {
		t.Fatalf("first migration version = %d, want 1", ms[0].Version)
	}
}

// TestMigrationCommentsContainNoSemicolons pins the migration comment style:
// comment-only lines carry no semicolons. SplitStatements is comment-aware
// and would no longer split a comment on ';' (TestSplitStatementsAndComments
// pins that), but keeping comments semicolon-free means every statement's
// text stays trivially readable in the digest review, and the guard catches
// the one shape a future splitter regression would reintroduce.
func TestMigrationCommentsContainNoSemicolons(t *testing.T) {
	entries, err := FS.ReadDir(".")
	if err != nil {
		t.Fatalf("read migration dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		raw, err := FS.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "--") && strings.Contains(trimmed, ";") {
				t.Errorf("%s:%d comment contains a semicolon (the splitter will cut it): %q", e.Name(), i+1, trimmed)
			}
		}
	}
}

func TestVersionOf(t *testing.T) {
	if v, err := versionOf("0012_name.sql"); err != nil || v != 12 {
		t.Fatalf("versionOf = (%d, %v)", v, err)
	}
	if _, err := versionOf("noname.sql"); err == nil {
		t.Fatal("missing underscore must fail")
	}
	if _, err := versionOf("_leading.sql"); err == nil {
		t.Fatal("empty version must fail")
	}
	if _, err := versionOf("abc_name.sql"); err == nil {
		t.Fatal("non-numeric version must fail")
	}
}

func TestSplitStatementsAndComments(t *testing.T) {
	got := SplitStatements("-- header\nCREATE TABLE a (id int);\n\n-- trailing\nINSERT INTO a VALUES (1) ;\n")
	if len(got) != 2 {
		t.Fatalf("statements = %v", got)
	}
	if got[0] != "CREATE TABLE a (id int)" {
		t.Fatalf("first statement = %q", got[0])
	}
	if got[1] != "INSERT INTO a VALUES (1)" {
		t.Fatalf("second statement = %q", got[1])
	}
	if out := SplitStatements("-- only a comment\n"); len(out) != 0 {
		t.Fatalf("comment-only SQL = %v", out)
	}
	if out := SplitStatements(""); len(out) != 0 {
		t.Fatalf("empty SQL = %v", out)
	}
	if out := stripSQLComments("SELECT 1;\n   -- comment\nSELECT 2;"); strings.Contains(out, "comment") {
		t.Fatalf("stripSQLComments left a comment: %q", out)
	}
	// A semicolon inside a comment no longer splits the statement.
	if out := SplitStatements("SELECT 1 -- a comment with a ; semicolon\n"); len(out) != 1 {
		t.Fatalf("semicolon in a comment split the statement: %q", out)
	}
	// A dollar-quoted function body is ONE statement despite its semicolons.
	body := "CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $kiwi$\nBEGIN\n  RETURN NEW;\nEND;\n$kiwi$"
	if out := SplitStatements(body); len(out) != 1 {
		t.Fatalf("dollar-quoted body split into %d statements: %q", len(out), out)
	}
	if out := SplitStatements(body + ";\nSELECT 1"); len(out) != 2 {
		t.Fatalf("statement after a dollar-quoted body = %q", out)
	}
	// Dollar-quoted bodies may carry tags other than $kiwi$, and strings may
	// contain a semicolon without splitting.
	if out := SplitStatements("SELECT 'a;b'"); len(out) != 1 {
		t.Fatalf("semicolon in a string literal split the statement: %q", out)
	}
	if out := SplitStatements("SELECT $$a;b$$"); len(out) != 1 {
		t.Fatalf("semicolon in an untagged dollar quote split the statement: %q", out)
	}
}
