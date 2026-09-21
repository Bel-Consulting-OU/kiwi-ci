package migrations

import (
	"strings"
	"testing"
)

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
			if strings.TrimSpace(s) == "" || strings.Contains(s, ";") {
				t.Fatalf("migration %s has an unsplit statement %q", m.Name, s)
			}
		}
	}
	if ms[0].Version != 1 {
		t.Fatalf("first migration version = %d, want 1", ms[0].Version)
	}
}

// TestMigrationCommentsContainNoSemicolons pins the splitter's constraint:
// SplitStatements splits raw SQL on ';' BEFORE stripping comment lines, so a
// semicolon inside a comment slices the comment in half and leaves the tail
// as a stray non-comment fragment that the migration runner then executes as
// SQL. This is exactly the deploy-time failure this guard exists to prevent.
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
}
