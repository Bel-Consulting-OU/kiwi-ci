package migrations

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

// TestMaxVersionMatchesAll pins MaxVersion to the newest embedded migration:
// the runner compares its schema floor against this value, so a divergence
// would let an old binary believe a newer database is still compatible.
func TestMaxVersionMatchesAll(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Fatal("no embedded migrations")
	}
	got, err := MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	if want := all[len(all)-1].Version; got != want {
		t.Fatalf("MaxVersion = %d, want %d", got, want)
	}
}

// TestCompatibleFromOf covers the expand/contract directive parser: the
// default floor, a declared floor, and every rejected shape.
func TestCompatibleFromOf(t *testing.T) {
	if got, err := compatibleFromOf("CREATE TABLE a (id int);\n", 7); err != nil || got != 7 {
		t.Fatalf("default = (%d, %v), want (7, nil)", got, err)
	}
	if got, err := compatibleFromOf("-- kiwi:compatible-from 3\nSELECT 1;\n", 7); err != nil || got != 3 {
		t.Fatalf("declared = (%d, %v), want (3, nil)", got, err)
	}
	if got, err := compatibleFromOf("  -- kiwi:compatible-from 7\n", 7); err != nil || got != 7 {
		t.Fatalf("indented declaration = (%d, %v), want (7, nil)", got, err)
	}
	if got, err := compatibleFromOf("-- kiwi:compatible-from-notes\n", 7); err != nil || got != 7 {
		t.Fatalf("marker word = (%d, %v), want (7, nil) for an ordinary comment", got, err)
	}
	for _, raw := range []string{
		"-- kiwi:compatible-from nope\n",
		"-- kiwi:compatible-from 0\n",
		"-- kiwi:compatible-from -3\n",
		"-- kiwi:compatible-from\n",
		"-- kiwi:compatible-from 8\n", // newer than the migration version
	} {
		if got, err := compatibleFromOf(raw, 7); err == nil {
			t.Errorf("compatibleFromOf(%q) = (%d, nil), want an error", raw, got)
		}
	}
}

// openFailFS wraps an fs.FS whose Open for one name fails, so load's
// read-error branches are reachable without a real broken filesystem.
type openFailFS struct {
	fs.FS
	fail string
}

func (f openFailFS) Open(name string) (fs.File, error) {
	if name == f.fail {
		return nil, fs.ErrPermission
	}
	return f.FS.Open(name)
}

// TestLoadRejectsMalformedTrees covers every fail-closed branch of the
// migration tree loader with in-memory filesystems.
func TestLoadRejectsMalformedTrees(t *testing.T) {
	valid := fstest.MapFS{"0001_init.sql": {Data: []byte("CREATE TABLE a (id int);\n")}}

	t.Run("empty tree", func(t *testing.T) {
		got, err := load(fstest.MapFS{})
		if err != nil || len(got) != 0 {
			t.Fatalf("load(empty) = (%v, %v), want no migrations and no error", got, err)
		}
	})
	t.Run("bad version prefix", func(t *testing.T) {
		_, err := load(fstest.MapFS{"noname.sql": {Data: []byte("SELECT 1;")}})
		if err == nil || !strings.Contains(err.Error(), "expected NNNN_name.sql") {
			t.Fatalf("load(bad name) = %v, want NNNN_name.sql error", err)
		}
	})
	t.Run("non-numeric version", func(t *testing.T) {
		_, err := load(fstest.MapFS{"abcd_x.sql": {Data: []byte("SELECT 1;")}})
		if err == nil || !strings.Contains(err.Error(), "bad version") {
			t.Fatalf("load(bad version) = %v, want bad-version error", err)
		}
	})
	t.Run("comment-only migration", func(t *testing.T) {
		_, err := load(fstest.MapFS{"0001_empty.sql": {Data: []byte("-- nothing here\n")}})
		if err == nil || !strings.Contains(err.Error(), "has no statements") {
			t.Fatalf("load(empty body) = %v, want no-statements error", err)
		}
	})
	t.Run("duplicate version", func(t *testing.T) {
		_, err := load(fstest.MapFS{
			"0001_a.sql": {Data: []byte("SELECT 1;")},
			"0001_b.sql": {Data: []byte("SELECT 2;")},
		})
		if err == nil || !strings.Contains(err.Error(), "duplicate version 1") {
			t.Fatalf("load(duplicate) = %v, want duplicate-version error", err)
		}
	})
	t.Run("unreadable file", func(t *testing.T) {
		_, err := load(openFailFS{FS: valid, fail: "0001_init.sql"})
		if err == nil || !strings.Contains(err.Error(), "read 0001_init.sql") {
			t.Fatalf("load(read fail) = %v, want read error", err)
		}
	})
	t.Run("unreadable dir", func(t *testing.T) {
		_, err := load(openFailFS{FS: valid, fail: "."})
		if err == nil || !strings.Contains(err.Error(), "read dir") {
			t.Fatalf("load(dir fail) = %v, want read-dir error", err)
		}
	})
	t.Run("invalid compatible-from", func(t *testing.T) {
		_, err := load(fstest.MapFS{"0001_a.sql": {Data: []byte("-- kiwi:compatible-from 9\nSELECT 1;")}})
		if err == nil || !strings.Contains(err.Error(), "newer than the migration version") {
			t.Fatalf("load(bad floor) = %v, want compatible-from error", err)
		}
	})
	t.Run("non-sql entries ignored", func(t *testing.T) {
		got, err := load(fstest.MapFS{
			"0001_init.sql": {Data: []byte("CREATE TABLE a (id int);")},
			"README.txt":    {Data: []byte("notes")},
			"sub/0002.sql":  {Data: []byte("SELECT 1;")},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Version != 1 {
			t.Fatalf("load = %+v, want only the 0001 migration", got)
		}
	})
}

// TestSplitStatementsEdgeCases pins the splitter's PostgreSQL-shaped edge
// cases: nested block comments, every dollar-quote shape, doubled quotes,
// unterminated constructs and multi-statement input around them.
func TestSplitStatementsEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want []string
	}{
		{
			name: "nested block comment hides semicolons",
			sql:  "SELECT 1 /* outer /* inner */ ; still outer */; SELECT 2",
			want: []string{"SELECT 1 /* outer /* inner */ ; still outer */", "SELECT 2"},
		},
		{
			name: "unterminated block comment consumes the rest",
			sql:  "SELECT 1; SELECT 2 /* never closed",
			want: []string{"SELECT 1", "SELECT 2 /* never closed"},
		},
		{
			name: "unterminated line comment consumes the rest",
			sql:  "SELECT 1; -- trailing without newline",
			want: []string{"SELECT 1"},
		},
		{
			name: "tagged dollar quote",
			sql:  "CREATE FUNCTION f() AS $t1$a;b$t1$; SELECT 2",
			want: []string{"CREATE FUNCTION f() AS $t1$a;b$t1$", "SELECT 2"},
		},
		{
			name: "untagged dollar quote",
			sql:  "SELECT $$a;b$$; SELECT 2",
			want: []string{"SELECT $$a;b$$", "SELECT 2"},
		},
		{
			name: "unterminated dollar quote consumes the rest",
			sql:  "CREATE FUNCTION f() AS $q$ BEGIN RETURN 1; END;",
			want: []string{"CREATE FUNCTION f() AS $q$ BEGIN RETURN 1; END;"},
		},
		{
			name: "bind-like dollar token is not a quote",
			sql:  "SELECT $1, $2; SELECT 3",
			want: []string{"SELECT $1, $2", "SELECT 3"},
		},
		{
			name: "invalid dollar tag emitted verbatim",
			sql:  "SELECT $a b$; SELECT 2",
			want: []string{"SELECT $a b$", "SELECT 2"},
		},
		{
			name: "lone trailing dollar",
			sql:  "SELECT 1$",
			want: []string{"SELECT 1$"},
		},
		{
			name: "dollar tag without a closing delimiter is not a quote",
			sql:  "SELECT $abc",
			want: []string{"SELECT $abc"},
		},
		{
			name: "doubled single quotes preserve semicolons",
			sql:  "SELECT 'it''s; fine'; SELECT 2",
			want: []string{"SELECT 'it''s; fine'", "SELECT 2"},
		},
		{
			name: "doubled double quotes preserve semicolons",
			sql:  `SELECT "a""b;c"; SELECT 2`,
			want: []string{`SELECT "a""b;c"`, "SELECT 2"},
		},
		{
			name: "unterminated single quote consumes the rest",
			sql:  "SELECT 'abc; SELECT 2",
			want: []string{"SELECT 'abc; SELECT 2"},
		},
		{
			name: "comment-only lines stripped per statement",
			sql:  "-- header\nSELECT 1;\n-- between\nSELECT 2;\n-- tail",
			want: []string{"SELECT 1", "SELECT 2"},
		},
		{
			name: "trailing statement without semicolon",
			sql:  "SELECT 1; SELECT 2",
			want: []string{"SELECT 1", "SELECT 2"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SplitStatements(tc.sql)
			if len(got) != len(tc.want) {
				t.Fatalf("SplitStatements(%q) = %q, want %q", tc.sql, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("statement %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestScanBlockComment pins depth tracking directly, including the
// unterminated case returning end-of-input.
func TestScanBlockComment(t *testing.T) {
	sql := "/* a /* b */ c */rest"
	if got := scanBlockComment(sql, 0); got != strings.Index(sql, "rest") {
		t.Fatalf("scanBlockComment = %d, want %d", got, strings.Index(sql, "rest"))
	}
	if got := scanBlockComment("/* open", 0); got != len("/* open") {
		t.Fatalf("scanBlockComment(unterminated) = %d, want %d", got, len("/* open"))
	}
	if got := scanBlockComment("/*/ still open", 0); got != len("/*/ still open") {
		t.Fatalf("scanBlockComment(/*/) = %d, want %d", got, len("/*/ still open"))
	}
}
