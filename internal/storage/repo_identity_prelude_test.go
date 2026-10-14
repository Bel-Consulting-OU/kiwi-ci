package storage

import (
	"strings"
	"testing"
)

// TestEnsureRepoIdentityFunctionsSQLDependencyOrder: the restore prelude
// must emit the function family in call order so a vanilla pg_restore can
// create expression indexes that inline them. kiwi_canonical_repo_id has to
// appear before either normalize_* body that calls it.
func TestEnsureRepoIdentityFunctionsSQLDependencyOrder(t *testing.T) {
	sql := EnsureRepoIdentityFunctionsSQL()
	want := []string{
		"CREATE OR REPLACE FUNCTION kiwi_canonical_host",
		"CREATE OR REPLACE FUNCTION kiwi_canonical_repo_id",
		"CREATE OR REPLACE FUNCTION kiwi_normalize_run_repo_identity",
		"CREATE OR REPLACE FUNCTION kiwi_normalize_run_repo_full_name",
	}
	pos := -1
	for _, w := range want {
		i := strings.Index(sql, w)
		if i < 0 {
			t.Fatalf("missing %s in prelude", w)
		}
		if i <= pos {
			t.Fatalf("%s must come after the previous function (pos %d <= %d)", w, i, pos)
		}
		pos = i
	}
	// Every CREATE must be IMMUTABLE SQL so pg_dump can inline them the same
	// way the expression indexes do.
	if strings.Count(sql, "LANGUAGE sql IMMUTABLE") != len(want) {
		t.Fatalf("expected %d IMMUTABLE SQL functions, got %d", len(want), strings.Count(sql, "LANGUAGE sql IMMUTABLE"))
	}
	// The normalize bodies must call the canonical function (the dependency
	// the index relies on).
	if !strings.Contains(sql, "kiwi_canonical_repo_id(payload, url_key)") {
		t.Fatal("normalize bodies must call kiwi_canonical_repo_id")
	}
}
