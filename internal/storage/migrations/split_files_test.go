package migrations

import (
	"strings"
	"testing"
)

// TestMigrationSplitOutboxForgeVersionsFilesInOrder pins the deploy-safety
// split of the versioned forge-delivery migration. The runner applies every
// migration FILE in one transaction (internal/storage/postgres.go
// applyMigration), so a file that both ALTERs outbox and builds indexes holds
// the ALTER's ACCESS EXCLUSIVE lock across every index build, blocking all
// outbox writes. The split guarantees:
//
//	0018 = the two metadata-only ADD COLUMNs + the new watermark table,
//	0019 = the unique (logical_key, state_version) index,
//	0020 = the pending partial index,
//
// each of 0019/0020 a single-statement file whose SHARE lock on outbox is
// released before the next migration starts.
func TestMigrationSplitOutboxForgeVersionsFilesInOrder(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	byVersion := map[int]Migration{}
	order := map[int]int{}
	for i, m := range all {
		byVersion[m.Version] = m
		order[m.Version] = i
	}
	for _, v := range []int{18, 19, 20} {
		if _, ok := byVersion[v]; !ok {
			t.Fatalf("split migration %04d missing from embedded set", v)
		}
	}
	if !(order[18] < order[19] && order[19] < order[20]) {
		t.Fatalf("split migrations not applied in order: 18@%d 19@%d 20@%d", order[18], order[19], order[20])
	}
	if got := byVersion[18].Name; got != "0018_outbox_forge_versions.sql" {
		t.Errorf("0018 file = %q", got)
	}
	if got := byVersion[19].Name; got != "0019_outbox_logical_version_index.sql" {
		t.Errorf("0019 file = %q", got)
	}
	if got := byVersion[20].Name; got != "0020_outbox_logical_pending_index.sql" {
		t.Errorf("0020 file = %q", got)
	}

	m18 := byVersion[18]
	if len(m18.Statements) != 3 {
		t.Fatalf("0018 statements = %d, want 2 ALTERs + CREATE TABLE", len(m18.Statements))
	}
	for _, s := range m18.Statements {
		if strings.Contains(s, "CREATE INDEX") || strings.Contains(s, "CREATE UNIQUE INDEX") {
			t.Errorf("0018 contains an index build: %q", s)
		}
		if !strings.Contains(s, "ALTER TABLE outbox ADD COLUMN IF NOT EXISTS") &&
			!strings.Contains(s, "CREATE TABLE IF NOT EXISTS forge_check_state") {
			t.Errorf("0018 has an unexpected statement: %q", s)
		}
	}
	for _, v := range []int{19, 20} {
		m := byVersion[v]
		if len(m.Statements) != 1 {
			t.Fatalf("%04d statements = %d, want 1", v, len(m.Statements))
		}
		s := m.Statements[0]
		if !strings.Contains(s, "IF NOT EXISTS") {
			t.Errorf("%04d must preserve IF NOT EXISTS semantics: %q", v, s)
		}
		if !strings.Contains(s, "ON outbox (logical_key, state_version)") {
			t.Errorf("%04d lost the (logical_key, state_version) index target: %q", v, s)
		}
	}
	if s := byVersion[19].Statements[0]; !strings.Contains(s, "CREATE UNIQUE INDEX") {
		t.Errorf("0019 must stay UNIQUE: %q", s)
	}
	if s := byVersion[20].Statements[0]; strings.Contains(s, "UNIQUE") {
		t.Errorf("0020 must stay non-unique: %q", s)
	}
}
