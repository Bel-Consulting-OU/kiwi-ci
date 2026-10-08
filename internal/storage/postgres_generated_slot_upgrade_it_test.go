package storage

// Real-PostgreSQL regression for BLOCKER 3: migration 0043's UNIQUE
// (parent_job_id, fragment_id) index fails on a database that actually hit
// the pre-0043 duplicate-receipt bug, which is exactly the database the fix
// must upgrade. The immutable 0043 cannot be edited, so the migrator runs an
// idempotent preflight inside the SAME transaction: it creates the
// generated_fragments_conflicts evidence table, quarantines the older
// duplicate receipts (full generation/children/created_at preserved, reason
// 'duplicate semantic receipt (pre-0043 upgrade)') and deletes exactly those
// rows, so the index build succeeds. Migration 0047 then adds the mutation
// slot and quarantines the slot-level duplicates. Gated on
// KIWI_TEST_POSTGRES_URL like every *_it_test.go here.

import (
	"context"
	"fmt"
	"testing"
)

// TestPostgresIntegrationUpgradeFromV42QuarantinesDuplicateReceipts migrates
// a scratch database only through version 42, seeds the duplicate shape the
// old bug produced (same parent+fragment, two generations, different
// children), then runs the full Migrate: it must succeed, keep the newest
// receipt, preserve the older one (children intact) in
// generated_fragments_conflicts, and still serve the newest children through
// GetGeneratedFragment. A fresh database still gets both unique indexes.
func TestPostgresIntegrationUpgradeFromV42QuarantinesDuplicateReceipts(t *testing.T) {
	env := pgITSetupAtVersion(t, 42)
	st := env.open(t)
	ctx := context.Background()

	parent := pgITNewID(t)
	const fragment = "frag-duplicate-receipt"
	oldChild, newChild := pgITNewID(t), pgITNewID(t)
	seed := func(generation int64, child, age string) {
		t.Helper()
		if _, err := st.pool.Exec(ctx, fmt.Sprintf(
			`INSERT INTO generated_fragments (parent_job_id, lease_generation, fragment_id, children, created_at)
			 VALUES ($1, $2, $3, jsonb_build_array(jsonb_build_object('key', 'child', 'id', $4::text)), now() - interval '%s')`,
			age), parent, generation, fragment, child); err != nil {
			t.Fatalf("seed duplicate receipt gen%d: %v", generation, err)
		}
	}
	seed(1, oldChild, "1 hour")
	seed(2, newChild, "1 minute")

	// The real startup migration path applies 0043 (with the preflight), 0044
	// through 0047. Pre-fix it aborted here on the unique index build.
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate from v42 with duplicate receipts: %v", err)
	}
	if v, err := st.SchemaVersion(ctx); err != nil || v != pgITLatestVersion(t) {
		t.Fatalf("SchemaVersion = %d, %v; want %d", v, err, pgITLatestVersion(t))
	}

	// Exactly the newest receipt survives, with its children.
	var survivingGen int64
	var survivingChild string
	if err := st.pool.QueryRow(ctx,
		`SELECT lease_generation, children->0->>'id' FROM generated_fragments WHERE parent_job_id=$1 AND fragment_id=$2`,
		parent, fragment).Scan(&survivingGen, &survivingChild); err != nil {
		t.Fatalf("read surviving receipt: %v", err)
	}
	if survivingGen != 2 || survivingChild != newChild {
		t.Fatalf("surviving receipt = gen%d child %s, want gen2 child %s", survivingGen, survivingChild, newChild)
	}

	// The older duplicate is preserved in the evidence table, children intact.
	var conflictGen int64
	var conflictChild, reason string
	if err := st.pool.QueryRow(ctx,
		`SELECT lease_generation, children->0->>'id', reason FROM generated_fragments_conflicts WHERE parent_job_id=$1 AND fragment_id=$2`,
		parent, fragment).Scan(&conflictGen, &conflictChild, &reason); err != nil {
		t.Fatalf("read quarantined receipt: %v", err)
	}
	if conflictGen != 1 || conflictChild != oldChild {
		t.Fatalf("quarantined receipt = gen%d child %s, want gen1 child %s", conflictGen, conflictChild, oldChild)
	}
	if reason != "duplicate semantic receipt (pre-0043 upgrade)" {
		t.Fatalf("quarantine reason = %q", reason)
	}

	// The receipt read serves the newest children under the default slot.
	rec, ok, err := st.GetGeneratedFragment(ctx, parent, GeneratedFragmentMutationSlotDefault)
	if err != nil || !ok || len(rec.Children) != 1 || rec.Children[0].ID != newChild {
		t.Fatalf("GetGeneratedFragment = %+v, %v, %v; want the newest child %s", rec, ok, err, newChild)
	}

	// Both unique identities are live after the upgrade.
	for _, idx := range []string{"generated_fragments_mutation_idx", "generated_fragments_slot_idx"} {
		var exists bool
		if err := st.pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, idx).Scan(&exists); err != nil || !exists {
			t.Fatalf("index %s missing after upgrade: exists=%v err=%v", idx, exists, err)
		}
	}

	// Idempotent: a second Migrate is a no-op and does not re-quarantine.
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	var conflicts int
	if err := st.pool.QueryRow(ctx, `SELECT COUNT(*) FROM generated_fragments_conflicts WHERE parent_job_id=$1`, parent).Scan(&conflicts); err != nil {
		t.Fatalf("count conflicts: %v", err)
	}
	if conflicts != 1 {
		t.Fatalf("conflicts after second Migrate = %d, want 1", conflicts)
	}

	// A FRESH database still creates both unique indexes from scratch.
	fresh := pgITStore(t)
	for _, idx := range []string{"generated_fragments_mutation_idx", "generated_fragments_slot_idx"} {
		var exists bool
		if err := fresh.pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, idx).Scan(&exists); err != nil || !exists {
			t.Fatalf("fresh database index %s missing: exists=%v err=%v", idx, exists, err)
		}
	}
}
