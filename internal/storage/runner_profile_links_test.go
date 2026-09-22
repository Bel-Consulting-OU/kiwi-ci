package storage

import (
	"context"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// runnerProfileContractStore is the surface the shared contract needs: the
// link contract under test plus the profile writes that seed the live rows.
type runnerProfileContractStore interface {
	RunnerProfileLinkStore
	ProfileStore
}

// runRunnerProfileLinkContract exercises the RunnerProfileLinkStore contract
// against one implementation. The mem store and the real-PostgreSQL IT both
// run it, so the in-memory mirror and the durable table are pinned to the
// same semantics: PRIMARY KEY uniqueness per runner, live profile joins,
// dangling-link fail-closed resolution, idempotent unlink and deterministic
// profile-scoped listing.
func runRunnerProfileLinkContract(t *testing.T, st runnerProfileContractStore) {
	t.Helper()
	ctx := context.Background()
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: "p-primary", Labels: []string{"container"}, MaxCapacity: 3}); err != nil {
		t.Fatalf("UpsertProfile p-primary: %v", err)
	}
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: "p-secondary", Labels: []string{"tart"}, MaxCapacity: 9}); err != nil {
		t.Fatalf("UpsertProfile p-secondary: %v", err)
	}

	// Empty IDs are rejected (matching the SQL parameter contract).
	if err := st.LinkRunnerProfile(ctx, "", "p-primary"); err == nil {
		t.Fatal("LinkRunnerProfile with an empty runner id must fail")
	}
	if err := st.LinkRunnerProfile(ctx, "r1", ""); err == nil {
		t.Fatal("LinkRunnerProfile with an empty profile id must fail")
	}
	if err := st.UnlinkRunnerProfile(ctx, ""); err == nil {
		t.Fatal("UnlinkRunnerProfile with an empty runner id must fail")
	}

	// Unbound runner: found=false, no error.
	if p, ok, err := st.ProfileForRunnerID(ctx, "r1"); err != nil || ok || p.ID != "" {
		t.Fatalf("unbound ProfileForRunnerID = (%+v, %v, %v)", p, ok, err)
	}
	// An empty runner ID names no binding and must resolve to not-found
	// (never to an arbitrary row).
	if p, ok, err := st.ProfileForRunnerID(ctx, ""); err != nil || ok || p.ID != "" {
		t.Fatalf("empty-id ProfileForRunnerID = (%+v, %v, %v)", p, ok, err)
	}
	if ids, err := st.RunnerIDsForProfile(ctx, "p-primary"); err != nil || len(ids) != 0 {
		t.Fatalf("unbound RunnerIDsForProfile = (%v, %v)", ids, err)
	}

	// Bind and resolve the LIVE profile row.
	if err := st.LinkRunnerProfile(ctx, "r1", "p-primary"); err != nil {
		t.Fatalf("LinkRunnerProfile: %v", err)
	}
	p, ok, err := st.ProfileForRunnerID(ctx, "r1")
	if err != nil || !ok || p.ID != "p-primary" || p.MaxCapacity != 3 || len(p.Labels) != 1 || p.Labels[0] != "container" {
		t.Fatalf("ProfileForRunnerID = (%+v, %v, %v)", p, ok, err)
	}
	// A second runner bound to the same profile is listed deterministically.
	if err := st.LinkRunnerProfile(ctx, "r0", "p-primary"); err != nil {
		t.Fatalf("LinkRunnerProfile r0: %v", err)
	}
	if ids, err := st.RunnerIDsForProfile(ctx, "p-primary"); err != nil || len(ids) != 2 || ids[0] != "r0" || ids[1] != "r1" {
		t.Fatalf("RunnerIDsForProfile = (%v, %v), want [r0 r1]", ids, err)
	}

	// The PRIMARY KEY replaces: re-linking r1 moves it to p-secondary and
	// leaves exactly one binding for the runner.
	if err := st.LinkRunnerProfile(ctx, "r1", "p-secondary"); err != nil {
		t.Fatalf("re-link: %v", err)
	}
	if p, ok, err := st.ProfileForRunnerID(ctx, "r1"); err != nil || !ok || p.ID != "p-secondary" {
		t.Fatalf("re-linked ProfileForRunnerID = (%+v, %v, %v)", p, ok, err)
	}
	if ids, err := st.RunnerIDsForProfile(ctx, "p-primary"); err != nil || len(ids) != 1 || ids[0] != "r0" {
		t.Fatalf("p-primary after re-link = (%v, %v), want [r0]", ids, err)
	}
	if ids, err := st.RunnerIDsForProfile(ctx, "p-secondary"); err != nil || len(ids) != 1 || ids[0] != "r1" {
		t.Fatalf("p-secondary after re-link = (%v, %v), want [r1]", ids, err)
	}

	// A dangling binding (profile row missing) resolves to not-found: the
	// caller fails closed instead of resurrecting a deleted profile.
	if err := st.LinkRunnerProfile(ctx, "r2", "p-missing"); err != nil {
		t.Fatalf("dangling LinkRunnerProfile: %v", err)
	}
	if _, ok, err := st.ProfileForRunnerID(ctx, "r2"); err != nil || ok {
		t.Fatalf("dangling ProfileForRunnerID ok=%v err=%v, want not found", ok, err)
	}

	// A profile edit is live on the next resolution.
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: "p-secondary", Labels: []string{"tart"}, MaxCapacity: 11}); err != nil {
		t.Fatalf("edit profile: %v", err)
	}
	if p, ok, err := st.ProfileForRunnerID(ctx, "r1"); err != nil || !ok || p.MaxCapacity != 11 {
		t.Fatalf("edited ProfileForRunnerID = (%+v, %v, %v), want capacity 11", p, ok, err)
	}

	// Unlink is idempotent and takes effect immediately.
	if err := st.UnlinkRunnerProfile(ctx, "r1"); err != nil {
		t.Fatalf("UnlinkRunnerProfile: %v", err)
	}
	if _, ok, err := st.ProfileForRunnerID(ctx, "r1"); err != nil || ok {
		t.Fatalf("unlinked ProfileForRunnerID ok=%v err=%v", ok, err)
	}
	if err := st.UnlinkRunnerProfile(ctx, "r1"); err != nil {
		t.Fatalf("second UnlinkRunnerProfile must be a no-op: %v", err)
	}

	// Empty/unknown profile listing stays an empty (non-nil) slice.
	if ids, err := st.RunnerIDsForProfile(ctx, ""); err != nil || ids == nil || len(ids) != 0 {
		t.Fatalf("RunnerIDsForProfile(\"\") = (%v, %v)", ids, err)
	}
	if ids, err := st.RunnerIDsForProfile(ctx, "p-unknown"); err != nil || ids == nil || len(ids) != 0 {
		t.Fatalf("RunnerIDsForProfile(unknown) = (%v, %v)", ids, err)
	}
}

// TestRunnerProfileLinksMemoryParity pins the in-memory mirror of migration
// 0031 to the RunnerProfileLinkStore contract the PostgreSQL IT also runs.
func TestRunnerProfileLinksMemoryParity(t *testing.T) {
	runRunnerProfileLinkContract(t, newMemStore())
}

// TestRunnerProfileLinksMigrationShape pins the deploy-safe shape of
// migration 0031: one new relation with the runner_id PRIMARY KEY the
// binding model relies on, added immediately after 0030, with no statement
// touching an existing (hot) relation.
func TestRunnerProfileLinksMigrationShape(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0031_runner_profile_links.sql")
	if err != nil {
		t.Fatalf("read 0031: %v", err)
	}
	sql := string(raw)
	if !strings.Contains(sql, "CREATE TABLE IF NOT EXISTS runner_profile_links") {
		t.Fatalf("0031 must create runner_profile_links idempotently:\n%s", sql)
	}
	if !strings.Contains(sql, "runner_id TEXT NOT NULL PRIMARY KEY") {
		t.Fatalf("0031 must make runner_id the PRIMARY KEY:\n%s", sql)
	}
	if !strings.Contains(sql, "profile_id TEXT NOT NULL") {
		t.Fatalf("0031 must declare profile_id NOT NULL:\n%s", sql)
	}
	for _, bad := range []string{"ALTER TABLE ", "UPDATE ", "DELETE FROM ", "INSERT INTO "} {
		if strings.Contains(sql, bad) {
			t.Fatalf("0031 must only create the new relation, found %q", bad)
		}
	}
	all, err := migrations.All()
	if err != nil {
		t.Fatalf("migrations.All: %v", err)
	}
	versions := map[int]string{}
	for _, m := range all {
		versions[m.Version] = m.Name
	}
	if versions[31] != "0031_runner_profile_links.sql" {
		t.Fatalf("version 31 = %q", versions[31])
	}
	if versions[30] != "0030_resource_reservations.sql" {
		t.Fatalf("0031 must follow 0030, version 30 = %q", versions[30])
	}
}
