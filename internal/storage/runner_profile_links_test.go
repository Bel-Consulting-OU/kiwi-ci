package storage

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// runnerProfileContractStore is the surface the shared contract needs: the
// link contract under test, the profile writes that seed the live rows, and
// the runner reads/writes that seed and observe the marked registration
// snapshot the unlink must revoke.
type runnerProfileContractStore interface {
	RunnerProfileLinkStore
	ProfileStore
	UpsertRunner(ctx context.Context, runner model.Runner) error
	GetRunner(ctx context.Context, id string) (model.Runner, error)
}

// runRunnerProfileLinkContract exercises the RunnerProfileLinkStore contract
// against one implementation. The mem store and the real-PostgreSQL IT both
// run it, so the in-memory mirror and the durable table are pinned to the
// same semantics: PRIMARY KEY uniqueness per runner, live profile joins,
// dangling-link fail-closed resolution, revocation on unlink (binding row AND
// profile-derived snapshot fields cleared together), idempotent unlink and
// deterministic profile-scoped listing.
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

	// Unlink is REVOCATION: a marked runner row (its scheduling attributes
	// were copied from the linked profile) has those attributes cleared in
	// the same operation as the binding row, so the removed profile cannot
	// keep applying through the registration snapshot. Unmarked rows
	// (self-reported dev-mode attributes) are untouched. The runner IDs are
	// canonical (32 hex) because the SQL store validates them.
	const markedID, unmarkedID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02"
	if err := st.UpsertRunner(ctx, model.Runner{
		ID: markedID, Name: "marked", ProfileID: "p-primary",
		Labels: []string{"container"}, Region: "region-1", AllowedRepositories: []string{"github.com/o/mine"},
		Capabilities: []string{"container"}, Capacity: 3, ResourceCapacity: model.ResourceCapacity{CPU: 2, Memory: 1 << 30, Disk: 2 << 30, PIDs: 128},
		CostPerHour: 1.5, PowerWatts: 75, Busy: true, ActiveJobs: []string{"job-1"}, CurrentJob: "job-1",
	}); err != nil {
		t.Fatalf("seed marked runner: %v", err)
	}
	if err := st.UpsertRunner(ctx, model.Runner{ID: unmarkedID, Name: "unmarked", Labels: []string{"self"}, Capacity: 5}); err != nil {
		t.Fatalf("seed unmarked runner: %v", err)
	}
	for _, id := range []string{markedID, unmarkedID} {
		if err := st.LinkRunnerProfile(ctx, id, "p-primary"); err != nil {
			t.Fatalf("link %s: %v", id, err)
		}
	}
	if err := st.UnlinkRunnerProfile(ctx, markedID); err != nil {
		t.Fatalf("unlink marked: %v", err)
	}
	got, err := st.GetRunner(ctx, markedID)
	if err != nil {
		t.Fatalf("get marked: %v", err)
	}
	if got.ProfileID != "" || got.Labels != nil || got.Region != "" || got.AllowedRepositories != nil ||
		got.Capabilities != nil || got.Capacity != 0 || got.ResourceCapacity != (model.ResourceCapacity{}) ||
		got.CostPerHour != 0 || got.PowerWatts != 0 || got.Busy {
		t.Fatalf("marked runner after unlink = %+v, want the profile-derived fields cleared", got)
	}
	// The runner's own non-derived state survives: identity, admin state,
	// active jobs and metadata are not profile grants.
	if got.ID != markedID || got.Name != "marked" || len(got.ActiveJobs) != 1 || got.ActiveJobs[0] != "job-1" || got.CurrentJob != "job-1" {
		t.Fatalf("marked runner lost non-derived state: %+v", got)
	}
	if err := st.UnlinkRunnerProfile(ctx, unmarkedID); err != nil {
		t.Fatalf("unlink unmarked: %v", err)
	}
	got, err = st.GetRunner(ctx, unmarkedID)
	if err != nil {
		t.Fatalf("get unmarked: %v", err)
	}
	if got.ProfileID != "" || got.Capacity != 5 || len(got.Labels) != 1 || got.Labels[0] != "self" {
		t.Fatalf("unmarked runner after unlink = %+v, want its own self-reported attributes", got)
	}
	// Unlinking a runner that never registered is a successful no-op.
	if err := st.UnlinkRunnerProfile(ctx, "r-never-registered"); err != nil {
		t.Fatalf("unbound unregistered unlink: %v", err)
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

// TestRunnerProfileLinksFaultyStoreParity: the fault-injectable wrapper
// delegates the whole RunnerProfileLinkStore contract — revocation on unlink
// included — to the wrapped store, so the mem/PG parity holds under the
// fault-injection wiring as well (a fault-injected unlink returns before the
// inner call and revokes nothing).
func TestRunnerProfileLinksFaultyStoreParity(t *testing.T) {
	runRunnerProfileLinkContract(t, &FaultyStore{Inner: newMemStore()})
}

// TestFaultyStoreFailedUnlinkRevokesNothing: an injected write failure makes
// the unlink fail BEFORE the inner call, so neither the binding nor the
// marked snapshot is touched — revocation is all-or-nothing.
func TestFaultyStoreFailedUnlinkRevokesNothing(t *testing.T) {
	ctx := context.Background()
	inner := newMemStore()
	runnerID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa03"
	if err := inner.UpsertProfile(ctx, model.RunnerProfile{ID: "p-fault", Labels: []string{"bound"}, MaxCapacity: 2}); err != nil {
		t.Fatal(err)
	}
	if err := inner.UpsertRunner(ctx, model.Runner{ID: runnerID, ProfileID: "p-fault", Capacity: 2, Labels: []string{"bound"}}); err != nil {
		t.Fatal(err)
	}
	if err := inner.LinkRunnerProfile(ctx, runnerID, "p-fault"); err != nil {
		t.Fatal(err)
	}
	f := &FaultyStore{Inner: inner, FailAfter: 1, Err: errors.New("synthetic unlink failure")}
	if err := f.UnlinkRunnerProfile(ctx, runnerID); err == nil {
		t.Fatal("fault-injected unlink must fail")
	}
	if _, ok, err := inner.ProfileForRunnerID(ctx, runnerID); err != nil || !ok {
		t.Fatalf("failed unlink dropped the binding: ok=%v err=%v", ok, err)
	}
	got, err := inner.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProfileID != "p-fault" || got.Capacity != 2 || len(got.Labels) != 1 {
		t.Fatalf("failed unlink cleared the snapshot: %+v", got)
	}
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
