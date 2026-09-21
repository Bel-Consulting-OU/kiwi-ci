package storage

// Two-store real-PostgreSQL regression for the downstream-launch leadership
// fence (migration 0025). The downstream child-enqueue claim and the
// leader-owned reservation lifecycle (reserve / release / parent-edge append)
// must be epoch-fenced: a replica whose cached leadership claim outlived its
// advisory-lock session commits NONE of them, while the current leader
// commits each exactly once. The unfenced operator/compatibility variants
// keep working without an epoch, which is the deliberate operator surface.
//
// Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go here. The two
// stores are two pools over ONE schema, mirroring two control-plane replicas
// of one deployment.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestPostgresIntegrationDownstreamLeaderFenceStaleStoreMutatesNothing(t *testing.T) {
	env := pgITSetup(t)
	a := env.open(t)
	env.migrate(t, a)
	b := env.open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	key := "kiwi-it-downstream-fence-" + pgITRandomHex(t, 8)

	// A acquires leadership (epoch N) and its dedicated session is killed the
	// way a crashed backend does: the advisory lock dies server-side while A
	// still retains epoch N.
	if got, err := a.TryAcquireLeadership(ctx, key, time.Minute); err != nil || !got {
		t.Fatalf("A acquire = %v, %v", got, err)
	}
	epochA, ok := a.LeaderEpoch()
	if !ok || epochA < 1 {
		t.Fatalf("A retained epoch = %d/%v; want a published epoch", epochA, ok)
	}
	if a.leaderConn == nil {
		t.Fatal("A has no dedicated leader session to kill")
	}
	_ = a.leaderConn.Close(ctx)

	// B takes the freed lock and publishes a strictly greater epoch N+1.
	var epochB int64
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := b.TryAcquireLeadership(ctx, key, time.Minute)
		if err != nil {
			t.Fatalf("B acquire = %v, %v", got, err)
		}
		if got {
			epochB, ok = b.LeaderEpoch()
			if !ok {
				t.Fatal("B acquired but retained no epoch")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("B never acquired the lock A's dead session released")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if epochB <= epochA {
		t.Fatalf("epoch after hand-over = %d; want strictly greater than A's %d", epochB, epochA)
	}

	// B is a standby before this loop: a store that never acquired fails the
	// leader variants closed as well (no retained epoch).
	standby := env.open(t)
	if won, err := standby.ReserveDownstreamLaunchLeader(ctx, pgITNewID(t), "acme/child", "refs/heads/main", "tok"); !errors.Is(err, ErrStaleLeader) || won {
		t.Fatalf("standby ReserveDownstreamLaunchLeader = %v/%v; want false/ErrStaleLeader", won, err)
	}

	// --- Seed the rows the fence must leave untouched. -------------------
	parentJob, parentRun := pgITNewID(t), pgITNewID(t)
	pgITRecSeedRun(t, a, parentRun, model.StatusRunning, map[string]model.Job{parentJob: pgITJob(parentRun, parentJob, pgITRepo)})

	stableChild := strings.Repeat("ab", 32)
	childRunID := stableChild[:32]
	linkKey := parentJob + "\x00acme/child\x00refs/heads/main"
	link := DownstreamLink{
		ParentJobID: parentJob, TargetRepo: "acme/child", TargetRef: "refs/heads/main",
		LaunchToken: "tok", TargetForge: "github", StableChildID: stableChild, CreatedAt: now,
	}
	if err := a.InsertDownstreamLink(ctx, link); err != nil {
		t.Fatalf("insert link: %v", err)
	}

	// A second link, already reserved, for the release audit.
	relJob := pgITNewID(t)
	reservedAt := now.Add(-time.Minute)
	if err := a.InsertDownstreamLink(ctx, DownstreamLink{
		ParentJobID: relJob, TargetRepo: "acme/child", TargetRef: "refs/heads/main",
		LaunchToken: "tok", Reserved: true, ReservedAt: &reservedAt, CreatedAt: now,
	}); err != nil {
		t.Fatalf("insert reserved link: %v", err)
	}

	// Each stale call re-arms A's retained epoch first: the first rejection
	// clears it (fail closed), and every mutation class must still be
	// rejected by the fence INSIDE its own transaction, not merely locally.
	stale := func(op string, err error) {
		t.Helper()
		if !errors.Is(err, ErrStaleLeader) {
			t.Fatalf("%s with A's stale epoch = %v; want ErrStaleLeader", op, err)
		}
	}

	// 1. Reservation: rejected, no reservation recorded.
	a.SetLeaderEpoch(epochA)
	won, err := a.ReserveDownstreamLaunchLeader(ctx, parentJob, "acme/child", "refs/heads/main", "tok")
	stale("ReserveDownstreamLaunchLeader", err)
	if won {
		t.Fatal("stale ReserveDownstreamLaunchLeader reported a won reservation")
	}
	if l, found, gerr := a.GetDownstreamLink(ctx, parentJob, "acme/child", "refs/heads/main"); gerr != nil || !found || l.Reserved || l.ChildRunID != "" {
		t.Fatalf("stale reservation mutated the link: found=%v reserved=%v child=%q err=%v", found, l.Reserved, l.ChildRunID, gerr)
	}

	// 2. Release: rejected, the reservation stays (the leader expiry sweep,
	// not the stale leader, reclaims it).
	a.SetLeaderEpoch(epochA)
	stale("ReleaseDownstreamReservationLeader", a.ReleaseDownstreamReservationLeader(ctx, relJob, "acme/child", "refs/heads/main"))
	if l, found, gerr := a.GetDownstreamLink(ctx, relJob, "acme/child", "refs/heads/main"); gerr != nil || !found || !l.Reserved {
		t.Fatalf("stale release mutated the reserved link: found=%v reserved=%v err=%v", found, l.Reserved, gerr)
	}

	// 3. Parent edge append: rejected, the parent run keeps no edge.
	a.SetLeaderEpoch(epochA)
	stale("AppendDownstreamRunLeader", a.AppendDownstreamRunLeader(ctx, parentRun, childRunID))
	if run, gerr := a.GetRun(ctx, parentRun); gerr != nil || len(run.DownstreamRuns) != 0 {
		t.Fatalf("stale append mutated the parent run: downstream_runs=%v err=%v", run.DownstreamRuns, gerr)
	}

	// 4. Child enqueue with the downstream launch claim: rejected before the
	// first insert, so no child run, no link update, no reservation consumed.
	childJob := pgITNewID(t)
	enqueueReq := InsertCompiledRunRequest{
		Run:  pgITRun(childRunID, model.StatusQueued),
		Jobs: map[string]model.Job{childJob: pgITJob(childRunID, childJob, pgITRepo)},
		DownstreamLaunch: &DownstreamLaunchClaim{
			LinkKey:       linkKey,
			StableChildID: stableChild,
		},
	}
	a.SetLeaderEpoch(epochA)
	stale("InsertCompiledRun(downstream)", a.InsertCompiledRun(ctx, enqueueReq))
	if _, gerr := a.GetRun(ctx, childRunID); !errors.Is(gerr, ErrNotFound) {
		t.Fatalf("stale downstream enqueue inserted the child run: err=%v", gerr)
	}
	if l, found, gerr := a.GetDownstreamLink(ctx, parentJob, "acme/child", "refs/heads/main"); gerr != nil || !found || l.ChildRunID != "" || l.Reserved {
		t.Fatalf("stale downstream enqueue mutated the link: found=%v child=%q reserved=%v err=%v", found, l.ChildRunID, l.Reserved, gerr)
	}

	// The first rejections cleared A's retained epoch (fail-closed proof).
	if epoch, ok := a.LeaderEpoch(); ok {
		t.Fatalf("stale store still retains epoch %d", epoch)
	}

	// --- Operator paths keep working WITHOUT a leadership epoch: the
	// unfenced variants are safety/admin operations, not leader authority,
	// and the child enqueue is the fenced step that decides a launch. -----
	opJob := pgITNewID(t)
	if won, err := a.ReserveDownstreamLaunch(ctx, opJob, "acme/child", "refs/heads/main", "op-tok"); err != nil || !won {
		t.Fatalf("operator reserve without epoch = %v/%v; want true/nil", won, err)
	}
	if err := a.ReleaseDownstreamReservation(ctx, opJob, "acme/child", "refs/heads/main"); err != nil {
		t.Fatalf("operator release without epoch = %v; want nil", err)
	}
	if l, _, gerr := a.GetDownstreamLink(ctx, opJob, "acme/child", "refs/heads/main"); gerr != nil || l.Reserved {
		t.Fatalf("operator release left reserved=%v err=%v", l.Reserved, gerr)
	}
	if err := a.MarkDownstreamLaunched(ctx, opJob, "acme/child", "refs/heads/main", childRunID); err != nil {
		t.Fatalf("operator MarkDownstreamLaunched without epoch = %v; want nil", err)
	}
	if err := a.AppendDownstreamRun(ctx, parentRun, childRunID); err != nil {
		t.Fatalf("operator AppendDownstreamRun without epoch = %v; want nil", err)
	}
	if run, gerr := a.GetRun(ctx, parentRun); gerr != nil || len(run.DownstreamRuns) != 1 || run.DownstreamRuns[0] != childRunID {
		t.Fatalf("operator append did not record the edge: %v err=%v", run.DownstreamRuns, gerr)
	}

	// --- The current leader (B, epoch N+1) commits the same work exactly
	// once with the SAME stable child ID. --------------------------------
	won, err = b.ReserveDownstreamLaunchLeader(ctx, parentJob, "acme/child", "refs/heads/main", "tok")
	if err != nil || !won {
		t.Fatalf("B ReserveDownstreamLaunchLeader = %v/%v; want true/nil", won, err)
	}
	if err := b.InsertCompiledRun(ctx, enqueueReq); err != nil {
		t.Fatalf("B downstream enqueue = %v", err)
	}
	if l, found, gerr := b.GetDownstreamLink(ctx, parentJob, "acme/child", "refs/heads/main"); gerr != nil || !found || l.ChildRunID != childRunID || l.StableChildID != stableChild || l.Reserved {
		t.Fatalf("B launch left the link wrong: found=%v child=%q stable=%q reserved=%v err=%v", found, l.ChildRunID, l.StableChildID, l.Reserved, gerr)
	}
	if child, gerr := b.GetRun(ctx, childRunID); gerr != nil || child.RepoFullName != "kiwi-it/repo" {
		t.Fatalf("B child run = %+v err=%v", child, gerr)
	}
	// Replay: the same stable child is idempotent, the link is taken.
	if err := b.InsertCompiledRun(ctx, enqueueReq); !errors.Is(err, ErrDownstreamLaunched) {
		t.Fatalf("B downstream enqueue replay = %v; want ErrDownstreamLaunched", err)
	}
	if won, err := b.ReserveDownstreamLaunchLeader(ctx, parentJob, "acme/child", "refs/heads/main", "tok"); err != nil || won {
		t.Fatalf("B re-reserve after launch = %v/%v; want false/nil", won, err)
	}

	// B's leader-fenced release works on the reserved link.
	if err := b.ReleaseDownstreamReservationLeader(ctx, relJob, "acme/child", "refs/heads/main"); err != nil {
		t.Fatalf("B ReleaseDownstreamReservationLeader = %v", err)
	}
	if l, _, gerr := b.GetDownstreamLink(ctx, relJob, "acme/child", "refs/heads/main"); gerr != nil || l.Reserved {
		t.Fatalf("B release left reserved=%v err=%v", l.Reserved, gerr)
	}
}
