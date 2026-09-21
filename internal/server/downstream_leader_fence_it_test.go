package server

// Two-store real-PostgreSQL regression for the downstream launch chain under
// the leadership-epoch fence (migration 0025). Replica A claims a downstream
// outbox row as leader epoch N, loses its leadership session (B acquires and
// publishes N+1) and then continues dispatchDownstream: every mutation of the
// chain — the link reservation, the child enqueue, the wait=true parent edge
// and the outbox ACK — must fail with storage.ErrStaleLeader and commit
// nothing. B's dispatch of the SAME work then succeeds exactly once with the
// stable child run ID preserved.
//
// Gated on KIWI_TEST_POSTGRES_URL like the other integration tests in this
// package. The two stores are two pools over ONE schema, mirroring two
// control-plane replicas of one deployment.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func TestPostgresIntegrationDownstreamFenceStaleLeaderDispatch(t *testing.T) {
	env := pgITServerSetup(t)
	storeA := env.open(t)
	storeB := env.open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	key := "kiwi-it-downstream-dispatch-" + pgITServerRandomHex(t, 8)

	sA, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatalf("NewPersistent A: %v", err)
	}
	if err := sA.SwitchToDB(storeA); err != nil {
		t.Fatalf("SwitchToDB A: %v", err)
	}
	sB, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatalf("NewPersistent B: %v", err)
	}
	if err := sB.SwitchToDB(storeB); err != nil {
		t.Fatalf("SwitchToDB B: %v", err)
	}
	fetcher := func(context.Context, string, string) (string, error) { return pgITServerPipeline, nil }
	sA.DownstreamPipelineFetcher = fetcher
	sB.DownstreamPipelineFetcher = fetcher
	allow := map[string][]string{"github.com/acme/child": {}}
	sA.DownstreamAllowlist = allow
	sB.DownstreamAllowlist = allow

	// A acquires leadership (epoch N).
	if got, err := storeA.TryAcquireLeadership(ctx, key, time.Minute); err != nil || !got {
		t.Fatalf("A acquire = %v, %v", got, err)
	}
	epochA, ok := storeA.LeaderEpoch()
	if !ok || epochA < 1 {
		t.Fatalf("A retained epoch = %d/%v; want a published epoch", epochA, ok)
	}

	// --- Seed a completed parent run and its durable downstream intent,
	// exactly as recordDownstreamIntents would. ---------------------------
	parentRunID, parentJobID := pgITServerRandomHex(t, 32), pgITServerRandomHex(t, 32)
	parentJob := model.Job{
		ID: parentJobID, RunID: parentRunID, Key: "build", RepoURL: "https://github.com/o/r.git",
		RepoFullName: "o/r", Status: model.StatusSuccess, CreatedAt: now,
	}
	if err := storeA.InsertCompiledRun(ctx, storage.InsertCompiledRunRequest{
		Run:  model.Run{ID: parentRunID, Repo: "https://github.com/o/r.git", RepoFullName: "o/r", Status: model.StatusSuccess, CreatedAt: now},
		Jobs: map[string]model.Job{parentJobID: parentJob},
	}); err != nil {
		t.Fatalf("seed parent run: %v", err)
	}
	stableKey := downstreamStableKey(parentJobID, "acme/child", "refs/heads/main")
	stableChildID := downstreamStableChildRunID(stableKey)
	if err := storeA.InsertDownstreamLink(ctx, storage.DownstreamLink{
		ParentJobID: parentJobID, TargetRepo: "acme/child", TargetRef: "refs/heads/main",
		LaunchToken: "tok", TargetForge: "github", StableChildID: stableKey, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed downstream link: %v", err)
	}
	payload, err := json.Marshal(downstreamPayload{
		ParentJobID: parentJobID, ParentRunID: parentRunID, TargetRepo: "acme/child",
		TargetRef: "refs/heads/main", LaunchToken: "tok", Event: "upstream", Wait: true, Forge: "github",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := storeA.OutboxAppend(ctx, storage.OutboxItem{ID: stableKey, Kind: forge.OutboxKindDownstream, Payload: payload, CreatedAt: now}); err != nil {
		t.Fatalf("seed downstream intent: %v", err)
	}

	// A claims the downstream outbox work as leader epoch N (the claim itself
	// is fenced and admissible while A is current).
	claimed, err := storeA.ClaimOutbox(ctx, "replica-a", storage.OutboxClaimBatch)
	if err != nil {
		t.Fatalf("A ClaimOutbox: %v", err)
	}
	var item forge.OutboxItem
	found := false
	for _, c := range claimed {
		if c.ID == stableKey {
			item = forge.OutboxItem{ID: c.ID, Kind: c.Kind, Payload: c.Payload, CreatedAt: c.CreatedAt}
			found = true
		}
	}
	if !found {
		t.Fatalf("A did not claim the downstream row %s (claimed %d rows)", stableKey, len(claimed))
	}

	// Kill A's leadership session; B takes the freed lock and publishes a
	// strictly greater epoch N+1, while A keeps presenting the stale epoch N
	// (the cached-proof window the fence must neutralize). In production A's
	// session dies underneath the cached claim; ReleaseLeadership +
	// SetLeaderEpoch reproduces exactly that observable state through the
	// exported API.
	if err := storeA.ReleaseLeadership(ctx, key); err != nil {
		t.Fatalf("A release: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	var epochB int64
	for {
		got, err := storeB.TryAcquireLeadership(ctx, key, time.Minute)
		if err != nil {
			t.Fatalf("B acquire = %v, %v", got, err)
		}
		if got {
			epochB, ok = storeB.LeaderEpoch()
			if !ok {
				t.Fatal("B acquired but retained no epoch")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("B never acquired the leadership claim")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if epochB <= epochA {
		t.Fatalf("epoch after hand-over = %d; want strictly greater than A's %d", epochB, epochA)
	}
	storeA.SetLeaderEpoch(epochA)

	// --- A continues dispatchDownstream: fenced, commits nothing. ---------
	if err := sA.dispatchDownstream(ctx, item); !errors.Is(err, storage.ErrStaleLeader) {
		t.Fatalf("stale dispatchDownstream = %v; want storage.ErrStaleLeader", err)
	}
	// No reservation row: the seeded link is still unreserved and unlaunched.
	if l, ok, err := storeA.GetDownstreamLink(ctx, parentJobID, "acme/child", "refs/heads/main"); err != nil || !ok || l.Reserved || l.ChildRunID != "" {
		t.Fatalf("stale dispatch mutated the link: found=%v reserved=%v child=%q err=%v", ok, l.Reserved, l.ChildRunID, err)
	}
	// No child run.
	if _, err := storeA.GetRun(ctx, stableChildID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("stale dispatch created the child run: err=%v", err)
	}
	// No parent downstream edge.
	if parent, err := storeA.GetRun(ctx, parentRunID); err != nil || len(parent.DownstreamRuns) != 0 {
		t.Fatalf("stale dispatch recorded a parent edge: downstream_runs=%v err=%v", parent.DownstreamRuns, err)
	}

	// The remaining chain mutations are fenced too. The exact server enqueue
	// the dispatch performs (admission, then InsertCompiledRun carrying the
	// downstream claim) is rejected with A's stale epoch: no child run, no
	// link update, no reservation consumed.
	storeA.SetLeaderEpoch(epochA)
	_, err = sA.enqueueID(ctx, SubmitRun{
		RepoID:          "github.com/acme/child",
		PolicyRepoID:    "github.com/acme/child",
		CheckoutRepoURL: "https://github.com/acme/child",
		RepoURL:         "https://github.com/acme/child",
		RepoFullName:    "acme/child",
		Ref:             "refs/heads/main",
		Event:           "upstream",
		Pipeline:        pgITServerPipeline,
		Metadata:        map[string]string{"downstream_of": parentRunID, "downstream_job": parentJobID, "downstream_token": "tok"},
		identityBound:   true,
		DownstreamLaunch: &storage.DownstreamLaunchClaim{
			LinkKey:       downstreamLinkKey(parentJobID, "acme/child", "refs/heads/main"),
			StableChildID: stableKey,
		},
	}, stableChildID)
	if !errors.Is(err, storage.ErrStaleLeader) {
		t.Fatalf("stale downstream child enqueue = %v; want storage.ErrStaleLeader", err)
	}
	if _, err := storeA.GetRun(ctx, stableChildID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("stale child enqueue inserted the child run: err=%v", err)
	}
	if l, _, err := storeA.GetDownstreamLink(ctx, parentJobID, "acme/child", "refs/heads/main"); err != nil || l.ChildRunID != "" || l.Reserved {
		t.Fatalf("stale child enqueue mutated the link: child=%q reserved=%v err=%v", l.ChildRunID, l.Reserved, err)
	}
	// ... and so is the wait=true parent edge append.
	storeA.SetLeaderEpoch(epochA)
	if err := storeA.AppendDownstreamRunLeader(ctx, parentRunID, stableChildID); !errors.Is(err, storage.ErrStaleLeader) {
		t.Fatalf("stale AppendDownstreamRunLeader = %v; want storage.ErrStaleLeader", err)
	}
	if parent, err := storeA.GetRun(ctx, parentRunID); err != nil || len(parent.DownstreamRuns) != 0 {
		t.Fatalf("stale append recorded a parent edge: downstream_runs=%v err=%v", parent.DownstreamRuns, err)
	}
	// ... and the outbox ACK: the claimed row survives A's attempt.
	storeA.SetLeaderEpoch(epochA)
	if err := storeA.OutboxAck(ctx, stableKey); !errors.Is(err, storage.ErrStaleLeader) {
		t.Fatalf("stale OutboxAck = %v; want storage.ErrStaleLeader", err)
	}
	if has, err := storeA.OutboxHas(ctx, stableKey); err != nil || !has {
		t.Fatalf("stale OutboxAck removed the row: has=%v err=%v", has, err)
	}

	// ... and the dispatch failure/cleanup release: A's server helper must
	// refuse to clear a reservation it no longer owns (the leader-only expiry
	// sweep reclaims it instead).
	relJob := pgITServerRandomHex(t, 32)
	reservedAt := now.Add(-time.Minute)
	if err := storeA.InsertDownstreamLink(ctx, storage.DownstreamLink{
		ParentJobID: relJob, TargetRepo: "acme/child", TargetRef: "refs/heads/main",
		LaunchToken: "tok", Reserved: true, ReservedAt: &reservedAt, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed reserved link: %v", err)
	}
	storeA.SetLeaderEpoch(epochA)
	sA.releaseDownstreamReservation(ctx, relJob, "acme/child", "refs/heads/main")
	if l, _, err := storeA.GetDownstreamLink(ctx, relJob, "acme/child", "refs/heads/main"); err != nil || !l.Reserved {
		t.Fatalf("stale dispatch release mutated the reservation: reserved=%v err=%v", l.Reserved, err)
	}
	// The current leader can clear it through the fenced variant.
	if err := storeB.ReleaseDownstreamReservationLeader(ctx, relJob, "acme/child", "refs/heads/main"); err != nil {
		t.Fatalf("B ReleaseDownstreamReservationLeader = %v", err)
	}
	if l, _, err := storeB.GetDownstreamLink(ctx, relJob, "acme/child", "refs/heads/main"); err != nil || l.Reserved {
		t.Fatalf("B release left reserved=%v err=%v", l.Reserved, err)
	}

	// --- B (epoch N+1) dispatches the SAME work: exactly once, stable ID. --
	if err := sB.dispatchDownstream(ctx, item); err != nil {
		t.Fatalf("B dispatchDownstream = %v", err)
	}
	l, ok, err := storeB.GetDownstreamLink(ctx, parentJobID, "acme/child", "refs/heads/main")
	if err != nil || !ok || l.ChildRunID != stableChildID || l.StableChildID != stableKey || l.Reserved {
		t.Fatalf("B launch left the link wrong: found=%v child=%q stable=%q reserved=%v err=%v", ok, l.ChildRunID, l.StableChildID, l.Reserved, err)
	}
	child, err := storeB.GetRun(ctx, stableChildID)
	if err != nil || child.RepoFullName != "acme/child" {
		t.Fatalf("B child run = %+v err=%v", child, err)
	}
	parent, err := storeB.GetRun(ctx, parentRunID)
	if err != nil || len(parent.DownstreamRuns) != 1 || parent.DownstreamRuns[0] != stableChildID {
		t.Fatalf("B parent edge = %v err=%v; want [%s]", parent.DownstreamRuns, err, stableChildID)
	}
	countChildren := func() int {
		t.Helper()
		runs, err := storeB.ListRuns(ctx, 10000)
		if err != nil {
			t.Fatalf("ListRuns: %v", err)
		}
		n := 0
		for _, r := range runs {
			if r.RepoFullName == "acme/child" {
				n++
			}
		}
		return n
	}
	if n := countChildren(); n != 1 {
		t.Fatalf("child runs after B dispatch = %d; want exactly 1", n)
	}
	// A replayed dispatch of the same intent is a no-op: still one child,
	// same stable ID.
	if err := sB.dispatchDownstream(ctx, item); err != nil {
		t.Fatalf("B replayed dispatchDownstream = %v", err)
	}
	if n := countChildren(); n != 1 {
		t.Fatalf("child runs after replayed dispatch = %d; want exactly 1", n)
	}
}
