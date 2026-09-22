package storage

// Parity coverage for the FaultyStore wrappers and memStore mirrors that the
// generic wrapper table (faulty_wrapper_test.go) cannot drive because their
// signatures return values instead of a bare error: the check-run mapping,
// the outbox membership probe, the schedule reads, the leader-epoch
// retention, the digest/named fences and the resource-reservation ledger.
//
// Every case asserts OBSERVABLE behavior (round trip, missing-value
// semantics, mutual exclusion, monotonicity, parity between the two stores)
// rather than merely calling the method, and every wrapper is additionally
// checked against a store that lacks the optional interface so a missing
// contract fails closed instead of silently succeeding.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// wantMissingInner asserts err is the typed missing-inner-interface failure
// naming contract.
func wantMissingInner(t *testing.T, err error, contract string) {
	t.Helper()
	var missing *missingInnerInterfaceError
	if !errors.As(err, &missing) {
		t.Fatalf("err = %v, want *missingInnerInterfaceError", err)
	}
	if missing.Error() == "" || !contains(missing.Error(), contract) {
		t.Fatalf("missing-inner error %q does not name %s", missing.Error(), contract)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestFaultyStoreCheckRunParity: the check-run mapping round-trips through
// both stores, an unknown key is "not found" (never an empty success), a
// missing inner contract fails closed, and fault injection surfaces the
// configured error without reaching the inner store.
func TestFaultyStoreCheckRunParity(t *testing.T) {
	inner := newMemStore()
	fs := &FaultyStore{Inner: inner}
	if err := fs.PutCheckRun(ctx(), "run/check", "check-1"); err != nil {
		t.Fatalf("PutCheckRun: %v", err)
	}
	// Last write wins: a re-created check run is the one to patch.
	if err := fs.PutCheckRun(ctx(), "run/check", "check-2"); err != nil {
		t.Fatalf("PutCheckRun replace: %v", err)
	}
	for name, store := range map[string]CheckRunStore{"faulty": fs, "mem": inner} {
		id, ok, err := store.GetCheckRun(ctx(), "run/check")
		if err != nil || !ok || id != "check-2" {
			t.Fatalf("%s: GetCheckRun = (%q, %v, %v), want check-2", name, id, ok, err)
		}
		if id, ok, err := store.GetCheckRun(ctx(), "absent"); err != nil || ok || id != "" {
			t.Fatalf("%s: unknown key = (%q, %v, %v), want not found", name, id, ok, err)
		}
	}

	// The keyless/keyed round trip through the memStore mirror itself (the
	// server's memory mode uses the same map).
	plain := &checkRunMem{}
	if err := plain.put("k", "v"); err != nil {
		t.Fatalf("checkRunMem.put: %v", err)
	}
	if id, ok := plain.get("k"); !ok || id != "v" {
		t.Fatalf("checkRunMem.get = (%q, %v)", id, ok)
	}
	if _, ok := plain.get("missing"); ok {
		t.Fatal("checkRunMem.get reported an absent key")
	}

	faulted := &FaultyStore{Inner: inner, FailAfter: 1, Err: errBoom}
	if err := faulted.PutCheckRun(ctx(), "run/check", "check-3"); !errors.Is(err, errBoom) {
		t.Fatalf("faulted PutCheckRun = %v, want injected", err)
	}
	if id, _, _ := inner.GetCheckRun(ctx(), "run/check"); id != "check-2" {
		t.Fatalf("faulted PutCheckRun leaked %q into the inner store", id)
	}
	if _, _, err := (&FaultyStore{Inner: inner, FailAfter: 1, Err: errBoom}).GetCheckRun(ctx(), "run/check"); !errors.Is(err, errBoom) {
		t.Fatalf("faulted GetCheckRun = %v, want injected", err)
	}

	storeOnly := &FaultyStore{Inner: storeOnlyInner{}}
	if err := storeOnly.PutCheckRun(ctx(), "k", "v"); err == nil {
		t.Fatal("PutCheckRun without CheckRunStore succeeded")
	} else {
		wantMissingInner(t, err, "CheckRunStore")
	}
	if _, _, err := storeOnly.GetCheckRun(ctx(), "k"); err == nil {
		t.Fatal("GetCheckRun without CheckRunStore succeeded")
	} else {
		wantMissingInner(t, err, "CheckRunStore")
	}
}

// TestFaultyStoreOutboxHasParity: the membership probe reflects durable
// appends on both stores, reports false for unknown IDs, never injects faults
// (it is a read), and fails closed without the optional contract.
func TestFaultyStoreOutboxHasParity(t *testing.T) {
	inner := newMemStore()
	fs := &FaultyStore{Inner: inner}
	if err := fs.OutboxAppend(ctx(), OutboxItem{ID: "item-1", Kind: "test"}); err != nil {
		t.Fatalf("OutboxAppend: %v", err)
	}
	for name, probe := range map[string]interface {
		OutboxHas(context.Context, string) (bool, error)
	}{"faulty": fs, "mem": inner} {
		if ok, err := probe.OutboxHas(ctx(), "item-1"); err != nil || !ok {
			t.Fatalf("%s: OutboxHas(known) = (%v, %v)", name, ok, err)
		}
		if ok, err := probe.OutboxHas(ctx(), "absent"); err != nil || ok {
			t.Fatalf("%s: OutboxHas(unknown) = (%v, %v)", name, ok, err)
		}
	}
	// A read must not consume the fault budget, and an armed fault still
	// reaches the caller rather than being swallowed.
	if ok, err := fs.OutboxHas(ctx(), "item-1"); err != nil || !ok {
		t.Fatalf("read after reads = (%v, %v)", ok, err)
	}
	armed := &FaultyStore{Inner: inner, FailAfter: 1, Err: errBoom}
	if _, err := armed.OutboxHas(ctx(), "item-1"); !errors.Is(err, errBoom) {
		t.Fatalf("armed OutboxHas = %v, want injected", err)
	}
	if _, err := (&FaultyStore{Inner: storeOnlyInner{}}).OutboxHas(ctx(), "item-1"); err == nil {
		t.Fatal("OutboxHas without OutboxStore succeeded")
	} else {
		wantMissingInner(t, err, "OutboxStore")
	}
}

// TestFaultyStoreScheduleReadParity: GetSchedule resolves stored schedules
// and reports unknown IDs as not found on both stores, and
// AdvanceScheduleLastRun is monotonic (a stale nominal can never move the
// marker backwards), rejects an empty ID and reports ErrNotFound for an
// unknown schedule.
func TestFaultyStoreScheduleReadParity(t *testing.T) {
	inner := newMemStore()
	fs := &FaultyStore{Inner: inner}
	if err := fs.UpsertSchedule(ctx(), testSchedule); err != nil {
		t.Fatalf("UpsertSchedule: %v", err)
	}
	for name, store := range map[string]ScheduleStore{"faulty": fs, "mem": inner} {
		got, ok, err := store.GetSchedule(ctx(), testSchedule.ID)
		if err != nil || !ok || got.ID != testSchedule.ID || got.Spec != testSchedule.Spec {
			t.Fatalf("%s: GetSchedule = (%+v, %v, %v)", name, got, ok, err)
		}
		if _, ok, err := store.GetSchedule(ctx(), "absent"); err != nil || ok {
			t.Fatalf("%s: unknown schedule = (ok=%v, err=%v), want not found", name, ok, err)
		}
	}

	// The in-memory store is unarmed (epoch 1) so the monotonic update is
	// admitted.
	newer := time.Unix(5000, 0).UTC()
	if err := fs.AdvanceScheduleLastRun(ctx(), testSchedule.ID, newer); err != nil {
		t.Fatalf("AdvanceScheduleLastRun: %v", err)
	}
	stored, _, err := fs.GetSchedule(ctx(), testSchedule.ID)
	if err != nil || stored.LastRun == nil || !stored.LastRun.Equal(newer) {
		t.Fatalf("advanced marker = (%+v, %v)", stored.LastRun, err)
	}
	// A stale (older) nominal must not move the marker backwards.
	if err := fs.AdvanceScheduleLastRun(ctx(), testSchedule.ID, time.Unix(1, 0).UTC()); err != nil {
		t.Fatalf("stale advance: %v", err)
	}
	if stored, _, _ = fs.GetSchedule(ctx(), testSchedule.ID); stored.LastRun == nil || !stored.LastRun.Equal(newer) {
		t.Fatalf("stale advance moved the marker: %v", stored.LastRun)
	}
	if err := fs.AdvanceScheduleLastRun(ctx(), "", newer); err == nil {
		t.Fatal("empty schedule id accepted")
	}
	if err := fs.AdvanceScheduleLastRun(ctx(), "absent", newer); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown schedule advance = %v, want ErrNotFound", err)
	}
	// The memStore mirror implements the same monotonic contract.
	mem := newMemStore()
	if err := mem.UpsertSchedule(ctx(), testSchedule); err != nil {
		t.Fatal(err)
	}
	if err := mem.AdvanceScheduleLastRun(ctx(), testSchedule.ID, newer); err != nil {
		t.Fatal(err)
	}
	if err := mem.AdvanceScheduleLastRun(ctx(), testSchedule.ID, time.Unix(1, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if stored, _, _ = mem.GetSchedule(ctx(), testSchedule.ID); stored.LastRun == nil || !stored.LastRun.Equal(newer) {
		t.Fatalf("mem marker = %v, want monotonic", stored.LastRun)
	}
	// A store whose epoch was cleared fails closed instead of advancing.
	lost := &FaultyStore{Inner: newMemStore()}
	if err := lost.UpsertSchedule(ctx(), testSchedule); err != nil {
		t.Fatal(err)
	}
	lost.ClearLeaderEpoch()
	if err := lost.AdvanceScheduleLastRun(ctx(), testSchedule.ID, newer); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("advance after epoch loss = %v, want ErrStaleLeader", err)
	}

	if _, _, err := (&FaultyStore{Inner: storeOnlyInner{}}).GetSchedule(ctx(), testSchedule.ID); err == nil {
		t.Fatal("GetSchedule without ScheduleStore succeeded")
	} else {
		wantMissingInner(t, err, "ScheduleStore")
	}
}

// TestFaultyStoreLeaderEpochParity: both stores retain an epoch, report it
// with ok=true only when one is present, and clear it so fenced operations
// fail closed; a store without the fence contract reports no retained epoch.
func TestFaultyStoreLeaderEpochParity(t *testing.T) {
	for name, store := range map[string]LeaderFenceStore{"faulty": &FaultyStore{Inner: newMemStore()}, "mem": newMemStore()} {
		// The in-memory store models a replica that retains a valid epoch
		// from the start (single-process mode has no split brain): the epoch
		// is 1 and every fenced operation is admitted.
		if e, ok := store.LeaderEpoch(); !ok || e != 1 {
			t.Fatalf("%s: fresh store epoch = (%d, %v), want (1, true)", name, e, ok)
		}
		store.SetLeaderEpoch(7)
		if e, ok := store.LeaderEpoch(); !ok || e != 7 {
			t.Fatalf("%s: LeaderEpoch = (%d, %v), want (7, true)", name, e, ok)
		}
		got, err := store.ReadLeaderEpoch(ctx())
		if err != nil || got != 7 {
			t.Fatalf("%s: ReadLeaderEpoch = (%d, %v)", name, got, err)
		}
		// Non-positive clears (documented SetLeaderEpoch contract).
		store.SetLeaderEpoch(0)
		if _, ok := store.LeaderEpoch(); ok {
			t.Fatalf("%s: epoch 0 retained", name)
		}
		store.SetLeaderEpoch(3)
		store.ClearLeaderEpoch()
		if e, ok := store.LeaderEpoch(); ok || e != 0 {
			t.Fatalf("%s: ClearLeaderEpoch left (%d, %v)", name, e, ok)
		}
	}
	// A wrapped store without the fence surface reports "no epoch" instead
	// of inventing one.
	plain := &FaultyStore{Inner: storeOnlyInner{}}
	if e, ok := plain.LeaderEpoch(); ok || e != 0 {
		t.Fatalf("missing-inner LeaderEpoch = (%d, %v), want (0, false)", e, ok)
	}
	plain.SetLeaderEpoch(5)
	plain.ClearLeaderEpoch()
	if _, err := plain.ReadLeaderEpoch(ctx()); err != nil {
		t.Fatalf("missing-inner ReadLeaderEpoch = %v, want nil", err)
	}
}

// TestFaultyStoreFenceParity: the named and digest fences serialize
// acquisition, release idempotently, respect a canceled context and fail
// closed without the optional fence contract.
func TestFaultyStoreFenceParity(t *testing.T) {
	fs := &FaultyStore{Inner: newMemStore()}
	// Named fence: a second acquisition blocks until the first is released.
	release, err := fs.AcquireNamedFence(ctx(), "ns", "key")
	if err != nil || release == nil {
		t.Fatalf("AcquireNamedFence = (%v, %v)", release != nil, err)
	}
	acquired := make(chan struct{})
	released := make(chan struct{})
	go func() {
		r2, err := fs.AcquireNamedFence(ctx(), "ns", "key")
		if err != nil {
			t.Errorf("second AcquireNamedFence: %v", err)
			close(acquired)
			return
		}
		close(acquired)
		r2()
		close(released)
	}()
	select {
	case <-acquired:
		t.Fatal("second holder acquired the fence while the first held it")
	case <-time.After(200 * time.Millisecond):
	}
	release()
	select {
	case <-released:
	case <-time.After(10 * time.Second):
		t.Fatal("second holder never acquired after release")
	}
	// Release is idempotent (a wedged double cleanup must not panic).
	release()

	// A DIFFERENT key is independent of the first namespace+key pair.
	other, err := fs.AcquireNamedFence(ctx(), "ns", "other")
	if err != nil {
		t.Fatalf("independent fence: %v", err)
	}
	other()

	// Digest fence: a canceled context refuses to wait.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fs.AcquireDigestFence(canceled, "digest"); !errors.Is(err, context.Canceled) {
		t.Fatalf("AcquireDigestFence(canceled) = %v, want context.Canceled", err)
	}
	if err := fs.WithDigestFence(canceled, "digest", func() error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("WithDigestFence(canceled) = %v, want context.Canceled", err)
	}

	// WithDigestFence runs the function and propagates its error, and the
	// SAME digest serializes with an outstanding holder.
	ran := 0
	if err := fs.WithDigestFence(ctx(), "digest", func() error { ran++; return nil }); err != nil || ran != 1 {
		t.Fatalf("WithDigestFence = (%d, %v)", ran, err)
	}
	fnErr := errors.New("fence body failed")
	if err := fs.WithDigestFence(ctx(), "digest", func() error { return fnErr }); !errors.Is(err, fnErr) {
		t.Fatalf("WithDigestFence(body error) = %v", err)
	}
	digestRelease, err := fs.AcquireDigestFence(ctx(), "digest")
	if err != nil {
		t.Fatalf("AcquireDigestFence: %v", err)
	}
	blocked := make(chan struct{})
	go func() {
		_ = fs.WithDigestFence(ctx(), "digest", func() error {
			close(blocked)
			return nil
		})
	}()
	select {
	case <-blocked:
		t.Fatal("digest fence body ran while the digest was held")
	case <-time.After(200 * time.Millisecond):
	}
	digestRelease()
	select {
	case <-blocked:
	case <-time.After(10 * time.Second):
		t.Fatal("digest fence body never ran after release")
	}

	// The memStore mirrors are exercised through the plain store too.
	mem := newMemStore()
	if r, err := mem.AcquireNamedFence(ctx(), "ns", "key"); err != nil || r == nil {
		t.Fatalf("mem AcquireNamedFence = (%v, %v)", r != nil, err)
	} else {
		r()
	}
	if r, err := mem.AcquireDigestFence(ctx(), "d"); err != nil || r == nil {
		t.Fatalf("mem AcquireDigestFence = (%v, %v)", r != nil, err)
	} else {
		r()
	}
	if err := mem.WithDigestFence(ctx(), "d", func() error { return nil }); err != nil {
		t.Fatalf("mem WithDigestFence: %v", err)
	}

	// Missing contract fails closed for every fence entry point.
	plain := &FaultyStore{Inner: storeOnlyInner{}}
	if _, err := plain.AcquireNamedFence(ctx(), "ns", "key"); err == nil {
		t.Fatal("AcquireNamedFence without DigestFenceStore succeeded")
	} else {
		wantMissingInner(t, err, "DigestFenceStore")
	}
	if _, err := plain.AcquireDigestFence(ctx(), "d"); err == nil {
		t.Fatal("AcquireDigestFence without DigestFenceStore succeeded")
	} else {
		wantMissingInner(t, err, "DigestFenceStore")
	}
	if err := plain.WithDigestFence(ctx(), "d", func() error { return nil }); err == nil {
		t.Fatal("WithDigestFence without DigestFenceStore succeeded")
	} else {
		wantMissingInner(t, err, "DigestFenceStore")
	}
}

// TestFaultyStoreReservationLedgerParity: the reservation observation API
// reports what the lease claim reserved on both stores (the claim's TOTAL
// request, job + service envelope), the listing is job-ID ordered and
// complete, an invalid runner ID is rejected before any query, and the
// wrappers fail closed without the reservation contract.
func TestFaultyStoreReservationLedgerParity(t *testing.T) {
	for name, store := range map[string]Store{"faulty": &FaultyStore{Inner: newMemStore()}, "mem": newMemStore()} {
		if err := store.InsertRun(ctx(), testRun); err != nil {
			t.Fatalf("%s: InsertRun: %v", name, err)
		}
		if err := store.InsertJob(ctx(), testJob); err != nil {
			t.Fatalf("%s: InsertJob: %v", name, err)
		}
		if err := store.UpsertRunner(ctx(), testRunner); err != nil {
			t.Fatalf("%s: UpsertRunner: %v", name, err)
		}
		claim := LeaseClaim{
			JobID: testJob.ID, RunnerID: testRunner.ID, TokenHash: []byte("h"), Generation: 1,
			ExpiresAt: time.Unix(3000, 0).UTC(), RunnerCapacity: 2,
			CPURequest: 1.5, MemoryRequest: 1 << 30, DiskRequest: 4096, PIDsRequest: 32,
			ServiceEnvelopeRequest: model.ResourceCapacity{CPU: 0.5, Memory: 1 << 29, PIDs: 8},
		}
		if _, err := store.(AtomicLeaseStore).AcquireLeaseAtomic(ctx(), claim); err != nil {
			t.Fatalf("%s: AcquireLeaseAtomic: %v", name, err)
		}
		ledger := store.(ResourceReservationStore)
		sum, err := ledger.RunnerReservedResources(ctx(), testRunner.ID)
		if err != nil {
			t.Fatalf("%s: RunnerReservedResources: %v", name, err)
		}
		want := claim.RequestedResources()
		if sum != want {
			t.Fatalf("%s: reserved = %+v, want the TOTAL claim request %+v", name, sum, want)
		}
		rows, err := ledger.ListResourceReservations(ctx(), testRunner.ID)
		if err != nil || len(rows) != 1 {
			t.Fatalf("%s: ListResourceReservations = (%d rows, %v)", name, len(rows), err)
		}
		if rows[0].JobID != testJob.ID || rows[0].Generation != 1 || rows[0].Capacity() != want {
			t.Fatalf("%s: reservation row = %+v, want the claim total %+v", name, rows[0], want)
		}
		if _, err := ledger.ListResourceReservations(ctx(), "not-a-valid-id!"); err == nil {
			t.Fatalf("%s: invalid runner id accepted", name)
		}
		if empty, err := ledger.RunnerReservedResources(ctx(), testRunner.ID[:31]+"0"); err != nil || empty != (model.ResourceCapacity{}) {
			t.Fatalf("%s: unreserved runner sum = (%+v, %v), want zero", name, empty, err)
		}
	}

	// A store without the reservation contract fails closed.
	plain := &FaultyStore{Inner: storeOnlyInner{}}
	if _, err := plain.RunnerReservedResources(ctx(), testRunner.ID); err == nil {
		t.Fatal("RunnerReservedResources without ResourceReservationStore succeeded")
	} else {
		wantMissingInner(t, err, "ResourceReservationStore")
	}
	if _, err := plain.ListResourceReservations(ctx(), testRunner.ID); err == nil {
		t.Fatal("ListResourceReservations without ResourceReservationStore succeeded")
	} else {
		wantMissingInner(t, err, "ResourceReservationStore")
	}
}

// TestCompletionEffectKindClassification pins the split completion-effect
// classification: the two internal rows are completion effects and internal,
// the bounded external forge rows (forge_delivery, legacy forge_status) are
// completion effects but NOT internal, and unrelated kinds are neither.
func TestCompletionEffectKindClassification(t *testing.T) {
	internalKinds := NewCompletionEffectKinds()
	if len(internalKinds) != 2 || internalKinds[0] != OutboxKindCompletionReconcile || internalKinds[1] != OutboxKindForgeDelivery {
		t.Fatalf("NewCompletionEffectKinds = %v, want the pinned pair", internalKinds)
	}
	if CompletionEffectIntentCount != len(internalKinds) {
		t.Fatalf("CompletionEffectIntentCount = %d, want %d", CompletionEffectIntentCount, len(internalKinds))
	}
	for _, legacy := range CompletionEffectKinds() {
		if !IsCompletionEffectKind(legacy) {
			t.Fatalf("legacy completion kind %q classified as a non-effect", legacy)
		}
		// The bounded external forge kinds are carved out of the internal
		// family: they own the retry/dead-letter policy.
		wantInternal := legacy != OutboxKindForgeStatus
		if got := InternalCompletionEffectKind(legacy); got != wantInternal {
			t.Fatalf("legacy completion kind %q internal = %v, want %v", legacy, got, wantInternal)
		}
	}
	for _, kind := range []string{OutboxKindCompletionReconcile, OutboxKindForgeDelivery} {
		if !IsCompletionEffectKind(kind) {
			t.Fatalf("%q must be a completion effect", kind)
		}
	}
	// Only the internal reconcile row converges forever; the external
	// forge_delivery row (like the legacy forge_status row) is bounded and
	// dead-letterable.
	if !InternalCompletionEffectKind(OutboxKindCompletionReconcile) {
		t.Fatalf("%q must be internal", OutboxKindCompletionReconcile)
	}
	if InternalCompletionEffectKind(OutboxKindForgeDelivery) {
		t.Fatalf("%q must not be internal: it owns the dead-letter policy", OutboxKindForgeDelivery)
	}
	if !IsCompletionEffectKind(OutboxKindForgeStatus) {
		t.Fatalf("%q must stay a completion effect (bounded external delivery)", OutboxKindForgeStatus)
	}
	if InternalCompletionEffectKind(OutboxKindForgeStatus) {
		t.Fatalf("%q must not be internal: it owns the dead-letter policy", OutboxKindForgeStatus)
	}
	if IsCompletionEffectKind("some.other.kind") || InternalCompletionEffectKind("some.other.kind") {
		t.Fatal("an unrelated outbox kind classified as a completion effect")
	}
}

// TestPostgresStorePureFenceHelpers covers the pure leader-epoch retention
// helpers (no database involved) so their clear/retain contract is pinned
// without a live PostgreSQL.
func TestPostgresStorePureFenceHelpers(t *testing.T) {
	st := &PostgresStore{}
	st.SetLeaderEpoch(11)
	if e, ok := st.LeaderEpoch(); !ok || e != 11 {
		t.Fatalf("LeaderEpoch = (%d, %v), want (11, true)", e, ok)
	}
	st.ClearLeaderEpoch()
	if e, ok := st.LeaderEpoch(); ok || e != 0 {
		t.Fatalf("after ClearLeaderEpoch = (%d, %v)", e, ok)
	}
	// A non-positive epoch is retained as-is but reports ok=false, so every
	// fenced operation fails closed (the doc's "non-positive clears").
	st.SetLeaderEpoch(-1)
	if _, ok := st.LeaderEpoch(); ok {
		t.Fatal("negative epoch reported as retained")
	}
}

// TestDigestFenceSerialization guards the fence mutual-exclusion property
// under concurrency for the in-memory store: with N workers contending on
// one digest, the critical sections never overlap.
func TestDigestFenceSerialization(t *testing.T) {
	mem := newMemStore()
	var mu sync.Mutex
	inside := 0
	maxInside := 0
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if err := mem.WithDigestFence(ctx(), "shared", func() error {
					mu.Lock()
					inside++
					if inside > maxInside {
						maxInside = inside
					}
					mu.Unlock()
					time.Sleep(time.Microsecond)
					mu.Lock()
					inside--
					mu.Unlock()
					return nil
				}); err != nil {
					t.Errorf("WithDigestFence: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if maxInside != 1 {
		t.Fatalf("digest fence allowed %d concurrent holders, want 1", maxInside)
	}
}
