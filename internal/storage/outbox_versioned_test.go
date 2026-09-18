package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// TestMigration0018Content pins the schema contract of the versioned
// forge-delivery identity and the delivered watermark table after the
// deploy-safety split: 0018 carries only the fast, non-rewriting metadata DDL
// (the two ADD COLUMNs and the watermark table) and the two index builds live
// in their own files. The runner applies every file in one transaction
// (internal/storage/postgres.go applyMigration), so keeping the builds out of
// 0018 is what keeps the ADD COLUMN transaction's ACCESS EXCLUSIVE lock on
// outbox from being held across them.
func TestMigration0018Content(t *testing.T) {
	raw18, err := migrations.FS.ReadFile("0018_outbox_forge_versions.sql")
	if err != nil {
		t.Fatalf("read 0018: %v", err)
	}
	sql18 := string(raw18)
	for _, want := range []string{
		`ALTER TABLE outbox ADD COLUMN IF NOT EXISTS logical_key TEXT`,
		`ALTER TABLE outbox ADD COLUMN IF NOT EXISTS state_version BIGINT NOT NULL DEFAULT 0`,
		`CREATE TABLE IF NOT EXISTS forge_check_state`,
		`logical_key       TEXT PRIMARY KEY`,
		`delivered_version BIGINT NOT NULL DEFAULT 0`,
		`updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()`,
	} {
		if !strings.Contains(sql18, want) {
			t.Errorf("0018_outbox_forge_versions.sql is missing %q", want)
		}
	}
	// No index build may share the ALTER transaction: it would hold ACCESS
	// EXCLUSIVE on outbox (the writer path) for the whole build.
	if strings.Contains(sql18, "CREATE INDEX") || strings.Contains(sql18, "CREATE UNIQUE INDEX") {
		t.Error("0018 must not contain an index build; the ADD COLUMN ACCESS EXCLUSIVE lock would span it")
	}
	if stmts := migrations.SplitStatements(sql18); len(stmts) != 3 {
		t.Fatalf("0018 has %d statements, want 3", len(stmts))
	}

	raw19, err := migrations.FS.ReadFile("0019_outbox_logical_version_index.sql")
	if err != nil {
		t.Fatalf("read 0019: %v", err)
	}
	sql19 := string(raw19)
	for _, want := range []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS outbox_logical_version_idx`,
		`ON outbox (logical_key, state_version)`,
		`WHERE logical_key IS NOT NULL`,
	} {
		if !strings.Contains(sql19, want) {
			t.Errorf("0019_outbox_logical_version_index.sql is missing %q", want)
		}
	}
	if strings.Contains(sql19, "ALTER TABLE") {
		t.Error("0019 must contain only its index build (its own lock window)")
	}
	if stmts := migrations.SplitStatements(sql19); len(stmts) != 1 {
		t.Fatalf("0019 has %d statements, want 1", len(stmts))
	}

	raw20, err := migrations.FS.ReadFile("0020_outbox_logical_pending_index.sql")
	if err != nil {
		t.Fatalf("read 0020: %v", err)
	}
	sql20 := string(raw20)
	for _, want := range []string{
		`CREATE INDEX IF NOT EXISTS outbox_logical_pending_idx`,
		`ON outbox (logical_key, state_version)`,
		`WHERE logical_key IS NOT NULL AND dead_lettered_at IS NULL`,
	} {
		if !strings.Contains(sql20, want) {
			t.Errorf("0020_outbox_logical_pending_index.sql is missing %q", want)
		}
	}
	if strings.Contains(sql20, "UNIQUE") {
		t.Error("0020 is the non-unique pending lookup index")
	}
	if strings.Contains(sql20, "ALTER TABLE") {
		t.Error("0020 must contain only its index build (its own lock window)")
	}
	if stmts := migrations.SplitStatements(sql20); len(stmts) != 1 {
		t.Fatalf("0020 has %d statements, want 1", len(stmts))
	}

	// Applied in order: All() is what Migrate iterates; the split files must
	// sort between 0018 and any later migration.
	all, err := migrations.All()
	if err != nil {
		t.Fatalf("migrations.All: %v", err)
	}
	pos := map[int]int{}
	for i, m := range all {
		pos[m.Version] = i
	}
	if !(pos[18] < pos[19] && pos[19] < pos[20]) {
		t.Fatalf("split migrations out of order: positions 18=%d 19=%d 20=%d", pos[18], pos[19], pos[20])
	}
}

// versionedItem builds one versioned outbox row with a stable logical key.
func versionedItem(key string, version int64, kind, payload string) OutboxItem {
	return OutboxItem{ID: key + "#" + itoaVersion(version), Kind: kind, Payload: []byte(payload), LogicalKey: key, StateVersion: version}
}

func itoaVersion(v int64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// TestMemOutboxVersionedSupersedeAndWatermark proves the in-memory mirror of
// the versioned enqueue contract: older pending versions are superseded, an
// out-of-order older enqueue is rejected while a newer one is pending, the
// ack advances the delivered watermark, and a delivered version can never be
// re-enqueued or pass the guard.
func TestMemOutboxVersionedSupersedeAndWatermark(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	key := "check-key-1"

	// v1 inserts; v2 supersedes the pending v1 in the same operation.
	if outcome, err := m.OutboxEnqueueVersioned(ctx, versionedItem(key, 1, "github_check", `{"v":1}`)); err != nil || outcome != VersionedEnqueued {
		t.Fatalf("enqueue v1 = %v, %v", outcome, err)
	}
	if outcome, err := m.OutboxEnqueueVersioned(ctx, versionedItem(key, 2, "github_check", `{"v":2}`)); err != nil || outcome != VersionedEnqueued {
		t.Fatalf("enqueue v2 = %v, %v", outcome, err)
	}
	pending, err := m.OutboxPending(ctx)
	if err != nil || len(pending) != 1 || pending[0].StateVersion != 2 {
		t.Fatalf("pending after supersede = %+v, %v; want only v2", pending, err)
	}
	// Out-of-order: an older version arriving while a newer one is pending is
	// rejected (the newer state will publish the newest remote result).
	if outcome, err := m.OutboxEnqueueVersioned(ctx, versionedItem(key, 1, "github_check", `{"v":1b}`)); err != nil || outcome != VersionedSuperseded {
		t.Fatalf("out-of-order v1 = %v, %v; want superseded", outcome, err)
	}
	if pending, _ = m.OutboxPending(ctx); len(pending) != 1 || pending[0].StateVersion != 2 {
		t.Fatalf("out-of-order enqueue disturbed pending: %+v", pending)
	}

	// Claims and guard see the newest row.
	claimed, err := m.ClaimOutbox(ctx, "flusher", 10)
	if err != nil || len(claimed) != 1 || claimed[0].StateVersion != 2 {
		t.Fatalf("claim = %+v, %v", claimed, err)
	}
	publish, err := m.OutboxVersionGuard(ctx, claimed[0].ID, key, 2)
	if err != nil || !publish {
		t.Fatalf("guard for newest = %v, %v; want publish", publish, err)
	}
	if err := m.OutboxAck(ctx, claimed[0].ID); err != nil {
		t.Fatal(err)
	}
	if got := m.forgeState[key]; got != 2 {
		t.Fatalf("delivered watermark = %d, want 2", got)
	}
	// A delivered version can never be re-enqueued and cannot pass a guard
	// (the row no longer exists).
	if outcome, err := m.OutboxEnqueueVersioned(ctx, versionedItem(key, 2, "github_check", `{"v":2}`)); err != nil || outcome != VersionedSuperseded {
		t.Fatalf("re-enqueue delivered v2 = %v, %v", outcome, err)
	}
	if publish, err := m.OutboxVersionGuard(ctx, key+"#2", key, 2); err != nil || publish {
		t.Fatalf("guard for delivered row = %v, %v; want skip", publish, err)
	}
	// A newer version after delivery inserts and publishes.
	if outcome, err := m.OutboxEnqueueVersioned(ctx, versionedItem(key, 3, "github_check", `{"v":3}`)); err != nil || outcome != VersionedEnqueued {
		t.Fatalf("enqueue v3 = %v, %v", outcome, err)
	}
}

// TestMemOutboxVersionedDeadLetterLifecycle is T3's storage half: a versioned
// intent that exhausts attempts is retired (out of pending and claims),
// listed by the operator API, requeued, claimable and publishable again, and
// delete removes it.
func TestMemOutboxVersionedDeadLetterLifecycle(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	key := "check-key-dead"
	item := versionedItem(key, 1, "github_check", `{"v":1}`)
	if outcome, err := m.OutboxEnqueueVersioned(ctx, item); err != nil || outcome != VersionedEnqueued {
		t.Fatalf("enqueue = %v, %v", outcome, err)
	}
	if err := m.OutboxRetry(ctx, item.ID, errors.New("forge down"), 2); err != nil {
		t.Fatal(err)
	}
	if pending, _ := m.OutboxPending(ctx); len(pending) != 1 {
		t.Fatalf("pending after first failure = %+v, want the active row", pending)
	}
	if err := m.OutboxRetry(ctx, item.ID, errors.New("forge down again"), 2); err != nil {
		t.Fatal(err)
	}
	// Retired: absent from pending, never claimed, visible to the operator
	// with its failure context and delivery identity.
	if pending, _ := m.OutboxPending(ctx); len(pending) != 0 {
		t.Fatalf("dead letter still pending: %+v", pending)
	}
	if claims, _ := m.ClaimOutbox(ctx, "flusher", 10); len(claims) != 0 {
		t.Fatalf("dead letter claimed: %+v", claims)
	}
	dead, err := m.OutboxDeadLetters(ctx)
	if err != nil || len(dead) != 1 {
		t.Fatalf("dead letters = %+v, %v", dead, err)
	}
	if dead[0].ID != item.ID || dead[0].LogicalKey != key || dead[0].StateVersion != 1 || dead[0].Attempts != 2 || dead[0].LastError != "forge down again" {
		t.Fatalf("dead letter context = %+v", dead[0])
	}

	// Requeue: claimable again, guard passes, ack advances the watermark.
	if err := m.OutboxRequeue(ctx, item.ID); err != nil {
		t.Fatalf("requeue: %v", err)
	}
	if dead, _ := m.OutboxDeadLetters(ctx); len(dead) != 0 {
		t.Fatalf("dead letters after requeue = %+v", dead)
	}
	claims, err := m.ClaimOutbox(ctx, "flusher-2", 10)
	if err != nil || len(claims) != 1 || claims[0].ID != item.ID {
		t.Fatalf("claims after requeue = %+v, %v", claims, err)
	}
	publish, err := m.OutboxVersionGuard(ctx, item.ID, key, 1)
	if err != nil || !publish {
		t.Fatalf("guard after requeue = %v, %v; want publish", publish, err)
	}
	if err := m.OutboxAck(ctx, item.ID); err != nil {
		t.Fatal(err)
	}
	if got := m.forgeState[key]; got != 1 {
		t.Fatalf("watermark after requeue delivery = %d, want 1", got)
	}

	// Retire a second intent and delete it through the operator API.
	second := versionedItem("check-key-delete", 1, "github_check", `{}`)
	if _, err := m.OutboxEnqueueVersioned(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := m.OutboxRetry(ctx, second.ID, errors.New("boom"), 1); err != nil {
		t.Fatal(err)
	}
	if err := m.OutboxDelete(ctx, second.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if dead, _ := m.OutboxDeadLetters(ctx); len(dead) != 0 {
		t.Fatalf("dead letters after delete = %+v", dead)
	}
	if err := m.OutboxDelete(ctx, second.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete of missing dead letter = %v, want ErrNotFound", err)
	}
}

// TestFaultyStoreForgeCheckStateWiring proves the fault-injection wrapper
// delegates the versioned contract and honors injected faults on the
// mutating call without corrupting the read-only guard.
func TestFaultyStoreForgeCheckStateWiring(t *testing.T) {
	f := &FaultyStore{Inner: newMemStore()}
	ctx := context.Background()
	item := versionedItem("check-key-faulty", 1, "github_check", `{}`)
	if _, err := f.OutboxEnqueueVersioned(ctx, item); err != nil {
		t.Fatalf("wrapped enqueue: %v", err)
	}
	if publish, err := f.OutboxVersionGuard(ctx, item.ID, item.LogicalKey, 1); err != nil || !publish {
		t.Fatalf("wrapped guard = %v, %v", publish, err)
	}
	injected := errors.New("injected forge-check failure")
	f.FailAfter = f.Mutations() + 1
	f.Err = injected
	if _, err := f.OutboxEnqueueVersioned(ctx, versionedItem("check-key-faulty-2", 1, "github_check", `{}`)); !errors.Is(err, injected) {
		t.Fatalf("injected enqueue fault = %v, want %v", err, injected)
	}
}

// TestMemOutboxMarkDeliveredLegacy covers the memStore mirror of the legacy
// (unversioned) watermark stamp: OutboxMarkDelivered advances the delivered
// watermark monotonically, the guard then rejects older derived versions, and
// validation refuses an empty key or non-positive version.
func TestMemOutboxMarkDeliveredLegacy(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	key := "legacy-check-key"
	legacyID := "legacy-row-1"
	if err := m.OutboxAppend(ctx, OutboxItem{ID: legacyID, Kind: "github_check", Payload: []byte(`{"name":"Pipeline"}`), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if publish, err := m.OutboxVersionGuard(ctx, legacyID, key, 2); err != nil || !publish {
		t.Fatalf("guard before stamp = %v, %v; want publish", publish, err)
	}
	if err := m.OutboxMarkDelivered(ctx, key, 3); err != nil {
		t.Fatal(err)
	}
	if got := m.forgeState[key]; got != 3 {
		t.Fatalf("watermark = %d, want 3", got)
	}
	if publish, err := m.OutboxVersionGuard(ctx, legacyID, key, 2); err != nil || publish {
		t.Fatalf("guard after stamp = %v, %v; want skip", publish, err)
	}
	// A lower stamp never lowers the watermark; a newer version passes.
	if err := m.OutboxMarkDelivered(ctx, key, 1); err != nil {
		t.Fatal(err)
	}
	if got := m.forgeState[key]; got != 3 {
		t.Fatalf("watermark after lower stamp = %d, want 3", got)
	}
	if publish, err := m.OutboxVersionGuard(ctx, legacyID, key, 4); err != nil || !publish {
		t.Fatalf("guard for newer version = %v, %v; want publish", publish, err)
	}
	if err := m.OutboxMarkDelivered(ctx, "", 1); err == nil {
		t.Fatal("empty logical key must be refused")
	}
	if err := m.OutboxMarkDelivered(ctx, key, 0); err == nil {
		t.Fatal("non-positive version must be refused")
	}
}
