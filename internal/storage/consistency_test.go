package storage

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// TestMigration0010Content pins the schema contract of the generated-fragment
// receipts, the outbox claim lease and the artifact-generation idempotency
// key.
func TestMigration0010Content(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0010_generation_outbox_artifact_consistency.sql")
	if err != nil {
		t.Fatalf("read 0010: %v", err)
	}
	sql := string(raw)
	for _, want := range []string{
		`CREATE TABLE generated_fragments`,
		`parent_job_id TEXT NOT NULL`,
		`lease_generation BIGINT NOT NULL`,
		`fragment_id TEXT NOT NULL`,
		`children JSONB NOT NULL`,
		`PRIMARY KEY (parent_job_id, lease_generation, fragment_id)`,
		`ALTER TABLE outbox ADD COLUMN IF NOT EXISTS claimed_at`,
		`ALTER TABLE outbox ADD COLUMN IF NOT EXISTS claimed_by`,
		`outbox_claim_idx`,
		`ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS job_generation`,
		// G5-A: the generation backfill must guard the cast, or one malformed
		// payload aborts the whole migration transaction.
		`UPDATE artifacts SET job_generation = CASE`,
		`WHEN jsonb_typeof(payload->'lease_generation') = 'number'`,
		`'^-?[0-9]+$'`,
		`CREATE UNIQUE INDEX IF NOT EXISTS artifacts_job_generation_name_idx ON artifacts (job_id, job_generation, name)`,
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("0010_generation_outbox_artifact_consistency.sql is missing %q", want)
		}
	}
	stmts := migrations.SplitStatements(sql)
	if len(stmts) != 7 {
		t.Fatalf("0010 has %d statements, want 7", len(stmts))
	}
}

// TestMemStoreOutboxClaimDisjointAndStaleReclaim proves the in-memory claim
// lease mirrors the SQL FOR UPDATE SKIP LOCKED behavior: concurrent flushers
// claim disjoint batches, a fresh claim is invisible to other flushers, and a
// claim older than OutboxClaimTTL is reclaimable.
func TestMemStoreOutboxClaimDisjointAndStaleReclaim(t *testing.T) {
	m := newMemStore()
	ids := []string{"1", "2", "3", "4"}
	for _, id := range ids {
		if err := m.OutboxAppend(ctx(), OutboxItem{ID: id, Kind: "github_check", Payload: []byte("{}"), CreatedAt: time.Unix(1000, 0).UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	a, err := m.ClaimOutbox(ctx(), "flusher-a", 2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.ClaimOutbox(ctx(), "flusher-b", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("claims = %d/%d, want 2/2", len(a), len(b))
	}
	if a[0].ID == b[0].ID || a[1].ID == b[0].ID || a[0].ID == b[1].ID || a[1].ID == b[1].ID {
		t.Fatalf("claims overlap: a=%v b=%v", itemIDs(a), itemIDs(b))
	}
	if c, _ := m.ClaimOutbox(ctx(), "flusher-c", 4); len(c) != 0 {
		t.Fatalf("fresh claims were handed to a third flusher: %v", itemIDs(c))
	}
	// Age one claim beyond the TTL: only its rows become reclaimable.
	m.mu.Lock()
	m.outboxClaims[a[0].ID] = outboxClaim{claimer: "flusher-a", at: time.Now().UTC().Add(-2 * OutboxClaimTTL)}
	m.mu.Unlock()
	c, err := m.ClaimOutbox(ctx(), "flusher-c", 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != 1 || c[0].ID != a[0].ID {
		t.Fatalf("stale claim reclaim = %v, want [%s]", itemIDs(c), a[0].ID)
	}
	// Ack clears the claim with the row.
	if err := m.OutboxAck(ctx(), a[0].ID); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	_, claimLeft := m.outboxClaims[a[0].ID]
	m.mu.Unlock()
	if claimLeft {
		t.Fatal("ack left the claim behind")
	}
	if d, _ := m.ClaimOutbox(ctx(), "flusher-d", 4); len(d) != 0 {
		t.Fatalf("acked row or fresh claims handed out: %v", itemIDs(d))
	}
	// Release returns an undispatched claim for immediate reuse.
	if err := m.ReleaseOutboxClaim(ctx(), b[0].ID, "flusher-b"); err != nil {
		t.Fatal(err)
	}
	if e, _ := m.ClaimOutbox(ctx(), "flusher-e", 4); len(e) != 1 || e[0].ID != b[0].ID {
		t.Fatalf("released claim not reclaimable: %v", itemIDs(e))
	}
}

func itemIDs(items []OutboxItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.ID)
	}
	return out
}

// TestMemStoreArtifactIdempotentOnce proves the in-memory
// (job, generation, name) key admits exactly one record: a same-digest replay
// returns the stored record, a different digest conflicts, a new generation
// is a new key, and a NULL-like empty job ID never conflicts.
func TestMemStoreArtifactIdempotentOnce(t *testing.T) {
	m := newMemStore()
	base := model.ArtifactRecord{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RunID: testRun.ID, JobID: testJob.ID, Name: "bin", SHA256: "digest-1", CreatedAt: time.Unix(1000, 0).UTC()}
	got, created, err := m.InsertArtifactOnce(ctx(), base)
	if err != nil || !created || got.ID != base.ID {
		t.Fatalf("first insert = %v created=%v err=%v", got.ID, created, err)
	}
	replay := base
	replay.ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	replay.Size = 42
	got, created, err = m.InsertArtifactOnce(ctx(), replay)
	if err != nil || created {
		t.Fatalf("same-digest replay = created=%v err=%v, want existing record", created, err)
	}
	if got.ID != base.ID || got.SHA256 != "digest-1" {
		t.Fatalf("replay returned %+v, want the stored record", got)
	}
	conflict := base
	conflict.ID = "cccccccccccccccccccccccccccccccc"
	conflict.SHA256 = "digest-2"
	got, created, err = m.InsertArtifactOnce(ctx(), conflict)
	if !errors.Is(err, ErrArtifactDigestConflict) || created {
		t.Fatalf("different-digest insert = created=%v err=%v, want ErrArtifactDigestConflict", created, err)
	}
	if got.SHA256 != "digest-1" {
		t.Fatalf("conflict returned %q, want the stored digest", got.SHA256)
	}
	if list, _ := m.ListArtifacts(ctx(), testRun.ID); len(list) != 1 {
		t.Fatalf("artifacts = %d rows, want exactly 1", len(list))
	}
	// A new lease generation is a distinct key.
	next := base
	next.ID = "dddddddddddddddddddddddddddddddd"
	next.LeaseGeneration = 1
	if _, created, err := m.InsertArtifactOnce(ctx(), next); err != nil || !created {
		t.Fatalf("new generation insert = created=%v err=%v", created, err)
	}
	// Empty job IDs mirror SQL NULLs: they never join the unique key.
	noJob := base
	noJob.ID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	noJob.JobID = ""
	noJob.Name = "log"
	if _, created, err := m.InsertArtifactOnce(ctx(), noJob); err != nil || !created {
		t.Fatalf("empty-job insert = created=%v err=%v", created, err)
	}
	if _, created, err := m.InsertArtifactOnce(ctx(), noJob); err != nil || !created {
		t.Fatalf("empty-job second insert = created=%v err=%v (NULL keys never conflict)", created, err)
	}
}
