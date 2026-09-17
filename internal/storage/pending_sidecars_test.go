package storage

import (
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// TestMigration0012PendingSidecars verifies the pending-sidecar migration
// creates the durable table with the (job, artifact, kind) primary key, the
// digest column and the created_at prune index.
func TestMigration0012PendingSidecars(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0012_artifact_pending_sidecars.sql")
	if err != nil {
		t.Fatalf("read 0012: %v", err)
	}
	sql := string(raw)
	for _, want := range []string{
		`CREATE TABLE artifact_pending_sidecars`,
		`job_id TEXT NOT NULL`,
		`artifact_name TEXT NOT NULL`,
		`kind TEXT NOT NULL`,
		`digest TEXT NOT NULL`,
		`created_at TIMESTAMPTZ NOT NULL DEFAULT now()`,
		`PRIMARY KEY (job_id, artifact_name, kind)`,
		`artifact_pending_sidecars_created_at_idx`,
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("0012_artifact_pending_sidecars.sql is missing %q", want)
		}
	}
	if stmts := migrations.SplitStatements(sql); len(stmts) != 2 {
		t.Fatalf("0012 has %d statements, want 2 (CREATE TABLE + CREATE INDEX)", len(stmts))
	}
}

// TestMemStorePendingSidecarRoundTrip proves the durable pending-sidecar
// contract on the in-memory store: remember upserts, pending resolves per
// (job, artifact, kind), consume deletes only the consumed digest, delete
// clears the job, and prune drops only expired rows.
func TestMemStorePendingSidecarRoundTrip(t *testing.T) {
	m := newMemStore()
	ctx := ctx()
	job := testJob.ID
	names := []string{ArtifactSidecarKindSBOM, ArtifactSidecarKindSigstore}
	if err := m.RememberPendingSidecar(ctx, job, "bin", names[0], strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := m.RememberPendingSidecar(ctx, job, "bin", names[1], strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	// A re-upload replaces the digest.
	if err := m.RememberPendingSidecar(ctx, job, "bin", names[0], strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	if d, ok, err := m.PendingSidecar(ctx, job, "bin", names[0]); err != nil || !ok || d != strings.Repeat("c", 64) {
		t.Fatalf("pending sbom = %q ok=%v err=%v", d, ok, err)
	}
	// A different artifact name is a different key.
	if _, ok, _ := m.PendingSidecar(ctx, job, "other", names[0]); ok {
		t.Fatal("pending row leaked across artifact names")
	}
	// Consume with a STALE digest must not drop the current row.
	if err := m.ConsumePendingSidecar(ctx, job, "bin", names[0], strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := m.PendingSidecar(ctx, job, "bin", names[0]); !ok {
		t.Fatal("stale consume dropped the re-uploaded digest")
	}
	// Consume with the current digest deletes it.
	if err := m.ConsumePendingSidecar(ctx, job, "bin", names[0], strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := m.PendingSidecar(ctx, job, "bin", names[0]); ok {
		t.Fatal("consume left the pending row behind")
	}
	// DeletePendingSidecars clears the job's remaining rows only.
	if err := m.RememberPendingSidecar(ctx, "cccccccccccccccccccccccccccccccc", "bin", names[0], strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
	if err := m.DeletePendingSidecars(ctx, job); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := m.PendingSidecar(ctx, job, "bin", names[1]); ok {
		t.Fatal("delete-by-job left a row for the job")
	}
	if _, ok, _ := m.PendingSidecar(ctx, "cccccccccccccccccccccccccccccccc", "bin", names[0]); !ok {
		t.Fatal("delete-by-job dropped another job's row")
	}
	// Prune drops only rows older than the cutoff.
	m.mu.Lock()
	m.pendingSidecars[pendingSidecarKey("dddddddddddddddddddddddddddddddd", "bin", names[0])] = pendingSidecar{digest: strings.Repeat("e", 64), createdAt: time.Now().UTC().Add(-8 * 24 * time.Hour)}
	m.mu.Unlock()
	n, err := m.PrunePendingSidecars(ctx, time.Now().UTC().Add(-7*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("prune = %d, %v; want 1 row", n, err)
	}
	if _, ok, _ := m.PendingSidecar(ctx, "dddddddddddddddddddddddddddddddd", "bin", names[0]); ok {
		t.Fatal("prune left the expired row behind")
	}
}

// TestMemStorePendingSidecarValidation rejects malformed keys and digests
// so a bad row can never be persisted.
func TestMemStorePendingSidecarValidation(t *testing.T) {
	m := newMemStore()
	ctx := ctx()
	if err := m.RememberPendingSidecar(ctx, "not-an-id", "bin", ArtifactSidecarKindSBOM, strings.Repeat("a", 64)); err == nil {
		t.Fatal("malformed job id accepted")
	}
	if err := m.RememberPendingSidecar(ctx, testJob.ID, "bin", "bogus", strings.Repeat("a", 64)); err == nil {
		t.Fatal("unknown sidecar kind accepted")
	}
	if err := m.RememberPendingSidecar(ctx, testJob.ID, "bin", ArtifactSidecarKindSBOM, "short"); err == nil {
		t.Fatal("malformed digest accepted")
	}
	if _, _, err := m.PendingSidecar(ctx, testJob.ID, "", ArtifactSidecarKindSBOM); err == nil {
		t.Fatal("empty artifact name accepted")
	}
	if err := m.ConsumePendingSidecar(ctx, testJob.ID, "bin", ArtifactSidecarKindSBOM, strings.Repeat("z", 64)); err == nil {
		t.Fatal("non-hex digest accepted")
	}
	// A faulted consume must not report success twice.
	if err := m.DeletePendingSidecars(ctx, "not-an-id"); err == nil {
		t.Fatal("malformed job id accepted by delete")
	}
}
