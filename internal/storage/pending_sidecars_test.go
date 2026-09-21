package storage

import (
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// TestMigration0012PendingSidecars verifies the SHIPPED 0012 DDL (its
// generation-less primary key is superseded by 0028; the file itself is
// intentionally left untouched so a replay stays identical).
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

// TestMigration0028GenerationScopedPendingSidecars pins the migration that
// makes the lease generation part of the pending-sidecar primary key: it
// DRAINS the transient pre-0028 rows (they carry no generation and cannot be
// attributed safely) and recreates artifact_pending_sidecars keyed by the
// full artifact identity, keeping the created_at prune index.
func TestMigration0028GenerationScopedPendingSidecars(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0028_generation_scoped_pending_sidecars.sql")
	if err != nil {
		t.Fatalf("read 0028: %v", err)
	}
	sql := string(raw)
	for _, want := range []string{
		`DELETE FROM artifact_pending_sidecars`,
		`DROP TABLE IF EXISTS artifact_pending_sidecars`,
		`CREATE TABLE artifact_pending_sidecars`,
		`job_generation BIGINT NOT NULL`,
		`created_at TIMESTAMPTZ NOT NULL DEFAULT now()`,
		`PRIMARY KEY (job_id, job_generation, artifact_name, kind)`,
		`CREATE INDEX IF NOT EXISTS artifact_pending_sidecars_created_at_idx`,
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("0028_generation_scoped_pending_sidecars.sql is missing %q", want)
		}
	}
	// The generation-less key must be gone from the new DDL.
	if strings.Contains(sql, `PRIMARY KEY (job_id, artifact_name, kind)`) {
		t.Error("0028 kept the generation-less primary key")
	}
	stmts := migrations.SplitStatements(sql)
	if len(stmts) != 4 {
		t.Fatalf("0028 has %d statements, want 4 (DELETE + DROP + CREATE TABLE + CREATE INDEX)", len(stmts))
	}
	// DRAIN must run before the recreated table accepts rows; the DROP+CREATE
	// must stay in the same file so no committed schema version has the table
	// absent.
	if !strings.HasPrefix(stmts[0], "DELETE FROM artifact_pending_sidecars") {
		t.Fatalf("0028 statement 1 = %q, want the drain DELETE first", stmts[0])
	}
	if !strings.HasPrefix(stmts[1], "DROP TABLE IF EXISTS artifact_pending_sidecars") {
		t.Fatalf("0028 statement 2 = %q, want the DROP", stmts[1])
	}
	if !strings.HasPrefix(stmts[2], "CREATE TABLE artifact_pending_sidecars") {
		t.Fatalf("0028 statement 3 = %q, want the CREATE TABLE", stmts[2])
	}
	// The migration set is ordered: 0028 runs exactly once, after everything
	// that existed before it, and later migrations append after it.
	all, err := migrations.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if got := all[len(all)-1].Version; got < 29 {
		t.Fatalf("newest migration version = %d, want >= 29 (0029 adds the report-delivery receipts)", got)
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Version >= all[i].Version {
			t.Fatalf("migrations not strictly ordered at %d/%d", all[i-1].Version, all[i].Version)
		}
	}
}

// TestMemStorePendingSidecarRoundTrip proves the generation-qualified
// pending-sidecar contract on the in-memory store: remember upserts one exact
// (job, generation, artifact, kind) row, a differing generation or artifact
// never resolves it, consume deletes only the consumed digest of its own
// generation, and prune drops expired rows (keeping fresh ones).
func TestMemStorePendingSidecarRoundTrip(t *testing.T) {
	m := newMemStore()
	ctx := ctx()
	job := testJob.ID
	names := []string{ArtifactSidecarKindSBOM, ArtifactSidecarKindSigstore}
	if err := m.RememberPendingSidecar(ctx, job, 1, "bin", names[0], strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := m.RememberPendingSidecar(ctx, job, 1, "bin", names[1], strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	// A re-upload of the same generation replaces the digest.
	if err := m.RememberPendingSidecar(ctx, job, 1, "bin", names[0], strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	if d, ok, err := m.PendingSidecar(ctx, job, 1, "bin", names[0]); err != nil || !ok || d != strings.Repeat("c", 64) {
		t.Fatalf("pending sbom = %q ok=%v err=%v", d, ok, err)
	}
	// A different artifact name is a different key.
	if _, ok, _ := m.PendingSidecar(ctx, job, 1, "other", names[0]); ok {
		t.Fatal("pending row leaked across artifact names")
	}
	// A different lease generation is a different key.
	if _, ok, _ := m.PendingSidecar(ctx, job, 2, "bin", names[0]); ok {
		t.Fatal("pending row leaked across lease generations")
	}
	// Consume with a STALE digest must not drop the current row.
	if err := m.ConsumePendingSidecar(ctx, job, 1, "bin", names[0], strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := m.PendingSidecar(ctx, job, 1, "bin", names[0]); !ok {
		t.Fatal("stale consume dropped the re-uploaded digest")
	}
	// Consume with the current digest deletes it.
	if err := m.ConsumePendingSidecar(ctx, job, 1, "bin", names[0], strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := m.PendingSidecar(ctx, job, 1, "bin", names[0]); ok {
		t.Fatal("consume left the pending row behind")
	}
	// Prune drops only rows older than the cutoff; a fresh row (any
	// generation) survives.
	m.mu.Lock()
	m.pendingSidecars[pendingSidecarKey("dddddddddddddddddddddddddddddddd", 7, "bin", names[0])] = pendingSidecar{digest: strings.Repeat("e", 64), createdAt: time.Now().UTC().Add(-8 * 24 * time.Hour)}
	m.pendingSidecars[pendingSidecarKey("dddddddddddddddddddddddddddddddd", 8, "bin", names[0])] = pendingSidecar{digest: strings.Repeat("f", 64), createdAt: time.Now().UTC()}
	m.mu.Unlock()
	n, err := m.PrunePendingSidecars(ctx, time.Now().UTC().Add(-7*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("prune = %d, %v; want 1 row", n, err)
	}
	if _, ok, _ := m.PendingSidecar(ctx, "dddddddddddddddddddddddddddddddd", 7, "bin", names[0]); ok {
		t.Fatal("prune left the expired row behind")
	}
	if _, ok, _ := m.PendingSidecar(ctx, "dddddddddddddddddddddddddddddddd", 8, "bin", names[0]); !ok {
		t.Fatal("prune dropped a fresh row")
	}
}

// TestMemStorePendingSidecarValidation rejects malformed keys (including a
// negative lease generation) and digests so a bad row can never be persisted.
func TestMemStorePendingSidecarValidation(t *testing.T) {
	m := newMemStore()
	ctx := ctx()
	if err := m.RememberPendingSidecar(ctx, "not-an-id", 1, "bin", ArtifactSidecarKindSBOM, strings.Repeat("a", 64)); err == nil {
		t.Fatal("malformed job id accepted")
	}
	if err := m.RememberPendingSidecar(ctx, testJob.ID, -1, "bin", ArtifactSidecarKindSBOM, strings.Repeat("a", 64)); err == nil {
		t.Fatal("negative lease generation accepted")
	}
	if err := m.RememberPendingSidecar(ctx, testJob.ID, 1, "bin", "bogus", strings.Repeat("a", 64)); err == nil {
		t.Fatal("unknown sidecar kind accepted")
	}
	if err := m.RememberPendingSidecar(ctx, testJob.ID, 1, "bin", ArtifactSidecarKindSBOM, "short"); err == nil {
		t.Fatal("malformed digest accepted")
	}
	if _, _, err := m.PendingSidecar(ctx, testJob.ID, 1, "", ArtifactSidecarKindSBOM); err == nil {
		t.Fatal("empty artifact name accepted")
	}
	if _, _, err := m.PendingSidecar(ctx, testJob.ID, -1, "bin", ArtifactSidecarKindSBOM); err == nil {
		t.Fatal("negative generation accepted by pending")
	}
	if err := m.ConsumePendingSidecar(ctx, testJob.ID, 1, "bin", ArtifactSidecarKindSBOM, strings.Repeat("z", 64)); err == nil {
		t.Fatal("non-hex digest accepted")
	}
}

// TestMemStorePendingSidecarsAreLeaseGenerationScoped proves the storage-level
// generation scoping that backs the HTTP gate: a pending row written for
// generation N resolves for N only, a consume for M != N deletes nothing,
// and writing M never mutates N's digest.
func TestMemStorePendingSidecarsAreLeaseGenerationScoped(t *testing.T) {
	m := newMemStore()
	ctx := ctx()
	job := testJob.ID
	gen1Digest := strings.Repeat("1", 64)
	gen2Digest := strings.Repeat("2", 64)
	if err := m.RememberPendingSidecar(ctx, job, 1, "bin", ArtifactSidecarKindSBOM, gen1Digest); err != nil {
		t.Fatal(err)
	}
	if d, ok, _ := m.PendingSidecar(ctx, job, 1, "bin", ArtifactSidecarKindSBOM); !ok || d != gen1Digest {
		t.Fatalf("generation 1 pending = %q ok=%v", d, ok)
	}
	if _, ok, _ := m.PendingSidecar(ctx, job, 2, "bin", ArtifactSidecarKindSBOM); ok {
		t.Fatal("generation 2 resolved generation 1's pending row")
	}
	if err := m.RememberPendingSidecar(ctx, job, 2, "bin", ArtifactSidecarKindSBOM, gen2Digest); err != nil {
		t.Fatal(err)
	}
	if d, ok, _ := m.PendingSidecar(ctx, job, 1, "bin", ArtifactSidecarKindSBOM); !ok || d != gen1Digest {
		t.Fatalf("generation 1 row mutated by generation 2: %q ok=%v", d, ok)
	}
	// Consuming generation 1 leaves generation 2 untouched, and vice versa.
	if err := m.ConsumePendingSidecar(ctx, job, 1, "bin", ArtifactSidecarKindSBOM, gen1Digest); err != nil {
		t.Fatal(err)
	}
	if d, ok, _ := m.PendingSidecar(ctx, job, 2, "bin", ArtifactSidecarKindSBOM); !ok || d != gen2Digest {
		t.Fatalf("generation 2 row lost after generation 1 consume: %q ok=%v", d, ok)
	}
	if err := m.ConsumePendingSidecar(ctx, job, 1, "bin", ArtifactSidecarKindSBOM, gen2Digest); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := m.PendingSidecar(ctx, job, 2, "bin", ArtifactSidecarKindSBOM); !ok {
		t.Fatal("generation 2 row deleted by a generation 1 consume")
	}
}

// TestFaultyStorePendingSidecarGenerationParity proves the FaultyStore wrapper
// is a transparent pass-through for the generation-qualified store API: the
// exact same scoping observable on the bare memStore holds through the
// wrapper, including the injected-fault paths.
func TestFaultyStorePendingSidecarGenerationParity(t *testing.T) {
	ctx := ctx()
	job := testJob.ID
	gen1Digest := strings.Repeat("1", 64)
	gen2Digest := strings.Repeat("2", 64)
	f := &FaultyStore{Inner: newMemStore()}
	if err := f.RememberPendingSidecar(ctx, job, 1, "bin", ArtifactSidecarKindSBOM, gen1Digest); err != nil {
		t.Fatalf("RememberPendingSidecar: %v", err)
	}
	if err := f.RememberPendingSidecar(ctx, job, 2, "bin", ArtifactSidecarKindSBOM, gen2Digest); err != nil {
		t.Fatalf("RememberPendingSidecar gen2: %v", err)
	}
	if d, ok, err := f.PendingSidecar(ctx, job, 1, "bin", ArtifactSidecarKindSBOM); err != nil || !ok || d != gen1Digest {
		t.Fatalf("wrapper generation 1 pending = %q ok=%v err=%v", d, ok, err)
	}
	if d, ok, err := f.PendingSidecar(ctx, job, 2, "bin", ArtifactSidecarKindSBOM); err != nil || !ok || d != gen2Digest {
		t.Fatalf("wrapper generation 2 pending = %q ok=%v err=%v", d, ok, err)
	}
	if _, ok, _ := f.PendingSidecar(ctx, job, 3, "bin", ArtifactSidecarKindSBOM); ok {
		t.Fatal("wrapper resolved another generation's pending row")
	}
	// A consume of one generation never removes the other's row.
	if err := f.ConsumePendingSidecar(ctx, job, 1, "bin", ArtifactSidecarKindSBOM, gen1Digest); err != nil {
		t.Fatalf("wrapper consume gen1: %v", err)
	}
	if _, ok, _ := f.PendingSidecar(ctx, job, 1, "bin", ArtifactSidecarKindSBOM); ok {
		t.Fatal("wrapper consume left generation 1 behind")
	}
	if _, ok, _ := f.PendingSidecar(ctx, job, 2, "bin", ArtifactSidecarKindSBOM); !ok {
		t.Fatal("wrapper consume of generation 1 dropped generation 2")
	}
	// Prune through the wrapper keeps fresh rows and drops expired ones.
	if err := f.RememberPendingSidecar(ctx, job, 4, "bin", ArtifactSidecarKindSigstore, strings.Repeat("3", 64)); err != nil {
		t.Fatal(err)
	}
	if n, err := f.PrunePendingSidecars(ctx, time.Now().UTC().Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("wrapper prune fresh = %d, %v", n, err)
	}
	healthy := &FaultyStore{Inner: f.Inner}
	if n, err := healthy.PrunePendingSidecars(ctx, time.Now().UTC().Add(time.Hour)); err != nil || n != 2 {
		t.Fatalf("wrapper prune stale = %d, %v", n, err)
	}
	// Injected faults surface through the wrapper for the generation-scoped
	// methods.
	armedRemember := &FaultyStore{Inner: f.Inner, FailAfter: 1, Err: errBoom}
	if err := armedRemember.RememberPendingSidecar(ctx, job, 9, "bin", ArtifactSidecarKindSBOM, gen1Digest); err == nil {
		t.Fatal("armed wrapper RememberPendingSidecar returned nil")
	}
	armedConsume := &FaultyStore{Inner: f.Inner, FailAfter: 1, Err: errBoom}
	if err := armedConsume.ConsumePendingSidecar(ctx, job, 9, "bin", ArtifactSidecarKindSBOM, gen1Digest); err == nil {
		t.Fatal("armed wrapper ConsumePendingSidecar returned nil")
	}
}
