package server

// Real-PostgreSQL integration test for the reference-aware CAS garbage
// collector: the durable reference sources (artifact rows, pending sidecar
// rows) and the cross-replica collector lease are exercised against a live
// database. Gated on KIWI_TEST_POSTGRES_URL like the other integration
// tests in this package.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func TestCASGCIntegrationDBMode(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	ctx := context.Background()

	referenced := putCASBlob(t, s, "pg referenced payload")
	orphan := putCASBlob(t, s, "pg orphan payload")
	fresh := putCASBlob(t, s, "pg fresh payload")
	pending := putCASBlob(t, s, "pg pending sidecar payload")

	// Durable references: one artifact row and one pending-sidecar row.
	runID := pgITServerRandomHex(t, 32)
	if err := st.InsertArtifact(ctx, model.ArtifactRecord{
		ID: pgITServerRandomHex(t, 32), RunID: runID, JobID: runID, JobKey: "build",
		Name: "bin", Size: referenced.Size, SHA256: referenced.SHA256, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("insert artifact: %v", err)
	}
	if err := st.RememberPendingSidecar(ctx, runID, "bin", storage.ArtifactSidecarKindSBOM, pending.SHA256); err != nil {
		t.Fatalf("remember pending sidecar: %v", err)
	}

	ageCASBlob(t, s, referenced.SHA256, 48*time.Hour)
	ageCASBlob(t, s, orphan.SHA256, 48*time.Hour)
	ageCASBlob(t, s, pending.SHA256, 48*time.Hour)

	// Another replica holds the collector advisory lease: this pass must be
	// skipped even though the orphan is old and unreferenced.
	other := env.open(t)
	pgITSrvArmFence(t, other)
	lease, held, err := other.TryAcquireCASGCLease(ctx, casGCLeaseKey)
	if err != nil || !held {
		t.Fatalf("second replica lease: held=%v err=%v", held, err)
	}
	stats, err := s.runCASGC(ctx, casGCOptions{MinAge: 24 * time.Hour, Batch: 100})
	if err != nil {
		t.Fatalf("runCASGC under held lease: %v", err)
	}
	if stats.Deleted != 0 || !casBlobExists(t, s, orphan.SHA256) {
		t.Fatalf("a lease held by another replica must skip collection: %+v", stats)
	}
	if err := lease.Release(ctx); err != nil {
		t.Fatalf("release lease: %v", err)
	}

	// With the lease free, the pass reads the durable references and removes
	// only the old unreferenced object.
	stats, err = s.runCASGC(ctx, casGCOptions{MinAge: 24 * time.Hour, Batch: 100})
	if err != nil {
		t.Fatalf("runCASGC: %v", err)
	}
	if stats.Deleted != 1 || stats.Bytes != orphan.Size {
		t.Fatalf("deleted = %d (%d bytes), want 1 (%d)", stats.Deleted, stats.Bytes, orphan.Size)
	}
	if casBlobExists(t, s, orphan.SHA256) {
		t.Fatal("the durable-store orphan must be deleted")
	}
	for name, digest := range map[string]string{
		"artifact":        referenced.SHA256,
		"fresh":           fresh.SHA256,
		"pending sidecar": pending.SHA256,
	} {
		if !casBlobExists(t, s, digest) {
			t.Fatalf("%s object must survive", name)
		}
	}
}
