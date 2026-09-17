package storage

// Real-PostgreSQL integration tests for the CAS reference read paths and the
// collector advisory lease. Gated on KIWI_TEST_POSTGRES_URL like the rest of
// the integration lane.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func pgITDigest(b byte) string {
	return strings.Repeat(string([]byte{b}), 64)
}

func TestPostgresIntegrationCASReferenceReads(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	payload := pgITDigest('a')
	provenance := pgITDigest('b')
	sbom := pgITDigest('c')
	sigstore := pgITDigest('d')
	snapshot := pgITDigest('e')
	root := pgITDigest('f')
	cacheDigest := pgITDigest('0')
	pendingDigest := pgITDigest('1')

	if err := st.InsertArtifact(ctx, model.ArtifactRecord{
		ID: pgITNewID(t), RunID: runID, JobID: jobID, JobKey: "build", Name: "bin",
		Size: 3, SHA256: payload, ProvenanceSHA256: provenance, SBOMSHA256: sbom, SigstoreSHA256: sigstore,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("insert artifact: %v", err)
	}
	if err := st.InsertSnapshotRecord(ctx, model.SnapshotRecord{
		ID: pgITNewID(t), RunID: runID, JobID: jobID, JobKey: "build",
		Path: "cas:" + snapshot, Size: 7, SHA256: snapshot, RootSHA256: root, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("insert snapshot: %v", err)
	}
	if err := st.PutCacheManifest(ctx, CacheManifestRecord{
		Repo: "r", TrustDomain: "t", LogicalKey: "k", BlobSHA256: cacheDigest,
		BlobSize: 5, CreatedAt: time.Now().UTC(), Envelope: []byte(`{"payloadType":"x"}`),
	}); err != nil {
		t.Fatalf("put cache manifest: %v", err)
	}
	if err := st.RememberPendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, pendingDigest); err != nil {
		t.Fatalf("remember pending sidecar: %v", err)
	}

	artifacts, err := st.ListAllArtifacts(ctx)
	if err != nil {
		t.Fatalf("ListAllArtifacts: %v", err)
	}
	foundArtifact := false
	for _, a := range artifacts {
		if a.SHA256 == payload {
			foundArtifact = true
			if a.ProvenanceSHA256 != provenance || a.SBOMSHA256 != sbom || a.SigstoreSHA256 != sigstore {
				t.Fatalf("artifact sidecar digests lost: %+v", a)
			}
		}
	}
	if !foundArtifact {
		t.Fatalf("artifact %s missing from %d rows", payload, len(artifacts))
	}

	snapshots, err := st.ListAllSnapshots(ctx)
	if err != nil {
		t.Fatalf("ListAllSnapshots: %v", err)
	}
	foundSnapshot := false
	for _, rec := range snapshots {
		if rec.SHA256 == snapshot {
			foundSnapshot = true
			if rec.RootSHA256 != root {
				t.Fatalf("snapshot root lost: %+v", rec)
			}
		}
	}
	if !foundSnapshot {
		t.Fatalf("snapshot %s missing from %d rows", snapshot, len(snapshots))
	}

	manifests, err := st.ListAllCacheManifests(ctx)
	if err != nil {
		t.Fatalf("ListAllCacheManifests: %v", err)
	}
	foundManifest := false
	for _, rec := range manifests {
		if rec.BlobSHA256 == cacheDigest {
			foundManifest = true
		}
	}
	if !foundManifest {
		t.Fatalf("cache manifest %s missing from %d rows", cacheDigest, len(manifests))
	}

	digests, err := st.ListAllPendingSidecarDigests(ctx)
	if err != nil {
		t.Fatalf("ListAllPendingSidecarDigests: %v", err)
	}
	foundPending := false
	for _, d := range digests {
		if d == pendingDigest {
			foundPending = true
		}
	}
	if !foundPending {
		t.Fatalf("pending sidecar digest %s missing from %v", pendingDigest, digests)
	}
}

// TestPostgresIntegrationCASGCLeaseSeparation proves the collector lease is
// mutually exclusive across store instances and never disturbs the
// scheduler's leadership claim on the same store.
func TestPostgresIntegrationCASGCLeaseSeparation(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	env.migrate(t, st)
	other := env.open(t)
	ctx := context.Background()

	// The scheduler leadership claim is held first, exactly as in
	// production.
	leader := "kiwi-leader-" + pgITRandomHex(t, 8)
	got, err := st.TryAcquireLeadership(ctx, leader, time.Minute)
	if err != nil || !got {
		t.Fatalf("leadership claim: got=%v err=%v", got, err)
	}
	t.Cleanup(func() { _ = st.ReleaseLeadership(context.Background(), leader) })

	lease, held, err := st.TryAcquireCASGCLease(ctx, "kiwi-cas-gc")
	if err != nil || !held {
		t.Fatalf("collector lease: held=%v err=%v", held, err)
	}
	// The leadership claim must still be renewable on the same store: the
	// collector lease uses its own connection.
	if got, err := st.TryAcquireLeadership(ctx, leader, time.Minute); err != nil || !got {
		t.Fatalf("leadership disturbed by the collector lease: got=%v err=%v", got, err)
	}
	// A second replica cannot take the collector lease.
	if _, held, err := other.TryAcquireCASGCLease(ctx, "kiwi-cas-gc"); err != nil || held {
		t.Fatalf("second replica collector lease: held=%v err=%v", held, err)
	}
	// Releasing the first lease hands it to the second replica.
	if err := lease.Release(ctx); err != nil {
		t.Fatalf("release collector lease: %v", err)
	}
	otherLease, held, err := other.TryAcquireCASGCLease(ctx, "kiwi-cas-gc")
	if err != nil || !held {
		t.Fatalf("handover collector lease: held=%v err=%v", held, err)
	}
	if err := otherLease.Release(ctx); err != nil {
		t.Fatalf("release handover lease: %v", err)
	}
}
