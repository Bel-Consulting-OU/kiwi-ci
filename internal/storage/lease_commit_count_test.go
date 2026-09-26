package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestMemStoreCountSnapshotsForJobKeyedToLockedPair pins the O(1) preflight
// count behind the snapshot-upload cap: it counts exactly the records of the
// addressed (run, job) pair — never a sibling job's records and never legacy
// NULL-job rows on the same run — and rejects a malformed run id before the
// scan instead of reporting a count for an addressable run.
func TestMemStoreCountSnapshotsForJobKeyedToLockedPair(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	exp := time.Now().UTC().Add(time.Hour)
	runnerA := strings.Repeat("1", 32)
	runnerC := strings.Repeat("3", 32)
	jobA, runA := leaseCommitSeed(t, m, model.StatusRunning, runnerA, 7, exp)
	jobC, runC := leaseCommitSeed(t, m, model.StatusRunning, runnerC, 3, exp)

	for i := 0; i < 2; i++ {
		if err := m.InsertSnapshotForLease(ctx, jobA, runnerA, 7, 0, model.SnapshotRecord{ID: pgITNewID(t), RunID: runA, JobID: jobA, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("seed snapshot for A: %v", err)
		}
	}
	m.snapshots = append(m.snapshots, model.SnapshotRecord{ID: pgITNewID(t), RunID: runA, CreatedAt: time.Now().UTC()})
	for i := 0; i < 3; i++ {
		if err := m.InsertSnapshotForLease(ctx, jobC, runnerC, 3, 0, model.SnapshotRecord{ID: pgITNewID(t), RunID: runC, JobID: jobC, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("seed snapshot for C: %v", err)
		}
	}

	if n, err := m.CountSnapshotsForJob(ctx, runA, jobA); err != nil || n != 2 {
		t.Fatalf("CountSnapshotsForJob(A) = (%d, %v), want (2, nil): the NULL-job legacy row must not count", n, err)
	}
	if n, err := m.CountSnapshotsForJob(ctx, runC, jobC); err != nil || n != 3 {
		t.Fatalf("CountSnapshotsForJob(C) = (%d, %v), want (3, nil)", n, err)
	}
	if n, err := m.CountSnapshotsForJob(ctx, runA, jobC); err != nil || n != 0 {
		t.Fatalf("CountSnapshotsForJob(cross pair) = (%d, %v), want (0, nil)", n, err)
	}
	if n, err := m.CountSnapshotsForJob(ctx, runC, jobA); err != nil || n != 0 {
		t.Fatalf("CountSnapshotsForJob(foreign job on C's run) = (%d, %v), want (0, nil)", n, err)
	}
	if _, err := m.CountSnapshotsForJob(ctx, "", jobA); err == nil {
		t.Fatal("malformed run id accepted by CountSnapshotsForJob")
	}
}

// TestFaultyStoreCountSnapshotsForJobParity pins the wrapper contract of the
// optional preflight capability: it delegates unchanged to an inner store that
// has it, and a minimal inner store without it fails closed with the typed
// missing-interface error instead of reporting a fabricated count.
func TestFaultyStoreCountSnapshotsForJobParity(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	runner := strings.Repeat("1", 32)
	jobID, runID := leaseCommitSeed(t, m, model.StatusRunning, runner, 5, time.Now().UTC().Add(time.Hour))
	if err := m.InsertSnapshotForLease(ctx, jobID, runner, 5, 0, model.SnapshotRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	f := &FaultyStore{Inner: m}
	if n, err := f.CountSnapshotsForJob(ctx, runID, jobID); err != nil || n != 1 {
		t.Fatalf("FaultyStore CountSnapshotsForJob = (%d, %v), want (1, nil)", n, err)
	}
	_, err := (&FaultyStore{Inner: storeOnlyInner{}}).CountSnapshotsForJob(ctx, runID, jobID)
	var miss *missingInnerInterfaceError
	if !errors.As(err, &miss) {
		t.Fatalf("store without the count capability = %v, want *missingInnerInterfaceError", err)
	}
}

// TestMemStoreLeaseCommitTrustedCacheNamespace pins the trust-domain half of
// the cache namespace derivation: a trusted job's manifest must carry the
// trusted domain the store derives from the LOCKED job, and a record claiming
// the wrong domain commits nothing.
func TestMemStoreLeaseCommitTrustedCacheNamespace(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	runner := strings.Repeat("2", 32)
	jobID, runID := leaseCommitSeed(t, m, model.StatusRunning, runner, 4, time.Now().UTC().Add(time.Hour))
	j, err := m.GetJob(ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	j.Trusted = true
	if err := m.InsertJob(ctx, j); err != nil {
		t.Fatal(err)
	}

	rec := leaseCommitManifest(t, "trusted-key")
	rec.TrustDomain = "trusted"
	if err := m.PutCacheManifestForLease(ctx, jobID, runner, 4, rec); err != nil {
		t.Fatalf("trusted manifest commit: %v", err)
	}
	stored, found, err := m.GetCacheManifest(ctx, "github.com/acme/widget", "trusted", "trusted-key")
	if err != nil || !found {
		t.Fatalf("trusted manifest lookup = (%v, %v)", found, err)
	}
	if stored.ProducerJob != jobID || stored.ProducerRun != runID {
		t.Fatalf("producer = %s/%s, want %s/%s", stored.ProducerJob, stored.ProducerRun, jobID, runID)
	}

	wrong := leaseCommitManifest(t, "trusted-key-wrong")
	wrong.TrustDomain = "untrusted"
	if err := m.PutCacheManifestForLease(ctx, jobID, runner, 4, wrong); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("untrusted domain for a trusted job = %v, want ErrLeaseIdentityMismatch", err)
	}
	if _, found, _ := m.GetCacheManifest(ctx, "github.com/acme/widget", "untrusted", "trusted-key-wrong"); found {
		t.Fatal("cross-domain manifest was committed")
	}
}

// TestMemStoreLeaseCommitRunBindingRefused fills the two identity-binding
// fields the cross-job matrix did not exercise: an artifact whose run id names
// another run (same job id) and a cache manifest whose producer run disagrees,
// both under a live lease.
func TestMemStoreLeaseCommitRunBindingRefused(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	runner := strings.Repeat("7", 32)
	jobID, runID := leaseCommitSeed(t, m, model.StatusRunning, runner, 9, time.Now().UTC().Add(time.Hour))
	otherRun := pgITNewID(t)

	art := model.ArtifactRecord{ID: pgITNewID(t), RunID: otherRun, JobID: jobID, Name: "dist", LeaseGeneration: 9, SHA256: strings64('f'), CreatedAt: time.Now().UTC()}
	if _, _, err := m.InsertArtifactOnceForLease(ctx, jobID, runner, 9, art); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("artifact with a foreign run id = %v, want ErrLeaseIdentityMismatch", err)
	}
	if got, _ := m.ListArtifacts(ctx, ""); len(got) != 0 {
		t.Fatalf("cross-run artifact committed: %d rows", len(got))
	}

	rec := leaseCommitManifest(t, "run-bound")
	rec.ProducerRun = otherRun
	if err := m.PutCacheManifestForLease(ctx, jobID, runner, 9, rec); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("manifest with a foreign producer run = %v, want ErrLeaseIdentityMismatch", err)
	}
	if _, found, _ := m.GetCacheManifest(ctx, rec.Repo, rec.TrustDomain, rec.LogicalKey); found {
		t.Fatal("cross-run manifest was committed")
	}

	// The same records with the locked run id commit, and the run id is the
	// only difference.
	art.RunID = runID
	if _, created, err := m.InsertArtifactOnceForLease(ctx, jobID, runner, 9, art); err != nil || !created {
		t.Fatalf("matching artifact = (created=%v, %v)", created, err)
	}
	rec.ProducerRun = runID
	if err := m.PutCacheManifestForLease(ctx, jobID, runner, 9, rec); err != nil {
		t.Fatalf("matching manifest: %v", err)
	}
}

// TestPostgresLeaseCommitRejectsInvalidInputBeforeConnecting pins the
// validation contract of every lease-fenced PG commit: malformed lease
// coordinates, an incomplete cache namespace, a bad digest and invalid record
// identities are refused before a transaction is ever opened. The store has
// no pool on purpose: reaching the pool would panic, proving the ordering.
func TestPostgresLeaseCommitRejectsInvalidInputBeforeConnecting(t *testing.T) {
	ctx := context.Background()
	st := &PostgresStore{}

	for _, bad := range []struct {
		name   string
		jobID  string
		runner string
		gen    int64
	}{
		{"empty job", "", "runner", 1},
		{"empty runner", "job", "", 1},
		{"negative generation", "job", "runner", -1},
	} {
		t.Run(bad.name, func(t *testing.T) {
			if err := st.PutCacheManifestForLease(ctx, bad.jobID, bad.runner, bad.gen, leaseCommitManifest(t, "k")); err == nil {
				t.Fatal("manifest commit accepted malformed lease coordinates")
			}
			if err := st.InsertSnapshotForLease(ctx, bad.jobID, bad.runner, bad.gen, 0, model.SnapshotRecord{ID: pgITNewID(t), RunID: pgITNewID(t)}); err == nil {
				t.Fatal("snapshot commit accepted malformed lease coordinates")
			}
			if _, _, err := st.InsertArtifactOnceForLease(ctx, bad.jobID, bad.runner, bad.gen, model.ArtifactRecord{ID: pgITNewID(t), RunID: pgITNewID(t), Name: "dist"}); err == nil {
				t.Fatal("artifact commit accepted malformed lease coordinates")
			}
		})
	}

	if err := st.PutCacheManifestForLease(ctx, "job", "runner", 1, CacheManifestRecord{}); err == nil {
		t.Fatal("manifest with an empty namespace accepted")
	}
	if err := st.PutCacheManifestForLease(ctx, "job", "runner", 1, CacheManifestRecord{Repo: "r", TrustDomain: "t", LogicalKey: "k", BlobSHA256: "short"}); err == nil {
		t.Fatal("manifest with a malformed digest accepted")
	}
	if err := st.InsertSnapshotForLease(ctx, "job", "runner", 1, 0, model.SnapshotRecord{RunID: pgITNewID(t)}); err == nil {
		t.Fatal("snapshot with an empty id accepted")
	}
	if err := st.InsertSnapshotForLease(ctx, "job", "runner", 1, 0, model.SnapshotRecord{ID: pgITNewID(t)}); err == nil {
		t.Fatal("snapshot with an empty run id accepted")
	}
	if _, _, err := st.InsertArtifactOnceForLease(ctx, "job", "runner", 1, model.ArtifactRecord{RunID: pgITNewID(t), Name: "dist"}); err == nil {
		t.Fatal("artifact with an empty id accepted")
	}
	if _, _, err := st.InsertArtifactOnceForLease(ctx, "job", "runner", 1, model.ArtifactRecord{ID: pgITNewID(t), Name: "dist"}); err == nil {
		t.Fatal("artifact with an empty run id accepted")
	}
	if _, err := st.CountSnapshotsForJob(ctx, "", "job"); err == nil {
		t.Fatal("preflight count accepted a malformed run id")
	}
}
