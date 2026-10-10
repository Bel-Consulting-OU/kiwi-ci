package storage

// Entry-validation branches of the PostgreSQL commit methods: every guard
// that must refuse malformed identities BEFORE opening a transaction. These
// need no database because the zero-value store reaches the validation return
// before touching the pool.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestPostgresLeaseCommitValidationBranches(t *testing.T) {
	ctx := context.Background()
	st := &PostgresStore{}
	jobID, runnerID := pgITNewID(t), pgITNewID(t)
	goodDigest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	cacheRec := CacheManifestRecord{Repo: "acme/backend", TrustDomain: "default", LogicalKey: "cache-key", BlobSHA256: goodDigest, BlobSize: 1}
	if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, -1, cacheRec); err == nil {
		t.Fatal("cache manifest with a negative generation accepted")
	}
	bad := cacheRec
	bad.Repo = ""
	if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, 0, bad); err == nil {
		t.Fatal("cache manifest without a repository accepted")
	}
	bad = cacheRec
	bad.TrustDomain = ""
	if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, 0, bad); err == nil {
		t.Fatal("cache manifest without a trust domain accepted")
	}
	bad = cacheRec
	bad.LogicalKey = ""
	if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, 0, bad); err == nil {
		t.Fatal("cache manifest without a logical key accepted")
	}
	bad = cacheRec
	bad.BlobSHA256 = "short"
	if err := st.PutCacheManifestForLease(ctx, jobID, runnerID, 0, bad); err == nil {
		t.Fatal("cache manifest with a malformed digest accepted")
	}

	if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, -1, 0, model.SnapshotRecord{}); err == nil {
		t.Fatal("snapshot with a negative generation accepted")
	}
	if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, 0, 0, model.SnapshotRecord{}); err == nil {
		t.Fatal("snapshot without an id accepted")
	}
	if err := st.InsertSnapshotForLease(ctx, jobID, runnerID, 0, 0, model.SnapshotRecord{ID: pgITNewID(t)}); err == nil {
		t.Fatal("snapshot without a run accepted")
	}

	if _, _, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, -1, model.ArtifactRecord{}); err == nil {
		t.Fatal("artifact with a negative generation accepted")
	}
	if _, _, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, 0, model.ArtifactRecord{}); err == nil {
		t.Fatal("artifact without an id accepted")
	}
	if _, _, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, 0, model.ArtifactRecord{ID: pgITNewID(t)}); err == nil {
		t.Fatal("artifact without a run accepted")
	}

	rep := model.TestReport{ID: pgITNewID(t), RunID: pgITNewID(t)}
	delivery := TestReportDelivery{JobID: jobID, LeaseGeneration: 0, DeliveryID: "d", ContentDigest: "c"}
	if _, err := st.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runnerID, -1, rep, "repo", delivery); err == nil {
		t.Fatal("report with a negative generation accepted")
	}
	if _, err := st.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runnerID, 0, model.TestReport{RunID: pgITNewID(t)}, "repo", delivery); err == nil {
		t.Fatal("report without an id accepted")
	}
	if _, err := st.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runnerID, 0, model.TestReport{ID: pgITNewID(t)}, "repo", delivery); err == nil {
		t.Fatal("report without a run accepted")
	}
	mismatch := delivery
	mismatch.JobID = pgITNewID(t)
	if _, err := st.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runnerID, 0, rep, "repo", mismatch); err == nil {
		t.Fatal("delivery identity for another job accepted")
	}
	mismatch = delivery
	mismatch.LeaseGeneration = 7
	if _, err := st.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runnerID, 0, rep, "repo", mismatch); err == nil {
		t.Fatal("delivery identity for another generation accepted")
	}
}

func TestPostgresCommitEntryValidationBranches(t *testing.T) {
	ctx := context.Background()
	st := &PostgresStore{}

	if _, _, err := st.CommitExecutionAttestation(ctx, model.ExecutionAttestationRecord{}, model.ExecutionEvent{}); err == nil {
		t.Fatal("attestation without a job id accepted")
	}
	if _, _, err := st.CommitSecretIssuance(ctx, SecretIssuance{}); !errors.Is(err, ErrSecretIssuanceInvalid) {
		t.Fatalf("empty secret issuance = %v, want ErrSecretIssuanceInvalid", err)
	}
	if _, err := st.DisableRunnerAndRevokeCert(ctx, "bad", "serial", "actor"); err == nil {
		t.Fatal("disable with a malformed runner id accepted")
	}
	if _, err := st.RevokeRunnerLeases(ctx, "bad", "reason"); err == nil {
		t.Fatal("revoke with a malformed runner id accepted")
	}
	if err := st.RecoverExpiredLease(ctx, "bad", 0, time.Time{}); err == nil {
		t.Fatal("recover with a malformed job id accepted")
	}
	if err := st.ExpireQueuedJob(ctx, "bad", time.Time{}); err == nil {
		t.Fatal("expire with a malformed job id accepted")
	}
}
