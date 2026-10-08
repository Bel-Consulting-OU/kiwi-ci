package storage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func memObservedRuntime() *model.ObservedRuntime {
	return &model.ObservedRuntime{
		OS:                  "linux",
		Arch:                "amd64",
		RuntimeName:         "docker",
		RuntimeVersion:      "27.1.2",
		MainImage:           "alpine:3.19",
		MainImageDigest:     "sha256:" + strings.Repeat("a", 64),
		ServiceImages:       map[string]string{"db": "postgres:16"},
		ServiceImageDigests: map[string]string{"db": "sha256:" + strings.Repeat("b", 64)},
		CapturedAt:          time.Unix(1700000000, 0).UTC(),
	}
}

func TestMemStoreCompleteJobPersistsObservedRuntime(t *testing.T) {
	m := newMemStore()
	resourceProfileRunner(t, m, leaseRunner, leaseProf, leaseCert, 8, model.ResourceCapacity{})
	resourceJob(t, m, leaseRunID, leaseJobID, model.ResourceCapacity{})
	if _, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJobID, leaseRunner, model.ResourceCapacity{})); err != nil {
		t.Fatalf("lease: %v", err)
	}
	obs := memObservedRuntime()
	receipt := model.CompletionReceipt{JobID: leaseJobID, Generation: 1, RunnerID: leaseRunner, ResultHash: "h"}
	if err := m.CompleteJob(ctx(), leaseJobID, 1, leaseRunner, model.StatusSuccess, "", nil, receipt, obs); err != nil {
		t.Fatalf("complete: %v", err)
	}
	j, err := m.GetJob(ctx(), leaseJobID)
	if err != nil {
		t.Fatal(err)
	}
	if j.ObservedRuntime == nil {
		t.Fatal("completed job lost the observed runtime")
	}
	if j.ObservedRuntime.RuntimeName != "docker" || j.ObservedRuntime.MainImageDigest != obs.MainImageDigest ||
		j.ObservedRuntime.ServiceImageDigests["db"] != obs.ServiceImageDigests["db"] {
		t.Fatalf("observed runtime = %+v, want %+v", j.ObservedRuntime, obs)
	}
	// An idempotent replay must not rewrite the persisted evidence.
	if err := m.CompleteJob(ctx(), leaseJobID, 1, leaseRunner, model.StatusSuccess, "", nil, receipt, &model.ObservedRuntime{RuntimeName: "tampered"}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	j, _ = m.GetJob(ctx(), leaseJobID)
	if j.ObservedRuntime == nil || j.ObservedRuntime.RuntimeName != "docker" {
		t.Fatalf("replay rewrote the evidence: %+v", j.ObservedRuntime)
	}
}

func TestMemStoreCompletionEffectsPayloadCarriesGeneration(t *testing.T) {
	m := newMemStore()
	resourceProfileRunner(t, m, leaseRunner, leaseProf, leaseCert, 8, model.ResourceCapacity{})
	resourceJob(t, m, leaseRunID, leaseJobID, model.ResourceCapacity{})
	if _, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJobID, leaseRunner, model.ResourceCapacity{})); err != nil {
		t.Fatalf("lease: %v", err)
	}
	receipt := model.CompletionReceipt{JobID: leaseJobID, Generation: 1, RunnerID: leaseRunner, ResultHash: "h"}
	if err := m.CompleteJob(ctx(), leaseJobID, 1, leaseRunner, model.StatusSuccess, "", nil, receipt, nil); err != nil {
		t.Fatalf("complete: %v", err)
	}
	found := 0
	m.mu.Lock()
	for _, item := range m.outbox {
		if item.Kind != OutboxKindCompletionReconcile {
			continue
		}
		var payload CompletionEffectsPayload
		if err := json.Unmarshal(item.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.JobID != leaseJobID || payload.RunID != leaseRunID || payload.Generation != 1 {
			t.Fatalf("effect payload = %+v", payload)
		}
		found++
	}
	m.mu.Unlock()
	if found != 1 {
		t.Fatalf("completion_reconcile rows = %d, want 1", found)
	}
}

func TestMemStoreRecordUsageOncePersistsGeneration(t *testing.T) {
	m := newMemStore()
	resourceProfileRunner(t, m, leaseRunner, leaseProf, leaseCert, 8, model.ResourceCapacity{})
	resourceJob(t, m, leaseRunID, leaseJobID, model.ResourceCapacity{})
	if _, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJobID, leaseRunner, model.ResourceCapacity{})); err != nil {
		t.Fatalf("lease: %v", err)
	}
	receipt := model.CompletionReceipt{JobID: leaseJobID, Generation: 1, RunnerID: leaseRunner, ResultHash: "h"}
	if err := m.CompleteJob(ctx(), leaseJobID, 1, leaseRunner, model.StatusSuccess, "", nil, receipt, nil); err != nil {
		t.Fatalf("complete: %v", err)
	}
	won, err := m.RecordUsageOnce(ctx(), leaseJobID, 1, 1.5, 2.5)
	if err != nil || !won {
		t.Fatalf("RecordUsageOnce = %v/%v, want win", won, err)
	}
	j, _ := m.GetJob(ctx(), leaseJobID)
	if !j.UsageRecorded || j.UsageLeaseGeneration != 1 || j.Cost != 1.5 || j.EnergyWh != 2.5 {
		t.Fatalf("usage record = %+v", j)
	}
	won, err = m.RecordUsageOnce(ctx(), leaseJobID, 9, 9, 9)
	if err != nil || won {
		t.Fatalf("second RecordUsageOnce = %v/%v, want loss", won, err)
	}
	j, _ = m.GetJob(ctx(), leaseJobID)
	if j.UsageLeaseGeneration != 1 || j.Cost != 1.5 {
		t.Fatalf("lost race rewrote usage: %+v", j)
	}
}

func TestMemStoreLeaseReportStampsGeneration(t *testing.T) {
	m := newMemStore()
	resourceProfileRunner(t, m, leaseRunner, leaseProf, leaseCert, 8, model.ResourceCapacity{})
	resourceJob(t, m, leaseRunID, leaseJobID, model.ResourceCapacity{})
	claim := resourceClaim(leaseJobID, leaseRunner, model.ResourceCapacity{})
	claim.ExpiresAt = time.Now().UTC().Add(time.Hour)
	if _, err := m.AcquireLeaseAtomic(ctx(), claim); err != nil {
		t.Fatalf("lease: %v", err)
	}
	j, err := m.GetJob(ctx(), leaseJobID)
	if err != nil {
		t.Fatal(err)
	}
	repo := RepoIDForJob(j)
	rep := model.TestReport{ID: strings.Repeat("ab", 16), RunID: j.RunID, JobID: j.ID, JobKey: j.Key, CreatedAt: time.Now().UTC()}
	delivery := TestReportDelivery{JobID: j.ID, LeaseGeneration: 1, DeliveryID: "delivery-observed", ContentDigest: "digest"}
	if _, err := m.InsertTestReportWithHistoryDeliveryForLease(ctx(), j.ID, leaseRunner, 1, rep, repo, delivery); err != nil {
		t.Fatalf("report delivery: %v", err)
	}
	reports, err := m.ListTestReports(ctx(), j.RunID)
	if err != nil || len(reports) != 1 {
		t.Fatalf("reports = %+v err=%v", reports, err)
	}
	if reports[0].LeaseGeneration != 1 {
		t.Fatalf("report generation = %d, want the verified lease generation", reports[0].LeaseGeneration)
	}
}
