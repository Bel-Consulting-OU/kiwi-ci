package storage

// Architectural guard: the production PostgreSQL store must implement every
// storage capability whose ABSENCE would weaken correctness (not merely
// disable an optional feature). The per-file `var _ X = (*PostgresStore)(nil)`
// assertions remain the source of truth; this test makes the required set
// explicit in one place so a future store/backend cannot silently drop one at
// the type level (the runtime side, e.g. the server's SwitchToDB checks,
// covers wiring).

import "testing"

func implementsCapability[T any](v any) bool {
	_, ok := v.(T)
	return ok
}

func TestProductionDBStoreSatisfiesRequiredCapabilities(t *testing.T) {
	var st *PostgresStore
	required := []struct {
		name    string
		present bool
	}{
		{"Store", implementsCapability[Store](st)},
		{"RunEnqueueStore", implementsCapability[RunEnqueueStore](st)},
		{"AtomicLeaseStore", implementsCapability[AtomicLeaseStore](st)},
		{"LeaseClockStore", implementsCapability[LeaseClockStore](st)},
		{"LiveLeaseStore", implementsCapability[LiveLeaseStore](st)},
		{"ClockStore", implementsCapability[ClockStore](st)},
		{"LeaseCommitStore", implementsCapability[LeaseCommitStore](st)},
		{"LeaseTestReportStore", implementsCapability[LeaseTestReportStore](st)},
		{"RunnerHeartbeatStore", implementsCapability[RunnerHeartbeatStore](st)},
		{"RunnerProfileUpdateStore", implementsCapability[RunnerProfileUpdateStore](st)},
		{"RunnerDisableStore", implementsCapability[RunnerDisableStore](st)},
		{"DeploymentStore", implementsCapability[DeploymentStore](st)},
		{"SnapshotStore", implementsCapability[SnapshotStore](st)},
		{"SnapshotPageStore", implementsCapability[SnapshotPageStore](st)},
		{"CacheManifestStore", implementsCapability[CacheManifestStore](st)},
		{"CacheManifestPruner", implementsCapability[CacheManifestPruner](st)},
		{"TestHistoryAggregateStore", implementsCapability[TestHistoryAggregateStore](st)},
		{"TestReportDeliveryStore", implementsCapability[TestReportDeliveryStore](st)},
		{"TestHistoryRepoResolutionStore", implementsCapability[TestHistoryRepoResolutionStore](st)},
		{"DigestFenceStore", implementsCapability[DigestFenceStore](st)},
		{"CASReferenceStore", implementsCapability[CASReferenceStore](st)},
		{"CASGCLeaseStore", implementsCapability[CASGCLeaseStore](st)},
		{"QuotaCounterStore", implementsCapability[QuotaCounterStore](st)},
		{"JobApprovalStore", implementsCapability[JobApprovalStore](st)},
		{"ResourceReservationStore", implementsCapability[ResourceReservationStore](st)},
		{"ResourceReconcileStore", implementsCapability[ResourceReconcileStore](st)},
		{"RecoveryStore", implementsCapability[RecoveryStore](st)},
		{"CheckRunStore", implementsCapability[CheckRunStore](st)},
		{"LogBatchStore", implementsCapability[LogBatchStore](st)},
		{"MetricsAggregateStore", implementsCapability[MetricsAggregateStore](st)},
	}
	var missing []string
	for _, capability := range required {
		if !capability.present {
			missing = append(missing, capability.name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("PostgresStore is missing correctness-critical capabilities: %v", missing)
	}
}
