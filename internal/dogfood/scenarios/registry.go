package scenarios

// ScenarioID is a stable dogfood scenario identifier.
type ScenarioID string

// The closed dogfood scenario registry. IDs are permanent; a requirement
// that loses its scenario loses its proof, so removal is a deliberate act
// recorded in docs, never a side effect of a refactor.
const (
	// ScenarioBootCleanLocal is DF-BOOT-001: clean local bootstrap and
	// restart. Positive arm: launch, seed, run to green, stop, relaunch
	// from the same seed and prove the eight oracles still agree. Negative
	// arm: a second launch must not collide with the first namespace.
	ScenarioBootCleanLocal ScenarioID = "DF-BOOT-001"

	// ScenarioEvidenceGenerationVerify is DF-EVID-001: generate a signed
	// execution attestation and verify it (signature + self-binding).
	ScenarioEvidenceGenerationVerify ScenarioID = "DF-EVID-001"
	// ScenarioEvidenceTamperMatrix is DF-EVID-002: flip each signed field
	// (commit/capsule, runner, job, attempt, artifact digest, policy
	// digest, graph fingerprint, execution semantics, assurance facts,
	// external effects, event frontier) — each must fail verification.
	ScenarioEvidenceTamperMatrix ScenarioID = "DF-EVID-002"
	// ScenarioEvidenceObservedMismatch is DF-EVID-003: a contradictory
	// effective/observed receipt must fail signing AND verification.
	ScenarioEvidenceObservedMismatch ScenarioID = "DF-EVID-003"
	// ScenarioEvidenceQuotaTruth is DF-EVID-004: workspace_quota_enforced
	// is only ever true from observed hard-quota.
	ScenarioEvidenceQuotaTruth ScenarioID = "DF-EVID-004"
	// ScenarioEvidenceSecretAbsence is DF-EVID-005: serialized evidence
	// contains no secret material.
	ScenarioEvidenceSecretAbsence ScenarioID = "DF-EVID-005"

	// ScenarioLeaseStaleRunner is DF-LEASE-001: a stale runner's completion
	// after reassignment is rejected AND the current runner still completes
	// (safety AND liveness).
	ScenarioLeaseStaleRunner ScenarioID = "DF-LEASE-001"
	// ScenarioLeaseCompletionExpiry is DF-LEASE-002: completion vs lease
	// expiry — a completion after expiry is rejected, one under a live
	// lease is accepted.
	ScenarioLeaseCompletionExpiry ScenarioID = "DF-LEASE-002"

	// ScenarioQuotaUntrustedGate is DF-QUOTA-001: an untrusted job that
	// requires a hard workspace quota is REJECTED when no hard quota is
	// available (table-driven unit of the gate).
	ScenarioQuotaUntrustedGate ScenarioID = "DF-QUOTA-001"
)

// Entry is one registry row: the stable identity, what each arm proves, and
// whether the scenario is allowed to retry (only retry-under-test arms may).
type Entry struct {
	ID             ScenarioID
	Name           string
	PositiveArm    string
	NegativeArm    string
	RetryUnderTest bool
}

// Registry is the closed dogfood scenario catalog.
var Registry = []Entry{
	{
		ID:          ScenarioBootCleanLocal,
		Name:        "clean local bootstrap and restart",
		PositiveArm: "launch → seed → complete → stop → relaunch; eight oracles agree across the restart",
		NegativeArm: "a second invocation's namespace must not collide with the first",
	},
	{
		ID:          ScenarioEvidenceGenerationVerify,
		Name:        "attestation generation and verification",
		PositiveArm: "signed attestation verifies (signature + self-binding + facts derivation)",
		NegativeArm: "an unsigned or self-contradictory envelope is refused",
	},
	{
		ID:          ScenarioEvidenceTamperMatrix,
		Name:        "attestation tamper matrix",
		PositiveArm: "untampered evidence verifies",
		NegativeArm: "every single-field flip fails VerifyExecutionAttestation",
	},
	{
		ID:          ScenarioEvidenceObservedMismatch,
		Name:        "effective/observed consistency",
		PositiveArm: "a consistent receipt signs and verifies",
		NegativeArm: "effective network=none + observed container-namespace fails signing AND verification",
	},
	{
		ID:          ScenarioEvidenceQuotaTruth,
		Name:        "workspace quota truthfulness",
		PositiveArm: "hard-quota success is the only path to workspace_quota_enforced=true",
		NegativeArm: "fallback accounting, setup failure and no-request all record false; untrusted+require+unavailable rejects",
	},
	{
		ID:          ScenarioEvidenceSecretAbsence,
		Name:        "secret absence scan",
		PositiveArm: "evidence serializes without any seeded secret material",
		NegativeArm: "a planted secret in the evidence surface is detected",
	},
	{
		ID:          ScenarioLeaseStaleRunner,
		Name:        "stale runner after reassignment",
		PositiveArm: "current holder completes and evidence verifies after the stale attempt",
		NegativeArm: "stale generation / reassigned holder completions are rejected",
	},
	{
		ID:          ScenarioLeaseCompletionExpiry,
		Name:        "completion vs lease expiry",
		PositiveArm: "completion under a live lease is accepted",
		NegativeArm: "completion after expiry (and across the reclaim window) is rejected",
	},
	{
		ID:          ScenarioQuotaUntrustedGate,
		Name:        "untrusted hard-quota admission gate",
		PositiveArm: "hard quota available → untrusted container job admitted",
		NegativeArm: "hard quota required and unavailable → execution rejected before checkout",
	},
}

// Lookup returns the registry entry for id.
func Lookup(id ScenarioID) (Entry, bool) {
	for _, e := range Registry {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}
