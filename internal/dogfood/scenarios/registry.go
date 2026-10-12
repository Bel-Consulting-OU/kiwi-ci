package scenarios

import (
	"regexp"
	"sort"
	"strings"
)

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

	// ScenarioEffectWinnerOnce is DF-EFFECT-001: the authorized winner's
	// external effect lands exactly once (fake sink ledger is the authority).
	ScenarioEffectWinnerOnce ScenarioID = "DF-EFFECT-001"
	// ScenarioEffectLoserZero is DF-EFFECT-002: speculative losers and
	// stale-generation holders produce zero external effects.
	ScenarioEffectLoserZero ScenarioID = "DF-EFFECT-002"

	// ScenarioSelfGenLimit is DF-SELF-001: the harness records G0/G1/G2 and
	// refuses unintended recursion past the explicit generation limit.
	ScenarioSelfGenLimit ScenarioID = "DF-SELF-001"

	// ScenarioUpgradeEvidenceCompat is DF-UPGRADE-001: evidence from an
	// older schema still verifies; contradictory facts are refused on every
	// schema.
	ScenarioUpgradeEvidenceCompat ScenarioID = "DF-UPGRADE-001"

	// ScenarioScaleFixedWorkload is DF-SCALE-001: a fixed high-volume
	// lifecycle with attempt accounting and no hidden retries.
	ScenarioScaleFixedWorkload ScenarioID = "DF-SCALE-001"

	// ScenarioArtifactFinalizationCrash is DF-ART-001: crash through the
	// artifact finalization boundaries. Positive arm: a fully finalized
	// artifact is durable and verifies against its manifest. Negative arms:
	// a crash after rename but before the manifest never yields an
	// acknowledged artifact; a crash before rename publishes nothing; a
	// canceled capture publishes nothing.
	ScenarioArtifactFinalizationCrash ScenarioID = "DF-ART-001"

	// ScenarioCacheUntrustedPoison is DF-CACHE-001: an untrusted producer
	// cannot poison the trusted cache. Positive arm: a trusted restore of a
	// key it published is a hit. Negative arms: an untrusted write never
	// lands in the trusted namespace of the same logical key, and rewriting
	// the signed manifest's trust domain invalidates its signature.
	ScenarioCacheUntrustedPoison ScenarioID = "DF-CACHE-001"
)

// Entry is one registry row: the stable identity, what each arm proves, and
// whether the scenario is allowed to retry (only retry-under-test arms may).
//
// This registry is the MACHINE-READABLE source of truth for dogfood coverage.
// Suite membership (suites.go), the Makefile dogfood-* --require lists,
// DOGFOOD_MATRIX.md and CI wiring must agree with it;
// TestEveryRegistryScenarioHasATest, TestSuiteMembershipMatchesRegistry,
// TestDogfoodMatrixMatchesRegistry and TestMakefileRequiresOnlyExistingTests
// keep that agreement executable.
//
// The MandatoryFor* flags mirror the executable Makefile gates
// (dogfood-fast / dogfood-local / dogfood-adversarial / dogfood-release
// --require sets). Requires* stay false for every model-species row until a
// SystemHarness can drive real Docker/Postgres/object-store/forge processes.
type Entry struct {
	ID             ScenarioID
	Name           string
	Tier           string // DF0..DF7
	Implemented    bool   // true when a Test* in this package exercises it
	MandatoryForPR bool
	// MandatoryForMain is the main-branch / DF1 local product lifecycle gate
	// (Makefile dogfood-local).
	MandatoryForMain bool
	// MandatoryForNightly is the nightly DF3 chaos gate
	// (Makefile dogfood-adversarial). DF4 compatibility runs under the
	// upgrade suite, which nightly schedules separately.
	MandatoryForNightly bool
	// MandatoryForRelease is the release-candidate gate
	// (Makefile dogfood-release).
	MandatoryForRelease bool
	// InvariantIDs names the docs/INVARIANTS.md invariants (I1..I10) this
	// scenario is a system-dogfood proof for. Empty when the scenario
	// proves an assurance fact or harness property outside those numbers.
	InvariantIDs []string
	// CapabilityIDs names the public-surface capabilities
	// (docs/DOGFOOD_MATRIX.md "Public-surface → scenario mapping") this
	// scenario dogfoods.
	CapabilityIDs []string
	// RequiresDocker is true when the scenario needs a real container
	// runtime. False for every model-species row until a SystemHarness
	// exists.
	RequiresDocker bool
	// RequiresPostgres is true when the scenario needs the canonical
	// PostgreSQL store. False for every model-species row until a
	// SystemHarness exists.
	RequiresPostgres bool
	// RequiresObjectStore is true when the scenario needs a real object
	// store. False for every model-species row until a SystemHarness
	// exists.
	RequiresObjectStore bool
	// RequiresRealForge is true when the scenario needs a live forge
	// (webhooks, PR events). False for every model-species row until a
	// SystemHarness exists.
	RequiresRealForge bool
	PositiveArm       string
	NegativeArm       string
	RetryUnderTest    bool
	// Species is "model" (in-memory harness/oracle), "component" (real
	// packages in-process) or "system" (real NewPersistent + HTTP + runner via internal/dogfood/system).
	// Do not treat model proofs as product dogfood — see docs/DOGFOOD.md.
	//
	// DF-BOOT-001, DF-EVID-001, DF-LEASE-001 and DF-QUOTA-001 ALSO have
	// SYSTEM-species proofs in internal/dogfood/system (TestSysDFBoot001,
	// TestSysDFEvid001, TestSysDFLease001, TestSysQuotaGate). Species stays
	// "model" here until a deliberate registry flip; the system suite is
	// name-required by `make dogfood-system`.
	Species string
}

// Registry is the closed dogfood scenario catalog.
var Registry = []Entry{
	{
		ID:                  ScenarioBootCleanLocal,
		Tier:                "DF1",
		Implemented:         true,
		MandatoryForPR:      true,
		MandatoryForMain:    true,
		MandatoryForNightly: false,
		MandatoryForRelease: true,
		Species:             "model",
		Name:                "clean local bootstrap and restart",
		PositiveArm:         "launch → seed → complete → stop → relaunch; eight oracles agree across the restart",
		NegativeArm:         "a second invocation's namespace must not collide with the first",
		InvariantIDs:        []string{"I1", "I2"},
		CapabilityIDs:       []string{"run.create"},
	},
	{
		ID:                  ScenarioEvidenceGenerationVerify,
		Tier:                "DF1",
		Implemented:         true,
		MandatoryForPR:      true,
		MandatoryForMain:    true,
		MandatoryForNightly: false,
		MandatoryForRelease: true,
		Species:             "model",
		Name:                "attestation generation and verification",
		PositiveArm:         "signed attestation verifies (signature + self-binding + facts derivation)",
		NegativeArm:         "an unsigned or self-contradictory envelope is refused",
		CapabilityIDs:       []string{"evidence.verify", "evidence.fetch"},
	},
	{
		ID:                  ScenarioEvidenceTamperMatrix,
		Tier:                "DF1",
		Implemented:         true,
		MandatoryForPR:      true,
		MandatoryForMain:    true,
		MandatoryForNightly: true,
		MandatoryForRelease: true,
		Species:             "model",
		Name:                "attestation tamper matrix",
		PositiveArm:         "untampered evidence verifies",
		NegativeArm:         "every single-field flip fails VerifyExecutionAttestation",
		CapabilityIDs:       []string{"evidence.verify"},
	},
	{
		ID:                  ScenarioEvidenceObservedMismatch,
		Tier:                "DF1",
		Implemented:         true,
		MandatoryForPR:      true,
		MandatoryForMain:    true,
		MandatoryForNightly: true,
		MandatoryForRelease: true,
		Species:             "model",
		Name:                "effective/observed consistency",
		PositiveArm:         "a consistent receipt signs and verifies",
		NegativeArm:         "effective network=none + observed container-namespace fails signing AND verification",
		CapabilityIDs:       []string{"evidence.verify", "jobs.complete"},
	},
	{
		ID:                  ScenarioEvidenceQuotaTruth,
		Tier:                "DF1",
		Implemented:         true,
		MandatoryForPR:      true,
		MandatoryForMain:    true,
		MandatoryForNightly: true,
		MandatoryForRelease: true,
		Species:             "model",
		Name:                "workspace quota truthfulness",
		PositiveArm:         "hard-quota success is the only path to workspace_quota_enforced=true",
		NegativeArm:         "fallback accounting, setup failure and no-request all record false; untrusted+require+unavailable rejects",
		CapabilityIDs:       []string{"evidence.verify"},
	},
	{
		ID:                  ScenarioEvidenceSecretAbsence,
		Tier:                "DF1",
		Implemented:         true,
		MandatoryForPR:      true,
		MandatoryForMain:    true,
		MandatoryForNightly: false,
		MandatoryForRelease: true,
		Species:             "model",
		Name:                "secret absence scan",
		PositiveArm:         "evidence serializes without any seeded secret material",
		NegativeArm:         "a planted secret in the evidence surface is detected",
		InvariantIDs:        []string{"I9"},
		CapabilityIDs:       []string{"evidence.verify"},
	},
	{
		ID:                  ScenarioLeaseStaleRunner,
		Tier:                "DF1",
		Implemented:         true,
		MandatoryForPR:      true,
		MandatoryForMain:    true,
		MandatoryForNightly: true,
		MandatoryForRelease: false,
		Species:             "model",
		Name:                "stale runner after reassignment",
		PositiveArm:         "current holder completes and evidence verifies after the stale attempt",
		NegativeArm:         "stale generation / reassigned holder completions are rejected",
		InvariantIDs:        []string{"I3"},
		CapabilityIDs:       []string{"jobs.claim"},
	},
	{
		ID:                  ScenarioLeaseCompletionExpiry,
		Tier:                "DF1",
		Implemented:         true,
		MandatoryForPR:      true,
		MandatoryForMain:    true,
		MandatoryForNightly: true,
		MandatoryForRelease: false,
		Species:             "model",
		Name:                "completion vs lease expiry",
		PositiveArm:         "completion under a live lease is accepted",
		NegativeArm:         "completion after expiry (and across the reclaim window) is rejected",
		InvariantIDs:        []string{"I1"},
		CapabilityIDs:       []string{"jobs.complete"},
	},
	{
		ID:                  ScenarioQuotaUntrustedGate,
		Tier:                "DF1",
		Implemented:         true,
		MandatoryForPR:      true,
		MandatoryForMain:    true,
		MandatoryForNightly: true,
		MandatoryForRelease: true,
		Species:             "model",
		Name:                "untrusted hard-quota admission gate",
		PositiveArm:         "hard quota available → untrusted container job admitted",
		NegativeArm:         "hard quota required and unavailable → execution rejected before checkout",
		CapabilityIDs:       []string{"run.create"},
	},

	{
		ID:                  ScenarioEffectWinnerOnce,
		Tier:                "DF1",
		Implemented:         true,
		MandatoryForPR:      false,
		MandatoryForMain:    true,
		MandatoryForNightly: false,
		MandatoryForRelease: true,
		Species:             "model",
		Name:                "authorized winner external effect exactly once",
		PositiveArm:         "winner's capability produces exactly one sink row",
		NegativeArm:         "a second effect without reauthorization is refused",
		CapabilityIDs:       []string{"deploy.authorize"},
	},
	{
		ID:                  ScenarioEffectLoserZero,
		Tier:                "DF1",
		Implemented:         true,
		MandatoryForPR:      false,
		MandatoryForMain:    true,
		MandatoryForNightly: true,
		MandatoryForRelease: true,
		Species:             "model",
		Name:                "loser and stale runner external effect zero",
		PositiveArm:         "sink ledger stays empty for losers/stale holders",
		NegativeArm:         "eight-oracle agreement on zero effects",
		InvariantIDs:        []string{"I9"},
		CapabilityIDs:       []string{"deploy.authorize"},
	},
	{
		ID:                  ScenarioSelfGenLimit,
		Tier:                "DF1",
		Implemented:         true,
		MandatoryForPR:      false,
		MandatoryForMain:    true,
		MandatoryForNightly: false,
		MandatoryForRelease: true,
		Species:             "model",
		Name:                "self-host generation limit",
		PositiveArm:         "G0, G1, G2 are recorded",
		NegativeArm:         "G3+ is refused",
		CapabilityIDs:       []string{"self-host.build"},
	},
	{
		ID:                  ScenarioUpgradeEvidenceCompat,
		Tier:                "DF4",
		Implemented:         true,
		MandatoryForPR:      false,
		MandatoryForMain:    false,
		MandatoryForNightly: false,
		MandatoryForRelease: false,
		Species:             "model",
		Name:                "cross-version evidence compatibility",
		PositiveArm:         "legacy schema evidence still verifies",
		NegativeArm:         "contradictory facts refused on every schema",
		CapabilityIDs:       []string{"evidence.verify"},
	},
	{
		ID:                  ScenarioScaleFixedWorkload,
		Tier:                "DF6",
		Implemented:         true,
		MandatoryForPR:      false,
		MandatoryForMain:    true,
		MandatoryForNightly: false,
		MandatoryForRelease: false,
		Species:             "model",
		Name:                "fixed high-volume lifecycle",
		PositiveArm:         "N attempts complete under one-attempt accounting",
		NegativeArm:         "hidden retries are non-green",
		CapabilityIDs:       []string{"run.create"},
	},
	{
		ID:                  ScenarioArtifactFinalizationCrash,
		Tier:                "DF3",
		Implemented:         true,
		MandatoryForPR:      false,
		MandatoryForMain:    false,
		MandatoryForNightly: true,
		MandatoryForRelease: true,
		Species:             "component",
		Name:                "crash through artifact finalization boundaries",
		PositiveArm:         "a finalized artifact is durable and verifies against its manifest",
		NegativeArm:         "crash after rename / before manifest, crash before rename, and canceled capture publish nothing acknowledged",
		CapabilityIDs:       []string{"artifact.publish"},
	},
	{
		ID:                  ScenarioCacheUntrustedPoison,
		Tier:                "DF3",
		Implemented:         true,
		MandatoryForPR:      false,
		MandatoryForMain:    false,
		MandatoryForNightly: true,
		MandatoryForRelease: true,
		Species:             "component",
		Name:                "untrusted-to-trusted cache poisoning attempt",
		PositiveArm:         "trusted restore of a key the trusted domain published is a hit",
		NegativeArm:         "untrusted write never lands in the trusted namespace; a rewritten trust domain invalidates the signed manifest",
		CapabilityIDs:       []string{"cache.restore", "cache.publish"},
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

// CheckMatrixImplementedIDs reports every drift between the "Implemented
// scenario IDs" list of docs/DOGFOOD_MATRIX.md and the registry's
// Implemented set. An empty result means the doc and the registry agree.
// Both TestDogfoodMatrixMatchesRegistry (this package) and the surfacecheck
// matrix gate call this one implementation so CI cannot pass while the two
// disagree.
func CheckMatrixImplementedIDs(doc string) []string {
	const heading = "## Implemented scenario IDs"
	start := strings.Index(doc, heading)
	if start < 0 {
		return []string{`DOGFOOD_MATRIX.md has no "Implemented scenario IDs" section`}
	}
	rest := doc[start+len(heading):]
	if end := strings.Index(rest, "\n## "); end >= 0 {
		rest = rest[:end]
	}
	idRe := regexp.MustCompile(`DF-[A-Z0-9]+-\d+`)
	docIDs := map[string]bool{}
	for _, m := range idRe.FindAllString(rest, -1) {
		docIDs[m] = true
	}
	if len(docIDs) == 0 {
		return []string{"Implemented scenario IDs section lists no IDs"}
	}

	regImplemented := map[string]bool{}
	for _, e := range Registry {
		if e.Implemented {
			regImplemented[string(e.ID)] = true
		}
	}

	var drift []string
	for id := range regImplemented {
		if !docIDs[id] {
			drift = append(drift, "Implemented registry ID "+id+" is missing from DOGFOOD_MATRIX.md implemented list")
		}
	}
	for id := range docIDs {
		if !regImplemented[id] {
			drift = append(drift, "DOGFOOD_MATRIX.md claims "+id+" is implemented, but the registry does not")
		}
	}
	sort.Strings(drift)
	return drift
}
