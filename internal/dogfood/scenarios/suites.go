package scenarios

import "strings"

// Suite is one dogfood suite: a named, tier-tagged set of registry scenarios.
// Membership is derived from the registry's mandatory flags where a gate flag
// already defines the set (fast=PR, local=main, release) and is an explicit
// list where the suite is a topology/workload cut that no single flag captures
// (distributed, adversarial, upgrade, scale).
type Suite struct {
	Name string
	Tier string
	// ScenarioIDs is the suite's closed membership. Every ID must exist in
	// Registry; TestSuiteMembershipMatchesRegistry enforces that.
	ScenarioIDs []ScenarioID
}

// Suite names match the Makefile dogfood-* entry points (dogfood-fast,
// dogfood-local, …). Keep them in sync.
const (
	SuiteFast        = "fast"
	SuiteLocal       = "local"
	SuiteDistributed = "distributed"
	SuiteAdversarial = "adversarial"
	SuiteUpgrade     = "upgrade"
	SuiteScale       = "scale"
	SuiteRelease     = "release"
)

// idsWhere returns registry IDs whose entry satisfies pred, in registry order.
func idsWhere(pred func(Entry) bool) []ScenarioID {
	out := make([]ScenarioID, 0, len(Registry))
	for _, e := range Registry {
		if pred(e) {
			out = append(out, e.ID)
		}
	}
	return out
}

// Suites is the machine-readable dogfood suite catalog. fast/local/release
// mirror the registry's mandatory flags; the other suites are the explicit
// topology cuts the Makefile runs under dogfood-distributed/adversarial/
// upgrade/scale.
var Suites = []Suite{
	{
		Name: SuiteFast,
		Tier: "DF0/DF1",
		ScenarioIDs: idsWhere(func(e Entry) bool {
			return e.MandatoryForPR
		}),
	},
	{
		Name: SuiteLocal,
		Tier: "DF1",
		ScenarioIDs: idsWhere(func(e Entry) bool {
			return e.MandatoryForMain
		}),
	},
	{
		Name: SuiteDistributed,
		Tier: "DF2",
		// Multi-party model proofs the distributed suite owns today
		// (Makefile dogfood-distributed --require set, scenario half).
		ScenarioIDs: []ScenarioID{
			ScenarioBootCleanLocal,
			ScenarioLeaseStaleRunner,
			ScenarioLeaseCompletionExpiry,
			ScenarioEvidenceGenerationVerify,
			ScenarioEvidenceObservedMismatch,
			ScenarioEvidenceQuotaTruth,
			ScenarioQuotaUntrustedGate,
			ScenarioEffectWinnerOnce,
			ScenarioEffectLoserZero,
		},
	},
	{
		Name: SuiteAdversarial,
		Tier: "DF3",
		// Nightly chaos/compat: races, tamper/mismatch, gate, loser-zero.
		ScenarioIDs: idsWhere(func(e Entry) bool {
			return e.MandatoryForNightly
		}),
	},
	{
		Name: SuiteUpgrade,
		Tier: "DF4",
		ScenarioIDs: []ScenarioID{
			ScenarioUpgradeEvidenceCompat,
		},
	},
	{
		Name: SuiteScale,
		Tier: "DF6",
		ScenarioIDs: []ScenarioID{
			ScenarioScaleFixedWorkload,
		},
	},
	{
		Name: SuiteRelease,
		Tier: "DF7",
		ScenarioIDs: idsWhere(func(e Entry) bool {
			return e.MandatoryForRelease
		}),
	},
}

// RequiredTestPrefixes maps a suite's scenario IDs to the TestDF… name
// prefixes dogfood-run.sh --require uses (DF-BOOT-001 → TestDFBOOT001).
// Returns nil for an unknown suite name.
func RequiredTestPrefixes(suite string) []string {
	for _, s := range Suites {
		if s.Name != suite {
			continue
		}
		prefixes := make([]string, 0, len(s.ScenarioIDs))
		for _, id := range s.ScenarioIDs {
			prefixes = append(prefixes, ScenarioTestPrefix(id))
		}
		return prefixes
	}
	return nil
}

// ScenarioTestPrefix is the stable test-name prefix for one scenario ID.
func ScenarioTestPrefix(id ScenarioID) string {
	return "Test" + strings.ReplaceAll(string(id), "-", "")
}
