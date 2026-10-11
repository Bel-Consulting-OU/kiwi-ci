package dogfood

import (
	"fmt"
	"strings"
)

// Surface is one of the eight independent observation surfaces the outer
// oracle cross-checks. The set is closed: a Check that is missing a surface
// cannot be green, because "agreeing among the surfaces that happened to
// report" is exactly the self-grading the eight-oracle rule forbids.
type Surface string

const (
	// SurfaceClientResult is what the public API returned to the caller.
	SurfaceClientResult Surface = "client_result"
	// SurfaceAuthoritativeState is the durable control-plane record.
	SurfaceAuthoritativeState Surface = "authoritative_state"
	// SurfaceLedger is the crash-recovery / event ledger.
	SurfaceLedger Surface = "ledger"
	// SurfaceRunnerAuthority is the lease holder's own report of the attempt.
	SurfaceRunnerAuthority Surface = "runner_authority"
	// SurfaceArtifacts is the collected artifact bytes and identities.
	SurfaceArtifacts Surface = "artifacts"
	// SurfaceEvidence is the signed attestation envelope.
	SurfaceEvidence Surface = "evidence"
	// SurfaceExternalEffects is the out-of-band effect sink (deployment,
	// OIDC) — the only authority on "an effect happened".
	SurfaceExternalEffects Surface = "external_effects"
	// SurfaceRecovery is what a restart/reclaim reconciled.
	SurfaceRecovery Surface = "recovery"
)

// AllSurfaces is the closed eight-oracle set, in canonical report order.
var AllSurfaces = []Surface{
	SurfaceClientResult,
	SurfaceAuthoritativeState,
	SurfaceLedger,
	SurfaceRunnerAuthority,
	SurfaceArtifacts,
	SurfaceEvidence,
	SurfaceExternalEffects,
	SurfaceRecovery,
}

// Observation is one surface's independent account of a scenario outcome.
// Terminal is the outcome the surface observed ("success", "failure",
// "rejected", ...). EffectCount is the number of external effects that
// surface attributes to the attempt; only SurfaceExternalEffects is an
// authority on that number, every other surface reports what it saw so a
// disagreement is detectable.
type Observation struct {
	Surface     Surface `json:"surface"`
	Terminal    string  `json:"terminal"`
	EffectCount int     `json:"effect_count"`
	Detail      string  `json:"detail,omitempty"`
}

// SurfaceCheck is the oracle's verdict for one surface.
type SurfaceCheck struct {
	Surface Surface `json:"surface"`
	OK      bool    `json:"ok"`
	Detail  string  `json:"detail,omitempty"`
}

// OracleResult is the eight-oracle verdict of one scenario arm. Green is
// true only when all eight surfaces reported and every surface agrees with
// the others on terminal outcome and effect count.
type OracleResult struct {
	Checks []SurfaceCheck `json:"checks"`
	Green  bool           `json:"green"`
}

// Oracle is the outer oracle: it never inspects system-under-test internals
// and never mutates anything. It only compares independent observations.
type Oracle struct{}

// NewOracle returns the outer oracle.
func NewOracle() Oracle { return Oracle{} }

// Check cross-checks one account per surface. It fails closed on:
//   - a missing surface (no self-grading over a partial panel),
//   - an unknown surface (a typo must not pass as a ninth oracle),
//   - a duplicate surface (one surface must not vote twice),
//   - any disagreement on Terminal or EffectCount between surfaces.
//
// SurfaceExternalEffects is the AUTHORITY for EffectCount: when it disagrees
// with another surface the other surface is wrong, but the panel still fails
// — a system whose own artifact count disagrees with its effect sink is not
// green, the oracle merely names the sink as the correct number.
func (Oracle) Check(observations []Observation) OracleResult {
	bySurface := make(map[Surface]Observation, len(observations))
	res := OracleResult{Green: true}
	fail := func(format string, args ...any) {
		res.Green = false
		res.Checks = append(res.Checks, SurfaceCheck{Surface: "", OK: false, Detail: fmt.Sprintf(format, args...)})
	}
	for _, obs := range observations {
		if !knownSurface(obs.Surface) {
			fail("unknown surface %q", obs.Surface)
			continue
		}
		if _, dup := bySurface[obs.Surface]; dup {
			fail("surface %q reported twice", obs.Surface)
			continue
		}
		bySurface[obs.Surface] = obs
	}
	for _, s := range AllSurfaces {
		obs, ok := bySurface[s]
		if !ok {
			res.Green = false
			res.Checks = append(res.Checks, SurfaceCheck{Surface: s, OK: false, Detail: "surface did not report"})
			continue
		}
		res.Checks = append(res.Checks, SurfaceCheck{Surface: s, OK: true, Detail: obs.Detail})
	}
	if !res.Green {
		return res
	}
	// All eight present and unique: now require agreement. The terminal
	// outcome must be unanimous; the effect count must match the authority
	// (SurfaceExternalEffects). Disagreement marks every disagreeing
	// surface not-OK and fails the panel.
	authority := bySurface[SurfaceExternalEffects]
	ref := bySurface[SurfaceClientResult]
	for i := range res.Checks {
		s := res.Checks[i].Surface
		obs := bySurface[s]
		why := ""
		if obs.Terminal != ref.Terminal {
			why = fmt.Sprintf("terminal %q disagrees with %s %q", obs.Terminal, SurfaceClientResult, ref.Terminal)
		} else if obs.EffectCount != authority.EffectCount {
			why = fmt.Sprintf("effect count %d disagrees with %s %d", obs.EffectCount, SurfaceExternalEffects, authority.EffectCount)
		}
		if why != "" {
			res.Checks[i].OK = false
			res.Checks[i].Detail = why
			res.Green = false
		}
	}
	return res
}

func knownSurface(s Surface) bool {
	for _, k := range AllSurfaces {
		if k == s {
			return true
		}
	}
	return false
}

// Summary renders a one-line verdict for scenario logs and result files.
func (r OracleResult) Summary() string {
	if r.Green {
		return "eight-oracle green (surfaces agree)"
	}
	var bad []string
	for _, c := range r.Checks {
		if !c.OK {
			bad = append(bad, string(c.Surface)+": "+c.Detail)
		}
	}
	return "eight-oracle red: " + strings.Join(bad, "; ")
}
