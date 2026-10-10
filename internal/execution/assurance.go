package execution

import (
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

// MaterializeFromJob derives the effective execution of one persisted job
// using only durable control-plane records: it parses the job's stored
// pipeline, verifies the persisted compilation payload binding when one
// exists, decodes and trust-floor-applies the effective policy, and then
// materializes through the same shared path the runner and exact replay use.
// ok=false means the records cannot be proven to describe an execution (an
// unparseable pipeline, a payload that does not bind, an over-ceiling network
// request); the caller must not fabricate execution evidence in that case.
//
// A job without a CompiledJobPayload is still materialized through the
// documented legacy path (the persisted job is authoritative), so assurance
// and effects classification remain derivable for legacy records.
func MaterializeFromJob(j model.Job) (EffectiveExecution, bool) {
	if strings.TrimSpace(j.Pipeline) == "" {
		return EffectiveExecution{}, false
	}
	spec, err := pipeline.Parse([]byte(j.Pipeline))
	if err != nil {
		return EffectiveExecution{}, false
	}
	var cj pipeline.CompiledJob
	p := j.CompiledJobPayload
	if p != nil {
		cj, err = pipeline.VerifyCompiledJobBinding(spec, j.Key, p)
		if err != nil {
			return EffectiveExecution{}, false
		}
	} else {
		g, cerr := pipeline.Compile(spec)
		if cerr != nil {
			return EffectiveExecution{}, false
		}
		job, ok := g.Jobs[j.Key]
		if !ok {
			return EffectiveExecution{}, false
		}
		cj = job
	}
	caps := policy.Capabilities{}
	if p != nil {
		c, policyOK, cerr := EffectivePolicyCapabilities(p, j.Trusted)
		if cerr != nil {
			return EffectiveExecution{}, false
		}
		if policyOK {
			caps = c
		}
	} else if !j.Trusted {
		// A legacy untrusted job carries no policy record. The untrusted hard
		// floor is an engine invariant every untrusted execution runs under
		// (the server's admission and the runner's verification both apply
		// it), so the explicit deny-all allowlist is provable without a
		// payload. A legacy TRUSTED job stays at the zero capability value:
		// the permissive trusted base has no provable restrictions.
		caps = policy.DefaultUntrustedCapabilities()
	}
	eff, err := MaterializeEffectiveExecution(cj, p, j, caps)
	if err != nil {
		return EffectiveExecution{}, false
	}
	return eff, true
}

// nativeRuntime reports whether the effective runtime executes directly on
// the runner host with host authority ("", "native"). The host filesystem,
// host credential files and host sockets are reachable from such a job, so it
// is never classified as isolated or credential-free.
func (e EffectiveExecution) nativeRuntime() bool {
	switch e.CompiledJob.Job.Runtime {
	case "", "native":
		return true
	default:
		return false
	}
}

// filesystemIsolated reports whether the level-1 control is enforced: a
// container/Tart runtime boundary, or a hard OS-level workspace quota
// installed before the workspace is populated.
func (e EffectiveExecution) filesystemIsolated() bool {
	switch e.CompiledJob.Job.Runtime {
	case "container", "tart":
		return true
	}
	return e.WorkspaceQuotaLimit > 0
}

// noAmbientCredentials reports whether the level-2 control is enforced: the
// effective secret allowlist is explicitly empty (non-nil with no entries,
// which the policy engine verifies denies every secret) and the execution
// mode has no ambient credential source (no inherited host environment, no
// native host authority). The materialized execution is the DISTRIBUTED
// execution model, whose runner always starts from the minimal clean
// environment; the local `kiwi run` host-environment opt-in is not a
// distributed attempt and is never represented here.
func (e EffectiveExecution) noAmbientCredentials() bool {
	if e.nativeRuntime() {
		return false
	}
	return e.Capabilities.Secrets != nil && len(e.Capabilities.Secrets) == 0
}

// networkDenied reports whether the level-3 control is enforced: the
// effective network is none. The legacy shape is preserved too (a persisted
// job whose network field is "none" with a default sandbox network).
func (e EffectiveExecution) networkDenied() bool {
	if e.Network == pipeline.NetworkPolicyNone {
		return true
	}
	return e.CompiledJob.Job.Network == "none"
}

// declaresDeployment reports whether the job declares a deployment effect:
// a target environment or any declared deployment phase.
func (e EffectiveExecution) declaresDeployment() bool {
	j := e.CompiledJob.Job
	if j.Environment.Name != "" {
		return true
	}
	return len(j.Deployment.Canary) > 0 || len(j.Deployment.Verify) > 0 || len(j.Deployment.Rollback) > 0
}

// declaresOIDC reports whether the job declares an id_token request.
func (e EffectiveExecution) declaresOIDC() bool {
	return e.CompiledJob.Job.Permissions.IDToken
}

// declaredAuthorityMediated reports whether the level-4 control is enforced:
// no native host authority, and every declared external effect is covered by
// the effective capability set that admitted the job (deployments by the
// deployment capability, OIDC by the audience allowlist). Artifacts and
// downloads always flow through the control-plane API, so they are mediated
// by construction. A declared effect whose capability is explicitly denied is
// NOT mediated: the derivation reports the network-denied level instead when
// that control holds.
func (e EffectiveExecution) declaredAuthorityMediated() bool {
	if e.nativeRuntime() {
		return false
	}
	if e.declaresDeployment() && !e.Capabilities.Deployments {
		return false
	}
	if e.declaresOIDC() && e.Capabilities.OIDC != nil && len(e.Capabilities.OIDC) == 0 {
		return false
	}
	return true
}

// imagesDigestPinned reports whether every declared executable image
// reference is digest-pinned: the container image and every service image for
// the container runtime, the VM reference for the Tart runtime. A runtime
// with no images (native) is never hermetic.
func (e EffectiveExecution) imagesDigestPinned() bool {
	j := e.CompiledJob.Job
	switch j.Runtime {
	case "container":
		if j.Image == "" || !pipeline.IsDigestPinned(j.Image) {
			return false
		}
		for i := range j.Services {
			if !pipeline.IsDigestPinned(j.Services[i].Image) {
				return false
			}
		}
		return true
	case "tart":
		return j.VM != "" && pipeline.IsDigestPinned(j.VM)
	default:
		return false
	}
}

// Assurance derives the execution-assurance level of the materialized
// execution. The derivation is deterministic and total: every EffectiveExecution
// maps to exactly one level. It reports the strongest satisfied control set
// under the documented sibling rule (see model.ExecutionAssurance): the
// level-4 control outranks the level-3 control when both hold, and level 5
// additionally requires network denial and digest-pinned images.
func (e EffectiveExecution) Assurance() model.ExecutionAssurance {
	if !e.filesystemIsolated() {
		return model.AssuranceUncontrolled
	}
	if !e.noAmbientCredentials() {
		return model.AssuranceIsolatedFilesystem
	}
	if e.declaredAuthorityMediated() {
		if e.networkDenied() && e.imagesDigestPinned() {
			return model.AssuranceHermetic
		}
		return model.AssuranceKiwiMediatedAuthority
	}
	if e.networkDenied() {
		return model.AssuranceNetworkDenied
	}
	return model.AssuranceNoAmbientCredentials
}

// EffectsClass derives the external-effects class of the materialized
// execution. The derivation is deterministic and total.
func (e EffectiveExecution) EffectsClass() model.ExternalEffectsClass {
	if !e.noAmbientCredentials() {
		return model.EffectsOpaqueExternal
	}
	if e.networkDenied() && !e.declaresOIDC() && !e.declaresDeployment() {
		return model.EffectsPure
	}
	return model.EffectsKiwiMediated
}
