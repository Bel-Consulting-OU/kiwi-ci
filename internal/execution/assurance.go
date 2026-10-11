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

// runtimeFact maps the effective runtime onto the closed fact vocabulary. An
// unrecognized runtime is "unknown", never silently treated as sandboxed.
func (e EffectiveExecution) runtimeFact() model.ExecutionRuntimeFact {
	switch e.CompiledJob.Job.Runtime {
	case "", "native":
		return model.RuntimeFactNative
	case "container":
		return model.RuntimeFactContainer
	case "tart":
		return model.RuntimeFactTart
	default:
		return model.RuntimeFactUnknown
	}
}

// sandboxed reports whether the effective runtime is a real confinement
// boundary (container or Tart). A workspace quota is NOT a sandbox: it
// bounds disk consumption without confining the process's filesystem view.
func (e EffectiveExecution) sandboxed() bool {
	switch e.runtimeFact() {
	case model.RuntimeFactContainer, model.RuntimeFactTart:
		return true
	default:
		return false
	}
}

// networkModeFact maps the effective network policy onto the closed fact
// vocabulary. The legacy shape is preserved (a persisted job whose network
// field is "none" with a default sandbox network).
func (e EffectiveExecution) networkModeFact() model.ExecutionNetworkModeFact {
	if e.CompiledJob.Job.Network == "none" {
		return model.NetworkModeFactNone
	}
	switch e.Network {
	case pipeline.NetworkPolicyNone:
		return model.NetworkModeFactNone
	case pipeline.NetworkPolicyServicesOnly:
		return model.NetworkModeFactServices
	case pipeline.NetworkPolicyDefault:
		return model.NetworkModeFactDefault
	case pipeline.NetworkPolicyInternet:
		return model.NetworkModeFactInternet
	default:
		return model.NetworkModeFactUnknown
	}
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

// DeclaresOIDC is the exported form of declaresOIDC for effects classification.
func (e EffectiveExecution) DeclaresOIDC() bool { return e.declaresOIDC() }

// DeclaresDeployment is the exported form of declaresDeployment for effects
// classification.
func (e EffectiveExecution) DeclaresDeployment() bool { return e.declaresDeployment() }

// declaresOIDC reports whether the job declares an id_token request.
func (e EffectiveExecution) declaresOIDC() bool {
	return e.CompiledJob.Job.Permissions.IDToken
}

// declaredAuthorityMediated reports whether every DECLARED external effect is
// covered by the effective capability set that admitted the job (deployments
// by the deployment capability, OIDC by the audience allowlist) on a
// sandboxed runtime. Artifacts and downloads always flow through the
// control-plane API, so they are mediated by construction. A declared effect
// whose capability is explicitly denied is NOT mediated.
func (e EffectiveExecution) declaredAuthorityMediated() bool {
	if !e.sandboxed() {
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
// with no images (native) is never pinned.
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

// Facts materializes the AUTHORITATIVE control-fact vector from the durable
// records this effective execution was built from. The facts are orthogonal
// by construction: FilesystemIsolated requires a real sandbox boundary and is
// never implied by the workspace quota; KiwiSecretsInjected is the narrower
// "no INJECTED credentials" fact (a nil allowlist or any allowed entry means
// a secret could be injected). Observed is left nil here; the evidence
// emitter attaches the executor-observed receipt from the persisted job, so
// this function stays a pure function of the effective execution.
//
// Quota truthfulness (P1): WorkspaceQuotaConfigured records that the plan
// requested a bound. WorkspaceQuotaEnforced is NEVER derived from the
// requested limit — it stays false here and is set only from the
// attempt-specific hard-quota observation on the control receipt
// (model.ExecutionFacts.ApplyObservedControl). A signed
// workspace_quota_enforced=true therefore always means an OS-level hard
// quota was proven installed, not merely that one was asked for.
func (e EffectiveExecution) Facts() model.ExecutionFacts {
	caps := e.Capabilities
	return model.ExecutionFacts{
		Runtime:                   e.runtimeFact(),
		FilesystemIsolated:        e.sandboxed(),
		WorkspaceQuotaConfigured:  e.WorkspaceQuotaLimit > 0,
		WorkspaceQuotaEnforced:    false,
		KiwiSecretsInjected:       !(caps.Secrets != nil && len(caps.Secrets) == 0),
		HostEnvironmentInherited:  false, // the distributed model always starts from a clean environment
		NetworkMode:               e.networkModeFact(),
		DeclaredAuthorityMediated: e.declaredAuthorityMediated(),
		ImagesDigestPinned:        e.imagesDigestPinned(),
	}
}

// Assurance derives the execution-assurance PROFILE LABEL of the materialized
// execution from its authoritative facts (model.DeriveAssuranceProfile is the
// single shared derivation rule). The label is a convenience view; consumers
// authorize against Facts().
func (e EffectiveExecution) Assurance() model.ExecutionAssurance {
	return model.DeriveAssuranceProfile(e.Facts())
}

// EffectsClass derives the external-effects class of the materialized
// execution from its PROVEN facts (call only after ApplyObservedControl when
// an observed receipt exists). "pure" requires a proven network denial
// (NetworkAccessDenied) — a policy of network none on native is NOT enough.
// A native or unknown runtime is always opaque (ambient host credentials are
// reachable through the unconfined filesystem), as is any execution that
// could receive an injected secret or inherit the host environment.
func (e EffectiveExecution) EffectsClass() model.ExternalEffectsClass {
	f := e.Facts()
	if !f.FilesystemIsolated || f.KiwiSecretsInjected || f.HostEnvironmentInherited {
		return model.EffectsOpaqueExternal
	}
	if f.NetworkAccessDenied && !e.declaresOIDC() && !e.declaresDeployment() {
		return model.EffectsPure
	}
	return model.EffectsKiwiMediated
}

// EffectsClassFromFacts classifies from an already-completed fact vector
// (including ApplyObservedControl). Preferred when a receipt may be present.
func EffectsClassFromFacts(f model.ExecutionFacts, declaresOIDC, declaresDeployment bool) model.ExternalEffectsClass {
	if !f.FilesystemIsolated || f.KiwiSecretsInjected || f.HostEnvironmentInherited {
		return model.EffectsOpaqueExternal
	}
	if f.NetworkAccessDenied && !declaresOIDC && !declaresDeployment {
		return model.EffectsPure
	}
	return model.EffectsKiwiMediated
}
