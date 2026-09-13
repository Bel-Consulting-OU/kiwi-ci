package policy

import (
	"errors"
	"fmt"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// Violation kinds allow callers to classify admission failures.
const (
	ViolationKindSecrets    = "secrets"
	ViolationKindNative     = "native_execution"
	ViolationKindContainer  = "container"
	ViolationKindTart       = "tart"
	ViolationKindEgress     = "egress"
	ViolationKindOIDC       = "oidc"
	ViolationKindLabels     = "runner_labels"
	ViolationKindDeployment = "deployments"
)

// Violation is a typed policy admission failure.
type Violation struct {
	Kind   string
	Detail string
}

func (v *Violation) Error() string {
	if v.Detail == "" {
		return "policy violation: " + v.Kind
	}
	return "policy violation: " + v.Kind + ": " + v.Detail
}

// IsViolation reports whether err is a policy Violation.
func IsViolation(err error) bool {
	var v *Violation
	return errors.As(err, &v)
}

// ValidatePipeline performs rigorous capability-based admission of a pipeline
// request against an effective capability set. The capability set is expected
// to already include the trust floor; ValidateAdmissionWithCapabilities
// documents the server contract.
func ValidatePipeline(s *pipeline.Spec, caps Capabilities) error {
	if s == nil {
		return &Violation{Kind: "spec", Detail: "nil pipeline"}
	}
	if len(s.Secrets) > 0 && caps.Secrets != nil {
		for _, name := range s.Secrets {
			if !caps.Secrets[name] {
				return &Violation{Kind: ViolationKindSecrets, Detail: fmt.Sprintf("pipeline requests secret %q", name)}
			}
		}
	}
	for id, job := range s.Jobs {
		if err := validateJob(id, job, caps); err != nil {
			return err
		}
	}
	return nil
}

// ValidateAdmissionWithCapabilities is the server-phase admission entry point:
// the caller compiles the effective capabilities (repository ∩ organization ∩
// trust domain ∩ request) and applies the trust floor via Capabilities.Effective
// before calling. ValidateAdmission keeps working for legacy call sites.
func ValidateAdmissionWithCapabilities(s *pipeline.Spec, caps Capabilities) error {
	return ValidatePipeline(s, caps)
}

func validateJob(id string, job pipeline.Job, caps Capabilities) error {
	switch job.Runtime {
	case "", "native":
		if !caps.NativeExecution {
			return &Violation{Kind: ViolationKindNative, Detail: fmt.Sprintf("job %q must use runtime container or tart; native host execution is forbidden", id)}
		}
	case "container":
		if !caps.Container {
			return &Violation{Kind: ViolationKindContainer, Detail: fmt.Sprintf("job %q requests runtime container", id)}
		}
	case "tart":
		if !caps.Tart {
			return &Violation{Kind: ViolationKindTart, Detail: fmt.Sprintf("job %q requests runtime tart", id)}
		}
	}
	requested := requestedNetwork(job)
	if requested != pipeline.NetworkPolicyDefault && networkStrength(requested) > networkStrength(caps.Network) {
		return &Violation{Kind: ViolationKindEgress, Detail: fmt.Sprintf("job %q requests network %s which exceeds allowed egress %s", id, networkName(requested), networkName(caps.Network))}
	}
	if job.Permissions.IDToken && caps.OIDC != nil && len(caps.OIDC) == 0 {
		return &Violation{Kind: ViolationKindOIDC, Detail: fmt.Sprintf("job %q requests id_token but no OIDC audiences are allowed", id)}
	}
	if caps.RunnerLabels != nil {
		for _, label := range job.Runner {
			if label != "" && !containsString(caps.RunnerLabels, label) {
				return &Violation{Kind: ViolationKindLabels, Detail: fmt.Sprintf("job %q requests runner label %q", id, label)}
			}
		}
	}
	if job.Environment.Name != "" && !caps.Deployments {
		return &Violation{Kind: ViolationKindDeployment, Detail: fmt.Sprintf("job %q targets environment %q", id, job.Environment.Name)}
	}
	if caps.Secrets != nil {
		for _, step := range job.Steps {
			for _, name := range step.Secrets {
				if !caps.Secrets[name] {
					return &Violation{Kind: ViolationKindSecrets, Detail: fmt.Sprintf("job %q step %q requests secret %q", id, step.Name, name)}
				}
			}
		}
	}
	return nil
}

// requestedNetwork derives the network policy a job requests: an explicit
// sandbox.network declaration, NetworkPolicyNone for network "none", and
// NetworkPolicyDefault otherwise. Default (absent, bridge, or host) carries no
// explicit egress request: it inherits the capability ceiling and the server
// clamps it at enqueue time, so it never trips egress admission on its own.
func requestedNetwork(j pipeline.Job) pipeline.NetworkPolicy {
	if j.Network == "none" {
		return pipeline.NetworkPolicyNone
	}
	return j.Sandbox.Network
}

func networkName(p pipeline.NetworkPolicy) string {
	switch p {
	case pipeline.NetworkPolicyNone:
		return "none"
	case pipeline.NetworkPolicyServicesOnly:
		return "services-only"
	case pipeline.NetworkPolicyInternet:
		return "internet"
	default:
		return "default"
	}
}
