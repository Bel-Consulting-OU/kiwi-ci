package policy

import (
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// ValidateAdmission enforces the deny-by-default capability policy before a
// pipeline is queued. Untrusted code is deliberately unable to opt itself
// into a weaker execution mode: it receives the untrusted capability floor,
// while trusted callers receive the trusted defaults. This preserves the
// existing server/runner call sites; the server should migrate to
// ValidateAdmissionWithCapabilities once per-repository capability
// compilation lands.
//
// For TRUSTED runs, deployments are deferred to the caller's effective-policy
// check: deployments are an opt-in POLICY grant (repository/organization
// configuration the runner cannot see), not a sandbox bound, so the bare
// trust-domain default must not refuse a job the control plane explicitly
// granted. The runner's signed compiled payload carries that effective policy
// and is validated immediately after this baseline check; an untrusted run
// keeps the hard no-deployments floor.
func ValidateAdmission(s *pipeline.Spec, trusted bool) error {
	caps := DefaultTrustedCapabilities()
	if trusted {
		caps.Deployments = true
	} else {
		caps = DefaultUntrustedCapabilities()
	}
	return ValidatePipeline(s, caps)
}
