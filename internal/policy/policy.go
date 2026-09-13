package policy

import (
	"github.com/kiwici/kiwi/internal/pipeline"
)

// ValidateAdmission enforces the deny-by-default capability policy before a
// pipeline is queued. Untrusted code is deliberately unable to opt itself
// into a weaker execution mode: it receives the untrusted capability floor,
// while trusted callers receive the trusted defaults. This preserves the
// existing server/runner call sites; the server should migrate to
// ValidateAdmissionWithCapabilities once per-repository capability
// compilation lands.
func ValidateAdmission(s *pipeline.Spec, trusted bool) error {
	caps := DefaultTrustedCapabilities()
	if !trusted {
		caps = DefaultUntrustedCapabilities()
	}
	return ValidatePipeline(s, caps)
}
