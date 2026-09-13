package policy

import (
	"fmt"

	"github.com/kiwici/kiwi/internal/pipeline"
)

// ValidateAdmission enforces hard security invariants before a pipeline is queued.
// Untrusted code is deliberately unable to opt itself into a weaker execution mode.
func ValidateAdmission(s *pipeline.Spec, trusted bool) error {
	if trusted {
		return nil
	}
	if len(s.Secrets) > 0 {
		return fmt.Errorf("untrusted pipeline requests global secrets")
	}
	for id, job := range s.Jobs {
		if job.Runtime == "" || job.Runtime == "native" {
			return fmt.Errorf("untrusted job %q must use runtime container or tart; native host execution is forbidden", id)
		}
		for _, step := range job.Steps {
			if len(step.Secrets) > 0 {
				return fmt.Errorf("untrusted job %q step %q requests secrets", id, step.Name)
			}
		}
	}
	return nil
}
