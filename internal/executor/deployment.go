package executor

import (
	"fmt"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/deploy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// effectiveSteps returns the ordered step list a job executes. A job that
// declares a deployment runs its canary/verify/rollback phases instead of
// the plain step list; every other job runs its steps unchanged.
func effectiveSteps(cj pipeline.CompiledJob) []pipeline.Step {
	if hasDeploymentSteps(cj.Job.Deployment) {
		return deploymentSteps(cj.Job.Deployment)
	}
	return cj.Job.Steps
}

// hasDeploymentSteps reports whether the job declares at least one
// deployment phase step. An empty DeploymentSpec is not a deployment job.
func hasDeploymentSteps(d pipeline.DeploymentSpec) bool {
	return len(d.Canary)+len(d.Verify)+len(d.Rollback) > 0
}

// deploymentSteps renders a deployment into the linear step stream the
// executor's state machine runs: canary steps first, then verify steps,
// then rollback steps. Defaults come from the deploy package (canary and
// verify default to success(); rollback defaults to failure() so it runs
// only after the deployment failed). Each step's log name is namespaced by
// its phase ("canary.<name>", "verify.<name>", "rollback.<name>", or
// "<phase>.step-N" for unnamed steps) while step IDs are left untouched so
// output references keep their declared names.
func deploymentSteps(d pipeline.DeploymentSpec) []pipeline.Step {
	n := deploy.Normalize(d)
	phases := []struct {
		prefix string
		steps  []pipeline.Step
		defIf  string
	}{
		{"canary", n.Canary, deploy.DefaultCanaryCondition},
		{"verify", n.Verify, deploy.DefaultVerifyCondition},
		{"rollback", n.Rollback, deploy.DefaultRollbackCondition},
	}
	out := make([]pipeline.Step, 0, len(n.Canary)+len(n.Verify)+len(n.Rollback))
	for _, p := range phases {
		for i := range p.steps {
			st := p.steps[i]
			if strings.TrimSpace(st.If) == "" {
				st.If = p.defIf
			}
			st.Name = namespacedDeploymentStepName(p.prefix, st.Name, i)
			out = append(out, st)
		}
	}
	return out
}

func namespacedDeploymentStepName(phase, name string, idx int) string {
	if name == "" {
		return fmt.Sprintf("%s.step-%d", phase, idx+1)
	}
	return phase + "." + name
}
