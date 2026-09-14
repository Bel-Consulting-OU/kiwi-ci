// Package deploy models environment deployments: the lifecycle record
// tracked by the control plane and the normalization of the three-phase
// deployment step lists (canary, verify, rollback) declared on a job.
//
// The normalized form is what a caller (the executor or a sub-DAG runner)
// executes: canary steps run first, then verify steps (both defaulting to
// success()), then rollback steps (defaulting to failure()) when the deploy
// did not verify. Rollback is a conservative default: a deployment that
// failed verification always rolls back unless a step's condition says
// otherwise.
package deploy

import (
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// DefaultRollbackCondition is applied to rollback steps without an explicit
// condition: roll back when the deployment failed or was blocked.
const DefaultRollbackCondition = "failure()"

// DefaultCanaryCondition is applied to canary steps without an explicit
// condition: run the canary while the deployment still admits success.
const DefaultCanaryCondition = "success()"

// DefaultVerifyCondition is applied to verify steps without an explicit
// condition: verify only when the canary phase succeeded.
const DefaultVerifyCondition = "success()"

// Deployment is the deployment record owned by this package. It mirrors
// model.Deployment so the control plane can persist/read the same shape
// without an extra conversion layer.
type Deployment = model.Deployment

// NormalizedDeployment is a DeploymentSpec with defaults resolved. Canary,
// Verify and Rollback hold the original step lists (rollback steps receive
// their default condition at Normalize time); EffectiveSteps renders the
// ordered execution list with the remaining defaults (canary and verify
// success()) applied.
type NormalizedDeployment struct {
	Canary   []pipeline.Step
	Verify   []pipeline.Step
	Rollback []pipeline.Step
	// DefaultRollbackCondition is the condition applied to rollback steps
	// that did not declare one.
	DefaultRollbackCondition string
}

// Normalize converts a pipeline DeploymentSpec into its normalized form.
// Rollback steps default to `if: failure()`: a deployment whose verify phase
// failed rolls back automatically. Verify defaults are applied by
// EffectiveSteps so Normalize stays idempotent and cheap.
func Normalize(d pipeline.DeploymentSpec) NormalizedDeployment {
	n := NormalizedDeployment{
		Canary:                   cloneSteps(d.Canary),
		Verify:                   cloneSteps(d.Verify),
		Rollback:                 cloneSteps(d.Rollback),
		DefaultRollbackCondition: DefaultRollbackCondition,
	}
	for i := range n.Rollback {
		if n.Rollback[i].If == "" {
			n.Rollback[i].If = DefaultRollbackCondition
		}
	}
	return n
}

// EffectiveSteps returns the ordered step list a caller executes as a
// sub-DAG: canary steps first, then verify steps, then rollback steps.
// Canary and verify steps default to success(); rollback steps default to
// failure() (already applied at Normalize time). Steps that declared an
// explicit condition keep it. This is the complete execution plan for one
// deployment.
func (n NormalizedDeployment) EffectiveSteps() []pipeline.Step {
	out := make([]pipeline.Step, 0, len(n.Canary)+len(n.Verify)+len(n.Rollback))
	for _, st := range n.Canary {
		if st.If == "" {
			st.If = DefaultCanaryCondition
		}
		out = append(out, st)
	}
	for _, st := range n.Verify {
		if st.If == "" {
			st.If = DefaultVerifyCondition
		}
		out = append(out, st)
	}
	for _, st := range n.Rollback {
		if st.If == "" {
			st.If = n.DefaultRollbackCondition
			if st.If == "" {
				st.If = DefaultRollbackCondition
			}
		}
		out = append(out, st)
	}
	return out
}

// NewDeployment builds a deployment record for a job starting its
// environment deployment. ApprovedBy/ApprovedAt are copied from the job's
// approval state.
func NewDeployment(job model.Job, approvedBy string, approvedAt, startedAt *time.Time) Deployment {
	now := time.Now().UTC()
	created := now
	if startedAt != nil {
		created = *startedAt
	}
	return Deployment{
		ID:          job.ID,
		RunID:       job.RunID,
		JobID:       job.ID,
		Repository:  job.RepoURL,
		Environment: job.Environment,
		Commit:      job.SHA,
		Status:      model.StatusRunning,
		ApprovedBy:  approvedBy,
		ApprovedAt:  approvedAt,
		StartedAt:   startedAt,
		CreatedAt:   created,
	}
}

func cloneSteps(in []pipeline.Step) []pipeline.Step {
	return append([]pipeline.Step(nil), in...)
}
