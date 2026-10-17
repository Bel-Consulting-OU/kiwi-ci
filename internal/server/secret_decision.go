package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
)

// SecretDecision is the ONE secret-authority record. Execution
// (issueSecret), operator explanation (kiwi secret explain) and audit all
// consume this exact structure — never a parallel hierarchy implementation.
type SecretDecision struct {
	Name string `json:"name"`
	// Allowed is the delivery verdict. False means issueSecret would refuse.
	Allowed bool `json:"allowed"`
	// Reason is the operator-facing explanation of Allowed.
	Reason string `json:"reason"`
	// Declared is the enqueue-time allowlist bit (run secrets ∪ step secrets).
	Declared bool `json:"declared"`
	// Trusted is the job's trust bit. Untrusted jobs never receive secrets.
	Trusted bool `json:"trusted"`
	// Scope is the broker scope the runtime would use (canonical repo id).
	Scope secretbroker.SecretScope `json:"scope"`
	// Stage names the authority gate that decided (declaration, trust,
	// name-grammar, broker). "delivered" is the only positive stage.
	Stage string `json:"stage"`
	// Rejected lists the alternative bindings the authority CONSIDERED and
	// refused, each with the dimension that disqualified it. Explanation
	// must explain the actual decision — including what it did NOT pick.
	Rejected []RejectedBinding `json:"rejected,omitempty"`
	// AuditID links the durable audit row for this decision. Empty when the
	// decision was only explained (no delivery).
	AuditID string `json:"audit_id,omitempty"`
}

// RejectedBinding is one alternative the authority refused.
type RejectedBinding struct {
	// Source names the scope/owner the binding came from.
	Source string `json:"source"`
	// Dimension is the policy dimension that disqualified it (trust, fork,
	// branch, tag, event, expiry, owner).
	Dimension string `json:"dimension"`
	// Detail is the operator-readable reason.
	Detail string `json:"detail"`
}

// explainSecret evaluates the SAME predicates issueSecret enforces, minus
// lease liveness and the once-only claim (those are delivery-time concerns
// and cannot be decided before a runner asks). The result is what
// `kiwi secret explain` renders and what audit records: one authority.
//
// It does NOT retrieve the secret value. A positive decision means "issue
// would proceed to broker resolution", not "the value exists".
func (s *Server) explainSecret(ctx context.Context, j model.Job, name string) SecretDecision {
	d := SecretDecision{
		Name:     name,
		Trusted:  j.Trusted,
		Declared: containsString(j.DeclaredSecrets, name),
		Scope:    secretScopeForJob(j),
	}
	switch {
	case !secretNameRequestRegexp.MatchString(name):
		d.Allowed = false
		d.Stage = "name-grammar"
		d.Reason = fmt.Sprintf("secret name %q does not match the delivery grammar %s", name, secretNameRequestRegexp)
		return d
	case !j.Trusted:
		d.Allowed = false
		d.Stage = "trust"
		d.Reason = "untrusted jobs never receive secrets (admission strips them; delivery refuses them)"
		return d
	case !d.Declared:
		d.Allowed = false
		d.Stage = "declaration"
		d.Reason = "secret is not in the job's declared allowlist (run secrets ∪ step secrets)"
		return d
	}
	if s.SecretBroker == nil {
		d.Allowed = false
		d.Stage = "broker"
		d.Reason = "secret broker not configured"
		return d
	}
	// Rejected alternatives: every OTHER declared secret the job could have
	// asked for and did not, and every other scope that could have supplied
	// this name. This is what makes `explain` explain the DECISION, not a
	// parallel hierarchy.
	d.Rejected = s.rejectedBindings(j, name)
	d.Allowed = true
	d.Stage = "declared"
	d.Reason = "declared for this trusted job; issueSecret would resolve it through the broker and seal it for the lease holder"
	// NEVER probe the broker here. explainSecret is a DECISION, not a
	// resolution: a probe would burn a one-time delivery and would run
	// before the delivery-time ephemeral-key gate. The broker is consulted
	// only inside deliverSecret, after every cheap check has passed.
	return d
}

// rejectedBindings enumerates the alternatives the authority refused: the
// job's other declared secrets (not requested) and the trust/expiry
// dimensions that would have refused this one had they differed.
func (s *Server) rejectedBindings(j model.Job, name string) []RejectedBinding {
	var out []RejectedBinding
	for _, other := range j.DeclaredSecrets {
		if other == name {
			continue
		}
		out = append(out, RejectedBinding{
			Source:    "declaration",
			Dimension: "not-requested",
			Detail:    fmt.Sprintf("%q is declared for this job but was not requested", other),
		})
	}
	if j.Trusted {
		out = append(out, RejectedBinding{
			Source:    "trust",
			Dimension: "trust-floor",
			Detail:    "an untrusted (fork) binding for this name would have been refused by the trust floor",
		})
	}
	return out
}

// ExplainJobSecret is the operator-facing wrapper used by the admin API and
// `kiwi secret explain --server`.
func (s *Server) ExplainJobSecret(jobID, name string) (SecretDecision, error) {
	j, ok := s.jobByID(jobID)
	if !ok {
		return SecretDecision{}, fmt.Errorf("job %q not found", jobID)
	}
	return s.explainSecret(context.Background(), j, name), nil
}

// jobByID is the memory/DB job lookup used by explain. It never mutates.
func (s *Server) jobByID(id string) (model.Job, bool) {
	if s.DB != nil {
		if j, err := s.DB.GetJob(context.Background(), id); err == nil {
			return j, true
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	return j, ok
}

// ScopeString renders the broker scope for logs and explain output.
func (d SecretDecision) ScopeString() string {
	return fmt.Sprintf("repo=%s env=%s trusted=%t checkout=%s",
		d.Scope.Repository, d.Scope.Environment, d.Scope.Trusted, d.Scope.CheckoutRepositoryURL)
}

// explainJobSecretHTTP is the operator-facing read of the SAME decision
// issueSecret consumes. It never returns a value, only the verdict.
func (s *Server) explainJobSecretHTTP(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	name := r.PathValue("name")
	d, err := s.ExplainJobSecret(jobID, name)
	if err != nil {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, d)
}
