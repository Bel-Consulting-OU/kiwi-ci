package server

import (
	"context"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

// OPA deny gate wiring: the policy.Config's opa_file/opa_rules Rego source
// is compiled once and evaluated against every enqueue. Capabilities are
// already intersected deterministically before this gate runs; OPA adds
// boolean admission on top and can only deny.

// opaDenialError marks an OPA admission rejection so submit() can map it to
// HTTP 403 rather than the generic 400.
type opaDenialError struct {
	Reasons []string
}

func (e *opaDenialError) Error() string {
	return "admission denied by policy: " + strings.Join(e.Reasons, "; ")
}

// ConfigureOPA compiles the loaded policy's Rego rules into a prepared
// query. A nil Policy or no rules yields no gate. Compilation errors fail
// closed: the server refuses to start rather than admit without the gate.
func (s *Server) ConfigureOPA() error {
	if s.Policy == nil {
		return nil
	}
	p, err := s.Policy.CompileOPA()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.opaPolicy = p
	s.mu.Unlock()
	return nil
}

// ensureOPAPolicy returns the compiled OPA gate, compiling it lazily when a
// Policy was installed after construction (tests, dynamic reload).
func (s *Server) ensureOPAPolicy() *policy.OPAPolicy {
	if s.Policy == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.opaPolicy == nil && !s.opaBroken && (s.Policy.OPAFile != "" || s.Policy.OPARules != "") {
		if p, err := s.Policy.CompileOPA(); err == nil {
			s.opaPolicy = p
		} else {
			s.logError("opa: compile failed, failing closed", "error", err.Error())
			s.opaBroken = true
		}
	}
	return s.opaPolicy
}

// opaAdmissionCheck evaluates the compiled OPA gate against the submission
// (per job: runtime, environment, labels, network, secrets, audiences) and
// returns a denial error when any job is denied. A configured-but-broken
// gate denies everything (fail closed).
func (s *Server) opaAdmissionCheck(ctx context.Context, in SubmitRun, g *pipeline.Graph, caps policy.Capabilities, oidcAudiences []string) *opaDenialError {
	gate := s.ensureOPAPolicy()
	s.mu.Lock()
	broken := s.opaBroken
	s.mu.Unlock()
	if broken {
		return &opaDenialError{Reasons: []string{"opa policy failed to compile; all admissions are denied"}}
	}
	if gate == nil {
		return nil
	}
	branch := branchFromRef(in.Ref)
	var reasons []string
	seen := map[string]bool{}
	add := func(rs []string) {
		for _, r := range rs {
			if !seen[r] {
				seen[r] = true
				reasons = append(reasons, r)
			}
		}
	}
	for _, cj := range g.Jobs {
		runtime := cj.Job.Runtime
		if runtime == "" {
			runtime = "native"
		}
		network := cj.Job.Network
		if network == "" {
			network = "bridge"
		}
		if !in.Trusted && cj.Job.Runtime == "container" {
			network = "none"
		}
		decision, err := gate.Decide(ctx, policy.OPAInput{
			Repository:   repoIDForSubmit(in),
			RepoFullName: in.RepoFullName,
			Trusted:      in.Trusted,
			Branch:       branch,
			Event:        in.Event,
			Runtime:      runtime,
			Secrets:      declaredSecrets(g.Spec, cj.Job),
			Audiences:    oidcAudiences,
			Environment:  cj.Job.Environment.Name,
			RunnerLabels: labelsForJob(cj.Job),
			Network:      network,
		})
		if err != nil {
			add([]string{"opa evaluation failed: " + err.Error()})
			continue
		}
		if !decision.Allow {
			add(decision.Reasons)
		}
	}
	if len(reasons) > 0 {
		return &opaDenialError{Reasons: reasons}
	}
	return nil
}
