package server

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

// admissionError is a typed enqueue admission rejection with an HTTP status
// and a machine-readable reason. submit() maps it to the status instead of
// the generic 400, so policy rejections surface as 403 and quota rejections
// as 429 with the reason attached.
type admissionError struct {
	Status int
	Reason string
	Msg    string
}

func (e *admissionError) Error() string {
	if e.Reason != "" {
		return e.Reason + ": " + e.Msg
	}
	return e.Msg
}

func policyDenied(msg string) error {
	return &admissionError{Status: 403, Reason: "policy_denied", Msg: msg}
}

func quotaDenied(reason, msg string) error {
	return &admissionError{Status: 429, Reason: reason, Msg: msg}
}

var downstreamRepoRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// repoIdentity is the repository coordinate set a submission is admitted
// under: the canonical RepoID (the policy lookup key), the clone URL the
// host checks derive from, and the human-readable full name. RepoID is
// derived once at ingress; the other fields are display/derivation inputs
// only.
type repoIdentity struct {
	RepoID       string
	RepoURL      string
	RepoFullName string
}

// admitCompiledSpec is the SINGLE canonical admission path for compiled
// pipeline specs. It runs for the initial enqueue, generated dynamic
// fragments, scheduled runs, and downstream child runs — there is no
// second-class path. In order it enforces:
//
//  1. structural validation (a container job must name an image — this is
//     a compile-time admission error, never deferred to execution);
//  2. the capability admission (runtime/network/secrets/OIDC/deployment/
//     label constraints) against the effective capability set;
//  3. the capability-scoped declaration invariants (downstream cross-repo
//     triggers, generated child graphs) — these ALWAYS run, with or
//     without a policy file, so capability defaults still reject them;
//  4. the organization policy file's repository restrictions (clone
//     hosts, placement regions, digest pins) — only when a policy file is
//     loaded.
func (s *Server) admitCompiledSpec(id repoIdentity, spec *pipeline.Spec, caps policy.Capabilities) error {
	if err := validateCompiledSpecStructure(spec); err != nil {
		return err
	}
	if err := policy.ValidateAdmissionWithCapabilities(spec, caps); err != nil {
		return err
	}
	if err := s.admitCapabilityDeclarations(spec, caps); err != nil {
		return err
	}
	if s.Policy != nil {
		if err := s.admitOrgPolicyRestrictions(id, spec); err != nil {
			return err
		}
	}
	return nil
}

// validateCompiledSpecStructure enforces the structural rules that belong
// to compile time. A container job with an empty image is rejected here so
// it can never reach a backend that would fail it mid-execution.
func validateCompiledSpecStructure(spec *pipeline.Spec) error {
	for id, j := range spec.Jobs {
		if j.Runtime == "container" && strings.TrimSpace(j.Image) == "" {
			return fmt.Errorf("job %q: container runtime requires an image", id)
		}
	}
	return nil
}

// admitCapabilityDeclarations gates capability-scoped pipeline
// declarations (downstream cross-repo triggers, dynamic child graph
// generation) against the effective capability set. It ALWAYS runs — the
// capability defaults deny these declarations even when no policy file is
// loaded — so the split from the org-policy restrictions can never turn a
// no-policy deployment into a capability bypass.
func (s *Server) admitCapabilityDeclarations(spec *pipeline.Spec, caps policy.Capabilities) error {
	for id, j := range spec.Jobs {
		if d := strings.TrimSpace(j.Downstream.Repository); d != "" {
			if !caps.CrossRepoTrigger {
				return policyDenied(fmt.Sprintf("job %q declares downstream repository %q without the cross_repo_trigger capability", id, d))
			}
			if err := validateDownstreamSpec(id, j.Downstream); err != nil {
				return err
			}
		}
		if g := strings.TrimSpace(j.Generate.Path); g != "" && !caps.GenerateChildGraph {
			return policyDenied(fmt.Sprintf("job %q declares generate.path %q without the generate_child_graph capability", id, g))
		}
	}
	return nil
}

// admitOrgPolicyRestrictions enforces the organization policy file's
// repository and image restrictions at admission (allowed clone hosts,
// allowed placement regions, digest-pinned images). It only runs when a
// policy file is loaded; a policy file can only ever narrow admission, so
// every rejection here is a hard 403.
func (s *Server) admitOrgPolicyRestrictions(id repoIdentity, spec *pipeline.Spec) error {
	if s.Policy == nil {
		return nil
	}
	repoID := id.RepoID
	if repoID == "" {
		repoID = repoIDFor(id.RepoID, id.RepoURL, id.RepoFullName)
	}
	repoPolicy, hasRepo := s.Policy.RepoPolicyFor(repoID)

	// Allowed clone hosts: org-level allowlist intersected with the
	// repo-level allowlist. Nil means the level imposes no restriction;
	// a non-nil EMPTY result (disjoint restrictions) denies every host.
	// Both sides are canonicalized (lowercase, one trailing dot, default
	// port dropped) so equivalent forge-host spellings match.
	if hosts := s.Policy.AllowedCloneHostsFor(repoID); hosts != nil {
		host := repoHost(id.RepoURL)
		if !s.Policy.CloneHostAllowed(repoID, host) {
			return policyDenied(fmt.Sprintf("repository host %q is not in the allowed clone hosts", host))
		}
	}

	// Allowed regions: every placement.regions entry must be inside the
	// effective allowlist. Same nil/empty semantics as clone hosts: a
	// non-nil empty intersection denies every region.
	if regions := s.Policy.AllowedRegionsFor(repoID); regions != nil {
		for id, j := range spec.Jobs {
			for _, r := range j.Placement.Regions {
				if !containsList(regions, r) {
					return policyDenied(fmt.Sprintf("job %q requests placement region %q outside the allowed regions", id, r))
				}
			}
		}
	}

	// Digest pins: every container image and tart VM must carry a strict,
	// terminal "@sha256:<64 lowercase hex>" digest pin so image contents
	// are immutable. IsDigestPinned (not substring matching) rejects
	// truncated, uppercase, or embedded digests.
	requirePins := s.Policy.RequireDigestPins
	if hasRepo && repoPolicy.RequireDigestPins != nil && *repoPolicy.RequireDigestPins {
		requirePins = true
	}
	if requirePins {
		for id, j := range spec.Jobs {
			for _, img := range []string{j.Image, j.VM} {
				if img != "" && !pipeline.IsDigestPinned(img) {
					return policyDenied(fmt.Sprintf("job %q image %q is not digest-pinned (require_digest_pins)", id, img))
				}
			}
			for i := range j.Services {
				if !pipeline.IsDigestPinned(j.Services[i].Image) {
					return policyDenied(fmt.Sprintf("job %q service %q image %q is not digest-pinned (require_digest_pins)", id, j.Services[i].Name, j.Services[i].Image))
				}
			}
		}
	}
	return nil
}

// validateDownstreamSpec bounds a downstream declaration's shape at enqueue
// so persisted dispatch state stays sane. Repository must be owner/name;
// ref/event lengths and input counts are bounded.
func validateDownstreamSpec(jobID string, d pipeline.DownstreamSpec) error {
	if !downstreamRepoRE.MatchString(d.Repository) {
		return fmt.Errorf("job %q downstream.repository must be owner/name, got %q", jobID, d.Repository)
	}
	if len(d.Ref) > 512 {
		return fmt.Errorf("job %q downstream.ref exceeds 512 bytes", jobID)
	}
	if len(d.Event) > 128 {
		return fmt.Errorf("job %q downstream.event exceeds 128 bytes", jobID)
	}
	if len(d.Inputs) > 64 {
		return fmt.Errorf("job %q downstream.inputs exceeds 64 entries", jobID)
	}
	for k, v := range d.Inputs {
		if len(k) > 128 || len(v) > 64<<10 {
			return fmt.Errorf("job %q downstream.inputs.%s exceeds size limits", jobID, k)
		}
	}
	return nil
}

func containsList(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}
