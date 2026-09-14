package server

import (
	"fmt"
	"net/url"
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

// admitPolicyRestrictions enforces the organization policy's repository and
// image restrictions at enqueue admission (allowed clone hosts, allowed
// placement regions, digest-pinned images) and gates capability-scoped
// pipeline declarations (downstream cross-repo triggers, dynamic child
// graph generation) against the effective capability set. A policy file can
// only ever narrow admission, so every rejection here is a hard 403.
func (s *Server) admitPolicyRestrictions(in SubmitRun, spec *pipeline.Spec, caps policy.Capabilities) error {
	if s.Policy == nil {
		return nil
	}
	repoPolicy, hasRepo := s.Policy.Repositories[in.RepoFullName]

	// Allowed clone hosts: org-level allowlist intersected with the
	// repo-level allowlist (nil = no restriction from that level). A
	// non-empty effective list must contain the run's repository host.
	hosts := s.Policy.AllowedCloneHosts
	if hasRepo && len(repoPolicy.AllowedCloneHosts) > 0 {
		hosts = intersectLists(hosts, repoPolicy.AllowedCloneHosts)
	}
	if len(hosts) > 0 {
		host := repoURLHost(in.RepoURL)
		if host == "" || !containsList(hosts, host) {
			return policyDenied(fmt.Sprintf("repository host %q is not in the allowed clone hosts", host))
		}
	}

	// Allowed regions: every placement.regions entry must be inside the
	// effective allowlist.
	regions := s.Policy.AllowedRegions
	if hasRepo && len(repoPolicy.AllowedRegions) > 0 {
		regions = intersectLists(regions, repoPolicy.AllowedRegions)
	}
	if len(regions) > 0 {
		for id, j := range spec.Jobs {
			for _, r := range j.Placement.Regions {
				if !containsList(regions, r) {
					return policyDenied(fmt.Sprintf("job %q requests placement region %q outside the allowed regions", id, r))
				}
			}
		}
	}

	// Digest pins: every container image and tart VM must reference a
	// pinned digest (@sha256:...) so image contents are immutable.
	requirePins := s.Policy.RequireDigestPins
	if hasRepo && repoPolicy.RequireDigestPins != nil && *repoPolicy.RequireDigestPins {
		requirePins = true
	}
	if requirePins {
		for id, j := range spec.Jobs {
			for _, img := range []string{j.Image, j.VM} {
				if img != "" && !strings.Contains(img, "@sha256:") {
					return policyDenied(fmt.Sprintf("job %q image %q is not digest-pinned (require_digest_pins)", id, img))
				}
			}
			for i := range j.Services {
				if !strings.Contains(j.Services[i].Image, "@sha256:") {
					return policyDenied(fmt.Sprintf("job %q service %q image %q is not digest-pinned (require_digest_pins)", id, j.Services[i].Name, j.Services[i].Image))
				}
			}
		}
	}

	// Capability-scoped declarations: downstream cross-repo triggers and
	// dynamic child graph generation are granted by policy only.
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

// repoURLHost extracts the host of a repository clone URL for the clone-host
// allowlist check. Unparseable URLs return "" and are rejected by any
// configured allowlist (fail closed).
func repoURLHost(repoURL string) string {
	u, err := url.Parse(strings.TrimSpace(repoURL))
	if err != nil {
		return ""
	}
	if u.Host == "" {
		return ""
	}
	return u.Host
}

// repoURLTeam derives the quota team key from the repository URL: the
// host plus the first path segment (the org), so teams never collide across
// forges. Unparseable URLs fall back to the raw string.
func repoURLTeam(repoURL string) string {
	u, err := url.Parse(strings.TrimSpace(repoURL))
	if err != nil || u.Host == "" {
		return strings.TrimSpace(repoURL)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return u.Host
	}
	return u.Host + "/" + parts[0]
}

// intersectLists returns the set intersection of a and b, where nil is the
// universal set (no restriction from that side).
func intersectLists(a, b []string) []string {
	if a == nil {
		return append([]string(nil), b...)
	}
	if b == nil {
		return append([]string(nil), a...)
	}
	out := make([]string, 0, len(a))
	for _, v := range a {
		if containsList(b, v) {
			out = append(out, v)
		}
	}
	return out
}

func containsList(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}
