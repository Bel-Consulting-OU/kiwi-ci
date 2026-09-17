package server

import (
	"context"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

const fcNativeDenyPolicy = `package kiwi

allow := false

deny contains "native runtime is denied" if {
	input.runtime == "native"
}
`

func TestFlowOPAEnsureLazyCompile(t *testing.T) {
	s := New("token")
	s.Policy = &policy.Config{OPARules: opaDenyPolicy}
	if got := s.ensureOPAPolicy(); got == nil {
		t.Fatal("lazy compile did not install the gate")
	}
	// The second call reuses the compiled gate.
	if got := s.ensureOPAPolicy(); got == nil || got != s.opaPolicy {
		t.Fatal("second ensure must reuse the compiled gate")
	}
	// No policy: nil gate.
	s2 := New("token")
	if got := s2.ensureOPAPolicy(); got != nil {
		t.Fatal("policy-less server must have no gate")
	}
}

func TestFlowOPAEmptyRuntimeAndEvaluationFailure(t *testing.T) {
	s := New("token")
	s.Policy = &policy.Config{OPARules: fcNativeDenyPolicy}
	spec := &pipeline.Spec{Jobs: map[string]pipeline.Job{"j": {}}}
	g := &pipeline.Graph{Spec: spec, Jobs: map[string]pipeline.CompiledJob{"j": {ID: "j", Job: spec.Jobs["j"]}}}
	denial := s.opaAdmissionCheck(context.Background(), SubmitRun{Ref: "refs/heads/main"}, g, policy.DefaultTrustedCapabilities(), nil)
	if denial == nil || len(denial.Reasons) == 0 || !strings.Contains(denial.Reasons[0], "native") {
		t.Fatalf("empty-runtime denial = %+v", denial)
	}

	// A gate with no engine fails evaluation: every job contributes the
	// evaluation-failure reason.
	s2 := New("token")
	s2.Policy = &policy.Config{OPARules: opaDenyPolicy}
	s2.opaPolicy = &policy.OPAPolicy{}
	denial = s2.opaAdmissionCheck(context.Background(), SubmitRun{}, g, policy.DefaultTrustedCapabilities(), nil)
	if denial == nil || len(denial.Reasons) == 0 || !strings.Contains(denial.Reasons[0], "evaluation failed") {
		t.Fatalf("evaluation failure denial = %+v", denial)
	}

	// A broken gate denies everything.
	s3 := New("token")
	s3.Policy = &policy.Config{OPARules: opaDenyPolicy}
	s3.opaBroken = true
	denial = s3.opaAdmissionCheck(context.Background(), SubmitRun{}, g, policy.DefaultTrustedCapabilities(), nil)
	if denial == nil || !strings.Contains(denial.Reasons[0], "failed to compile") {
		t.Fatalf("broken gate denial = %+v", denial)
	}
}

func TestFlowAdmissionErrorMessage(t *testing.T) {
	if got := (&admissionError{Msg: "plain"}).Error(); got != "plain" {
		t.Fatalf("reasonless error = %q", got)
	}
	if got := (&admissionError{Reason: "r", Msg: "m"}).Error(); got != "r: m" {
		t.Fatalf("reasoned error = %q", got)
	}
}

func TestFlowAdmissionCompiledSpec(t *testing.T) {
	s := New("token")
	spec := &pipeline.Spec{Jobs: map[string]pipeline.Job{"j": {Runtime: "native"}}}
	if err := s.admitCompiledSpec(repoIdentity{RepoID: "o/r"}, spec, policy.DefaultUntrustedCapabilities()); err == nil {
		t.Fatal("untrusted native job must be rejected by capabilities")
	}
	// Capability declaration gates always run.
	downstreamSpec := &pipeline.Spec{Jobs: map[string]pipeline.Job{"j": {Runtime: "container", Image: "img", Downstream: pipeline.DownstreamSpec{Repository: "o/target"}}}}
	if err := s.admitCompiledSpec(repoIdentity{RepoID: "o/r"}, downstreamSpec, policy.DefaultUntrustedCapabilities()); err == nil {
		t.Fatal("downstream declaration without the capability must be rejected")
	}
	generateSpec := &pipeline.Spec{Jobs: map[string]pipeline.Job{"j": {Runtime: "container", Image: "img", Generate: pipeline.GenerateSpec{Path: "gen.yaml"}}}}
	if err := s.admitCompiledSpec(repoIdentity{RepoID: "o/r"}, generateSpec, policy.DefaultUntrustedCapabilities()); err == nil {
		t.Fatal("generate declaration without the capability must be rejected")
	}
}

func TestFlowAdmissionOrgPolicyFallbacks(t *testing.T) {
	// No policy file: restrictions are skipped.
	s := New("token")
	if err := s.admitOrgPolicyRestrictions(repoIdentity{RepoURL: "https://github.com/o/r.git"}, &pipeline.Spec{}); err != nil {
		t.Fatalf("policy-less restrictions = %v", err)
	}
	// Empty RepoID falls back to the derived canonical identity.
	s2 := New("token")
	s2.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{
		"o/r": {AllowedCloneHosts: []string{"github.com"}},
	}}
	spec := &pipeline.Spec{Jobs: map[string]pipeline.Job{"j": {Runtime: "container", Image: "img"}}}
	if err := s2.admitOrgPolicyRestrictions(repoIdentity{RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r"}, spec); err != nil {
		t.Fatalf("derived identity restrictions = %v", err)
	}
	// A host outside the allowlist is rejected.
	if err := s2.admitOrgPolicyRestrictions(repoIdentity{RepoURL: "https://gitlab.com/o/r.git", RepoFullName: "o/r"}, spec); err == nil {
		t.Fatal("disallowed host must be rejected")
	}
	// A region outside the allowlist is rejected.
	s3 := New("token")
	s3.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{
		"o/r": {AllowedRegions: []string{"eu"}},
	}}
	regionSpec := &pipeline.Spec{Jobs: map[string]pipeline.Job{"j": {Runtime: "container", Image: "img", Placement: pipeline.Placement{Regions: []string{"us"}}}}}
	if err := s3.admitOrgPolicyRestrictions(repoIdentity{RepoID: "o/r", RepoURL: "https://github.com/o/r.git"}, regionSpec); err == nil {
		t.Fatal("disallowed region must be rejected")
	}
	// Digest pins: unpinned images are rejected, pinned ones pass.
	s4 := New("token")
	s4.Policy = &policy.Config{RequireDigestPins: true}
	unpinned := &pipeline.Spec{Jobs: map[string]pipeline.Job{"j": {Runtime: "container", Image: "alpine:3"}}}
	if err := s4.admitOrgPolicyRestrictions(repoIdentity{RepoID: "o/r"}, unpinned); err == nil {
		t.Fatal("unpinned image must be rejected")
	}
	pinned := &pipeline.Spec{Jobs: map[string]pipeline.Job{"j": {Runtime: "container", Image: "alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}
	if err := s4.admitOrgPolicyRestrictions(repoIdentity{RepoID: "o/r"}, pinned); err != nil {
		t.Fatalf("pinned image rejected: %v", err)
	}
	// Unpinned service images are rejected too.
	svc := &pipeline.Spec{Jobs: map[string]pipeline.Job{"j": {Runtime: "container", Image: "alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Services: []pipeline.Service{{Name: "db", Image: "postgres:16"}}}}}
	if err := s4.admitOrgPolicyRestrictions(repoIdentity{RepoID: "o/r"}, svc); err == nil {
		t.Fatal("unpinned service image must be rejected")
	}
	// Per-repo pins intersect with the org switch.
	s5 := New("token")
	pins := true
	s5.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{"o/r": {RequireDigestPins: &pins}}}
	if err := s5.admitOrgPolicyRestrictions(repoIdentity{RepoID: "o/r"}, unpinned); err == nil {
		t.Fatal("repo-level pins must be rejected")
	}
}

func TestFlowAdmissionDownstreamSpecBounds(t *testing.T) {
	base := pipeline.DownstreamSpec{Repository: "o/target"}
	cases := []struct {
		name string
		spec pipeline.DownstreamSpec
		ok   bool
	}{
		{"valid", base, true},
		{"bad repository", pipeline.DownstreamSpec{Repository: "not-a-repo"}, false},
		{"ref too long", pipeline.DownstreamSpec{Repository: "o/target", Ref: strings.Repeat("r", 513)}, false},
		{"event too long", pipeline.DownstreamSpec{Repository: "o/target", Event: strings.Repeat("e", 129)}, false},
		{"too many inputs", pipeline.DownstreamSpec{Repository: "o/target", Inputs: func() map[string]string {
			m := make(map[string]string, 65)
			for i := 0; i < 65; i++ {
				m[string(rune('a'+i%26))+string(rune('0'+i/26))] = "v"
			}
			return m
		}()}, false},
		{"key too long", pipeline.DownstreamSpec{Repository: "o/target", Inputs: map[string]string{strings.Repeat("k", 129): "v"}}, false},
		{"value too large", pipeline.DownstreamSpec{Repository: "o/target", Inputs: map[string]string{"k": strings.Repeat("v", 64<<10+1)}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDownstreamSpec("job", tc.spec)
			if tc.ok && err != nil {
				t.Fatalf("valid spec rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("invalid spec accepted")
			}
		})
	}
}

func TestFlowAdmissionStructureRequiresImage(t *testing.T) {
	spec := &pipeline.Spec{Jobs: map[string]pipeline.Job{"j": {Runtime: "container"}}}
	if err := validateCompiledSpecStructure(spec); err == nil {
		t.Fatal("container job without an image must be rejected")
	}
}
