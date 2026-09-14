package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

const opaDenyPolicy = `package kiwi

allow := true

deny contains "untrusted container jobs are rejected by org policy" if {
	input.runtime == "container"
	input.trusted == false
}
`

const nativePipeline = `version: 1
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`

func TestOPADeniesAtEnqueue(t *testing.T) {
	s := New("token")
	s.Policy = &policy.Config{OPARules: opaDenyPolicy}
	if err := s.ConfigureOPA(); err != nil {
		t.Fatal(err)
	}
	// A trusted container job with bridge networking is denied by the rule.
	submit := `{"repo_url":"https://example.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","sha":"abc","event":"push","pipeline":` + jsonString(smokePipeline) + `}`
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", submit)
	if w.Code != http.StatusForbidden {
		t.Fatalf("denied submit = %d, want 403: %s", w.Code, w.Body.String())
	}
	if w.Body.String() == "" {
		t.Fatal("denial must carry reasons")
	}
}

func TestOPAAllowsWhenRulesSatisfied(t *testing.T) {
	s := New("token")
	s.Policy = &policy.Config{OPARules: opaDenyPolicy}
	if err := s.ConfigureOPA(); err != nil {
		t.Fatal(err)
	}
	// The rule only denies container jobs with non-none network; a native
	// job passes the gate.
	spec, err := pipeline.Parse([]byte(nativePipeline))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	if denial := s.opaAdmissionCheck(context.Background(), SubmitRun{RepoFullName: "o/r", Trusted: false, Ref: "refs/heads/main", Event: "push"}, g, policy.DefaultUntrustedCapabilities(), nil); denial != nil {
		t.Fatalf("native job denied by OPA: %v", denial.Reasons)
	}
}

func TestOPABrokenPolicyFailsClosed(t *testing.T) {
	s := New("token")
	s.Policy = &policy.Config{OPARules: `package kiwi
allow := true
deny contains "x" if { input.undefined_field == true }
`}
	// The policy references an unknown input field: loading fails, and the
	// gate denies every admission.
	if err := s.ConfigureOPA(); err == nil {
		t.Fatal("invalid policy must fail ConfigureOPA")
	}
	s.opaPolicy = nil
	submit := `{"repo_url":"https://example.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","sha":"abc","event":"push","pipeline":` + jsonString(smokePipeline) + `}`
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", submit)
	if w.Code != http.StatusForbidden {
		t.Fatalf("broken gate submit = %d, want 403: %s", w.Code, w.Body.String())
	}
}

func TestNoPolicyConfigMeansNoOPAGate(t *testing.T) {
	s := New("token")
	submit := `{"repo_url":"https://example.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","sha":"abc","event":"push","pipeline":` + jsonString(smokePipeline) + `}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", submit); w.Code != http.StatusAccepted {
		t.Fatalf("no-policy submit = %d: %s", w.Code, w.Body.String())
	}
}
