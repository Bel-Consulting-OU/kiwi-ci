package policy

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kiwici/kiwi/internal/pipeline"
)

func mustParse(t *testing.T, y string) *pipeline.Spec {
	t.Helper()
	s, err := pipeline.Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return s
}

func TestTrustedAdmissionAllowsNativeSecretsAndIDToken(t *testing.T) {
	s := mustParse(t, `version: 1
secrets: [deploy-key]
jobs:
  x:
    steps:
      - run: echo hi
        secrets: [deploy-key]
  y:
    runtime: container
    image: alpine
    permissions:
      id_token: true
    steps:
      - run: echo hi
`)
	if err := ValidateAdmission(s, true); err != nil {
		t.Fatalf("trusted admission must allow native, secrets, and id_token: %v", err)
	}
}

func TestUntrustedIDTokenRejected(t *testing.T) {
	s := mustParse(t, `version: 1
jobs:
  x:
    runtime: container
    image: alpine
    permissions:
      id_token: true
    steps:
      - run: echo hi
`)
	err := ValidateAdmission(s, false)
	if err == nil {
		t.Fatal("untrusted id_token must be rejected")
	}
	if !IsViolation(err) {
		t.Fatalf("expected policy violation, got %T: %v", err, err)
	}
	var v *Violation
	if !errors.As(err, &v) || v.Kind != ViolationKindOIDC {
		t.Fatalf("violation kind = %q, want %q", v.Kind, ViolationKindOIDC)
	}
}

func TestValidatePipelineRejectsIDTokenWhenOIDCEmpty(t *testing.T) {
	s := mustParse(t, `version: 1
jobs:
  x:
    runtime: container
    image: alpine
    permissions:
      id_token: true
    steps:
      - run: echo hi
`)
	if err := ValidatePipeline(s, Capabilities{OIDC: []string{}}); err == nil {
		t.Fatal("empty non-nil OIDC allowlist must reject id_token")
	}
	if err := ValidatePipeline(s, Capabilities{OIDC: nil, NativeExecution: true, Container: true}); err != nil {
		t.Fatalf("nil OIDC (trusted) must allow id_token: %v", err)
	}
	if err := ValidatePipeline(s, Capabilities{OIDC: []string{"ci.example.com"}, NativeExecution: true, Container: true}); err != nil {
		t.Fatalf("non-empty OIDC allowlist must allow id_token at admission: %v", err)
	}
}

func TestEgressInternetRejectedWithNoneCap(t *testing.T) {
	s := mustParse(t, `version: 1
jobs:
  x:
    runtime: container
    image: alpine
    sandbox:
      network: 3
    steps:
      - run: echo hi
`)
	err := ValidatePipeline(s, Capabilities{Container: true, Network: pipeline.NetworkPolicyNone})
	if err == nil {
		t.Fatal("explicit internet request must be rejected with none egress cap")
	}
	if !IsViolation(err) {
		t.Fatalf("expected policy violation, got %v", err)
	}
	if err := ValidateAdmission(s, false); err == nil {
		t.Fatal("untrusted admission must reject explicit internet request")
	}
}

func TestEgressServicesOnlyAllowedWhenCapAllows(t *testing.T) {
	s := mustParse(t, `version: 1
jobs:
  x:
    runtime: container
    image: alpine
    sandbox:
      network: 2
    steps:
      - run: echo hi
`)
	if err := ValidatePipeline(s, Capabilities{Container: true, Network: pipeline.NetworkPolicyServicesOnly}); err != nil {
		t.Fatalf("services-only request with services-only cap must be allowed: %v", err)
	}
	if err := ValidatePipeline(s, Capabilities{Container: true, Network: pipeline.NetworkPolicyInternet}); err != nil {
		t.Fatalf("services-only request with internet cap must be allowed: %v", err)
	}
	if err := ValidatePipeline(s, Capabilities{Container: true, Network: pipeline.NetworkPolicyNone}); err == nil {
		t.Fatal("services-only request with none cap must be rejected")
	}
}

func TestEgressNoneAlwaysAllowed(t *testing.T) {
	s := mustParse(t, `version: 1
jobs:
  x:
    runtime: container
    image: alpine
    network: none
    steps:
      - run: echo hi
`)
	if err := ValidatePipeline(s, Capabilities{Container: true, Network: pipeline.NetworkPolicyNone}); err != nil {
		t.Fatalf("none request must be allowed with none cap: %v", err)
	}
	if err := ValidateAdmission(s, false); err != nil {
		t.Fatalf("none request must be allowed for untrusted: %v", err)
	}
}

func TestEgressDefaultInheritsCap(t *testing.T) {
	s := mustParse(t, `version: 1
jobs:
  x:
    runtime: container
    image: alpine
    steps:
      - run: echo hi
`)
	if err := ValidatePipeline(s, Capabilities{Container: true, Network: pipeline.NetworkPolicyNone}); err != nil {
		t.Fatalf("job without explicit network must inherit the cap, not be rejected: %v", err)
	}
	if err := ValidatePipeline(s, DefaultUntrustedCapabilities()); err != nil {
		t.Fatalf("untrusted container job without explicit network must pass: %v", err)
	}
}

func TestRunnerLabelsRestricted(t *testing.T) {
	s := mustParse(t, `version: 1
jobs:
  x:
    runtime: container
    image: alpine
    runner: [linux, gpu]
    steps:
      - run: echo hi
`)
	caps := Capabilities{Container: true, RunnerLabels: []string{"linux", "gpu", "docker"}}
	if err := ValidatePipeline(s, caps); err != nil {
		t.Fatalf("subset of allowed labels must pass: %v", err)
	}
	if err := ValidatePipeline(s, Capabilities{Container: true, RunnerLabels: []string{"linux"}}); err == nil {
		t.Fatal("label outside allowlist must be rejected")
	} else if !IsViolation(err) {
		t.Fatalf("expected policy violation, got %v", err)
	}
	if err := ValidatePipeline(s, Capabilities{Container: true, RunnerLabels: []string{}}); err == nil {
		t.Fatal("empty allowlist must reject any label")
	}
	if err := ValidatePipeline(s, Capabilities{Container: true, RunnerLabels: nil}); err != nil {
		t.Fatalf("nil allowlist must permit any label: %v", err)
	}
}

func TestEnvironmentRequiresDeployments(t *testing.T) {
	s := mustParse(t, `version: 1
jobs:
  x:
    runtime: container
    image: alpine
    environment:
      name: prod
    steps:
      - run: echo hi
`)
	if err := ValidatePipeline(s, Capabilities{Container: true, Deployments: false}); err == nil {
		t.Fatal("environment without deployments capability must be rejected")
	} else if !IsViolation(err) {
		t.Fatalf("expected policy violation, got %v", err)
	}
	if err := ValidatePipeline(s, Capabilities{Container: true, Deployments: true}); err != nil {
		t.Fatalf("environment with deployments capability must be allowed: %v", err)
	}
}

func TestSecretsAllowlist(t *testing.T) {
	s := mustParse(t, `version: 1
secrets: [known]
jobs:
  x:
    runtime: container
    image: alpine
    steps:
      - run: echo hi
        secrets: [known, other]
`)
	allow := Capabilities{Container: true, Secrets: map[string]bool{"known": true}}
	if err := ValidatePipeline(mustParse(t, `version: 1
secrets: [known]
jobs:
  x:
    runtime: container
    image: alpine
    steps:
      - run: echo hi
`), allow); err != nil {
		t.Fatalf("allowlisted global secret must pass: %v", err)
	}
	if err := ValidatePipeline(s, allow); err == nil {
		t.Fatal("step secret outside allowlist must be rejected")
	} else if !IsViolation(err) {
		t.Fatalf("expected policy violation, got %v", err)
	}
	if err := ValidatePipeline(s, Capabilities{Container: true, Secrets: nil}); err != nil {
		t.Fatalf("nil secrets (trusted) must allow any declared secret: %v", err)
	}
	if err := ValidatePipeline(s, Capabilities{Container: true, Secrets: map[string]bool{}}); err == nil {
		t.Fatal("empty secrets allowlist must reject declared secrets")
	}
}

func TestUntrustedStepSecretsRejected(t *testing.T) {
	s := mustParse(t, `version: 1
jobs:
  x:
    runtime: container
    image: alpine
    steps:
      - run: echo hi
        secrets: [s1]
`)
	if err := ValidateAdmission(s, false); err == nil {
		t.Fatal("untrusted step secrets must be rejected")
	} else if !IsViolation(err) {
		t.Fatalf("expected policy violation, got %v", err)
	}
}

func TestContainerAndTartCaps(t *testing.T) {
	container := mustParse(t, `version: 1
jobs:
  x:
    runtime: container
    image: alpine
    steps:
      - run: echo hi
`)
	tart := mustParse(t, `version: 1
jobs:
  x:
    runtime: tart
    vm: macos
    steps:
      - run: echo hi
`)
	if err := ValidatePipeline(container, Capabilities{Container: false, NativeExecution: true}); err == nil {
		t.Fatal("container runtime without container capability must be rejected")
	}
	if err := ValidatePipeline(tart, Capabilities{Tart: false, NativeExecution: true}); err == nil {
		t.Fatal("tart runtime without tart capability must be rejected")
	}
	if err := ValidatePipeline(container, Capabilities{Container: true, NativeExecution: true}); err != nil {
		t.Fatalf("container with capability must pass: %v", err)
	}
	if err := ValidatePipeline(tart, Capabilities{Tart: true, NativeExecution: true}); err != nil {
		t.Fatalf("tart with capability must pass: %v", err)
	}
}

func TestValidateAdmissionWithCapabilities(t *testing.T) {
	native := mustParse(t, `version: 1
jobs:
  x:
    steps:
      - run: echo hi
`)
	if err := ValidateAdmissionWithCapabilities(native, DefaultUntrustedCapabilities()); err == nil {
		t.Fatal("untrusted caps must reject native")
	}
	if err := ValidateAdmissionWithCapabilities(native, DefaultTrustedCapabilities()); err != nil {
		t.Fatalf("trusted caps must allow native: %v", err)
	}
	if err := ValidateAdmissionWithCapabilities(nil, DefaultTrustedCapabilities()); err == nil {
		t.Fatal("nil spec must be rejected")
	} else if !IsViolation(err) {
		t.Fatalf("expected policy violation, got %v", err)
	}
}

func TestViolationClassification(t *testing.T) {
	if IsViolation(nil) {
		t.Fatal("nil error must not be a violation")
	}
	if IsViolation(errors.New("plain error")) {
		t.Fatal("plain error must not be a violation")
	}
	wrapped := &Violation{Kind: "egress", Detail: "boom"}
	if !IsViolation(wrapped) {
		t.Fatal("Violation must classify as violation")
	}
	if !IsViolation(fmt.Errorf("context: %w", wrapped)) {
		t.Fatal("wrapped violation must classify via errors.As")
	}
	if got := wrapped.Error(); got != "policy violation: egress: boom" {
		t.Fatalf("Error() = %q", got)
	}
	if got := (&Violation{Kind: "egress"}).Error(); got != "policy violation: egress" {
		t.Fatalf("Error() without detail = %q", got)
	}
}
