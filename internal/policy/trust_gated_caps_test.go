package policy

import (
	"errors"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// Trust-gated capability surface: sandbox.privileged and volumes[].host_path
// are first-class Kiwi fields, refused without an explicit grant and never
// available to the untrusted floor.

func specWith(job pipeline.Job) *pipeline.Spec {
	return &pipeline.Spec{
		Version: 1,
		Jobs:    map[string]pipeline.Job{"build": job},
	}
}

func TestPrivilegedAndHostMountsAreTrustGated(t *testing.T) {
	priv := pipeline.Job{
		Runtime: "container",
		Image:   "golang:1.23",
		Sandbox: pipeline.Sandbox{Privileged: true},
		Steps:   []pipeline.Step{{Run: "true"}},
	}
	host := pipeline.Job{
		Runtime: "container",
		Image:   "golang:1.23",
		Volumes: []pipeline.Volume{{Name: "h", Path: "/mnt/h", HostPath: "/var/h"}},
		Steps:   []pipeline.Step{{Run: "true"}},
	}

	// Untrusted floor never grants either.
	untrusted := DefaultUntrustedCapabilities()
	if err := ValidatePipeline(specWith(priv), untrusted); !IsViolation(err) {
		t.Fatalf("untrusted privileged = %v, want Violation", err)
	}
	if err := ValidatePipeline(specWith(host), untrusted); !IsViolation(err) {
		t.Fatalf("untrusted host mount = %v, want Violation", err)
	}

	// Trusted default is also opt-in (like Deployments).
	trusted := DefaultTrustedCapabilities()
	if err := ValidatePipeline(specWith(priv), trusted); err == nil {
		t.Fatal("privileged without grant must be refused")
	} else if !IsViolation(err) || !strings.Contains(err.Error(), "privileged") {
		t.Fatalf("privileged error = %v, want privileged violation", err)
	}
	if err := ValidatePipeline(specWith(host), trusted); err == nil {
		t.Fatal("host mount without grant must be refused")
	} else if !IsViolation(err) || !strings.Contains(err.Error(), "host") {
		t.Fatalf("host mount error = %v, want host_mount violation", err)
	}

	// Explicit grant admits both.
	granted := trusted
	granted.Privileged = true
	granted.HostMounts = true
	if err := ValidatePipeline(specWith(priv), granted); err != nil {
		t.Fatalf("granted privileged = %v", err)
	}
	if err := ValidatePipeline(specWith(host), granted); err != nil {
		t.Fatalf("granted host mount = %v", err)
	}

	// Intersect with the untrusted floor strips the grant even if a layer
	// above asked for it.
	stripped := Intersect(granted, DefaultUntrustedCapabilities())
	if stripped.Privileged || stripped.HostMounts {
		t.Fatalf("untrusted intersect leaked grants: %+v", stripped)
	}
	if err := ValidatePipeline(specWith(priv), stripped); !IsViolation(err) {
		t.Fatalf("intersected privileged = %v, want Violation", err)
	}
}

func TestPrivilegedViolationKind(t *testing.T) {
	err := ValidatePipeline(specWith(pipeline.Job{
		Runtime: "container",
		Image:   "img",
		Sandbox: pipeline.Sandbox{Privileged: true},
		Steps:   []pipeline.Step{{Run: "true"}},
	}), DefaultTrustedCapabilities())
	var v *Violation
	if !errors.As(err, &v) {
		t.Fatalf("err = %v, want *Violation", err)
	}
	if v.Kind != ViolationKindPrivileged {
		t.Fatalf("Kind = %q, want %q", v.Kind, ViolationKindPrivileged)
	}
}
