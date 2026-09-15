package executor

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestDigestPinned(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		ref  string
		want bool
	}{
		{"alpine@sha256:" + valid, true},
		{"registry.example/org/app@sha256:" + valid, true},
		{"ghcr.io/cirruslabs/macos-sonoma-base@sha256:" + valid, true},
		{"alpine:latest", false},
		{"alpine", false},
		{"", false},
		{"alpine@sha256:" + valid[:63], false},
		{"alpine@sha256:" + valid + "a", false},
		{"alpine@sha256:" + strings.ToUpper(valid), false},
		{"alpine@sha256:" + strings.ReplaceAll(valid, "a", "g"), false},
		{"alpine@sha256:" + valid + ":latest", false},
		{"alpine@sha512:" + valid, false},
	}
	for _, tc := range cases {
		if got := digestPinned(tc.ref); got != tc.want {
			t.Errorf("digestPinned(%q) = %t, want %t", tc.ref, got, tc.want)
		}
	}
}

func TestValidateServiceImages(t *testing.T) {
	valid := strings.Repeat("a", 64)
	pinned := "postgres:16@sha256:" + valid
	services := []pipeline.Service{{Name: "db", Image: pinned}}

	// Trusted job (no pin requirement): pinned image passes.
	if err := validateServiceImages(services, "run-1", "job-1", false); err != nil {
		t.Fatalf("trusted job with pinned service rejected: %v", err)
	}
	// Untrusted job: pinned image passes.
	if err := validateServiceImages(services, "run-1", "job-1", true); err != nil {
		t.Fatalf("pinned service rejected: %v", err)
	}
	// Untrusted job: unpinned service rejected before any docker invocation.
	unpinned := []pipeline.Service{{Name: "db", Image: "postgres:16"}}
	err := validateServiceImages(unpinned, "run-1", "job-1", true)
	if err == nil {
		t.Fatal("unpinned service image accepted")
	}
	if !strings.Contains(err.Error(), "digest") || !strings.Contains(err.Error(), "db") {
		t.Fatalf("error does not name the service and the digest requirement: %v", err)
	}
	// Malformed digest (uppercase) rejected even though it contains @sha256:.
	malformed := []pipeline.Service{{Name: "db", Image: "postgres:16@sha256:" + strings.ToUpper(valid)}}
	if err := validateServiceImages(malformed, "run-1", "job-1", true); err == nil {
		t.Fatal("malformed digest accepted")
	}
	// Empty image rejected regardless of trust.
	empty := []pipeline.Service{{Name: "db"}}
	if err := validateServiceImages(empty, "run-1", "job-1", false); err == nil || !strings.Contains(err.Error(), "no image") {
		t.Fatalf("empty service image not rejected: %v", err)
	}
}
