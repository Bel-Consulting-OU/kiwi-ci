package executor

import (
	"context"
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

// TestDigestPinnedRejectsFlagShapedReferences is the H1-D regression: the
// digest matcher must validate the WHOLE reference, so a flag-shaped value
// whose suffix happens to be a well-formed digest can never be reported as
// pinned (the pre-fix unanchored regex matched the suffix and returned true).
func TestDigestPinnedRejectsFlagShapedReferences(t *testing.T) {
	valid := strings.Repeat("a", 64)
	hostile := []string{
		"-v/:/host@sha256:" + valid,         // the auditor's proof
		"--privileged@sha256:" + valid,      // long flag
		" -v@sha256:" + valid,               // leading whitespace
		"\t-v@sha256:" + valid,              // leading tab
		"\x01-v@sha256:" + valid,            // leading control byte
		"alpine\x00@sha256:" + valid,        // embedded control byte
		"--mount=type=bind@sha256:" + valid, // flag with '='
		"alpine b@sha256:" + valid,          // embedded space
		"alpine@sha256:" + valid + " ",      // trailing whitespace
	}
	for _, ref := range hostile {
		if digestPinned(ref) {
			t.Errorf("digestPinned(%q) = true, want false", ref)
		}
	}
	// The same shapes must be refused for untrusted jobs on every image
	// surface, not merely reported as pinned.
	svc := []pipeline.Service{{Name: "db", Image: hostile[0]}}
	if err := validateServiceImages(svc, "run-1", "job-1", true); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("flag-shaped service image accepted for an untrusted job: %v", err)
	}
	cb := &ContainerBackend{Image: hostile[0], RequireImmutableImages: true}
	if err := cb.StartJob(context.Background(), t.TempDir(), func(string) {}); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("flag-shaped container image accepted for an untrusted job: %v", err)
	}
	tb := &TartBackend{VM: hostile[0], RequireImmutableImages: true}
	if err := tb.StartJob(context.Background(), t.TempDir(), func(string) {}); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("flag-shaped tart image accepted for an untrusted job: %v", err)
	}
}

// TestContainerRunArgvSeparatesImage verifies the argv boundary: the docker
// run invocation carries "--" immediately before the image reference, so the
// runtime can never parse an image as an option.
func TestContainerRunArgvSeparatesImage(t *testing.T) {
	installFakeBins(t)
	b := &ContainerBackend{Image: "alpine:3.19", RunID: "run1", JobID: "job1"}
	if err := b.StartJob(context.Background(), t.TempDir(), func(string) {}); err != nil {
		t.Fatalf("StartJob: %v", err)
	}
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	if !strings.Contains(log, "run ") || !strings.Contains(log, "-- alpine:3.19 sh -c") {
		t.Fatalf("docker run argv does not separate the image with --: %q", log)
	}
}

// TestStartServiceImagesRejectsFlagShaped covers the service argv validation
// for an untrusted job: a flag-shaped reference never reaches docker.
func TestStartServiceImagesRejectsFlagShaped(t *testing.T) {
	valid := strings.Repeat("a", 64)
	services := []pipeline.Service{{Name: "db", Image: "-v/:/host@sha256:" + valid}}
	if err := validateServiceImages(services, "run-1", "job-1", true); err == nil {
		t.Fatal("flag-shaped service image passed the untrusted digest gate")
	}
}
