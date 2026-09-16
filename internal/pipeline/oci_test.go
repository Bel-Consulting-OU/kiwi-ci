package pipeline

import (
	"strings"
	"testing"
)

const ociValidDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestValidateOCIRefPinned(t *testing.T) {
	valid := []string{
		"alpine@" + "sha256:" + ociValidDigest,
		"registry.example.com:5000/org/app@" + "sha256:" + ociValidDigest,
		"ghcr.io/cirruslabs/macos-sonoma-base@" + "sha256:" + ociValidDigest,
	}
	for _, ref := range valid {
		if err := ValidateOCIRef(ref); err != nil {
			t.Errorf("pinned ref %q rejected: %v", ref, err)
		}
		if !ValidOCIImageReference(ref) {
			t.Errorf("ValidOCIImageReference(%q) = false", ref)
		}
		if !IsDigestPinned(ref) {
			t.Errorf("IsDigestPinned(%q) = false", ref)
		}
	}
}

func TestValidateOCIRefUnpinned(t *testing.T) {
	valid := []string{"alpine", "alpine:latest", "registry.example/org/app:1.2.3", "postgres:16"}
	for _, ref := range valid {
		if err := ValidateOCIRef(ref); err != nil {
			t.Errorf("tag-only ref %q rejected: %v", ref, err)
		}
		if !ValidOCIImageReference(ref) {
			t.Errorf("ValidOCIImageReference(%q) = false", ref)
		}
		if IsDigestPinned(ref) {
			t.Errorf("IsDigestPinned(%q) = true, want unpinned", ref)
		}
	}
}

func TestValidateOCIRefMalformed(t *testing.T) {
	cases := []struct {
		name string
		ref  string
	}{
		{"empty", ""},
		{"whitespace", "  "},
		{"uppercase repo", "Alpine:latest"},
		{"uppercase digest", "alpine@sha256:" + strings.ToUpper(ociValidDigest)},
		{"truncated digest", "alpine@sha256:" + ociValidDigest[:63]},
		{"digest too long", "alpine@sha256:" + ociValidDigest + "a"},
		{"trailing tag after digest", "alpine@sha256:" + ociValidDigest + ":latest"},
		{"non-hex digest", "alpine@sha256:" + strings.ReplaceAll(ociValidDigest, "a", "g")},
		{"empty tag", "alpine:"},
		{"empty path component", "alpine/"},
		{"space in repo", "a b"},
		{"double pin", "alpine@sha256:" + ociValidDigest + "@sha256:" + ociValidDigest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateOCIRef(tc.ref); err == nil {
				t.Fatalf("ref %q accepted", tc.ref)
			}
			if ValidOCIImageReference(tc.ref) {
				t.Fatalf("ValidOCIImageReference(%q) = true", tc.ref)
			}
		})
	}
}

func TestIsDigestPinnedTerminalOnly(t *testing.T) {
	if IsDigestPinned("alpine@sha256:" + ociValidDigest + ":latest") {
		t.Fatal("non-terminal pin must not count as pinned")
	}
	if IsDigestPinned("") {
		t.Fatal("empty ref must not be pinned")
	}
	if !IsDigestPinned("alpine@" + "sha256:" + ociValidDigest) {
		t.Fatal("terminal pin must be pinned")
	}
}
