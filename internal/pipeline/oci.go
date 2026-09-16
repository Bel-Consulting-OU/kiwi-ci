package pipeline

import (
	"fmt"
	"regexp"
	"strings"
)

// OCI image reference grammar shared by admission and the executor:
// a lowercase repository path (alphanumerics, ".", "_", "/", ":", "-"),
// optionally terminated by a strict digest pin of the form
// "@sha256:<64 lowercase hex>" with nothing trailing. Tag-only
// references (alpine, alpine:latest) are structurally valid but carry no
// digest pin; an uppercase repository or digest, a truncated digest, or
// anything after the digest is rejected.
var (
	ociReferenceRegexp = regexp.MustCompile(`^[a-z0-9._/:-]+(@sha256:[0-9a-f]{64})?$`)
	ociDigestPinRegexp = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
)

// ValidOCIImageReference reports whether ref is a structurally valid OCI
// image reference (see ociReferenceRegexp).
func ValidOCIImageReference(ref string) bool {
	return ValidateOCIRef(ref) == nil
}

// IsDigestPinned reports whether ref carries a strict, terminal
// "@sha256:<64 lowercase hex>" digest pin. It checks only the pin suffix
// (matching the executor's immutable-image gate), so callers that need
// full structural validity should check ValidateOCIRef as well.
func IsDigestPinned(ref string) bool {
	return ociDigestPinRegexp.MatchString(ref)
}

// ValidateOCIRef enforces the OCI reference grammar: non-empty, lowercase
// repository characters only, no empty components (trailing "/", ":", "."
// or "-" before an optional digest pin), and an optional terminal digest
// pin that must be exactly "@sha256:" followed by 64 lowercase hex
// digits.
func ValidateOCIRef(ref string) error {
	if strings.TrimSpace(ref) == "" {
		return fmt.Errorf("image reference is empty")
	}
	if !ociReferenceRegexp.MatchString(ref) {
		return fmt.Errorf("image reference %q is invalid (must match %s)", ref, ociReferenceRegexp.String())
	}
	name := ref
	if i := strings.Index(name, "@"); i >= 0 {
		name = name[:i]
	}
	if c := name[len(name)-1]; c == '/' || c == ':' || c == '.' || c == '-' {
		return fmt.Errorf("image reference %q has an empty component", ref)
	}
	return nil
}
