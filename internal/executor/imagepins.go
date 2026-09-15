package executor

import (
	"fmt"
	"regexp"
)

// imageDigestPin matches a reference that ends in a well-formed sha256
// digest pin: "@sha256:" followed by exactly 64 lowercase hex characters.
// Nothing may trail the digest, so "alpine@sha256:<digest>:latest" is not a
// pin and an uppercase or truncated digest is not a pin.
var imageDigestPin = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// digestPinned reports whether ref carries a strict, well-formed sha256
// digest pin. The hard untrusted floor requires a pin on every executable
// image: the main image, every service image, and every Tart VM reference.
func digestPinned(ref string) bool {
	if ref == "" {
		return false
	}
	return imageDigestPin.MatchString(ref)
}

// unpinnedImageError renders the uniform refusal for an image that is not
// pinned by a strict digest when RequireImmutableImages is on.
func unpinnedImageError(kind, ref string) error {
	return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("%s %q is not pinned by a well-formed @sha256:<64-hex> digest (require_immutable_images)", kind, ref)}
}
