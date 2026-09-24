package executor

import (
	"fmt"
	"regexp"
)

// imageName is the distribution/reference name grammar shared by docker and
// tart image references: an optional registry domain, one or more lowercase
// path components, and an optional tag. Go's regexp has no non-capturing
// groups, so the grouping parentheses are plain capturing groups.
//
//	domain-component = [a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?
//	domain           = domain-component("." domain-component)*(":" [0-9]+)?
//	path-component   = [a-z0-9]+(("."|"_"|"__"|"-"+)[a-z0-9]+)*
//	tag              = [a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}
const imageName = `(([a-zA-Z0-9](([a-zA-Z0-9-])*[a-zA-Z0-9])?)(\.([a-zA-Z0-9](([a-zA-Z0-9-])*[a-zA-Z0-9])?))*(:[0-9]+)?/)?` +
	`[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*` +
	`(/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*` +
	`(:[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127})?`

// imageDigestPin matches a reference that is ENTIRELY a well-formed image
// reference ending in a strict sha256 digest pin: the full reference grammar
// (name, optional tag) followed by "@sha256:" and exactly 64 lowercase hex
// characters with nothing trailing.
//
// The whole pattern is anchored with "^...$", which is what closes the
// flag-injection bypass: a value like "-v/:/host@sha256:<digest>" is not a
// reference at all (it starts with "-", carries ":" and "/" in an invalid
// position), so it can never be reported as pinned even though the digest
// suffix is well-formed. Leading whitespace and control characters are
// rejected by the same full-match rule.
var imageDigestPin = regexp.MustCompile(`^` + imageName + `@sha256:[0-9a-f]{64}$`)

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
