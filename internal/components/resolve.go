package components

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// remoteRefRE matches the only accepted remote component reference form:
// name@sha256:<64 hex chars>. Digest pinning is mandatory for remote
// registries so a resolved component can never change underneath a pipeline.
var remoteRefRE = regexp.MustCompile(`^[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$`)

// localPathRE matches workspace-relative local component paths. A local path
// may address a component definition bundled with the repository (or a
// registry shim resolving it); it is never digest-pinned, matching how
// in-repo pipeline definitions themselves are trusted at the ref they are
// read from.
var localPathRE = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// ResolveComponentRef validates a component reference. Remote refs must be
// the pinned name@sha256:<hex> form; anything else containing "@" is
// rejected. References without "@" are treated as local paths and must be
// clean relative paths (no absolute paths, no "..", no backslashes) — and the
// name half of a remote ref is held to exactly the same rules, because it is
// joined into a registry request URL and would otherwise escape the component
// namespace.
func ResolveComponentRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return fmt.Errorf("component reference is empty")
	}
	if strings.Contains(ref, "@") {
		if !remoteRefRE.MatchString(ref) {
			return fmt.Errorf("invalid component reference %q: remote refs must be name@sha256:<64 hex chars> (digest pinning is mandatory)", ref)
		}
		name, _ := splitRemoteRef(ref)
		if err := validateCleanRelativePath(name); err != nil {
			return fmt.Errorf("invalid component reference %q: %v", ref, err)
		}
		return nil
	}
	if err := validateCleanRelativePath(ref); err != nil {
		return fmt.Errorf("invalid component reference %q: %v", ref, err)
	}
	return nil
}

// validateCleanRelativePath rejects a component name/path that is not a clean
// workspace-relative path: an absolute path, a backslash, a ".." segment, or
// a character outside the accepted set. It is shared by local refs and by the
// name half of remote refs so the two can never diverge.
func validateCleanRelativePath(ref string) error {
	if strings.Contains(ref, "\\") {
		return fmt.Errorf("backslashes are not allowed")
	}
	if strings.HasPrefix(ref, "/") {
		return fmt.Errorf("absolute paths are not allowed")
	}
	if strings.Contains(ref, "..") || !localPathRE.MatchString(ref) {
		return fmt.Errorf("must be a clean relative path")
	}
	return nil
}

// splitRemoteRef separates a validated remote reference into its name and
// pinned digest. The caller must have validated the ref first.
func splitRemoteRef(ref string) (name, digest string) {
	parts := strings.SplitN(ref, "@", 2)
	if len(parts) != 2 {
		return ref, ""
	}
	return parts[0], strings.TrimPrefix(parts[1], "sha256:")
}

// canonicalJSON renders a component spec deterministically: struct fields
// keep declaration order and maps are sorted by key (encoding/json sorts
// map keys), so identical specs always produce identical bytes.
func canonicalJSON(spec Spec) ([]byte, error) {
	return json.Marshal(spec)
}

func sha256Sum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
