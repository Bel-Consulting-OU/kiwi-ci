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
// clean relative paths (no absolute paths, no "..", no backslashes).
func ResolveComponentRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return fmt.Errorf("component reference is empty")
	}
	if strings.Contains(ref, "@") {
		if !remoteRefRE.MatchString(ref) {
			return fmt.Errorf("invalid component reference %q: remote refs must be name@sha256:<64 hex chars> (digest pinning is mandatory)", ref)
		}
		return nil
	}
	if strings.Contains(ref, "\\") {
		return fmt.Errorf("invalid component reference %q: backslashes are not allowed", ref)
	}
	if strings.HasPrefix(ref, "/") {
		return fmt.Errorf("invalid component reference %q: absolute paths are not allowed", ref)
	}
	if strings.Contains(ref, "..") || !localPathRE.MatchString(ref) {
		return fmt.Errorf("invalid component reference %q: must be a clean relative path", ref)
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
