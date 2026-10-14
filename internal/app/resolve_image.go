package app

import (
	"fmt"
	"os/exec"
	"strings"
)

// ResolveImageDigest resolves a container tag to its immutable
// `@sha256:` digest. The resolver seam is replaceable in tests.
var ResolveImageDigest = resolveImageDigestCLI

func resolveImageDigestCLI(ref string) (string, error) {
	if strings.Contains(ref, "@sha256:") {
		// Already pinned.
		return ref, nil
	}
	// docker buildx imagetools inspect is the portable resolver when Docker
	// is present; crane is the alternative.
	if _, err := exec.LookPath("docker"); err == nil {
		out, err := exec.Command("docker", "buildx", "imagetools", "inspect", ref, "--format", "{{.Manifest.Digest}}").Output()
		if err == nil {
			d := strings.TrimSpace(string(out))
			if strings.HasPrefix(d, "sha256:") {
				return ref + "@" + d, nil
			}
		}
	}
	if _, err := exec.LookPath("crane"); err == nil {
		out, err := exec.Command("crane", "digest", ref).Output()
		if err == nil {
			d := strings.TrimSpace(string(out))
			if strings.HasPrefix(d, "sha256:") {
				return ref + "@" + d, nil
			}
		}
	}
	return "", fmt.Errorf("cannot resolve %s: need docker buildx imagetools or crane", ref)
}
