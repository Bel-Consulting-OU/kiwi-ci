package snapshot

import (
	"fmt"
	"io"
	"os"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// Restore extracts a snapshot archive into dest using the hardened safefs
// extractor with default resource limits (only regular files and
// directories, no symlink following, bounded sizes), then recomputes the
// manifest from the restored workspace so callers can verify the roundtrip
// against the captured manifest's root digest.
func Restore(r io.Reader, dest string) (Manifest, error) {
	if dest == "" {
		return Manifest{}, fmt.Errorf("snapshot: empty destination")
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return Manifest{}, fmt.Errorf("snapshot: prepare destination: %w", err)
	}
	root, err := safefs.OpenRootNoFollow(dest)
	if err != nil {
		return Manifest{}, fmt.Errorf("snapshot: open root: %w", err)
	}
	defer root.Close()
	if _, err := safefs.Extract(root, r, safefs.DefaultLimits()); err != nil {
		return Manifest{}, fmt.Errorf("snapshot: extract: %w", err)
	}
	m, err := ManifestFor(dest)
	if err != nil {
		return Manifest{}, fmt.Errorf("snapshot: manifest after restore: %w", err)
	}
	return m, nil
}
