package snapshot

import (
	"fmt"
	"io"
	"os"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// manifestAfterRestore is a test-only seam over ManifestFor. Production
// behavior is unchanged; it lets the post-extraction manifest failure be
// exercised deterministically.
var manifestAfterRestore = ManifestFor

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
	// Snapshot restore restores the whole archive: opt in explicitly.
	limits := safefs.DefaultLimits()
	limits.AllowAll = true
	if _, err := safefs.Extract(root, r, limits); err != nil {
		return Manifest{}, fmt.Errorf("snapshot: extract: %w", err)
	}
	m, err := manifestAfterRestore(dest)
	if err != nil {
		return Manifest{}, fmt.Errorf("snapshot: manifest after restore: %w", err)
	}
	return m, nil
}
