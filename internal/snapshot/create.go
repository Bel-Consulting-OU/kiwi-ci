package snapshot

import (
	"fmt"
	"io"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// Create captures the whole workspace into a deterministic tar.gz written to
// dest and returns the manifest describing it. Symlinks and special files
// are never archived (safefs.WriteTarGz guarantees this); the returned
// manifest contains regular files only, in the same normalized mode the
// archive uses, so Create's manifest and Parse's manifest agree.
func Create(workspace string, dest io.Writer) (Manifest, error) {
	if workspace == "" {
		return Manifest{}, fmt.Errorf("snapshot: empty workspace")
	}
	m, err := ManifestFor(workspace)
	if err != nil {
		return Manifest{}, err
	}
	if err := safefs.WriteTarGz(dest, workspace, []string{"."}, false); err != nil {
		return Manifest{}, fmt.Errorf("snapshot: write archive: %w", err)
	}
	return m, nil
}
