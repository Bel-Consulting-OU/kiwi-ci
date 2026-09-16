package snapshot

import (
	"fmt"
	"io"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// Create captures the whole workspace into a deterministic tar.gz written to
// dest and returns the manifest describing it. Symlinks and special files
// are never archived; the returned manifest contains regular files only, in
// the same normalized mode the archive uses, so Create's manifest and
// Parse's manifest agree. All reads go through a held safefs.WorkspaceRoot:
// files are opened relative to the root handle (no-follow) and hashed from
// the returned descriptors, never re-opened by name.
func Create(workspace string, dest io.Writer) (Manifest, error) {
	if workspace == "" {
		return Manifest{}, fmt.Errorf("snapshot: empty workspace")
	}
	root, err := safefs.OpenWorkspaceRoot(workspace)
	if err != nil {
		return Manifest{}, fmt.Errorf("snapshot: open workspace: %w", err)
	}
	defer root.Close()
	m, err := manifestForRoot(root)
	if err != nil {
		return Manifest{}, err
	}
	if err := safefs.WriteTarGzFromRoot(dest, root, []string{"."}); err != nil {
		return Manifest{}, fmt.Errorf("snapshot: write archive: %w", err)
	}
	return m, nil
}
