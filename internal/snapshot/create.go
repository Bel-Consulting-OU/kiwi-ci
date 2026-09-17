package snapshot

import (
	"fmt"
	"io"
	"sort"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// Create captures the whole workspace into a deterministic tar.gz written to
// dest and returns the manifest describing it. Symlinks and special files
// are never archived. All reads go through a held safefs.WorkspaceRoot:
// files are opened relative to the root handle (no-follow) at write time,
// and the manifest is built from the exact bytes written into the archive,
// so the returned root digest binds the archive content even if the
// workspace is mutated concurrently. The manifest's normalized mode matches
// what the archive stores, so Create's manifest and Parse's manifest agree.
func Create(workspace string, dest io.Writer) (Manifest, error) {
	if workspace == "" {
		return Manifest{}, fmt.Errorf("snapshot: empty workspace")
	}
	root, err := safefs.OpenWorkspaceRoot(workspace)
	if err != nil {
		return Manifest{}, fmt.Errorf("snapshot: open workspace: %w", err)
	}
	defer root.Close()
	archived, err := safefs.WriteTarGzFromRootEntries(dest, root, []string{"."})
	if err != nil {
		return Manifest{}, fmt.Errorf("snapshot: write archive: %w", err)
	}
	entries := make([]Entry, 0, len(archived))
	for _, f := range archived {
		entries = append(entries, Entry{Path: f.Path, Mode: uint32(f.Mode), Size: f.Size, SHA256: f.SHA256})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return Manifest{Version: ManifestVersion, RootSHA256: rootSHA256(entries), Entries: entries}, nil
}
