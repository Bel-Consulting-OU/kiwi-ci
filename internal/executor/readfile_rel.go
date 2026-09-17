package executor

import (
	"path/filepath"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
)

// relWithinRoot derives the root-relative path for path, tolerating the
// platform spellings of the same location: the canonical root spelling,
// the parent-canonicalized spelling, and finally the caller's own root
// spelling. The containment check is purely lexical; the actual read is
// always anchored to the opened root handle, so a lexical fallback cannot
// escape the workspace.
func relWithinRoot(ws *safefs.WorkspaceRoot, originalRoot, path string) (string, bool) {
	if rel, err := filepath.Rel(ws.Canonical, path); err == nil && !escapesRoot(rel) {
		return rel, true
	}
	parent, base := filepath.Split(path)
	if realParent, err := filepath.EvalSymlinks(filepath.Clean(parent)); err == nil {
		if rel, rerr := filepath.Rel(ws.Canonical, filepath.Join(realParent, base)); rerr == nil && !escapesRoot(rel) {
			return rel, true
		}
	}
	if rel, err := filepath.Rel(originalRoot, path); err == nil && !escapesRoot(rel) {
		return rel, true
	}
	return "", false
}

func escapesRoot(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel)
}
