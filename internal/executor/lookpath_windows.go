//go:build windows

package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// defaultPathExt mirrors Go's os/exec Windows default when the execution
// environment does not define PATHEXT.
const defaultPathExt = ".COM;.EXE;.BAT;.CMD"

func lookPathWithExt(name, pathEnv, pathExt string) (string, error) {
	if name == "" {
		return "", errEmptyExecutable
	}
	// Explicit path (contains separator or drive colon): try PATHEXT forms.
	// Empty pathExt still gets the platform default so a bare "tool" resolves
	// to tool.COM/.EXE/.BAT/.CMD, matching Go LookPath.
	if pathExt == "" {
		pathExt = defaultPathExt
	}
	hasSep := strings.ContainsAny(name, `/\`)
	isAbs := len(name) >= 2 && name[1] == ':'
	if hasSep || isAbs {
		for _, cand := range windowsCandidates(name, pathExt) {
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				return cand, nil
			}
		}
		return "", fmt.Errorf("executable %s not found", name)
	}
	if pathEnv == "" {
		// Fail closed: no ambient fallback. Callers must supply PATH.
		return "", fmt.Errorf("%s: execution PATH is empty", name)
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		base := filepath.Join(dir, name)
		for _, cand := range windowsCandidates(base, pathExt) {
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				return cand, nil
			}
		}
	}
	return "", errNotFoundOnPath(name, pathEnv, pathExt)
}
