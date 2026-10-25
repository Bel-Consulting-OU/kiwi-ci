//go:build !windows

package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func lookPathWithExt(name, pathEnv, pathExt string) (string, error) {
	_ = pathExt
	if name == "" {
		return "", errEmptyExecutable
	}
	if strings.ContainsRune(name, os.PathSeparator) || (len(name) > 1 && name[1] == ':') {
		if st, err := os.Stat(name); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return name, nil
		}
		return "", fmt.Errorf("executable %s not found or not executable", name)
	}
	if pathEnv == "" {
		// Fail closed: an empty execution PATH never falls back to a
		// hardcoded list or the runner's ambient PATH.
		return "", fmt.Errorf("%s: execution PATH is empty", name)
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" {
			continue
		}
		cand := filepath.Join(dir, name)
		if st, err := os.Stat(cand); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return cand, nil
		}
	}
	return "", errNotFoundOnPath(name, pathEnv, "")
}
