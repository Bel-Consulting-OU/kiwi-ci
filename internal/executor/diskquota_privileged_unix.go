//go:build unix

package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// validatePrivilegedTool proves a recorded helper before executing it as the
// runner (root for XFS): absolute path, regular executable file, owned by the
// effective user. It lives on unix (not just Linux) because the property it
// checks — executable bits and filesystem ownership — is a unix property;
// there is no XFS assignment to clean up on platforms without project quotas,
// and no non-test caller reaches it there.
func validatePrivilegedTool(path string) error {
	if !filepath.IsAbs(path) || strings.Contains(path, "..") {
		return fmt.Errorf("recorded tool path %q is not a safe absolute path", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat recorded tool %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("recorded tool %s is not an executable regular file", path)
	}
	if !lockFileOwnerOK(info) {
		return fmt.Errorf("recorded tool %s is not owned by the runner", path)
	}
	return nil
}
