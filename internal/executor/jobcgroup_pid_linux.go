//go:build linux

package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func writePIDToJobCgroup(parent string, pid int) error {
	if !strings.HasPrefix(parent, "/") || strings.Contains(parent, "..") {
		return fmt.Errorf("refusing to add pid to malformed cgroup %q", parent)
	}
	root := jobCgroupRoot()
	dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(parent, "/")))
	return os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)+"\n"), 0o644)
}
