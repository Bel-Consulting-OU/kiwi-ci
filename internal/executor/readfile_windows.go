//go:build windows

package executor

import (
	"fmt"
	"os"
)

// readFileNoFollow opens path for reading and refuses symlinks. Windows has
// no O_NOFOLLOW, so the final component is checked with Lstat before the open
// (best-effort; a concurrent swap between check and open is mitigated by the
// workspace cleanup model).
func readFileNoFollow(path string, maxBytes int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to follow symlink: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readCapped(f, maxBytes)
}
