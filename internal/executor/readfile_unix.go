//go:build !windows

package executor

import (
	"os"
	"syscall"
)

// readFileNoFollow opens path for reading and refuses to follow a symlink in
// the final path component (O_NOFOLLOW turns that into ELOOP). This prevents
// an attacker-controlled workspace from redirecting step-output reads to
// arbitrary host files.
func readFileNoFollow(path string, maxBytes int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readCapped(f, maxBytes)
}
