//go:build !unix

package runner

import "os"

// processAlive reports whether the PID appears live. Without a portable
// signal-0, a process that cannot be found is treated as alive so a stale
// lock is never force-broken while the owner might still exist.
func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil || p == nil {
		return false
	}
	return true
}
