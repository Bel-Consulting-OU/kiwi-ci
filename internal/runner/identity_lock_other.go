//go:build !unix

package runner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// acquireRunnerIdentityLock takes an exclusive <IdentityDir>/runner.lock via
// O_EXCL on platforms without flock. A lock whose recorded PID is no longer
// alive is reclaimed; a live PID refuses the duplicate identity. Stale locks
// from a process the OS cannot prove dead require manual removal (documented).
func acquireRunnerIdentityLock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, identityDirMode); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "runner.lock")
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
			return func() {
				_ = f.Close()
				_ = os.Remove(path)
			}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create runner identity lock: %w", err)
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, fmt.Errorf("runner identity %s is already active in another process; refusing to start a duplicate", dir)
		}
		pid, perr := strconv.Atoi(strings.TrimSpace(string(b)))
		if perr == nil && pid > 0 && processAlive(pid) {
			return nil, fmt.Errorf("runner identity %s is already active in process %d; refusing to start a duplicate", dir, pid)
		}
		_ = os.Remove(path)
	}
	return nil, fmt.Errorf("runner identity lock %s could not be acquired", path)
}
