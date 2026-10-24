//go:build !windows

package runner

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// reclaimNativeServices kills leftover native-service process groups from a
// previous runner incarnation, but only when the recorded start stamp still
// matches (PID-reuse guard).
func reclaimNativeServices(svcs []NativeServiceLedger) error {
	var firstErr error
	for _, ns := range svcs {
		if ns.PID <= 0 {
			continue
		}
		if ns.Start != "" {
			if stamp := processStartStamp(ns.PID); stamp != "" && stamp != ns.Start {
				continue
			}
		}
		if ns.PGID > 1 {
			_ = syscall.Kill(-ns.PGID, syscall.SIGKILL)
		}
		if err := syscall.Kill(ns.PID, syscall.SIGKILL); err != nil && err != syscall.ESRCH && firstErr == nil {
			firstErr = fmt.Errorf("kill native service %s pid %d: %w", ns.Name, ns.PID, err)
		}
	}
	return firstErr
}

func processStartStamp(pid int) string {
	if pid <= 0 {
		return ""
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		s := string(b)
		if i := strings.LastIndex(s, ")"); i >= 0 {
			fields := strings.Fields(s[i+1:])
			if len(fields) > 19 {
				return "t:" + fields[19]
			}
		}
	}
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "start=").Output()
	if err == nil {
		return "ps:" + strings.TrimSpace(string(out))
	}
	return ""
}
