package system_test

import (
	"os"
	"path/filepath"
	"testing"
)

// installFakeDockerForSystem makes the runner's startup crash
// reconciliation hermetic for system tests that never create containers.
//
// The embedded runner fail-closes on ANY `docker ps` error (daemon down is
// not proof of absence — the correct production stance), so on a host whose
// docker CLI exists but daemon is unreachable the runner dies right after
// registration and every job waits in `queued` forever. A fresh dogfood
// stack never created a container: the shim answers ps/network/rm with
// success and empty output (proof of absence), and `info` the way this
// host's real daemon would answer a capability probe. Tests that NEED a
// real daemon keep using requireDocker and never install this shim.
func installFakeDockerForSystem(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "docker")
	body := "#!/bin/sh\ncase \"$1\" in\n  ps) exit 0;;\n  network) exit 0;;\n  info) echo cgroupfs;;\n  rm) exit 0;;\nesac\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}
