package executor

import (
	"context"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSecurityOptionsRootless(t *testing.T) {
	cases := []struct {
		report string
		want   bool
	}{
		{"[name=rootless]", true},
		{"[name=seccomp,profile=builtin name=rootless]", true},
		{"name=seccomp,profile=builtin name=rootless", true},
		{"[name=seccomp,profile=builtin]", false},
		{"", false},
		{"name=apparmor", false},
	}
	for _, tc := range cases {
		if got := securityOptionsRootless(tc.report); got != tc.want {
			t.Errorf("securityOptionsRootless(%q) = %t, want %t", tc.report, got, tc.want)
		}
	}
}

// TestRequireRootlessDaemonRunsTheCheckWithAFakeDocker drives the real
// requireRootlessDaemon function through a fake docker binary: a non-rootless
// security-options report must refuse, a rootless one must pass.
func TestRequireRootlessDaemonRunsTheCheckWithAFakeDocker(t *testing.T) {
	testutil.UnixShell(t)
	if runtime.GOOS == "windows" {
		t.Skip("fake docker script is a POSIX shell script")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "docker")

	writeFake := func(report string) {
		script := "#!/bin/sh\nif [ \"$1\" = \"info\" ]; then printf '%s\\n' '" + strings.ReplaceAll(report, "'", "") + "'; exit 0; fi\necho unexpected args >&2\nexit 1\n"
		if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Rootful daemon: rootless-absent must be refused with an infra error
	// naming the security options.
	writeFake("[name=seccomp,profile=builtin]")
	err := requireRootlessDaemon(context.Background(), fake)
	if err == nil {
		t.Fatal("rootful daemon accepted for a rootless job")
	}
	if !strings.Contains(err.Error(), "not rootless") {
		t.Fatalf("error = %q, want rootless refusal", err)
	}
	re, ok := err.(*RunError)
	if !ok || re.Kind != ErrorInfra {
		t.Fatalf("refusal is not an infra error: %T %v", err, err)
	}

	// Rootless daemon: check passes.
	writeFake("[name=rootless]")
	if err := requireRootlessDaemon(context.Background(), fake); err != nil {
		t.Fatalf("rootless daemon rejected: %v", err)
	}

	// Broken daemon: the docker info failure is surfaced.
	writeFake("")
	script := "#!/bin/sh\nexit 1\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := requireRootlessDaemon(context.Background(), fake); err == nil || !strings.Contains(err.Error(), "inspect docker daemon") {
		t.Fatalf("docker info failure not surfaced: %v", err)
	}
}
