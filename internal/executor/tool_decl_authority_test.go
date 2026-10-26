package executor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// writeProbeTool writes a tool script that drops marker (when non-empty)
// and prints a version line. On Windows a text body cannot execute, so the
// execution halves of these tests are unix-only; resolution still binds
// there (the file merely has to exist with an executable extension).
func writeProbeTool(t *testing.T, path, versionLine, marker string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/sh\n"
	if marker != "" {
		body += ": > '" + marker + "'\n"
	}
	body += "echo '" + versionLine + "'\n"
	if runtime.GOOS == "windows" {
		body = "MZ-probe"
	}
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func authorityExecutor() *Executor {
	return &Executor{
		Opt:    Options{Logs: logging.Func(func(string, string, string) {})},
		Masker: &secrets.Masker{},
	}
}

// TestBoundToolchainPathQualifiedBindsToWorkspace: a toolchains: entry that
// names a path ("./tools/go") must resolve ONLY inside the job workspace.
// The old exec.LookPath fall-through executed the verification probe against
// a same-named binary beside the runner daemon — running bytes outside the
// source authority and certifying THAT version in the attestation.
func TestBoundToolchainPathQualifiedBindsToWorkspace(t *testing.T) {
	runnerCWD := t.TempDir()
	work := t.TempDir()
	decoyMarker := filepath.Join(t.TempDir(), "decoy-probe-ran")
	// Decoy beside the runner daemon; the workspace has NO tools/go yet.
	decoy := filepath.Join(runnerCWD, "tools", exeName("go"))
	writeProbeTool(t, decoy, "go version go1.99.99-decoy", decoyMarker)

	t.Chdir(runnerCWD)
	e := authorityExecutor()
	decl := []pipeline.Toolchain{{Path: "./tools/" + exeName("go")}}

	// Missing in the workspace with a decoy beside the runner: refused
	// before any probe executes.
	err := e.checkBoundToolchains(context.Background(), "j", decl, work)
	if err == nil {
		t.Fatal("path-qualified toolchain resolved outside the workspace")
	}
	if !strings.Contains(err.Error(), "not found relative to workdir") {
		t.Fatalf("error = %v, want workdir-bound not-found", err)
	}
	if runtime.GOOS != "windows" {
		if _, mErr := os.Stat(decoyMarker); mErr == nil {
			t.Fatal("the runner-CWD decoy executed during verification — bytes outside source authority")
		}
	}

	// Present in the workspace: the probe runs the WORKSPACE copy. (On
	// Windows the test file body cannot execute, so the execution half is
	// unix-only; the miss-case above still binds the Windows contract.)
	if runtime.GOOS != "windows" {
		ownMarker := filepath.Join(t.TempDir(), "own-probe-ran")
		writeProbeTool(t, filepath.Join(work, "tools", exeName("go")), "go version go1.99.99-workspace", ownMarker)
		if err := e.checkBoundToolchains(context.Background(), "j", decl, work); err != nil {
			t.Fatalf("workspace toolchain: %v", err)
		}
		if _, mErr := os.Stat(ownMarker); mErr != nil {
			t.Fatalf("workspace tool was never probed: %v", mErr)
		}
	}
}

// TestToolFingerprintPathQualifiedBindsToWorkspace: the same domain for
// tools: fingerprints — a version gate must certify the tool the job's
// workspace holds, never a runner-CWD namesake.
func TestToolFingerprintPathQualifiedBindsToWorkspace(t *testing.T) {
	runnerCWD := t.TempDir()
	work := t.TempDir()
	decoyMarker := filepath.Join(t.TempDir(), "decoy-fingerprint-ran")
	writeProbeTool(t, filepath.Join(runnerCWD, "tools", exeName("faketool")), "faketool 9.9.9-decoy", decoyMarker)

	t.Chdir(runnerCWD)
	e := authorityExecutor()
	decl := []string{"./tools/" + exeName("faketool") + "=1.2"}

	err := e.checkToolFingerprint("j", decl, work)
	if err == nil {
		t.Fatal("path-qualified fingerprint resolved outside the workspace")
	}
	if !strings.Contains(err.Error(), "not found relative to workdir") {
		t.Fatalf("error = %v, want workdir-bound not-found", err)
	}
	if runtime.GOOS != "windows" {
		if _, mErr := os.Stat(decoyMarker); mErr == nil {
			t.Fatal("runner-CWD decoy executed for the fingerprint gate")
		}
	}

	// Workspace tool with the right version certifies (execution half is
	// unix-only; see the toolchain test above).
	if runtime.GOOS != "windows" {
		ownMarker := filepath.Join(t.TempDir(), "own-fingerprint-ran")
		writeProbeTool(t, filepath.Join(work, "tools", exeName("faketool")), "faketool 1.2.3", ownMarker)
		if err := e.checkToolFingerprint("j", decl, work); err != nil {
			t.Fatalf("workspace fingerprint: %v", err)
		}
		if _, mErr := os.Stat(ownMarker); mErr != nil {
			t.Fatalf("workspace fingerprint tool was never probed: %v", mErr)
		}
	}
}
