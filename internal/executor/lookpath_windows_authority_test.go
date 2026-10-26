//go:build windows

package executor

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestWindowsPathQualifiedBindsToWorkDir is the Windows half of the argv0
// authority contract: relative path-qualified names (.\tools\x, tools\x)
// resolve only against the workDir, drive-absolute misses stay misses, and
// drive-relative names never fall back to the runner's CWD-on-drive. PATHEXT
// applies to path-qualified hits (.\tool → .\tool.exe) but never rescues a
// workdir miss from the runner's own directory.
func TestWindowsPathQualifiedBindsToWorkDir(t *testing.T) {
	runnerCWD := t.TempDir()
	work := t.TempDir()
	// Decoy beside the runner daemon.
	decoy := filepath.Join(runnerCWD, "tools", "tool.exe")
	writeExe(t, decoy)
	// The workdir's own tool for the positive case.
	own := filepath.Join(work, "tools", "own.exe")
	writeExe(t, own)

	t.Chdir(runnerCWD)
	env := map[string]string{
		"PATH":    runnerCWD,
		"PATHEXT": ".COM;.EXE;.BAT;.CMD",
	}

	for _, rel := range []string{`.\tools\tool`, `tools\tool`, `./tools/tool`} {
		if got, err := resolveExecutable(rel, work, env); err == nil {
			t.Fatalf("resolveExecutable(%q) = %q, want failure: decoy lives beside the runner, not in the workdir", rel, got)
		}
	}
	// Drive-absolute miss.
	if _, err := resolveExecutable(`Z:\kiwi-no-such\tool.exe`, work, env); err == nil {
		t.Fatal("missing drive-absolute path must fail")
	}
	// Drive-relative (C:tool): resolution domain is still the workDir join —
	// never a bare stat on the runner's current directory for that drive.
	if got, err := resolveExecutable(`C:tool`, work, env); err == nil {
		t.Fatalf("drive-relative resolve = %q, want failure (workdir join misses; runner-CWD must not rescue)", got)
	}
	// Positive: PATHEXT suffix applies to the workdir-bound candidate.
	got, err := resolveExecutable(`.\tools\own`, work, env)
	if err != nil {
		t.Fatalf("workdir tool with PATHEXT: %v", err)
	}
	if want := own; !strings.EqualFold(got, want) {
		t.Fatalf("resolved %q, want %q", got, want)
	}
	// Bare name still searches the effective PATH (with PATHEXT).
	bare := filepath.Join(runnerCWD, "bare.exe")
	writeExe(t, bare)
	got, err = resolveExecutable("bare", work, env)
	if err != nil {
		t.Fatalf("bare PATH lookup: %v", err)
	}
	if !strings.EqualFold(got, bare) {
		t.Fatalf("bare resolve = %q, want %q", got, bare)
	}
}

// TestWindowsShellResolutionUsesWorkDir pins the same domain for the step
// shell through the shared resolver (NativeBackend calls
// resolveExecutableIn for every shell).
func TestWindowsShellResolutionUsesWorkDir(t *testing.T) {
	work := t.TempDir()
	t.Chdir(t.TempDir()) // runner CWD with nothing in it
	shell := filepath.Join(work, "tools", "custom.exe")
	writeExe(t, shell)
	env := map[string]string{"PATH": `C:\Windows\System32`, "PATHEXT": ".COM;.EXE"}
	got, err := resolveExecutableIn(`.\tools\custom`, work, env["PATH"], env["PATHEXT"])
	if err != nil {
		t.Fatalf("shell resolve: %v", err)
	}
	if !strings.EqualFold(got, shell) {
		t.Fatalf("shell = %q, want %q", got, shell)
	}
	// Missing in workdir with nothing under the requested workdir-relative
	// path → never resolved, whatever exists beside the runner.
	t.Chdir(filepath.Dir(shell)) // runner CWD = work\tools (contains custom.exe)
	if got, err := resolveExecutableIn(`.\tools\missing`, work, env["PATH"], env["PATHEXT"]); err == nil {
		t.Fatalf("missing shell resolved to %q — escaped the workdir", got)
	} else if !strings.Contains(err.Error(), "not found relative to workdir") {
		t.Fatalf("error = %v, want workdir-bound not-found", err)
	}
}
