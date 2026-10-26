package executor

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// exeName adapts a bare tool name to the platform (PATHEXT requires an
// executable extension on Windows for a file the test creates).
func exeName(name string) string {
	if runtime.GOOS == "windows" && filepath.Ext(name) == "" {
		return name + ".exe"
	}
	return name
}

// writeExe creates an executable-looking file at path (mode 0755; on
// Windows the extension alone makes it resolvable).
func writeExe(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestResolveExecutablePathQualifiedNeverEscapesWorkDir is the P1 authority
// oracle for argv0 resolution: a path-qualified name has expressed its
// resolution domain, so a miss against the job workDir must FAIL — never
// fall through to a bare stat of the name relative to the RUNNER PROCESS's
// current directory (or to a PATH search). The decoy planted in the
// runner-CWD tree is exactly what the old fall-through executed.
func TestResolveExecutablePathQualifiedNeverEscapesWorkDir(t *testing.T) {
	runnerCWD := t.TempDir()
	work := t.TempDir()
	// Decoy beside the runner daemon: same relative shape the job asked for.
	decoy := filepath.Join(runnerCWD, "tools", exeName("compiler"))
	writeExe(t, decoy)
	// Also plant a PATH decoy so a (hypothetical) PATH fallback cannot pass.
	pathDir := t.TempDir()
	writeExe(t, filepath.Join(pathDir, exeName("compiler")))
	// The job's own copy, for the positive case.
	own := filepath.Join(work, "tools", exeName("own-tool"))
	writeExe(t, own)

	t.Chdir(runnerCWD)
	env := map[string]string{"PATH": pathDir}

	for _, rel := range []string{"./tools/" + exeName("compiler"), "tools/" + exeName("compiler")} {
		if got, err := resolveExecutable(rel, work, env); err == nil {
			t.Fatalf("resolveExecutable(%q) = %q, want failure: the name exists only beside the RUNNER, never in the workdir (authority escape)", rel, got)
		}
	}
	// Absolute miss: same rule, no CWD games.
	missingAbs := filepath.Join(work, "tools", exeName("no-such-abs"))
	if _, err := resolveExecutable(missingAbs, work, env); err == nil {
		t.Fatalf("resolveExecutable(absolute miss) = nil error, want not-found")
	}
	// Positive: a tool present in the WORKDIR resolves to the workdir path,
	// even though the runner-CWD tree has its own decoy candidates.
	got, err := resolveExecutable("./tools/"+exeName("own-tool"), work, env)
	if err != nil {
		t.Fatalf("workdir tool: %v", err)
	}
	if want := filepath.Join(work, "tools", exeName("own-tool")); got != want {
		t.Fatalf("resolved %q, want %q (workdir authority)", got, want)
	}
	// Bare names still use PATH (the other half of the contract).
	bare := exeName("bare-tool")
	writeExe(t, filepath.Join(pathDir, bare))
	got, err = resolveExecutable(bare, work, env)
	if err != nil {
		t.Fatalf("bare PATH lookup: %v", err)
	}
	if want := filepath.Join(pathDir, bare); got != want {
		t.Fatalf("bare resolve = %q, want PATH hit %q", got, want)
	}
}
