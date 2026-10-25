package executor

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestResolveExecutableRelativeUsesWorkDir pins the Go Cmd.Dir contract:
// a relative path with a separator resolves against the execution
// directory, not the runner process CWD.
func TestResolveExecutableRelativeUsesWorkDir(t *testing.T) {
	work := t.TempDir()
	binDir := filepath.Join(work, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(binDir, "tool")
	if runtime.GOOS == "windows" {
		tool += ".exe"
	}
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"PATH": "/usr/bin:/bin"}
	got, err := resolveExecutable("./bin/tool", work, env)
	if err != nil {
		t.Fatalf("resolveExecutable: %v", err)
	}
	want := filepath.Join(work, "bin", "tool")
	if runtime.GOOS == "windows" {
		want += ".exe"
	}
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// TestResolveExecutableUsesMergedServicePATH: a service whose Env changes
// PATH must resolve against that PATH, not only baseEnv.
func TestResolveExecutableUsesMergedServicePATH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix PATH layout")
	}
	svcDir := t.TempDir()
	tool := filepath.Join(svcDir, "svc-tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	base := map[string]string{"PATH": "/usr/bin:/bin"}
	merged := mergeEnvMap(base, map[string]string{"PATH": svcDir})
	got, err := resolveExecutable("svc-tool", t.TempDir(), merged)
	if err != nil {
		t.Fatalf("resolveExecutable: %v", err)
	}
	if got != tool {
		t.Fatalf("got %q want %q", got, tool)
	}
	// Without the merge the binary must not resolve from base PATH alone.
	if _, err := resolveExecutable("svc-tool", t.TempDir(), base); err == nil {
		t.Fatal("base PATH alone must not resolve a svc-only binary")
	}
}

// TestWindowsEnvMergeCaseInsensitive: Path= and PATH= collapse to one entry.
func TestWindowsEnvMergeCaseInsensitive(t *testing.T) {
	if runtime.GOOS != "windows" {
		// Exercise the same contract via envKeyCanon on windows only; on
		// Unix keys keep case (documented divergence).
		m := mergeEnvMap(map[string]string{"Path": "a"}, map[string]string{"PATH": "b"})
		if m["Path"] != "a" || m["PATH"] != "b" {
			t.Fatalf("unix merge must keep both keys: %v", m)
		}
		return
	}
	m := mergeEnvMap(map[string]string{"Path": `C:\host`}, map[string]string{"PATH": `C:\job`})
	if len(m) != 1 {
		t.Fatalf("windows merge must collapse case variants: %v", m)
	}
	if envValueFold(m, "PATH") != `C:\job` {
		t.Fatalf("later PATH must win: %v", m)
	}
}
