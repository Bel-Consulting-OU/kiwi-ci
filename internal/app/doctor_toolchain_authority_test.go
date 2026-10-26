package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeDoctorTool writes an executable that drops marker and prints a
// version-ish line (doctor probes with --version/-v).
func writeDoctorTool(t *testing.T, path, marker, line string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/sh\n: > '" + marker + "'\necho '" + line + "'\n"
	if runtime.GOOS == "windows" {
		body = "MZ-tool"
	}
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestDoctorToolchainPathQualifiedBindsToPipelineRoot is the doctor-side
// authority oracle: `kiwi doctor --pipeline` must resolve path-qualified
// toolchain declarations against the PIPELINE'S PROJECT ROOT (the same
// domain family the executor uses for job workspaces), never against the
// doctor process's CWD. The old exec.LookPath fall-through let doctor
// certify, and execute, a same-named binary in whatever directory the
// operator happened to stand in — while every job resolved the same
// declaration inside its workspace.
func TestDoctorToolchainPathQualifiedBindsToPipelineRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("probe scripts are POSIX; the windows resolution domain is pinned by the executor authority tests")
	}
	// Project A: pipeline declares ./tools/nope, which does NOT exist in
	// the project. A decoy exists in the doctor's CWD.
	projA := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projA, ".kiwi"), 0o755); err != nil {
		t.Fatal(err)
	}
	pipeA := filepath.Join(projA, ".kiwi", "pipeline.yaml")
	pipeBody := "version: 1\njobs:\n  j:\n    steps:\n      - run: echo x\n" +
		"toolchains:\n  tc:\n    path: ./tools/" + toolExe("nope") + "\n"
	if err := os.WriteFile(pipeA, []byte(pipeBody), 0o644); err != nil {
		t.Fatal(err)
	}
	runnerCWD := t.TempDir()
	decoyMarker := filepath.Join(t.TempDir(), "decoy-doctor-ran")
	writeDoctorTool(t, filepath.Join(runnerCWD, "tools", toolExe("nope")), decoyMarker, "nope 9.9.9-decoy")

	t.Chdir(runnerCWD)
	err := doctorPipelineToolchains(pipeA, false)
	if err == nil {
		t.Fatal("doctor certified a path-qualified toolchain that does not exist in the pipeline root")
	}
	if _, mErr := os.Stat(decoyMarker); mErr == nil {
		t.Fatal("doctor executed the runner-CWD decoy during verification")
	}

	// Project B: the tool EXISTS at the pipeline root; doctor probes the
	// ROOT copy (marker lands) even though the CWD copy also exists.
	projB := t.TempDir()
	if err := os.MkdirAll(filepath.Join(projB, ".kiwi"), 0o755); err != nil {
		t.Fatal(err)
	}
	pipeB := filepath.Join(projB, ".kiwi", "pipeline.yaml")
	bodyB := strings.Replace(pipeBody, "nope", "tool", 1)
	if err := os.WriteFile(pipeB, []byte(bodyB), 0o644); err != nil {
		t.Fatal(err)
	}
	projMarker := filepath.Join(t.TempDir(), "project-tool-ran")
	writeDoctorTool(t, filepath.Join(projB, "tools", toolExe("tool")), projMarker, "tool 1.0.0-root")
	// Decoy with the same name in the CWD: doctor must pick the root copy.
	decoy2 := filepath.Join(runnerCWD, "tools", toolExe("tool"))
	writeDoctorTool(t, decoy2, decoyMarker, "tool 9.9.9-decoy")

	if err := doctorPipelineToolchains(pipeB, false); err != nil {
		t.Fatalf("doctor rejected a toolchain present at the pipeline root: %v", err)
	}
	if _, mErr := os.Stat(projMarker); mErr != nil {
		t.Fatalf("doctor never probed the pipeline-root tool: %v", mErr)
	}
	if _, mErr := os.Stat(decoyMarker); mErr == nil {
		t.Fatal("doctor probed the runner-CWD decoy instead of the pipeline-root tool")
	}
}

// toolExe adapts a bare tool name for PATHEXT on Windows (kept even though
// the test skips there, so the fixture builder stays uniform).
func toolExe(name string) string {
	if runtime.GOOS == "windows" && filepath.Ext(name) == "" {
		return name + ".exe"
	}
	return name
}
