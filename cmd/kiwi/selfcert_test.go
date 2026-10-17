package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot returns the repository root (two levels above cmd/kiwi).
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// TestKiwiSelfCertificationIsHermetic proves the product can load and
// interpret its own certification pipeline without any pre-built workspace
// artifact. The executable is built into t.TempDir(): `go test ./...` must
// never depend on dist/kiwi or any other checkout-side binary.
//
// This is integration behavior ("Kiwi launches and understands
// .kiwi/certify.yaml"), not a unit property of a single function — it is
// kept here so the ordinary unit lane still guards the self-cert contract
// without a separate bootstrap step.
func TestKiwiSelfCertificationIsHermetic(t *testing.T) {
	if testing.Short() {
		t.Skip("short: builds a real kiwi binary")
	}
	root := repoRoot(t)
	certify := filepath.Join(root, ".kiwi", "certify.yaml")
	if _, err := os.Stat(certify); err != nil {
		t.Fatalf("self-certification pipeline missing: %v", err)
	}

	bin := filepath.Join(t.TempDir(), "kiwi")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(root, "cmd", "kiwi")
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build kiwi: %v\n%s", err, out)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("built binary missing: %v", err)
	}

	// Interpret the certification DAG with the product. validate is the
	// cheap in-process check; a full run is covered by the kiwi-certify
	// workflow (and needs a longer timeout).
	validate := exec.Command(bin, "validate", "-f", certify)
	validate.Dir = root
	validate.Env = os.Environ()
	out, err := validate.CombinedOutput()
	if err != nil {
		t.Fatalf("kiwi validate .kiwi/certify.yaml: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "valid:") {
		t.Fatalf("validate output missing success marker: %s", out)
	}
}

// TestReleaseGateWorkflowHasBalancedShellQuotes guards the release-gate
// workflow's inline shell. A missing closing quote made the Release Gate
// unrunnable ("unexpected EOF while looking for matching `\"'") and also
// failed actionlint. The test extracts the run: | blocks and syntax-checks
// them with bash -n so the next unbalanced quote cannot ship.
func TestReleaseGateWorkflowHasBalancedShellQuotes(t *testing.T) {
	path := filepath.Join(repoRoot(t), ".github", "workflows", "release-gate.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	scripts := extractRunScripts(string(raw))
	if len(scripts) == 0 {
		t.Fatal("release-gate.yml has no run: | blocks")
	}
	for i, script := range scripts {
		cmd := exec.Command("bash", "-n")
		cmd.Stdin = strings.NewReader(script)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("run block %d has a shell syntax error: %v\n%s\n---\n%s", i, err, out, script)
		}
	}
}

// extractRunScripts returns the indented bodies of every `run: |` block.
func extractRunScripts(yaml string) []string {
	var scripts []string
	lines := strings.Split(yaml, "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed != "run: |" && !strings.HasPrefix(trimmed, "run: |") {
			continue
		}
		indent := len(lines[i]) - len(strings.TrimLeft(lines[i], " "))
		var body []string
		for i+1 < len(lines) {
			i++
			line := lines[i]
			if strings.TrimSpace(line) == "" {
				body = append(body, "")
				continue
			}
			lineIndent := len(line) - len(strings.TrimLeft(line, " "))
			if lineIndent <= indent {
				i--
				break
			}
			body = append(body, line[indent+2:])
		}
		scripts = append(scripts, strings.Join(body, "\n"))
	}
	return scripts
}

// TestSelfCertGofmtUsesSameToolchain pins the gofmt step to the gofmt that
// belongs to the `go` on PATH. A PATH reset could pair a newer go.mod
// toolchain with an older /usr/local/go/bin/gofmt and report files that the
// CI gofmt job (setup-go's toolchain) does not see.
func TestSelfCertGofmtUsesSameToolchain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".kiwi", "certify.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "gofmt") {
		t.Fatal("certify.yaml lost its gofmt gate")
	}
	// The invocation must resolve gofmt next to `go`, not a bare PATH lookup.
	if !strings.Contains(s, `GOFMT="$(dirname "$(command -v go)")/gofmt"`) {
		t.Fatalf("gofmt step is not pinned to the go toolchain:\n%s", s)
	}
}
