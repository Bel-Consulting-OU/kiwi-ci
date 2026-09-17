package executor

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// nativeScript returns the POSIX script on Unix hosts and the PowerShell
// script on Windows hosts. Tests that drive the native backend through a
// real shell use it so the same fixture runs on both host families without
// POSIX-only tools (test, touch, dd, ln).
func nativeScript(posix, windows string) string {
	if runtime.GOOS == "windows" {
		return windows
	}
	return posix
}

// writeBytesScript returns a native-shell one-liner that writes a file of n
// zero bytes at path (the `dd if=/dev/zero` equivalent for both host
// families).
func writeBytesScript(path string, n int) string {
	return nativeScript(
		"dd if=/dev/zero of="+path+" bs="+strconv.Itoa(n)+" count=1 2>/dev/null",
		fmt.Sprintf("[IO.File]::WriteAllBytes('%s', [byte[]]::new(%d))", path, n),
	)
}

// yamlRun renders a native-shell script as a YAML single-quoted scalar so
// embedded colons, backslashes, quotes, redirections and PowerShell syntax
// can never break the pipeline parser on any platform.
func yamlRun(script string) string {
	return "'" + strings.ReplaceAll(script, "'", "''") + "'"
}

// TestYAMLRunEmbedsWindowsScripts proves every known Windows script fixture
// stays parseable when embedded into a pipeline (the PowerShell forms carry
// colons, backslashes and quotes that break plain YAML scalars). The parse
// runs on every host; only the script choice is platform-specific.
func TestYAMLRunEmbedsWindowsScripts(t *testing.T) {
	scripts := []string{
		`"TOKEN=$env:KIWI_SECRET_TOKEN" | Out-File -Encoding utf8 $env:KIWI_OUTPUT`,
		fmt.Sprintf("[IO.File]::WriteAllBytes('%s', [byte[]]::new(%d))", `.kiwi-output-1`, 1048577),
		`echo "token is $env:KIWI_SECRET_STEP_A"`,
		`Set-Content -LiteralPath 'probe.txt' -Value $env:CI`,
		`$v = [Environment]::GetEnvironmentVariable('KIWI_RUNNER_TOKEN'); if ($v) { exit 9 }`,
	}
	for i, script := range scripts {
		src := "version: 1\njobs:\n  probe:\n    runtime: container\n    image: alpine\n    steps:\n      - run: " + yamlRun(script) + "\n"
		s, err := pipeline.Parse([]byte(src))
		if err != nil {
			t.Fatalf("script %d: parse: %v", i, err)
		}
		got := s.Jobs["probe"].Steps[0].Run
		if got != script {
			t.Fatalf("script %d round trip = %q, want %q", i, got, script)
		}
	}
}
