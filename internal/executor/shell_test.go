package executor

import (
	"runtime"
	"testing"
)

// TestDefaultShell locks the per-runtime-kind shell fallback: containers run
// sh, Tart guests run bash, and native hosts run pwsh on Windows and bash
// elsewhere. The "" kind is the implicit native runtime.
func TestDefaultShell(t *testing.T) {
	want := map[string]string{
		"container": "sh",
		"tart":      "bash",
		"native":    "bash",
		"":          "bash",
	}
	if runtime.GOOS == "windows" {
		want["native"] = "pwsh"
		want[""] = "pwsh"
	}
	for kind, w := range want {
		if got := defaultShell(kind); got != w {
			t.Errorf("defaultShell(%q) = %q, want %q", kind, got, w)
		}
	}
}
