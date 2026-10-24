package executor

import (
	"runtime"
	"strings"
	"testing"
)

func TestCleanExecutionEnvHasResolvablePATH(t *testing.T) {
	m := cleanExecutionEnv()
	path, ok := m["PATH"]
	if !ok || path == "" {
		t.Fatal("cleanExecutionEnv missing PATH")
	}
	if runtime.GOOS == "windows" {
		if !strings.Contains(path, ";") {
			t.Fatalf("windows PATH must use ';': %q", path)
		}
		if m["PATHEXT"] == "" {
			t.Fatal("windows clean env missing PATHEXT")
		}
	} else if strings.Contains(path, ";") && !strings.Contains(path, ":") {
		t.Fatalf("unix PATH looks windows-shaped: %q", path)
	}
}
