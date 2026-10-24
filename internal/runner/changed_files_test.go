package runner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestEffectiveChangedFilesKnownEmptyNoGitFallback (P1-23): when the
// server's changed-files list is marked KNOWN, an empty list stays empty —
// the runner must not fall back to a local git diff (which is absent here:
// the fake git would fail loudly if invoked). The git fallback only
// applies when the list is NOT known.
func TestEffectiveChangedFilesKnownEmptyNoGitFallback(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "git-invoked")
	withFakeGit(t, marker, func() {
		// Known-empty: no git invocation, empty result.
		got, known := effectiveChangedFiles(context.Background(), nil, true, dir)
		if len(got) != 0 || !known {
			t.Fatalf("known-empty with nil = %v known=%v", got, known)
		}
		got, known = effectiveChangedFiles(context.Background(), []string{}, true, dir)
		if len(got) != 0 || !known {
			t.Fatalf("known-empty with empty list = %v known=%v", got, known)
		}
		// Known non-empty: returned as-is, no git call.
		got, known = effectiveChangedFiles(context.Background(), []string{"a.go"}, true, dir)
		if len(got) != 1 || got[0] != "a.go" || !known {
			t.Fatalf("known non-empty = %v", got)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("known lists must never invoke git")
		}
		// Unknown with a non-empty server list: no git call either.
		got, known = effectiveChangedFiles(context.Background(), []string{"b.go"}, false, dir)
		if len(got) != 1 || got[0] != "b.go" || !known {
			t.Fatalf("unknown non-empty = %v", got)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("non-empty unknown lists must not invoke git")
		}
		// Unknown with an EMPTY list: the fallback path runs git.
		got, known = effectiveChangedFiles(context.Background(), nil, false, dir)
		if _, err := os.Stat(marker); err != nil {
			t.Fatal("unknown empty list must fall back to the local git diff")
		}
		// Fake git exits 0 with no output: diff succeeded but is empty.
		if !known {
			// fake git produced no error path for HEAD~1... actually exit 0 empty => known true
			t.Fatalf("empty successful git diff should be known, got files=%v known=%v", got, known)
		}
	})
}

// withFakeGit installs a fake `git` executable in PATH that records its
// invocation to the marker file and exits 0 with no output.
func withFakeGit(t *testing.T, marker string, fn func()) {
	t.Helper()
	bin := t.TempDir()
	var name, script string
	if runtime.GOOS == "windows" {
		// .bat is resolved through PATHEXT; cmd.exe writes the marker.
		name = "git.bat"
		script = "@echo off\r\necho invoked> \"" + marker + "\"\r\nexit /b 0\r\n"
	} else {
		name = "git"
		script = "#!/bin/sh\ntouch '" + marker + "'\nexit 0\n"
	}
	if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := os.Getenv("PATH")
	t.Setenv("PATH", bin+string(filepath.ListSeparator)+old)
	fn()
}
