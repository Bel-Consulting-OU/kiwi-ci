package runner

import (
	"os"
	"path/filepath"
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
		got := effectiveChangedFiles(nil, true, dir)
		if len(got) != 0 {
			t.Fatalf("known-empty with nil = %v, want empty", got)
		}
		got = effectiveChangedFiles([]string{}, true, dir)
		if len(got) != 0 {
			t.Fatalf("known-empty with empty list = %v, want empty", got)
		}
		// Known non-empty: returned as-is, no git call.
		got = effectiveChangedFiles([]string{"a.go"}, true, dir)
		if len(got) != 1 || got[0] != "a.go" {
			t.Fatalf("known non-empty = %v", got)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("known lists must never invoke git")
		}
		// Unknown with a non-empty server list: no git call either.
		got = effectiveChangedFiles([]string{"b.go"}, false, dir)
		if len(got) != 1 || got[0] != "b.go" {
			t.Fatalf("unknown non-empty = %v", got)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("non-empty unknown lists must not invoke git")
		}
		// Unknown with an EMPTY list: the fallback path runs git.
		got = effectiveChangedFiles(nil, false, dir)
		if _, err := os.Stat(marker); err != nil {
			t.Fatal("unknown empty list must fall back to the local git diff")
		}
		_ = got
	})
}

// withFakeGit installs a fake `git` executable in PATH that records its
// invocation to the marker file and exits 0 with no output.
func withFakeGit(t *testing.T, marker string, fn func()) {
	t.Helper()
	bin := t.TempDir()
	script := "#!/bin/sh\ntouch '" + marker + "'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := os.Getenv("PATH")
	t.Setenv("PATH", bin+":"+old)
	fn()
}
