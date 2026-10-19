package executor

import (
	"testing"
)

// TestShellCommandDoesNotLogin: K2 — `-lc` sources /etc/profile and resets
// the image's ENV PATH (rust's /usr/local/cargo/bin vanishes). The engine
// must use -c so a digest-pinned image's PATH stands.
func TestShellCommandDoesNotLogin(t *testing.T) {
	got := shellCommand("bash", "echo hi")
	if len(got) < 3 {
		t.Fatalf("shellCommand = %v", got)
	}
	if got[1] == "-lc" || got[1] == "-l" {
		t.Fatalf("login shell %q would clobber image PATH: %v", got[1], got)
	}
	if got[1] != "-c" {
		t.Fatalf("want -c, got %q", got[1])
	}
	// sh and dash the same
	for _, sh := range []string{"sh", "dash", "zsh"} {
		got := shellCommand(sh, "x")
		if got[1] != "-c" {
			t.Fatalf("%s: want -c, got %q", sh, got[1])
		}
	}
	// pwsh keeps -NoProfile
	got = shellCommand("pwsh", "x")
	if got[1] != "-NoProfile" {
		t.Fatalf("pwsh = %v", got)
	}
}

// TestContainerSafeEnvKeepsImageTools: the engine must not inject PATH at
// all into a container step — the image's own PATH is the toolchain.
func TestContainerSafeEnvDropsPath(t *testing.T) {
	out := containerSafeEnv(map[string]string{
		"PATH": "/usr/local/bin:/usr/bin:/bin",
		"CI":   "true",
	})
	if _, ok := out["PATH"]; ok {
		t.Fatal("PATH must not be injected into container env")
	}
	if out["CI"] != "true" {
		t.Fatal("CI dropped")
	}
}
