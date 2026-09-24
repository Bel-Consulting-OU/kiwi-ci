package giturl

import "testing"

// TestParseCloneURLRejectionBranches drives each rejection branch of the
// shared strict parser that the form table does not already exercise: empty
// input, a malformed URL, a URL with no host, unsafe schemes/users, and the
// scp-style host/colon rules.
func TestParseCloneURLRejectionBranches(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"malformed url escape", "https://github.com/%zz"},
		{"url without host", "https:///owner/repo"},
		{"scp without at", "github.com:owner/repo"},
		{"scp wrong user", "bob@github.com:owner/repo"},
		{"scp without colon", "git@github.com"},
		{"scp bad path", "git@github.com:../etc"},
		{"ssh url with a non-git user", "ssh://bob@github.com/acme/repo"},
		{"ssh url with a password", "ssh://git:pw@github.com/acme/repo"},
	}
	for _, tc := range cases {
		if host, path, scheme, err := ParseCloneURL(tc.raw); err == nil {
			t.Errorf("%s: ParseCloneURL(%q) = (%q,%q,%q), want error", tc.name, tc.raw, host, path, scheme)
		}
	}
}

// TestCleanPathBranches pins the internal path normalizer's rejection and
// normalization branches directly.
func TestCleanPathBranches(t *testing.T) {
	ok := []struct {
		in, want string
	}{
		{"acme/repo", "acme/repo"},
		{"/acme/repo/", "acme/repo"},
		{"acme/repo.git", "acme/repo"},
		{"/group/sub/repo.GIT", "group/sub/repo"},
	}
	for _, tc := range ok {
		got, err := cleanPath(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("cleanPath(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, in := range []string{"//acme/repo", "", "/", "a//b", "a/./b", "a/../b"} {
		if got, err := cleanPath(in); err == nil {
			t.Errorf("cleanPath(%q) = %q, want error", in, got)
		}
	}
}

// TestForgePathFromFullName covers the legacy full-name-to-path helper: an
// empty name, a URL/scp spelling (including a rejected one), and a plain
// owner/name path.
func TestForgePathFromFullName(t *testing.T) {
	if p, ok := ForgePathFromFullName("  "); ok || p != "" {
		t.Fatalf("ForgePathFromFullName(blank) = %q, %v; want \"\", false", p, ok)
	}
	if p, ok := ForgePathFromFullName("https://github.com/acme/repo.git"); !ok || p != "acme/repo" {
		t.Fatalf("URL spelling = %q, %v; want acme/repo, true", p, ok)
	}
	if p, ok := ForgePathFromFullName("git@github.com:group/sub/repo"); !ok || p != "group/sub/repo" {
		t.Fatalf("scp spelling = %q, %v; want group/sub/repo, true", p, ok)
	}
	if p, ok := ForgePathFromFullName("https://github.com/%zz"); ok || p != "" {
		t.Fatalf("malformed URL spelling = %q, %v; want \"\", false", p, ok)
	}
	if p, ok := ForgePathFromFullName(".."); ok || p != "" {
		t.Fatalf("traversal name = %q, %v; want \"\", false", p, ok)
	}
	if p, ok := ForgePathFromFullName("acme/repo"); !ok || p != "acme/repo" {
		t.Fatalf("plain name = %q, %v; want acme/repo, true", p, ok)
	}
}

// TestIsLoopbackHostNames pins the exact loopback rule: only "localhost" and
// genuine loopback IP literals qualify; lookalike names do not.
func TestIsLoopbackHostNames(t *testing.T) {
	trueCases := []string{"localhost", "LOCALHOST", "127.0.0.1", "::1", " 127.0.0.1 "}
	for _, h := range trueCases {
		if !IsLoopbackHost(h) {
			t.Errorf("IsLoopbackHost(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"", "127.evil.example", "example.com", "localhost.evil"} {
		if IsLoopbackHost(h) {
			t.Errorf("IsLoopbackHost(%q) = true, want false", h)
		}
	}
}
