package giturl

import "testing"

// TestParseCloneURLFormTable is the shared-parser contract the server and the
// runner both rely on: every accepted form must be accepted identically on
// both sides (this table is also exercised end-to-end by the runner's
// gitEnvForRepo tests).
func TestParseCloneURLFormTable(t *testing.T) {
	cases := []struct {
		raw    string
		host   string
		path   string
		scheme string
		ok     bool
	}{
		{"https://github.com/acme/repo.git", "github.com", "acme/repo", "https", true},
		{"https://GitHub.COM/acme/repo", "github.com", "acme/repo", "https", true},
		{"https://github.com:443/acme/repo", "github.com", "acme/repo", "https", true},
		{"ssh://git@github.com/acme/repo.git", "github.com", "acme/repo", "ssh", true},
		{"git@github.com:acme/repo.git", "github.com", "acme/repo", "ssh", true},
		{"git@gitlab.example.com:group/sub/repo", "gitlab.example.com", "group/sub/repo", "ssh", true},
		{"http://127.0.0.1/acme/repo", "127.0.0.1", "acme/repo", "http", true},
		{"http://example.com/acme/repo", "", "", "", false},
		{"https://user:pass@github.com/acme/repo", "", "", "", false},
		{"https://github.com/acme/repo?x=1", "", "", "", false},
		{"https://github.com/acme/repo#frag", "", "", "", false},
		{"file:///acme/repo", "", "", "", false},
		{"-oProxyCommand=evil", "", "", "", false},
		{"https://github.com/a//b", "", "", "", false},
		{"https://github.com/../etc", "", "", "", false},
	}
	for _, tc := range cases {
		host, path, scheme, err := ParseCloneURL(tc.raw)
		if tc.ok {
			if err != nil || host != tc.host || path != tc.path || scheme != tc.scheme {
				t.Errorf("%q = (%q,%q,%q,%v), want (%q,%q,%q)", tc.raw, host, path, scheme, err, tc.host, tc.path, tc.scheme)
			}
			continue
		}
		if err == nil {
			t.Errorf("%q accepted, want rejection", tc.raw)
		}
	}
}

// TestCanonicalHostMatchesAuth pins that both spellings of one host collapse
// (the auth implementation is the reference; giturl delegates to it).
func TestCanonicalHostMatchesAuth(t *testing.T) {
	for _, raw := range []string{"GITHUB.COM", "github.com.", "github.com:443", "https://GitHub.com:443/x", "git@github.com:acme/repo.git"} {
		if got := CanonicalHost(raw); got != "github.com" {
			t.Errorf("CanonicalHost(%q) = %q, want github.com", raw, got)
		}
	}
	if got := CanonicalHost("github.com:8443"); got != "github.com:8443" {
		t.Errorf("non-default port must survive: %q", got)
	}
}
