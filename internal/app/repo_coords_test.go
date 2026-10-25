package app

import "testing"

// TestRepoCoordsParsesRemoteShapes pins the coordinate derivation that is
// still live production code (the --repo flag path and, via delegation to
// workspace.RemoteRepoCoords, the freeze-time remote capture): a full URL
// keeps its host and drops scheme/.git to the owner/name full name; a bare
// owner/name defaults to GitHub. The old live detectGitRepo wrapper around
// this math is gone — RunLocal reads the remote ONCE at Freeze instead.
func TestRepoCoordsParsesRemoteShapes(t *testing.T) {
	cases := []struct {
		in, wantURL, wantFull string
	}{
		{"https://github.com/acme/widget.git", "https://github.com/acme/widget.git", "acme/widget"},
		{"https://gitlab.example.com/group/proj", "https://gitlab.example.com/group/proj", "group/proj"},
		{"acme/widget", "https://github.com/acme/widget.git", "acme/widget"},
		{"  https://github.com/x/y.git/  ", "https://github.com/x/y.git/", "x/y"},
	}
	for _, c := range cases {
		url, full := repoCoords(c.in)
		if url != c.wantURL || full != c.wantFull {
			t.Fatalf("repoCoords(%q) = (%q, %q), want (%q, %q)", c.in, url, full, c.wantURL, c.wantFull)
		}
	}
}
