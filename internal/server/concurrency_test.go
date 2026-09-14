package server

import "testing"

// TestExpandConcurrency covers the expression-engine-backed concurrency
// group expansion, including the previously broken
// "${{ repo }}:${{ branch }}" example.
func TestExpandConcurrency(t *testing.T) {
	in := SubmitRun{
		RepoURL:      "https://git.example.com/acme/kilo.git",
		RepoFullName: "acme/kilo",
		Ref:          "refs/heads/main",
		SHA:          "abc123def456",
		Event:        "push",
	}
	cases := []struct {
		name string
		src  string
		want string
		ref  string
	}{
		{"plain group", "deploy", "deploy", "refs/heads/main"},
		{"repo and branch example", "${{ repo }}:${{ branch }}", "https://git.example.com/acme/kilo.git:main", "refs/heads/main"},
		{"repo full name", "${{ repo.full_name }}", "acme/kilo", "refs/heads/main"},
		{"git branch", "${{ git.branch }}", "main", "refs/heads/main"},
		{"git ref", "${{ git.ref }}", "refs/heads/main", "refs/heads/main"},
		{"git sha", "${{ git.sha }}", "abc123def456", "refs/heads/main"},
		{"event", "${{ event }}", "push", "refs/heads/main"},
		{"ref", "${{ ref }}", "refs/heads/main", "refs/heads/main"},
		{"sha", "${{ sha }}", "abc123def456", "refs/heads/main"},
		{"tight braces", "${{repo}}/${{branch}}", "https://git.example.com/acme/kilo.git/main", "refs/heads/main"},
		{"mixed", "env:${{ branch }}-${{ sha }}", "env:main-abc123def456", "refs/heads/main"},
		{"tag ref has empty branch", "${{ branch }}", "", "refs/tags/v1.0.0"},
		{"bare ref is the branch", "${{ branch }}", "main", "main"},
		{"unresolved hole stays literal", "${{ matrix.GO }}", "${{ matrix.GO }}", "refs/heads/main"},
		{"unknown context stays literal", "${{ github.sha }}", "${{ github.sha }}", "refs/heads/main"},
		{"unterminated hole stays literal", "pre ${{ repo", "pre ${{ repo", "refs/heads/main"},
		{"whitespace trimmed", "  ${{ repo }}  ", "https://git.example.com/acme/kilo.git", "refs/heads/main"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := in
			in.Ref = tc.ref
			if got := expandConcurrency(tc.src, in); got != tc.want {
				t.Errorf("expandConcurrency(%q) = %q, want %q", tc.src, got, tc.want)
			}
		})
	}
}
