package server

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
)

// FuzzWebhookGitHub drives the GitHub webhook parser with arbitrary delivery
// bodies. Webhook parsing is a pre-authentication boundary: the payload is
// attacker-controlled bytes and the parse path must never panic.
func FuzzWebhookGitHub(f *testing.F) {
	f.Add([]byte(`{"ref":"refs/heads/main","after":"9049f1265b7d61be4a8904a9a27120d2064dab3b","repository":{"full_name":"octocat/hello-world","clone_url":"https://github.com/octocat/hello-world.git","default_branch":"main"}}`))
	f.Add([]byte(`{"action":"opened","pull_request":{"head":{"ref":"feature","sha":"abc"},"base":{"ref":"main","sha":"def"}}}`))
	f.Add([]byte("not json"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = (&forge.GitHub{}).ParseEvent(data)
	})
}

// FuzzWebhookGitLab drives the GitLab webhook parser with arbitrary delivery
// bodies. Never panics.
func FuzzWebhookGitLab(f *testing.F) {
	f.Add([]byte(`{"object_kind":"push","ref":"refs/heads/main","checkout_sha":"abc","project":{"path_with_namespace":"group/proj","git_http_url":"https://gitlab.example.com/group/proj.git","default_branch":"main"}}`))
	f.Add([]byte(`{"object_kind":"merge_request","object_attributes":{"action":"open","source_branch":"f","target_branch":"main","last_commit":{"id":"abc"},"draft":false}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = (&forge.GitLab{}).ParseEvent(data)
	})
}

// FuzzWebhookForgejo drives the Forgejo webhook parser with arbitrary
// delivery bodies. Never panics.
func FuzzWebhookForgejo(f *testing.F) {
	f.Add([]byte(`{"ref":"refs/heads/main","after":"abc","repository":{"full_name":"org/repo","clone_url":"https://code.example.org/org/repo.git"}}`))
	f.Add([]byte(`{"action":"opened","pull_request":{"head":{"ref":"f","sha":"abc"},"base":{"ref":"main","sha":"def"}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = (&forge.Forgejo{}).ParseEvent(data)
	})
}
