package runner

import (
	"strings"
	"testing"
	"time"

	"github.com/kiwici/kiwi/internal/server"
)

func TestHeartbeatTick(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	t.Run("error keeps deadline", func(t *testing.T) {
		deadline := now.Add(45 * time.Second)
		nd, cancel := heartbeatTick(now, deadline, nil, errBoom())
		if cancel {
			t.Fatal("must not cancel with time remaining")
		}
		if !nd.Equal(deadline) {
			t.Fatalf("deadline moved on error: %v -> %v", deadline, nd)
		}
	})
	t.Run("deadline approach cancels", func(t *testing.T) {
		deadline := now.Add(1500 * time.Millisecond)
		nd, cancel := heartbeatTick(now, deadline, nil, nil)
		if !cancel {
			t.Fatal("must cancel within 2s of deadline")
		}
		if !nd.Equal(deadline) {
			t.Fatalf("deadline must not move: %v -> %v", deadline, nd)
		}
	})
	t.Run("success extends deadline", func(t *testing.T) {
		deadline := now.Add(45 * time.Second)
		newDeadline := now.Add(90 * time.Second)
		nd, cancel := heartbeatTick(now, deadline, &server.HeartbeatResponse{LeaseExpiresAt: newDeadline}, nil)
		if cancel {
			t.Fatal("must not cancel on success")
		}
		if !nd.Equal(newDeadline) {
			t.Fatalf("deadline not extended: %v -> %v", newDeadline, nd)
		}
	})
	t.Run("server cancel request", func(t *testing.T) {
		deadline := now.Add(45 * time.Second)
		nd, cancel := heartbeatTick(now, deadline, &server.HeartbeatResponse{Cancel: true, LeaseExpiresAt: now.Add(time.Hour)}, nil)
		if !cancel {
			t.Fatal("must cancel when server requests it")
		}
		if !nd.Equal(deadline) {
			t.Fatalf("deadline must not move on cancel: %v", nd)
		}
	})
	t.Run("error near deadline cancels", func(t *testing.T) {
		deadline := now.Add(time.Second)
		_, cancel := heartbeatTick(now, deadline, nil, errBoom())
		if !cancel {
			t.Fatal("unreachable control plane must self-cancel before lease expiry")
		}
	})
}

type boom struct{}

func (boom) Error() string { return "boom" }

func errBoom() error { return boom{} }

func TestGitEnvForRepo(t *testing.T) {
	t.Setenv("KIWI_ALLOW_INSECURE_CLONE", "")
	t.Setenv("KIWI_GIT_ALLOWED_SSH_HOSTS", "")
	t.Setenv("KIWI_GIT_ALLOWED_HTTPS_HOSTS", "")
	t.Setenv("KIWI_GIT_TOKEN_GITHUB_COM", "ghp-token")
	t.Setenv("KIWI_GIT_TOKEN_OTHER_TOKEN", "leaky")

	hasEnv := func(env []string, name string) bool {
		for _, kv := range env {
			if strings.HasPrefix(kv, name+"=") {
				return true
			}
		}
		return false
	}
	envValue := func(env []string, name string) string {
		for _, kv := range env {
			if strings.HasPrefix(kv, name+"=") {
				return strings.TrimPrefix(kv, name+"=")
			}
		}
		return ""
	}

	t.Run("https github allowed with host-scoped config", func(t *testing.T) {
		env, err := gitEnvForRepo("https://github.com/kiwi/repo.git", []string{"PATH=/bin", "KIWI_GIT_TOKEN_OTHER_TOKEN=leaky", "KIWI_GIT_TOKEN_GITHUB_COM=ghp-token"})
		if err != nil {
			t.Fatal(err)
		}
		if envValue(env, "GIT_CONFIG_KEY_0") != "http.https://github.com/.extraHeader" {
			t.Fatalf("config key not host-scoped: %q", envValue(env, "GIT_CONFIG_KEY_0"))
		}
		if envValue(env, "GIT_CONFIG_VALUE_0") != "Authorization: Bearer ghp-token" {
			t.Fatalf("token not injected: %q", envValue(env, "GIT_CONFIG_VALUE_0"))
		}
		if envValue(env, "GIT_CONFIG_COUNT") != "1" {
			t.Fatalf("GIT_CONFIG_COUNT missing")
		}
		// Tokens never leak into the environment, even unrelated ones.
		if hasEnv(env, "KIWI_GIT_TOKEN_OTHER_TOKEN") || hasEnv(env, "KIWI_GIT_TOKEN_GITHUB_COM") {
			t.Fatal("KIWI_GIT_TOKEN_* leaked into job environment")
		}
		if !hasEnv(env, "PATH") {
			t.Fatal("host environment not preserved")
		}
	})

	t.Run("http non-loopback rejected", func(t *testing.T) {
		if _, err := gitEnvForRepo("http://evil.example/repo.git", nil); err == nil {
			t.Fatal("expected rejection")
		}
	})
	t.Run("http loopback requires opt-in", func(t *testing.T) {
		if _, err := gitEnvForRepo("http://127.0.0.1/repo.git", nil); err == nil {
			t.Fatal("expected rejection without opt-in")
		}
		t.Setenv("KIWI_ALLOW_INSECURE_CLONE", "1")
		if _, err := gitEnvForRepo("http://127.0.0.1/repo.git", nil); err != nil {
			t.Fatalf("loopback with opt-in should be allowed: %v", err)
		}
	})
	t.Run("file and git schemes rejected", func(t *testing.T) {
		if _, err := gitEnvForRepo("file:///etc/passwd", nil); err == nil {
			t.Fatal("file:// must be rejected")
		}
		if _, err := gitEnvForRepo("git://github.com/x/y.git", nil); err == nil {
			t.Fatal("git:// must be rejected")
		}
	})
	t.Run("userinfo rejected", func(t *testing.T) {
		if _, err := gitEnvForRepo("https://user:pass@github.com/x/y.git", nil); err == nil {
			t.Fatal("embedded credentials must be rejected")
		}
		if _, err := gitEnvForRepo("ssh://git:pass@github.com/x/y.git", nil); err == nil {
			t.Fatal("ssh password in URL must be rejected")
		}
	})
	t.Run("query and fragment rejected", func(t *testing.T) {
		if _, err := gitEnvForRepo("https://github.com/x?token=y", nil); err == nil {
			t.Fatal("query must be rejected")
		}
		if _, err := gitEnvForRepo("https://github.com/x#evil", nil); err == nil {
			t.Fatal("fragment must be rejected")
		}
	})
	t.Run("option-looking URL rejected", func(t *testing.T) {
		if _, err := gitEnvForRepo("--upload-pack=evil", nil); err == nil {
			t.Fatal("option injection must be rejected")
		}
	})
	t.Run("ssh github allowed without token injection", func(t *testing.T) {
		env, err := gitEnvForRepo("ssh://git@github.com/kiwi/repo.git", []string{"KIWI_GIT_TOKEN_GITHUB_COM=ghp-token"})
		if err != nil {
			t.Fatal(err)
		}
		if hasEnv(env, "GIT_CONFIG_COUNT") || hasEnv(env, "GIT_CONFIG_VALUE_0") {
			t.Fatal("ssh clones must not receive token config")
		}
	})
	t.Run("ssh other host rejected unless allowlisted", func(t *testing.T) {
		if _, err := gitEnvForRepo("ssh://git@evil.com/x.git", nil); err == nil {
			t.Fatal("expected rejection")
		}
		t.Setenv("KIWI_GIT_ALLOWED_SSH_HOSTS", "evil.com")
		if _, err := gitEnvForRepo("ssh://git@evil.com/x.git", nil); err != nil {
			t.Fatalf("allowlisted host should pass: %v", err)
		}
	})
	t.Run("https other host rejected unless allowlisted", func(t *testing.T) {
		if _, err := gitEnvForRepo("https://evil.example/x.git", nil); err == nil {
			t.Fatal("expected rejection")
		}
		t.Setenv("KIWI_GIT_ALLOWED_HTTPS_HOSTS", "evil.example")
		if _, err := gitEnvForRepo("https://evil.example/x.git", nil); err != nil {
			t.Fatalf("allowlisted host should pass: %v", err)
		}
	})
	t.Run("missing scheme rejected", func(t *testing.T) {
		if _, err := gitEnvForRepo("github.com/x/y.git", nil); err == nil {
			t.Fatal("scheme-less URLs must be rejected")
		}
	})
}

func TestValidateServerURL(t *testing.T) {
	t.Setenv("KIWI_RUNNER_ALLOW_INSECURE", "")
	cases := []struct {
		url string
		ok  bool
	}{
		{"http://127.0.0.1:8080", true},
		{"http://localhost:8080", true},
		{"http://[::1]:8080", true},
		{"https://ci.example.com", true},
		{"http://ci.example.com", false},
		{"ftp://ci.example.com", false},
	}
	for _, tc := range cases {
		err := validateServerURL(tc.url)
		if tc.ok && err != nil {
			t.Errorf("%s: unexpected error %v", tc.url, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: expected rejection", tc.url)
		}
	}
	t.Setenv("KIWI_RUNNER_ALLOW_INSECURE", "1")
	if err := validateServerURL("http://ci.example.com"); err != nil {
		t.Errorf("override should allow insecure: %v", err)
	}
}
