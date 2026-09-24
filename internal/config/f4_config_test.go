package config

// F4-D/F4-G regressions: an empty KIWI_SERVER_MODE must not downgrade a
// configured production mode, and URL-bearing config errors must reject
// userinfo and never echo raw credentials.

import (
	"strings"
	"testing"
)

func TestApplyEnvEmptyModeDoesNotDowngradeProduction(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "production"
	cfg.Server.ExternalURL = "https://ci.example.com"
	t.Setenv("KIWI_SERVER_MODE", "")
	if err := cfg.ApplyEnv(); err != nil {
		t.Fatalf("ApplyEnv: %v", err)
	}
	if cfg.Server.Mode != "production" {
		t.Fatalf("empty KIWI_SERVER_MODE downgraded mode to %q, want production", cfg.Server.Mode)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("production config must stay valid: %v", err)
	}

	// A whitespace-only value is not treated as empty: it is an invalid mode
	// and Validate rejects it (fail closed), never coerced to dev.
	ws := Default()
	ws.Server.Mode = "production"
	t.Setenv("KIWI_SERVER_MODE", "   ")
	if err := ws.ApplyEnv(); err != nil {
		t.Fatalf("ApplyEnv whitespace: %v", err)
	}
	if err := ws.Validate(); err == nil {
		t.Fatal("whitespace-only mode must be rejected, not coerced to dev")
	}
}

func TestComponentsRemoteURLRejectsUserinfoAndRedacts(t *testing.T) {
	cases := []string{
		"https://user:s3cret@reg.example.com/base",
		"https://user:s3cret@exa mple.com/base", // unparseable, still credential-bearing
	}
	for _, raw := range cases {
		cfg := Default()
		cfg.Components.RemoteURL = raw
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("remote_url %q accepted", raw)
		}
		if strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "user:") {
			t.Fatalf("config error leaked credentials: %v", err)
		}
	}
}

func TestForgeBaseURLErrorsDoNotLeakCredentials(t *testing.T) {
	cfg := Default()
	cfg.GitLab.BaseURL = "https://user:s3cret@exa mple.com"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("malformed credential-bearing gitlab.base_url accepted")
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("config error leaked credentials: %v", err)
	}
}
