package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kiwi.toml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadFullFile(t *testing.T) {
	p := writeTemp(t, `
# Kiwi CI server configuration
[server]
external_url = "https://ci.example.com"
listen = ":8443"
tls_cert = "/etc/kiwi/server.crt"
tls_key = "/etc/kiwi/server.key"
mode = "production"

[database]
url = "postgres://kiwi:secret@db:5432/kiwi"
max_connections = 25

[runner_pki]
enabled = true
enroll_token = "enroll-secret"

[blob]
backend = "s3"
s3_endpoint = "https://s3.example.com"
s3_bucket = "kiwi-artifacts"
s3_region = "eu-central-1"
s3_access_key = "AKIA..."
s3_secret_key = "secret"

[github]
app_id = 123456
private_key_path = "/etc/kiwi/github.pem"
webhook_secret = "wh"
token = "gh-token"

[gitlab]
webhook_secret = "gl-wh"
token = "gl-token"

[forgejo]
webhook_secret = "fj-wh"
token = "fj-token"

[policy]
file = "/etc/kiwi/policy.rego"

[observability]
otel_endpoint = "http://otel:4317"
metrics_listen = ":9090"

[rate_limit]
per_second = 10
burst = 50
next_per_second = 5
logs_per_second = 20

[auth]
admin_token = "admin"
runner_token = "runner"
tokens_file = "/etc/kiwi/tokens.json"
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.ExternalURL != "https://ci.example.com" || cfg.Server.Listen != ":8443" || cfg.Server.Mode != "production" {
		t.Errorf("server section not applied: %+v", cfg.Server)
	}
	if cfg.Database.URL != "postgres://kiwi:secret@db:5432/kiwi" || cfg.Database.MaxConnections != 25 {
		t.Errorf("database section not applied: %+v", cfg.Database)
	}
	if !cfg.RunnerPKI.Enabled || cfg.RunnerPKI.EnrollToken != "enroll-secret" {
		t.Errorf("runner_pki section not applied: %+v", cfg.RunnerPKI)
	}
	if cfg.Blob.Backend != "s3" || cfg.Blob.S3Bucket != "kiwi-artifacts" {
		t.Errorf("blob section not applied: %+v", cfg.Blob)
	}
	if cfg.GitHub.AppID != 123456 || cfg.GitHub.Token != "gh-token" {
		t.Errorf("github section not applied: %+v", cfg.GitHub)
	}
	if cfg.GitLab.Token != "gl-token" || cfg.Forgejo.Token != "fj-token" {
		t.Errorf("gitlab/forgejo sections not applied")
	}
	if cfg.Policy.File != "/etc/kiwi/policy.rego" {
		t.Errorf("policy section not applied: %+v", cfg.Policy)
	}
	if cfg.Observability.OTelEndpoint != "http://otel:4317" || cfg.Observability.MetricsListen != ":9090" {
		t.Errorf("observability section not applied: %+v", cfg.Observability)
	}
	if cfg.RateLimit.PerSecond != 10 || cfg.RateLimit.Burst != 50 || cfg.RateLimit.NextPerSecond != 5 {
		t.Errorf("rate_limit section not applied: %+v", cfg.RateLimit)
	}
	if cfg.Auth.AdminToken != "admin" || cfg.Auth.RunnerToken != "runner" {
		t.Errorf("auth section not applied: %+v", cfg.Auth)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("full config should validate: %v", err)
	}
}

func TestLoadDefaultsOnMissingKeys(t *testing.T) {
	cfg, err := Load(writeTemp(t, "[server]\nmode = \"dev\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != ":8080" {
		t.Errorf("default listen = %q, want :8080", cfg.Server.Listen)
	}
	if cfg.Blob.Backend != "fs" {
		t.Errorf("default blob backend = %q, want fs", cfg.Blob.Backend)
	}
	if cfg.RateLimit.Burst != 100 {
		t.Errorf("default burst = %d, want 100", cfg.RateLimit.Burst)
	}
}

func TestLoadStrictRejections(t *testing.T) {
	cases := []struct {
		name, content, want string
	}{
		{"unknown section", "[server]\n[typo_section]\nx = 1\n", "unknown section"},
		{"unknown key", "[server]\nport = 8080\n", "unknown key \"port\" in section [server]"},
		{"unknown nested key", "[database]\nuser = \"u\"\n", "unknown key"},
		{"duplicate key", "[server]\nmode = \"dev\"\nmode = \"production\"\n", "duplicate key"},
		{"key outside section", "mode = \"dev\"\n", "outside any section"},
		{"bad value", "[server]\nmode = maybe\n", "invalid value"},
		{"type mismatch", "[database]\nmax_connections = \"many\"\n", "expected an integer"},
		{"malformed header", "[server\n", "malformed section header"},
		{"no equals", "[server]\nmode\n", "expected key = value"},
		{"empty value", "[server]\nmode =\n", "empty key or value"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(writeTemp(t, c.content))
			if err == nil {
				t.Fatalf("Load accepted invalid file, want error mentioning %q", c.want)
			}
			if !contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.toml")); err == nil {
		t.Fatal("Load of missing file succeeded")
	}
}

func TestLoadStringEscapesAndComments(t *testing.T) {
	p := writeTemp(t, `
# a comment with a # inside
[server]
external_url = "https://ci.example.com/path#frag" # trailing comment
listen = ":8080"  # another
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.ExternalURL != "https://ci.example.com/path#frag" {
		t.Errorf("external_url = %q", cfg.Server.ExternalURL)
	}
}

func TestValidate(t *testing.T) {
	base := Default()
	base.Server.ExternalURL = "https://ci.example.com"
	base.Database.URL = "postgres://db"

	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"bad mode", func(c *Config) { c.Server.Mode = "staging" }, "server.mode"},
		{"production without external url", func(c *Config) { c.Server.Mode = "production"; c.Server.ExternalURL = "" }, "external_url"},
		{"production with http external url", func(c *Config) { c.Server.Mode = "production"; c.Server.ExternalURL = "http://ci.example.com" }, "https://"},
		{"bad database url", func(c *Config) { c.Database.URL = "mysql://db" }, "database.url"},
		{"bad blob backend", func(c *Config) { c.Blob.Backend = "gcs" }, "blob.backend"},
		{"s3 without endpoint", func(c *Config) { c.Blob.Backend = "s3"; c.Blob.S3Bucket = "b"; c.Blob.S3Region = "r" }, "s3_endpoint"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := *base
			c.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate accepted config, want error mentioning %q", c.want)
			}
			if !contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
	if err := base.Validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	if err := Default().Validate(); err != nil {
		t.Errorf("default config rejected: %v", err)
	}
}

func TestApplyEnv(t *testing.T) {
	os.Setenv("KIWI_SERVER_EXTERNAL_URL", "https://env.example.com")
	os.Setenv("KIWI_SERVER_LISTEN", ":9999")
	os.Setenv("KIWI_DATABASE_URL", "postgres://env")
	os.Setenv("KIWI_RUNNER_TOKEN", "env-runner")
	t.Cleanup(func() {
		os.Unsetenv("KIWI_SERVER_EXTERNAL_URL")
		os.Unsetenv("KIWI_SERVER_LISTEN")
		os.Unsetenv("KIWI_DATABASE_URL")
		os.Unsetenv("KIWI_RUNNER_TOKEN")
	})
	cfg := Default()
	if err := cfg.ApplyEnv(); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.ExternalURL != "https://env.example.com" || cfg.Server.Listen != ":9999" {
		t.Errorf("env not applied to server: %+v", cfg.Server)
	}
	if cfg.Database.URL != "postgres://env" || cfg.Auth.RunnerToken != "env-runner" {
		t.Errorf("env not applied: %+v / %+v", cfg.Database, cfg.Auth)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
