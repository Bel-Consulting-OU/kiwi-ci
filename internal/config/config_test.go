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
ca_cert = "/etc/kiwi/runner-ca.crt"
ca_key = "/etc/kiwi/runner-ca.key"
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
	if !cfg.RunnerPKI.Enabled || cfg.RunnerPKI.EnrollToken != "enroll-secret" || cfg.RunnerPKI.CACert != "/etc/kiwi/runner-ca.crt" || cfg.RunnerPKI.CAKey != "/etc/kiwi/runner-ca.key" {
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

func TestValidateRunnerPKIMatrix(t *testing.T) {
	// enabled is authoritative: it demands the full CA pair. The enroll
	// token is optional (single-use grants may be used instead). A
	// half-configured pair is an error regardless of enabled.
	valid := Default()
	valid.RunnerPKI.Enabled = true
	valid.RunnerPKI.CACert = "/etc/kiwi/runner-ca.crt"
	valid.RunnerPKI.CAKey = "/etc/kiwi/runner-ca.key"
	if err := valid.Validate(); err != nil {
		t.Fatalf("enabled with full CA pair rejected: %v", err)
	}
	validEnroll := valid
	validEnroll.RunnerPKI.EnrollToken = "enroll-secret"
	if err := validEnroll.Validate(); err != nil {
		t.Fatalf("enabled with CA pair + enroll token rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"enabled without any material", func(c *Config) { c.RunnerPKI.Enabled = true }},
		{"enabled with cert only", func(c *Config) { c.RunnerPKI.Enabled = true; c.RunnerPKI.CACert = "/ca.crt" }},
		{"enabled with key only", func(c *Config) { c.RunnerPKI.Enabled = true; c.RunnerPKI.CAKey = "/ca.key" }},
		{"enabled with cert+enroll token but no key", func(c *Config) {
			c.RunnerPKI.Enabled = true
			c.RunnerPKI.CACert = "/ca.crt"
			c.RunnerPKI.EnrollToken = "t"
		}},
		{"cert only without enabled", func(c *Config) { c.RunnerPKI.CACert = "/ca.crt" }},
		{"key only without enabled", func(c *Config) { c.RunnerPKI.CAKey = "/ca.key" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Default()
			c.mutate(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate accepted %s config", c.name)
			}
		})
	}
	// A disabled runner_pki with a full pair validates (material present
	// but inactive), and an enroll token without enabled keeps the legacy
	// data-dir CA generation path valid.
	inactive := Default()
	inactive.RunnerPKI.CACert = "/ca.crt"
	inactive.RunnerPKI.CAKey = "/ca.key"
	if err := inactive.Validate(); err != nil {
		t.Fatalf("disabled runner_pki with a full pair rejected: %v", err)
	}
	if err := func() error {
		c := Default()
		c.RunnerPKI.EnrollToken = "enroll-secret"
		return c.Validate()
	}(); err != nil {
		t.Fatalf("enroll token without enabled rejected: %v", err)
	}
}

func TestStripCommentEscapeAware(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"escaped quote keeps in-string state", `key = "a\"#b"`, `key = "a\"#b"`},
		{"double backslash before closing quote strips comment", `key = "a\\" # comment`, `key = "a\\" `},
		{"full line comment", `# full line`, ``},
		{"comment after single-quoted string", `key = 'a#b' # comment`, `key = 'a#b' `},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := stripComment(c.in); got != c.want {
				t.Fatalf("stripComment(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
	// The escaped-quote value survives a full Load: the # stays part of the
	// string value and a trailing comment is stripped.
	p := writeTemp(t, `
[server]
listen = "a\"#b"
mode = "dev"  # trailing
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != `a"#b` {
		t.Fatalf("listen = %q, want %q", cfg.Server.Listen, `a"#b`)
	}
}

func TestApplyEnvStrictNumeric(t *testing.T) {
	unset := func(names ...string) {
		for _, n := range names {
			os.Unsetenv(n)
			t.Cleanup(func() { os.Unsetenv(n) })
		}
	}
	// An explicitly provided malformed numeric env var must fail startup,
	// not silently fall back to the config-file/default value.
	t.Setenv("KIWI_QUOTA_REPO_CONCURRENCY", "abc")
	if err := Default().ApplyEnv(); err == nil {
		t.Fatal("KIWI_QUOTA_REPO_CONCURRENCY=abc must fail ApplyEnv")
	}
	t.Setenv("KIWI_QUOTA_REPO_CONCURRENCY", "4")
	t.Setenv("KIWI_DAILY_COST_LIMIT", "not-a-number")
	if err := Default().ApplyEnv(); err == nil {
		t.Fatal("KIWI_DAILY_COST_LIMIT=not-a-number must fail ApplyEnv")
	}
	unset("KIWI_DAILY_COST_LIMIT")
	t.Setenv("KIWI_DATABASE_MAX_CONNECTIONS", "many")
	if err := Default().ApplyEnv(); err == nil {
		t.Fatal("KIWI_DATABASE_MAX_CONNECTIONS=many must fail ApplyEnv")
	}
	unset("KIWI_DATABASE_MAX_CONNECTIONS")
	t.Setenv("KIWI_GITHUB_APP_ID", "0x10")
	if err := Default().ApplyEnv(); err == nil {
		t.Fatal("KIWI_GITHUB_APP_ID=0x10 must fail ApplyEnv")
	}
	unset("KIWI_GITHUB_APP_ID")
	t.Setenv("KIWI_QUOTA_FAIL_OPEN", "sometimes")
	if err := Default().ApplyEnv(); err == nil {
		t.Fatal("KIWI_QUOTA_FAIL_OPEN=sometimes must fail ApplyEnv")
	}
	unset("KIWI_QUOTA_FAIL_OPEN")
	unset("KIWI_QUOTA_REPO_CONCURRENCY")

	// Absent env vars leave the defaults untouched.
	cfg := Default()
	if err := cfg.ApplyEnv(); err != nil {
		t.Fatalf("ApplyEnv with absent numeric env vars: %v", err)
	}
	if cfg.Quota.RepoConcurrency != 0 || cfg.Database.MaxConnections != 0 || cfg.GitHub.AppID != 0 || cfg.Quota.FailOpen {
		t.Fatalf("defaults drifted: %+v %+v %+v", cfg.Quota, cfg.Database, cfg.GitHub)
	}

	// Valid values still win over the defaults.
	t.Setenv("KIWI_QUOTA_REPO_CONCURRENCY", "7")
	t.Setenv("KIWI_DATABASE_MAX_CONNECTIONS", "19")
	t.Setenv("KIWI_GITHUB_APP_ID", "4242")
	t.Setenv("KIWI_QUOTA_FAIL_OPEN", "true")
	cfg = Default()
	if err := cfg.ApplyEnv(); err != nil {
		t.Fatal(err)
	}
	if cfg.Quota.RepoConcurrency != 7 || cfg.Database.MaxConnections != 19 || cfg.GitHub.AppID != 4242 || !cfg.Quota.FailOpen {
		t.Fatalf("valid numeric env not applied: %+v %+v %+v", cfg.Quota, cfg.Database, cfg.GitHub)
	}

	// The legacy unprefixed spellings still work (canonical KIWI_QUOTA_*
	// wins when both are set).
	t.Setenv("KIWI_REPO_CONCURRENCY", "5")
	t.Setenv("KIWI_QUOTA_REPO_CONCURRENCY", "9")
	cfg = Default()
	if err := cfg.ApplyEnv(); err != nil {
		t.Fatal(err)
	}
	if cfg.Quota.RepoConcurrency != 9 {
		t.Fatalf("canonical KIWI_QUOTA_REPO_CONCURRENCY must win over legacy, got %v", cfg.Quota.RepoConcurrency)
	}
}
