package config

import (
	"flag"
	"os"
	"testing"
)

func TestLoadNewSections(t *testing.T) {
	p := writeTemp(t, `
[server]
mode = "production"
external_url = "https://ci.example.com"

[gitlab]
webhook_secret = "gl-wh"
token = "gl-token"
base_url = "https://gitlab.internal.example"

[forgejo]
webhook_secret = "fj-wh"
token = "fj-token"
base_url = "https://forgejo.internal.example"

[quota]
repo_concurrency = 4
team_concurrency = 12
repo_queue_depth = 8
team_queue_depth = 24
daily_cost_limit = 1.5
daily_energy_limit = 2500
fail_open = true

[secret_broker]
broker = "vault"
vault_addr = "https://vault.internal.example"
vault_token = "hvs.token"

[components]
registry_dir = "/etc/kiwi/components"
remote_url = "https://components.internal.example"
remote_token = "reg-token"

[observability]
metrics_listen = ":9091"

[database]
max_connections = 25
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GitLab.BaseURL != "https://gitlab.internal.example" || cfg.Forgejo.BaseURL != "https://forgejo.internal.example" {
		t.Errorf("base URLs not applied: %+v %+v", cfg.GitLab, cfg.Forgejo)
	}
	if cfg.Quota.RepoConcurrency != 4 || cfg.Quota.TeamConcurrency != 12 || cfg.Quota.RepoQueueDepth != 8 || cfg.Quota.TeamQueueDepth != 24 {
		t.Errorf("quota not applied: %+v", cfg.Quota)
	}
	if cfg.Quota.DailyCostLimit != 1.5 || cfg.Quota.DailyEnergyLimit != 2500 || !cfg.Quota.FailOpen {
		t.Errorf("daily budgets not applied: %+v", cfg.Quota)
	}
	if cfg.SecretBroker.Broker != "vault" || cfg.SecretBroker.VaultAddr != "https://vault.internal.example" || cfg.SecretBroker.VaultToken != "hvs.token" {
		t.Errorf("secret broker not applied: %+v", cfg.SecretBroker)
	}
	if cfg.Components.RegistryDir != "/etc/kiwi/components" || cfg.Components.RemoteURL != "https://components.internal.example" || cfg.Components.RemoteToken != "reg-token" {
		t.Errorf("components not applied: %+v", cfg.Components)
	}
	if cfg.Observability.MetricsListen != ":9091" || cfg.Database.MaxConnections != 25 {
		t.Errorf("observability/database not applied: %+v %+v", cfg.Observability, cfg.Database)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("new sections should validate: %v", err)
	}
}

func TestValidateNewFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"app id without key", func(c *Config) { c.GitHub.AppID = 123 }, "private_key_path"},
		{"key without app id", func(c *Config) { c.GitHub.PrivateKeyPath = "/k.pem" }, "app_id"},
		{"runner pki enabled without material", func(c *Config) { c.RunnerPKI.Enabled = true }, "runner_pki"},
		{"negative max connections", func(c *Config) { c.Database.MaxConnections = -1 }, "max_connections"},
		{"negative repo concurrency", func(c *Config) { c.Quota.RepoConcurrency = -1 }, "quota"},
		{"unknown secret broker", func(c *Config) { c.SecretBroker.Broker = "keeper" }, "secret_broker.broker"},
		{"vault without addr", func(c *Config) { c.SecretBroker.Broker = "vault" }, "vault_addr"},
		{"aws without region", func(c *Config) { c.SecretBroker.Broker = "aws" }, "aws_region"},
		{"gcp without credentials", func(c *Config) { c.SecretBroker.Broker = "gcp"; c.SecretBroker.GCPProject = "p" }, "gcp_credentials"},
		{"azure incomplete", func(c *Config) { c.SecretBroker.Broker = "azure"; c.SecretBroker.AzureTenant = "t" }, "azure_vault_url"},
		{"onepassword incomplete", func(c *Config) { c.SecretBroker.Broker = "onepassword"; c.SecretBroker.OnePasswordHost = "h" }, "onepassword_vault"},
		{"static without entries", func(c *Config) { c.SecretBroker.Broker = "static" }, "static"},
		{"component remote http", func(c *Config) { c.Components.RemoteURL = "http://reg.example" }, "https"},
		{"gitlab base url bad", func(c *Config) { c.GitLab.BaseURL = "not-a-url" }, "gitlab.base_url"},
		{"forgejo base url bad", func(c *Config) { c.Forgejo.BaseURL = "ftp://x" }, "forgejo.base_url"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Default()
			c.mutate(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate accepted config, want error mentioning %q", c.want)
			}
			if !contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
	// The positive counterparts validate.
	ok := Default()
	ok.GitHub.AppID = 123
	ok.GitHub.PrivateKeyPath = "/k.pem"
	ok.SecretBroker = SecretBrokerConfig{
		Broker: "azure", AzureTenant: "t", AzureClientID: "c", AzureSecret: "s", AzureVaultURL: "https://vault.example",
	}
	ok.Quota = QuotaConfig{RepoConcurrency: 2, DailyCostLimit: 10}
	ok.Components.RemoteURL = "https://reg.example"
	ok.GitLab.BaseURL = "https://gitlab.internal.example"
	if err := ok.Validate(); err != nil {
		t.Errorf("valid new config rejected: %v", err)
	}
}

func TestApplyEnvNewFields(t *testing.T) {
	env := map[string]string{
		"KIWI_GITHUB_APP_ID":            "4242",
		"KIWI_GITLAB_BASE_URL":          "https://gl.env.example",
		"KIWI_FORGEJO_BASE_URL":         "https://fj.env.example",
		"KIWI_AUTH_TOKENS_FILE":         "/tokens.json",
		"KIWI_METRICS_LISTEN":           ":9091",
		"KIWI_SECRET_BROKER":            "aws",
		"KIWI_AWS_REGION":               "eu-west-1",
		"KIWI_COMPONENT_REMOTE":         "https://reg.env.example",
		"KIWI_REPO_CONCURRENCY":         "6",
		"KIWI_DAILY_COST_LIMIT":         "2.5",
		"KIWI_QUOTA_FAIL_OPEN":          "true",
		"KIWI_DATABASE_MAX_CONNECTIONS": "17",
	}
	for k, v := range env {
		os.Setenv(k, v)
	}
	t.Cleanup(func() {
		for k := range env {
			os.Unsetenv(k)
		}
	})
	cfg := Default()
	if err := cfg.ApplyEnv(); err != nil {
		t.Fatal(err)
	}
	if cfg.GitHub.AppID != 4242 {
		t.Errorf("app id = %d", cfg.GitHub.AppID)
	}
	if cfg.GitLab.BaseURL != "https://gl.env.example" || cfg.Forgejo.BaseURL != "https://fj.env.example" {
		t.Errorf("base urls = %q %q", cfg.GitLab.BaseURL, cfg.Forgejo.BaseURL)
	}
	if cfg.Auth.TokensFile != "/tokens.json" || cfg.Observability.MetricsListen != ":9091" {
		t.Errorf("tokens/metrics = %q %q", cfg.Auth.TokensFile, cfg.Observability.MetricsListen)
	}
	if cfg.SecretBroker.Broker != "aws" || cfg.SecretBroker.AWSRegion != "eu-west-1" {
		t.Errorf("secret broker = %+v", cfg.SecretBroker)
	}
	if cfg.Components.RemoteURL != "https://reg.env.example" {
		t.Errorf("components = %+v", cfg.Components)
	}
	if cfg.Quota.RepoConcurrency != 6 || cfg.Quota.DailyCostLimit != 2.5 || !cfg.Quota.FailOpen {
		t.Errorf("quota = %+v", cfg.Quota)
	}
	if cfg.Database.MaxConnections != 17 {
		t.Errorf("max connections = %d", cfg.Database.MaxConnections)
	}
}

func TestOverrideFromFlagsNewFlags(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_ = fs.String("github-app-id", "", "")
	_ = fs.String("github-app-private-key", "", "")
	_ = fs.String("gitlab-token", "", "")
	_ = fs.String("gitlab-base-url", "", "")
	_ = fs.String("forgejo-base-url", "", "")
	_ = fs.String("tokens-file", "", "")
	_ = fs.String("database-max-connections", "", "")
	_ = fs.String("metrics-listen", "", "")
	_ = fs.String("secret-broker", "", "")
	_ = fs.String("vault-addr", "", "")
	_ = fs.String("aws-region", "", "")
	_ = fs.String("azure-vault-url", "", "")
	_ = fs.String("onepassword-host", "", "")
	_ = fs.String("secret-static", "", "")
	_ = fs.String("component-registry-dir", "", "")
	_ = fs.String("component-remote", "", "")
	_ = fs.String("repo-concurrency", "", "")
	_ = fs.String("team-concurrency", "", "")
	_ = fs.String("repo-queue-depth", "", "")
	_ = fs.String("team-queue-depth", "", "")
	_ = fs.String("daily-cost-limit", "", "")
	_ = fs.String("daily-energy-limit", "", "")
	_ = fs.String("quota-fail-open", "", "")
	args := []string{
		"-github-app-id", "4242",
		"-github-app-private-key", "/k.pem",
		"-gitlab-token", "gl-token",
		"-gitlab-base-url", "https://gl.example",
		"-forgejo-base-url", "https://fj.example",
		"-tokens-file", "/tokens.json",
		"-database-max-connections", "17",
		"-metrics-listen", ":9091",
		"-secret-broker", "vault",
		"-vault-addr", "https://vault.example",
		"-aws-region", "us-east-1",
		"-azure-vault-url", "https://kv.example",
		"-onepassword-host", "https://op.example",
		"-secret-static", "a=1,b=2",
		"-component-registry-dir", "/components",
		"-component-remote", "https://reg.example",
		"-repo-concurrency", "6",
		"-team-concurrency", "8",
		"-repo-queue-depth", "10",
		"-team-queue-depth", "12",
		"-daily-cost-limit", "2.5",
		"-daily-energy-limit", "900",
		"-quota-fail-open", "true",
	}
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	if err := cfg.OverrideFromFlags(fs); err != nil {
		t.Fatal(err)
	}
	if cfg.GitHub.AppID != 4242 || cfg.GitHub.PrivateKeyPath != "/k.pem" {
		t.Errorf("github = %+v", cfg.GitHub)
	}
	if cfg.GitLab.Token != "gl-token" || cfg.GitLab.BaseURL != "https://gl.example" || cfg.Forgejo.BaseURL != "https://fj.example" {
		t.Errorf("gitlab/forgejo = %+v %+v", cfg.GitLab, cfg.Forgejo)
	}
	if cfg.Auth.TokensFile != "/tokens.json" || cfg.Database.MaxConnections != 17 || cfg.Observability.MetricsListen != ":9091" {
		t.Errorf("tokens/db/metrics = %+v %+v %+v", cfg.Auth, cfg.Database, cfg.Observability)
	}
	if cfg.SecretBroker.Broker != "vault" || cfg.SecretBroker.VaultAddr != "https://vault.example" || cfg.SecretBroker.AWSRegion != "us-east-1" || cfg.SecretBroker.AzureVaultURL != "https://kv.example" || cfg.SecretBroker.OnePasswordHost != "https://op.example" || cfg.SecretBroker.Static != "a=1,b=2" {
		t.Errorf("secret broker = %+v", cfg.SecretBroker)
	}
	if cfg.Components.RegistryDir != "/components" || cfg.Components.RemoteURL != "https://reg.example" {
		t.Errorf("components = %+v", cfg.Components)
	}
	if cfg.Quota.RepoConcurrency != 6 || cfg.Quota.TeamConcurrency != 8 || cfg.Quota.RepoQueueDepth != 10 || cfg.Quota.TeamQueueDepth != 12 || cfg.Quota.DailyCostLimit != 2.5 || cfg.Quota.DailyEnergyLimit != 900 || !cfg.Quota.FailOpen {
		t.Errorf("quota = %+v", cfg.Quota)
	}
	// Bad numeric values surface as errors.
	bad := flag.NewFlagSet("bad", flag.ContinueOnError)
	_ = bad.String("repo-concurrency", "", "")
	if err := bad.Parse([]string{"-repo-concurrency", "many"}); err != nil {
		t.Fatal(err)
	}
	if err := Default().OverrideFromFlags(bad); err == nil {
		t.Fatal("non-numeric repo-concurrency accepted")
	}
}
