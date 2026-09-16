// Package config loads and validates the kiwi server configuration file
// (kiwi.toml). The loader uses a minimal, dependency-free TOML subset
// (sections, key = string|int|bool, # comments) tuned to the fixed schema
// below; switching to a full TOML library later is allowed as long as the
// schema and precedence rules stay stable.
//
// Effective-value precedence: CLI flags > environment (KIWI_*) > config
// file > built-in defaults. Server code calls Default/Load, then ApplyEnv,
// then OverrideFromFlags in that order.
package config

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/quotas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/ratelimit"
)

type ServerConfig struct {
	// ExternalURL is the public base URL the control plane advertises
	// (OIDC issuer, forge statuses). Required and https:// in production.
	ExternalURL string `toml:"external_url"`
	// Listen is the HTTP listen address (default ":8080").
	Listen string `toml:"listen"`
	// TLSCert/TLSKey enable HTTPS when both are set.
	TLSCert string `toml:"tls_cert"`
	TLSKey  string `toml:"tls_key"`
	// Mode is "dev" (in-memory, default) or "production".
	Mode string `toml:"mode"`
}

type DatabaseConfig struct {
	// URL is the PostgreSQL connection URL; when set the durable SQL
	// control plane is enabled.
	URL            string `toml:"url"`
	MaxConnections int    `toml:"max_connections"`
}

type RunnerPKIConfig struct {
	Enabled     bool   `toml:"enabled"`
	CACert      string `toml:"ca_cert"`
	CAKey       string `toml:"ca_key"`
	EnrollToken string `toml:"enroll_token"`
}

type BlobConfig struct {
	// Backend selects artifact/blob storage: "fs" (default) or "s3".
	Backend     string `toml:"backend"`
	Path        string `toml:"path"`
	S3Endpoint  string `toml:"s3_endpoint"`
	S3Bucket    string `toml:"s3_bucket"`
	S3Region    string `toml:"s3_region"`
	S3AccessKey string `toml:"s3_access_key"`
	S3SecretKey string `toml:"s3_secret_key"`
}

type GitHubConfig struct {
	AppID          int64  `toml:"app_id"`
	PrivateKeyPath string `toml:"private_key_path"`
	WebhookSecret  string `toml:"webhook_secret"`
	Token          string `toml:"token"`
}

type GitLabConfig struct {
	WebhookSecret string `toml:"webhook_secret"`
	Token         string `toml:"token"`
	// BaseURL is the GitLab instance root (default https://gitlab.com).
	BaseURL string `toml:"base_url"`
}

type ForgejoConfig struct {
	WebhookSecret string `toml:"webhook_secret"`
	Token         string `toml:"token"`
	// BaseURL is the Forgejo/Gitea instance root (default
	// https://codeberg.org).
	BaseURL string `toml:"base_url"`
}

type PolicyConfig struct {
	File string `toml:"file"`
}

type ObservabilityConfig struct {
	// OTelEndpoint is accepted for forward compatibility; OpenTelemetry
	// endpoint receives OTLP/HTTP traces from the control plane.
	OTelEndpoint string `toml:"otel_endpoint"`
	// MetricsListen optionally serves /metrics on a separate address.
	MetricsListen string `toml:"metrics_listen"`
}

// RateLimitConfig holds per-class request rate limits. PerSecond and Burst
// are the defaults applied to every class; the *_per_second keys override
// PerSecond for their class. A rate of 0 (the default) disables limiting.
type RateLimitConfig struct {
	PerSecond float64 `toml:"per_second"`
	Burst     int     `toml:"burst"`

	NextPerSecond           float64 `toml:"next_per_second"`
	HeartbeatPerSecond      float64 `toml:"heartbeat_per_second"`
	LogsPerSecond           float64 `toml:"logs_per_second"`
	ArtifactUploadPerSecond float64 `toml:"artifact_upload_per_second"`
	CacheUploadPerSecond    float64 `toml:"cache_upload_per_second"`
	DispatchPerSecond       float64 `toml:"dispatch_per_second"`
	WebhooksPerSecond       float64 `toml:"webhooks_per_second"`
	EnrollPerSecond         float64 `toml:"enroll_per_second"`
	RegisterPerSecond       float64 `toml:"register_per_second"`
	OIDCPerSecond           float64 `toml:"oidc_per_second"`
	SecretsPerSecond        float64 `toml:"secrets_per_second"`
	LoginPerSecond          float64 `toml:"login_per_second"`
}

type AuthConfig struct {
	AdminToken string `toml:"admin_token"`
	// RunnerToken is the bearer token shared by ALL runners. It is a
	// shared credential, not a per-runner identity: it cannot distinguish
	// runners. Production strongly prefers persistent per-runner mTLS
	// identities (runner_pki); the control plane refuses to serve runner
	// traffic with neither a runner token nor enforced runner mTLS. In
	// production the shared token is dev/bootstrap-only: runner
	// authentication must be per-runner mTLS or per-runner bearer tokens
	// (runner_tokens_file).
	RunnerToken string `toml:"runner_token"`
	// TokensFile is the JSON token-store path for fine-grained principals.
	TokensFile string `toml:"tokens_file"`
	// RunnerTokensFile is a JSON file of per-runner bearer credentials:
	// {"<runner-id>": "<sha256-hex-token-digest>"}. The server provisions
	// these into the durable runner_bearer_tokens table in DB mode and
	// keeps them in memory otherwise.
	RunnerTokensFile string `toml:"runner_tokens_file"`
}

// QuotaConfig holds the enqueue and daily-budget quota policy. All counts
// are float for parity with quotas.Limits; 0 means unlimited.
type QuotaConfig struct {
	RepoConcurrency  float64 `toml:"repo_concurrency"`
	TeamConcurrency  float64 `toml:"team_concurrency"`
	RepoQueueDepth   float64 `toml:"repo_queue_depth"`
	TeamQueueDepth   float64 `toml:"team_queue_depth"`
	DailyCostLimit   float64 `toml:"daily_cost_limit"`
	DailyEnergyLimit float64 `toml:"daily_energy_limit"`
	// FailOpen lets enqueues and leases proceed when the usage store is
	// unavailable instead of failing closed.
	FailOpen bool `toml:"fail_open"`
}

// SecretBrokerConfig selects the secret backend (vault, aws, gcp, azure,
// onepassword or static) and its credentials. Only the fields of the
// selected broker are required.
type SecretBrokerConfig struct {
	// Broker selects the provider; empty disables secret resolution.
	Broker           string `toml:"broker"`
	VaultAddr        string `toml:"vault_addr"`
	VaultToken       string `toml:"vault_token"`
	AWSRegion        string `toml:"aws_region"`
	AWSAccessKey     string `toml:"aws_access_key"`
	AWSSecretKey     string `toml:"aws_secret_key"`
	AWSToken         string `toml:"aws_token"`
	GCPCredentials   string `toml:"gcp_credentials"`
	GCPProject       string `toml:"gcp_project"`
	AzureTenant      string `toml:"azure_tenant"`
	AzureClientID    string `toml:"azure_client_id"`
	AzureSecret      string `toml:"azure_client_secret"`
	AzureVaultURL    string `toml:"azure_vault_url"`
	OnePasswordHost  string `toml:"onepassword_host"`
	OnePasswordToken string `toml:"onepassword_token"`
	OnePasswordVault string `toml:"onepassword_vault"`
	// Static is a comma-separated list of k=v entries served by the
	// static broker (the repeatable --secret-static flag joins the same
	// way).
	Static string `toml:"static"`
}

// ComponentsConfig configures server-side component resolution: a local
// directory registry and/or a remote registry HTTP API.
type ComponentsConfig struct {
	// RegistryDir loads component spec files (.yaml/.json) from a local
	// directory.
	RegistryDir string `toml:"registry_dir"`
	// RemoteURL is the remote registry base URL (https required).
	RemoteURL string `toml:"remote_url"`
	// RemoteToken is the bearer token for the remote registry.
	RemoteToken string `toml:"remote_token"`
}

type Config struct {
	Server        ServerConfig        `toml:"server"`
	Database      DatabaseConfig      `toml:"database"`
	RunnerPKI     RunnerPKIConfig     `toml:"runner_pki"`
	Blob          BlobConfig          `toml:"blob"`
	GitHub        GitHubConfig        `toml:"github"`
	GitLab        GitLabConfig        `toml:"gitlab"`
	Forgejo       ForgejoConfig       `toml:"forgejo"`
	Policy        PolicyConfig        `toml:"policy"`
	Observability ObservabilityConfig `toml:"observability"`
	RateLimit     RateLimitConfig     `toml:"rate_limit"`
	Auth          AuthConfig          `toml:"auth"`
	Quota         QuotaConfig         `toml:"quota"`
	SecretBroker  SecretBrokerConfig  `toml:"secret_broker"`
	Components    ComponentsConfig    `toml:"components"`
}

// Default returns the built-in defaults (the bottom of the precedence
// chain).
func Default() *Config {
	return &Config{
		Server:    ServerConfig{Listen: ":8080", Mode: "dev"},
		Blob:      BlobConfig{Backend: "fs"},
		RateLimit: RateLimitConfig{Burst: 100},
	}
}

// Validate enforces the cross-field invariants: mode, production external
// URL scheme, database URL format and blob backend enum.
func (c *Config) Validate() error {
	mode := c.Server.Mode
	if mode == "" {
		mode = "dev"
	}
	if mode != "dev" && mode != "production" {
		return fmt.Errorf("server.mode must be \"dev\" or \"production\", got %q", mode)
	}
	if mode == "production" {
		if c.Server.ExternalURL == "" {
			return fmt.Errorf("server.external_url is required in production mode (the OIDC issuer always serves in production)")
		}
		if !strings.HasPrefix(c.Server.ExternalURL, "https://") {
			return fmt.Errorf("server.external_url must start with https:// in production mode, got %q", c.Server.ExternalURL)
		}
	}
	if c.Database.URL != "" {
		if !strings.HasPrefix(c.Database.URL, "postgres://") && !strings.HasPrefix(c.Database.URL, "postgresql://") {
			return fmt.Errorf("database.url must be a postgres:// or postgresql:// URL, got %q", c.Database.URL)
		}
	}
	backend := c.Blob.Backend
	if backend == "" {
		backend = "fs"
	}
	if backend != "fs" && backend != "s3" {
		return fmt.Errorf("blob.backend must be \"fs\" or \"s3\", got %q", backend)
	}
	if backend == "s3" {
		if c.Blob.S3Endpoint == "" || c.Blob.S3Bucket == "" || c.Blob.S3Region == "" {
			return fmt.Errorf("blob.backend \"s3\" requires blob.s3_endpoint, blob.s3_bucket and blob.s3_region")
		}
	}
	// GitHub App credentials are a pair: an app ID without a private key
	// (or a key without an ID) can never authenticate.
	switch {
	case c.GitHub.AppID != 0 && c.GitHub.PrivateKeyPath == "":
		return fmt.Errorf("github.app_id requires github.private_key_path (the App private key PEM)")
	case c.GitHub.AppID == 0 && c.GitHub.PrivateKeyPath != "":
		return fmt.Errorf("github.private_key_path requires github.app_id")
	}
	// Runner PKI: enabled is authoritative — it demands the full CA pair at
	// startup (the enroll token stays optional; single-use grants may be
	// used instead). A half-configured pair is an error regardless of
	// enabled: cert-only/key-only can never authenticate anything.
	switch {
	case c.RunnerPKI.CACert != "" && c.RunnerPKI.CAKey == "":
		return fmt.Errorf("runner_pki.ca_cert requires runner_pki.ca_key")
	case c.RunnerPKI.CAKey != "" && c.RunnerPKI.CACert == "":
		return fmt.Errorf("runner_pki.ca_key requires runner_pki.ca_cert")
	case c.RunnerPKI.Enabled && (c.RunnerPKI.CACert == "" || c.RunnerPKI.CAKey == ""):
		return fmt.Errorf("runner_pki.enabled requires runner_pki.ca_cert and runner_pki.ca_key")
	}
	if c.Database.MaxConnections < 0 {
		return fmt.Errorf("database.max_connections must not be negative, got %d", c.Database.MaxConnections)
	}
	ql := quotas.Limits{
		RepoConcurrency: c.Quota.RepoConcurrency,
		TeamConcurrency: c.Quota.TeamConcurrency,
		RepoQueueDepth:  c.Quota.RepoQueueDepth,
		TeamQueueDepth:  c.Quota.TeamQueueDepth,
		DailyCost:       c.Quota.DailyCostLimit,
		DailyEnergy:     c.Quota.DailyEnergyLimit,
	}
	if err := ql.Validate(); err != nil {
		return fmt.Errorf("quota: %w", err)
	}
	if err := validateSecretBroker(c.SecretBroker); err != nil {
		return err
	}
	if c.Components.RemoteURL != "" {
		u, err := url.Parse(c.Components.RemoteURL)
		if err != nil {
			return fmt.Errorf("components.remote_url: %w", err)
		}
		if u.Scheme != "https" {
			return fmt.Errorf("components.remote_url must use https:// (got %q)", c.Components.RemoteURL)
		}
		if u.Host == "" {
			return fmt.Errorf("components.remote_url has no host: %q", c.Components.RemoteURL)
		}
	}
	for name, base := range map[string]string{
		"gitlab.base_url":  c.GitLab.BaseURL,
		"forgejo.base_url": c.Forgejo.BaseURL,
	} {
		if base == "" {
			continue
		}
		u, err := url.Parse(base)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("%s must be an http(s):// URL, got %q", name, base)
		}
	}
	return nil
}

// secretBrokerProviders are the supported secret brokers.
var secretBrokerProviders = map[string]bool{
	"vault": true, "aws": true, "gcp": true, "azure": true, "onepassword": true, "static": true,
}

// validateSecretBroker enforces the per-provider credential requirements so
// a misconfigured broker surfaces at startup instead of at first resolve.
func validateSecretBroker(c SecretBrokerConfig) error {
	b := c.Broker
	if b == "" {
		return nil
	}
	if !secretBrokerProviders[b] {
		return fmt.Errorf("secret_broker.broker must be one of vault, aws, gcp, azure, onepassword, static, got %q", b)
	}
	switch b {
	case "vault":
		if c.VaultAddr == "" {
			return fmt.Errorf("secret_broker.broker \"vault\" requires secret_broker.vault_addr")
		}
	case "aws":
		if c.AWSRegion == "" {
			return fmt.Errorf("secret_broker.broker \"aws\" requires secret_broker.aws_region")
		}
	case "gcp":
		if c.GCPProject == "" || c.GCPCredentials == "" {
			return fmt.Errorf("secret_broker.broker \"gcp\" requires secret_broker.gcp_project and secret_broker.gcp_credentials")
		}
	case "azure":
		if c.AzureTenant == "" || c.AzureClientID == "" || c.AzureSecret == "" || c.AzureVaultURL == "" {
			return fmt.Errorf("secret_broker.broker \"azure\" requires secret_broker.azure_tenant, azure_client_id, azure_client_secret and azure_vault_url")
		}
	case "onepassword":
		if c.OnePasswordHost == "" || c.OnePasswordToken == "" || c.OnePasswordVault == "" {
			return fmt.Errorf("secret_broker.broker \"onepassword\" requires secret_broker.onepassword_host, onepassword_token and onepassword_vault")
		}
	case "static":
		if strings.TrimSpace(c.Static) == "" {
			return fmt.Errorf("secret_broker.broker \"static\" requires at least one secret_broker.static k=v entry")
		}
	}
	return nil
}

// ApplyEnv overlays KIWI_* environment variables onto the config (env
// beats config file, loses to CLI flags). Parsing is strict: an explicitly
// provided malformed numeric/bool environment variable fails startup
// instead of silently falling back to the config file or default — a typo
// in an env override must never produce a silently different deployment.
func (c *Config) ApplyEnv() error {
	vars := []struct {
		name string
		dst  *string
	}{
		{"KIWI_EXTERNAL_URL", &c.Server.ExternalURL},
		{"KIWI_SERVER_EXTERNAL_URL", &c.Server.ExternalURL},
		{"KIWI_SERVER_LISTEN", &c.Server.Listen},
		{"KIWI_SERVER_MODE", &c.Server.Mode},
		{"KIWI_SERVER_TLS_CERT", &c.Server.TLSCert},
		{"KIWI_SERVER_TLS_KEY", &c.Server.TLSKey},
		{"KIWI_DATABASE_URL", &c.Database.URL},
		{"KIWI_GITHUB_WEBHOOK_SECRET", &c.GitHub.WebhookSecret},
		{"KIWI_GITHUB_TOKEN", &c.GitHub.Token},
		{"KIWI_GITHUB_PRIVATE_KEY_PATH", &c.GitHub.PrivateKeyPath},
		{"KIWI_GITLAB_WEBHOOK_SECRET", &c.GitLab.WebhookSecret},
		{"KIWI_GITLAB_TOKEN", &c.GitLab.Token},
		{"KIWI_GITLAB_BASE_URL", &c.GitLab.BaseURL},
		{"KIWI_FORGEJO_WEBHOOK_SECRET", &c.Forgejo.WebhookSecret},
		{"KIWI_FORGEJO_TOKEN", &c.Forgejo.Token},
		{"KIWI_FORGEJO_BASE_URL", &c.Forgejo.BaseURL},
		{"KIWI_RUNNER_TOKEN", &c.Auth.RunnerToken},
		{"KIWI_ADMIN_TOKEN", &c.Auth.AdminToken},
		{"KIWI_AUTH_TOKENS_FILE", &c.Auth.TokensFile},
		{"KIWI_AUTH_RUNNER_TOKENS_FILE", &c.Auth.RunnerTokensFile},
		{"KIWI_RUNNER_ENROLL_TOKEN", &c.RunnerPKI.EnrollToken},
		{"KIWI_BLOB_BACKEND", &c.Blob.Backend},
		{"KIWI_OTEL_ENDPOINT", &c.Observability.OTelEndpoint},
		{"KIWI_METRICS_LISTEN", &c.Observability.MetricsListen},
		{"KIWI_SECRET_BROKER", &c.SecretBroker.Broker},
		{"KIWI_VAULT_ADDR", &c.SecretBroker.VaultAddr},
		{"KIWI_VAULT_TOKEN", &c.SecretBroker.VaultToken},
		{"KIWI_AWS_REGION", &c.SecretBroker.AWSRegion},
		{"KIWI_AWS_ACCESS_KEY", &c.SecretBroker.AWSAccessKey},
		{"KIWI_AWS_SECRET_KEY", &c.SecretBroker.AWSSecretKey},
		{"KIWI_AWS_TOKEN", &c.SecretBroker.AWSToken},
		{"KIWI_GCP_CREDENTIALS", &c.SecretBroker.GCPCredentials},
		{"KIWI_GCP_PROJECT", &c.SecretBroker.GCPProject},
		{"KIWI_AZURE_TENANT", &c.SecretBroker.AzureTenant},
		{"KIWI_AZURE_CLIENT_ID", &c.SecretBroker.AzureClientID},
		{"KIWI_AZURE_CLIENT_SECRET", &c.SecretBroker.AzureSecret},
		{"KIWI_AZURE_VAULT_URL", &c.SecretBroker.AzureVaultURL},
		{"KIWI_ONEPASSWORD_HOST", &c.SecretBroker.OnePasswordHost},
		{"KIWI_ONEPASSWORD_TOKEN", &c.SecretBroker.OnePasswordToken},
		{"KIWI_ONEPASSWORD_VAULT", &c.SecretBroker.OnePasswordVault},
		{"KIWI_SECRET_STATIC", &c.SecretBroker.Static},
		{"KIWI_COMPONENT_REGISTRY_DIR", &c.Components.RegistryDir},
		{"KIWI_COMPONENT_REMOTE", &c.Components.RemoteURL},
		{"KIWI_COMPONENT_REMOTE_TOKEN", &c.Components.RemoteToken},
	}
	for _, e := range vars {
		if v, ok := os.LookupEnv(e.name); ok {
			*e.dst = v
		}
	}
	if v, ok := os.LookupEnv("KIWI_DATABASE_MAX_CONNECTIONS"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("KIWI_DATABASE_MAX_CONNECTIONS: invalid integer %q", v)
		}
		if n > 0 {
			c.Database.MaxConnections = n
		}
	}
	if v, ok := os.LookupEnv("KIWI_GITHUB_APP_ID"); ok {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("KIWI_GITHUB_APP_ID: invalid integer %q", v)
		}
		c.GitHub.AppID = n
	}
	if v, ok := os.LookupEnv("KIWI_QUOTA_FAIL_OPEN"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("KIWI_QUOTA_FAIL_OPEN: invalid boolean %q", v)
		}
		c.Quota.FailOpen = b
	}
	// Numeric quota overrides: the KIWI_QUOTA_-prefixed spellings are the
	// canonical names and win over the legacy unprefixed ones.
	for _, q := range []struct {
		name, legacy string
		dst          *float64
	}{
		{"KIWI_QUOTA_REPO_CONCURRENCY", "KIWI_REPO_CONCURRENCY", &c.Quota.RepoConcurrency},
		{"KIWI_QUOTA_TEAM_CONCURRENCY", "KIWI_TEAM_CONCURRENCY", &c.Quota.TeamConcurrency},
		{"KIWI_QUOTA_REPO_QUEUE_DEPTH", "KIWI_REPO_QUEUE_DEPTH", &c.Quota.RepoQueueDepth},
		{"KIWI_QUOTA_TEAM_QUEUE_DEPTH", "KIWI_TEAM_QUEUE_DEPTH", &c.Quota.TeamQueueDepth},
		{"KIWI_QUOTA_DAILY_COST_LIMIT", "KIWI_DAILY_COST_LIMIT", &c.Quota.DailyCostLimit},
		{"KIWI_QUOTA_DAILY_ENERGY_LIMIT", "KIWI_DAILY_ENERGY_LIMIT", &c.Quota.DailyEnergyLimit},
	} {
		v, ok := os.LookupEnv(q.name)
		if !ok {
			v, ok = os.LookupEnv(q.legacy)
		}
		if ok {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return fmt.Errorf("%s: invalid number %q", q.name, v)
			}
			*q.dst = f
		}
	}
	return nil
}

// OverrideFromFlags applies CLI flags that were explicitly set (flags left
// at their defaults do not override the config file or environment). Only
// server-relevant flags are mapped; unknown flags are ignored so the same
// call works for future flag sets.
func (c *Config) OverrideFromFlags(fs *flag.FlagSet) error {
	var err error
	fs.Visit(func(f *flag.Flag) {
		if err != nil {
			return
		}
		switch f.Name {
		case "listen":
			c.Server.Listen = f.Value.String()
		case "mode":
			c.Server.Mode = f.Value.String()
		case "external-url":
			c.Server.ExternalURL = f.Value.String()
		case "tls-cert":
			c.Server.TLSCert = f.Value.String()
		case "tls-key":
			c.Server.TLSKey = f.Value.String()
		case "database-url":
			c.Database.URL = f.Value.String()
		case "runner-token":
			c.Auth.RunnerToken = f.Value.String()
		case "admin-token":
			c.Auth.AdminToken = f.Value.String()
		case "runner-enroll-token":
			c.RunnerPKI.EnrollToken = f.Value.String()
		case "runner-ca-cert":
			c.RunnerPKI.CACert = f.Value.String()
		case "runner-ca-key":
			c.RunnerPKI.CAKey = f.Value.String()
		case "github-webhook-secret":
			c.GitHub.WebhookSecret = f.Value.String()
		case "github-token":
			c.GitHub.Token = f.Value.String()
		case "github-app-id":
			if f.Value.String() != "" {
				v, perr := strconv.ParseInt(f.Value.String(), 10, 64)
				if perr != nil {
					err = fmt.Errorf("--github-app-id: %w", perr)
				} else {
					c.GitHub.AppID = v
				}
			}
		case "github-app-private-key":
			c.GitHub.PrivateKeyPath = f.Value.String()
		case "gitlab-token":
			c.GitLab.Token = f.Value.String()
		case "gitlab-webhook-secret":
			c.GitLab.WebhookSecret = f.Value.String()
		case "gitlab-base-url":
			c.GitLab.BaseURL = f.Value.String()
		case "forgejo-token":
			c.Forgejo.Token = f.Value.String()
		case "forgejo-webhook-secret":
			c.Forgejo.WebhookSecret = f.Value.String()
		case "forgejo-base-url":
			c.Forgejo.BaseURL = f.Value.String()
		case "tokens-file":
			c.Auth.TokensFile = f.Value.String()
		case "runner-tokens-file":
			c.Auth.RunnerTokensFile = f.Value.String()
		case "database-max-connections":
			if f.Value.String() != "" {
				v, perr := strconv.Atoi(f.Value.String())
				if perr != nil {
					err = fmt.Errorf("--database-max-connections: %w", perr)
				} else {
					c.Database.MaxConnections = v
				}
			}
		case "metrics-listen":
			c.Observability.MetricsListen = f.Value.String()
		case "secret-broker":
			c.SecretBroker.Broker = f.Value.String()
		case "vault-addr":
			c.SecretBroker.VaultAddr = f.Value.String()
		case "vault-token":
			c.SecretBroker.VaultToken = f.Value.String()
		case "aws-region":
			c.SecretBroker.AWSRegion = f.Value.String()
		case "aws-access-key":
			c.SecretBroker.AWSAccessKey = f.Value.String()
		case "aws-secret-key":
			c.SecretBroker.AWSSecretKey = f.Value.String()
		case "aws-token":
			c.SecretBroker.AWSToken = f.Value.String()
		case "gcp-credentials":
			c.SecretBroker.GCPCredentials = f.Value.String()
		case "gcp-project":
			c.SecretBroker.GCPProject = f.Value.String()
		case "azure-tenant":
			c.SecretBroker.AzureTenant = f.Value.String()
		case "azure-client-id":
			c.SecretBroker.AzureClientID = f.Value.String()
		case "azure-client-secret":
			c.SecretBroker.AzureSecret = f.Value.String()
		case "azure-vault-url":
			c.SecretBroker.AzureVaultURL = f.Value.String()
		case "onepassword-host":
			c.SecretBroker.OnePasswordHost = f.Value.String()
		case "onepassword-token":
			c.SecretBroker.OnePasswordToken = f.Value.String()
		case "onepassword-vault":
			c.SecretBroker.OnePasswordVault = f.Value.String()
		case "secret-static":
			c.SecretBroker.Static = f.Value.String()
		case "component-registry-dir":
			c.Components.RegistryDir = f.Value.String()
		case "component-remote":
			c.Components.RemoteURL = f.Value.String()
		case "component-remote-token":
			c.Components.RemoteToken = f.Value.String()
		case "repo-concurrency":
			if perr := flagFloat(f, &c.Quota.RepoConcurrency); perr != nil {
				err = perr
			}
		case "team-concurrency":
			if perr := flagFloat(f, &c.Quota.TeamConcurrency); perr != nil {
				err = perr
			}
		case "repo-queue-depth":
			if perr := flagFloat(f, &c.Quota.RepoQueueDepth); perr != nil {
				err = perr
			}
		case "team-queue-depth":
			if perr := flagFloat(f, &c.Quota.TeamQueueDepth); perr != nil {
				err = perr
			}
		case "daily-cost-limit":
			if perr := flagFloat(f, &c.Quota.DailyCostLimit); perr != nil {
				err = perr
			}
		case "daily-energy-limit":
			if perr := flagFloat(f, &c.Quota.DailyEnergyLimit); perr != nil {
				err = perr
			}
		case "quota-fail-open":
			if f.Value.String() != "" {
				v, perr := strconv.ParseBool(f.Value.String())
				if perr != nil {
					err = fmt.Errorf("--quota-fail-open: %w", perr)
				} else {
					c.Quota.FailOpen = v
				}
			}
		case "otel-endpoint":
			c.Observability.OTelEndpoint = f.Value.String()
		case "rate-limit-per-second":
			if f.Value.String() != "" {
				if v, perr := strconv.ParseFloat(f.Value.String(), 64); perr != nil {
					err = fmt.Errorf("--rate-limit-per-second: %w", perr)
				} else {
					c.RateLimit.PerSecond = v
				}
			}
		case "rate-limit-burst":
			if f.Value.String() != "" {
				if v, perr := strconv.Atoi(f.Value.String()); perr != nil {
					err = fmt.Errorf("--rate-limit-burst: %w", perr)
				} else {
					c.RateLimit.Burst = v
				}
			}
		}
	})
	return err
}

// flagFloat parses a non-empty float flag value into dst. Empty values
// (flags left unset) are ignored.
func flagFloat(f *flag.Flag, dst *float64) error {
	if f.Value.String() == "" {
		return nil
	}
	v, err := strconv.ParseFloat(f.Value.String(), 64)
	if err != nil {
		return fmt.Errorf("--%s: %w", f.Name, err)
	}
	*dst = v
	return nil
}

// RateLimitClasses returns the effective per-class rates: each class uses
// its *_per_second override, falling back to the global PerSecond.
func (c *Config) RateLimitClasses() map[string]float64 {
	base := c.RateLimit.PerSecond
	pick := func(v float64) float64 {
		if v > 0 {
			return v
		}
		return base
	}
	return map[string]float64{
		ratelimit.ClassEnroll:         pick(c.RateLimit.EnrollPerSecond),
		ratelimit.ClassRegister:       pick(c.RateLimit.RegisterPerSecond),
		ratelimit.ClassNext:           pick(c.RateLimit.NextPerSecond),
		ratelimit.ClassHeartbeat:      pick(c.RateLimit.HeartbeatPerSecond),
		ratelimit.ClassOIDC:           pick(c.RateLimit.OIDCPerSecond),
		ratelimit.ClassSecrets:        pick(c.RateLimit.SecretsPerSecond),
		ratelimit.ClassLogs:           pick(c.RateLimit.LogsPerSecond),
		ratelimit.ClassArtifactUpload: pick(c.RateLimit.ArtifactUploadPerSecond),
		ratelimit.ClassCacheUpload:    pick(c.RateLimit.CacheUploadPerSecond),
		ratelimit.ClassDispatch:       pick(c.RateLimit.DispatchPerSecond),
		ratelimit.ClassWebhooks:       pick(c.RateLimit.WebhooksPerSecond),
		ratelimit.ClassLogin:          pick(c.RateLimit.LoginPerSecond),
		ratelimit.ClassDefault:        base,
	}
}

// RateLimitBurst returns the effective burst size (default 100).
func (c *Config) RateLimitBurst() int {
	if c.RateLimit.Burst > 0 {
		return c.RateLimit.Burst
	}
	return 100
}

// RateLimitMiddleware builds the request rate limiter from the rate_limit
// section, or returns nil when limiting is disabled (no rates configured).
func (c *Config) RateLimitMiddleware() *ratelimit.Middleware {
	classes := c.RateLimitClasses()
	enabled := false
	for _, r := range classes {
		if r > 0 {
			enabled = true
			break
		}
	}
	if !enabled {
		return nil
	}
	return ratelimit.NewMiddleware(classes, c.RateLimitBurst())
}
