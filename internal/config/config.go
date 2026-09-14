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
	"os"
	"strconv"
	"strings"

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
}

type ForgejoConfig struct {
	WebhookSecret string `toml:"webhook_secret"`
	Token         string `toml:"token"`
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
	// RunnerToken is the bearer token shared by all runners.
	RunnerToken string `toml:"runner_token"`
	// TokensFile is the JSON token-store path for fine-grained principals.
	TokensFile string `toml:"tokens_file"`
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
	return nil
}

// ApplyEnv overlays KIWI_* environment variables onto the config (env
// beats config file, loses to CLI flags). It cannot fail; the error return
// keeps the precedence pipeline uniform.
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
		{"KIWI_GITLAB_WEBHOOK_SECRET", &c.GitLab.WebhookSecret},
		{"KIWI_GITLAB_TOKEN", &c.GitLab.Token},
		{"KIWI_FORGEJO_WEBHOOK_SECRET", &c.Forgejo.WebhookSecret},
		{"KIWI_FORGEJO_TOKEN", &c.Forgejo.Token},
		{"KIWI_RUNNER_TOKEN", &c.Auth.RunnerToken},
		{"KIWI_ADMIN_TOKEN", &c.Auth.AdminToken},
		{"KIWI_RUNNER_ENROLL_TOKEN", &c.RunnerPKI.EnrollToken},
		{"KIWI_BLOB_BACKEND", &c.Blob.Backend},
		{"KIWI_OTEL_ENDPOINT", &c.Observability.OTelEndpoint},
	}
	for _, e := range vars {
		if v, ok := os.LookupEnv(e.name); ok {
			*e.dst = v
		}
	}
	if v, ok := os.LookupEnv("KIWI_DATABASE_MAX_CONNECTIONS"); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.Database.MaxConnections = n
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
