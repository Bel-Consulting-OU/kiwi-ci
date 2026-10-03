package app

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/config"
)

// ConfigCheck implements `kiwi config check`: it loads and validates a
// configuration file (including the environment overlay and the schema
// invariants) without starting the server. All sections — server,
// database, runner_pki, blob, github, gitlab, forgejo, policy,
// observability, rate_limit, auth, quota, secret_broker and components —
// are covered by config.Validate.
func ConfigCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("config check", flag.ContinueOnError)
	path := fs.String("config", "kiwi.toml", "configuration file to validate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	if err := cfg.ApplyEnv(); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	// Production-mode parity with `kiwi server`: the same static hardening
	// contract, so a config that passes `config check` cannot fail startup
	// for a static reason (missing shared session key, disabled untrusted
	// ceilings, missing staging bound, weak admin token, ...).
	if strings.TrimSpace(cfg.Server.Mode) == "production" {
		if err := validateProductionConfig(productionConfig{
			Mode:                   cfg.Server.Mode,
			DatabaseURL:            cfg.Database.URL,
			RunnerToken:            cfg.Auth.RunnerToken,
			AdminToken:             cfg.Auth.AdminToken,
			ExternalURL:            cfg.Server.ExternalURL,
			TLSCert:                cfg.Server.TLSCert,
			TLSKey:                 cfg.Server.TLSKey,
			StagingDir:             cfg.Staging.Dir,
			StagingMaxBytes:        cfg.Staging.MaxBytes,
			StagingInstanceID:      cfg.Staging.InstanceID,
			WebSessionSecret:       strings.TrimSpace(os.Getenv("KIWI_WEB_SESSION_SECRET")),
			UntrustedCPUCeiling:    cfg.Quota.UntrustedCPUCeiling,
			UntrustedMemoryCeiling: cfg.Quota.UntrustedMemoryCeiling,
			UntrustedDiskCeiling:   cfg.Quota.UntrustedDiskCeiling,
		}); err != nil {
			return fmt.Errorf("invalid production config: %w", err)
		}
	}
	summary := map[string]string{
		"mode":           cfg.Server.Mode,
		"listen":         cfg.Server.Listen,
		"database":       boolWord(cfg.Database.URL != ""),
		"quota":          boolWord(cfg.Quota.RepoConcurrency > 0 || cfg.Quota.TeamConcurrency > 0 || cfg.Quota.RepoQueueDepth > 0 || cfg.Quota.TeamQueueDepth > 0 || cfg.Quota.DailyCostLimit > 0 || cfg.Quota.DailyEnergyLimit > 0),
		"secret_broker":  orWord(cfg.SecretBroker.Broker, "none"),
		"components":     boolWord(cfg.Components.RegistryDir != "" || cfg.Components.RemoteURL != ""),
		"metrics_listen": orWord(cfg.Observability.MetricsListen, "main-listener"),
		"tokens_file":    boolWord(cfg.Auth.TokensFile != ""),
	}
	fmt.Printf("config %s is valid (mode=%s, listen=%s, database=%s, quota=%s, secret_broker=%s, components=%s, metrics_listen=%s, tokens_file=%s)\n",
		*path, summary["mode"], summary["listen"], summary["database"], summary["quota"], summary["secret_broker"], summary["components"], summary["metrics_listen"], summary["tokens_file"])
	return nil
}

// boolWord renders a boolean as a stable summary word.
func boolWord(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// orWord renders a possibly-empty string with a fallback word.
func orWord(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
