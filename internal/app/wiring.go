package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/components"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/config"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/quotas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// applyForgeConfig wires the forge integration surface from the merged
// configuration: webhook secrets and API tokens for all three forges, base
// URL overrides for self-hosted GitLab/Forgejo, and the GitHub App
// credential pair (the App installation-token adapter authenticates
// FetchFile/ChangedFiles/PublishCheck; the plain token remains the
// fallback when no App is configured).
func applyForgeConfig(srv *server.Server, cfg *config.Config) error {
	srv.GitHubWebhookSecret = cfg.GitHub.WebhookSecret
	srv.GitHubToken = cfg.GitHub.Token
	srv.GitLabWebhookSecret = cfg.GitLab.WebhookSecret
	srv.GitLabToken = cfg.GitLab.Token
	srv.ForgejoWebhookSecret = cfg.Forgejo.WebhookSecret
	srv.ForgejoToken = cfg.Forgejo.Token
	if cfg.GitLab.BaseURL != "" {
		srv.SetForgeBaseURL("gitlab", cfg.GitLab.BaseURL)
	}
	if cfg.Forgejo.BaseURL != "" {
		srv.SetForgeBaseURL("forgejo", cfg.Forgejo.BaseURL)
	}
	if cfg.GitHub.AppID != 0 {
		keyPEM, err := os.ReadFile(cfg.GitHub.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("github app private key: %w", err)
		}
		srv.GitHubAppID = cfg.GitHub.AppID
		srv.GitHubAppPrivateKey = string(keyPEM)
	}
	return nil
}

// applyAuthConfig loads the fine-grained principal token store when
// auth.tokens_file is configured. The auth middleware already reads
// srv.AuthStore, so loading the file activates the store.
func applyAuthConfig(srv *server.Server, cfg *config.Config) error {
	if cfg.Auth.TokensFile == "" {
		return nil
	}
	if err := srv.AuthStore.Load(cfg.Auth.TokensFile); err != nil {
		return fmt.Errorf("auth tokens file: %w", err)
	}
	return nil
}

// applyQuotaConfig populates the server's quota policy: per-repo/team
// concurrency and queue depth, the trailing-24h daily cost/energy budgets,
// and the fail-open switch.
func applyQuotaConfig(srv *server.Server, cfg *config.Config) {
	srv.QuotaLimits = quotas.Limits{
		RepoConcurrency: cfg.Quota.RepoConcurrency,
		TeamConcurrency: cfg.Quota.TeamConcurrency,
		RepoQueueDepth:  cfg.Quota.RepoQueueDepth,
		TeamQueueDepth:  cfg.Quota.TeamQueueDepth,
	}
	srv.DailyCostLimit = cfg.Quota.DailyCostLimit
	srv.DailyEnergyLimit = cfg.Quota.DailyEnergyLimit
	srv.QuotaFailOpen = cfg.Quota.FailOpen
}

// buildSecretBroker constructs the secret broker chain from the
// secret_broker section: the selected provider broker plus (when
// configured) the static broker as a fallback. It returns nil when no
// broker is configured (the secrets endpoint stays disabled).
func buildSecretBroker(cfg config.SecretBrokerConfig) (secretbroker.Broker, error) {
	var primary secretbroker.Broker
	switch cfg.Broker {
	case "":
	case "vault":
		primary = &secretbroker.VaultClient{Address: cfg.VaultAddr, Token: cfg.VaultToken}
	case "aws":
		primary = &secretbroker.SecretsManagerClient{
			Region:          cfg.AWSRegion,
			AccessKeyID:     cfg.AWSAccessKey,
			SecretAccessKey: cfg.AWSSecretKey,
			SessionToken:    cfg.AWSToken,
		}
	case "gcp":
		email, keyPEM, err := parseGCPServiceAccount(cfg.GCPCredentials)
		if err != nil {
			return nil, err
		}
		primary = &secretbroker.GCPClient{
			Project:       cfg.GCPProject,
			ClientEmail:   email,
			PrivateKeyPEM: keyPEM,
		}
	case "azure":
		primary = &secretbroker.AzureClient{
			TenantID:     cfg.AzureTenant,
			ClientID:     cfg.AzureClientID,
			ClientSecret: cfg.AzureSecret,
			VaultURL:     cfg.AzureVaultURL,
		}
	case "onepassword":
		primary = &secretbroker.OnePasswordClient{
			Host:    cfg.OnePasswordHost,
			Token:   cfg.OnePasswordToken,
			VaultID: cfg.OnePasswordVault,
		}
	case "static":
		primary = secretbroker.StaticBroker(parseStaticPairs(cfg.Static))
	default:
		return nil, fmt.Errorf("secret broker: unknown provider %q", cfg.Broker)
	}
	static := parseStaticPairs(cfg.Static)
	var chain secretbroker.ChainBroker
	if primary != nil {
		chain = append(chain, primary)
	}
	if len(static) > 0 && cfg.Broker != "static" {
		chain = append(chain, secretbroker.StaticBroker(static))
	}
	switch len(chain) {
	case 0:
		return nil, nil
	case 1:
		return chain[0], nil
	default:
		return chain, nil
	}
}

// parseStaticPairs parses comma-separated k=v entries (the first "="
// separates key and value) into a static secret map.
func parseStaticPairs(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// parseGCPServiceAccount reads a GCP service-account JSON credentials file
// and returns the client email and private key PEM.
func parseGCPServiceAccount(path string) (string, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("secret broker: gcp credentials: %w", err)
	}
	var sa struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal(b, &sa); err != nil {
		return "", nil, fmt.Errorf("secret broker: gcp credentials: %w", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return "", nil, fmt.Errorf("secret broker: gcp credentials file %s has no client_email/private_key", path)
	}
	return sa.ClientEmail, []byte(sa.PrivateKey), nil
}

// buildComponentRegistry constructs the component registry from the
// components section: a local directory registry and/or a remote registry
// client (strict https, no redirects). A nil result keeps server-side
// component resolution disabled (pipelines referencing components are
// rejected).
func buildComponentRegistry(cfg config.ComponentsConfig) (components.Registry, error) {
	var chain components.ChainRegistry
	if cfg.RegistryDir != "" {
		local, err := components.NewLocalRegistryFromDir(cfg.RegistryDir)
		if err != nil {
			return nil, err
		}
		chain = append(chain, local)
	}
	if cfg.RemoteURL != "" {
		remote, err := components.NewRemoteRegistry(cfg.RemoteURL, cfg.RemoteToken)
		if err != nil {
			return nil, err
		}
		chain = append(chain, remote)
	}
	switch len(chain) {
	case 0:
		return nil, nil
	case 1:
		return chain[0], nil
	default:
		return chain, nil
	}
}

// startMetricsListener binds the dedicated metrics listener and serves the
// server's Prometheus surface on it. Binding is synchronous so an
// observability.metrics_listen address that cannot be bound fails startup;
// the returned stop function shuts the listener down. The returned addr is
// the actual bound address (useful when the configured address uses port
// 0).
func startMetricsListener(srv *server.Server, addr string) (bound string, stop func(), err error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, fmt.Errorf("metrics listener %s: %w", addr, err)
	}
	h := &http.Server{
		Handler:           srv.MetricsHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = h.Serve(ln) }()
	return ln.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.Shutdown(ctx)
	}, nil
}
