package app

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/config"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runner"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// productionConfig is the pure input to validateProductionConfig, extracted
// so production-mode requirements are unit-testable without a network.
// Server() fills it from the merged configuration (CLI > environment >
// config file > defaults).
type productionConfig struct {
	Mode             string
	DatabaseURL      string
	RunnerToken      string
	AdminToken       string
	ExternalURL      string
	TLSCert          string
	TLSKey           string
	AllowSharedToken bool
	// RunnerMTLSEnforced reports whether runner client certificates are
	// mandatory (runner CA configured and --runner-require-client-certs
	// not disabled). When enforced, the runner bearer token becomes
	// optional in production.
	RunnerMTLSEnforced bool
}

// validateProductionConfig enforces the production-mode startup contract:
// a database URL, distinct admin/runner credentials (or an explicit
// --allow-shared-token), an external URL (the OIDC issuer always serves in
// production), TLS, and a working runner credential. The runner bearer
// token is a SHARED credential, not a per-runner identity; when an admin
// token is configured but no runner token, enforced runner mTLS is the
// only acceptable runner authentication (fail closed). Dev mode has no
// additional requirements.
// drainTimeout bounds the graceful drain wait on signal.
const drainTimeout = 30 * time.Second

// drainableServer is the compile-checkable adoption seam for the server
// agent's graceful-drain methods: BeginDrain marks the control plane
// draining (no new jobs, runners finish active work) and ActiveJobs reports
// the number of in-flight jobs. Once *server.Server implements both, the
// --drain-on-sigterm flag activates automatically.
type drainableServer interface {
	BeginDrain(reason string)
	ActiveJobs() int
}

// blobStoreSetter is the compile-checkable adoption seam for the server
// agent's SetBlobStore method: when the server build provides it, the blob
// backend configured via config (s3 or the data-dir filesystem) is wired
// in; otherwise a warning is printed and the server defaults apply.
type blobStoreSetter interface {
	SetBlobStore(store blob.Store)
}

// waitForDrain polls ActiveJobs until it is zero or the timeout elapses. It
// reports whether the drain completed within the bound.
func waitForDrain(s drainableServer, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if s.ActiveJobs() == 0 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// buildBlobStore constructs the blob backend from the merged config: s3
// when blob.backend is s3, otherwise the filesystem rooted at blob.path or
// <data-dir>/blobs.
func buildBlobStore(cfg config.BlobConfig, dataDir string) blob.Store {
	switch cfg.Backend {
	case "s3":
		return &blob.S3{
			Endpoint:        cfg.S3Endpoint,
			Region:          cfg.S3Region,
			Bucket:          cfg.S3Bucket,
			AccessKeyID:     cfg.S3AccessKey,
			SecretAccessKey: cfg.S3SecretKey,
		}
	default:
		root := cfg.Path
		if root == "" {
			root = filepath.Join(dataDir, "blobs")
		}
		return blob.NewFS(root)
	}
}

func validateProductionConfig(cfg productionConfig) error {
	switch cfg.Mode {
	case "dev", "production":
	case "":
		cfg.Mode = "dev"
	default:
		return fmt.Errorf("--mode must be \"dev\" or \"production\", got %q", cfg.Mode)
	}
	if cfg.Mode != "production" {
		return nil
	}
	if cfg.DatabaseURL == "" {
		return fmt.Errorf("production mode requires --database-url")
	}
	if cfg.AdminToken == "" || cfg.AdminToken == cfg.RunnerToken {
		if !cfg.AllowSharedToken {
			return fmt.Errorf("production mode requires distinct --admin-token and --runner-token (or --allow-shared-token to acknowledge the shared credential)")
		}
	}
	if cfg.ExternalURL == "" {
		return fmt.Errorf("production mode requires --external-url (the OIDC issuer always serves in production)")
	}
	if cfg.TLSCert == "" || cfg.TLSKey == "" {
		return fmt.Errorf("production mode requires --tls-cert and --tls-key")
	}
	// Fail closed: an admin token without any runner credential would serve
	// 503s on every runner route (the server's own fail-closed tier), so
	// refuse it at startup unless runner mTLS is enforced.
	if cfg.AdminToken != "" && cfg.RunnerToken == "" && !cfg.RunnerMTLSEnforced {
		return fmt.Errorf("production mode with an admin token requires --runner-token or enforced runner mTLS (--runner-ca-cert/--runner-ca-key with --runner-require-client-certs)")
	}
	return nil
}

func Server(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	// Flags default to empty: effective values come from the merged
	// configuration (CLI > environment > config file > defaults). Only
	// explicitly set flags override the config.
	listen := fs.String("listen", "", "listen address (default: \":8080\")")
	// The runner bearer token is a SHARED credential across all runners,
	// not a per-runner identity. Production strongly prefers persistent
	// per-runner mTLS identities (--runner-ca-cert/--runner-ca-key +
	// enrollment); the control plane fails closed when neither is present.
	token := fs.String("runner-token", "", "runner bearer token shared by all runners (prefer per-runner mTLS certificates in production)")
	adminToken := fs.String("admin-token", "", "admin bearer token (defaults to runner token)")
	webhookSecret := fs.String("github-webhook-secret", "", "GitHub webhook HMAC secret")
	githubToken := fs.String("github-token", "", "GitHub token for private pipeline fetches")
	pipelinePath := fs.String("pipeline-path", ".kiwi/pipeline.yaml", "pipeline path in repositories")
	dataDir := fs.String("data-dir", "", "persistent state directory (default: in-memory; production deployments should always set this)")
	externalURL := fs.String("external-url", "", "public base URL (required for OIDC)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	tlsKey := fs.String("tls-key", "", "TLS private key file")
	runnerCACert := fs.String("runner-ca-cert", "", "runner CA certificate PEM (enables runner certificate enrollment and per-runner mTLS identity)")
	runnerCAKey := fs.String("runner-ca-key", "", "runner CA private key PEM")
	runnerEnrollToken := fs.String("runner-enroll-token", "", "token authorizing runner certificate enrollment")
	// The shared TLS listener always uses VerifyClientCertIfGiven: the
	// certificate requirement for runner-tier routes is enforced at the
	// HTTP authorization layer, keeping admin/forge/enrollment traffic on
	// the same listener.
	runnerRequireClientCerts := fs.Bool("runner-require-client-certs", true, "require runner client certificates on runner-tier routes when a runner CA is configured (default true)")
	clusterKeyDir := fs.String("cluster-key-dir", "", "shared cluster key store directory (HA replicas share signing material); requires --data-dir")
	databaseURL := fs.String("database-url", "", "PostgreSQL connection URL (wires the durable SQL control plane)")
	mode := fs.String("mode", "", "server mode: dev (in-memory, default) or production")
	allowSharedToken := fs.Bool("allow-shared-token", false, "production: allow --admin-token to equal --runner-token")
	configPath := fs.String("config", "", "TOML configuration file (kiwi.toml); CLI flags override it")
	otelEndpoint := fs.String("otel-endpoint", "", "OpenTelemetry OTLP/HTTP collector endpoint (enables tracing)")
	rateLimitPerSecond := fs.Float64("rate-limit-per-second", 0, "global request rate limit per principal/runner/IP (0 disables)")
	rateLimitBurst := fs.Int("rate-limit-burst", 0, "rate limit burst size (default 100)")
	drainOnSigterm := fs.Bool("drain-on-sigterm", false, "on SIGTERM/SIGINT drain active jobs (up to 30s) before shutting down")
	githubAppID := fs.String("github-app-id", "", "GitHub App ID (enables installation-token auth for private pipeline fetches/statuses)")
	githubAppPrivateKey := fs.String("github-app-private-key", "", "GitHub App private key PEM file (requires --github-app-id)")
	gitlabToken := fs.String("gitlab-token", "", "GitLab API token for pipeline fetches and status publishing")
	gitlabWebhookSecret := fs.String("gitlab-webhook-secret", "", "GitLab webhook secret token")
	gitlabBaseURL := fs.String("gitlab-base-url", "", "self-managed GitLab instance root (default https://gitlab.com)")
	forgejoToken := fs.String("forgejo-token", "", "Forgejo API token for pipeline fetches and status publishing")
	forgejoWebhookSecret := fs.String("forgejo-webhook-secret", "", "Forgejo webhook HMAC secret")
	forgejoBaseURL := fs.String("forgejo-base-url", "", "self-managed Forgejo instance root (default https://codeberg.org)")
	tokensFile := fs.String("tokens-file", "", "JSON token-store file for fine-grained principal tokens")
	databaseMaxConnections := fs.String("database-max-connections", "", "PostgreSQL pool max connections")
	metricsListen := fs.String("metrics-listen", "", "serve /metrics on a separate listener address (e.g. :9091)")
	secretBroker := fs.String("secret-broker", "", "secret backend: vault, aws, gcp, azure, onepassword or static")
	vaultAddr := fs.String("vault-addr", "", "HashiCorp Vault address (requires --secret-broker vault)")
	vaultToken := fs.String("vault-token", "", "HashiCorp Vault token")
	awsRegion := fs.String("aws-region", "", "AWS region (requires --secret-broker aws)")
	awsAccessKey := fs.String("aws-access-key", "", "AWS access key ID")
	awsSecretKey := fs.String("aws-secret-key", "", "AWS secret access key")
	awsToken := fs.String("aws-token", "", "AWS session token")
	gcpCredentials := fs.String("gcp-credentials", "", "GCP service-account JSON credentials file (requires --secret-broker gcp)")
	gcpProject := fs.String("gcp-project", "", "GCP project (requires --secret-broker gcp)")
	azureTenant := fs.String("azure-tenant", "", "Azure tenant ID (requires --secret-broker azure)")
	azureClientID := fs.String("azure-client-id", "", "Azure client ID")
	azureClientSecret := fs.String("azure-client-secret", "", "Azure client secret")
	azureVaultURL := fs.String("azure-vault-url", "", "Azure Key Vault URL")
	onePasswordHost := fs.String("onepassword-host", "", "1Password Connect host (requires --secret-broker onepassword)")
	onePasswordToken := fs.String("onepassword-token", "", "1Password Connect bearer token")
	onePasswordVault := fs.String("onepassword-vault", "", "1Password Connect vault ID")
	var secretStatic stringList
	fs.Var(&secretStatic, "secret-static", "static secret k=v (repeatable; served by the static broker)")
	componentRegistryDir := fs.String("component-registry-dir", "", "directory of component spec files (server-side component registry)")
	componentRemote := fs.String("component-remote", "", "remote component registry base URL (https required)")
	componentRemoteToken := fs.String("component-remote-token", "", "bearer token for the remote component registry")
	repoConcurrency := fs.String("repo-concurrency", "", "per-repository running-job concurrency limit (0 = unlimited)")
	teamConcurrency := fs.String("team-concurrency", "", "per-team running-job concurrency limit (0 = unlimited)")
	repoQueueDepth := fs.String("repo-queue-depth", "", "per-repository queued-job depth limit (0 = unlimited)")
	teamQueueDepth := fs.String("team-queue-depth", "", "per-team queued-job depth limit (0 = unlimited)")
	dailyCostLimit := fs.String("daily-cost-limit", "", "trailing-24h cost budget (0 = unlimited)")
	dailyEnergyLimit := fs.String("daily-energy-limit", "", "trailing-24h energy budget in Wh (0 = unlimited)")
	quotaFailOpen := fs.Bool("quota-fail-open", false, "let enqueues/leases proceed when the usage store is unavailable instead of failing closed")
	var downstreamAllow repeatFlag
	fs.Var(&downstreamAllow, "downstream-allow", "downstream dispatch authorization: target=src[,src...] (repeatable; a target with no sources allows any source)")
	var downstreamTrustedIngress repeatFlag
	fs.Var(&downstreamTrustedIngress, "downstream-trusted-ingress", "downstream target inheriting the parent's trust: target=true|false (repeatable)")
	var sigstoreTrustKeys repeatFlag
	fs.Var(&sigstoreTrustKeys, "sigstore-key", "Sigstore verification key: id=/path/to/ed25519-public-key-pem (repeatable)")
	rekorPublicKey := fs.String("rekor-public-key", "", "Rekor transparency-log Ed25519 public key (PEM file or contents)")
	rekorBaseURL := fs.String("rekor-base-url", "", "Rekor transparency-log base URL (activates inclusion verification together with --rekor-public-key)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Merge the configuration: config file (or built-in defaults), then
	// environment, then explicitly set CLI flags.
	var cfg *config.Config
	var err error
	if *configPath != "" {
		cfg, err = config.Load(*configPath)
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
	} else {
		cfg = config.Default()
	}
	if err := cfg.ApplyEnv(); err != nil {
		return err
	}
	if err := cfg.OverrideFromFlags(fs); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	// The flag pointers exist only to register the flags; their values are
	// read back through config.OverrideFromFlags (which inspects only
	// explicitly set flags).
	discard(listen, token, adminToken, webhookSecret, githubToken, externalURL, tlsCert, tlsKey, runnerCACert, runnerCAKey, runnerEnrollToken, databaseURL, mode, rateLimitPerSecond, rateLimitBurst, otelEndpoint, drainOnSigterm, githubAppID, githubAppPrivateKey, gitlabToken, gitlabWebhookSecret, gitlabBaseURL, forgejoToken, forgejoWebhookSecret, forgejoBaseURL, tokensFile, databaseMaxConnections, metricsListen, secretBroker, vaultAddr, vaultToken, awsRegion, awsAccessKey, awsSecretKey, awsToken, gcpCredentials, gcpProject, azureTenant, azureClientID, azureClientSecret, azureVaultURL, onePasswordHost, onePasswordToken, onePasswordVault, componentRegistryDir, componentRemote, componentRemoteToken, repoConcurrency, teamConcurrency, repoQueueDepth, teamQueueDepth, dailyCostLimit, dailyEnergyLimit, quotaFailOpen)

	// Effective values after the precedence merge.
	listenV := cfg.Server.Listen
	if listenV == "" {
		listenV = ":8080"
	}
	tokenV := cfg.Auth.RunnerToken
	adminTokenV := cfg.Auth.AdminToken
	if adminTokenV == "" {
		adminTokenV = tokenV
	}
	modeV := cfg.Server.Mode
	if modeV == "" {
		modeV = "dev"
	}
	databaseURLV := cfg.Database.URL
	externalURLV := cfg.Server.ExternalURL
	tlsCertV := cfg.Server.TLSCert
	tlsKeyV := cfg.Server.TLSKey
	runnerEnrollTokenV := cfg.RunnerPKI.EnrollToken
	runnerCACertV := cfg.RunnerPKI.CACert
	runnerCAKeyV := cfg.RunnerPKI.CAKey

	if tlsCertV == "" && tlsKeyV != "" {
		return fmt.Errorf("--tls-key requires --tls-cert")
	}
	if tlsCertV != "" && tlsKeyV == "" {
		return fmt.Errorf("--tls-cert requires --tls-key")
	}
	if err := validateProductionConfig(productionConfig{
		Mode:               modeV,
		DatabaseURL:        databaseURLV,
		RunnerToken:        tokenV,
		AdminToken:         adminTokenV,
		ExternalURL:        externalURLV,
		TLSCert:            tlsCertV,
		TLSKey:             tlsKeyV,
		AllowSharedToken:   *allowSharedToken,
		RunnerMTLSEnforced: runnerCACertV != "" && runnerCAKeyV != "" && *runnerRequireClientCerts,
	}); err != nil {
		return err
	}
	var srv *server.Server
	var clusterStore *server.FSClusterKeyStore
	if *clusterKeyDir != "" {
		if *dataDir == "" {
			return fmt.Errorf("--cluster-key-dir requires --data-dir (the persistent state root)")
		}
		clusterStore = &server.FSClusterKeyStore{Dir: *clusterKeyDir}
	}
	if databaseURLV != "" {
		// DB mode: the SQL store is the source of truth. A data-dir is still
		// used when set (lease key, OIDC signer, artifact bytes); without it
		// artifact storage is unavailable.
		var pgOpts []storage.PostgresOption
		if cfg.Database.MaxConnections > 0 {
			pgOpts = append(pgOpts, storage.WithMaxConnections(cfg.Database.MaxConnections))
		}
		db, derr := storage.NewPostgresOpt(ctx, databaseURLV, pgOpts...)
		if derr != nil {
			return derr
		}
		defer db.Close()
		if merr := db.Migrate(ctx); merr != nil {
			return fmt.Errorf("auto-migrate: %w", merr)
		}
		if clusterStore != nil {
			srv, err = server.NewPersistentWithCluster(tokenV, adminTokenV, *dataDir, clusterStore)
		} else if *dataDir != "" {
			srv, err = server.NewPersistent(tokenV, adminTokenV, *dataDir)
		} else {
			srv = server.New(tokenV)
			if adminTokenV != "" {
				srv.AdminToken = adminTokenV
			}
		}
		if err != nil {
			return err
		}
		if err := srv.SwitchToDB(db); err != nil {
			return err
		}
		// A production DB control plane without a cluster key store would
		// mint per-replica signing material: replicas could not verify each
		// other's tokens. Surface that at startup.
		if modeV == "production" {
			if err := srv.ValidateHAReady(); err != nil {
				return err
			}
		}
	} else if clusterStore != nil {
		srv, err = server.NewPersistentWithCluster(tokenV, adminTokenV, *dataDir, clusterStore)
		if err != nil {
			return err
		}
	} else if *dataDir != "" {
		srv, err = server.NewPersistent(tokenV, adminTokenV, *dataDir)
		if err != nil {
			return err
		}
	} else {
		srv = server.New(tokenV)
		if adminTokenV != "" {
			srv.AdminToken = adminTokenV
		}
	}
	if err := applyForgeConfig(srv, cfg); err != nil {
		return err
	}
	if err := applyAuthConfig(srv, cfg); err != nil {
		return err
	}
	applyQuotaConfig(srv, cfg)
	// Downstream authorization and Sigstore trust roots are repeatable map
	// flags (not config-merged: the TOML schema does not model them).
	if allowlist, perr := parseDownstreamAllowlist(downstreamAllow.values()); perr != nil {
		return perr
	} else if len(allowlist) > 0 {
		srv.DownstreamAllowlist = allowlist
	}
	if ingress, perr := parseDownstreamTrustedIngress(downstreamTrustedIngress.values()); perr != nil {
		return perr
	} else if len(ingress) > 0 {
		srv.DownstreamTrustedIngress = ingress
	}
	if sigstoreKeys, perr := parseSigstoreKeys(sigstoreTrustKeys.values()); perr != nil {
		return perr
	} else {
		var rekorPub ed25519.PublicKey
		if v := strings.TrimSpace(*rekorPublicKey); v != "" {
			if rekorPub, perr = loadEd25519PublicKey(v); perr != nil {
				return fmt.Errorf("--rekor-public-key: %w", perr)
			}
		}
		if len(sigstoreKeys) > 0 || len(rekorPub) > 0 || strings.TrimSpace(*rekorBaseURL) != "" {
			srv.SetSigstoreTrustRoot(sigstoreKeys, rekorPub, strings.TrimSpace(*rekorBaseURL))
		}
	}
	if broker, err := buildSecretBroker(cfg.SecretBroker); err != nil {
		return err
	} else if broker != nil {
		srv.SecretBroker = broker
	}
	if reg, err := buildComponentRegistry(cfg.Components); err != nil {
		return err
	} else if reg != nil {
		srv.ComponentRegistry = reg
	}
	srv.PipelinePath = *pipelinePath
	srv.ExternalURL = externalURLV
	srv.RunnerEnrollToken = runnerEnrollTokenV
	if ep := strings.TrimSpace(cfg.Observability.OTelEndpoint); ep != "" {
		if err := srv.ConfigureTracing(ctx, ep); err != nil {
			return fmt.Errorf("otel: %w", err)
		}
		defer srv.ShutdownTracing(context.Background())
	}
	if cfg.Policy.File != "" {
		pol, perr := policy.Load(cfg.Policy.File)
		if perr != nil {
			return fmt.Errorf("policy: %w", perr)
		}
		srv.Policy = pol
	}
	if m := cfg.RateLimitMiddleware(); m != nil {
		srv.RateLimiter = m
	}
	// runner_pki.enabled is authoritative: when enabled, the CA pair is
	// mandatory at startup (config.Validate already enforces it; this is
	// the belt-and-braces check for direct flag use). An enroll token
	// without an explicit pair lets the server persist a generated CA in
	// the data dir.
	if cfg.RunnerPKI.Enabled || runnerCACertV != "" || runnerCAKeyV != "" {
		if runnerCACertV == "" || runnerCAKeyV == "" {
			return fmt.Errorf("runner_pki enabled requires --runner-ca-cert and --runner-ca-key")
		}
		if err := srv.SetRunnerCA(runnerCACertV, runnerCAKeyV); err != nil {
			return err
		}
	} else if runnerEnrollTokenV != "" {
		if *dataDir == "" {
			return fmt.Errorf("runner enrollment requires --data-dir (to persist the runner CA) or explicit --runner-ca-cert/--runner-ca-key")
		}
		if err := srv.EnsureRunnerCA(*dataDir); err != nil {
			return err
		}
	}
	// With a runner CA present (configured or enrolled), the TLS listener
	// verifies runner client certificates against it and runner-tier
	// routes require the certificate when --runner-require-client-certs
	// (default) is set. The shared listener itself stays
	// VerifyClientCertIfGiven so non-runner traffic keeps working.
	applyRunnerTLSConfig(srv, *runnerRequireClientCerts)
	// Blob backend wiring: an s3 backend or an explicit data-dir feeds the
	// server's blob store when the server build provides SetBlobStore.
	if cfg.Blob.Backend == "s3" || *dataDir != "" {
		if bs, ok := any(srv).(blobStoreSetter); ok {
			bs.SetBlobStore(buildBlobStore(cfg.Blob, *dataDir))
		} else if cfg.Blob.Backend == "s3" {
			fmt.Println("warning: blob.backend=s3 configured but this server build does not implement SetBlobStore; the s3 backend is inactive")
		}
	}
	// Graceful drain on signal: intercept SIGTERM/SIGINT before the context
	// shutdown path, ask the control plane to drain, and keep the listener
	// up until active jobs finish (bounded by drainTimeout).
	drainDone := (<-chan struct{})(nil)
	if *drainOnSigterm {
		ds, ok := any(srv).(drainableServer)
		if !ok {
			return fmt.Errorf("--drain-on-sigterm requires server support (BeginDrain/ActiveJobs), which this build does not provide")
		}
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		done := make(chan struct{})
		drainDone = done
		go func() {
			<-sig
			ds.BeginDrain("signal")
			fmt.Println("Kiwi server: drain on signal — waiting for active jobs")
			if waitForDrain(ds, drainTimeout) {
				fmt.Println("Kiwi server: drained, no active jobs")
			} else {
				fmt.Printf("Kiwi server: drain timed out after %s\n", drainTimeout)
			}
			close(done)
		}()
	}
	h := &http.Server{
		Addr:              listenV,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	// The TLS identity comes from the server's own certificate pair plus the
	// runner client CA trust settings (Server.TLSConfig), so the listener
	// verifies runner certificates at the handshake.
	if tlsCertV != "" {
		tlsConf, terr := srv.TLSConfig(tlsCertV, tlsKeyV)
		if terr != nil {
			return fmt.Errorf("TLS configuration: %w", terr)
		}
		h.TLSConfig = tlsConf
	}
	go srv.Maintain(ctx)
	// Dedicated metrics listener: when observability.metrics_listen is set,
	// the Prometheus surface binds on its own address (binding failure is a
	// startup error). The main listener keeps its /metrics route.
	if maddr := strings.TrimSpace(cfg.Observability.MetricsListen); maddr != "" {
		_, stop, merr := startMetricsListener(srv, maddr)
		if merr != nil {
			return merr
		}
		defer stop()
		fmt.Printf("Kiwi metrics listening on http://%s\n", maddr)
	}
	go func() {
		<-ctx.Done()
		if drainDone != nil {
			select {
			case <-drainDone:
			case <-time.After(drainTimeout):
			}
		}
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.Shutdown(c)
	}()
	scheme := "http"
	if tlsCertV != "" {
		scheme = "https"
	}
	fmt.Printf("Kiwi server listening on %s://%s\n", scheme, listenV)
	serveErr := h.ListenAndServe()
	if serveErr == http.ErrServerClosed {
		return nil
	}
	return serveErr
}

// applyRunnerTLSConfig populates the server's runner client certificate
// trust settings from its runner CA: the TLS listener verifies presented
// client certificates against the CA, and require decides whether the
// certificate is mandatory for runner-tier routes (enforced at the HTTP
// authorization layer — the shared listener always uses
// VerifyClientCertIfGiven). Without a runner CA the settings stay
// untouched (bearer-token mode).
func applyRunnerTLSConfig(srv *server.Server, require bool) {
	if srv.RunnerCA == nil {
		return
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.RunnerCA.Cert)
	srv.RunnerClientCAPool = pool
	srv.RequireRunnerClientCerts = require
}

func Runner(ctx context.Context, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "list", "drain", "disable", "enable":
			return RunnerAdmin(ctx, args[0], args[1:])
		}
	}
	fs := flag.NewFlagSet("runner", flag.ContinueOnError)
	url := fs.String("server", "http://127.0.0.1:8080", "Kiwi server URL")
	token := fs.String("token", os.Getenv("KIWI_RUNNER_TOKEN"), "runner token")
	name := fs.String("name", "", "runner name")
	labels := fs.String("labels", "", "comma-separated labels")
	runnerCACert := fs.String("runner-ca-cert", "", "CA certificate PEM used to verify the server (path or contents)")
	runnerCert := fs.String("runner-cert", "", "runner client certificate PEM (path or contents)")
	runnerKey := fs.String("runner-key", "", "runner client private key PEM (path or contents)")
	runnerEnrollToken := fs.String("runner-enroll-token", os.Getenv("KIWI_RUNNER_ENROLL_TOKEN"), "enrollment token to obtain a runner certificate")
	runnerMTLS := fs.Bool("runner-mtls", false, "require mTLS (explicit client certificate or enrollment)")
	var enrollLabels repeatFlag
	fs.Var(&enrollLabels, "enroll-label", "label sent with the enrollment request (repeatable; required for label-bound enrollment grants)")
	identityDir := fs.String("identity-dir", "", "directory for the persisted enrollment identity (default ~/.kiwi/runner)")
	drain := fs.Bool("drain", false, "register as draining: finish active jobs, take no new work, then exit")
	captureSnapshots := fs.Bool("capture-snapshots", true, "upload a workspace snapshot after each job (failures are warnings)")
	var prewarmRefs stringList
	fs.Var(&prewarmRefs, "prewarm", "digest-pinned image reference to prewarm (repeatable, require @sha256:)")
	metricsListen := fs.String("metrics-listen", "", "serve Prometheus text metrics on this address (e.g. :9091)")
	sigstoreKey := fs.String("sigstore-key", "", "PKCS8 PEM Ed25519 private key for Sigstore artifact attestations (path or contents)")
	workDir := fs.String("work-dir", "", "working directory for garbage-collection subprocesses (default: system temp)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := runner.Config{
		Server:           strings.TrimRight(*url, "/"),
		Token:            *token,
		Name:             *name,
		CACert:           *runnerCACert,
		Cert:             *runnerCert,
		Key:              *runnerKey,
		EnrollToken:      *runnerEnrollToken,
		EnrollLabels:     enrollLabels.values(),
		IdentityDir:      *identityDir,
		Drain:            *drain,
		CaptureSnapshots: *captureSnapshots,
		Prewarm:          prewarmRefs.values(),
		MetricsListen:    *metricsListen,
		SigstoreKeyPath:  *sigstoreKey,
		WorkDir:          *workDir,
	}
	if *labels != "" {
		cfg.Labels = strings.Split(*labels, ",")
	}
	if *runnerMTLS {
		if (cfg.Cert == "") != (cfg.Key == "") {
			return fmt.Errorf("--runner-cert and --runner-key must be set together")
		}
		if cfg.Cert == "" && cfg.Key == "" && cfg.EnrollToken == "" {
			return fmt.Errorf("--runner-mtls requires --runner-cert/--runner-key or --runner-enroll-token")
		}
	}
	return (&runner.Runner{Cfg: cfg}).Run(ctx)
}

// stringList collects repeatable comma-separated string flags.
type stringList struct {
	items []string
}

func (s *stringList) String() string { return strings.Join(s.items, ",") }

func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			s.items = append(s.items, part)
		}
	}
	return nil
}

func (s *stringList) values() []string { return append([]string{}, s.items...) }

// repeatFlag collects repeatable string flags WITHOUT splitting on commas,
// for flags whose values carry commas themselves (downstream-allow's
// target=src1,src2 form).
type repeatFlag struct {
	items []string
}

func (r *repeatFlag) String() string { return strings.Join(r.items, ",") }

func (r *repeatFlag) Set(v string) error {
	if v = strings.TrimSpace(v); v != "" {
		r.items = append(r.items, v)
	}
	return nil
}

func (r *repeatFlag) values() []string { return append([]string{}, r.items...) }

// parseDownstreamAllowlist parses repeatable --downstream-allow entries of
// the form target=src[,src...] into the server's bilateral downstream
// authorization map. A target with an empty source list allows any source
// (matching the server's semantics for a nil/empty source list).
func parseDownstreamAllowlist(entries []string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, item := range entries {
		target, sources, ok := strings.Cut(item, "=")
		target = strings.TrimSpace(target)
		if !ok || target == "" {
			return nil, fmt.Errorf("--downstream-allow requires target=src[,src...] entries, got %q", item)
		}
		var srcs []string
		for _, s := range strings.Split(sources, ",") {
			if s = strings.TrimSpace(s); s != "" {
				srcs = append(srcs, s)
			}
		}
		out[target] = srcs
	}
	return out, nil
}

// parseDownstreamTrustedIngress parses repeatable
// --downstream-trusted-ingress entries of the form target=bool.
func parseDownstreamTrustedIngress(entries []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, item := range entries {
		target, val, ok := strings.Cut(item, "=")
		target = strings.TrimSpace(target)
		if !ok || target == "" {
			return nil, fmt.Errorf("--downstream-trusted-ingress requires target=true|false entries, got %q", item)
		}
		b, err := strconv.ParseBool(strings.TrimSpace(val))
		if err != nil {
			return nil, fmt.Errorf("--downstream-trusted-ingress %q: %w", item, err)
		}
		out[target] = b
	}
	return out, nil
}

// parseSigstoreKeys parses repeatable --sigstore-key entries of the form
// id=/path/to/pem (or id=<PEM contents>) into Ed25519 verification keys.
func parseSigstoreKeys(entries []string) (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	for _, item := range entries {
		id, ref, ok := strings.Cut(item, "=")
		id = strings.TrimSpace(id)
		if !ok || id == "" || strings.TrimSpace(ref) == "" {
			return nil, fmt.Errorf("--sigstore-key requires id=/path/to/pem entries, got %q", item)
		}
		pub, err := loadEd25519PublicKey(strings.TrimSpace(ref))
		if err != nil {
			return nil, fmt.Errorf("--sigstore-key %s: %w", id, err)
		}
		out[id] = pub
	}
	return out, nil
}

// loadEd25519PublicKey loads an Ed25519 verification key from PEM contents
// (PKIX "PUBLIC KEY"), a PEM file path, or a raw 32-byte file.
func loadEd25519PublicKey(v string) (ed25519.PublicKey, error) {
	v = strings.TrimSpace(v)
	b := []byte(v)
	if !strings.Contains(v, "-----BEGIN") {
		raw, err := os.ReadFile(v)
		if err != nil {
			return nil, err
		}
		b = raw
	}
	if strings.Contains(string(b), "-----BEGIN") {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("invalid PEM contents")
		}
		b = block.Bytes
	}
	if k, err := x509.ParsePKIXPublicKey(b); err == nil {
		if pub, ok := k.(ed25519.PublicKey); ok {
			return pub, nil
		}
		return nil, fmt.Errorf("key is not an Ed25519 public key")
	}
	if len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte{}, b...)), nil
	}
	return nil, fmt.Errorf("unsupported public key encoding (want PKIX Ed25519 PEM or raw 32 bytes)")
}

// RunnerAdmin implements the admin-side runner control commands:
//
//	kiwi runner list                 — GET /api/v1/runners
//	kiwi runner drain   RUNNER_ID    — POST /api/v1/runners/{id}/drain
//	kiwi runner disable RUNNER_ID    — POST /api/v1/runners/{id}/disable
//	kiwi runner enable  RUNNER_ID    — POST /api/v1/runners/{id}/enable
//
// These are admin-tier server operations; --token must be an admin token.
func RunnerAdmin(ctx context.Context, sub string, args []string) error {
	fs := flag.NewFlagSet("runner "+sub, flag.ContinueOnError)
	url := fs.String("server", "http://127.0.0.1:8080", "Kiwi server URL")
	token := fs.String("token", os.Getenv("KIWI_ADMIN_TOKEN"), "admin bearer token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	base := strings.TrimRight(*url, "/")
	client := &http.Client{Timeout: 30 * time.Second}
	do := func(method, path string, out any) error {
		var body io.Reader
		if method == http.MethodPost {
			body = strings.NewReader("{}")
		}
		req, err := http.NewRequestWithContext(ctx, method, base+path, body)
		if err != nil {
			return err
		}
		if *token != "" {
			req.Header.Set("Authorization", "Bearer "+*token)
		}
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(b)))
		}
		if out != nil {
			return json.NewDecoder(resp.Body).Decode(out)
		}
		return nil
	}
	switch sub {
	case "list":
		var out []model.Runner
		if err := do(http.MethodGet, "/api/v1/runners", &out); err != nil {
			return err
		}
		if len(out) == 0 {
			fmt.Println("no runners registered")
			return nil
		}
		fmt.Printf("%-8s %-24s %-12s %-5s %-9s %-9s %-8s %s\n", "ID", "NAME", "REGION", "BUSY", "DISABLED", "DRAINING", "CAPACITY", "LABELS")
		for _, rn := range out {
			fmt.Printf("%-8s %-24s %-12s %-5t %-9t %-9t %-8d %s\n", rn.ID[:min(8, len(rn.ID))], rn.Name, rn.Region, rn.Busy, rn.Disabled, rn.Draining, rn.Capacity, strings.Join(rn.Labels, ","))
		}
		return nil
	case "drain", "disable", "enable":
		id := fs.Arg(0)
		if id == "" {
			return fmt.Errorf("runner %s requires a runner ID argument", sub)
		}
		var out model.Runner
		if err := do(http.MethodPost, "/api/v1/runners/"+id+"/"+sub, &out); err != nil {
			return err
		}
		fmt.Printf("runner %s (%s): %s\n", out.Name, out.ID, sub)
		return nil
	default:
		return fmt.Errorf("unknown runner admin subcommand %q", sub)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// discard marks values as intentionally read elsewhere.
func discard(_ ...any) {}
