package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

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
}

// validateProductionConfig enforces the production-mode startup contract:
// a database URL, distinct admin/runner credentials (or an explicit
// --allow-shared-token), an external URL (the OIDC issuer always serves in
// production), and TLS. Dev mode has no additional requirements.
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
	return nil
}

func Server(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	// Flags default to empty: effective values come from the merged
	// configuration (CLI > environment > config file > defaults). Only
	// explicitly set flags override the config.
	listen := fs.String("listen", "", "listen address (default: \":8080\")")
	token := fs.String("runner-token", "", "runner/API bearer token")
	adminToken := fs.String("admin-token", "", "admin bearer token (defaults to runner token)")
	webhookSecret := fs.String("github-webhook-secret", "", "GitHub webhook HMAC secret")
	githubToken := fs.String("github-token", "", "GitHub token for private pipeline fetches")
	pipelinePath := fs.String("pipeline-path", ".kiwi/pipeline.yaml", "pipeline path in repositories")
	dataDir := fs.String("data-dir", "", "persistent state directory (default: in-memory; production deployments should always set this)")
	externalURL := fs.String("external-url", "", "public base URL (required for OIDC)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	tlsKey := fs.String("tls-key", "", "TLS private key file")
	runnerCACert := fs.String("runner-ca-cert", "", "runner CA certificate PEM (enables runner certificate enrollment)")
	runnerCAKey := fs.String("runner-ca-key", "", "runner CA private key PEM")
	runnerEnrollToken := fs.String("runner-enroll-token", "", "token authorizing runner certificate enrollment")
	databaseURL := fs.String("database-url", "", "PostgreSQL connection URL (wires the durable SQL control plane)")
	mode := fs.String("mode", "", "server mode: dev (in-memory, default) or production")
	allowSharedToken := fs.Bool("allow-shared-token", false, "production: allow --admin-token to equal --runner-token")
	configPath := fs.String("config", "", "TOML configuration file (kiwi.toml); CLI flags override it")
	otelEndpoint := fs.String("otel-endpoint", "", "OpenTelemetry OTLP/HTTP collector endpoint (enables tracing)")
	rateLimitPerSecond := fs.Float64("rate-limit-per-second", 0, "global request rate limit per principal/runner/IP (0 disables)")
	rateLimitBurst := fs.Int("rate-limit-burst", 0, "rate limit burst size (default 100)")
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
	discard(listen, token, adminToken, webhookSecret, githubToken, externalURL, tlsCert, tlsKey, runnerCACert, runnerCAKey, runnerEnrollToken, databaseURL, mode, rateLimitPerSecond, rateLimitBurst, otelEndpoint)

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
	webhookSecretV := cfg.GitHub.WebhookSecret
	githubTokenV := cfg.GitHub.Token
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
		Mode:             modeV,
		DatabaseURL:      databaseURLV,
		RunnerToken:      tokenV,
		AdminToken:       adminTokenV,
		ExternalURL:      externalURLV,
		TLSCert:          tlsCertV,
		TLSKey:           tlsKeyV,
		AllowSharedToken: *allowSharedToken,
	}); err != nil {
		return err
	}
	var srv *server.Server
	if databaseURLV != "" {
		// DB mode: the SQL store is the source of truth. A data-dir is still
		// used when set (lease key, OIDC signer, artifact bytes); without it
		// artifact storage is unavailable.
		db, derr := storage.NewPostgres(ctx, databaseURLV)
		if derr != nil {
			return derr
		}
		defer db.Close()
		if merr := db.Migrate(ctx); merr != nil {
			return fmt.Errorf("auto-migrate: %w", merr)
		}
		if *dataDir != "" {
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
	srv.GitHubWebhookSecret = webhookSecretV
	srv.GitHubToken = githubTokenV
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
	if runnerCACertV != "" || runnerCAKeyV != "" {
		if runnerCACertV == "" || runnerCAKeyV == "" {
			return fmt.Errorf("--runner-ca-cert and --runner-ca-key must be set together")
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
	h := &http.Server{
		Addr:              listenV,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	go srv.Maintain(ctx)
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.Shutdown(c)
	}()
	scheme := "http"
	if tlsCertV != "" {
		scheme = "https"
	}
	fmt.Printf("Kiwi server listening on %s://%s\n", scheme, listenV)
	var serveErr error
	if tlsCertV != "" {
		serveErr = h.ListenAndServeTLS(tlsCertV, tlsKeyV)
	} else {
		serveErr = h.ListenAndServe()
	}
	if serveErr == http.ErrServerClosed {
		return nil
	}
	return serveErr
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
