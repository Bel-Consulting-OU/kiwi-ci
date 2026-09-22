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
	"net"
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
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// productionConfig is the pure input to validateProductionConfig, extracted
// so production-mode requirements are unit-testable without a network.
// Server() fills it from the merged configuration (CLI > environment >
// config file > defaults). Per-runner credential requirements are NOT part of
// this static input: they can only be decided after the SQL store is open
// (see validateProductionRunnerCredentials), so the static validator never
// rejects a production config for `--runner-token` alone.
type productionConfig struct {
	Mode             string
	DatabaseURL      string
	RunnerToken      string
	AdminToken       string
	ExternalURL      string
	TLSCert          string
	TLSKey           string
	AllowSharedToken bool
	// StagingDir/StagingMaxBytes are the large-upload staging bound. They
	// are required in production: without a bound, concurrent valid runner
	// uploads would spool into an unbounded temp directory and could
	// exhaust the control-plane root filesystem. StagingInstanceID is the
	// optional per-replica id: staging.dir is a shared root and each replica
	// stages inside <dir>/<id>, so replicas sharing the root must use
	// distinct ids (an id may also come from the root's persisted file).
	StagingDir        string
	StagingMaxBytes   int64
	StagingInstanceID string
}

// validateProductionConfig enforces the STATIC half of the production-mode
// startup contract: a database URL, distinct admin/runner credentials (or an
// explicit --allow-shared-token), an external URL (the OIDC issuer always
// serves in production), and TLS. The runner-auth half is post-DB: at least
// one actual per-runner mechanism (enforced mTLS or provisioned per-runner
// bearer credentials) must exist, checked by
// validateProductionRunnerCredentials once the store is open, because
// per-runner credentials may already be provisioned in
// runner_bearer_tokens. Dev mode has no additional requirements.
// drainTimeout bounds the graceful drain wait on signal.
const drainTimeout = 30 * time.Second

// listenControlPlane binds the control-plane listener. It is net.Listen in
// production; socket-level tests replace it to bind 127.0.0.1:0 and learn the
// ephemeral address without the close/reopen race of a reserved-port probe.
// controlPlaneBuilt, when non-nil, is invoked with the assembled *http.Server
// and the resolved listen address immediately before serving begins, letting
// the socket tests inspect the timeout/TLS configuration actually in force
// (and shrink the header bound for the stalled-header test). Production
// leaves both untouched.
var (
	listenControlPlane = net.Listen
	controlPlaneBuilt  func(h *http.Server, addr string)
)

// apiReadDeadline/apiWriteDeadline bound ordinary (non-streaming) API
// requests: the body read and the response write respectively. They are
// variables only so the socket-level tests can shrink the bound; production
// uses these values.
//
// streamIdleTimeout is the SLIDING inactivity bound applied to streaming
// routes instead: every successful body read re-arms the read deadline and
// every write re-arms the write deadline, so a transfer that keeps making
// progress (an 8 GiB artifact at any sustainable rate) completes regardless
// of how long it takes, while a peer that stops moving bytes for this long is
// dropped. It is a variable only so tests can shrink the bound; production
// uses this value.
var (
	apiReadDeadline   = 30 * time.Second
	apiWriteDeadline  = 60 * time.Second
	streamIdleTimeout = 90 * time.Second
)

// withAPIDeadlines re-applies the former global ReadTimeout/WriteTimeout
// contract to the ordinary API routes, while leaving bulk streaming routes
// unbounded in total but bounded per idle window. The http.Server itself runs
// with ReadTimeout/WriteTimeout 0: artifact/cache/snapshot traffic streams up
// to 8 GiB (maxBlobBytes in internal/server/blobs.go) and the log stream is
// long-lived, so any fixed global deadline cuts transfers Kiwi's own size
// limits allow (the P2 defect). Deadlines here are absolute per request,
// covering the body read and the response write.
//
// Streaming routes get two things:
//
//  1. Both connection deadlines are CLEARED before dispatch, so an absolute
//     deadline set for an earlier request can never bound a later stream on
//     a reused HTTP/1.1 keep-alive connection. Current net/http happens to
//     reset connection deadlines between requests because the server's own
//     ReadTimeout/WriteTimeout are 0, but the middleware must not depend on
//     that incidental reset; clearing is explicit, cheap, and a no-op on
//     writers that do not support deadlines.
//  2. A sliding inactivity bound replaces the absolute one: each successful
//     body Read re-arms the read deadline and each Write re-arms the write
//     deadline, so continuous progress is never cut while a stalled peer is.
//
// Keep the exemption list tight and in sync with the route table in
// internal/server/server.go; any new long-lived/bulk route MUST be added
// there instead of dropping the deadline globally again.
func withAPIDeadlines(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ResponseController reaches the underlying net.Conn; on writers that
		// do not support deadlines (httptest recorders) the error is
		// deliberately ignored: deadlines are a production hardening, not an
		// authorization decision.
		rc := http.NewResponseController(w)
		if streamingRoute(r.Method, r.URL.Path) {
			_ = rc.SetReadDeadline(time.Time{})
			_ = rc.SetWriteDeadline(time.Time{})
			sw := &streamDeadlineWriter{ResponseWriter: w, rc: rc, idle: streamIdleTimeout}
			r.Body = newStreamDeadlineBody(r.Body, rc, streamIdleTimeout)
			next.ServeHTTP(sw, r)
			return
		}
		now := time.Now()
		_ = rc.SetReadDeadline(now.Add(apiReadDeadline))
		_ = rc.SetWriteDeadline(now.Add(apiWriteDeadline))
		next.ServeHTTP(w, r)
	})
}

// streamDeadlineWriter implements the write half of the sliding bound: every
// Write (and Flush) re-arms the connection write deadline. It preserves
// http.Flusher so SSE handlers keep flushing, and exposes the underlying
// writer via Unwrap so http.ResponseController reaches the real connection.
type streamDeadlineWriter struct {
	http.ResponseWriter
	rc   *http.ResponseController
	idle time.Duration
}

func (w *streamDeadlineWriter) Write(p []byte) (int, error) {
	_ = w.rc.SetWriteDeadline(time.Now().Add(w.idle))
	return w.ResponseWriter.Write(p)
}

// Flush forwards SSE flushes; a flush is progress too, so the deadline is
// re-armed before delegating.
func (w *streamDeadlineWriter) Flush() {
	_ = w.rc.SetWriteDeadline(time.Now().Add(w.idle))
	_ = w.rc.Flush()
}

// Unwrap exposes the underlying ResponseWriter to http.ResponseController.
func (w *streamDeadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// newStreamDeadlineBody wraps a streaming request body with the read half of
// the sliding bound. Requests without a body (GET downloads, SSE) keep the
// no-body sentinel and are bounded only by their writes; the guard is armed
// immediately so an upload peer that sends nothing is dropped after one idle
// window rather than holding the route open forever.
func newStreamDeadlineBody(body io.ReadCloser, rc *http.ResponseController, idle time.Duration) io.ReadCloser {
	if body == nil || body == http.NoBody {
		return body
	}
	_ = rc.SetReadDeadline(time.Now().Add(idle))
	return &streamDeadlineBody{ReadCloser: body, rc: rc, idle: idle}
}

// streamDeadlineBody implements the read half of the sliding bound: every
// successful Read re-arms the connection read deadline.
type streamDeadlineBody struct {
	io.ReadCloser
	rc   *http.ResponseController
	idle time.Duration
}

func (b *streamDeadlineBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		_ = b.rc.SetReadDeadline(time.Now().Add(b.idle))
	}
	return n, err
}

// streamingRoute reports whether the route legitimately streams bulk or
// long-lived traffic and therefore must not carry the ordinary API
// deadlines. The set mirrors the route table in internal/server/server.go:
//
//	PUT  /api/v1/jobs/{id}/artifacts/{name}      upload up to 8 GiB
//	PUT  /api/v1/jobs/{id}/cache/{key}           upload up to 8 GiB
//	POST /api/v1/jobs/{id}/snapshots             upload up to 8 GiB
//	GET  /api/v1/jobs/{id}/cache/{key}           download (streamed)
//	GET  /api/v1/jobs/{id}/dependencies/...      download (streamed)
//	GET  /api/v1/artifacts/{id}[/provenance]     download (streamed)
//	GET  /api/v1/runs/{id}/snapshots/{sid}       download (streamed)
//	GET  /api/v1/runs/{id}/logs/stream           SSE, long-lived
func streamingRoute(method, path string) bool {
	switch {
	case method == http.MethodPut && strings.HasPrefix(path, "/api/v1/jobs/") &&
		(strings.Contains(path, "/artifacts/") || strings.Contains(path, "/cache/")):
		return true
	case method == http.MethodPost && strings.HasPrefix(path, "/api/v1/jobs/") &&
		strings.HasSuffix(path, "/snapshots"):
		return true
	case method == http.MethodGet && strings.HasPrefix(path, "/api/v1/jobs/") &&
		(strings.Contains(path, "/cache/") || strings.Contains(path, "/dependencies/")):
		return true
	case method == http.MethodGet && strings.HasPrefix(path, "/api/v1/artifacts/"):
		return true
	case method == http.MethodGet && strings.HasPrefix(path, "/api/v1/runs/") &&
		(strings.Contains(path, "/snapshots/") || strings.HasSuffix(path, "/logs/stream")):
		return true
	}
	return false
}

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
			PathStyle:       cfg.S3PathStyle,
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
	// Large-upload staging MUST have a configured bound in production: the
	// cache/snapshot/artifact routes stage multi-GB request bodies, and
	// without staging.dir + staging.max_bytes those bytes would land in an
	// unbounded system temp directory on the control-plane root filesystem.
	// The directory must also be USABLE — that half is enforced when the
	// budget is constructed (staging.NewBudget) so an unusable path fails
	// startup instead of the first upload.
	if strings.TrimSpace(cfg.StagingDir) == "" || cfg.StagingMaxBytes <= 0 {
		return fmt.Errorf("production mode requires --staging-dir and --staging-max-bytes (large runner uploads must stage inside a bounded directory; set staging.dir and staging.max_bytes)")
	}
	// Runner credentials are a POST-DB decision (per-runner tokens may
	// already live in the runner_bearer_tokens table), so the static
	// validator deliberately says nothing about --runner-token here.
	return nil
}

// validateProductionRunnerCredentials is the post-DB half of the production
// runner-auth contract: at least one actual per-runner mechanism must exist —
// enforced runner mTLS, per-runner bearer credentials supplied through
// --runner-tokens-file (provisioned into runner_bearer_tokens next), or rows
// already provisioned in runner_bearer_tokens. mtlsEnforced must be the
// ACTUAL initialized server state (a loaded runner CA with client
// certificates required), never the presence of flags: the runner PKI is
// initialized before this check, so a shared CA, an explicit CA installed
// into the cluster key store, and an auto-enrolled CA all count exactly when
// they really enforce mTLS. The shared runner token is dev/bootstrap
// compatibility only: production accepts it at neither this check nor the
// request path (Server() clears Server.RunnerToken once this function
// passes), so a production server holding only --runner-token refuses to
// start.
func validateProductionRunnerCredentials(ctx context.Context, db storage.Store, mtlsEnforced bool, fileTokens map[string]string) error {
	if mtlsEnforced || len(fileTokens) > 0 {
		return nil
	}
	has, err := hasProvisionedRunnerTokens(ctx, db)
	if err != nil {
		return fmt.Errorf("check per-runner credentials: %w", err)
	}
	if !has {
		return fmt.Errorf("production requires runner mTLS or per-runner credentials; the shared runner token is dev/bootstrap-only and is disabled in production")
	}
	return nil
}

// buildStagingBudget constructs the configured large-upload staging budget
// for this replica and reclaims the spool files its dead owner left behind,
// before the listeners start. The configured directory is a ROOT: the budget
// owns <root>/<instance-id> (staging.instance_id, or a generated-and-persisted
// id when unset) and deletes every kiwi-stage-* file found there, plus legacy
// bare spool files directly under the root — the ownership lock proves they
// belong to a dead process. An unconfigured section returns (nil, 0, nil) so
// the server keeps its bounded data-dir default; a configured but unusable
// bound (a path under a regular file, a read-only or full directory, or a
// directory already owned by a live replica) returns the constructor's error,
// so startup fails closed instead of the first upload. config.Validate
// already rejected a partial (dir xor max_bytes) section.
func buildStagingBudget(cfg config.StagingConfig) (*staging.Budget, int, error) {
	if strings.TrimSpace(cfg.Dir) == "" && cfg.MaxBytes == 0 {
		return nil, 0, nil
	}
	b, err := staging.NewReplicaBudget(cfg.Dir, cfg.InstanceID, cfg.MaxBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("staging: %w", err)
	}
	return b, b.StaleFilesRemoved(), nil
}

func Server(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	// Flags default to empty: effective values come from the merged
	// configuration (CLI > environment > config file > defaults). Only
	// explicitly set flags override the config.
	listen := fs.String("listen", "", "listen address (default: \":8080\")")
	// The runner bearer token is a SHARED credential across all runners,
	// not a per-runner identity. It is dev/bootstrap compatibility only:
	// production clears it at startup and requires per-runner mTLS
	// identities (--runner-ca-cert/--runner-ca-key + enrollment) or
	// per-runner bearer credentials (--runner-tokens-file /
	// runner_bearer_tokens).
	token := fs.String("runner-token", "", "runner bearer token shared by all runners (dev/bootstrap only; production requires per-runner mTLS or --runner-tokens-file)")
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
	clusterKeyDir := fs.String("cluster-key-dir", "", "shared cluster key store directory (HA replicas share signing material); requires --data-dir; DB mode defaults to the database-backed store")
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
	runnerTokensFile := fs.String("runner-tokens-file", "", "JSON file of per-runner bearer credentials (runner ID -> SHA-256 token digest); production accepts runner mTLS or these per-runner tokens")
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
	stagingDir := fs.String("staging-dir", "", "staging ROOT for large runner uploads; each replica stages inside <dir>/<instance-id> (required in production)")
	stagingMaxBytes := fs.String("staging-max-bytes", "", "this replica's staging byte budget for concurrent large runner uploads (required in production)")
	stagingInstanceID := fs.String("staging-instance-id", "", "this replica's id under staging-dir; replicas sharing the root must use distinct ids (default: a generated id persisted in the root)")
	repoConcurrency := fs.String("repo-concurrency", "", "per-repository running-job concurrency limit (0 = unlimited)")
	teamConcurrency := fs.String("team-concurrency", "", "per-team running-job concurrency limit (0 = unlimited)")
	repoQueueDepth := fs.String("repo-queue-depth", "", "per-repository queued-job depth limit (0 = unlimited)")
	teamQueueDepth := fs.String("team-queue-depth", "", "per-team queued-job depth limit (0 = unlimited)")
	dailyCostLimit := fs.String("daily-cost-limit", "", "trailing-24h cost budget (0 = unlimited)")
	dailyEnergyLimit := fs.String("daily-energy-limit", "", "trailing-24h energy budget in Wh (0 = unlimited)")
	quotaFailOpen := fs.Bool("quota-fail-open", false, "let enqueues/leases proceed when the usage store is unavailable instead of failing closed")
	untrustedCPUCeiling := fs.String("untrusted-cpu-ceiling", "", "untrusted job CPU ceiling in cores (0 disables; default 2)")
	untrustedMemoryCeiling := fs.String("untrusted-memory-ceiling", "", "untrusted job memory ceiling in bytes (0 disables; default 4 GiB = 4294967296)")
	untrustedDiskCeiling := fs.String("untrusted-disk-ceiling", "", "untrusted job disk ceiling in bytes (0 disables; default 10 GiB = 10737418240)")
	untrustedPIDsCeiling := fs.String("untrusted-pids-ceiling", "", "untrusted job PIDs ceiling (0 disables; default 256)")
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
	discard(listen, token, adminToken, webhookSecret, githubToken, externalURL, tlsCert, tlsKey, runnerCACert, runnerCAKey, runnerEnrollToken, databaseURL, mode, rateLimitPerSecond, rateLimitBurst, otelEndpoint, drainOnSigterm, githubAppID, githubAppPrivateKey, gitlabToken, gitlabWebhookSecret, gitlabBaseURL, forgejoToken, forgejoWebhookSecret, forgejoBaseURL, tokensFile, runnerTokensFile, databaseMaxConnections, metricsListen, secretBroker, vaultAddr, vaultToken, awsRegion, awsAccessKey, awsSecretKey, awsToken, gcpCredentials, gcpProject, azureTenant, azureClientID, azureClientSecret, azureVaultURL, onePasswordHost, onePasswordToken, onePasswordVault, componentRegistryDir, componentRemote, componentRemoteToken, stagingDir, stagingMaxBytes, stagingInstanceID, repoConcurrency, teamConcurrency, repoQueueDepth, teamQueueDepth, dailyCostLimit, dailyEnergyLimit, quotaFailOpen, untrustedCPUCeiling, untrustedMemoryCeiling, untrustedDiskCeiling, untrustedPIDsCeiling)

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
	// Per-runner bearer credentials: auth.runner_tokens_file maps runner
	// IDs to SHA-256 token digests. In DB mode these are provisioned into
	// runner_bearer_tokens; otherwise they stay in server memory.
	runnerTokens, err := loadRunnerTokensFile(cfg.Auth.RunnerTokensFile)
	if err != nil {
		return err
	}
	if err := validateProductionConfig(productionConfig{
		Mode:              modeV,
		DatabaseURL:       databaseURLV,
		RunnerToken:       tokenV,
		AdminToken:        adminTokenV,
		ExternalURL:       externalURLV,
		TLSCert:           tlsCertV,
		TLSKey:            tlsKeyV,
		AllowSharedToken:  *allowSharedToken,
		StagingDir:        cfg.Staging.Dir,
		StagingMaxBytes:   cfg.Staging.MaxBytes,
		StagingInstanceID: cfg.Staging.InstanceID,
	}); err != nil {
		return err
	}
	// Shared staging budget: large uploads spool into this replica's
	// directory under the configured root (<staging.dir>/<staging.instance_id>,
	// or a generated-and-persisted id when none is configured), never an
	// unbounded system temp directory and never straight into a root shared
	// with another replica. Constructing it takes exclusive ownership of the
	// replica directory and reclaims every spool file a dead owner left
	// (including legacy bare files directly under the root), so the ledger
	// starts from a truthful zero. It happens BEFORE any network or datastore
	// work so an unusable configured bound — or a directory already owned by
	// a live replica — fails startup immediately. An unconfigured section
	// keeps the server's data-dir bounded default, and production
	// additionally refuses to start with no bound at all
	// (validateProductionConfig above). It is installed on the server once
	// the server exists.
	stagingBudget, stagingPruned, berr := buildStagingBudget(cfg.Staging)
	if berr != nil {
		return berr
	}
	var srv *server.Server
	var clusterStore *server.FSClusterKeyStore
	// db is the durable SQL store in DB mode. It is declared here because the
	// production runner-auth decision runs AFTER the runner PKI is
	// initialized and still needs the store to probe provisioned
	// per-runner bearer credentials.
	var db storage.Store
	if *clusterKeyDir != "" {
		if *dataDir == "" {
			return fmt.Errorf("--cluster-key-dir requires --data-dir (the persistent state root)")
		}
		clusterStore = &server.FSClusterKeyStore{Dir: *clusterKeyDir}
	}
	if databaseURLV != "" {
		// DB mode: the SQL store is the source of truth. A data-dir is still
		// used when set (artifact bytes, and the seed for migrating legacy
		// node-local key material into the shared store); without it
		// artifact storage is unavailable.
		var pgOpts []storage.PostgresOption
		if cfg.Database.MaxConnections > 0 {
			pgOpts = append(pgOpts, storage.WithMaxConnections(cfg.Database.MaxConnections))
		}
		var derr error
		db, derr = storage.NewPostgresOpt(ctx, databaseURLV, pgOpts...)
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
		// Shared cluster keys: an explicit --cluster-key-dir wins; otherwise
		// the DB-backed store is preferred so HA replicas share every signing
		// material through PostgreSQL instead of relying on per-node data
		// dirs. The node-local store (when a data dir exists) is only the
		// migration seed, keeping an upgrading deployment's existing OIDC /
		// provenance / runner-CA trust roots.
		if clusterStore == nil {
			blobs, ok := any(db).(storage.ClusterKeyBlobStore)
			if !ok {
				if modeV == "production" {
					return fmt.Errorf("production DB mode requires a shared cluster key store: configure --cluster-key-dir on shared storage (the SQL store does not support the database-backed key store)")
				}
			} else {
				if err := blobs.EnsureClusterKeySchema(ctx); err != nil {
					return fmt.Errorf("cluster key store: %w", err)
				}
				var seed server.ClusterKeyStore
				if *dataDir != "" {
					seed = srv.ClusterKeys
				}
				if err := srv.UseClusterKeyStore(&server.DBClusterKeyStore{Blobs: blobs, Seed: seed}); err != nil {
					return err
				}
			}
		}
		if err := srv.SwitchToDB(db); err != nil {
			return err
		}
		if len(runnerTokens) > 0 {
			if err := srv.ProvisionRunnerTokensDB(ctx, runnerTokens); err != nil {
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
	// Install the staging budget built before the server existed (see above).
	if stagingBudget != nil {
		srv.SetStagingBudget(stagingBudget)
		if stagingPruned > 0 {
			fmt.Printf("Kiwi staging: pruned %d abandoned file(s) from %s\n", stagingPruned, stagingBudget.Dir())
		}
	}
	// Runner PKI is initialized BEFORE HA and production credential
	// validation: those checks must judge the ACTUAL initialized server
	// state (a shared cluster CA the DB store already holds, an explicit CA
	// installed into that store, or an auto-generated shared CA), not the
	// presence of flags. An explicit CA is installed-or-compared against the
	// shared cluster key store: bytes that disagree with the store's runner
	// CA fail startup (a replica must never trust a node-local CA its peers
	// reject). runner_pki.enabled is authoritative: when enabled, the CA
	// pair is mandatory at startup (config.Validate already enforces it; this
	// is the belt-and-braces check for direct flag use). An enroll token
	// without an explicit pair makes the server persist a generated CA in
	// the shared cluster key store.
	if cfg.RunnerPKI.Enabled || runnerCACertV != "" || runnerCAKeyV != "" {
		if runnerCACertV == "" || runnerCAKeyV == "" {
			return fmt.Errorf("runner_pki enabled requires --runner-ca-cert and --runner-ca-key")
		}
		if err := srv.SetRunnerCA(runnerCACertV, runnerCAKeyV); err != nil {
			return err
		}
	} else if runnerEnrollTokenV != "" {
		// Enrollment needs a durable SHARED CA. In DB mode PostgreSQL is the
		// durable shared key store, so a node-local --data-dir is NOT
		// required; in file/dev mode the FS cluster key store under
		// --data-dir (or an explicit pair above) is still required.
		if databaseURLV == "" && *dataDir == "" {
			return fmt.Errorf("runner enrollment requires --data-dir (to persist the shared runner CA through the cluster key store) or explicit --runner-ca-cert/--runner-ca-key")
		}
		if err := srv.EnsureRunnerCA(); err != nil {
			return err
		}
	}
	// With a runner CA present (configured, shared or enrolled), the TLS
	// listener verifies runner client certificates against it and runner-tier
	// routes require the certificate when --runner-require-client-certs
	// (default) is set. The shared listener itself stays
	// VerifyClientCertIfGiven so non-runner traffic keeps working. This runs
	// before validation so the production decision uses the actual state.
	applyRunnerTLSConfig(srv, *runnerRequireClientCerts)
	if modeV == "production" {
		// Profile enforcement is a production hardening: runner-supplied
		// scheduling attributes are ignored and only a certificate-bound
		// runner profile supplies them (a profile-less runner registers with
		// capacity 0). Dev mode keeps the legacy self-reported registration.
		srv.RequireProfiles = true
		// A production DB control plane without a shared cluster key store
		// would mint per-replica signing material: replicas could not verify
		// each other's tokens. Surface that at startup. Runner credentials
		// are then validated post-DB (per-runner tokens may already be
		// provisioned in runner_bearer_tokens).
		if err := srv.ValidateHAReady(); err != nil {
			return err
		}
		// The runner-auth half of the contract is decided on the ACTUAL
		// initialized state: enforced mTLS (a runner CA with client certs
		// required) or provisioned per-runner bearer credentials. The shared
		// runner token is dev/bootstrap compatibility only, and the
		// production per-runner contract above now holds, so disable it
		// PERMANENTLY (static startup decision, not per-request DB
		// contents): production runner traffic is authenticated only by
		// per-runner bearer tokens or mTLS.
		mtlsReady := srv.RunnerCA != nil && srv.RequireRunnerClientCerts
		if db != nil {
			if err := validateProductionRunnerCredentials(ctx, db, mtlsReady, runnerTokens); err != nil {
				return err
			}
		}
		srv.RunnerToken = ""
	}
	// Per-runner bearer credentials in memory/fs mode (DB mode provisioned
	// them through ProvisionRunnerTokensDB above).
	if len(runnerTokens) > 0 && databaseURLV == "" {
		srv.LoadRunnerTokens(runnerTokens)
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
		Handler:           withAPIDeadlines(srv.Handler()),
		ReadHeaderTimeout: 5 * time.Second,
		// ReadTimeout/WriteTimeout are deliberately 0 (disabled): artifact,
		// cache and snapshot endpoints stream up to 8 GiB and log streaming
		// is long-lived, so a global 30s/60s body/write deadline aborts
		// legitimate transfers regardless of Kiwi's own size limits.
		// withAPIDeadlines reapplies the bounded contract to the ordinary
		// JSON API, and streamingRoute exempts the bulk/long-lived routes.
		ReadTimeout:    0,
		WriteTimeout:   0,
		IdleTimeout:    90 * time.Second,
		MaxHeaderBytes: 1 << 20,
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
	// Bind explicitly so the socket-level tests can observe the address and
	// server actually in force; Serve/ServeTLS have the same semantics as
	// ListenAndServe/ListenAndServeTLS (listener tracking for Shutdown,
	// HTTP/2 setup, ErrServerClosed).
	ln, lerr := listenControlPlane("tcp", listenV)
	if lerr != nil {
		return lerr
	}
	if controlPlaneBuilt != nil {
		controlPlaneBuilt(h, ln.Addr().String())
	}
	// Truthful startup logging: scheme follows the serving branch below, and
	// the printed address is the address actually bound.
	scheme := "http"
	if tlsCertV != "" {
		scheme = "https"
	}
	fmt.Printf("Kiwi server listening on %s://%s\n", scheme, ln.Addr())
	var serveErr error
	if tlsCertV != "" {
		// The TLS serving point. The certificate comes from Server.TLSConfig
		// (h.TLSConfig.Certificates is populated), so the empty filenames are
		// intentional and correct. Calling ListenAndServe() here would open a
		// PLAINTEXT listener and never exercise the constructed TLS
		// 1.2+/client-CA configuration (the P0 defect).
		serveErr = h.ServeTLS(ln, "", "")
	} else {
		serveErr = h.Serve(ln)
	}
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

// loadRunnerTokensFile reads the auth.runner_tokens_file JSON map
// (runner ID -> SHA-256 hex token digest). An unset path yields an empty
// map; a configured path must parse and every entry must be well formed.
func loadRunnerTokensFile(path string) (map[string]string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("runner tokens file: %w", err)
	}
	m := map[string]string{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("runner tokens file %s: %w", path, err)
	}
	out := map[string]string{}
	for id, digest := range m {
		id = strings.TrimSpace(id)
		digest = strings.TrimSpace(digest)
		if id == "" || len(digest) != 64 {
			return nil, fmt.Errorf("runner tokens file %s: entry %q must map a runner id to a 64-char SHA-256 hex digest", path, id)
		}
		out[id] = digest
	}
	return out, nil
}

// hasProvisionedRunnerTokens reports whether the durable
// runner_bearer_tokens table already holds per-runner credentials.
func hasProvisionedRunnerTokens(ctx context.Context, db storage.Store) (bool, error) {
	ts, ok := db.(storage.RunnerTokenStore)
	if !ok {
		return false, nil
	}
	return ts.HasRunnerTokens(ctx)
}
