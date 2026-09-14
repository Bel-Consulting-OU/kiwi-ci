package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/Bel-Consulting-OU/kiwi-ci/internal/api/v1"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/components"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/expr"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/queue"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/quotas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/ratelimit"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/scheduler"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/version"
	"go.opentelemetry.io/otel/codes"
)

const (
	defaultLeaseDuration  = 45 * time.Second
	maxCompletionReceipts = 4096
)

type Server struct {
	// Token remains for source compatibility; RunnerToken/AdminToken are authoritative.
	Token                string
	RunnerToken          string
	AdminToken           string
	GitHubWebhookSecret  string
	GitHubToken          string
	GitHubAppID          int64
	GitHubAppPrivateKey  string
	GitLabWebhookSecret  string
	GitLabToken          string
	ForgejoWebhookSecret string
	ForgejoToken         string
	PipelinePath         string
	ExternalURL          string
	LeaseDuration        time.Duration
	// SecretBroker resolves declared secrets for trusted jobs holding an
	// active lease. A nil broker disables the secrets endpoint (503).
	SecretBroker secretbroker.Broker

	// WebSessionSecret is the HMAC key for short-lived web UI session
	// cookies (see session.go). It is 32 bytes, generated from crypto/rand
	// or the KIWI_WEB_SESSION_SECRET env var on first use. Empty disables
	// cookie authentication until a login is attempted.
	WebSessionSecret []byte

	// RunnerCA signs runner client certificates for enrollment and mTLS
	// identity binding. Nil disables runner certificate enrollment and
	// binding (bearer-token mode).
	RunnerCA *runnerpki.CA
	// RunnerEnrollToken authorizes POST /api/v1/runners/enroll. Empty
	// disables the endpoint.
	RunnerEnrollToken string

	// AuthStore maps hashed bearer tokens to principals for admin/API
	// authorization. An empty store keeps legacy AdminToken/RunnerToken
	// mode. AuthFile is the JSON token-store path for persistent
	// deployments; callers load it into AuthStore after construction.
	AuthStore *auth.TokenStore
	AuthFile  string

	mu          sync.Mutex
	runs        map[string]model.Run
	jobs        map[string]model.Job
	runners     map[string]model.Runner
	artifacts   map[string]model.ArtifactRecord
	reports     map[string]model.TestReport
	deliveries  map[string]string
	completions map[string]model.CompletionReceipt
	leaseKey    []byte
	logSeq      int64
	store       *storage.Repository
	oidc        *oidcSigner
	outbox      *Outbox

	// DB mode: when Sched is non-nil the PostgreSQL store is the source of
	// truth and scheduler operations delegate to it. The in-memory maps
	// remain only for dev mode. s.mu guards the memory maps and dev-mode
	// scheduling; DB paths must not hold s.mu across store calls.
	DB        storage.Store
	Sched     *scheduler.DBScheduler
	LeaderKey string
	leader    bool

	// Forge API base overrides, used by tests to point adapters at local
	// HTTP servers; empty means the public API endpoints.
	gitHubAPIBase  string
	gitLabAPIBase  string
	forgejoAPIBase string

	// ComponentRegistry resolves job component references server-side at
	// enqueue time (see resolvePipeline). A nil registry rejects pipelines
	// that reference components.
	ComponentRegistry components.Registry

	// AdmissionCapabilities, when non-nil, overrides the trust-default
	// capabilities used for pipeline admission. The loaded organization
	// policy file (Policy) is intersected — and its explicit grants
	// applied — on top of this; tests use the field to grant capabilities
	// such as deployments directly.
	AdmissionCapabilities *policy.Capabilities

	// Policy is the loaded organization policy file; its repository
	// restrictions are intersected into every admission decision and can
	// only narrow the effective capabilities.
	Policy *policy.Config

	// QuotaLimits bounds per-repository and per-team concurrency and queue
	// depth at enqueue (quotas.Limits; every field 0 means unlimited).
	QuotaLimits quotas.Limits
	// DailyCostLimit/DailyEnergyLimit bound the trailing-24h cost and
	// energy budget; exceeding them refuses new leases (0 = unlimited).
	DailyCostLimit   float64
	DailyEnergyLimit float64
	// QuotaFailOpen, when true, lets enqueues and leases proceed when the
	// usage store is unavailable instead of refusing them with
	// BUDGET_STATE_UNAVAILABLE. Default false: the budget gate fails
	// closed.
	QuotaFailOpen bool

	// BlobStore is the shared content-addressed blob backend for DB mode.
	// CAS wraps it with digest-verified put/open. When nil (or dataDir is
	// set at construction) the server uses a filesystem blob store under
	// dataDir/cas. SetBlobStore overrides both.
	BlobStore blob.Store
	CAS       *cas.CAS

	// DownstreamPipelineFetcher, when non-nil, overrides the forge-based
	// pipeline fetch for downstream dispatch (tests inject a stub; the
	// default resolves the target forge adapter from the parent run's
	// repository host).
	DownstreamPipelineFetcher func(ctx context.Context, targetRepo, targetRef string) (string, error)

	// Logger writes operational (control-plane) logs as structured JSON
	// lines. Build logs stay in LogEntry paths. Defaults to os.Stderr.
	Logger *logging.Structured
	// Metrics is the Prometheus-style registry rendered on /metrics
	// alongside the state gauges.
	Metrics *Metrics
	// RateLimiter, when non-nil, enforces per-class request rate limits
	// in front of the authorization chain.
	RateLimiter *ratelimit.Middleware
	// LogStreamIdleTimeout bounds how long the SSE log stream stays open
	// without new entries (default 30s).
	LogStreamIdleTimeout time.Duration

	// deployments records environment deployment lifecycles per job. It is
	// the dev-mode mirror: DB mode persists through DeploymentStore (see
	// deployments.go).
	deployments map[string]model.Deployment
	// snapshots records uploaded workspace snapshots per run. It is the
	// dev-mode mirror: DB mode persists through SnapshotStore (see
	// snapshots.go).
	snapshots map[string]model.SnapshotRecord

	// dataDir is the persistent state root ("" for in-memory servers).
	dataDir string

	// ClusterKeys, when non-nil, is the shared key store backing every
	// signing material (lease HMAC key, OIDC ring, provenance key, cache
	// signing key, web session secret, runner CA) so replicas of an HA
	// control plane verify each other's tokens (see clusterkeys.go).
	ClusterKeys ClusterKeyStore

	// RunnerClientCAPool is the trust pool of runner client CAs. When
	// non-nil, presented client certificates are verified against it at
	// the TLS handshake (see TLSConfig). Derived from RunnerCA by the app
	// wiring when runner mTLS is enabled.
	RunnerClientCAPool *x509.CertPool
	// RequireRunnerClientCerts rejects connections without a valid runner
	// client certificate at the handshake (tls.RequireAndVerifyClientCert).
	RequireRunnerClientCerts bool

	// contracts holds the per-job artifact contract sets (memory mode;
	// DB mode persists them through ArtifactContractStore).
	contracts map[string]map[string]storage.ArtifactContract
	// pendingSidecars maps (jobID, base, kind) to the CAS digest of a
	// sidecar uploaded before its artifact payload in DB mode; the payload
	// upload gate resolves the bytes through CAS instead of node-local
	// sidecar files. Guarded by s.mu.
	pendingSidecars map[string]string
	// jobLocks serializes the upload critical section per job so staging,
	// idempotency checks and record insertion are atomic per (job, name).
	jobLocks   map[string]*sync.Mutex
	jobLocksMu sync.Mutex

	// provenance is the artifact provenance signing key. It is a distinct
	// trust root from the OIDC signing key (see keys.go).
	provenance *provenanceSigner
	// cacheSigner signs cache manifests in DB mode (keys.go).
	cacheSigner *cacheSigner

	// crl maps revoked runner certificate serials to runner IDs; persisted
	// as runner-crl.json under dataDir (crl.go).
	crl map[string]string

	// secretReceipts is the durable one-time secret delivery record keyed by
	// (jobID, generation, secret name); persisted as secrets-receipts.json
	// under dataDir (secret.go). Guarded by s.mu.
	secretReceipts map[string]bool

	// history is the persistent test-intelligence history (testshards.go).
	history *testintelHistory

	// schedules/occurrences are the memory-mode schedule store; DB mode
	// uses storage.ScheduleStore (schedules.go).
	schedules   map[string]storage.Schedule
	occurrences map[string]map[int64]string

	// opaPolicy is the compiled OPA deny gate (nil when no rules are
	// configured); opaBroken is set when a configured gate failed to
	// compile, which fails every admission closed.
	opaPolicy *policy.OPAPolicy
	opaBroken bool

	// drain state: draining refuses new leases, readiness reports 503, and
	// GET /api/v1/drain exposes the state. drainMu guards the flags; the
	// drain.flag file under dataDir persists the state across restarts.
	drainMu     sync.Mutex
	draining    bool
	drainReason string

	// downstreamLinks holds the fs-mode downstream dispatch claims
	// (memory/fs servers). DB mode claims live in the DownstreamStore.
	downstreamLinks map[string]storage.DownstreamLink

	// usage tracks completed jobs' cost/energy for the trailing-24h daily
	// budget in memory/fs mode. DB mode queries UsageStore.RecentUsage.
	usageMu sync.Mutex
	usage   []usageEntry

	// OTel tracing (tracing.go).
	OTelEndpoint string
	otelShutdown func(context.Context) error
	otelEnabled  bool
}

func New(token string) *Server {
	key, err := newLeaseKey()
	if err != nil {
		// A fresh lease key is security-critical state; without entropy the
		// control plane must not start.
		panic("kiwi server: failed to generate lease key: " + err.Error())
	}
	return &Server{
		Token: token, RunnerToken: token, AdminToken: token,
		LeaseDuration: defaultLeaseDuration,
		runs:          map[string]model.Run{}, jobs: map[string]model.Job{}, runners: map[string]model.Runner{}, artifacts: map[string]model.ArtifactRecord{}, reports: map[string]model.TestReport{}, deliveries: map[string]string{}, completions: map[string]model.CompletionReceipt{}, leaseKey: key, oidc: newOIDCSigner(),
		outbox:          NewOutbox(nil),
		AuthStore:       auth.NewTokenStore(),
		deployments:     map[string]model.Deployment{},
		snapshots:       map[string]model.SnapshotRecord{},
		contracts:       map[string]map[string]storage.ArtifactContract{},
		pendingSidecars: map[string]string{},
		jobLocks:        map[string]*sync.Mutex{},
		crl:             map[string]string{},
		history:         newTestintelHistory(""),
		schedules:       map[string]storage.Schedule{},
		occurrences:     map[string]map[int64]string{},
		downstreamLinks: map[string]storage.DownstreamLink{},
		Logger:          logging.NewStructured(os.Stderr),
		Metrics:         NewMetrics(),
	}
}

// newLeaseKey generates a 32-byte lease HMAC key from crypto/rand.
func newLeaseKey() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// loadLeaseKey loads the persisted lease HMAC key from dataDir, generating and
// persisting a fresh one on first use. The key is what lets lease tokens
// survive control-plane restarts: only their HMAC is stored in job state.
func loadLeaseKey(root string) ([]byte, error) {
	path := filepath.Join(root, "lease.key")
	if b, err := os.ReadFile(path); err == nil {
		raw, er := hex.DecodeString(strings.TrimSpace(string(b)))
		if er != nil {
			return nil, er
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("invalid lease key size")
		}
		return raw, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key, err := newLeaseKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return key, nil
}

func NewPersistent(runnerToken, adminToken, dataDir string) (*Server, error) {
	// The filesystem cluster key store under dataDir reproduces the legacy
	// per-file key layout exactly (see FSClusterKeyStore), so existing
	// deployments keep their key material and behavior unchanged while the
	// cluster identity is present for HA validation.
	return NewPersistentWithCluster(runnerToken, adminToken, dataDir, &FSClusterKeyStore{Dir: dataDir})
}

// NewPersistentWithCluster is NewPersistent with an explicit cluster key
// store. A nil store keeps the legacy data-dir loaders. When the store is
// non-nil every signing material loads and persists through it.
func NewPersistentWithCluster(runnerToken, adminToken, dataDir string, cluster ClusterKeyStore) (*Server, error) {
	if adminToken == "" {
		adminToken = runnerToken
	}
	s := New(runnerToken)
	s.AdminToken = adminToken
	s.dataDir = dataDir
	s.ClusterKeys = cluster
	s.store = storage.New(dataDir)
	s.outbox = NewOutbox(s.store)
	if cluster != nil {
		if signer, err := s.loadOIDCSignerCluster(cluster); err != nil {
			return nil, err
		} else {
			s.oidc = signer
		}
		if err := s.loadLeaseKeyCluster(cluster); err != nil {
			return nil, err
		}
		if err := s.loadRunnerCACluster(cluster); err != nil {
			return nil, err
		}
		if err := s.loadProvenanceCluster(cluster); err != nil {
			return nil, err
		}
		if err := s.loadCacheSignerCluster(cluster); err != nil {
			return nil, err
		}
		if err := s.loadWebSessionCluster(cluster); err != nil {
			return nil, err
		}
	} else {
		if signer, err := loadOIDCSigner(dataDir); err != nil {
			return nil, err
		} else {
			s.oidc = signer
		}
		key, err := loadLeaseKey(dataDir)
		if err != nil {
			return nil, err
		}
		s.leaseKey = key
		if err := s.loadRunnerCA(dataDir); err != nil {
			return nil, err
		}
		// Distinct signing roots: artifact provenance, cache manifests and web
		// session cookies each get their own persisted key material.
		if err := s.loadProvenanceKey(dataDir); err != nil {
			return nil, err
		}
		if err := s.loadCacheSigner(dataDir); err != nil {
			return nil, err
		}
		if err := s.loadWebSessionSecret(dataDir); err != nil {
			return nil, err
		}
	}
	if err := s.loadCRL(dataDir); err != nil {
		return nil, err
	}
	if err := s.loadSecretReceipts(dataDir); err != nil {
		return nil, err
	}
	if err := s.loadTestintelHistory(dataDir); err != nil {
		return nil, err
	}
	if err := s.loadSchedules(dataDir); err != nil {
		return nil, err
	}
	snap, err := s.store.Load()
	if err != nil {
		return nil, err
	}
	s.runs, s.jobs, s.runners, s.artifacts, s.reports = snap.Runs, snap.Jobs, snap.Runners, snap.Artifacts, snap.Reports
	s.downstreamLinks = snap.DownstreamLinks
	if s.downstreamLinks == nil {
		s.downstreamLinks = map[string]storage.DownstreamLink{}
	}
	s.rebuildArtifactContractsLocked()
	// DB-mode artifact transport: payload bytes move through the shared
	// CAS blob store (default: filesystem under dataDir/cas) so downloads
	// resolve on any replica. The app agent overrides the backend via
	// SetBlobStore when config selects S3.
	if s.BlobStore == nil {
		s.BlobStore = blob.NewFS(filepath.Join(dataDir, "cas"))
	}
	s.CAS = cas.New(s.BlobStore)
	if err := s.loadDrainFlag(dataDir); err != nil {
		return nil, err
	}
	if seq, err := s.store.MaxLogSeq(); err != nil {
		return nil, err
	} else {
		s.logSeq = seq
	}
	for id, run := range s.runs {
		for _, key := range []string{"github_delivery", "gitlab_delivery", "forgejo_delivery"} {
			if delivery := strings.TrimSpace(run.Metadata[key]); delivery != "" {
				s.deliveries[delivery] = id
			}
		}
	}
	for id, a := range s.artifacts {
		a.Path = filepath.Join(dataDir, "artifacts", a.RunID, a.JobID, id+".tar.gz")
		if a.ProvenanceSHA256 != "" {
			a.ProvenancePath = a.Path + ".intoto.json"
		}
		s.artifacts[id] = a
	}
	// A restarted control plane must not blindly assume an old process is
	// still polling, but it also must not duplicate jobs whose leases are
	// still valid: rebuild each runner's ActiveJobs from the jobs whose
	// unexpired running leases it actually still holds.
	now := time.Now().UTC()
	for id, r := range s.runners {
		var active []string
		for _, j := range s.jobs {
			if j.LeaseRunnerID == id && j.Status == model.StatusRunning && j.LeaseExpiresAt != nil && j.LeaseExpiresAt.After(now) {
				active = append(active, j.ID)
			}
		}
		if r.Capacity < 1 {
			r.Capacity = 1
		}
		r.ActiveJobs = active
		r.Busy = len(active) >= r.Capacity
		r.CurrentJob = ""
		if len(active) > 0 {
			r.CurrentJob = active[0]
		}
		s.runners[id] = r
	}
	s.mu.Lock()
	s.recoverLeasesLocked(now, true)
	err = s.persistLocked()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := s.ConfigureOPA(); err != nil {
		return nil, err
	}
	s.initTracingFromEnv()
	return s, nil
}

// SwitchToDB wires the PostgreSQL control plane into an already-constructed
// Server: Sched backs enqueue/lease/heartbeat/complete/cancel/recover and the
// SQL store becomes the source of truth. The in-memory maps are kept but
// ignored while Sched is set. A hard store failure is returned; losing the
// leadership claim to another live instance is not an error — the server
// starts as a standby (leader=false) and Maintain polls for promotion.
func (s *Server) SwitchToDB(db storage.Store) error {
	// Tokens are HMACed with the server lease key before persistence so the
	// durable row validates under validActiveLease on every instance that
	// shares the key (persisted via data-dir in production).
	sched := scheduler.NewDB(db, s.leaseDuration(), nil, func(raw string) []byte {
		return hashLeaseToken(s.leaseKey, raw)
	})
	if err := sched.InitErr(); err != nil {
		return fmt.Errorf("server: switch to db: %w", err)
	}
	s.Sched = sched
	s.DB = db
	s.LeaderKey = sched.LeaderKey
	s.leader = sched.IsLeader(context.Background())
	// DB mode: the durable outbox, schedules and artifact contracts move
	// into the SQL store.
	s.outbox.AttachDB(db)
	if err := s.outbox.ReplayDB(context.Background()); err != nil {
		s.logError("outbox: db replay failed", "error", err.Error())
	}
	if err := s.reloadSchedulesDB(context.Background()); err != nil {
		s.logError("schedules: db load failed", "error", err.Error())
	}
	if err := s.ConfigureOPA(); err != nil {
		return fmt.Errorf("server: compile OPA policy: %w", err)
	}
	s.initTracingFromEnv()
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.ui)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(webAssets())))
	mux.HandleFunc("POST /api/v1/login", s.webLogin)
	mux.HandleFunc("GET /api/v1/logout", s.webLogout)
	mux.HandleFunc("GET /readiness", s.readiness)
	mux.HandleFunc("GET /liveness", s.liveness)
	mux.HandleFunc("POST /hooks/github", s.githubWebhook)
	mux.HandleFunc("POST /hooks/gitlab", s.gitlabWebhook)
	mux.HandleFunc("POST /hooks/forgejo", s.forgejoWebhook)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.oidcConfiguration)
	mux.HandleFunc("GET /api/v1/oidc/jwks", s.oidcJWKS)
	mux.HandleFunc("POST /api/v1/jobs/{id}/oidc", s.issueOIDC)
	mux.HandleFunc("POST /api/v1/jobs/{id}/secrets", s.issueSecret)
	mux.HandleFunc("GET /api/v1/runs", s.listRuns)
	mux.HandleFunc("POST /api/v1/runs", s.submit)
	mux.HandleFunc("GET /api/v1/runs/{id}", s.getRun)
	mux.HandleFunc("POST /api/v1/runs/{id}/cancel", s.cancelRun)
	mux.HandleFunc("POST /api/v1/runs/{id}/rerun", s.rerunRun)
	mux.HandleFunc("GET /api/v1/runs/{id}/jobs", s.listJobs)
	mux.HandleFunc("GET /api/v1/runs/{id}/logs", s.getLogs)
	mux.HandleFunc("GET /api/v1/runs/{id}/logs/stream", s.streamLogs)
	mux.HandleFunc("GET /api/v1/runs/{id}/artifacts", s.listArtifacts)
	mux.HandleFunc("GET /api/v1/runs/{id}/tests", s.listTestReports)
	mux.HandleFunc("GET /api/v1/test-intelligence", s.testIntelligence)
	mux.HandleFunc("POST /api/v1/jobs/{id}/tests", s.uploadTestReport)
	mux.HandleFunc("GET /api/v1/jobs/{id}/test-shards", s.testShards)
	mux.HandleFunc("GET /api/v1/artifacts/{id}", s.downloadArtifact)
	mux.HandleFunc("GET /api/v1/artifacts/{id}/provenance", s.downloadProvenance)
	mux.HandleFunc("PUT /api/v1/jobs/{id}/artifacts/{name}", s.uploadArtifact)
	mux.HandleFunc("GET /api/v1/jobs/{id}/dependencies/{producer}/{artifact}", s.downloadDependency)
	mux.HandleFunc("GET /api/v1/schedules", s.listSchedules)
	mux.HandleFunc("PUT /api/v1/schedules", s.upsertSchedule)
	mux.HandleFunc("POST /api/v1/schedules/{id}/trigger", s.triggerSchedule)
	// Cache transport is a job-lease operation: the namespace derives from
	// the leased job's repository and trust domain, never from client
	// headers (see P0-3 in blobs.go).
	mux.HandleFunc("GET /api/v1/jobs/{id}/cache/{key}", s.downloadJobCache)
	mux.HandleFunc("PUT /api/v1/jobs/{id}/cache/{key}", s.uploadJobCache)
	mux.HandleFunc("POST /api/v1/jobs/{id}/approve", s.approveJob)
	mux.HandleFunc("POST /api/v1/jobs/{id}/heartbeat", s.heartbeat)
	mux.HandleFunc("POST /api/v1/jobs/{id}/log", s.log)
	mux.HandleFunc("POST /api/v1/jobs/{id}/complete", s.complete)
	mux.HandleFunc("POST /api/v1/jobs/{id}/generated", s.generateJobs)
	mux.HandleFunc("POST /api/v1/jobs/{id}/snapshots", s.uploadSnapshot)
	mux.HandleFunc("GET /api/v1/runs/{id}/snapshots", s.listSnapshots)
	mux.HandleFunc("GET /api/v1/runs/{id}/snapshots/{sid}", s.downloadSnapshot)
	mux.HandleFunc("POST /api/v1/jobs/{id}/deployments", s.recordDeployment)
	mux.HandleFunc("GET /api/v1/runs/{id}/deployments", s.listDeployments)
	mux.HandleFunc("POST /api/v1/drain", s.drainServer)
	mux.HandleFunc("GET /api/v1/drain", s.drainStatus)
	mux.HandleFunc("POST /api/v1/runners/register", s.register)
	mux.HandleFunc("POST /api/v1/runners/enroll", s.enroll)
	mux.HandleFunc("POST /api/v1/runners/{id}/next", s.next)
	mux.HandleFunc("GET /api/v1/runners", s.listRunners)
	mux.HandleFunc("POST /api/v1/runners/{id}/drain", s.runnerDrain)
	mux.HandleFunc("POST /api/v1/runners/{id}/disable", s.runnerDisable)
	mux.HandleFunc("POST /api/v1/runners/{id}/enable", s.runnerEnable)
	mux.HandleFunc("GET /api/v1/audit", s.listAudit)
	// The auth middleware runs inside statusLogger/recoverer and outside
	// s.auth so authenticated principals are available to handlers; s.auth
	// keeps the legacy bearer checks and classifies routes. The rate
	// limiter runs between them: it sees the authenticated principal but
	// sits in front of authorization so 429s are cheap. observeHTTP
	// records kiwi_http_requests_total for every request.
	var h http.Handler = mux
	if s.RateLimiter != nil {
		h = s.RateLimiter.Wrap(h)
	}
	h = s.auth(h)
	h = auth.Middleware(s.AuthStore, s.AdminToken, h, s.logf)
	h = s.observeHTTP(h)
	h = s.tracingMiddleware(h)
	return requestID(s.recoverer(s.statusLogger(h)))
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch classifyRoute(r) {
		case tierPublic:
			next.ServeHTTP(w, r)
			return
		case tierEnroll:
			// Runner enrollment authenticates with the enrollment token instead
			// of the runner token; the certificate it returns is what the runner
			// uses for everything after.
			if s.RunnerEnrollToken == "" || s.RunnerCA == nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			if !bearerOK(r.Header.Get("Authorization"), s.RunnerEnrollToken) && !bearerOK(r.Header.Get("X-Kiwi-Enroll-Token"), s.RunnerEnrollToken) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
			return
		case tierRunner:
			// Runner-tier routes: only the runner token bearer may pass.
			// Handlers enforce the lease and mTLS identity binding on top.
			if s.RunnerToken != "" && !bearerOK(r.Header.Get("Authorization"), s.RunnerToken) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
			return
		case tierRBAC:
			// RBAC action routes: the per-action role (read, artifact_read,
			// run, approve, cancel, rerun, runner_manage, policy_manage) is
			// enforced in the handlers via requireAction with the resolved
			// repository scope. Web sessions authenticate as admin-tier; a
			// store principal is required otherwise.
			if s.webSessionOK(r) {
				if webMutatingMethod(r.Method) && !s.webCSRFOK(r) {
					http.Error(w, "invalid csrf token", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			if s.adminOK(r) {
				next.ServeHTTP(w, r)
				return
			}
			if s.AdminToken == "" && (s.AuthStore == nil || s.AuthStore.Empty()) {
				// Legacy open mode: nothing is configured, so there is no
				// identity to authorize against.
				next.ServeHTTP(w, r)
				return
			}
			if _, ok := auth.PrincipalFrom(r); !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
			return
		case tierAdmin:
			// Web sessions: a valid kiwi_session cookie authorizes admin-tier
			// routes like the admin bearer token. Mutating requests
			// authenticated this way must also present the double-submit CSRF
			// token in the X-Kiwi-CSRF header.
			if s.webSessionOK(r) {
				if webMutatingMethod(r.Method) && !s.webCSRFOK(r) {
					http.Error(w, "invalid csrf token", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			// Admin-tier routes: the AdminToken bearer or a store principal
			// with the admin role. Nothing configured is the legacy open mode.
			if !s.adminOK(r) {
				if s.AdminToken == "" && (s.AuthStore == nil || s.AuthStore.Empty()) {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}
	})
}

// adminOK authorizes admin-tier routes: the AdminToken bearer or a store
// principal holding the admin role.
func (s *Server) adminOK(r *http.Request) bool {
	if s.AdminToken != "" && bearerOK(r.Header.Get("Authorization"), s.AdminToken) {
		return true
	}
	p, ok := auth.PrincipalFrom(r)
	return ok && p.Has(auth.RoleAdmin)
}

// requireAction enforces the per-action RBAC decision for authenticated
// store principals. Requests without a principal are legacy mode: no admin
// token and no store tokens are configured, so auth() gates nothing and
// there is no identity to authorize against.
func (s *Server) requireAction(w http.ResponseWriter, r *http.Request, action auth.Action, repo string, trusted bool) bool {
	p, ok := auth.PrincipalFrom(r)
	if !ok {
		return true
	}
	if auth.Authorize(p, action, repo, trusted) {
		return true
	}
	http.Error(w, "forbidden", http.StatusForbidden)
	return false
}

// actorFrom returns the audit actor for admin actions: the authenticated
// principal's subject. "api" is kept only for unauthenticated legacy mode
// where no principal exists; the X-Kiwi-Actor header is not trusted.
func actorFrom(r *http.Request) string {
	if p, ok := auth.PrincipalFrom(r); ok && p.Subject != "" {
		return p.Subject
	}
	return "api"
}

func bearerOK(header, want string) bool {
	got := strings.TrimPrefix(header, "Bearer ")
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// logf routes formatted messages (the auth middleware callback contract)
// into the structured operational logger.
func (s *Server) logf(format string, args ...any) {
	if s.Logger == nil {
		log.Printf(format, args...)
		return
	}
	s.Logger.Warn(fmt.Sprintf(format, args...))
}

// logInfo/logError emit structured operational logs, falling back to the
// standard logger when no structured logger is configured.
func (s *Server) logInfo(msg string, kv ...any) {
	if s.Logger == nil {
		log.Printf("server: %s %v", msg, kv)
		return
	}
	s.Logger.Info(msg, kv...)
}

func (s *Server) logError(msg string, kv ...any) {
	if s.Logger == nil {
		log.Printf("server: %s %v", msg, kv)
		return
	}
	s.Logger.Error(msg, kv...)
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request) {
	var in SubmitRun
	if !decode(w, r, &in) {
		return
	}
	if !s.requireAction(w, r, auth.ActionRun, auth.CanonicalRepoID(repoHost(in.RepoURL), in.RepoFullName), false) {
		return
	}
	// Direct API submissions are never trusted; only the forge webhook path
	// (and internal reruns of previously trusted runs) set Trusted. The
	// `trusted` field is not accepted from client JSON (json:"-").
	in.Trusted = false
	run, err := s.enqueue(in)
	if err != nil {
		var adm *admissionError
		if errors.As(err, &adm) {
			writeJSON(w, adm.Status, map[string]string{"error": adm.Msg, "reason": adm.Reason})
			return
		}
		var denial *opaDenialError
		if errors.As(err, &denial) {
			http.Error(w, denial.Error(), http.StatusForbidden)
			return
		}
		var budget *budgetUnavailableError
		if errors.As(err, &budget) {
			w.Header().Set("X-Kiwi-Quota", budget.Reason)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": budget.Error(), "reason": budget.Reason})
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) enqueue(in SubmitRun) (model.Run, error) {
	return s.enqueueID(in, "")
}

// enqueueID is enqueue with an optional pre-generated run ID (schedules
// claim their occurrence before enqueueing and therefore need the ID up
// front).
func (s *Server) enqueueID(in SubmitRun, preRunID string) (model.Run, error) {
	ctx, span := s.startSpan(context.Background(), "server.enqueue")
	defer span.End()
	// Server-side pipeline resolution: components are resolved and merged,
	// inputs validated and injected, and the canonical pipeline text
	// replaces the submission so every persisted job carries a
	// self-contained, deterministic pipeline.
	spec, pipelineText, componentDigests, err := s.resolvePipeline(ctx, in)
	if err != nil {
		return model.Run{}, err
	}
	in.Pipeline = pipelineText
	g, err := pipeline.Compile(spec)
	if err != nil {
		return model.Run{}, err
	}
	caps := policy.DefaultUntrustedCapabilities()
	if in.Trusted {
		caps = policy.DefaultTrustedCapabilities()
	}
	if s.AdmissionCapabilities != nil {
		caps = *s.AdmissionCapabilities
	}
	// Repository/org policy file restrictions are intersected on top of the
	// defaults, then the hard trust floor is applied. A policy file can only
	// ever narrow capabilities.
	if s.Policy != nil {
		caps = policy.Intersect(caps, s.Policy.CapabilitiesFor(in.RepoFullName))
		grants := s.Policy.GrantsFor(in.RepoFullName)
		caps.Deployments = caps.Deployments || grants.Deployments
		caps.GenerateChildGraph = caps.GenerateChildGraph || grants.GenerateChildGraph
		caps.CrossRepoTrigger = caps.CrossRepoTrigger || grants.CrossRepoTrigger
	}
	caps = caps.Effective(in.Trusted)
	// The OPA deny gate evaluates BEFORE capability admission: a denial is
	// cheaper than full admission validation and must win even when the
	// capability pass would also reject the submission.
	oidcAudiences := policy.OIDCFromCapabilities(caps).AllowedAudiences
	if denial := s.opaAdmissionCheck(ctx, in, g, caps, oidcAudiences); denial != nil {
		span.SetStatus(codes.Error, "opa denial")
		return model.Run{}, denial
	}
	if err = policy.ValidateAdmissionWithCapabilities(spec, caps); err != nil {
		return model.Run{}, err
	}
	// Organization policy restrictions (clone hosts, regions, digest pins)
	// and capability-scoped declarations (downstream, generate) are
	// enforced in the same admission step.
	if err = s.admitPolicyRestrictions(in, spec, caps); err != nil {
		return model.Run{}, err
	}
	pipelineDigest, err := pipeline.PipelineDigest(spec)
	if err != nil {
		return model.Run{}, err
	}
	policyJSON, err := json.Marshal(caps)
	if err != nil {
		return model.Run{}, err
	}
	now := time.Now().UTC()
	runID := preRunID
	if runID == "" {
		runID, err = newID()
		if err != nil {
			return model.Run{}, fmt.Errorf("generate run id: %w", err)
		}
	}
	group := expandConcurrency(spec.Concurrency.Group, in)
	run := model.Run{ID: runID, Repo: in.RepoURL, RepoFullName: in.RepoFullName, Ref: in.Ref, SHA: in.SHA, Event: in.Event,
		Status: model.StatusQueued, Trusted: in.Trusted, ConcurrencyGroup: group, CreatedAt: now, Metadata: cloneMap(in.Metadata)}

	jobIDs := make(map[string]string, len(g.Jobs))
	for key := range g.Jobs {
		id, idErr := newID()
		if idErr != nil {
			return model.Run{}, fmt.Errorf("generate job id: %w", idErr)
		}
		jobIDs[key] = id
	}
	created := make(map[string]model.Job, len(g.Jobs))
	jobContracts := map[string]map[string]storage.ArtifactContract{}
	for key, cj := range g.Jobs {
		needs := make([]string, 0, len(cj.Needs))
		for _, dep := range cj.Needs {
			needs = append(needs, jobIDs[dep])
		}
		env := cj.Job.Environment.Name
		infraRetries := cj.Job.InfraRetries
		if infraRetries <= 0 {
			infraRetries = 2
		}
		effectiveNetwork := cj.Job.Network
		if effectiveNetwork == "" {
			effectiveNetwork = "bridge"
		}
		if !in.Trusted && cj.Job.Runtime == "container" {
			effectiveNetwork = "none"
		}
		// The compiled job payload is the deterministic enqueue-time record
		// the runner can verify its own recompilation against.
		cjJSON, mErr := json.Marshal(cj)
		if mErr != nil {
			return model.Run{}, mErr
		}
		digestSum := sha256.Sum256(cjJSON)
		jobDigest := hex.EncodeToString(digestSum[:])
		jobContracts[jobIDs[key]] = buildJobContracts(cj)
		created[jobIDs[key]] = model.Job{
			ID: jobIDs[key], RunID: runID, Key: key, BaseKey: cj.BaseID, RepoURL: in.RepoURL, RepoFullName: in.RepoFullName, Ref: in.Ref, SHA: in.SHA,
			Event: in.Event, Condition: cj.Job.If, DependencyStatus: model.StatusSuccess, Pipeline: in.Pipeline, Trusted: in.Trusted, ChangedFiles: append([]string{}, in.ChangedFiles...), Needs: needs,
			RequiredLabels: labelsForJob(cj.Job), Network: effectiveNetwork, Environment: env, ApprovalRequired: cj.Job.Environment.Approval, EnvironmentBranches: append([]string{}, cj.Job.Environment.Branches...), EnvironmentConcurrency: cj.Job.Environment.Concurrency, OIDCAllowed: cj.Job.Permissions.IDToken, OIDCAudiences: cloneStrings(oidcAudiences),
			DeclaredSecrets: declaredSecrets(spec, cj.Job),
			Status:          model.StatusQueued, Priority: scheduler.DownstreamDepth(g, key), MaxInfraRetries: infraRetries, CreatedAt: now,
			PlacementRegions: append([]string{}, cj.Job.Placement.Regions...),
			ComponentDigest:  componentDigests[cj.BaseID],
			CompiledJobPayload: &model.CompiledJobPayload{
				SchemaVersion:   1,
				CompilerVersion: version.Version,
				PipelineDigest:  pipelineDigest,
				JobDigest:       jobDigest,
				EffectiveJob:    json.RawMessage(cjJSON),
				EffectivePolicy: json.RawMessage(policyJSON),
			},
		}
	}
	// Artifact contracts ride the enqueue transaction (InsertCompiledRun)
	// in DB mode and the in-memory maps in memory mode; nothing is
	// persisted before the run and its jobs exist.

	if s.Sched != nil {
		return s.enqueueDB(in, run, created, jobContracts, group, spec.Concurrency.CancelInProgress, now)
	}

	s.mu.Lock()
	// Schedule occurrence atomicity (memory mode): a conflicting claim for
	// the same nominal aborts before anything is inserted, and the claim
	// itself lands only after the run and its jobs are committed to the
	// in-memory maps, so a failed enqueue leaves the occurrence unclaimed
	// and the next tick refires it.
	if in.ScheduleClaim != nil {
		occ := s.occurrences[in.ScheduleClaim.ScheduleID]
		if occ != nil {
			if existing, ok := occ[in.ScheduleClaim.Nominal.UTC().Unix()]; ok && existing != runID {
				s.mu.Unlock()
				return model.Run{}, storage.ErrScheduleClaimLost
			}
		}
	}
	// Quota admission happens inside the run lock so the concurrency and
	// queue-depth counts are race-free with concurrent enqueues.
	if err := s.admitQuotaLocked(run, len(g.Jobs)); err != nil {
		s.mu.Unlock()
		return model.Run{}, err
	}
	// Webhook dedupe: forge retries reuse the delivery ID, so a second
	// submission for the same delivery returns the original run instead of
	// enqueueing a duplicate. Checked under the run lock to close the race
	// between the handler fast path and concurrent deliveries.
	if delivery, ok := webhookDelivery(in.Metadata); ok {
		if existing, ok := s.deliveries[delivery]; ok {
			if prior, ok := s.runs[existing]; ok && prior.RepoFullName == in.RepoFullName {
				s.mu.Unlock()
				return prior, nil
			}
		}
	}
	if group != "" && spec.Concurrency.CancelInProgress {
		for id, old := range s.runs {
			if old.ID != runID && old.Repo == in.RepoURL && old.ConcurrencyGroup == group && !old.Status.Terminal() {
				s.cancelRunLocked(id, "superseded by run "+runID, "scheduler")
			}
		}
	}
	s.runs[runID] = run
	for id, j := range created {
		s.jobs[id] = j
		if contracts, ok := jobContracts[id]; ok {
			s.contracts[id] = contracts
		}
	}
	if in.ScheduleClaim != nil {
		s.claimScheduleOccurrenceLocked(in.ScheduleClaim.ScheduleID, in.ScheduleClaim.Nominal, runID)
	}
	s.auditLocked("run.queued", "scheduler", runID, "", "run queued", map[string]string{"event": in.Event})
	s.scheduleStateLocked()
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		return model.Run{}, err
	}
	if in.ScheduleClaim != nil {
		if err := s.persistSchedulesLocked(); err != nil {
			s.mu.Unlock()
			return model.Run{}, err
		}
	}
	run = s.runs[runID]
	for _, key := range []string{"github_delivery", "gitlab_delivery", "forgejo_delivery"} {
		if delivery := in.Metadata[key]; delivery != "" {
			if _, exists := s.deliveries[delivery]; !exists {
				s.deliveries[delivery] = runID
			}
		}
	}
	s.mu.Unlock()
	s.publishGitHubStatus(run)
	return run, nil
}

// enqueueDB persists a compiled run through the storage.RunEnqueueStore:
// ONE InsertCompiledRun transaction inserts the run, jobs, dependencies and
// artifact contracts, cancels the superseded jobs with audit rows, and
// claims the webhook delivery, quota reservation and (optionally) schedule
// occurrence. It mirrors enqueue's dedupe and supersession semantics
// against the durable delivery table and the SQL run list, decides
// approval/environment gating up front (the SQL completion path does not
// re-run the full schedule pass), and emits the run.queued audit event
// through the DB audit funnel.
func (s *Server) enqueueDB(in SubmitRun, run model.Run, created map[string]model.Job, jobContracts map[string]map[string]storage.ArtifactContract, group string, cancelInProgress bool, now time.Time) (model.Run, error) {
	ctx := context.Background()
	// Daily budget state: enqueues are refused while the usage store is
	// unavailable unless the operator explicitly fails open.
	if _, _, err := s.dailyBudgetStateDB(ctx); err != nil && !s.QuotaFailOpen {
		return model.Run{}, &budgetUnavailableError{Reason: queueReasonBudgetStateUnavailable}
	}
	for id, j := range created {
		switch {
		case len(j.EnvironmentBranches) > 0 && !environmentBranchAllowed(run.Ref, j.EnvironmentBranches):
			j.Status = model.StatusBlocked
			j.Error = "ref is not allowed to deploy to environment " + j.Environment
			j.FinishedAt = &now
		case j.ApprovalRequired && j.ApprovedBy == "":
			j.Status = model.StatusWaitingApproval
			if j.WaitingSince == nil {
				j.WaitingSince = &now
			}
		}
		created[id] = j
	}
	deps := make(map[string][]string, len(created))
	for id, j := range created {
		deps[id] = append([]string(nil), j.Needs...)
	}
	// Concurrency supersession: collect the non-terminal job IDs of the
	// runs sharing this repository and concurrency group so the enqueue
	// transaction cancels them atomically with the insert.
	var cancelPrevious []string
	if cancelInProgress && group != "" {
		runs, err := s.DB.ListRuns(ctx, 10000)
		if err != nil {
			return model.Run{}, fmt.Errorf("list runs for supersession: %w", err)
		}
		for _, old := range runs {
			if old.ID == run.ID || old.Repo != run.Repo || old.ConcurrencyGroup != group || old.Status.Terminal() {
				continue
			}
			jobs, err := s.DB.ListJobsByRun(ctx, old.ID)
			if err != nil {
				return model.Run{}, fmt.Errorf("list jobs for supersession: %w", err)
			}
			for _, j := range jobs {
				if !j.Status.Terminal() {
					cancelPrevious = append(cancelPrevious, j.ID)
				}
			}
		}
	}
	req := storage.InsertCompiledRunRequest{
		Run:            run,
		Jobs:           created,
		Deps:           deps,
		Contracts:      jobContracts,
		CancelPrevious: cancelPrevious,
	}
	if forge, delivery, ok := webhookDeliveryForge(in.Metadata); ok {
		req.WebhookClaim = &storage.WebhookClaim{Forge: forge, DeliveryID: delivery, RunID: run.ID}
	}
	req.Quota = &storage.QuotaReservation{
		RepoKey:         run.Repo,
		TeamKey:         repoURLTeam(run.Repo),
		JobCount:        len(created),
		RepoConcurrency: s.QuotaLimits.RepoConcurrency,
		TeamConcurrency: s.QuotaLimits.TeamConcurrency,
		RepoQueueDepth:  s.QuotaLimits.RepoQueueDepth,
		TeamQueueDepth:  s.QuotaLimits.TeamQueueDepth,
	}
	if in.ScheduleClaim != nil {
		req.ScheduleClaim = in.ScheduleClaim
	}
	rs, ok := s.DB.(storage.RunEnqueueStore)
	if !ok {
		// Fallback for stores predating the atomic enqueue: the old
		// scheduler sequence plus a best-effort delivery upsert.
		if err := s.Sched.Enqueue(ctx, run, created, deps, cancelInProgress && group != ""); err != nil {
			return model.Run{}, err
		}
		if req.WebhookClaim != nil {
			if err := s.DB.UpsertDelivery(ctx, req.WebhookClaim.Forge, req.WebhookClaim.DeliveryID, run.ID, ""); err != nil {
				s.logError("delivery upsert failed", "error", err.Error())
			}
		}
		s.auditLocked("run.queued", "scheduler", run.ID, "", "run queued", map[string]string{"event": in.Event})
		s.publishGitHubStatus(run)
		return run, nil
	}
	err := rs.InsertCompiledRun(ctx, req)
	switch {
	case errors.Is(err, storage.ErrDeliveryDuplicate):
		// A forge retry replayed this delivery: return the ORIGINAL run
		// instead of the duplicate submission.
		if req.WebhookClaim == nil {
			return model.Run{}, err
		}
		if existingID, found, ferr := s.DB.FindDelivery(ctx, req.WebhookClaim.Forge, req.WebhookClaim.DeliveryID); ferr != nil {
			return model.Run{}, fmt.Errorf("lookup delivery: %w", ferr)
		} else if found {
			if prior, gerr := s.DB.GetRun(ctx, existingID); gerr == nil && prior.RepoFullName == in.RepoFullName {
				return prior, nil
			}
		}
		return model.Run{}, err
	case errors.Is(err, storage.ErrScheduleClaimLost):
		return model.Run{}, err
	default:
		var qe *storage.QuotaExceededError
		if errors.As(err, &qe) {
			return model.Run{}, &admissionError{Status: http.StatusTooManyRequests, Reason: qe.Reason, Msg: qe.Msg}
		}
		if err != nil {
			return model.Run{}, err
		}
	}
	s.auditLocked("run.queued", "scheduler", run.ID, "", "run queued", map[string]string{"event": in.Event})
	s.publishGitHubStatus(run)
	return run, nil
}

// webhookDeliveryForge extracts the forge and delivery ID from submit
// metadata, if any.
func webhookDeliveryForge(meta map[string]string) (forge, delivery string, ok bool) {
	for _, key := range []string{"github_delivery", "gitlab_delivery", "forgejo_delivery"} {
		if v := strings.TrimSpace(meta[key]); v != "" {
			return strings.TrimSuffix(key, "_delivery"), v, true
		}
	}
	return "", "", false
}

// webhookDelivery extracts the forge delivery ID from submit metadata, if
// any. The keys are recorded on the run's Metadata so a restarted control
// plane can rebuild its deliveries map from persisted runs.
func webhookDelivery(meta map[string]string) (string, bool) {
	for _, key := range []string{"github_delivery", "gitlab_delivery", "forgejo_delivery"} {
		if v := strings.TrimSpace(meta[key]); v != "" {
			return v, true
		}
	}
	return "", false
}

func labelsForJob(j pipeline.Job) []string {
	set := map[string]bool{}
	rt := j.Runtime
	if rt == "" {
		rt = "native"
	}
	set[rt] = true
	if rt == "tart" {
		set["os:darwin"] = true
	}
	for _, l := range j.Runner {
		if l != "" {
			set[l] = true
		}
	}
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// expandConcurrency resolves the concurrency group template against the
// submission context using the expression engine. Supported contexts:
// ${{ repo }}, ${{ repo.full_name }}, ${{ branch }}, ${{ ref }}, ${{ sha }},
// ${{ event }}, ${{ git.branch }}, ${{ git.ref }}, ${{ git.sha }} (tight
// brace forms too). Holes that fail to parse or evaluate are left literal,
// matching the previous replacer behavior. The branch context is derived
// from the ref: refs/heads/<name> yields <name>, a bare ref is used as-is,
// and other refs (e.g. refs/tags/...) yield an empty branch.
func expandConcurrency(v string, in SubmitRun) string {
	if !strings.Contains(v, "${{") {
		return strings.TrimSpace(v)
	}
	c := expr.Context{
		Event:    in.Event,
		Branch:   branchFromRef(in.Ref),
		Ref:      in.Ref,
		SHA:      in.SHA,
		Repo:     in.RepoURL,
		RepoFull: in.RepoFullName,
	}
	out, err := expr.EvalString(v, c)
	if err != nil {
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(out)
}

// branchFromRef derives the branch context value from a git ref.
func branchFromRef(ref string) string {
	if strings.HasPrefix(ref, "refs/heads/") {
		return strings.TrimPrefix(ref, "refs/heads/")
	}
	if strings.HasPrefix(ref, "refs/") {
		return ""
	}
	return ref
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	if !s.requireAction(w, r, auth.ActionRead, "", false) {
		return
	}
	// Scoped list: non-admin principals see only the repositories their
	// grants cover.
	visible := func(run model.Run) bool { return s.repoVisible(r, run) }
	if s.DB != nil {
		out, err := s.DB.ListRuns(r.Context(), 1000)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		dto := make([]v1.RunDTO, 0, len(out))
		for _, v := range out {
			if !visible(v) {
				continue
			}
			dto = append(dto, v1.RunDTOFrom(v))
		}
		writeJSON(w, http.StatusOK, dto)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Run, 0, len(s.runs))
	for _, v := range s.runs {
		if !visible(v) {
			continue
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	dto := make([]v1.RunDTO, 0, len(out))
	for _, v := range out {
		dto = append(dto, v1.RunDTOFrom(v))
	}
	writeJSON(w, http.StatusOK, dto)
}
func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.DB != nil {
		v, err := s.DB.GetRun(r.Context(), id)
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if !s.requireRunRead(w, r, v) {
			return
		}
		writeJSON(w, http.StatusOK, v1.RunDTOFrom(v))
		return
	}
	s.mu.Lock()
	v, ok := s.runs[id]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !s.requireRunRead(w, r, v) {
		return
	}
	writeJSON(w, http.StatusOK, v1.RunDTOFrom(v))
}
func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	if s.DB != nil {
		run, err := s.DB.GetRun(r.Context(), runID)
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		} else if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if !s.requireRunRead(w, r, run) {
			return
		}
		jobs, err := s.DB.ListJobsByRun(r.Context(), runID)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		out := make([]v1.JobDTO, 0, len(jobs))
		for _, j := range jobs {
			out = append(out, v1.JobDTOFrom(j))
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[runID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !s.requireRunRead(w, r, run) {
		return
	}
	out := make([]v1.JobDTO, 0)
	for _, j := range s.jobs {
		if j.RunID == runID {
			out = append(out, v1.JobDTOFrom(j))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	writeJSON(w, http.StatusOK, out)
}
func redactJob(j model.Job) model.Job { j.Pipeline = ""; j.LeaseTokenHash = nil; return j }

func (s *Server) getLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, err := s.runForAuth(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !s.requireRunRead(w, r, run) {
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if s.DB != nil {
		v, err := s.DB.ReadLogs(r.Context(), id, after, limit)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, http.StatusOK, v)
		return
	}
	if s.store != nil {
		v, err := s.store.ReadLogs(id, after, limit)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, http.StatusOK, v)
		return
	}
	// In-memory servers keep no historical log buffer by design; tests/dev can still stream stdout.
	writeJSON(w, http.StatusOK, []model.LogEntry{})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var in model.Runner
	if !decode(w, r, &in) {
		return
	}
	// The runner API protocol is mandatory: runners that cannot declare a
	// version range are rejected rather than silently bound to an old
	// contract.
	if in.ProtocolMin == 0 && in.ProtocolMax == 0 {
		http.Error(w, "protocol version required", http.StatusBadRequest)
		return
	}
	if in.ProtocolMax < ProtocolMin || in.ProtocolMin > ProtocolMax {
		http.Error(w, "unsupported protocol version", http.StatusBadRequest)
		return
	}
	if in.ProtocolMin < ProtocolMin {
		in.ProtocolMin = ProtocolMin
	}
	if in.ProtocolMax > ProtocolMax {
		in.ProtocolMax = ProtocolMax
	}
	// With runner mTLS enabled the TLS peer certificate is the identity: it
	// must match the claimed ID (an empty ID adopts the certificate
	// identity). Without mTLS the bearer token authenticated by auth() is
	// the identity.
	if err := s.bindRunnerIdentity(r, in.ID); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if in.ID == "" && s.RunnerCA != nil {
		if peerID, err := s.peerRunnerID(r); err == nil {
			in.ID = peerID
		}
	}
	if in.ID == "" {
		id, err := newID()
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		in.ID = id
	}
	if in.Name == "" {
		in.Name = in.ID
	}
	now := time.Now().UTC()
	if s.DB != nil {
		old, gerr := s.DB.GetRunner(r.Context(), in.ID)
		if gerr != nil && !errors.Is(gerr, storage.ErrNotFound) {
			http.Error(w, gerr.Error(), 500)
			return
		}
		// Re-registration must not clear admin state: a disabled runner
		// stays disabled and a draining runner keeps draining until an
		// admin re-enables it.
		in.Disabled = old.Disabled || in.Disabled
		in.Draining = old.Draining || in.Draining
		if old.Registered.IsZero() {
			in.Registered = now
		} else {
			in.Registered = old.Registered
			in.Completed = old.Completed
			in.Failed = old.Failed
		}
		if in.Capacity < 1 {
			in.Capacity = 1
		}
		in.LastSeen = now
		in.ActiveJobs = append([]string{}, old.ActiveJobs...)
		if len(in.ActiveJobs) == 0 && old.CurrentJob != "" {
			in.ActiveJobs = []string{old.CurrentJob}
		}
		in.Busy = len(in.ActiveJobs) >= in.Capacity
		if len(in.ActiveJobs) > 0 {
			in.CurrentJob = in.ActiveJobs[0]
		}
		if err := s.DB.UpsertRunner(r.Context(), in); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		s.auditLocked("runner.register", in.Name, "", "", "runner registered", nil)
		writeJSON(w, http.StatusOK, in)
		return
	}
	s.mu.Lock()
	old := s.runners[in.ID]
	// Re-registration must not clear admin state: a disabled runner stays
	// disabled and a draining runner keeps draining until an admin
	// re-enables it. Runners may also self-drain at registration
	// (kiwi runner --drain).
	in.Disabled = old.Disabled || in.Disabled
	in.Draining = old.Draining || in.Draining
	if old.Registered.IsZero() {
		in.Registered = now
	} else {
		in.Registered = old.Registered
		in.Completed = old.Completed
		in.Failed = old.Failed
	}
	if in.Capacity < 1 {
		in.Capacity = 1
	}
	in.LastSeen = now
	in.ActiveJobs = append([]string{}, old.ActiveJobs...)
	// Migrate persisted pre-capacity state without losing an active lease.
	if len(in.ActiveJobs) == 0 && old.CurrentJob != "" {
		in.ActiveJobs = []string{old.CurrentJob}
	}
	in.Busy = len(in.ActiveJobs) >= in.Capacity
	if len(in.ActiveJobs) > 0 {
		in.CurrentJob = in.ActiveJobs[0]
	}
	s.runners[in.ID] = in
	s.auditLocked("runner.register", in.Name, "", "", "runner registered", nil)
	_ = s.persistLocked()
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, in)
}
func (s *Server) listRunners(w http.ResponseWriter, r *http.Request) {
	if !s.requireAction(w, r, auth.ActionRead, "", false) {
		return
	}
	// Scoped list: a repository-scoped principal sees runners that serve
	// (or are about to serve) its repositories; idle runners carry no
	// repository data and stay visible.
	if s.DB != nil {
		out, err := s.DB.ListRunners(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		dto := make([]v1.RunnerDTO, 0, len(out))
		for _, x := range out {
			if !s.runnerVisible(r, x) {
				continue
			}
			dto = append(dto, v1.RunnerDTOFrom(x))
		}
		writeJSON(w, http.StatusOK, dto)
		return
	}
	s.mu.Lock()
	snapshot := make([]model.Runner, 0, len(s.runners))
	for _, x := range s.runners {
		snapshot = append(snapshot, x)
	}
	s.mu.Unlock()
	out := make([]model.Runner, 0, len(snapshot))
	for _, x := range snapshot {
		if !s.runnerVisible(r, x) {
			continue
		}
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	dto := make([]v1.RunnerDTO, 0, len(out))
	for _, x := range out {
		dto = append(dto, v1.RunnerDTOFrom(x))
	}
	writeJSON(w, http.StatusOK, dto)
}

// runnerVisible reports whether a runner is visible to the request's
// principal. Runners without active jobs are visible to any reader; runners
// with active jobs are visible when at least one of those jobs' repositories
// is.
func (s *Server) runnerVisible(r *http.Request, ri model.Runner) bool {
	if len(ri.ActiveJobs) == 0 {
		return true
	}
	allowed, restricted := s.visibleRepos(r)
	if !restricted {
		return true
	}
	for _, jobID := range ri.ActiveJobs {
		job, err := s.jobForLease(r.Context(), jobID)
		if err != nil {
			continue
		}
		run, err := s.runForAuth(r.Context(), job.RunID)
		if err != nil {
			continue
		}
		canon := canonicalRepoForRun(run)
		if allowed[canon] || allowed[run.RepoFullName] || allowed[auth.CanonicalRepoID("", run.RepoFullName)] {
			return true
		}
	}
	return false
}

// runnerDrain marks a runner as draining: it finishes its active jobs and
// receives no new leases. next() advertises the state via the
// X-Kiwi-Draining header so a drained runner exits its poll loop.
func (s *Server) runnerDrain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.requireAction(w, r, auth.ActionRunnerManage, "", false) {
		return
	}
	if s.DB != nil {
		ri, err := s.DB.GetRunner(r.Context(), id)
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		ri.Draining = true
		if err := s.DB.UpsertRunner(r.Context(), ri); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		s.auditLocked("runner.drain", actorFrom(r), "", "", "runner draining", map[string]string{"runner": id})
		writeJSON(w, http.StatusOK, ri)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ri, ok := s.runners[id]
	if !ok {
		http.NotFound(w, r)
		return
	}
	ri.Draining = true
	s.runners[id] = ri
	s.auditLocked("runner.drain", actorFrom(r), "", "", "runner draining", map[string]string{"runner": id})
	_ = s.persistLocked()
	writeJSON(w, http.StatusOK, ri)
}

// revokeRunnerDB invalidates every active lease held by the runner through
// the SQL scheduler: running jobs requeue (retry budget permitting) or
// cancel, their lease fields are cleared, and audit events are emitted.
// It is the DB-mode half of the runner disable kill switch and returns the
// number of invalidated leases.
func (s *Server) revokeRunnerDB(ctx context.Context, runnerID, reason string) (int, error) {
	if s.Sched == nil {
		return 0, errors.New("server: db runner revocation requires the sql scheduler")
	}
	return s.Sched.CancelJobsByRunner(ctx, runnerID, reason)
}

// runnerDisable takes a runner out of service: it is marked disabled, its
// active jobs are cancelled with "runner disabled", and next() refuses to
// lease to it. Re-registration cannot clear the flag. In mTLS mode the
// runner's certificate serial is also revoked (persisted CRL, see crl.go)
// so a disabled runner's still-valid certificate cannot be replayed.
func (s *Server) runnerDisable(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	actor := actorFrom(r)
	if !s.requireAction(w, r, auth.ActionRunnerManage, "", false) {
		return
	}
	if s.DB != nil {
		ri, err := s.DB.GetRunner(r.Context(), id)
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		ri.Disabled = true
		if ri.CertSerial != "" && ri.RevokedAt == nil {
			now := time.Now().UTC()
			ri.RevokedAt = &now
		}
		if err := s.DB.UpsertRunner(r.Context(), ri); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		// The disable flag alone does not stop a job already in flight: the
		// kill switch atomically invalidates every active lease held by the
		// runner so no further work can run.
		revoked, err := s.revokeRunnerDB(r.Context(), id, "runner disabled")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		s.metricAdd("kiwi_runner_killswitch_jobs_total", float64(revoked), nil)
		s.revokeRunnerCert(ri, actor)
		s.auditLocked("runner.disable", actor, "", "", "runner disabled", map[string]string{"runner": id})
		writeJSON(w, http.StatusOK, ri)
		return
	}
	s.mu.Lock()
	ri, ok := s.runners[id]
	if !ok {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	ri.Disabled = true
	if ri.CertSerial != "" && ri.RevokedAt == nil {
		now := time.Now().UTC()
		ri.RevokedAt = &now
	}
	now := time.Now().UTC()
	for jobID, j := range s.jobs {
		if j.Status != model.StatusRunning || j.LeaseRunnerID != id {
			continue
		}
		j.Status = model.StatusCancelled
		j.Error = "runner disabled"
		j.FinishedAt = &now
		j.LeaseRunnerID = ""
		j.LeaseTokenHash = nil
		j.LeaseExpiresAt = nil
		s.jobs[jobID] = j
	}
	ri.ActiveJobs = nil
	ri.Busy = false
	ri.CurrentJob = ""
	s.runners[id] = ri
	for runID := range s.runs {
		s.refreshRunLocked(runID)
	}
	s.auditLocked("runner.disable", actor, "", "", "runner disabled", map[string]string{"runner": id})
	_ = s.persistLocked()
	s.mu.Unlock()
	s.revokeRunnerCert(ri, actor)
	writeJSON(w, http.StatusOK, ri)
}

// runnerEnable returns a runner to service, clearing both the disabled and
// draining flags.
func (s *Server) runnerEnable(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.requireAction(w, r, auth.ActionRunnerManage, "", false) {
		return
	}
	if s.DB != nil {
		ri, err := s.DB.GetRunner(r.Context(), id)
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		ri.Disabled = false
		ri.Draining = false
		if err := s.DB.UpsertRunner(r.Context(), ri); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		s.auditLocked("runner.enable", actorFrom(r), "", "", "runner enabled", map[string]string{"runner": id})
		writeJSON(w, http.StatusOK, ri)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ri, ok := s.runners[id]
	if !ok {
		http.NotFound(w, r)
		return
	}
	ri.Disabled = false
	ri.Draining = false
	s.runners[id] = ri
	s.auditLocked("runner.enable", actorFrom(r), "", "", "runner enabled", map[string]string{"runner": id})
	_ = s.persistLocked()
	writeJSON(w, http.StatusOK, ri)
}

func (s *Server) next(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.verifyRunnerIdentity(r, id) {
		http.Error(w, "runner identity mismatch", http.StatusForbidden)
		return
	}
	// Graceful drain: no new leases while the control plane is draining;
	// heartbeats and completions keep working so in-flight jobs finish.
	if s.isDraining() {
		w.Header().Set("X-Kiwi-Draining", "true")
		http.Error(w, "control plane draining", http.StatusServiceUnavailable)
		return
	}
	if s.Sched != nil {
		s.nextDB(w, r, id)
		return
	}
	// Daily budget: leases are refused while the trailing-24h budget is
	// exhausted; waiting jobs are annotated with the reason.
	if reason, exceeded := s.dailyBudgetExceeded(r.Context()); exceeded {
		s.markQueueReasonsAll(r.Context(), reason)
		w.Header().Set("X-Kiwi-Quota", reason)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recoverLeasesLocked(now, false)
	s.scheduleStateLocked()
	ri, ok := s.runners[id]
	if !ok {
		http.Error(w, "runner not registered", http.StatusNotFound)
		return
	}
	ri.LastSeen = now
	if ri.Capacity < 1 {
		ri.Capacity = 1
	}
	// Disabled runners receive no leases at all: their active jobs were
	// cancelled at disable time, and re-registering cannot clear the flag.
	if ri.Disabled {
		w.Header().Set("X-Kiwi-Disabled", "true")
		s.runners[id] = ri
		_ = s.persistLocked()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Draining runners finish their active jobs but take no new work. The
	// response header lets a runner that has no active work exit its poll
	// loop instead of spinning forever.
	if ri.Draining {
		w.Header().Set("X-Kiwi-Draining", "true")
		s.runners[id] = ri
		_ = s.persistLocked()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if len(ri.ActiveJobs) >= ri.Capacity {
		ri.Busy = true
		s.runners[id] = ri
		_ = s.persistLocked()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	candidates := make([]model.Job, 0)
	for _, j := range s.jobs {
		if j.Status != model.StatusQueued || !depsReadyLocked(j, s.jobs) {
			continue
		}
		if !labelsSatisfied(ri.Labels, j.RequiredLabels) {
			continue
		}
		if !regionSatisfied(ri.Region, j.PlacementRegions) {
			continue
		}
		if environmentAtCapacityScoped(j, s.jobs) {
			continue
		}
		candidates = append(candidates, j)
	}
	if len(candidates) == 0 {
		// Explainable queueing: annotate every waiting job with the reason
		// it is not leasable by this runner. In-memory mode; nextDB applies
		// the same rules through applyQueueReasonsDB.
		s.applyQueueReasonsLocked(ri)
		s.runners[id] = ri
		_ = s.persistLocked()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority > candidates[j].Priority
		}
		return candidates[i].CreatedAt.Before(candidates[j].CreatedAt)
	})
	j := candidates[0]
	j.QueueReason = ""
	s.jobs[j.ID] = j
	j.NeedsOutputs = scheduler.CollectNeedsOutputs(j, s.jobs)
	exp := now.Add(s.leaseDuration())
	t1, err := newID()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	t2, err := newID()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	_, leaseSpan := s.startSpan(r.Context(), "server.lease")
	leaseSpan.SetAttributes(spanInt("kiwi.job_id_bytes", int64(len(j.ID))))
	rawToken := t1 + t2
	j.Status = model.StatusRunning
	j.Attempts++
	j.LeaseRunnerID = id
	j.LeaseTokenHash = hashLeaseToken(s.leaseKey, rawToken)
	j.LeaseGeneration++
	j.LeaseExpiresAt = &exp
	// The runner's registered rates are frozen into the job at lease time;
	// completion derives cost/energy from them and the wall-clock duration.
	j.CostRate = ri.CostPerHour
	j.PowerWatts = ri.PowerWatts
	if j.StartedAt == nil {
		j.StartedAt = &now
	}
	s.jobs[j.ID] = j
	ri.ActiveJobs = appendUnique(ri.ActiveJobs, j.ID)
	ri.Busy = len(ri.ActiveJobs) >= ri.Capacity
	if len(ri.ActiveJobs) > 0 {
		ri.CurrentJob = ri.ActiveJobs[0]
	}
	ri.LastSeen = now
	s.runners[id] = ri
	s.refreshRunLocked(j.RunID)
	if j.Environment != "" {
		s.recordDeploymentLocked(j, now)
	}
	s.auditLocked("job.leased", ri.Name, j.RunID, j.ID, "job leased", map[string]string{"job": j.Key, "generation": strconv.FormatInt(j.LeaseGeneration, 10)})
	s.metricObserve("kiwi_queue_latency_seconds", now.Sub(j.CreatedAt).Seconds(), nil)
	_ = s.persistLocked()
	// The raw token travels on the wire once; the hash is not needed by the
	// runner and is stripped from the task job.
	taskJob := j
	taskJob.LeaseTokenHash = nil
	task := Task{Job: taskJob, LeaseToken: rawToken, LeaseGeneration: j.LeaseGeneration, LeaseExpiresAt: exp}
	leaseSpan.End()
	writeJSON(w, http.StatusOK, task)
}

// nextDB leases through the PostgreSQL scheduler. No in-memory lock is held:
// the SQL rows are authoritative and the store serializes competing claims.
// The daily-budget gate runs BEFORE any lease: an unavailable usage store
// refuses leases (fail closed, BUDGET_STATE_UNAVAILABLE) unless
// QuotaFailOpen is set; an exhausted budget refuses with the budget reason.
// Runner admission (disabled/draining) is checked here; placement-region
// filtering happens inside scheduler.Lease against the runner's region.
func (s *Server) nextDB(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	reason, exceeded, err := s.dailyBudgetStateDB(ctx)
	switch {
	case err != nil && !s.QuotaFailOpen:
		s.markQueueReasonsAll(ctx, queueReasonBudgetStateUnavailable)
		w.Header().Set("X-Kiwi-Quota", queueReasonBudgetStateUnavailable)
		http.Error(w, "quota budget state unavailable", http.StatusServiceUnavailable)
		return
	case exceeded:
		s.markQueueReasonsAll(ctx, reason)
		w.Header().Set("X-Kiwi-Quota", reason)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	ri, err := s.DB.GetRunner(ctx, id)
	if errors.Is(err, storage.ErrNotFound) {
		http.Error(w, "runner not registered", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if ri.Disabled {
		w.Header().Set("X-Kiwi-Disabled", "true")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if ri.Draining {
		w.Header().Set("X-Kiwi-Draining", "true")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	j, rawToken, exp, err := s.Sched.Lease(ctx, id, time.Now().UTC())
	switch {
	case errors.Is(err, scheduler.ErrNotLeader):
		http.Error(w, "scheduler standby", http.StatusServiceUnavailable)
		return
	case errors.Is(err, scheduler.ErrNoJobs), errors.Is(err, storage.ErrLeaseConflict):
		s.applyQueueReasonsDB(ctx, ri)
		w.WriteHeader(http.StatusNoContent)
		return
	case errors.Is(err, storage.ErrNotFound):
		http.Error(w, "runner not registered", http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, err.Error(), 500)
		return
	}
	taskJob := *j
	taskJob.LeaseTokenHash = nil
	// Freeze the runner's registered rates into the leased job so
	// completion can derive cost/energy deterministically. The persisted
	// copy keeps the lease token hash; only the wire task strips it.
	stored := *j
	stored.CostRate = ri.CostPerHour
	stored.PowerWatts = ri.PowerWatts
	if err := s.DB.UpdateJob(ctx, stored); err != nil {
		s.logError("lease: persist frozen rates failed", "job", stored.ID, "error", err.Error())
	}
	taskJob.CostRate = stored.CostRate
	taskJob.PowerWatts = stored.PowerWatts
	task := Task{Job: taskJob, LeaseToken: rawToken, LeaseGeneration: j.LeaseGeneration, LeaseExpiresAt: exp}
	if j.Environment != "" {
		s.recordDeploymentDB(ctx, *j, time.Now().UTC())
	}
	s.metricObserve("kiwi_queue_latency_seconds", time.Since(j.CreatedAt).Seconds(), nil)
	writeJSON(w, http.StatusOK, task)
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	var in Heartbeat
	if !decode(w, r, &in) {
		return
	}
	if !s.verifyRunnerIdentity(r, in.RunnerID) {
		http.Error(w, "runner identity mismatch", http.StatusForbidden)
		return
	}
	if s.Sched != nil {
		s.heartbeatDB(w, r, jobID, in)
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if j.Status == model.StatusCancelled {
		writeJSON(w, http.StatusOK, HeartbeatResponse{Cancel: true})
		return
	}
	if !s.validActiveLease(j, in.RunnerID, in.LeaseToken, in.LeaseGeneration, now) {
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	exp := now.Add(s.leaseDuration())
	j.LeaseExpiresAt = &exp
	s.jobs[jobID] = j
	if ri, ok := s.runners[in.RunnerID]; ok {
		ri.LastSeen = now
		s.runners[in.RunnerID] = ri
	}
	_ = s.persistLocked()
	writeJSON(w, http.StatusOK, HeartbeatResponse{LeaseExpiresAt: exp})
}

// heartbeatDB validates the lease against the durable job row (the in-memory
// map may be stale) and delegates the extension to the scheduler, which also
// reports a concurrent cancellation.
func (s *Server) heartbeatDB(w http.ResponseWriter, r *http.Request, jobID string, in Heartbeat) {
	ctx := r.Context()
	now := time.Now().UTC()
	j, err := s.DB.GetJob(ctx, jobID)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if j.Status == model.StatusCancelled {
		writeJSON(w, http.StatusOK, HeartbeatResponse{Cancel: true})
		return
	}
	if !s.validActiveLease(j, in.RunnerID, in.LeaseToken, in.LeaseGeneration, now) {
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	exp := now.Add(s.leaseDuration())
	cancelled, err := s.Sched.Heartbeat(ctx, jobID, in.RunnerID, hashLeaseToken(s.leaseKey, in.LeaseToken), in.LeaseGeneration, exp)
	if errors.Is(err, storage.ErrLeaseConflict) || errors.Is(err, storage.ErrGenerationMismatch) {
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, http.StatusOK, HeartbeatResponse{Cancel: cancelled, LeaseExpiresAt: exp})
}

func (s *Server) log(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	var in LogLine
	if !decodeLimit(w, r, &in, 1<<20) {
		return
	}
	if len(in.Step) > 128 || len(in.Line) > 1<<20 || len(in.JobKey) > 512 {
		http.Error(w, "log line exceeds size limits", http.StatusBadRequest)
		return
	}
	if !s.verifyRunnerIdentity(r, in.RunnerID) {
		http.Error(w, "runner identity mismatch", http.StatusForbidden)
		return
	}
	now := time.Now().UTC()
	if s.DB != nil {
		s.logDB(w, r, jobID, in, now)
		return
	}
	s.mu.Lock()
	j, ok := s.jobs[jobID]
	if !ok {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	// Strict: a cancelled (or otherwise non-running) job no longer accepts
	// log lines. The runner logs cancellation locally before completing, so
	// no final flush grace window is needed.
	if !s.validActiveLease(j, in.RunnerID, in.LeaseToken, in.LeaseGeneration, now) {
		s.mu.Unlock()
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	s.logSeq++
	e := model.LogEntry{Seq: s.logSeq, RunID: j.RunID, JobID: j.ID, JobKey: j.Key, Step: in.Step, Line: in.Line, CreatedAt: time.Now().UTC()}
	s.mu.Unlock()
	if s.store != nil {
		if err := s.store.AppendLog(e); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// logDB validates the lease against the durable job row and appends the log
// line through the store. The seq is a wall-clock nanosecond timestamp so it
// stays monotonic across restarts and instances without a shared counter.
func (s *Server) logDB(w http.ResponseWriter, r *http.Request, jobID string, in LogLine, now time.Time) {
	ctx := r.Context()
	j, err := s.DB.GetJob(ctx, jobID)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !s.validActiveLease(j, in.RunnerID, in.LeaseToken, in.LeaseGeneration, now) {
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	e := model.LogEntry{Seq: time.Now().UnixNano(), RunID: j.RunID, JobID: j.ID, JobKey: j.Key, Step: in.Step, Line: in.Line, CreatedAt: time.Now().UTC()}
	if err := s.DB.AppendLog(ctx, e); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) complete(w http.ResponseWriter, r *http.Request) {
	_, span := s.startSpan(r.Context(), "server.complete")
	defer span.End()
	jobID := r.PathValue("id")
	var in Complete
	if !decode(w, r, &in) {
		return
	}
	if len(in.Error) > 64<<10 {
		http.Error(w, "error message exceeds 64 KiB", http.StatusBadRequest)
		return
	}
	if !s.verifyRunnerIdentity(r, in.RunnerID) {
		http.Error(w, "runner identity mismatch", http.StatusForbidden)
		return
	}
	hash, err := completionResultHash(in.Status, in.Error, in.Outputs)
	if err != nil {
		http.Error(w, "invalid outputs payload", http.StatusBadRequest)
		return
	}
	if s.Sched != nil {
		s.completeDB(w, r, jobID, in, hash)
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	j, ok := s.jobs[jobID]
	if !ok {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	// Completion is idempotent for the active generation. A previous
	// completion may already have made the job terminal and cleared its
	// lease; a duplicate delivery of the same result is acknowledged from
	// the receipt instead of being rejected.
	if !s.validActiveLease(j, in.RunnerID, in.LeaseToken, in.LeaseGeneration, now) {
		if rec, has := s.completions[completionReceiptKey(jobID, in.LeaseGeneration, in.RunnerID)]; has && rec.ResultHash == hash {
			s.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.mu.Unlock()
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	if !j.Status.Terminal() {
		st := in.Status
		if st != model.StatusSuccess && st != model.StatusFailure && st != model.StatusCancelled && st != model.StatusSkipped {
			st = model.StatusFailure
		}
		j.Status = st
		j.Error = in.Error
		if validJobOutputs(in.Outputs) {
			j.Outputs = cloneMap(in.Outputs)
		} else {
			j.Status = model.StatusFailure
			j.Error = "runner returned invalid or oversized job outputs"
		}
		// Required-artifact enforcement: a SUCCESSFUL completion must have
		// an artifact record for every contract entry with Required=true.
		if j.Status == model.StatusSuccess {
			if missing := s.requiredArtifactsMissingLocked(j); missing != "" {
				j.Status = model.StatusFailure
				j.Error = "required artifact " + missing + " missing"
				s.auditLocked("job.required_artifact_missing", in.RunnerID, j.RunID, j.ID, j.Error, map[string]string{"job": j.Key, "artifact": missing})
			}
		}
		j.FinishedAt = &now
	}
	if j.StartedAt != nil && j.FinishedAt != nil {
		s.metricObserve("kiwi_job_duration_seconds", j.FinishedAt.Sub(*j.StartedAt).Seconds(), nil)
	}
	// Usage accounting: cost/energy from the frozen lease-time rates and
	// the wall-clock duration, aggregated into the usage metrics and the
	// trailing-24h budget window.
	s.recordJobUsage(&j, now)
	// The lease is spent: clear all lease state so nothing can reuse it,
	// then dedupe future retries of this exact completion via the receipt.
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	s.recordCompletionReceiptLocked(jobID, in.LeaseGeneration, in.RunnerID, hash)
	runID := j.RunID
	s.jobs[jobID] = j
	if d, ok := s.deployments[jobID]; ok {
		d.Status = j.Status
		d.FinishedAt = j.FinishedAt
		s.deployments[jobID] = d
	}
	s.releaseRunnerLocked(in.RunnerID, j.ID, j.Status)
	s.auditLocked("job.completed", in.RunnerID, runID, j.ID, string(j.Status), map[string]string{"job": j.Key})
	s.scheduleStateLocked()
	s.refreshRunLocked(runID)
	// The completed job's run may itself be a wait=true downstream child of
	// another run: re-aggregate the parents.
	s.refreshDownstreamParentsLocked(runID)
	run := s.runs[runID]
	_ = s.persistLocked()
	s.mu.Unlock()
	// A successful job with a downstream declaration records the launch
	// claim and enqueues the dispatch intent (exactly-once via the claim).
	if j.Status == model.StatusSuccess {
		s.recordDownstreamIntents(context.Background(), j, run)
	}
	if run.Status.Terminal() {
		s.publishGitHubStatus(run)
	}
	w.WriteHeader(http.StatusNoContent)
}

// completeDB applies the completion through the scheduler's transactional
// CompleteJob. Idempotent replay is recognized from the durable receipt
// first (fast path), and again after a lease-conflict error in case the
// completion raced a concurrent replay.
func (s *Server) completeDB(w http.ResponseWriter, r *http.Request, jobID string, in Complete, hash string) {
	ctx := r.Context()
	if rec, has, err := s.DB.HasCompletionReceipt(ctx, jobID, in.LeaseGeneration, in.RunnerID); err != nil {
		http.Error(w, err.Error(), 500)
		return
	} else if has && rec.ResultHash == hash {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	j, err := s.DB.GetJob(ctx, jobID)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !s.validActiveLease(j, in.RunnerID, in.LeaseToken, in.LeaseGeneration, time.Now().UTC()) {
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	st := in.Status
	if st != model.StatusSuccess && st != model.StatusFailure && st != model.StatusCancelled && st != model.StatusSkipped {
		st = model.StatusFailure
	}
	errMsg := in.Error
	outputs := map[string]string{}
	if validJobOutputs(in.Outputs) {
		outputs = cloneMap(in.Outputs)
	} else {
		st = model.StatusFailure
		errMsg = "runner returned invalid or oversized job outputs"
	}
	if err := s.Sched.Complete(ctx, jobID, in.LeaseGeneration, in.RunnerID, st, errMsg, outputs, hash); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if rec, has, herr := s.DB.HasCompletionReceipt(ctx, jobID, in.LeaseGeneration, in.RunnerID); herr == nil && has && rec.ResultHash == hash {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	// Required-artifact enforcement (DB mode): a SUCCESSFUL completion must
	// have an artifact record for every contract entry with Required=true.
	// A missing required artifact flips the job to failure, emits the audit
	// event, and recomputes the run.
	if st == model.StatusSuccess {
		if missing, merr := s.requiredArtifactsMissingDB(ctx, j); merr == nil && missing != "" {
			if cur, gerr := s.DB.GetJob(ctx, jobID); gerr == nil && cur.Status == model.StatusSuccess {
				fin := time.Now().UTC()
				cur.Status = model.StatusFailure
				cur.Error = "required artifact " + missing + " missing"
				cur.FinishedAt = &fin
				cur.LeaseRunnerID = ""
				cur.LeaseTokenHash = nil
				cur.LeaseExpiresAt = nil
				if uerr := s.DB.UpdateJob(ctx, cur); uerr != nil {
					s.logError("complete: required-artifact failure persist failed", "job", jobID, "error", uerr.Error())
				}
				s.auditLocked("job.required_artifact_missing", in.RunnerID, j.RunID, jobID, cur.Error, map[string]string{"job": j.Key, "artifact": missing})
				s.recomputeRunDB(ctx, j.RunID)
			}
			st = model.StatusFailure
		} else if merr != nil {
			s.logError("complete: required-artifact check failed", "job", jobID, "error", merr.Error())
		}
	}
	s.finishDeploymentDB(ctx, j, st, time.Now().UTC())
	s.metricObserve("kiwi_job_duration_seconds", completionDurationSeconds(j), nil)
	// Usage accounting: cost/energy from the frozen lease-time rates, then
	// persisted back into the job payload for UsageStore.RecentUsage.
	if cur, gerr := s.DB.GetJob(ctx, jobID); gerr == nil {
		if cur.StartedAt != nil {
			finished := time.Now().UTC()
			if cur.FinishedAt != nil {
				finished = *cur.FinishedAt
			}
			s.recordJobUsage(&cur, finished)
			if uerr := s.DB.UpdateJob(ctx, cur); uerr != nil {
				s.logError("complete: persist job usage failed", "job", jobID, "error", uerr.Error())
			}
		}
		// A successful job with a downstream declaration records the launch
		// claim and enqueues the dispatch intent (exactly-once via the
		// claim row).
		if st == model.StatusSuccess {
			if run, gerr := s.DB.GetRun(ctx, j.RunID); gerr == nil {
				s.recordDownstreamIntents(ctx, cur, run)
			}
		}
	}
	// wait=true aggregation: the completed job's run may have downstream
	// children of its own, and may itself be a child of another run.
	s.adjustRunForChildrenDB(ctx, j.RunID)
	s.refreshDownstreamParentsDB(ctx, j.RunID)
	if run, gerr := s.DB.GetRun(ctx, j.RunID); gerr == nil && run.Status.Terminal() {
		s.publishGitHubStatus(run)
	}
	w.WriteHeader(http.StatusNoContent)
}

// completionDurationSeconds derives the wall-clock job duration at
// completion from the job's start/finish timestamps.
func completionDurationSeconds(j model.Job) float64 {
	if j.StartedAt == nil {
		return 0
	}
	finish := time.Now().UTC()
	if j.FinishedAt != nil {
		finish = *j.FinishedAt
	}
	return finish.Sub(*j.StartedAt).Seconds()
}

// recomputeRunDB recomputes one run's status from its jobs in DB mode,
// mirroring refreshRunLocked. Used when a server-side post-completion
// correction (required-artifact failure) changes a job state after the
// store's transactional recomputation already ran.
func (s *Server) recomputeRunDB(ctx context.Context, runID string) {
	run, err := s.DB.GetRun(ctx, runID)
	if err != nil || run.Status == model.StatusCancelled {
		return
	}
	jobs, err := s.DB.ListJobsByRun(ctx, runID)
	if err != nil {
		return
	}
	var total, terminal int
	var anyRunning, anyFailure, anyCancelled, anyWaiting bool
	var firstStart, lastFinish *time.Time
	for _, j := range jobs {
		total++
		if j.StartedAt != nil && (firstStart == nil || j.StartedAt.Before(*firstStart)) {
			t := *j.StartedAt
			firstStart = &t
		}
		if j.Status.Terminal() {
			terminal++
			if j.FinishedAt != nil && (lastFinish == nil || j.FinishedAt.After(*lastFinish)) {
				t := *j.FinishedAt
				lastFinish = &t
			}
		}
		switch j.Status {
		case model.StatusRunning:
			anyRunning = true
		case model.StatusFailure, model.StatusBlocked:
			anyFailure = true
		case model.StatusCancelled:
			anyCancelled = true
		case model.StatusWaitingApproval:
			anyWaiting = true
		}
	}
	if total == 0 {
		return
	}
	switch {
	case terminal == total:
		switch {
		case anyFailure:
			run.Status = model.StatusFailure
		case anyCancelled:
			run.Status = model.StatusCancelled
		default:
			run.Status = model.StatusSuccess
		}
		run.FinishedAt = lastFinish
		if run.FinishedAt == nil {
			n := time.Now().UTC()
			run.FinishedAt = &n
		}
	case anyRunning:
		run.Status = model.StatusRunning
	case anyWaiting:
		run.Status = model.StatusWaitingApproval
	default:
		run.Status = model.StatusQueued
	}
	if run.StartedAt == nil && firstStart != nil {
		run.StartedAt = firstStart
	}
	if err := s.DB.UpdateRunStatus(ctx, runID, run.Status, run.StartedAt, run.FinishedAt); err != nil {
		s.logError("complete: run recompute failed", "run", runID, "error", err.Error())
	}
}

// completionResultHash canonicalizes a completion payload so identical
// retries can be recognized. encoding/json sorts map keys, making outputs
// deterministic.
func completionResultHash(status model.Status, errMsg string, outputs map[string]string) (string, error) {
	outJSON, err := json.Marshal(outputs)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(status))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(errMsg))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(outJSON)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func completionReceiptKey(jobID string, generation int64, runnerID string) string {
	return jobID + "|" + strconv.FormatInt(generation, 10) + "|" + runnerID
}

// recordCompletionReceiptLocked keeps a bounded in-memory dedupe record.
// Receipts are intentionally not persisted in the filesystem snapshot; the
// PostgreSQL phase will store them durably. The bound keeps memory flat and
// evicts an arbitrary oldest entry when full.
func (s *Server) recordCompletionReceiptLocked(jobID string, generation int64, runnerID, resultHash string) {
	if len(s.completions) >= maxCompletionReceipts {
		for k := range s.completions {
			delete(s.completions, k)
			break
		}
	}
	s.completions[completionReceiptKey(jobID, generation, runnerID)] = model.CompletionReceipt{JobID: jobID, Generation: generation, RunnerID: runnerID, ResultHash: resultHash}
}

// hashLeaseToken computes the HMAC-SHA256 of a raw lease token under the
// server lease key. Only this digest is ever persisted or compared.
func hashLeaseToken(key []byte, raw string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(raw))
	return mac.Sum(nil)
}

// validActiveLease authorizes a runner action against a job's live lease:
// the job must be running, the lease unexpired, the runner and generation
// must match, and the presented token must hash to the stored digest.
func (s *Server) validActiveLease(j model.Job, runnerID, token string, generation int64, now time.Time) bool {
	if j.Status != model.StatusRunning || j.LeaseExpiresAt == nil || !j.LeaseExpiresAt.After(now) {
		return false
	}
	if j.LeaseRunnerID != runnerID || j.LeaseGeneration != generation || len(j.LeaseTokenHash) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(hashLeaseToken(s.leaseKey, token), j.LeaseTokenHash) == 1
}

// jobForLease returns the job addressed by jobID: from the store in DB mode
// (the in-memory map may be stale there) or from the in-memory map in dev
// mode. ErrNotFound means the job does not exist.
func (s *Server) jobForLease(ctx context.Context, jobID string) (model.Job, error) {
	if s.DB != nil {
		return s.DB.GetJob(ctx, jobID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok {
		return model.Job{}, storage.ErrNotFound
	}
	return j, nil
}

func (s *Server) approveJob(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	actor := actorFrom(r)
	if s.DB != nil {
		s.approveJobDB(w, r, jobID, actor)
		return
	}
	s.mu.Lock()
	j, ok := s.jobs[jobID]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !s.requireAction(w, r, auth.ActionApprove, canonicalRepoForJob(j), false) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok = s.jobs[jobID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !j.ApprovalRequired {
		http.Error(w, "job does not require approval", http.StatusConflict)
		return
	}
	if j.Status.Terminal() {
		http.Error(w, "job is already terminal", http.StatusConflict)
		return
	}
	j.ApprovedBy = actor
	if j.Status == model.StatusWaitingApproval {
		j.Status = model.StatusQueued
	}
	s.observeApprovalWait(&j)
	s.jobs[jobID] = j
	s.auditLocked("job.approved", actor, j.RunID, j.ID, "environment approved", map[string]string{"environment": j.Environment})
	s.scheduleStateLocked()
	s.refreshRunLocked(j.RunID)
	_ = s.persistLocked()
	writeJSON(w, http.StatusOK, redactJob(j))
}

// approveJobDB approves an environment-gated job durably: the job row is the
// source of truth, and the update goes through the store.
func (s *Server) approveJobDB(w http.ResponseWriter, r *http.Request, jobID, actor string) {
	ctx := r.Context()
	j, err := s.DB.GetJob(ctx, jobID)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !s.requireAction(w, r, auth.ActionApprove, canonicalRepoForJob(j), false) {
		return
	}
	if !j.ApprovalRequired {
		http.Error(w, "job does not require approval", http.StatusConflict)
		return
	}
	if j.Status.Terminal() {
		http.Error(w, "job is already terminal", http.StatusConflict)
		return
	}
	j.ApprovedBy = actor
	if j.Status == model.StatusWaitingApproval {
		j.Status = model.StatusQueued
	}
	s.observeApprovalWait(&j)
	if err := s.DB.UpdateJob(ctx, j); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.auditLocked("job.approved", actor, j.RunID, j.ID, "environment approved", map[string]string{"environment": j.Environment})
	writeJSON(w, http.StatusOK, redactJob(j))
}

// observeApprovalWait records how long an approval-gated job waited from
// entering the waiting state to approval and clears the marker.
func (s *Server) observeApprovalWait(j *model.Job) {
	if j.WaitingSince == nil {
		return
	}
	wait := time.Since(*j.WaitingSince).Seconds()
	s.metricObserve("kiwi_approval_wait_seconds", wait, nil)
	s.metricObserve("kiwi_environment_wait_seconds", wait, nil)
	j.WaitingSince = nil
}

func (s *Server) rerunRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.DB != nil {
		s.rerunRunDB(w, r, id)
		return
	}
	s.mu.Lock()
	old, ok := s.runs[id]
	var pipelineText string
	if ok {
		for _, j := range s.jobs {
			if j.RunID == id {
				pipelineText = j.Pipeline
				break
			}
		}
	}
	s.mu.Unlock()
	if !ok || pipelineText == "" {
		http.NotFound(w, r)
		return
	}
	if !s.requireAction(w, r, auth.ActionRerun, canonicalRepoForRun(old), false) {
		return
	}
	meta := cloneMap(old.Metadata)
	if meta == nil {
		meta = map[string]string{}
	}
	// A rerun is a new webhook-independent submission: drop the forge
	// delivery IDs so it cannot be confused with the original delivery.
	for _, key := range []string{"github_delivery", "gitlab_delivery", "forgejo_delivery"} {
		delete(meta, key)
	}
	meta["rerun_of"] = id
	run, err := s.enqueue(SubmitRun{RepoURL: old.Repo, RepoFullName: old.RepoFullName, Ref: old.Ref, SHA: old.SHA, Event: old.Event, Pipeline: pipelineText, Trusted: old.Trusted, Metadata: meta})
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

// rerunRunDB reads the previous run and its pipeline text from the store,
// then enqueues through the DB path.
func (s *Server) rerunRunDB(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	old, err := s.DB.GetRun(ctx, id)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	jobs, err := s.DB.ListJobsByRun(ctx, id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var pipelineText string
	for _, j := range jobs {
		if j.Pipeline != "" {
			pipelineText = j.Pipeline
			break
		}
	}
	if pipelineText == "" {
		http.NotFound(w, r)
		return
	}
	if !s.requireAction(w, r, auth.ActionRerun, canonicalRepoForRun(old), false) {
		return
	}
	meta := cloneMap(old.Metadata)
	if meta == nil {
		meta = map[string]string{}
	}
	for _, key := range []string{"github_delivery", "gitlab_delivery", "forgejo_delivery"} {
		delete(meta, key)
	}
	meta["rerun_of"] = id
	run, err := s.enqueue(SubmitRun{RepoURL: old.Repo, RepoFullName: old.RepoFullName, Ref: old.Ref, SHA: old.SHA, Event: old.Event, Pipeline: pipelineText, Trusted: old.Trusted, Metadata: meta})
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	actor := actorFrom(r)
	if s.Sched != nil {
		s.cancelRunDB(w, r, id, actor)
		return
	}
	s.mu.Lock()
	run, ok := s.runs[id]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !s.requireAction(w, r, auth.ActionCancel, canonicalRepoForRun(run), false) {
		return
	}
	s.mu.Lock()
	if _, ok := s.runs[id]; !ok {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	s.cancelRunLocked(id, "cancelled by "+actor, actor)
	run = s.runs[id]
	_ = s.persistLocked()
	s.mu.Unlock()
	s.publishGitHubStatus(run)
	writeJSON(w, http.StatusOK, run)
}

// cancelRunDB cancels through the store's transactional CancelRunJobs and
// emits the audit event through the DB audit funnel.
func (s *Server) cancelRunDB(w http.ResponseWriter, r *http.Request, id, actor string) {
	ctx := r.Context()
	run, err := s.DB.GetRun(ctx, id)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !s.requireAction(w, r, auth.ActionCancel, canonicalRepoForRun(run), false) {
		return
	}
	reason := "cancelled by " + actor
	if err := s.Sched.CancelRun(ctx, id, reason); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.auditLocked("run.cancelled", actor, id, "", reason, nil)
	if cur, gerr := s.DB.GetRun(ctx, id); gerr == nil {
		run = cur
	}
	s.publishGitHubStatus(run)
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) cancelRunLocked(runID, reason, actor string) {
	now := time.Now().UTC()
	for id, j := range s.jobs {
		if j.RunID != runID || j.Status.Terminal() {
			continue
		}
		j.Status = model.StatusCancelled
		j.Error = reason
		j.FinishedAt = &now
		// Cancellation immediately voids the lease so the runner's next
		// heartbeat learns the job is cancelled and any stale token is dead.
		j.LeaseRunnerID = ""
		j.LeaseTokenHash = nil
		j.LeaseExpiresAt = nil
		s.jobs[id] = j
	}
	run, ok := s.runs[runID]
	if ok && !run.Status.Terminal() {
		run.Status = model.StatusCancelled
		run.FinishedAt = &now
		s.runs[runID] = run
	}
	// A cancelled run may be a wait=true downstream child of another run:
	// re-aggregate the parents.
	s.refreshDownstreamParentsLocked(runID)
	s.auditLocked("run.cancelled", actor, runID, "", reason, nil)
}

func (s *Server) scheduleStateLocked() {
	if s.Sched != nil {
		// DB mode: dependency/approval recomputation happens in SQL
		// (CompleteJob) and in the scheduler's recovery pass; the memory
		// maps are not authoritative.
		return
	}
	changed := true
	for changed {
		changed = false
		for id, j := range s.jobs {
			if j.Status != model.StatusQueued && j.Status != model.StatusWaitingApproval {
				continue
			}
			ready, depStatus := dependencyOutcomeLocked(j, s.jobs)
			if !ready {
				continue
			}
			j.DependencyStatus = depStatus
			if depStatus != model.StatusSuccess && !scheduler.ConditionAllows(j.Condition, depStatus) {
				now := time.Now().UTC()
				j.Status = model.StatusBlocked
				j.Error = "dependency failed"
				j.FinishedAt = &now
				s.jobs[id] = j
				changed = true
				continue
			}
			s.jobs[id] = j
			if len(j.EnvironmentBranches) > 0 && !environmentBranchAllowed(s.runs[j.RunID].Ref, j.EnvironmentBranches) {
				now := time.Now().UTC()
				j.Status = model.StatusBlocked
				j.Error = "ref is not allowed to deploy to environment " + j.Environment
				j.FinishedAt = &now
				s.jobs[id] = j
				changed = true
				continue
			}
			if j.ApprovalRequired && j.ApprovedBy == "" {
				if j.Status != model.StatusWaitingApproval {
					j.Status = model.StatusWaitingApproval
					if j.WaitingSince == nil {
						w := time.Now().UTC()
						j.WaitingSince = &w
					}
					s.jobs[id] = j
					changed = true
				}
			} else if j.Status == model.StatusWaitingApproval {
				j.Status = model.StatusQueued
				s.jobs[id] = j
				changed = true
			}
		}
	}
	for runID := range s.runs {
		s.refreshRunLocked(runID)
	}
}

// applyQueueReasonsLocked annotates every waiting job with the queue reason
// explaining why it is not leasable by runner ri. Only the reasons the
// spec models are assigned: dependency gating, label mismatch, environment
// capacity and pending approval.
func (s *Server) applyQueueReasonsLocked(ri model.Runner) {
	for id, j := range s.jobs {
		reason := queue.None
		switch j.Status {
		case model.StatusWaitingApproval:
			reason = queue.WaitingApproval
		case model.StatusQueued:
			switch {
			case !depsReadyLocked(j, s.jobs):
				reason = queue.WaitingDependency
			case !labelsSatisfied(ri.Labels, j.RequiredLabels):
				reason = queue.NoCompatibleRunner
			case !regionSatisfied(ri.Region, j.PlacementRegions):
				reason = queue.RegionUnavailable
			case environmentAtCapacityScoped(j, s.jobs):
				reason = queue.EnvironmentLocked
			}
		}
		if j.QueueReason != string(reason) {
			j.QueueReason = string(reason)
			s.jobs[id] = j
		}
	}
}

// dependencyOutcomeLocked wraps the scheduler's unified DependencyOutcome
// over the in-memory job map (dev mode).
func dependencyOutcomeLocked(j model.Job, jobs map[string]model.Job) (bool, model.Status) {
	return scheduler.DependencyOutcome(j.Needs, nil, func(id string) (model.Status, bool) {
		d, ok := jobs[id]
		return d.Status, ok
	})
}

// depsReadyLocked reports whether a queued job's dependencies allow it to be
// leased. Condition evaluation uses the unified evaluator so the dev-mode
// gate and the SQL scheduler decide identically.
func depsReadyLocked(j model.Job, jobs map[string]model.Job) bool {
	ready, status := dependencyOutcomeLocked(j, jobs)
	return ready && (status == model.StatusSuccess || scheduler.ConditionAllows(j.Condition, status))
}

func (s *Server) refreshRunLocked(runID string) {
	if s.Sched != nil {
		// DB mode: run recomputation happens in SQL (CompleteJob) and in
		// the scheduler's recovery pass.
		return
	}
	run, ok := s.runs[runID]
	if !ok {
		return
	}
	var total, terminal int
	var anyRunning, anyFailure, anyCancelled, anyWaiting bool
	var firstStart *time.Time
	var lastFinish *time.Time
	for _, j := range s.jobs {
		if j.RunID != runID {
			continue
		}
		total++
		if j.StartedAt != nil && (firstStart == nil || j.StartedAt.Before(*firstStart)) {
			t := *j.StartedAt
			firstStart = &t
		}
		if j.Status.Terminal() {
			terminal++
			if j.FinishedAt != nil && (lastFinish == nil || j.FinishedAt.After(*lastFinish)) {
				t := *j.FinishedAt
				lastFinish = &t
			}
		}
		if j.Status == model.StatusRunning {
			anyRunning = true
		}
		if j.Status == model.StatusFailure || j.Status == model.StatusBlocked {
			anyFailure = true
		}
		if j.Status == model.StatusCancelled {
			anyCancelled = true
		}
		if j.Status == model.StatusWaitingApproval {
			anyWaiting = true
		}
	}
	if total == 0 {
		return
	}
	if run.Status == model.StatusCancelled {
		return
	}
	switch {
	case terminal == total:
		if anyFailure {
			run.Status = model.StatusFailure
		} else if anyCancelled {
			run.Status = model.StatusCancelled
		} else {
			run.Status = model.StatusSuccess
		}
		run.FinishedAt = lastFinish
		if run.FinishedAt == nil {
			n := time.Now().UTC()
			run.FinishedAt = &n
		}
	case anyRunning:
		run.Status = model.StatusRunning
	case anyWaiting:
		run.Status = model.StatusWaitingApproval
	default:
		run.Status = model.StatusQueued
	}
	if run.StartedAt == nil && firstStart != nil {
		run.StartedAt = firstStart
	}
	// wait=true downstream aggregation: a run that waits on child runs stays
	// open until the children finish and inherits their failures.
	s.applyDownstreamChildrenLocked(runID, &run)
	s.runs[runID] = run
}

func (s *Server) recoverLeasesLocked(now time.Time, startup bool) {
	if s.Sched != nil {
		// DB mode: expired-lease recovery is the leader's job and runs
		// through Sched.RecoverExpired in Maintain.
		return
	}
	_ = startup // Signature kept for call-site stability; startup no longer forces expiry: unexpired leases survive restart.
	expirations := 0
	lost := 0
	for id, j := range s.jobs {
		if j.Status != model.StatusRunning {
			continue
		}
		expired := j.LeaseExpiresAt == nil || !j.LeaseExpiresAt.After(now)
		if !expired {
			continue
		}
		expirations++
		runnerID := j.LeaseRunnerID
		if j.Attempts <= j.MaxInfraRetries {
			j.Status = model.StatusQueued
			j.Error = "runner lease expired; retrying"
			j.LeaseRunnerID = ""
			j.LeaseTokenHash = nil
			j.LeaseExpiresAt = nil
			s.auditLocked("job.lease_expired", "scheduler", j.RunID, j.ID, "job requeued after lost runner", map[string]string{"job": j.Key})
		} else {
			lost++
			j.Status = model.StatusFailure
			j.Error = "runner lease expired and infrastructure retry budget exhausted"
			j.FinishedAt = &now
			j.LeaseRunnerID = ""
			j.LeaseTokenHash = nil
			j.LeaseExpiresAt = nil
			s.auditLocked("job.lost_runner", "scheduler", j.RunID, j.ID, j.Error, map[string]string{"job": j.Key})
		}
		s.jobs[id] = j
		s.releaseRunnerLocked(runnerID, j.ID, model.StatusFailure)
	}
	s.metricAdd("kiwi_lease_expirations_total", float64(expirations), nil)
	s.metricAdd("kiwi_lost_runners_total", float64(lost), nil)
	s.scheduleStateLocked()
}

func (s *Server) releaseRunnerLocked(runnerID, jobID string, status model.Status) {
	ri, ok := s.runners[runnerID]
	if !ok {
		return
	}
	ri.ActiveJobs = removeString(ri.ActiveJobs, jobID)
	if ri.Capacity < 1 {
		ri.Capacity = 1
	}
	ri.Busy = len(ri.ActiveJobs) >= ri.Capacity
	ri.CurrentJob = ""
	if len(ri.ActiveJobs) > 0 {
		ri.CurrentJob = ri.ActiveJobs[0]
	}
	ri.LastSeen = time.Now().UTC()
	if status == model.StatusSuccess {
		ri.Completed++
	} else if status == model.StatusFailure {
		ri.Failed++
	}
	s.runners[runnerID] = ri
}

// auditLocked is the single audit funnel. In DB mode events go through the
// store (AppendAudit); failures are logged, never silently dropped. In dev
// mode events are appended to the filesystem repository when one is attached.
func (s *Server) auditLocked(action, actor, runID, jobID, msg string, meta map[string]string) {
	if s.store == nil && s.DB == nil {
		return
	}
	id, err := newID()
	if err != nil {
		s.logError("audit: dropping event", "action", action, "error", err.Error())
		return
	}
	e := model.AuditEvent{ID: id, Action: action, Actor: actor, RunID: runID, JobID: jobID, Message: msg, Metadata: meta, CreatedAt: time.Now().UTC()}
	if s.DB != nil {
		if err := s.DB.AppendAudit(context.Background(), e); err != nil {
			s.logError("audit: append failed", "action", action, "error", err.Error())
		}
		return
	}
	_ = s.store.AppendAudit(e)
}
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	if s.DB != nil {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		v, err := s.DB.ReadAudit(r.Context(), limit)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 200, v)
		return
	}
	if s.store == nil {
		writeJSON(w, 200, []model.AuditEvent{})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	v, err := s.store.ReadAudit(limit)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) persistLocked() error {
	if s.store == nil || s.DB != nil {
		// DB mode: the SQL store is the source of truth; the filesystem
		// snapshot must not be overwritten with stale memory maps.
		return nil
	}
	return s.store.Save(storage.Snapshot{Version: 1, Runs: s.runs, Jobs: s.jobs, Runners: s.runners, Artifacts: s.artifacts, Reports: s.reports, DownstreamLinks: s.downstreamLinks})
}
func (s *Server) leaseDuration() time.Duration {
	if s.LeaseDuration <= 0 {
		return defaultLeaseDuration
	}
	return s.LeaseDuration
}

func environmentBranchAllowed(ref string, patterns []string) bool {
	branch := strings.TrimPrefix(strings.TrimPrefix(ref, "refs/heads/"), "refs/")
	for _, ptn := range patterns {
		ptn = strings.TrimSpace(ptn)
		if ptn == "" {
			continue
		}
		if ptn == branch || ptn == ref {
			return true
		}
		if ok, _ := path.Match(ptn, branch); ok {
			return true
		}
	}
	return false
}

func labelsSatisfied(have, need []string) bool {
	m := map[string]bool{}
	for _, x := range have {
		m[x] = true
	}
	for _, x := range need {
		if !m[x] {
			return false
		}
	}
	return true
}

// regionSatisfied reports whether a runner in the given region may take a
// job: a job with placement regions only leases to a runner whose region is
// in the set. Runners without a region and jobs without region constraints
// are unaffected (label matching is unchanged).
func regionSatisfied(region string, allowed []string) bool {
	if len(allowed) == 0 || region == "" {
		return true
	}
	for _, a := range allowed {
		if a == region {
			return true
		}
	}
	return false
}

// environmentAtCapacityScoped is the scheduling-time environment concurrency
// gate for in-memory mode. The concurrency key is repo+environment: an
// environment name is not a global lock across repositories. The SQL lease
// pass applies the identical repo-scoped rule via
// Store.ListJobsByEnvironment inside scheduler.Lease.
func environmentAtCapacityScoped(j model.Job, jobs map[string]model.Job) bool {
	if j.Environment == "" || j.EnvironmentConcurrency <= 0 {
		return false
	}
	active := 0
	for _, other := range jobs {
		if other.ID == j.ID || other.Status != model.StatusRunning {
			continue
		}
		if other.Environment != j.Environment || other.RepoURL != j.RepoURL {
			continue
		}
		active++
		if active >= j.EnvironmentConcurrency {
			return true
		}
	}
	return false
}
func validJobOutputs(in map[string]string) bool {
	if len(in) > 256 {
		return false
	}
	total := 0
	for k, v := range in {
		if len(k) == 0 || len(k) > 128 || len(v) > 64<<10 {
			return false
		}
		total += len(k) + len(v)
		if total > 1<<20 {
			return false
		}
	}
	return true
}

func appendUnique(in []string, v string) []string {
	for _, x := range in {
		if x == v {
			return in
		}
	}
	return append(in, v)
}

func removeString(in []string, v string) []string {
	out := in[:0]
	for _, x := range in {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	return append([]string(nil), in...)
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	if s.DB != nil {
		s.metricsDB(w, r)
	} else {
		s.metricsMemory(w, r)
	}
	// The process-wide registry (counters/histograms/gauges) renders after
	// the state gauges so a scrape always sees both surfaces.
	if s.Metrics != nil {
		s.Metrics.WritePrometheus(w)
	}
}

// MetricsHandler returns a handler serving the Prometheus metrics surface.
// The app wiring mounts it on the dedicated metrics listener
// (observability.metrics_listen); the main listener keeps its /metrics
// route.
func (s *Server) MetricsHandler() http.Handler {
	return http.HandlerFunc(s.metrics)
}

// metricsMemory renders the state gauges from the in-memory maps.
func (s *Server) metricsMemory(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts := map[model.Status]int{}
	for _, r := range s.runs {
		counts[r.Status]++
	}
	jobs := map[model.Status]int{}
	for _, j := range s.jobs {
		jobs[j.Status]++
	}
	busy := 0
	capacity := 0
	for _, r := range s.runners {
		busy += len(r.ActiveJobs)
		c := r.Capacity
		if c < 1 {
			c = 1
		}
		capacity += c
	}
	queueReasons := map[string]int{}
	for _, j := range s.jobs {
		if j.QueueReason != "" && (j.Status == model.StatusQueued || j.Status == model.StatusWaitingApproval) {
			queueReasons[j.QueueReason]++
		}
	}
	fmt.Fprintln(w, "# HELP kiwi_runs Number of CI runs by status")
	fmt.Fprintln(w, "# TYPE kiwi_runs gauge")
	for st, n := range counts {
		fmt.Fprintf(w, "kiwi_runs{status=%q} %d\n", st, n)
	}
	fmt.Fprintln(w, "# HELP kiwi_jobs Number of CI jobs by status")
	fmt.Fprintln(w, "# TYPE kiwi_jobs gauge")
	for st, n := range jobs {
		fmt.Fprintf(w, "kiwi_jobs{status=%q} %d\n", st, n)
	}
	fmt.Fprintln(w, "# HELP kiwi_jobs_queue_reason Number of queued jobs by queue reason")
	fmt.Fprintln(w, "# TYPE kiwi_jobs_queue_reason gauge")
	for reason, n := range queueReasons {
		fmt.Fprintf(w, "kiwi_jobs_queue_reason{reason=%q} %d\n", reason, n)
	}
	fmt.Fprintf(w, "kiwi_runners %d\nkiwi_runner_slots %d\nkiwi_runner_slots_busy %d\n", len(s.runners), capacity, busy)
	if capacity > 0 {
		s.metricSet("kiwi_runner_saturation", float64(busy)/float64(capacity), nil)
	}
}

// metricsDB serves the same gauges from the SQL store, bounded to the most
// recent runs so a scrape cannot degenerate into a full-table scan.
func (s *Server) metricsDB(w http.ResponseWriter, r *http.Request) {
	runs, err := s.DB.ListRuns(r.Context(), 100)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	counts := map[model.Status]int{}
	jobs := map[model.Status]int{}
	for _, run := range runs {
		counts[run.Status]++
		if run.Status.Terminal() {
			continue
		}
		runJobs, err := s.DB.ListJobsByRun(r.Context(), run.ID)
		if err != nil {
			continue
		}
		for _, j := range runJobs {
			jobs[j.Status]++
		}
	}
	busy := 0
	capacity := 0
	allRunners, err := s.DB.ListRunners(r.Context())
	if err != nil {
		allRunners = nil
	}
	for _, ri := range allRunners {
		busy += len(ri.ActiveJobs)
		c := ri.Capacity
		if c < 1 {
			c = 1
		}
		capacity += c
	}
	fmt.Fprintln(w, "# HELP kiwi_runs Number of CI runs by status")
	fmt.Fprintln(w, "# TYPE kiwi_runs gauge")
	for st, n := range counts {
		fmt.Fprintf(w, "kiwi_runs{status=%q} %d\n", st, n)
	}
	fmt.Fprintln(w, "# HELP kiwi_jobs Number of CI jobs by status")
	fmt.Fprintln(w, "# TYPE kiwi_jobs gauge")
	for st, n := range jobs {
		fmt.Fprintf(w, "kiwi_jobs{status=%q} %d\n", st, n)
	}
	fmt.Fprintf(w, "kiwi_runners %d\nkiwi_runner_slots %d\nkiwi_runner_slots_busy %d\n", len(allRunners), capacity, busy)
	if capacity > 0 {
		s.metricSet("kiwi_runner_saturation", float64(busy)/float64(capacity), nil)
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeLimit(w, r, v, 8<<20)
}

// decodeLimit strictly decodes one JSON object from the request body,
// rejecting unknown fields and trailing data. Endpoints with tighter
// integrity budgets pass a smaller max.
func decodeLimit(w http.ResponseWriter, r *http.Request, v any, max int64) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "bad json: trailing data", http.StatusBadRequest)
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// newID returns a 128-bit crypto/rand identifier hex-encoded.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// requestID is the outermost middleware: it accepts a client-supplied
// X-Kiwi-Request-ID (bounded, safe charset) or mints one, echoes it on the
// response, and stores it in the request context for error logging.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Kiwi-Request-ID")
		if !validRequestID(id) {
			gen, err := newID()
			if err != nil {
				// Entropy failure is unrecoverable; leave the ID empty so
				// error responses still render.
				gen = ""
			}
			id = gen
		}
		w.Header().Set("X-Kiwi-Request-ID", id)
		r = r.WithContext(context.WithValue(r.Context(), requestIDContextKey{}, id))
		next.ServeHTTP(w, r)
	})
}

type requestIDContextKey struct{}

func requestIDFrom(r *http.Request) string {
	if id, ok := r.Context().Value(requestIDContextKey{}).(string); ok {
		return id
	}
	return ""
}

func validRequestID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Flush forwards stream flushes (SSE) to the underlying writer.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// statusLogger logs server-side errors (500+) with the request ID through
// the structured operational logger.
func (s *Server) statusLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status >= 500 {
			s.logError("request failed", "request_id", requestIDFrom(r), "method", r.Method, "path", r.URL.Path, "status", rec.status)
		}
	})
}

// recoverer converts panics into opaque 500 responses: the panic text and
// stack stay in the server log and never reach clients. The package-level
// function logs via the standard logger; Server.recoverer routes through
// the structured operational logger.
func recoverer(next http.Handler) http.Handler {
	return recovererWith(next, func(id, method, path string, x any, stack string) {
		log.Printf("panic serving %s %s (request_id=%s): %v\n%s", method, path, id, x, stack)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return recovererWith(next, func(id, method, path string, x any, stack string) {
		s.logError("panic serving request", "request_id", id, "method", method, "path", path, "panic", x, "stack", stack)
	})
}

func recovererWith(next http.Handler, onPanic func(id, method, path string, x any, stack string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if x := recover(); x != nil {
				id := requestIDFrom(r)
				onPanic(id, r.Method, r.URL.Path, x, string(debug.Stack()))
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error", "request_id": id})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Maintain performs control-plane housekeeping independent of runner polling.
// It recovers expired leases, advances dependency/approval state, persists the
// result, and publishes forge status changes caused by lost runners.
func (s *Server) Maintain(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case tick := <-ticker.C:
			loopStart := time.Now()
			if s.Sched != nil {
				s.maintainDB(ctx, tick.UTC())
				if s.leader {
					s.fireDueSchedules(ctx, tick.UTC())
				}
				s.metricObserve("kiwi_scheduler_loop_duration_seconds", time.Since(loopStart).Seconds(), nil)
				continue
			}
			s.mu.Lock()
			before := map[string]model.Status{}
			for id, r := range s.runs {
				before[id] = r.Status
			}
			s.recoverLeasesLocked(tick.UTC(), false)
			_ = s.persistLocked()
			var changed []model.Run
			for id, r := range s.runs {
				if before[id] != r.Status {
					changed = append(changed, r)
				}
			}
			s.mu.Unlock()
			for _, r := range changed {
				s.publishGitHubStatus(r)
			}
			s.GC(ctx, tick.UTC())
			s.flushOutbox()
			s.fireDueSchedules(ctx, tick.UTC())
			s.metricObserve("kiwi_scheduler_loop_duration_seconds", time.Since(loopStart).Seconds(), nil)
		}
	}
}

// maintainDB is the DB-mode housekeeping tick. The leader recovers expired
// leases, flushes the outbox, and garbage-collects memory artifacts (artifact
// bytes still live on the local filesystem, so DB-mode GC covers memory
// records only). A standby serves reads and polls the leadership claim; on
// promotion it runs RecoverExpired once so leases orphaned by the previous
// leader are reclaimed immediately.
func (s *Server) maintainDB(ctx context.Context, now time.Time) {
	if !s.leader {
		if !s.Sched.IsLeader(ctx) {
			return
		}
		s.leader = true
		s.logInfo("promoted to leader", "key", s.LeaderKey)
		if err := s.Sched.RecoverExpired(ctx, now); err != nil {
			s.logError("post-promotion recovery", "error", err.Error())
		}
		return
	}
	if !s.Sched.IsLeader(ctx) {
		s.leader = false
		s.logInfo("demoted to standby", "key", s.LeaderKey)
		return
	}
	if err := s.Sched.RecoverExpired(ctx, now); err != nil && !errors.Is(err, scheduler.ErrNotLeader) {
		s.logError("lease recovery", "error", err.Error())
	}
	s.recoverDownstreamReservations(ctx, now)
	s.flushOutbox()
	s.GC(ctx, now)
}
