package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/giturl"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	v1 "github.com/Bel-Consulting-OU/kiwi-ci/internal/api/v1"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/artifact"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

const (
	envAllowInsecureClone = "KIWI_ALLOW_INSECURE_CLONE"
	envAllowedSSHHosts    = "KIWI_GIT_ALLOWED_SSH_HOSTS"
	envAllowedHTTPSHosts  = "KIWI_GIT_ALLOWED_HTTPS_HOSTS"
	envRunnerAllowInsec   = "KIWI_RUNNER_ALLOW_INSECURE"
	envRunnerRegion       = "KIWI_RUNNER_REGION"
	// runnerProtocol is the runner API protocol version spoken by this
	// runner; it must overlap the control plane's ProtocolMin/Max.
	runnerProtocol = 3
	// gcInterval is how often the runner reaps stale runtime resources.
	gcInterval = time.Hour
	// gcOlderThan is the executor.GC staleness window.
	gcOlderThan = 24 * time.Hour
	// stagingMaintenanceInterval is how often the runner retries dependency
	// staging cleanup debt. It is deliberately far shorter than gcInterval:
	// with the conservative default staging budget (one maximum artifact), a
	// spool whose removal failed keeps its bytes charged and would otherwise
	// wedge every future maximum-size restore for the life of the runner.
	stagingMaintenanceInterval = 30 * time.Second
	// stagingCloseGrace bounds the orderly staging ownership hand-off at the
	// very end of Run, after every owned goroutine has joined. If cleanup
	// debt cannot be reclaimed (or the lock cannot be released) within this
	// bound, ownership is deliberately retained: process exit drops the
	// lock, and an in-process successor reuses the same ledger.
	stagingCloseGrace = 5 * time.Second
	// defaultCacheMaxBytes/defaultCacheMaxEntries/defaultCacheMaxAge bound
	// the runner-local cache tree when the operator configures nothing: a
	// persistent cache whose entries are never evicted is a host-disk
	// exhaustion primitive for any pipeline that rotates its logical keys.
	// 32 GiB / 4096 entries / 14 days fit typical runner disks while keeping
	// hot entries; operators tune them with the cache_max_* flags.
	defaultCacheMaxBytes   = 32 << 30
	defaultCacheMaxEntries = 4096
	defaultCacheMaxAge     = 14 * 24 * time.Hour
	// cachePruneInterval is the dedicated local-cache pruning cadence. It is
	// deliberately independent of the hourly runtime GC: eviction must keep
	// up with cache writes, not with container/network reaping.
	cachePruneInterval = 10 * time.Minute
	// defaultFinalizeTimeout bounds post-job finalization (test-report
	// delivery, snapshot upload) once the executor has returned. Job-scoped
	// work inside the executor stays under the declared job deadline; this is
	// the separate, explicitly bounded grace for the delivery that follows
	// it, so a job can never hold a runner slot indefinitely after its lease
	// stopped being renewed.
	defaultFinalizeTimeout = 2 * time.Minute
)

// completionGrace bounds one terminal completion delivery: it is derived from
// the runner/client context WITHOUT cancellation (a timed-out job still gets
// to report its timeout) but with its own wall-clock bound, so a wedged
// control plane cannot pin the runner slot. A var so tests can shrink it.
var completionGrace = 30 * time.Second

// ErrRunnerDisabledOrRevoked reports that the control plane has disabled
// this runner or revoked its certificate: the runner must be re-enrolled
// with fresh credentials and must not loop re-registering.
var ErrRunnerDisabledOrRevoked = errors.New("runner disabled or certificate revoked; re-enroll required")

// RunnerVersion is the software version reported at registration and can be
// overridden at build time via -ldflags.
var RunnerVersion = "dev"

// backgroundDrainGrace bounds how long Run waits for work it spawned
// (executes and maintenance passes) to finish after its context is cancelled
// or the drain completes. Run must not return while spawned work can still
// touch runner state; the bound keeps a job or probe that ignores
// cancellation from pinning process shutdown forever. A var so tests can
// shrink it.
var backgroundDrainGrace = 30 * time.Second

// heartbeatExiting, when non-nil, runs as the heartbeat goroutine is about to
// exit. It is a test seam for the join contract: holding it proves execute
// does not return before its heartbeat has actually stopped.
var heartbeatExiting func()

// heartbeatShutdownGrace bounds execute's wait for its heartbeat goroutine
// after the task finishes; the goroutine is signaled with close(done)+cancel
// and should return immediately, so the bound is a diagnostic backstop for
// the lifecycle contract, not a routine wait.
var heartbeatShutdownGrace = 5 * time.Second

// Seams over the standard library used by the runner. Production behavior is
// unchanged; they let checked failure branches be exercised deterministically:
// randReader covers identifier-generation failures (matching the
// internal/provenance randReader seam), and enrollTLSConfig covers the
// enrollment TLS configuration so a hermetic test can reach the server-CA
// fallback without a system-trusted listener certificate.
var (
	randReader      io.Reader = rand.Reader
	enrollTLSConfig           = runnerpki.TLSClientConfig
	// reportf writes runner maintenance reports. It is a seam so tests can
	// observe a report from the detached GC goroutine without racing the
	// process-wide stdout.
	reportf = fmt.Printf
	// removeJobWorkspace deletes the per-job workspace root after the job.
	// os.MkdirTemp creates the root 0700 and runner-owned; the container
	// backend provisions and restores the tree for hardened rootful
	// workloads. A seam so the docker integration test can observe the
	// post-run host-side state instead of racing the cleanup.
	removeJobWorkspace = os.RemoveAll
	// installWorkspaceDiskQuota installs the OS-level hard workspace bound
	// (XFS project quota, capability-probed and fail-closed) that execute
	// owns: it runs BEFORE the workspace is populated, so an untrusted
	// repository cannot fill the runner's disk during checkout or
	// dependency restore. A seam so tests can drive the quota lifecycle
	// without a quota-capable host filesystem.
	installWorkspaceDiskQuota = executor.WorkspaceDiskQuotaSetup
	// executorOptionsSeam observes the executor options derived for a job
	// immediately before it runs. It is a test seam: it lets tests assert
	// the derived resource bounds (WorkspaceMaxBytes) without executing the
	// job on a real backend. Production leaves it nil.
	executorOptionsSeam func(executor.Options)
	// closeStagingBudget is a seam over staging.Budget.CloseWithContext so the
	// hand-off failure branch (ownership release failed, and the budget is
	// finalized/CLOSING rather than open) can be exercised: the runner must
	// then DROP the ledger pointer instead of keeping a closed budget
	// installed for a restart to "reuse".
	closeStagingBudget = (*staging.Budget).CloseWithContext
)

// Client policy seams. Ordinary control-plane calls (register/next/heartbeat/
// log-batch/completion/status JSON) carry a bounded TOTAL timeout: a stalled
// control plane must fail fast and be retried, never pin a runner slot.
// Bulk streaming transfers (artifact, cache, snapshot and dependency traffic)
// must NOT carry a total wall-clock bound: Kiwi's own size limits allow
// objects up to 8 GiB, which at any sustainable rate can legitimately outlive
// any fixed total. The streaming client therefore has Timeout 0 and relies on
// its transport's phase bounds plus a sliding idle guard (streamIdleTimeout)
// so a dead peer is still torn down.
var (
	// controlClientTimeout bounds the total duration of one ordinary
	// control-plane exchange. Production uses this value; the variable is a
	// test seam so a stalled-transfer regression can be proven in bounded
	// time.
	controlClientTimeout = 65 * time.Second
	// streamIdleTimeout is the runner-side sliding inactivity bound for bulk
	// transfers: a request context is cancelled when no byte flows in either
	// direction for this long, so an arbitrarily large object may take as
	// long as it keeps making progress while a peer that stops transferring
	// is disconnected. It is held atomically because tests shrink it around
	// live transfers; a plain variable would race the request path. Each
	// guard snapshots it once at creation via get().
	streamIdleTimeout = newAtomicDuration(90 * time.Second)
)

// atomicDuration is a duration held atomically. The runner's streaming
// tests mutate the idle bound while transfers are live, so reads of the
// bound from request goroutines must be race-free (the same reasoning as the
// app middleware's apiDeadline seam).
type atomicDuration struct{ nanos atomic.Int64 }

func newAtomicDuration(d time.Duration) *atomicDuration {
	a := &atomicDuration{}
	a.nanos.Store(int64(d))
	return a
}

func (a *atomicDuration) get() time.Duration { return time.Duration(a.nanos.Load()) }

func (a *atomicDuration) set(v time.Duration) { a.nanos.Store(int64(v)) }

type Config struct {
	Server, Token, Name string
	Labels              []string
	Poll                time.Duration
	Heartbeat           time.Duration
	Concurrency         int
	// CACert, Cert and Key are PEM contents or file paths for the runner
	// mTLS identity: CACert verifies the server, Cert/Key present the
	// runner's client certificate. ServerName overrides the TLS server name
	// (defaults to the server URL host).
	CACert     string
	Cert       string
	Key        string
	ServerName string
	// EnrollToken bootstraps the mTLS identity: with a CA configured but no
	// client certificate, the runner enrolls a fresh key with this token.
	// The enrolled identity is persisted under IdentityDir and reused while
	// its certificate stays valid; an expired or revoked certificate is
	// re-enrolled once under the same runner ID.
	EnrollToken string
	// IdentityDir is the directory for the persisted enrollment identity
	// (default: ~/.kiwi/runner).
	IdentityDir string
	// EnrollLabels are the labels sent with the enrollment request. A
	// label-bound enrollment grant requires every bound label to be
	// reproduced here.
	EnrollLabels []string
	// Drain makes the runner register as draining: it takes no new jobs,
	// finishes its active work, and exits once its slots are free.
	Drain bool
	// CaptureSnapshots uploads a workspace snapshot after each finished job
	// (POST /api/v1/jobs/{id}/snapshots). Upload failures are warnings and
	// never fail the job. The CLI enables this by default.
	CaptureSnapshots bool
	// Prewarm lists digest-pinned image references pulled after
	// registration and refreshed every PrewarmInterval. Anything not pinned
	// by @sha256: is rejected at startup.
	Prewarm         []string
	PrewarmInterval time.Duration
	// PrewarmStateFile persists the bounded set of previously prewarmed
	// references (default: ~/.kiwi/prewarm.json).
	PrewarmStateFile string
	// GCInterval bounds how often the runner reaps stale runtime resources
	// via executor.GC (default: hourly); WorkDir is the GC subprocess
	// working directory (default: system temp).
	GCInterval time.Duration
	WorkDir    string
	// MetricsListen exposes the Prometheus text metrics endpoint when set
	// (e.g. ":9091").
	MetricsListen string
	// CacheRoot is the root for the runner's local cache and artifact
	// stores (default: ~/.kiwi).
	CacheRoot string
	// StagingDir is the ROOT for the runner's bounded dependency spool (the
	// scratch space a downloaded dependency artifact is written to before
	// extraction). The runner owns one immutable staging.Budget per process
	// and stages inside <StagingDir>/<runner instance id>, so two runners
	// sharing a root never share one ledger. Default: the dependency spool
	// root (CacheRoot, then WorkDir, then the system temp dir); production
	// runners that stage multi-GB dependencies should configure a dedicated
	// directory.
	StagingDir string
	// StagingMaxBytes bounds the runner-wide aggregate of concurrent
	// dependency spool bytes. Default: one maximum-size artifact
	// (dependencyArtifactMaxBytes, 8 GiB), which is conservative and
	// automatically serializes maximum-sized spools; operators that want
	// greater concurrent restore concurrency raise it.
	StagingMaxBytes int64
	// SetupTimeout bounds the setup phase (workspace checkout through
	// dependency restore and changed-files discovery) for jobs whose
	// persisted JobTimeout is unset (legacy records). Zero means the default
	// (15 minutes). Modern jobs are bounded by their persisted job timeout,
	// so this ceiling is the legacy fallback that keeps "no user job
	// timeout" from meaning "git may hang forever".
	SetupTimeout time.Duration
	// StagingInterval is how often the runner retries dependency-spool
	// cleanup debt (a spool whose removal failed keeps its bytes charged
	// until a retry succeeds). Zero means the default (30 seconds); the
	// heavy runtime GC keeps its own, much longer, interval.
	StagingInterval time.Duration
	// CacheMaxBytes, CacheMaxEntries and CacheMaxAge bound the runner-local
	// cache tree (all stored archives), distinct from the per-archive 8 GiB
	// cap. Without an aggregate bound a pipeline that derives a fresh
	// logical key per run can fill the runner host's disk forever, since
	// cache archives live outside the job workspace quota. Zero uses the
	// built-in defaults (32 GiB / 4096 entries / 14 days).
	CacheMaxBytes   int64
	CacheMaxEntries int
	CacheMaxAge     time.Duration
	// CacheArchiveMaxBytes overrides the per-archive cache bound (the shared
	// 8 GiB default) for this runner. Zero keeps the shared contract; the
	// same resolved value drives the local archive cap, the restore
	// verification AND the download preflight.
	CacheArchiveMaxBytes int64
	// CacheInterval is how often the local cache tree is pruned. Zero uses
	// the default (10 minutes); the hourly GC is a backstop. Saves also
	// prune synchronously when they push the tree over a cap.
	CacheInterval time.Duration
	// FinalizeTimeout bounds post-job finalization (test-report delivery and
	// snapshot upload) after the executor returns. Zero means the default
	// (2 minutes). Terminal completion uses its own shorter internal bound
	// and is not affected by this value.
	FinalizeTimeout time.Duration
	// StateDir is the runner's durable state directory; the per-job log
	// batch journal lives under it (keyed by job and lease generation) so a
	// restarted runner replays unconsumed batches under their original
	// identities instead of re-batching (and duplicating) them. Defaults
	// (resolved by Run, which fails closed when none can be resolved):
	// CacheRoot when set, otherwise the identity directory, otherwise
	// ~/.kiwi. Direct execute test callers opt out of the journal explicitly
	// through the Runner's journalOptOut seam.
	StateDir string
	// SigstoreKeyPath is a PKCS8 PEM Ed25519 private key used to sign
	// Sigstore attestations for artifacts whose contract declares a
	// sigstore gate.
	SigstoreKeyPath string
	// CheckoutFn replaces the default git checkout (test seam / custom
	// workspace provisioning). Jobs execute in the directory it populates.
	CheckoutFn func(ctx context.Context, j model.Job, dir string) error
}
type Runner struct {
	Cfg     Config
	ID      string
	Client  *http.Client
	Metrics *Metrics
	// StreamClient carries bulk transfers (artifact/cache/snapshot/dependency
	// uploads and downloads). It deliberately has no total timeout: the
	// transport bounds dial/TLS-handshake/response-header phases and each
	// request is bounded by its job context plus the sliding streamIdleTimeout
	// stall guard. Client stays bounded-total and is used for ordinary
	// control-plane calls. Run/prepareClient set both; a directly constructed
	// Runner without StreamClient (tests) falls back to Client.
	StreamClient *http.Client
	// store is the identity store used when enrollment persistence is
	// active (IdentityDir configured); it clears the persisted certificate
	// when the control plane disables or revokes this runner.
	store IdentityStore
	// clientCertPEM is the runner's own client certificate PEM (explicit
	// or enrolled); its serial is advertised at registration so the
	// control plane can bind the runner's profile to it.
	clientCertPEM []byte
	// effectiveCapabilities is the intersection of the hardware
	// capabilities discovered on this host and the profile capabilities
	// returned by the register response — it can only shrink the profile,
	// never enlarge it. capEnforced reports whether the server explicitly
	// declared the response's capability set authoritative via the
	// capabilities_enforced flag: the flag is decoded EXPLICITLY (modern
	// servers always include the capabilities field, so its presence proves
	// nothing), and an enforced empty intersection denies every runtime
	// instead of meaning "no restriction". Legacy servers omit the flag and
	// leave capEnforced false.
	effectiveCapabilities []string
	capEnforced           bool
	// journalOptOut is the explicit seam that lets a caller of execute run
	// WITHOUT the durable log journal: only direct test callers that do not
	// resolve a state directory set it (testRunnerFor does). Run never sets
	// it, so the production path always fails closed when no state
	// directory can be resolved.
	journalOptOut bool
	// staging is the immutable, runner-wide bounded spool budget every
	// dependency restore reserves from before a single compressed byte is
	// written. Run constructs it once (configureStaging); direct execute
	// callers (tests) resolve it lazily through dependencyStaging under
	// stagingMu. It is immutable thereafter: the budget's own ledger is
	// concurrency-safe, and nothing reassigns the pointer after the first
	// successful construction.
	stagingMu sync.Mutex
	staging   *staging.Budget
	// cacheMgr is the runner-wide aggregate cache budget owner shared by
	// every job's cache.Store (cacheManager constructs it lazily). A
	// per-job Store cannot enforce an aggregate bound over the shared cache
	// directory, so reservations/eviction/publication all go through this
	// one manager.
	cacheMu  sync.Mutex
	cacheMgr *cache.Manager
}

// registerResponse is the register reply. Capabilities carries the effective
// capability set and CapabilitiesEnforced is decoded EXPLICITLY as the
// server's authority flag: modern control planes always include both keys
// (an empty enforced set means deny-all), so key presence is no longer an
// authority signal — only the explicit flag marks a profile claim. A legacy
// server without the flag leaves capEnforced false and every runtime
// accepted.
type registerResponse struct {
	model.Runner
	Capabilities         []string `json:"capabilities"`
	CapabilitiesEnforced bool     `json:"capabilities_enforced"`
}

func (r *Runner) Run(ctx context.Context) error {
	if r.Cfg.Poll == 0 {
		r.Cfg.Poll = 2 * time.Second
	}
	if r.Cfg.Heartbeat == 0 {
		r.Cfg.Heartbeat = 10 * time.Second
	}
	if r.Cfg.Concurrency <= 0 {
		r.Cfg.Concurrency = 1
	}
	if r.Cfg.PrewarmInterval <= 0 {
		r.Cfg.PrewarmInterval = prewarmDefaultInterval
	}
	if r.Cfg.GCInterval <= 0 {
		r.Cfg.GCInterval = gcInterval
	}
	if r.Cfg.StagingInterval <= 0 {
		r.Cfg.StagingInterval = stagingMaintenanceInterval
	}
	if r.Cfg.CacheInterval <= 0 {
		r.Cfg.CacheInterval = cachePruneInterval
	}
	if r.Cfg.WorkDir == "" {
		r.Cfg.WorkDir = os.TempDir()
	}
	if r.Cfg.PrewarmStateFile == "" {
		home, _ := os.UserHomeDir()
		r.Cfg.PrewarmStateFile = filepath.Join(home, ".kiwi", "prewarm.json")
	}
	if r.Metrics == nil {
		r.Metrics = NewMetrics()
	}
	if err := validatePrewarmRefs(r.Cfg.Prewarm); err != nil {
		return err
	}
	if err := validateServerURL(r.Cfg.Server); err != nil {
		return err
	}
	if r.ID == "" {
		id, err := newRunnerID()
		if err != nil {
			return err
		}
		r.ID = id
	}
	r.resolveIdentityDir()
	if err := r.resolveStateDir(); err != nil {
		return err
	}
	if err := r.prepareClient(ctx); err != nil {
		return err
	}
	r.applyClientPolicy()
	// Credential-bearing runner traffic must never follow redirects to a
	// different origin.
	r.Client = server.NoRedirectClient(r.Client)
	r.StreamClient = server.NoRedirectClient(r.StreamClient)
	if err := r.register(ctx); err != nil {
		return err
	}
	// The runner-wide dependency staging budget is constructed ONCE per Run,
	// before any job can be leased, and owned until the fully joined
	// shutdown retires it (closeStaging): every dependency restore reserves
	// its exact spool size before a byte is downloaded, so the aggregate
	// compressed spool footprint can never exceed the configured bound even
	// with maximum runner concurrency. A failed construction (unusable
	// directory, another live owner) fails startup instead of the first
	// multi-GB restore.
	if err := r.configureStaging(); err != nil {
		return err
	}
	// The cache manager follows the same explicit lifecycle: a Run started
	// with a changed cache root or policy gets a fresh manager instead of
	// accounting against the previous Run's ledger.
	r.configureCacheManager()
	// The staging ledger is exposed as scrape-time gauges: Used() includes
	// cleanup debt (bytes whose removal failed and that a maintenance retry
	// must reclaim), and PendingCleanup() is the degraded/cleanup-required
	// signal. The failure counter is incremented both by a failed
	// CleanupSpool at the end of a restore and by a failed maintenance retry.
	r.Metrics.GaugeFunc("kiwi_runner_staging_bytes", func() float64 {
		st := r.currentStaging()
		if st == nil {
			return 0
		}
		return float64(st.Used())
	})
	r.Metrics.GaugeFunc("kiwi_runner_staging_pending_cleanup", func() float64 {
		st := r.currentStaging()
		if st == nil {
			return 0
		}
		return float64(st.PendingCleanup())
	})
	// runCtx is Run's private lifecycle context: everything Run spawns
	// (executes, maintenance passes, the metrics server) runs under it, and
	// Run cancels it before joining on EVERY return path — external
	// cancellation, remote disable and graceful drain alike — so no owned
	// component can outlive Run on a still-live parent context (a drain
	// leaves the caller's ctx alive, which is exactly the case a detached
	// metrics listener or maintenance goroutine would otherwise survive).
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	// background tracks every goroutine Run spawns. On every return path Run
	// first cancels runCtx and then joins the tracked work, bounded by
	// backgroundDrainGrace: spawned work can still touch runner state (test
	// seams, workspace teardown, a bound metrics port), so Run must not
	// return while any of it is alive — and if the grace expires anyway (a
	// job or probe that ignores cancellation must not pin process shutdown
	// forever), the worker is already canceled and can only wind down; the
	// detached waiter goroutine lives until it finishes. The grace case is
	// reported on stderr, never silent.
	var background sync.WaitGroup
	waitBackground := func() bool {
		finished := make(chan struct{})
		go func() { background.Wait(); close(finished) }()
		select {
		case <-finished:
			return true
		case <-time.After(backgroundDrainGrace):
			fmt.Fprintf(os.Stderr, "kiwi runner %s: background work still running after %s; exiting anyway (its context is canceled)\n", r.ID, backgroundDrainGrace)
			return false
		}
	}
	stop := func() {
		runCancel()
		// Only a fully joined shutdown may retire staging ownership: if the
		// drain grace expired while a worker is still alive, that worker can
		// still hold (or acquire) a reservation, so retaining ownership is
		// the safe choice.
		if waitBackground() {
			r.closeStaging()
		}
	}
	if r.Cfg.MetricsListen != "" {
		background.Add(1)
		go func() {
			defer background.Done()
			r.runMetricsServer(runCtx)
		}()
	}
	prewarmer := newPrewarmer(r.Cfg)
	background.Add(1)
	go func() {
		defer background.Done()
		_ = prewarmer.run(runCtx)
	}()
	lastPrewarm := time.Now()
	lastGC := time.Now()
	lastStaging := time.Now()
	lastCache := time.Now()
	maint := maintenanceSchedule{GCInterval: r.Cfg.GCInterval, PrewarmInterval: r.Cfg.PrewarmInterval, StagingInterval: r.Cfg.StagingInterval, CacheInterval: r.Cfg.CacheInterval}
	done := make(chan struct{}, r.Cfg.Concurrency)
	active := 0
	// Draining starts from the local --drain flag; the server may also
	// advertise the state on next() responses (an admin drained the runner
	// remotely), which flips this to true mid-run.
	draining := r.Cfg.Drain
	for {
		// Fill every free local execution slot before sleeping. The control plane
		// independently capacity-checks this runner, so a race cannot over-lease it.
		for active < r.Cfg.Concurrency {
			task, drainSignal, err := r.next(runCtx)
			if err != nil {
				if errors.Is(err, ErrRunnerDisabledOrRevoked) {
					stop()
					return err
				}
				fmt.Fprintf(os.Stderr, "kiwi runner %s: next: %v\n", r.ID, err)
				break
			}
			if task == nil {
				if drainSignal {
					draining = true
				}
				break
			}
			active++
			background.Add(1)
			go func(t server.Task) {
				defer background.Done()
				r.execute(runCtx, t)
				done <- struct{}{}
			}(*task)
		}
		if draining && active == 0 {
			fmt.Printf("kiwi runner %s drained: no active work, exiting\n", r.ID)
			stop()
			return nil
		}
		select {
		case <-ctx.Done():
			// Stop leasing, then cancel and join the work already started so
			// no execute or maintenance pass outlives Run (bounded by
			// backgroundDrainGrace: a job that ignores cancellation must not
			// pin process shutdown forever).
			stop()
			return ctx.Err()
		case <-done:
			active--
		case <-time.After(r.Cfg.Poll):
		}
		if gcDue, prewarmDue, stagingDue, cacheDue := maint.due(time.Now(), lastGC, lastPrewarm, lastStaging, lastCache); gcDue || prewarmDue || stagingDue || cacheDue {
			if gcDue {
				lastGC = time.Now()
				background.Add(1)
				go func() {
					defer background.Done()
					r.runGCPass(runCtx)
				}()
			}
			if prewarmDue {
				lastPrewarm = time.Now()
				background.Add(1)
				go func() {
					defer background.Done()
					_ = prewarmer.run(runCtx)
				}()
			}
			if stagingDue {
				lastStaging = time.Now()
				background.Add(1)
				go func() {
					defer background.Done()
					r.maintainStaging(runCtx)
				}()
			}
			if cacheDue {
				lastCache = time.Now()
				background.Add(1)
				go func() {
					defer background.Done()
					r.pruneJobCache(runCtx)
				}()
			}
		}
	}
}

// runMetricsServer serves the Prometheus text metrics until ctx is canceled,
// then shuts the server down within a bounded grace and returns. It is a
// TRACKED Run-owned component, not detached goroutines: Run cancels runCtx
// before joining, so a graceful drain releases the listen port before Run
// returns and an in-process restart cannot collide with the old listener. A
// bind failure is reported and the component returns; Run continues (metrics
// are diagnostics, not job execution).
func (r *Runner) runMetricsServer(ctx context.Context) {
	srv := newMetricsServer(r.Cfg.MetricsListen, r.Metrics)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "kiwi runner metrics: %v\n", err)
		}
		return
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	// Shutdown closes the listener before it waits for connections, so
	// ListenAndServe is already returning; waiting for it here (rather than
	// with a short timeout) is what guarantees the listen port is released
	// before Run returns — a fallback that returned early could leave the
	// listener bound under load and break an in-process restart.
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "kiwi runner metrics: %v\n", err)
	}
}
func (r *Runner) register(ctx context.Context) error {
	labels := append([]string{}, r.Cfg.Labels...)
	labels = append(labels, "os:"+runtime.GOOS, "arch:"+runtime.GOARCH, "native")
	discovered := discoveredCapabilities()
	labels = append(labels, discovered...)
	in := model.Runner{
		ID: r.ID, Name: r.Cfg.Name, Labels: unique(labels),
		Metadata:     map[string]string{"go": runtime.Version()},
		Capacity:     r.Cfg.Concurrency,
		ProtocolMin:  runnerProtocol,
		ProtocolMax:  runnerProtocol,
		Version:      RunnerVersion,
		Region:       os.Getenv(envRunnerRegion),
		Capabilities: discovered,
		CertSerial:   r.clientCertSerial(),
		Draining:     r.Cfg.Drain,
	}
	var out registerResponse
	if err := r.post(ctx, "/api/v1/runners/register", in, &out); err != nil {
		if isHTTPStatus(err, http.StatusForbidden) || isHTTPStatus(err, http.StatusUnauthorized) {
			// 401/403 on registration means the runner was disabled or
			// its certificate serial was revoked: re-registering cannot
			// clear either and must not be retried. The persisted
			// certificate is cleared (the ID is kept) so the next start
			// re-enrolls under the same identity.
			return r.onDisabled(fmt.Errorf("%w (server: %v)", ErrRunnerDisabledOrRevoked, err))
		}
		return err
	}
	r.ID = out.ID
	// Capability intersection: the profile capabilities in the response are
	// the ceiling; the runner advertises (and enforces) only the
	// intersection with what this host actually discovered, so a job
	// requiring a runtime the host cannot provide never starts here. The
	// claim is enforced exactly when the server set capabilities_enforced
	// (an empty enforced claim is an authoritative empty ceiling, not an
	// absent one, so the intersection may legitimately be empty and then
	// denies every runtime); a legacy server omits the flag and imposes no
	// restriction.
	r.capEnforced = out.CapabilitiesEnforced
	r.effectiveCapabilities = intersectStringLists(out.Capabilities, discovered)
	fmt.Printf("kiwi runner %s registered (%s/%s) labels=%s caps=%s\n", r.ID, runtime.GOOS, runtime.GOARCH, strings.Join(out.Labels, ","), strings.Join(r.effectiveCapabilities, ","))
	return nil
}

// discoveredCapabilities reports the runtime capabilities this host
// actually provides: native always, container when docker is on PATH, tart
// on macOS when the tart CLI is on PATH.
func discoveredCapabilities() []string {
	caps := []string{"native"}
	if _, err := exec.LookPath("docker"); err == nil {
		caps = append(caps, "container")
	}
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("tart"); err == nil {
			caps = append(caps, "tart")
		}
	}
	return caps
}

// clientCertSerial returns the serial of the runner's own client
// certificate (hex), or "" without one.
func (r *Runner) clientCertSerial() string {
	if len(r.clientCertPEM) == 0 {
		return ""
	}
	cert, err := runnerpki.ParseCertPEM(r.clientCertPEM)
	if err != nil || cert.SerialNumber == nil {
		return ""
	}
	return cert.SerialNumber.Text(16)
}

// intersectStringLists returns the elements of a that are also in b,
// preserving a's order.
func intersectStringLists(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	have := map[string]bool{}
	for _, x := range b {
		have[x] = true
	}
	out := make([]string, 0, len(a))
	for _, x := range a {
		if have[x] {
			out = append(out, x)
		}
	}
	return out
}

// next polls for work. The boolean reports the server's drain signal: the
// control plane advertises it as X-Kiwi-Draining, on a 204 (no work) and on
// the 503 it returns while draining (no new leases are issued), and the
// runner should exit once its active slots are free. Other 503s (durability
// degraded, no capacity) carry no drain header and stay retryable errors. A
// disabled runner (X-Kiwi-Disabled) or a rejected identity (403 —
// certificate revoked) is a terminal ErrRunnerDisabledOrRevoked: the runner
// exits instead of re-polling.
func (r *Runner) next(ctx context.Context) (*server.Task, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Cfg.Server+"/api/v1/runners/"+r.ID+"/next", bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, false, err
	}
	r.auth(req)
	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Kiwi-Disabled") == "true" {
		return nil, false, r.onDisabled(ErrRunnerDisabledOrRevoked)
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil, resp.Header.Get("X-Kiwi-Draining") == "true", nil
	}
	// The control plane signals a drain while it refuses new leases as 503 +
	// X-Kiwi-Draining. That is the graceful-exit signal, not a transport
	// error: without this mapping a remotely drained runner would poll and
	// log forever instead of draining.
	if resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get("X-Kiwi-Draining") == "true" {
		return nil, true, nil
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		b, _ := io.ReadAll(resp.Body)
		return nil, false, r.onDisabled(fmt.Errorf("%w (server: %s: %s)", ErrRunnerDisabledOrRevoked, resp.Status, strings.TrimSpace(string(b))))
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("next: %s: %s", resp.Status, b)
	}
	var t server.Task
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return nil, false, err
	}
	return &t, false, nil
}

// onDisabled handles the terminal disabled/revoked signal from the control
// plane: the persisted certificate is cleared (the runner ID and key are
// kept so a later re-enrollment continues the same identity), a re-enroll
// hint is logged, and the sentinel error is returned so Run exits nonzero
// without re-registering or re-enrolling in a loop.
func (r *Runner) onDisabled(err error) error {
	if r.store.Dir != "" {
		if rmErr := r.store.ClearCert(); rmErr != nil {
			fmt.Fprintf(os.Stderr, "kiwi runner %s: clear persisted certificate: %v\n", r.ID, rmErr)
		}
	}
	fmt.Fprintf(os.Stderr, "kiwi runner %s: runner disabled or certificate revoked; re-enroll required\n", r.ID)
	return err
}

// workspaceMaxBytesForResources converts a job's declared resources.disk
// request into the workspace bound handed to the executor. The unit is bytes:
// pipeline.ByteSize is the pipeline decoder's canonical byte count ("2Gi" is
// 2<<30 because the binary suffixes Ki/Gi/Ti are 1024-based; a plain integer
// is bytes), so the value only needs widening to int64, never re-parsing. An
// undeclared disk (zero) yields zero, the documented default: no workspace
// bound is derived and pipelines without a disk declaration keep their
// previous behavior.
func workspaceMaxBytesForResources(res pipeline.Resources) int64 {
	if res.Disk <= 0 {
		return 0
	}
	return int64(res.Disk)
}

// workspaceQuotaLimitForTask derives the hard workspace bound execute installs
// BEFORE the workspace is populated, using the same shared precedence as the
// executor: the authoritative persisted t.Job.DiskRequest, then the mandatory
// untrusted default for jobs the runner does not trust, and zero (no hard
// bound requested) for trusted jobs without a declaration. The unit is bytes;
// no re-parsing happens.
func workspaceQuotaLimitForTask(t server.Task) int64 {
	return executor.WorkspaceBoundBytes(t.Job.DiskRequest, !t.Job.Trusted, executor.DefaultUntrustedWorkspaceMaxBytes)
}

// runtimeRunsOnContainer reports whether a resolved job runtime is the
// container backend: the only backend whose untrusted jobs require a hard
// workspace quota (the container builder sets RequireDiskQuota from
// Options.RequireUntrustedDiskQuota).
func runtimeRunsOnContainer(runtime string) bool {
	return runtime == "container"
}

// compiledPayloadRuntime resolves the runtime claimed by the enqueue-time
// compiled payload's effective job. Before checkout the payload is
// unverified persisted state, so callers only use it as a consistency check
// against the persisted pipeline (see effectiveTaskRuntimeForSecurityGate);
// a malformed payload is an error, never silently "not container".
func compiledPayloadRuntime(p *model.CompiledJobPayload) (string, error) {
	if p == nil || p.EffectiveJob == nil {
		return "", fmt.Errorf("compiled job payload is absent")
	}
	raw, err := json.Marshal(p.EffectiveJob)
	if err != nil {
		return "", fmt.Errorf("compiled job payload effective job: %w", err)
	}
	var shape struct {
		Job struct {
			Runtime string `json:"runtime"`
		} `json:"job"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		return "", fmt.Errorf("compiled job payload effective job: %w", err)
	}
	return shape.Job.Runtime, nil
}

// persistedPipelineRuntime resolves the runtime independently from the
// persisted pipeline: it parses the canonical pipeline text and compiles the
// persisted job key. This is the authoritative source for the pre-checkout
// security gate because the compiled payload has NOT been digest-verified at
// that point (verifyCompiledPayload runs only after checkout).
func persistedPipelineRuntime(t server.Task) (string, error) {
	if strings.TrimSpace(t.Job.Pipeline) == "" {
		return "", fmt.Errorf("cannot resolve runtime for job %s: no persisted pipeline", t.Job.ID)
	}
	spec, err := pipeline.Parse([]byte(t.Job.Pipeline))
	if err != nil {
		return "", fmt.Errorf("cannot resolve runtime for job %s: parse persisted pipeline: %w", t.Job.ID, err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		return "", fmt.Errorf("cannot resolve runtime for job %s: compile persisted pipeline: %w", t.Job.ID, err)
	}
	cj, ok := g.Jobs[t.Job.Key]
	if !ok {
		return "", fmt.Errorf("cannot resolve runtime for job %s: compiled job %q not found in the persisted pipeline", t.Job.ID, t.Job.Key)
	}
	return cj.Job.Runtime, nil
}

// effectiveTaskRuntimeForSecurityGate resolves the effective runtime used by
// the PRE-CHECKOUT hard-quota gate. It never trusts the compiled payload on
// its own: the payload is only digest-verified after checkout, so at this
// point it is just persisted state that may be corrupt or inconsistent with
// the pipeline. The runtime therefore always comes from the persisted
// pipeline, and when a payload is present its claimed runtime must AGREE
// with the pipeline or the gate fails closed. A missing/undecodable pipeline
// is an error; callers refuse the checkout.
func effectiveTaskRuntimeForSecurityGate(t server.Task) (string, error) {
	pipelineRuntime, err := persistedPipelineRuntime(t)
	if err != nil {
		return "", err
	}
	if p := t.Job.CompiledJobPayload; p != nil && p.EffectiveJob != nil {
		payloadRuntime, perr := compiledPayloadRuntime(p)
		if perr != nil {
			return "", perr
		}
		if payloadRuntime != pipelineRuntime {
			return "", fmt.Errorf("cannot resolve runtime for job %s: compiled payload runtime %q disagrees with the persisted pipeline runtime %q", t.Job.ID, payloadRuntime, pipelineRuntime)
		}
	}
	return pipelineRuntime, nil
}

func (r *Runner) execute(parent context.Context, t server.Task) {
	// The declared job lifetime starts HERE, before workspace/quota setup,
	// checkout, pipeline parsing, policy and payload verification, dependency
	// downloads, changed-files discovery and journal/cache setup: the
	// persisted JobTimeout is the resolved compiled job timeout (else
	// pipeline defaults.timeout, see pipeline.EffectiveJobTimeout) stamped at
	// enqueue, exactly like the resource requests. The executor still applies
	// its own WithTimeout to the same value; a child context can only
	// shorten, never extend, this parent deadline, so distributed and local
	// execution now agree on what "job timeout" covers.
	ctx, cancel := context.WithCancel(parent)
	if d := t.Job.JobTimeout; d > 0 {
		cancel()
		ctx, cancel = context.WithTimeout(parent, d)
	}
	defer cancel()
	done := make(chan struct{})
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		defer func() {
			if heartbeatExiting != nil {
				heartbeatExiting()
			}
		}()
		r.heartbeatLoop(ctx, cancel, t, done)
	}()
	// Joining the execute goroutine must join the goroutines execute owns:
	// close(done) and cancel() signal the heartbeat to stop, and the bounded
	// wait guarantees it has actually returned (with a diagnostic if it
	// somehow does not) before the task's lifecycle ends.
	defer func() {
		close(done)
		cancel()
		select {
		case <-heartbeatDone:
		case <-time.After(heartbeatShutdownGrace):
			fmt.Fprintf(os.Stderr, "kiwi runner %s: heartbeat for %s did not stop within %s\n", r.ID, t.Job.ID, heartbeatShutdownGrace)
		}
	}()

	tmp, err := os.MkdirTemp("", "kiwi-run-*")
	if err != nil {
		r.complete(parent, t, model.StatusFailure, err, nil)
		return
	}
	untrusted := !t.Job.Trusted
	requireDiskQuota := untrusted && !executor.AllowUnquotaedUntrustedDisk()
	// The workspace quota lifecycle is OWNED by execute, not by the backend:
	// the hard bound is installed on the empty workspace directory BEFORE
	// checkout (and before dependency restore), so an untrusted repository
	// can no longer fill the host disk during clone. The bound comes from the
	// authoritative persisted t.Job.DiskRequest, or the mandatory untrusted
	// default when the job declares none. Teardown runs on EVERY return path
	// (defer), removes the quota before the workspace itself, and is
	// idempotent.
	quotaLimit := workspaceQuotaLimitForTask(t)
	var workspaceQuota *executor.DiskQuotaStatus
	var quotaCleanup func() error
	if quotaLimit > 0 {
		status, cleanup := installWorkspaceDiskQuota(tmp, quotaLimit)
		workspaceQuota = &status
		quotaCleanup = cleanup
	}
	defer func() {
		if quotaCleanup != nil {
			if qerr := quotaCleanup(); qerr != nil {
				fmt.Fprintf(os.Stderr, "kiwi runner %s: remove workspace quota for %s: %v\n", r.ID, t.Job.ID, qerr)
			}
			quotaCleanup = nil
		}
		if rerr := removeJobWorkspace(tmp); rerr != nil {
			fmt.Fprintf(os.Stderr, "kiwi runner %s: remove job workspace %s: %v\n", r.ID, tmp, rerr)
		}
	}()
	// An untrusted job that demands a hard bound must not even check out
	// when no hard bound could be established: the checkout itself is the
	// window the quota protects. The gate resolves the effective runtime
	// FAIL CLOSED and independently of the not-yet-verified compiled payload:
	// the runtime always comes from the persisted pipeline, and a payload
	// that disagrees (or cannot be decoded) refuses the checkout. "Couldn't
	// establish the runtime" is never interpreted as "not container", so the
	// gate does not depend on the compatibility field being populated or
	// trustworthy. Non-container runtimes keep their previous behavior (the
	// container backend is the only backend that requires the hard quota).
	if requireDiskQuota && workspaceQuota != nil && !workspaceQuota.Hard {
		runtime, rerr := effectiveTaskRuntimeForSecurityGate(t)
		if rerr != nil || runtimeRunsOnContainer(runtime) {
			detail := workspaceQuota.Detail
			if rerr != nil {
				detail = detail + "; effective runtime could not be resolved: " + rerr.Error()
			}
			r.complete(parent, t, model.StatusFailure, executor.UntrustedDiskQuotaGateError(detail), nil)
			return
		}
	}
	// The bound must be AVAILABLE, not merely installable: a project quota
	// caps the project but reserves nothing, so a hostile checkout could
	// otherwise consume all remaining host free space up to the quota limit
	// before any later availability test runs. The check runs on the EMPTY
	// workspace, before a single checkout byte is written. It is the same
	// preflight the executor would run after checkout, so the derived
	// options mark it as already performed and the executor skips its
	// redundant full-capacity re-check (a 2 GiB checkout must not silently
	// raise the requirement to bound + 2 GiB).
	availabilityChecked := false
	if quotaLimit > 0 {
		if aerr := executor.WorkspaceDiskAvailable(tmp, quotaLimit); aerr != nil {
			r.complete(parent, t, model.StatusFailure, &executor.RunError{
				Kind: executor.ErrorInfra,
				Err:  fmt.Errorf("workspace quota: %w", aerr),
			}, nil)
			return
		}
		availabilityChecked = true
	}
	// Legacy records carry no persisted JobTimeout, so the job context alone
	// leaves the setup phase unbounded: a clone (exec.CommandContext(ctx,
	// "git", ...)) that stays alive but stalls would occupy a runner slot
	// indefinitely while the heartbeat keeps renewing the lease, and a
	// continuously progressing multi-hour dependency download could exceed
	// any declared job budget. When (and only when) no job timeout exists,
	// the setup phase therefore gets its own ceiling; a modern job's
	// persisted JobTimeout already bounds this same span.
	setupCtx := ctx
	setupCancel := func() {}
	if t.Job.JobTimeout <= 0 {
		setupCtx, setupCancel = context.WithTimeout(ctx, r.setupPhaseTimeout())
	}
	defer setupCancel()
	checkoutStart := time.Now()
	if err = r.checkoutTask(setupCtx, t.Job, tmp); err != nil {
		r.complete(parent, t, statusForErr(setupCtx, err), err, nil)
		return
	}
	r.Metrics.Observe("kiwi_runner_checkout_duration_seconds", time.Since(checkoutStart).Seconds())
	spec, err := pipeline.Parse([]byte(t.Job.Pipeline))
	if err != nil {
		r.complete(parent, t, model.StatusFailure, err, nil)
		return
	}
	if err := policy.ValidateAdmission(spec, t.Job.Trusted); err != nil {
		r.complete(parent, t, model.StatusFailure, err, nil)
		return
	}
	// When the control plane attached the enqueue-time compilation record,
	// verify its digests and execute the payload's EffectiveJob instead of
	// recompiling/selecting locally. The baseline admission check above
	// stays; the payload's effective policy narrows it further. The
	// effective network also comes from the payload (the compiled job's
	// sandbox/network intersected with the effective policy ceiling), never
	// from the legacy job.Network reinterpretation.
	var cj pipeline.CompiledJob
	if t.Job.CompiledJobPayload != nil {
		var caps policy.Capabilities
		var policyOK bool
		cj, caps, policyOK, err = verifyCompiledPayload(spec, t.Job.CompiledJobPayload, t.Job.Trusted)
		if err != nil {
			r.complete(parent, t, model.StatusFailure, err, nil)
			return
		}
		if policyOK {
			if err := policy.ValidateAdmissionWithCapabilities(spec, caps); err != nil {
				r.complete(parent, t, model.StatusFailure, fmt.Errorf("compiled payload policy admission: %w", err), nil)
				return
			}
			if err := applyEffectiveNetwork(&cj, caps); err != nil {
				r.complete(parent, t, model.StatusFailure, fmt.Errorf("compiled payload network admission: %w", err), nil)
				return
			}
		}
	} else {
		g, gerr := pipeline.Compile(spec)
		if gerr != nil {
			r.complete(parent, t, model.StatusFailure, gerr, nil)
			return
		}
		var ok bool
		cj, ok = g.Jobs[t.Job.Key]
		if !ok {
			r.complete(parent, t, model.StatusFailure, fmt.Errorf("compiled job %q not found", t.Job.Key), nil)
			return
		}
		// Legacy path: the control plane did not attach a compilation
		// record, so the job-level network field is authoritative.
		cj.Job.Network = t.Job.Network
	}
	// Copy the effective policy's sandbox requirements onto the compiled
	// job before execution: the executor derives daemon-level promises
	// (rootless, read-only rootfs) from cj.Job.Sandbox alone, and the
	// verified payload is the only authoritative policy record.
	effSandbox, serr := payloadSandboxRequirements(t.Job.CompiledJobPayload)
	if serr != nil {
		r.complete(parent, t, model.StatusFailure, fmt.Errorf("compiled payload sandbox requirements: %w", serr), nil)
		return
	}
	applyEffectiveSandbox(&cj, effSandbox)
	// Capability intersection enforcement: when the profile declared a
	// capability ceiling, a job whose runtime capability this host did not
	// discover is refused up front (never silently executed by a backend
	// the host cannot provide).
	if err := r.checkCapability(cj.Job.Runtime); err != nil {
		r.complete(parent, t, model.StatusFailure, err, nil)
		return
	}
	if err := checkShardAssignment(cj); err != nil {
		r.complete(parent, t, model.StatusFailure, err, nil)
		return
	}
	masker := &secrets.Masker{}
	if cj.Job.Permissions.IDToken {
		if cj.Job.Env == nil {
			cj.Job.Env = map[string]string{}
		}
		cj.Job.Env["KIWI_OIDC_REQUEST_URL"] = r.Cfg.Server + "/api/v1/jobs/" + t.Job.ID + "/oidc"
		cj.Job.Env["KIWI_OIDC_REQUEST_TOKEN"] = t.LeaseToken
		masker.Add(t.LeaseToken)
	}
	if err := r.restoreDownloads(setupCtx, t, cj.Job.Downloads, tmp); err != nil {
		// setupCtx is the same context checkout runs under, so the same
		// status rule applies: a deadline/cancellation that ended a
		// dependency download is a CANCELLATION, not a failure. Without
		// this the identical deadline produced different terminal semantics
		// depending on which setup subphase it interrupted (checkout ->
		// cancelled, restore -> failure).
		r.complete(parent, t, statusForErr(setupCtx, err), err, nil)
		return
	}
	// The setup phase ends here: checkout, dependency restore and
	// changed-files discovery are its whole contract. The legacy setup
	// ceiling is therefore released immediately instead of lingering (as a
	// live timer and context) through the rest of the job. The git fallback
	// runs inside the phase it belongs to, and the resolved list is passed to
	// the executor as a value.
	resolvedChangedFiles := effectiveChangedFiles(setupCtx, t.Job.ChangedFiles, t.Job.ChangedFilesKnown, tmp)
	setupCancel()
	// The sink spools lines in memory and a dedicated sender drains them:
	// pipe readers must never block on control-plane delivery, so a slow log
	// endpoint cannot stall the drain and silently drop the tail. Overflow
	// and send failures are surfaced on completion (never a clean green job
	// with lost logs).
	consoleSink := logging.Func(func(job, step, line string) {
		fmt.Printf("[%s/%s] %s\n", job, step, masker.MaskMulti(line))
	})
	// Durable batch journal: every batch is journaled (masked) and fsynced
	// before its first POST, unconditionally acked after the control plane
	// confirms it, and unconsumed records from a crashed earlier process for
	// this same lease generation are replayed with their original identities
	// before new lines are sent. Opening fails closed: a corrupt/unreadable
	// journal fails the job instead of silently dropping durable state.
	journal, jerr := r.openJobLogJournal(t.Job.ID, t.LeaseGeneration, masker.MaskMulti)
	if jerr != nil {
		r.complete(parent, t, model.StatusFailure, fmt.Errorf("log journal: %w", jerr), nil)
		return
	}
	if journal != nil {
		// Terminal completion ends the lease generation: nothing can resume
		// this journal afterwards, so it is removed on every exit path. A
		// cleanup failure is reported but never fails the job (the records
		// are pruned when a later generation of the job opens its journal).
		defer func() {
			if rerr := journal.remove(); rerr != nil {
				fmt.Fprintf(os.Stderr, "kiwi runner %s: remove log journal for %s: %v\n", r.ID, t.Job.ID, rerr)
			}
		}()
	}
	sink := newJournaledAsyncLogSink(consoleSink, r.logBatchPost(t, masker), journal)
	// The workspace quota outcome is reported on the job's own log: a job
	// that runs without a hard bound (trusted without a declaration, or the
	// documented operator escape hatch) should say so, and a blocked hard
	// bound must never hide behind the step-boundary measurement.
	if workspaceQuota != nil {
		sink.WriteLine(cj.ID, "workspace", "disk quota: "+workspaceQuota.Detail)
	}
	// Distributed runs resolve secrets exclusively through the control
	// plane's lease-bound delivery endpoint. Host env/Keychain providers
	// are local-CLI-only (app.RunLocal keeps that chain); the runner never
	// falls back to them, so a job without a lease gets no secrets at all.
	var provider secrets.Provider
	if t.LeaseToken != "" {
		provider = &secretbroker.RemoteProvider{
			Server:          r.Cfg.Server,
			Token:           r.Cfg.Token,
			JobID:           t.Job.ID,
			LeaseToken:      t.LeaseToken,
			LeaseGeneration: t.LeaseGeneration,
			RunnerID:        r.ID,
			Client:          r.Client,
		}
	}
	cacheStore := r.newJobCache(t, r.Metrics)
	// Distributed artifact packaging is a TEMPORARY, budgeted publication
	// path, never the persistent local artifact store: the archive lives only
	// through capture -> attest -> upload -> cleanup, is bounded by
	// min(the global 8 GiB blob ceiling, the declaration's max_size), and
	// every archive's full size is charged to the runner-wide staging budget
	// BEFORE the first byte is written. That closes the escape where a
	// distributed job could accumulate unbounded archives under CacheRoot
	// outside the workspace quota (resources.disk and the XFS project quota
	// cover the workspace, not the runner's artifact tree).
	var (
		artifactStore *artifact.Store
		captureDir    string
	)
	if len(cj.Job.Artifacts) > 0 {
		d, derr := os.MkdirTemp(r.Cfg.WorkDir, "kiwi-artifacts-"+t.Job.ID+"-*")
		if derr != nil {
			r.complete(parent, t, model.StatusFailure, fmt.Errorf("artifact capture directory: %w", derr), nil)
			return
		}
		captureDir = d
		// The capture directory is per job and always removed; a leftover
		// only survives a hard runner crash, exactly like a job workspace.
		defer func() {
			if rerr := os.RemoveAll(captureDir); rerr != nil {
				fmt.Fprintf(os.Stderr, "kiwi runner %s: remove artifact capture dir %s: %v\n", r.ID, captureDir, rerr)
			}
		}()
		artifactStore = &artifact.Store{Root: captureDir}
	}
	// In-job artifact delivery runs under the DECLARED JOB LIFETIME, not the
	// process lifetime: a job that exceeds its timeout must not keep
	// uploading an artifact (and holding its runner slot) after its lease
	// stopped being renewed.
	reporter := func(_ string, name, path string) error {
		return r.uploadArtifactWithAttestations(ctx, t, cj, name, path)
	}
	// Distributed runs always start from the clean env (InheritEnv is left
	// false and no PassEnv allowlist is set); untrusted jobs additionally
	// require image references pinned by digest. The untrusted floor is
	// unconditional here: nothing may override RequireImmutableImages for
	// an untrusted job.
	opts := executor.Options{Workspace: tmp, RunID: t.Job.RunID, Event: t.Job.Event, Branch: branchFromRef(t.Job.Ref), ChangedFiles: resolvedChangedFiles, SecretProvider: provider, Logs: logging.Func(func(job, step, line string) { sink.WriteLine(job, step, line) }), Cache: cacheStore, Artifacts: artifactStore, ArtifactReporter: reporter, DependencyStatus: t.Job.DependencyStatus, NeedsOutputs: t.Job.NeedsOutputs, CacheNamespace: cacheNamespace(t.Job), RequireImmutableImages: !t.Job.Trusted, LifecycleContext: parent}
	if artifactStore != nil {
		// Capture is bounded by the job context while it is alive (so a job
		// that exceeds its declared lifetime stops publishing) and by the
		// runner context otherwise; the executor builds the cancellation-time
		// fallback itself from LifecycleContext.
		opts.ArtifactCapture = &executor.ArtifactCapture{
			Context:  ctx,
			MaxBytes: runnerArtifactMaxBytes,
			Reserve:  r.artifactCaptureReserve(),
		}
	}
	// The declared resources.disk is the job's workspace bound: it feeds the
	// executor's pre-execution free-space check and the container backend's
	// step-boundary workspace check, and it is what the snapshot capture
	// derives its local archive cap from (see uploadJobSnapshot). The
	// authoritative source is the persisted t.Job.DiskRequest (what the
	// scheduler reserved); the compiled job's declaration is the fallback
	// for legacy control planes that did not persist resource requests.
	// Untrusted jobs without a declaration get the mandatory executor default
	// budget instead of zero, so an undeclared disk can never mean
	// "unbounded" for a job the runner does not trust. Trusted jobs without a
	// declaration keep the documented zero (unbounded) behavior.
	declaredDisk := workspaceMaxBytesForResources(cj.Job.Resources)
	if t.Job.DiskRequest > 0 {
		declaredDisk = t.Job.DiskRequest
	}
	workspaceMaxBytes := executor.WorkspaceBoundBytes(declaredDisk, untrusted, executor.DefaultUntrustedWorkspaceMaxBytes)
	opts.WorkspaceMaxBytes = workspaceMaxBytes
	opts.WorkspaceAvailabilityChecked = availabilityChecked
	opts.Untrusted = untrusted
	// Production untrusted policy: the step-boundary resources.disk check is
	// not a security boundary, so an untrusted job whose workspace cannot get
	// a hard OS-level bound (project quota) fails closed. The escape hatch is
	// the documented operator switch for trusted-only/self-hosted runners.
	// The bound itself was already installed (or its absence recorded) above,
	// before checkout: the container backend consumes the outcome as defense
	// in depth and never re-probes when execute reported one.
	opts.RequireUntrustedDiskQuota = requireDiskQuota
	opts.WorkspaceQuota = workspaceQuota
	// Step durations come from the executor's wall-clock step measurements
	// (StepReporter), never from sink-derived log timing.
	applyStepReporter(&opts, r.Metrics)
	// P2-30 generate wiring: a successful job whose effective compiled job
	// declares generate.path produced a downstream child-graph fragment in
	// the workspace. The executor reads it through the job's live backend
	// session (no-follow on native, docker exec on container, ssh on tart)
	// with a hard 256 KiB cap and hands it to this hook for upload under the
	// active lease with the deterministic fragment_id derived from the
	// parsed fragment. A fragment that cannot be safely read fails the job
	// in the executor; a non-2xx upload response (the control plane may
	// reject per policy/caps/depth) fails the job too, unless the compiled
	// job declared generate.optional=true, in which case the executor keeps
	// the error as a warning and the completion proceeds. A replayed upload
	// (same fragment_id under the same lease generation) is answered with
	// the originally created children.
	opts.GenerateUpload = func(jobID, path string, data []byte) error {
		// Generated-fragment delivery is part of the job (the executor fails
		// the job when it cannot be uploaded), so it runs under the declared
		// job lifetime exactly like a normal artifact upload.
		if err := r.uploadGeneratedFragmentData(ctx, t, path, data); err != nil {
			return err
		}
		sink.WriteLine(jobID, "generate", "generated fragment uploaded from "+path)
		return nil
	}
	// The options are final here: report them to the test seam before the
	// executor takes ownership.
	if executorOptionsSeam != nil {
		executorOptionsSeam(opts)
	}
	ex := executor.Executor{Opt: opts, Masker: masker}
	res := ex.RunCompiledJob(ctx, spec, cj)
	// Post-job finalization (test-report delivery, snapshot upload) runs on
	// an explicitly bounded grace derived from the RUNNER context, not the
	// job context: a job whose deadline just expired still gets a short
	// chance to deliver its final intelligence (the job's cancellation is a
	// child of parent, so it cannot reach this context), but the grace has
	// its own wall-clock bound and a runner shutdown still aborts it. The
	// previous code used the unbounded runner context directly, so a wedged
	// delivery could hold the runner slot for as long as it liked.
	// Terminal completion has an even shorter internal bound (see complete).
	finalizeCtx, finalizeCancel := context.WithTimeout(parent, r.finalizeTimeout())
	defer finalizeCancel()
	if len(cj.Job.TestReports) > 0 {
		// Mask with the same masker the log path uses before the report is
		// persisted and later served by the ordinary read tier. Masker.Mask
		// takes its RWMutex read lock, so sharing it here is safe even while
		// the executor registers more secrets.
		report, er := testintel.AggregateMasked(tmp, cj.Job.TestReports, masker.MaskMulti)
		if er != nil {
			sink.WriteLine(cj.ID, "tests", "report warning: "+er.Error())
		} else if report.Tests > 0 {
			// The shared size contract is checked BEFORE any upload attempt:
			// buildTestReportDelivery serializes the exact /tests body and
			// rejects it against the same limits the parser and the server
			// use, so an oversized report is warned about locally instead of
			// being sent to be rejected (or worse, silently truncated).
			delivery, derr := buildTestReportDelivery(t.Job.ID, t.LeaseGeneration, r.ID, t.LeaseToken, report)
			if derr != nil {
				sink.WriteLine(cj.ID, "tests", "report warning: "+derr.Error())
			} else {
				// Durable delivery: the body carries the stable delivery ID
				// derived from (job, lease generation, payload digest), so
				// the server can deduplicate a replay. A dropped response or
				// a transient failure no longer discards the intelligence:
				// the report is retried with the identical delivery ID until
				// success, a permanent rejection (4xx) or the bounded attempt
				// budget. Retries are safe by construction — the server
				// answers an identical replay idempotently without
				// re-folding history, and a reused ID with different content
				// is an explicit 409. A permanent failure is only WARNED
				// about (never retried, never fatal to the job): the report
				// is advisory intelligence and its loss must not turn a
				// finished job into a failure, but the warning makes the
				// permanent rejection visible in the job log.
				er = retryDelivery(finalizeCtx, func() error {
					return r.post(finalizeCtx, "/api/v1/jobs/"+t.Job.ID+"/tests", delivery.Body, nil)
				})
				if er != nil {
					sink.WriteLine(cj.ID, "tests", "upload warning: "+er.Error())
				}
			}
		}
	}
	// CaptureSnapshots is the master switch; when set, the job's
	// snapshot.on declaration governs which outcomes are captured (an empty
	// on captures every outcome).
	if r.Cfg.CaptureSnapshots && snapshotRequested(cj.Job.Snapshot, res.Status) {
		snapStart := time.Now()
		if err := r.uploadJobSnapshot(finalizeCtx, t, tmp, workspaceMaxBytes); err != nil {
			sink.WriteLine(cj.ID, "snapshot", "upload warning: "+err.Error())
		} else {
			r.Metrics.Observe("kiwi_runner_snapshot_duration_seconds", time.Since(snapStart).Seconds())
		}
	}
	// Finish the log sender before reporting the result: unsent, dropped or
	// failed lines make the job fail explicitly rather than completing clean,
	// and the final sender state is inspected only AFTER it has stopped (a
	// late in-flight failure must still count).
	outcome := sink.Finish(10 * time.Second)
	var runErr error
	if res.Error != "" {
		runErr = fmt.Errorf("%s", res.Error)
	}
	status := res.Status
	if outcome.Dropped > 0 || outcome.Remaining > 0 || outcome.Err != nil || !outcome.Stopped {
		detail := ""
		if outcome.Dropped > 0 {
			detail += fmt.Sprintf("%d log lines dropped (control plane too slow)", outcome.Dropped)
		}
		if outcome.Remaining > 0 {
			if detail != "" {
				detail += "; "
			}
			detail += fmt.Sprintf("%d log lines unsent at completion", outcome.Remaining)
		}
		if !outcome.Stopped {
			if detail != "" {
				detail += "; "
			}
			detail += "log sender did not stop within the completion deadline"
		}
		if outcome.Err != nil {
			if detail != "" {
				detail += "; "
			}
			detail += "log delivery error: " + outcome.Err.Error()
		}
		if runErr != nil {
			runErr = fmt.Errorf("%w; %s", runErr, detail)
		} else {
			runErr = fmt.Errorf("%s", detail)
		}
		if status == model.StatusSuccess {
			status = model.StatusFailure
		}
	}
	r.complete(parent, t, status, runErr, res.Outputs)
}

// logBatchPost is the async sink's delivery callback for one immutable
// batch. ONE batched request per drain: per-line posts cannot keep up and
// force the spool to overflow on chatty builds. The callback posts on the
// ctx it receives from the sink (never the job's parent context), so
// Finish's cancellation aborts an in-flight HTTP request. HTTP failures are
// classified by type: 4xx-class responses are permanent and fail the batch
// immediately, 5xx and transport errors stay retryable. Because the batch
// identity was assigned once by the sink, every retry carries the identical
// BatchID and BatchSequence and the server's receipt can dedupe it.
func (r *Runner) logBatchPost(t server.Task, masker *secrets.Masker) func(context.Context, logBatch) error {
	return func(ctx context.Context, batch logBatch) error {
		out := make([]server.LogLine, 0, len(batch.Lines))
		for _, l := range batch.Lines {
			out = append(out, server.LogLine{RunnerID: r.ID, LeaseToken: t.LeaseToken, LeaseGeneration: t.LeaseGeneration, JobKey: l.Job, Step: l.Step, Line: masker.MaskMulti(l.Line)})
		}
		var body struct {
			RunnerID        string           `json:"runner_id"`
			LeaseToken      string           `json:"lease_token"`
			LeaseGeneration int64            `json:"lease_generation"`
			BatchID         string           `json:"batch_id"`
			BatchSequence   int64            `json:"batch_sequence"`
			Lines           []server.LogLine `json:"lines"`
		}
		body.RunnerID = r.ID
		body.LeaseToken = t.LeaseToken
		body.LeaseGeneration = t.LeaseGeneration
		body.BatchSequence = batch.Sequence
		body.BatchID = batch.ID
		body.Lines = out
		err := r.post(ctx, "/api/v1/jobs/"+t.Job.ID+"/log/batch", body, nil)
		var httpErr *HTTPStatusError
		if errors.As(err, &httpErr) && permanentHTTPStatus(httpErr.StatusCode) {
			return PermanentDeliveryError(err)
		}
		return err
	}
}

// checkShardAssignment verifies the compile-time shard contract: the// control plane compiles tests.shards = N (N > 1) into N jobs whose env
// carries KIWI_TEST_SHARD_TOTAL and KIWI_TEST_SHARD_INDEX. A compiled job
// missing the assignment is a configuration error, not something the runner
// can reconstruct at runtime.
// checkCapability enforces the runner-side capability intersection through
// the SAME predicate the control plane uses (storage.RuntimeAllowed): a job
// whose runtime (default native) is outside the runner's effective
// (discovered ∩ profile) set is refused before execution when the server
// declared the set authoritative. An enforced but EMPTY intersection denies
// every runtime — including the default native runtime (empty runtime) —
// because an empty claim means "run nothing", never "no restriction". A
// legacy server response without capabilities_enforced leaves the runner
// unrestricted.
func (r *Runner) checkCapability(runtimeName string) error {
	if storage.RuntimeAllowed(r.effectiveCapabilities, r.capEnforced, runtimeName) {
		return nil
	}
	if runtimeName == "" {
		runtimeName = "native"
	}
	return fmt.Errorf("runtime %q is outside this runner's profile capability intersection", runtimeName)
}

func checkShardAssignment(cj pipeline.CompiledJob) error {
	if cj.Job.Tests.Shards <= 1 {
		return nil
	}
	total := cj.Job.Env["KIWI_TEST_SHARD_TOTAL"]
	index := cj.Job.Env["KIWI_TEST_SHARD_INDEX"]
	if total == "" || index == "" {
		return fmt.Errorf("compiled job lacks shard assignment: %q declares tests.shards=%d without KIWI_TEST_SHARD_TOTAL/KIWI_TEST_SHARD_INDEX", cj.ID, cj.Job.Tests.Shards)
	}
	return nil
}

// applyEffectiveNetwork computes the minimal network policy for a payload
// compiled job: the job's own request (sandbox.network, or network "none")
// intersected with the payload's effective policy ceiling. A request that
// exceeds the ceiling is refused; a default request (no explicit egress
// declaration) inherits the ceiling. The result is written into the
// compiled job's sandbox.network, which the executor backend derives
// isolation from.
func applyEffectiveNetwork(cj *pipeline.CompiledJob, caps policy.Capabilities) error {
	requested := requestedNetworkPolicy(cj.Job)
	ceiling := caps.Network
	if ceiling == pipeline.NetworkPolicyDefault {
		ceiling = pipeline.NetworkPolicyInternet
	}
	if requested != pipeline.NetworkPolicyDefault && networkPolicyStrength(requested) > networkPolicyStrength(ceiling) {
		return fmt.Errorf("job requests network %s which exceeds the compiled policy ceiling %s", networkPolicyName(requested), networkPolicyName(ceiling))
	}
	effective := pipeline.NetworkPolicyDefault
	if networkPolicyStrength(requested) < networkPolicyStrength(ceiling) {
		effective = requested
	} else if ceiling != pipeline.NetworkPolicyInternet {
		effective = ceiling
	}
	if effective != pipeline.NetworkPolicyDefault {
		cj.Job.Sandbox.Network = effective
	}
	return nil
}

// requestedNetworkPolicy mirrors the policy engine's derivation of the
// network a job requests: an explicit sandbox.network declaration,
// NetworkPolicyNone for network "none", and NetworkPolicyDefault otherwise.
func requestedNetworkPolicy(j pipeline.Job) pipeline.NetworkPolicy {
	if j.Network == "none" {
		return pipeline.NetworkPolicyNone
	}
	return j.Sandbox.Network
}

// networkPolicyStrength orders network policies for least-privilege
// comparison: None < ServicesOnly < Internet, with Default compared as
// Internet.
func networkPolicyStrength(p pipeline.NetworkPolicy) int {
	switch p {
	case pipeline.NetworkPolicyNone:
		return 0
	case pipeline.NetworkPolicyServicesOnly:
		return 1
	default:
		return 2
	}
}

func networkPolicyName(p pipeline.NetworkPolicy) string {
	switch p {
	case pipeline.NetworkPolicyNone:
		return "none"
	case pipeline.NetworkPolicyServicesOnly:
		return "services-only"
	case pipeline.NetworkPolicyInternet:
		return "internet"
	default:
		return "default"
	}
}

// checkoutTask provisions the job workspace: the default git checkout or
// the configured replacement.
func (r *Runner) checkoutTask(ctx context.Context, j model.Job, dir string) error {
	if r.Cfg.CheckoutFn != nil {
		return r.Cfg.CheckoutFn(ctx, j, dir)
	}
	return r.checkout(ctx, j, dir)
}

func (r *Runner) heartbeatLoop(ctx context.Context, cancel context.CancelFunc, t server.Task, done <-chan struct{}) {
	interval := r.Cfg.Heartbeat
	if interval <= 0 {
		interval = 10 * time.Second
	}
	// The interval must stay comfortably below the control-plane lease
	// duration so the pre-emptive self-cancel never fires on a healthy
	// connection.
	if interval > 15*time.Second {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	deadline := t.LeaseExpiresAt
	if deadline.IsZero() {
		deadline = time.Now().Add(30 * time.Second)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case now := <-ticker.C:
			var out server.HeartbeatResponse
			err := r.post(ctx, "/api/v1/jobs/"+t.Job.ID+"/heartbeat", server.Heartbeat{RunnerID: r.ID, LeaseToken: t.LeaseToken, LeaseGeneration: t.LeaseGeneration}, &out)
			var cancelNow bool
			deadline, cancelNow = heartbeatTick(now, deadline, &out, err)
			if cancelNow {
				cancel()
				return
			}
		}
	}
}

// heartbeatTick decides the next lease deadline and whether the job must be
// cancelled now. When the control plane is unreachable the deadline is not
// extended, so a job self-cancels before its lease expires and the control
// plane can safely requeue it. A confirmed response may only EXTEND the
// deadline: a stale, zero or regressed LeaseExpiresAt must never shorten it,
// or the runner would self-cancel a job whose lease the control plane still
// considers valid, and the requeue would execute it a second time.
func heartbeatTick(now, deadline time.Time, resp *server.HeartbeatResponse, err error) (time.Time, bool) {
	if now.Add(2 * time.Second).After(deadline) {
		return deadline, true
	}
	if err != nil {
		return deadline, false
	}
	if resp != nil && resp.Cancel {
		return deadline, true
	}
	if resp != nil && resp.LeaseExpiresAt.After(deadline) {
		return resp.LeaseExpiresAt, false
	}
	return deadline, false
}

func statusForErr(ctx context.Context, err error) model.Status {
	if ctx.Err() != nil {
		return model.StatusCancelled
	}
	_ = err
	return model.StatusFailure
}
func cacheNamespace(j model.Job) string {
	trust := "untrusted"
	if j.Trusted {
		trust = "trusted"
	}
	// The namespace identity is the CANONICAL repository (PolicyRepoID when
	// set, otherwise the RepoID derivation from the checkout URL): the clone
	// URL is transport only, so HTTPS/SSH/default-port spellings of one
	// repository share a namespace, and fork PRs use the base policy
	// identity the server already wraps around this key.
	id := storage.RepoIDForJob(j)
	sum := sha256.Sum256([]byte(id))
	return "repo:" + hex.EncodeToString(sum[:12]) + ":" + trust
}

func branchFromRef(ref string) string {
	return strings.TrimPrefix(strings.TrimPrefix(ref, "refs/heads/"), "refs/")
}
func effectiveChangedFiles(ctx context.Context, serverFiles []string, known bool, dir string) []string {
	// ChangedFilesKnown marks the server-side list as the authoritative
	// forge-fetched diff: it is returned as-is, so a known-EMPTY list stays
	// empty (no local git fallback). The fallback applies only when the
	// server did not authoritatively know the diff.
	if known {
		return append([]string{}, serverFiles...)
	}
	if len(serverFiles) > 0 {
		return append([]string{}, serverFiles...)
	}
	return changedFiles(ctx, dir)
}

// changedFiles is the local git fallback for changed-file discovery. It runs
// under the setup-phase context (exec.CommandContext, never a bare
// exec.Command): a git process that stalls must be torn down by the phase
// deadline instead of hanging the job's setup forever.
func changedFiles(ctx context.Context, dir string) []string {
	b, err := exec.CommandContext(ctx, "git", "-C", dir, "diff", "--name-only", "HEAD~1", "HEAD").Output()
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range strings.Split(string(b), "\n") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (r *Runner) checkout(ctx context.Context, j model.Job, dir string) error {
	gitEnv, err := gitEnvForRepo(j.RepoURL, os.Environ())
	if err != nil {
		return err
	}
	args := []string{"clone", "--filter=blob:none", "--no-checkout", j.RepoURL, dir}
	cmdClone := exec.CommandContext(ctx, "git", args...)
	cmdClone.Env = gitEnv
	if out, err := cmdClone.CombinedOutput(); err != nil {
		return fmt.Errorf("git clone: %v: %s", err, out)
	}
	ref := j.Ref
	if j.SHA != "" {
		ref = j.SHA
	}
	if ref == "" {
		ref = "HEAD"
	}
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "checkout", "--force", ref)
	cmd.Env = gitEnv
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git checkout: %v: %s", err, out)
	}
	return nil
}

// gitEnvForRepo builds the environment for git clone/checkout commands from
// a repo URL. It rejects URLs that could exfiltrate credentials or trick git
// options, strips KIWI_GIT_TOKEN_* values from the environment entirely, and
// injects host-scoped (never global) Authorization config for https clones.
func gitEnvForRepo(repoURL string, osEnv []string) ([]string, error) {
	if strings.HasPrefix(repoURL, "-") {
		return nil, fmt.Errorf("refusing git repo URL that looks like an option: %q", repoURL)
	}
	// Shared strict parser: the runner accepts exactly the forms the control
	// plane admits (including scp-style git@host:owner/repo), so a URL Kiwi
	// authorized can always be cloned.
	host, _, scheme, err := giturl.ParseCloneURL(repoURL)
	if err != nil {
		return nil, fmt.Errorf("refusing repo URL: %w", err)
	}
	switch scheme {
	case "https":
		allowed := append([]string{"github.com"}, splitCSV(os.Getenv(envAllowedHTTPSHosts))...)
		if !containsHost(allowed, host) {
			return nil, fmt.Errorf("https clone from host %q is not allowed (see %s)", host, envAllowedHTTPSHosts)
		}
	case "ssh":
		allowed := append([]string{"github.com"}, splitCSV(os.Getenv(envAllowedSSHHosts))...)
		if !containsHost(allowed, host) {
			return nil, fmt.Errorf("ssh clone from host %q is not allowed (see %s)", host, envAllowedSSHHosts)
		}
	case "http":
		if !isLoopbackHost(host) || os.Getenv(envAllowInsecureClone) != "1" {
			return nil, fmt.Errorf("refusing insecure http clone from %q (loopback + %s=1 required)", host, envAllowInsecureClone)
		}
	default:
		return nil, fmt.Errorf("unsupported clone URL scheme %q", scheme)
	}

	// Copy the environment, stripping every KIWI_GIT_TOKEN_* value so deploy
	// tokens never leak into the job environment.
	out := make([]string, 0, len(osEnv)+3)
	for _, kv := range osEnv {
		if strings.HasPrefix(kv, "KIWI_GIT_TOKEN_") {
			continue
		}
		out = append(out, kv)
	}
	if scheme == "https" {
		// Exact-host token match: KIWI_GIT_TOKEN_<HOST with . and - mapped
		// to _>. The git config is scoped to this host only.
		tokenVar := "KIWI_GIT_TOKEN_" + strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(host))
		if token := os.Getenv(tokenVar); token != "" {
			out = append(out,
				"GIT_CONFIG_COUNT=1",
				"GIT_CONFIG_KEY_0=http.https://"+host+"/.extraHeader",
				"GIT_CONFIG_VALUE_0=Authorization: Bearer "+token,
			)
		}
	}
	return out, nil
}

func isLoopbackHost(host string) bool {
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

func containsHost(list []string, host string) bool {
	for _, h := range list {
		if h = strings.TrimSpace(h); h != "" && h == host {
			return true
		}
	}
	return false
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// ErrDependencyArtifactTooLarge reports that a dependency artifact body
// exceeded the runner's hard spool cap. The transfer fails closed before
// extraction and the spool file is removed.
var ErrDependencyArtifactTooLarge = errors.New("dependency artifact exceeds maximum size")

// dependencyArtifactMaxBytes is the hard cap on a spooled dependency body.
// It mirrors the server's authoritative per-object maximum (8 GiB) so a
// peer cannot make the runner spool an unbounded stream. It is a variable so
// tests can lower the bound.
var dependencyArtifactMaxBytes int64 = 8 << 30

// runnerArtifactMaxBytes is the global per-artifact capture ceiling for
// distributed jobs: it mirrors the server's blob maximum (8 GiB), which the
// control plane enforces regardless of what the pipeline declares. A
// variable so tests can lower the bound.
var runnerArtifactMaxBytes int64 = 8 << 30

// defaultStagingMaxBytes is the built-in runner staging budget used when the
// operator configures none: exactly one maximum-size dependency artifact. It
// is conservative by design — maximum-sized spools serialize instead of
// multiplying the runner's unbudgeted scratch footprint — while smaller
// restores still stream concurrently. Operators that want more concurrent
// large restores raise --staging-max-bytes.
const defaultStagingMaxBytes int64 = 8 << 30

// defaultSetupTimeout bounds the pre-execution setup phase (workspace
// checkout through dependency restore) for jobs whose persisted JobTimeout is
// unset (legacy records). See Config.SetupTimeout.
const defaultSetupTimeout = 15 * time.Minute

// dependencySpoolRoot resolves the ROOT under which the runner's staging
// budget is created. Explicitly: staging.dir when configured, otherwise the
// runner-owned cache root, then the configured work dir, then the system
// temp dir. The budget itself owns <root>/<runner instance id> (see
// newStagingBudget), so two runners sharing a root never share a ledger.
func (r *Runner) dependencySpoolRoot() string {
	if r.Cfg.CacheRoot != "" {
		return r.Cfg.CacheRoot
	}
	if r.Cfg.WorkDir != "" {
		return r.Cfg.WorkDir
	}
	return os.TempDir()
}

// runnerStagingInstanceID derives the runner's stable staging instance id
// from its identity: distinct runners get distinct <root>/<id> directories
// (no ErrStagingDirOwned collision when they share a root), and a restarted
// runner reclaims the spool files its dead predecessor left in its own
// directory. The derivation is deterministic and path-safe for any runner id
// (persisted identity ids are not guaranteed to satisfy the staging
// instance-id charset).
func runnerStagingInstanceID(id string) string {
	sum := sha256.Sum256([]byte("runner-staging:" + id))
	return "runner-" + hex.EncodeToString(sum[:8])
}

// desiredStagingMaxBytes resolves the runner-wide staging bound: a
// configured StagingMaxBytes wins; otherwise the default is one maximum-size
// artifact.
func (r *Runner) desiredStagingMaxBytes() int64 {
	maxBytes := r.Cfg.StagingMaxBytes
	if maxBytes <= 0 {
		maxBytes = dependencyArtifactMaxBytes
		if maxBytes <= 0 {
			maxBytes = defaultStagingMaxBytes
		}
	}
	return maxBytes
}

// newStagingBudget constructs the runner-wide bounded spool budget. The
// configured StagingDir (or the resolved spool root) is a ROOT: the budget
// owns <root>/<instance id>, takes its exclusive ownership lock, and
// reclaims the spool files a dead predecessor left behind.
func (r *Runner) newStagingBudget() (*staging.Budget, error) {
	root := strings.TrimSpace(r.Cfg.StagingDir)
	if root == "" {
		root = r.dependencySpoolRoot()
	}
	b, err := staging.NewReplicaBudget(root, runnerStagingInstanceID(r.ID), r.desiredStagingMaxBytes())
	if err != nil {
		return nil, fmt.Errorf("staging: %w", err)
	}
	return b, nil
}

// configureStaging constructs and installs the runner-wide staging budget.
// Run calls it exactly once, before any job can be leased, so a job can
// never observe a runner without its bounded spool. When a previous Run's
// shutdown could not retire the ledger (cleanup debt remained), the OPEN
// budget is deliberately retained on the runner: a restart with the SAME
// bound reuses that exact ledger (maintenance keeps retrying its debt), and a
// restart with a DIFFERENT bound fails with a clear error instead of
// deadlocking against the retained directory lock. Only a budget whose
// ownership was retired is ever replaced.
func (r *Runner) configureStaging() error {
	maxBytes := r.desiredStagingMaxBytes()
	r.stagingMu.Lock()
	defer r.stagingMu.Unlock()
	if existing := r.staging; existing != nil {
		if existing.MaxBytes() != maxBytes {
			return fmt.Errorf("staging ownership retained with a %d-byte bound; requested %d: reuse requires the same bound while cleanup debt remains (or process exit)", existing.MaxBytes(), maxBytes)
		}
		return nil
	}
	b, err := r.newStagingBudget()
	if err != nil {
		return err
	}
	r.staging = b
	return nil
}

// dependencyStaging returns the runner-wide staging budget, constructing it
// lazily when Run has not (direct execute callers in tests). Concurrent
// first calls converge on one budget: the lock covers construction, and the
// staging package's process-wide registry returns the same ledger for the
// same directory and bound.
func (r *Runner) dependencyStaging() (*staging.Budget, error) {
	r.stagingMu.Lock()
	defer r.stagingMu.Unlock()
	if r.staging != nil {
		return r.staging, nil
	}
	b, err := r.newStagingBudget()
	if err != nil {
		return nil, err
	}
	r.staging = b
	return b, nil
}

// setupPhaseTimeout resolves the fallback setup-phase ceiling (see
// Config.SetupTimeout).
func (r *Runner) setupPhaseTimeout() time.Duration {
	if r.Cfg.SetupTimeout > 0 {
		return r.Cfg.SetupTimeout
	}
	return defaultSetupTimeout
}

// artifactCaptureReserve returns the executor's ArtifactCapture.Reserve hook
// wired to the runner-wide staging budget. Each capture reserves its full
// bound before the archive is created; the returned finalize callback owns
// BOTH the physical deletion and the ledger release, so a removal failure
// keeps the bytes charged as cleanup debt (retried by the staging
// maintenance pass) instead of silently freeing accounting while the file
// still occupies disk.
func (r *Runner) artifactCaptureReserve() func(ctx context.Context, n int64) (func(string) error, error) {
	return func(rctx context.Context, n int64) (func(string) error, error) {
		budget, berr := r.dependencyStaging()
		if berr != nil {
			return nil, berr
		}
		res, aerr := budget.Acquire(rctx, n)
		if aerr != nil {
			return nil, aerr
		}
		return func(path string) error {
			if path == "" {
				// No archive was produced: just release the charge.
				res.Release()
				return nil
			}
			// The manifest is small and a failure to remove it leaves an
			// orphan that a same-key save overwrites; the archive is what the
			// staging ledger charges. Remove both, then hand the reservation
			// to CleanupSpool: it releases only when the archive is actually
			// gone and otherwise keeps the bytes charged as cleanup debt.
			_ = artifact.RemoveCaptured(path)
			if budget.CleanupSpool(path, res) {
				return nil
			}
			return fmt.Errorf("staging cleanup of %s failed; bytes remain charged as cleanup debt", path)
		}, nil
	}
}

// finalizeTimeout resolves the post-job finalization bound (see
// Config.FinalizeTimeout).
func (r *Runner) finalizeTimeout() time.Duration {
	if r.Cfg.FinalizeTimeout > 0 {
		return r.Cfg.FinalizeTimeout
	}
	return defaultFinalizeTimeout
}

// currentStaging returns the runner-wide staging budget, or nil when none has
// been constructed (and after a successful shutdown hand-off).
func (r *Runner) currentStaging() *staging.Budget {
	r.stagingMu.Lock()
	defer r.stagingMu.Unlock()
	return r.staging
}

// maintainStaging retries dependency-spool cleanup debt: every spool whose
// removal failed after its bytes were no longer needed stays charged (and
// counted by Used()) until RetryCleanup finally removes it. Without this
// periodic pass a single transient unlink failure permanently consumed
// staging capacity — with the default one-artifact budget, one 8 GiB spool
// that could not be unlinked would wedge every future maximum-size restore
// for the life of the runner. The failure counter and the
// kiwi_runner_staging_pending_cleanup gauge are the observable degraded
// condition. The pass is cheap when there is no debt (an empty snapshot plus
// one mutex acquisition).
func (r *Runner) maintainStaging(ctx context.Context) {
	st := r.currentStaging()
	if st == nil {
		return
	}
	removed, err := st.RetryCleanup(ctx)
	if removed > 0 {
		reportf("kiwi runner %s: staging cleanup reclaimed %d spool file(s)\n", r.ID, removed)
	}
	if err != nil {
		r.Metrics.Counter("kiwi_runner_staging_cleanup_failures_total", 1)
		reportf("kiwi runner %s: staging cleanup retry failed (pending=%d): %v\n", r.ID, st.PendingCleanup(), err)
	}
}

// closeStaging performs the orderly shutdown hand-off of the runner-wide
// staging ownership: after every owned goroutine has joined (no reservation
// can still be live), it makes one final cleanup-debt retry and then releases
// the directory ownership lock and the process-wide registry entry. Unlike
// the control plane's process-lifetime budget, the runner has explicit
// in-process restart semantics, so ownership follows the Run lifecycle. A
// hand-off blocked by cleanup debt deliberately RETAINS the OPEN budget (it
// stays registered, the ledger intact, and NOT transitioned to CLOSING)
// rather than releasing a directory whose bytes are still charged; process
// exit drops the lock, and a successor Run in the same process reuses the
// same open ledger, continuing its maintenance until the debt clears and a
// later shutdown retires it.
func (r *Runner) closeStaging() {
	st := r.currentStaging()
	if st == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), stagingCloseGrace)
	defer cancel()
	if _, err := st.RetryCleanup(ctx); err != nil {
		reportf("kiwi runner %s: staging cleanup before close: %v\n", r.ID, err)
	}
	// CloseWithContext transitions the budget to CLOSING BEFORE it waits, and
	// it cannot complete while cleanup debt remains. Calling it with debt
	// would therefore leave a CLOSED budget still holding the directory
	// lock; the process registry deliberately ignores closed budgets, so an
	// in-process restart would construct a fresh budget and deadlock against
	// the retained lock with ErrStagingDirOwned. Retention must instead keep
	// the ledger OPEN and registered: configureStaging reuses it and the
	// staging maintenance pass keeps retrying the debt.
	if used := st.Used(); used != 0 {
		reportf("kiwi runner %s: staging ownership retained: %d byte(s) still charged (%d cleanup item(s)); the next Run reuses this ledger\n", r.ID, used, st.PendingCleanup())
		return
	}
	if err := closeStagingBudget(st, ctx); err != nil {
		reportf("kiwi runner %s: staging close: %v (ownership release failed; process exit drops the lock)\n", r.ID, err)
		// CloseWithContext has already transitioned the budget to CLOSING
		// (and finalized it when it reached the release step): it can never
		// become the OPEN retained ledger a restart reuses, and keeping the
		// pointer would make configureStaging "reuse" a closed ledger whose
		// Acquire fails with ErrClosed. Drop the pointer so the next Run
		// constructs a fresh ledger; if the directory lock actually leaked,
		// that construction fails loudly with ErrStagingDirOwned instead of
		// handing out reservations against retired state.
		r.stagingMu.Lock()
		if r.staging == st {
			r.staging = nil
		}
		r.stagingMu.Unlock()
		return
	}
	r.stagingMu.Lock()
	if r.staging == st {
		r.staging = nil
	}
	r.stagingMu.Unlock()
}

// restoreDownloads fetches the job's declared dependency artifacts through
// the lease-bound dependency endpoint (GET /api/v1/jobs/{id}/dependencies/
// {producer}/{artifact}) — never through the run-level artifact list API.
// Only declared (producer, artifact) pairs are fetched: the server rejects
// undeclared downloads, and the runner never enumerates run artifacts to
// pick by name. Matrix producers follow the compiled Downloads semantics:
// From may name a BaseKey or a compiled Key and is passed through verbatim.
//
// The workspace root is opened once (no-follow) and every destination is
// resolved component-wise beneath that held handle, so a symlink left by a
// checkout can never redirect an extraction outside the workspace.
func (r *Runner) restoreDownloads(ctx context.Context, t server.Task, inputs []pipeline.ArtifactInput, workspace string) error {
	if len(inputs) == 0 {
		return nil
	}
	wsRoot, err := safefs.OpenWorkspaceRoot(workspace)
	if err != nil {
		return fmt.Errorf("downloads: open workspace root: %w", err)
	}
	defer wsRoot.Close()
	for _, in := range inputs {
		rel, err := safeDownloadDest(in.Path)
		if err != nil {
			return err
		}
		producer := strings.TrimSpace(in.From)
		name := strings.TrimSpace(in.Name)
		if producer == "" || name == "" {
			return fmt.Errorf("invalid download declaration (from=%q name=%q)", in.From, in.Name)
		}
		if err := r.restoreDownload(ctx, t, producer, name, rel, wsRoot.Root); err != nil {
			return err
		}
	}
	return nil
}

// restoreDownload fetches and extracts one declared dependency artifact. The
// body is spooled through the runner-wide staging budget: the exact size
// (Content-Length) is reserved BEFORE the first byte is downloaded, or the
// hard per-artifact cap when the peer sends a chunked/unknown-length body,
// so several concurrent downstream restores can never stage more than the
// configured bound outside every job workspace quota. The reservation is
// held through extraction (the compressed file is physically present until
// extraction completes) and released with the file on every path; extraction
// resolves rel beneath the held workspace root so a symlinked ancestor is
// rejected instead of traversed.
func (r *Runner) restoreDownload(ctx context.Context, t server.Task, producer, name, rel string, wsRoot *safefs.Root) error {
	url := r.Cfg.Server + "/api/v1/jobs/" + t.Job.ID + "/dependencies/" + url.PathEscape(producer) + "/" + url.PathEscape(name)
	reqCtx, cancel := context.WithCancel(ctx)
	guard := newStallGuard(cancel, streamIdleTimeout.get())
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		guard.stop()
		cancel()
		return err
	}
	r.auth(req)
	req.Header.Set("X-Kiwi-Runner-ID", r.ID)
	req.Header.Set("X-Kiwi-Lease-Token", t.LeaseToken)
	req.Header.Set("X-Kiwi-Lease-Generation", fmt.Sprint(t.LeaseGeneration))
	resp, err := r.streamClient().Do(req)
	if err != nil {
		guard.stop()
		cancel()
		return err
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		guard.stop()
		cancel()
		return fmt.Errorf("download dependency %s from %s: %s: %s", name, producer, resp.Status, strings.TrimSpace(string(b)))
	}
	body := &stallGuardedBody{ReadCloser: resp.Body, guard: guard, cancel: cancel}
	limit := dependencyArtifactMaxBytes
	if limit <= 0 {
		limit = defaultStagingMaxBytes
	}
	if resp.ContentLength > limit {
		body.Close()
		return fmt.Errorf("%w: content length %d exceeds limit %d", ErrDependencyArtifactTooLarge, resp.ContentLength, limit)
	}
	budget, err := r.dependencyStaging()
	if err != nil {
		body.Close()
		return err
	}
	// Reserve EXACTLY what the spool may occupy before a byte is written: the
	// advertised Content-Length when known, otherwise the hard per-artifact
	// cap (the worst case a chunked peer can produce). Acquire blocks while
	// the runner-wide budget is exhausted; it runs on the job/setup context,
	// so a declared job timeout (or the legacy setup ceiling) still bounds
	// the wait. The returned reservation is held through extraction and
	// released with the spool file.
	reserve := limit
	if resp.ContentLength >= 0 {
		reserve = resp.ContentLength
	}
	res, err := budget.Acquire(ctx, reserve)
	if err != nil {
		body.Close()
		return err
	}
	h := sha256.New()
	staged, n, spoolErr := budget.SpoolFile(io.TeeReader(body, h), reserve)
	body.Close()
	if spoolErr != nil {
		res.Release()
		if errors.Is(spoolErr, staging.ErrTooLarge) || n > reserve {
			return fmt.Errorf("%w: limit %d bytes", ErrDependencyArtifactTooLarge, reserve)
		}
		return spoolErr
	}
	// The spool file exists until CleanupSpool removes it; CleanupSpool
	// releases the reservation only when the file is actually gone. A failed
	// removal keeps the bytes charged as cleanup debt that the runner's
	// 30-second staging maintenance retries (RetryCleanup); the failure is
	// counted and reported here so the degraded state is observable before
	// the retry succeeds.
	defer func() {
		if budget.CleanupSpool(staged, res) {
			return
		}
		r.Metrics.Counter("kiwi_runner_staging_cleanup_failures_total", 1)
		reportf("kiwi runner %s: dependency spool cleanup for job %s failed; bytes stay charged until a staging retry reclaims %s\n", r.ID, t.Job.ID, staged)
	}()
	if want := resp.Header.Get("X-Kiwi-Content-SHA256"); want != "" {
		if got := hex.EncodeToString(h.Sum(nil)); got != want {
			return fmt.Errorf("artifact %s from %s integrity mismatch", name, producer)
		}
	}
	if err := artifact.Extract(staged, wsRoot, rel); err != nil {
		return err
	}
	return nil
}

// safeDownloadDest validates a declared download path and returns the
// workspace-relative destination (cleaned, no traversal). The result must be
// resolved through a held workspace root (safefs.OpenRootBeneath); it is
// never a filesystem path by itself. It rejects portable-absolute paths,
// parent traversal and backslashes/absolute paths that filepath.Clean would
// otherwise hide.
func safeDownloadDest(inPath string) (string, error) {
	if inPath == "" {
		return "", nil
	}
	clean := filepath.Clean(inPath)
	if pipeline.IsPortableAbsPath(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || strings.ContainsRune(clean, '\\') {
		return "", fmt.Errorf("unsafe download path %q", inPath)
	}
	if clean == "." {
		return "", nil
	}
	return filepath.ToSlash(clean), nil
}

// uploadArtifact delivers one captured artifact archive with bounded
// redelivery. The control plane identifies an upload by (job, lease
// generation, name) and answers a same-digest replay from its existing
// record, so retrying a dropped response can neither duplicate nor corrupt
// the artifact.
func (r *Runner) uploadArtifact(ctx context.Context, t server.Task, name, path string) error {
	if st, serr := os.Stat(path); serr == nil {
		r.Metrics.Counter("kiwi_runner_artifact_bytes", float64(st.Size()))
	}
	return retryDelivery(ctx, func() error { return r.putArtifact(ctx, t, name, path) })
}

// putArtifact performs one artifact PUT attempt. The archive is reopened on
// every attempt because the request body is the file itself. It runs on the
// streaming client (no total timeout) with a sliding inactivity guard, so an
// 8 GiB archive completes at any sustainable rate while a stalled peer is
// still torn down.
func (r *Runner) putArtifact(ctx context.Context, t server.Task, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	url := r.Cfg.Server + "/api/v1/jobs/" + t.Job.ID + "/artifacts/" + name
	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	guard := newStallGuard(cancel, streamIdleTimeout.get())
	defer guard.stop()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPut, url, &stallGuardReader{r: f, guard: guard})
	if err != nil {
		return err
	}
	r.auth(req)
	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("X-Kiwi-Runner-ID", r.ID)
	req.Header.Set("X-Kiwi-Lease-Token", t.LeaseToken)
	req.Header.Set("X-Kiwi-Lease-Generation", fmt.Sprint(t.LeaseGeneration))
	resp, err := r.streamClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("artifact upload %s: %w", resp.Status, &HTTPStatusError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(b))})
	}
	return nil
}

// complete delivers the terminal result with bounded redelivery. Completion
// is idempotent on the control plane: the receipt is keyed by (job, lease
// generation, runner) and the result hash, so a replay of the same result is
// acknowledged without re-accounting usage. A dropped response (the server
// committed but the runner never saw the 204) must therefore be retried:
// without the retry the job stays leased until expiry and is re-queued and
// re-executed even though it already finished.
func (r *Runner) complete(ctx context.Context, t server.Task, st model.Status, err error, outputs map[string]string) {
	// Complete receives the RUNNER context (every production caller passes
	// parent), never the job context, so there is no job cancellation to
	// strip here: a timed-out job still reports. Deriving directly from the
	// passed context keeps the two cancellations that matter correct —
	// runner shutdown/drain immediately aborts completion, while the
	// independent wall-clock grace keeps a healthy runner from pinning a
	// slot on a wedged control plane. (Stripping cancellation with
	// context.WithoutCancel would remove exactly the wrong one: shutdown.)
	completeCtx, cancel := context.WithTimeout(ctx, completionGrace)
	defer cancel()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	body := server.Complete{RunnerID: r.ID, LeaseToken: t.LeaseToken, LeaseGeneration: t.LeaseGeneration, Status: st, Error: msg, Outputs: outputs}
	_ = retryDelivery(completeCtx, func() error {
		return r.post(completeCtx, "/api/v1/jobs/"+t.Job.ID+"/complete", body, nil)
	})
}

// deliveryAttempts bounds the redelivery of an idempotent lease-bound
// request (job completion, artifact upload) whose commit may have succeeded
// even though its acknowledgement was lost. The request identity is
// deterministic (completion receipt; artifact name under the lease
// generation), so a replay is deduplicated server-side.
const deliveryAttempts = 5

// retryableDeliveryError reports whether an idempotent delivery failure may
// be retried: transport errors (the commit may have landed even though the
// response did not) and transient HTTP responses (5xx, 408, 429). Permanent
// 4xx responses and request-construction failures cannot be fixed by a
// replay and are returned immediately.
func retryableDeliveryError(err error) bool {
	if err == nil {
		return false
	}
	var httpErr *HTTPStatusError
	if errors.As(err, &httpErr) {
		return !permanentHTTPStatus(httpErr.StatusCode)
	}
	var urlErr *url.Error
	return errors.As(err, &urlErr)
}

// retryDelivery runs deliver with bounded exponential backoff + jitter until
// it succeeds, fails permanently, the attempts are exhausted, or ctx is
// cancelled. It returns the last delivery error.
func retryDelivery(ctx context.Context, deliver func() error) error {
	backoff := 100 * time.Millisecond
	var err error
	for attempt := 0; attempt < deliveryAttempts; attempt++ {
		if attempt > 0 {
			jitter := time.Duration(time.Now().UnixNano() % int64(backoff/2+1))
			select {
			case <-time.After(backoff + jitter):
			case <-ctx.Done():
				return err
			}
			backoff *= 2
			if backoff > 2*time.Second {
				backoff = 2 * time.Second
			}
		}
		if err = deliver(); err == nil || !retryableDeliveryError(err) || ctx.Err() != nil {
			return err
		}
	}
	return err
}

// testReportDelivery is one rendered /tests request: the exact body bytes,
// the stable delivery ID they carry and the payload digest the ID is derived
// from. The body is rendered ONCE and re-sent byte-identically on retries,
// so the delivery ID and the payload can never disagree.
type testReportDelivery struct {
	Body       json.RawMessage
	DeliveryID string
	Digest     string
}

// buildTestReportDelivery renders the /tests request body for one aggregated
// report and checks it against the SHARED size contract
// (internal/testintel/limits.go) before any upload is attempted. The
// delivery ID is sha256(jobID, lease generation, canonical payload digest),
// which is exactly the durable-delivery identity the server records next to
// the report, so retrying a dropped response can neither duplicate the report
// nor fold its history twice.
func buildTestReportDelivery(jobID string, leaseGeneration int64, runnerID, leaseToken string, report model.TestReport) (testReportDelivery, error) {
	// The shared validator enforces the same case/message/payload budget the
	// parser and the server apply, so an over-limit report is rejected here
	// with the same reason string, before any upload attempt.
	if err := testintel.ValidateReportPayload(report); err != nil {
		return testReportDelivery{}, err
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return testReportDelivery{}, fmt.Errorf("test report serialization: %w", err)
	}
	digest := testintel.ReportContentDigest(payload)
	deliveryID := testintel.ReportDeliveryID(jobID, leaseGeneration, digest)
	body, err := json.Marshal(map[string]any{
		"runner_id":        runnerID,
		"lease_token":      leaseToken,
		"lease_generation": leaseGeneration,
		"delivery_id":      deliveryID,
		"content_digest":   digest,
		"report":           json.RawMessage(payload),
	})
	if err != nil {
		return testReportDelivery{}, fmt.Errorf("test report request serialization: %w", err)
	}
	if len(body) > testintel.MaxTestReportRequestBytes {
		return testReportDelivery{}, fmt.Errorf("%w: /tests request body is %d bytes, over the %d-byte request budget", testintel.ErrLimitExceeded, len(body), testintel.MaxTestReportRequestBytes)
	}
	return testReportDelivery{Body: body, DeliveryID: deliveryID, Digest: digest}, nil
}

// snapshotRequested reports whether the job's snapshot declaration captures
// this final status. An empty snapshot.on captures every outcome; a
// non-empty list captures only the listed final status strings
// (success/failure/cancelled). The caller applies CaptureSnapshots as the
// master switch before consulting this predicate.
func snapshotRequested(s pipeline.SnapshotSpec, st model.Status) bool {
	if len(s.On) == 0 {
		return true
	}
	for _, o := range s.On {
		if strings.EqualFold(strings.TrimSpace(o), string(st)) {
			return true
		}
	}
	return false
}

// generatedFragment is the POST /api/v1/jobs/{id}/generated body: the child
// graph a generator produced, shared with the control plane so the
// deterministic fragment id is derived from the identical parsed shape on
// both sides.
type generatedFragment = v1.GeneratedFragment

// uploadGeneratedFragmentData parses the generator's fragment (already read
// through the job's live backend session by the executor, bounded and
// no-follow) and POSTs it to /api/v1/jobs/{id}/generated under the active
// lease. The body carries the deterministic fragment_id derived from the
// parsed {jobs, deps} pair: the control plane recomputes it and rejects a
// mismatch (400), and a replayed upload with the same (job, lease
// generation, fragment_id) is answered idempotently with the originally
// created child IDs, so a lost response never duplicates children. A non-2xx
// response is returned as an error; the executor fails the job unless the
// job declared generate.optional=true.
func (r *Runner) uploadGeneratedFragmentData(ctx context.Context, t server.Task, path string, data []byte) error {
	clean := filepath.Clean(path)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
		return fmt.Errorf("generate.path %q escapes the workspace", path)
	}
	var frag generatedFragment
	if err := json.Unmarshal(data, &frag); err != nil {
		return fmt.Errorf("parse generated fragment %q: %w", path, err)
	}
	fid, err := frag.Digest()
	if err != nil {
		return fmt.Errorf("fragment id for %q: %w", path, err)
	}
	frag.FragmentID = fid
	body, err := json.Marshal(frag)
	if err != nil {
		return fmt.Errorf("encode generated fragment: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Cfg.Server+"/api/v1/jobs/"+t.Job.ID+"/generated", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	r.auth(req)
	req.Header.Set("X-Kiwi-Runner-ID", r.ID)
	req.Header.Set("X-Kiwi-Lease-Token", t.LeaseToken)
	req.Header.Set("X-Kiwi-Lease-Generation", fmt.Sprint(t.LeaseGeneration))
	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("generated fragment upload: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// post sends one JSON request to the control plane. The body is encoded
// before any request is created, and an encoding failure is returned as a
// real error (wrapped with the endpoint for context): a payload the JSON
// encoder rejects (for example a NaN/Inf float) must never reach the wire as
// a malformed request, and no request is sent at all.
func (r *Runner) post(ctx context.Context, path string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("encode request body for %s: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Cfg.Server+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	r.auth(req)
	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bb, _ := io.ReadAll(resp.Body)
		return &HTTPStatusError{StatusCode: resp.StatusCode, Body: string(bb)}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// HTTPStatusError is returned by r.post for a non-2xx control-plane
// response. The typed status lets callers classify failures (permanent vs
// retryable, disabled/revoked) instead of parsing the error string.
type HTTPStatusError struct {
	StatusCode int
	Body       string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("%d %s: %s", e.StatusCode, http.StatusText(e.StatusCode), e.Body)
}

// permanentHTTPStatus classifies an HTTP status for delivery: 4xx-class
// failures are permanent (retrying cannot help) except 408 Request Timeout
// and 429 Too Many Requests, which are transient. 5xx and everything else
// stay retryable.
func permanentHTTPStatus(code int) bool {
	return code >= 400 && code < 500 && code != http.StatusRequestTimeout && code != http.StatusTooManyRequests
}
func unique(in []string) []string {
	m := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, x := range in {
		if x != "" && !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	return out
}

// containsString reports whether list contains v.
func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// isHTTPStatus reports whether err was produced by r.post failing with the
// given status; classification is typed (HTTPStatusError), never string
// parsing.
func isHTTPStatus(err error, status int) bool {
	var httpErr *HTTPStatusError
	return errors.As(err, &httpErr) && httpErr.StatusCode == status
}
func (r *Runner) auth(req *http.Request) {
	if r.Cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.Cfg.Token)
	}
}

// resolveIdentityDir defaults the identity directory to ~/.kiwi/runner
// when enrollment is active and installs the identity store on the runner.
// Without enrollment (or an explicit IdentityDir) the store stays empty and
// the disabled/revoked path leaves the filesystem alone.
func (r *Runner) resolveIdentityDir() {
	if r.Cfg.IdentityDir == "" && r.Cfg.EnrollToken != "" {
		home, _ := os.UserHomeDir()
		r.Cfg.IdentityDir = filepath.Join(home, ".kiwi", "runner")
	}
	if r.Cfg.IdentityDir != "" {
		r.store = IdentityStore{Dir: r.Cfg.IdentityDir}
	}
}

// resolveStateDir resolves the runner's durable state directory (home of the
// log batch journal). Precedence: an explicit StateDir, then the cache root
// (tests and deployments that already provision it), then the identity
// directory, and finally ~/.kiwi. It returns an explicit error when no
// durable directory can be determined: the production entry path (Run) must
// fail closed rather than silently running without the journal. Callers that
// invoke execute directly (tests) opt out explicitly via journalOptOut.
func (r *Runner) resolveStateDir() error {
	if r.Cfg.StateDir != "" {
		return nil
	}
	if r.Cfg.CacheRoot != "" {
		r.Cfg.StateDir = r.Cfg.CacheRoot
		return nil
	}
	if r.Cfg.IdentityDir != "" {
		r.Cfg.StateDir = r.Cfg.IdentityDir
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("runner state directory: %w", err)
	}
	if home == "" {
		return errors.New("runner state directory: no StateDir, CacheRoot, IdentityDir or HOME is configured; refusing to run without the durable log journal")
	}
	r.Cfg.StateDir = filepath.Join(home, ".kiwi")
	return nil
}

// openJobLogJournal opens the durable batch journal for one job lease
// generation. A missing state directory is an explicit error on the
// production path; the journalOptOut seam is the only way execute can run
// journal-less, and tests that call execute directly set it deliberately.
func (r *Runner) openJobLogJournal(jobID string, generation int64, mask func(string) string) (*logJournal, error) {
	if r.Cfg.StateDir == "" {
		if !r.journalOptOut {
			return nil, errors.New("runner state directory is not resolved: refusing to run without the durable log journal")
		}
		return nil, nil
	}
	return openLogJournal(filepath.Join(r.Cfg.StateDir, "log-journal"), jobID, generation, mask)
}

// prepareClient builds the mTLS HTTP client when certificate material or an
// enrollment token is configured. Without any of them the client stays nil
// (plain HTTP dev mode). Certificate-bearing configurations require an https
// server URL.
func (r *Runner) prepareClient(ctx context.Context) error {
	r.resolveIdentityDir()
	if r.Cfg.CACert == "" && r.Cfg.Cert == "" && r.Cfg.Key == "" && r.Cfg.EnrollToken == "" {
		return nil
	}
	u, err := url.Parse(r.Cfg.Server)
	if err != nil {
		return fmt.Errorf("invalid server URL %q: %w", r.Cfg.Server, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("runner certificates require an https server URL, got %q", r.Cfg.Server)
	}
	caPEM, err := loadPEM(r.Cfg.CACert)
	if err != nil {
		return fmt.Errorf("runner CA certificate: %w", err)
	}
	certPEM, err := loadPEM(r.Cfg.Cert)
	if err != nil {
		return fmt.Errorf("runner certificate: %w", err)
	}
	keyPEM, err := loadPEM(r.Cfg.Key)
	if err != nil {
		return fmt.Errorf("runner key: %w", err)
	}
	if (len(certPEM) == 0) != (len(keyPEM) == 0) {
		return fmt.Errorf("runner certificate and key must be provided together")
	}
	if len(certPEM) == 0 && r.Cfg.EnrollToken != "" {
		// Persistent bootstrap: a persisted identity whose certificate
		// still has enough remaining validity is reused verbatim (no
		// enrollment, no new key). Otherwise the runner enrolls once under
		// a stable ID: the persisted runner-id is reused when present so
		// revocation/drain/audit history stays continuous, and only a
		// brand-new runner has no ID to reuse. The authoritative runner_id
		// from the enroll response is what gets persisted.
		id, complete := r.store.Load()
		if complete && id.CertUsable() {
			r.ID = id.ID
			certPEM, keyPEM = id.CertPEM, id.KeyPEM
			if len(caPEM) == 0 {
				caPEM = id.CACertPEM
			}
		} else {
			if id.ID != "" {
				r.ID = id.ID
			}
			if r.ID == "" {
				fresh, err := newRunnerID()
				if err != nil {
					return err
				}
				r.ID = fresh
			}
			newKey, csrPEM, err := runnerpki.GenerateKeyAndCSR(r.ID)
			if err != nil {
				return fmt.Errorf("generate enrollment key: %w", err)
			}
			enc, err := r.enroll(ctx, caPEM, csrPEM)
			if err != nil {
				return err
			}
			keyPEM = newKey
			certPEM = []byte(enc.Certificate)
			if len(caPEM) == 0 {
				caPEM = []byte(enc.CACertificate)
			}
			if authoritative := strings.TrimSpace(enc.RunnerID); authoritative != "" {
				r.ID = authoritative
			}
			if err := r.store.Save(Identity{ID: r.ID, KeyPEM: keyPEM, CertPEM: certPEM, CACertPEM: caPEM}); err != nil {
				return fmt.Errorf("persist runner identity: %w", err)
			}
		}
	}
	tlsConf, err := runnerpki.TLSClientConfig(certPEM, keyPEM, caPEM, r.serverName())
	if err != nil {
		return err
	}
	r.clientCertPEM = append([]byte(nil), certPEM...)
	// Both clients share one connection pool; only the per-client total
	// timeout differs (control bounded, streaming unbounded).
	transport := newStreamingTransport(tlsConf)
	r.Client = &http.Client{Timeout: controlClientTimeout, Transport: transport}
	r.StreamClient = &http.Client{Transport: transport}
	return nil
}

// applyClientPolicy installs the split control/streaming client policy on a
// runner whose clients were not already built by prepareClient. A caller-
// provided Client is preserved (its Timeout is the control bound) and the
// streaming client reuses its transport, so tests and embedders that inject
// one client keep exactly one connection pool.
// runGCPass reaps stale runtime resources and reports what was removed. The
// maintenance loop calls it on the GC interval; tests call it directly so the
// assertion does not depend on scheduler timing.
func (r *Runner) runGCPass(ctx context.Context) executor.GCReport {
	// The heavyweight runtime GC also covers staging cleanup and cache
	// retention as backstops; the dedicated 30s staging and 10m cache passes
	// are the primary cadences.
	r.maintainStaging(ctx)
	r.pruneJobCache(ctx)
	rep := executor.GC(ctx, r.Cfg.WorkDir, gcOlderThan)
	if rep.Containers > 0 || rep.Networks > 0 || rep.VMs > 0 {
		reportf("kiwi runner %s: gc removed %d containers, %d networks, %d VMs\n", r.ID, rep.Containers, rep.Networks, rep.VMs)
	}
	return rep
}

func (r *Runner) applyClientPolicy() {
	if r.Client == nil {
		r.Client = &http.Client{Timeout: controlClientTimeout}
	}
	if r.StreamClient != nil {
		return
	}
	var transport http.RoundTripper
	if r.Client.Transport != nil {
		transport = r.Client.Transport
	} else {
		// Install the phase-bounded transport on the control client too, so
		// both clients share one connection pool.
		transport = newStreamingTransport(nil)
		r.Client.Transport = transport
	}
	r.StreamClient = &http.Client{Transport: transport}
}

// newStreamingTransport builds the transport used by the streaming client
// (and shared by the control client for connection reuse). It has no
// whole-request bound but each phase is bounded: dial and TLS handshake, the
// wait for response headers, and idle pooled connections. A peer that cannot
// make any progress is torn down by these bounds (plus the per-request stall
// guard); a peer that keeps transferring is never cut by wall-clock time.
func newStreamingTransport(tlsConf *tls.Config) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	t.TLSHandshakeTimeout = 30 * time.Second
	t.ResponseHeaderTimeout = 60 * time.Second
	t.IdleConnTimeout = 90 * time.Second
	if tlsConf != nil {
		t.TLSClientConfig = tlsConf
	}
	return t
}

// streamClient returns the client for bulk streaming transfers. A runner
// constructed directly by tests without a StreamClient falls back to Client
// so the transfer stays bounded by that client's total timeout.
func (r *Runner) streamClient() *http.Client {
	if r.StreamClient != nil {
		return r.StreamClient
	}
	if r.Client != nil {
		return r.Client
	}
	return http.DefaultClient
}

// stallGuard cancels a streaming request's context when no byte has moved
// for streamIdleTimeout. It is armed at creation and re-armed by every
// successful transfer, so sustained progress keeps an arbitrarily large
// object alive for exactly as long as it needs while a peer that stops
// transferring is disconnected. The bound is expressed as a sliding idle
// window, never as a total transfer time.
type stallGuard struct {
	cancel context.CancelFunc
	idle   time.Duration
	timer  *time.Timer
}

func newStallGuard(cancel context.CancelFunc, idle time.Duration) *stallGuard {
	g := &stallGuard{cancel: cancel, idle: idle}
	g.timer = time.AfterFunc(idle, cancel)
	return g
}

// progress re-arms the inactivity timer after a successful transfer.
func (g *stallGuard) progress() {
	g.timer.Reset(g.idle)
}

// stop disarms the timer once the request has finished.
func (g *stallGuard) stop() {
	g.timer.Stop()
}

// stallGuardReader re-arms a stall guard on every successful read. It wraps
// upload bodies: when the transport stops pulling bytes (a stalled peer
// applying backpressure) the guard fires and cancels the request.
type stallGuardReader struct {
	r     io.Reader
	guard *stallGuard
}

func (g *stallGuardReader) Read(p []byte) (int, error) {
	n, err := g.r.Read(p)
	if n > 0 {
		g.guard.progress()
	}
	return n, err
}

// stallGuardedBody wraps a streaming response body so a read-level stall
// cancels the request context. Close disarms the guard and releases the
// derived context.
type stallGuardedBody struct {
	io.ReadCloser
	guard  *stallGuard
	cancel context.CancelFunc
}

func (b *stallGuardedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.guard.progress()
	}
	return n, err
}

func (b *stallGuardedBody) Close() error {
	// The inner Close may still move bytes (a verifying reader drains the
	// remaining stream to validate its digest), so the stall guard and the
	// request context must stay armed until that drain returns: disarming
	// first would let a peer that stops sending hang Close forever.
	defer b.cancel()
	defer b.guard.stop()
	return b.ReadCloser.Close()
}

// enroll requests a runner certificate for r.ID in exchange for the
// enrollment token, using a client that only trusts caPEM.
func (r *Runner) enroll(ctx context.Context, caPEM, csrPEM []byte) (*server.EnrollResponse, error) {
	if r.Cfg.EnrollToken == "" {
		return nil, fmt.Errorf("runner enrollment token is empty")
	}
	tlsConf, err := enrollTLSConfig(nil, nil, caPEM, r.serverName())
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConf}}
	b, err := json.Marshal(server.EnrollRequest{RunnerID: r.ID, CSR: base64.StdEncoding.EncodeToString(csrPEM), Labels: r.Cfg.EnrollLabels})
	if err != nil {
		return nil, fmt.Errorf("encode enrollment request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Cfg.Server+"/api/v1/runners/enroll", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.Cfg.EnrollToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bb, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("enroll: %s: %s", resp.Status, bb)
	}
	var out server.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *Runner) serverName() string {
	if r.Cfg.ServerName != "" {
		return r.Cfg.ServerName
	}
	if u, err := url.Parse(r.Cfg.Server); err == nil {
		return u.Hostname()
	}
	return ""
}

// loadPEM accepts PEM contents directly or a path to a PEM file.
func loadPEM(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	if strings.Contains(v, "-----BEGIN") {
		return []byte(v), nil
	}
	return os.ReadFile(v)
}

// newRunnerID returns a 128-bit crypto/rand identifier hex-encoded. The
// runner generates its own stable-per-process identity for enrollment.
func newRunnerID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// validateServerURL rejects plaintext-HTTP control-plane URLs that are not
// loopback: runner tokens are bearer credentials and must not travel
// unencrypted off-host. KIWI_RUNNER_ALLOW_INSECURE=1 bypasses the check with
// a warning for explicitly trusted networks.
func validateServerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid server URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("server URL %q must use http or https", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		return nil
	}
	if os.Getenv(envRunnerAllowInsec) == "1" {
		fmt.Printf("warning: connecting to non-loopback server %q over plaintext HTTP (KIWI_RUNNER_ALLOW_INSECURE=1)\n", raw)
		return nil
	}
	return fmt.Errorf("refusing plaintext HTTP to non-loopback server %q: use https:// or set KIWI_RUNNER_ALLOW_INSECURE=1", raw)
}
