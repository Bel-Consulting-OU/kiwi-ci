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
	"time"

	v1 "github.com/Bel-Consulting-OU/kiwi-ci/internal/api/v1"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/artifact"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
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
)

// ErrRunnerDisabledOrRevoked reports that the control plane has disabled
// this runner or revoked its certificate: the runner must be re-enrolled
// with fresh credentials and must not loop re-registering.
var ErrRunnerDisabledOrRevoked = errors.New("runner disabled or certificate revoked; re-enroll required")

// RunnerVersion is the software version reported at registration and can be
// overridden at build time via -ldflags.
var RunnerVersion = "dev"

// Seams over the standard library used by the runner. Production behavior is
// unchanged; they let checked failure branches be exercised deterministically:
// closeRunnerTempFile covers os.File.Close failures (matching the
// internal/cache closeCacheFile seam), randReader covers identifier-generation
// failures (matching the internal/provenance randReader seam), and
// enrollTLSConfig covers the enrollment TLS configuration so a hermetic test
// can reach the server-CA fallback without a system-trusted listener
// certificate.
var (
	closeRunnerTempFile           = (*os.File).Close
	randReader          io.Reader = rand.Reader
	enrollTLSConfig               = runnerpki.TLSClientConfig
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
	// is disconnected. Production uses this value; the variable is a test
	// seam.
	streamIdleTimeout = 90 * time.Second
)

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
	// never enlarge it. capEnforced reports whether the server declared a
	// profile capability claim: a response carrying the capabilities key
	// (even an explicit empty list or null) is authoritative, so an empty
	// intersection denies every runtime instead of meaning "no
	// restriction". Legacy servers without profiles omit the key entirely
	// and leave capEnforced false.
	effectiveCapabilities []string
	capEnforced           bool
	// journalOptOut is the explicit seam that lets a caller of execute run
	// WITHOUT the durable log journal: only direct test callers that do not
	// resolve a state directory set it (testRunnerFor does). Run never sets
	// it, so the production path always fails closed when no state
	// directory can be resolved.
	journalOptOut bool
}

// registerResponse is the register reply. Capabilities is decoded as raw
// JSON so the runner can distinguish an ABSENT key (legacy pre-profile
// server: no claim) from a present-but-empty list or null (an explicit
// profile claim that grants nothing, which is an authoritative deny-all
// ceiling rather than a missing restriction).
type registerResponse struct {
	model.Runner
	Capabilities json.RawMessage `json:"capabilities"`
}

// decodeProfileCapabilities interprets the register response's capabilities
// field. claimed is true whenever the key is present at all: an explicit
// empty list or null yields a nil/empty list with claimed=true, which the
// runner turns into an enforced empty intersection.
func decodeProfileCapabilities(raw json.RawMessage) (caps []string, claimed bool, err error) {
	if raw == nil {
		return nil, false, nil
	}
	if err := json.Unmarshal(raw, &caps); err != nil {
		return nil, true, fmt.Errorf("capabilities claim: %w", err)
	}
	return caps, true, nil
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
	if r.Cfg.MetricsListen != "" {
		r.startMetricsServer(ctx)
	}
	prewarmer := newPrewarmer(r.Cfg)
	go prewarmer.run(ctx)
	lastPrewarm := time.Now()
	lastGC := time.Now()
	maint := maintenanceSchedule{GCInterval: r.Cfg.GCInterval, PrewarmInterval: r.Cfg.PrewarmInterval}
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
			task, drainSignal, err := r.next(ctx)
			if err != nil {
				if errors.Is(err, ErrRunnerDisabledOrRevoked) {
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
			go func(t server.Task) {
				r.execute(ctx, t)
				done <- struct{}{}
			}(*task)
		}
		if draining && active == 0 {
			fmt.Printf("kiwi runner %s drained: no active work, exiting\n", r.ID)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			active--
		case <-time.After(r.Cfg.Poll):
		}
		if gcDue, prewarmDue := maint.due(time.Now(), lastGC, lastPrewarm); gcDue || prewarmDue {
			if gcDue {
				lastGC = time.Now()
				go func() {
					rep := executor.GC(ctx, r.Cfg.WorkDir, gcOlderThan)
					if rep.Containers > 0 || rep.Networks > 0 || rep.VMs > 0 {
						reportf("kiwi runner %s: gc removed %d containers, %d networks, %d VMs\n", r.ID, rep.Containers, rep.Networks, rep.VMs)
					}
				}()
			}
			if prewarmDue {
				lastPrewarm = time.Now()
				go prewarmer.run(ctx)
			}
		}
	}
}

// startMetricsServer serves the Prometheus text metrics on the configured
// listen address for the runner's lifetime.
func (r *Runner) startMetricsServer(ctx context.Context) {
	srv := newMetricsServer(r.Cfg.MetricsListen, r.Metrics)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "kiwi runner metrics: %v\n", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
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
	// Capability intersection: the profile capabilities in the response
	// are the ceiling; the runner advertises (and enforces) only the
	// intersection with what this host actually discovered, so a job
	// requiring a runtime the host cannot provide never starts here. The
	// claim is enforced whenever the server sent the capabilities key at
	// all — an empty claim is an authoritative empty ceiling, not an
	// absent one, so the intersection may legitimately be empty and then
	// denies every runtime.
	profileCaps, claimed, err := decodeProfileCapabilities(out.Capabilities)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	r.capEnforced = claimed
	r.effectiveCapabilities = intersectStringLists(profileCaps, discovered)
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

// next polls for work. The boolean reports the server's drain signal
// (X-Kiwi-Draining on a 204): the runner is draining and should exit once
// its active slots are free. A disabled runner (X-Kiwi-Disabled) or a
// rejected identity (403 — certificate revoked) is a terminal
// ErrRunnerDisabledOrRevoked: the runner exits instead of re-polling.
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

func (r *Runner) execute(parent context.Context, t server.Task) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	done := make(chan struct{})
	go r.heartbeatLoop(ctx, cancel, t, done)
	defer close(done)

	tmp, err := os.MkdirTemp("", "kiwi-run-*")
	if err != nil {
		r.complete(parent, t, model.StatusFailure, err, nil)
		return
	}
	defer func() { _ = removeJobWorkspace(tmp) }()
	checkoutStart := time.Now()
	if err = r.checkoutTask(ctx, t.Job, tmp); err != nil {
		r.complete(parent, t, statusForErr(ctx, err), err, nil)
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
	if err := r.restoreDownloads(ctx, t, cj.Job.Downloads, tmp); err != nil {
		r.complete(parent, t, model.StatusFailure, err, nil)
		return
	}
	// The sink spools lines in memory and a dedicated sender drains them:
	// pipe readers must never block on control-plane delivery, so a slow log
	// endpoint cannot stall the drain and silently drop the tail. Overflow
	// and send failures are surfaced on completion (never a clean green job
	// with lost logs).
	consoleSink := logging.Func(func(job, step, line string) {
		fmt.Printf("[%s/%s] %s\n", job, step, masker.Mask(line))
	})
	// Durable batch journal: every batch is journaled (masked) and fsynced
	// before its first POST, unconditionally acked after the control plane
	// confirms it, and unconsumed records from a crashed earlier process for
	// this same lease generation are replayed with their original identities
	// before new lines are sent. Opening fails closed: a corrupt/unreadable
	// journal fails the job instead of silently dropping durable state.
	journal, jerr := r.openJobLogJournal(t.Job.ID, t.LeaseGeneration, masker.Mask)
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
	artifactStore := artifact.Default()
	if r.Cfg.CacheRoot != "" {
		artifactStore = &artifact.Store{Root: filepath.Join(r.Cfg.CacheRoot, "artifacts")}
	}
	reporter := func(_ string, name, path string) error {
		return r.uploadArtifactWithAttestations(parent, t, cj, name, path)
	}
	// Distributed runs always start from the clean env (InheritEnv is left
	// false and no PassEnv allowlist is set); untrusted jobs additionally
	// require image references pinned by digest. The untrusted floor is
	// unconditional here: nothing may override RequireImmutableImages for
	// an untrusted job.
	opts := executor.Options{Workspace: tmp, RunID: t.Job.RunID, Event: t.Job.Event, Branch: branchFromRef(t.Job.Ref), ChangedFiles: effectiveChangedFiles(t.Job.ChangedFiles, t.Job.ChangedFilesKnown, tmp), SecretProvider: provider, Logs: logging.Func(func(job, step, line string) { sink.WriteLine(job, step, line) }), Cache: cacheStore, Artifacts: artifactStore, ArtifactReporter: reporter, DependencyStatus: t.Job.DependencyStatus, NeedsOutputs: t.Job.NeedsOutputs, CacheNamespace: cacheNamespace(t.Job), RequireImmutableImages: !t.Job.Trusted}
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
		if err := r.uploadGeneratedFragmentData(parent, t, path, data); err != nil {
			return err
		}
		sink.WriteLine(jobID, "generate", "generated fragment uploaded from "+path)
		return nil
	}
	ex := executor.Executor{Opt: opts, Masker: masker}
	res := ex.RunCompiledJob(ctx, spec, cj)
	if len(cj.Job.TestReports) > 0 {
		report, er := testintel.Aggregate(tmp, cj.Job.TestReports)
		if er != nil {
			sink.WriteLine(cj.ID, "tests", "report warning: "+er.Error())
		} else if report.Tests > 0 {
			er = r.post(parent, "/api/v1/jobs/"+t.Job.ID+"/tests", map[string]any{"runner_id": r.ID, "lease_token": t.LeaseToken, "lease_generation": t.LeaseGeneration, "report": report}, nil)
			if er != nil {
				sink.WriteLine(cj.ID, "tests", "upload warning: "+er.Error())
			}
		}
	}
	// CaptureSnapshots is the master switch; when set, the job's
	// snapshot.on declaration governs which outcomes are captured (an empty
	// on captures every outcome).
	if r.Cfg.CaptureSnapshots && snapshotRequested(cj.Job.Snapshot, res.Status) {
		snapStart := time.Now()
		if err := r.uploadJobSnapshot(parent, t, tmp); err != nil {
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
			out = append(out, server.LogLine{RunnerID: r.ID, LeaseToken: t.LeaseToken, LeaseGeneration: t.LeaseGeneration, JobKey: l.Job, Step: l.Step, Line: masker.Mask(l.Line)})
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
// checkCapability enforces the runner-side capability intersection: when
// the register response declared a profile capability claim, a job whose
// runtime capability is not in the runner's effective (discovered ∩
// profile) set is refused before execution. An enforced but EMPTY
// intersection denies every runtime — including the default native runtime
// (empty runtime) — because an empty claim means "run nothing", never "no
// restriction". Without a claim (legacy server) every runtime is accepted.
func (r *Runner) checkCapability(runtime string) error {
	if !r.capEnforced {
		return nil
	}
	if runtime == "" {
		runtime = "native"
	}
	if !containsString(r.effectiveCapabilities, runtime) {
		return fmt.Errorf("runtime %q is outside this runner's profile capability intersection", runtime)
	}
	return nil
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
func effectiveChangedFiles(serverFiles []string, known bool, dir string) []string {
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
	return changedFiles(dir)
}
func changedFiles(dir string) []string {
	b, err := exec.Command("git", "-C", dir, "diff", "--name-only", "HEAD~1", "HEAD").Output()
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

// restoreDownloads fetches the job's declared dependency artifacts through
// the lease-bound dependency endpoint (GET /api/v1/jobs/{id}/dependencies/
// {producer}/{artifact}) — never through the run-level artifact list API.
// Only declared (producer, artifact) pairs are fetched: the server rejects
// undeclared downloads, and the runner never enumerates run artifacts to
// pick by name. Matrix producers follow the compiled Downloads semantics:
// From may name a BaseKey or a compiled Key and is passed through verbatim.
func (r *Runner) restoreDownloads(ctx context.Context, t server.Task, inputs []pipeline.ArtifactInput, workspace string) error {
	for _, in := range inputs {
		dest, err := safeDownloadDest(workspace, in.Path)
		if err != nil {
			return err
		}
		producer := strings.TrimSpace(in.From)
		name := strings.TrimSpace(in.Name)
		if producer == "" || name == "" {
			return fmt.Errorf("invalid download declaration (from=%q name=%q)", in.From, in.Name)
		}
		url := r.Cfg.Server + "/api/v1/jobs/" + t.Job.ID + "/dependencies/" + url.PathEscape(producer) + "/" + url.PathEscape(name)
		reqCtx, cancel := context.WithCancel(ctx)
		guard := newStallGuard(cancel, streamIdleTimeout)
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
		tmp, err := os.CreateTemp("", "kiwi-artifact-*.tar.gz")
		if err != nil {
			body.Close()
			return err
		}
		tmpPath := tmp.Name()
		h := sha256.New()
		_, cp := io.Copy(io.MultiWriter(tmp, h), body)
		body.Close()
		cl := closeRunnerTempFile(tmp)
		if cp != nil {
			os.Remove(tmpPath)
			return cp
		}
		if cl != nil {
			os.Remove(tmpPath)
			return cl
		}
		if want := resp.Header.Get("X-Kiwi-Content-SHA256"); want != "" {
			if got := hex.EncodeToString(h.Sum(nil)); got != want {
				os.Remove(tmpPath)
				return fmt.Errorf("artifact %s from %s integrity mismatch", name, producer)
			}
		}
		if err := artifact.Extract(tmpPath, dest); err != nil {
			os.Remove(tmpPath)
			return err
		}
		os.Remove(tmpPath)
	}
	return nil
}

// safeDownloadDest resolves a declared download path against the workspace
// and rejects anything that escapes it.
func safeDownloadDest(workspace, inPath string) (string, error) {
	dest := workspace
	if inPath != "" {
		clean := filepath.Clean(inPath)
		if pipeline.IsPortableAbsPath(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("unsafe download path %q", inPath)
		}
		dest = filepath.Join(workspace, clean)
	}
	return dest, nil
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
	guard := newStallGuard(cancel, streamIdleTimeout)
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
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	body := server.Complete{RunnerID: r.ID, LeaseToken: t.LeaseToken, LeaseGeneration: t.LeaseGeneration, Status: st, Error: msg, Outputs: outputs}
	_ = retryDelivery(ctx, func() error {
		return r.post(ctx, "/api/v1/jobs/"+t.Job.ID+"/complete", body, nil)
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
func (r *Runner) post(ctx context.Context, path string, in, out any) error {
	b, _ := json.Marshal(in)
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
	b.guard.stop()
	err := b.ReadCloser.Close()
	b.cancel()
	return err
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
	b, _ := json.Marshal(server.EnrollRequest{RunnerID: r.ID, CSR: base64.StdEncoding.EncodeToString(csrPEM), Labels: r.Cfg.EnrollLabels})
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
