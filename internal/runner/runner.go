package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/artifact"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
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
	EnrollToken string
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
	if err := r.prepareClient(ctx); err != nil {
		return err
	}
	if r.Client == nil {
		r.Client = &http.Client{Timeout: 65 * time.Second}
	}
	// Credential-bearing runner traffic must never follow redirects to a
	// different origin.
	r.Client = server.NoRedirectClient(r.Client)
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
						fmt.Printf("kiwi runner %s: gc removed %d containers, %d networks, %d VMs\n", r.ID, rep.Containers, rep.Networks, rep.VMs)
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
	capabilities := []string{"native"}
	if _, err := exec.LookPath("docker"); err == nil {
		labels = append(labels, "container")
		capabilities = append(capabilities, "container")
	}
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("tart"); err == nil {
			labels = append(labels, "tart")
			capabilities = append(capabilities, "tart")
		}
	}
	in := model.Runner{
		ID: r.ID, Name: r.Cfg.Name, Labels: unique(labels),
		Metadata:     map[string]string{"go": runtime.Version()},
		Capacity:     r.Cfg.Concurrency,
		ProtocolMin:  runnerProtocol,
		ProtocolMax:  runnerProtocol,
		Version:      RunnerVersion,
		Region:       os.Getenv(envRunnerRegion),
		Capabilities: capabilities,
		Draining:     r.Cfg.Drain,
	}
	var out model.Runner
	if err := r.post(ctx, "/api/v1/runners/register", in, &out); err != nil {
		if isHTTPStatus(err, http.StatusForbidden) {
			// 403 on registration means the runner was disabled or its
			// certificate serial was revoked: re-registering cannot clear
			// either and must not be retried.
			return fmt.Errorf("%w (server: %v)", ErrRunnerDisabledOrRevoked, err)
		}
		return err
	}
	r.ID = out.ID
	fmt.Printf("kiwi runner %s registered (%s/%s) labels=%s\n", r.ID, runtime.GOOS, runtime.GOARCH, strings.Join(out.Labels, ","))
	return nil
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
		return nil, false, ErrRunnerDisabledOrRevoked
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil, resp.Header.Get("X-Kiwi-Draining") == "true", nil
	}
	if resp.StatusCode == http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("%w (server: %s: %s)", ErrRunnerDisabledOrRevoked, resp.Status, strings.TrimSpace(string(b)))
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
	defer os.RemoveAll(tmp)
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
	sink := logging.Func(func(job, step, line string) {
		msg := masker.Mask(line)
		fmt.Printf("[%s/%s] %s\n", job, step, msg)
		_ = r.post(parent, "/api/v1/jobs/"+t.Job.ID+"/log", server.LogLine{RunnerID: r.ID, LeaseToken: t.LeaseToken, LeaseGeneration: t.LeaseGeneration, JobKey: job, Step: step, Line: msg}, nil)
	})
	provider := secrets.Chain{secrets.EnvProvider{Prefix: "KIWI_SECRET_"}, secrets.MacKeychainProvider{Service: "kiwi-ci"}}
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
	// require image references pinned by digest.
	opts := executor.Options{Workspace: tmp, RunID: t.Job.RunID, Event: t.Job.Event, Branch: branchFromRef(t.Job.Ref), ChangedFiles: effectiveChangedFiles(t.Job.ChangedFiles, tmp), SecretProvider: provider, Logs: logging.Func(func(job, step, line string) { sink.WriteLine(job, step, line) }), Cache: cacheStore, Artifacts: artifactStore, ArtifactReporter: reporter, DependencyStatus: t.Job.DependencyStatus, NeedsOutputs: t.Job.NeedsOutputs, CacheNamespace: cacheNamespace(t.Job), RequireImmutableImages: !t.Job.Trusted}
	// Step durations come from the executor's wall-clock step measurements
	// (StepReporter), never from sink-derived log timing.
	applyStepReporter(&opts, r.Metrics)
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
	if r.Cfg.CaptureSnapshots && res.Status != model.StatusSkipped && res.Status != model.StatusBlocked {
		snapStart := time.Now()
		if err := r.uploadJobSnapshot(parent, t, tmp); err != nil {
			sink.WriteLine(cj.ID, "snapshot", "upload warning: "+err.Error())
		} else {
			r.Metrics.Observe("kiwi_runner_snapshot_duration_seconds", time.Since(snapStart).Seconds())
		}
	}
	var runErr error
	if res.Error != "" {
		runErr = fmt.Errorf("%s", res.Error)
	}
	r.complete(parent, t, res.Status, runErr, res.Outputs)
}

// checkShardAssignment verifies the compile-time shard contract: the
// control plane compiles tests.shards = N (N > 1) into N jobs whose env
// carries KIWI_TEST_SHARD_TOTAL and KIWI_TEST_SHARD_INDEX. A compiled job
// missing the assignment is a configuration error, not something the runner
// can reconstruct at runtime.
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
// plane can safely requeue it.
func heartbeatTick(now, deadline time.Time, resp *server.HeartbeatResponse, err error) (time.Time, bool) {
	if now.Add(2 * time.Second).After(deadline) {
		return deadline, true
	}
	if err != nil {
		return deadline, false
	}
	if resp.Cancel {
		return deadline, true
	}
	return resp.LeaseExpiresAt, false
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
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(j.RepoURL))))
	return "repo:" + hex.EncodeToString(sum[:12]) + ":" + trust
}

func branchFromRef(ref string) string {
	return strings.TrimPrefix(strings.TrimPrefix(ref, "refs/heads/"), "refs/")
}
func effectiveChangedFiles(serverFiles []string, dir string) []string {
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
	u, err := url.Parse(repoURL)
	if err != nil {
		return nil, fmt.Errorf("invalid repo URL: %w", err)
	}
	// Embedded credentials are never accepted, except the conventional
	// username-only ssh form (git@host): a password in a URL always leaks.
	if u.User != nil {
		_, hasPass := u.User.Password()
		if u.Scheme != "ssh" || hasPass {
			return nil, fmt.Errorf("refusing repo URL with embedded credentials")
		}
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("refusing repo URL with query or fragment")
	}
	host := u.Hostname()
	switch u.Scheme {
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
	case "file", "git":
		return nil, fmt.Errorf("refusing %s clone URL", u.Scheme)
	default:
		return nil, fmt.Errorf("unsupported or missing clone URL scheme %q", u.Scheme)
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
	if u.Scheme == "https" {
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
func (r *Runner) restoreDownloads(ctx context.Context, t server.Task, inputs []pipeline.ArtifactInput, workspace string) error {
	if len(inputs) == 0 {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.Cfg.Server+"/api/v1/runs/"+t.Job.RunID+"/artifacts", nil)
	if err != nil {
		return err
	}
	r.auth(req)
	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("list artifacts %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var records []model.ArtifactRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return err
	}
	for _, in := range inputs {
		dest := workspace
		if in.Path != "" {
			clean := filepath.Clean(in.Path)
			if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
				return fmt.Errorf("unsafe download path %q", in.Path)
			}
			dest = filepath.Join(workspace, clean)
		}
		matches := 0
		for _, a := range records {
			base := a.JobKey
			if i := strings.IndexByte(base, '['); i >= 0 {
				base = base[:i]
			}
			if a.Name != in.Name || (a.JobKey != in.From && base != in.From) {
				continue
			}
			matches++
			tmp, err := os.CreateTemp("", "kiwi-artifact-*.tar.gz")
			if err != nil {
				return err
			}
			tmpPath := tmp.Name()
			h := sha256.New()
			url := r.Cfg.Server + "/api/v1/artifacts/" + a.ID
			dreq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err == nil {
				r.auth(dreq)
			}
			if err != nil {
				tmp.Close()
				os.Remove(tmpPath)
				return err
			}
			dresp, err := r.Client.Do(dreq)
			if err != nil {
				tmp.Close()
				os.Remove(tmpPath)
				return err
			}
			if dresp.StatusCode != 200 {
				b, _ := io.ReadAll(io.LimitReader(dresp.Body, 4096))
				dresp.Body.Close()
				tmp.Close()
				os.Remove(tmpPath)
				return fmt.Errorf("download artifact %s: %s: %s", a.Name, dresp.Status, strings.TrimSpace(string(b)))
			}
			_, cp := io.Copy(io.MultiWriter(tmp, h), dresp.Body)
			dresp.Body.Close()
			cl := tmp.Close()
			if cp != nil {
				os.Remove(tmpPath)
				return cp
			}
			if cl != nil {
				os.Remove(tmpPath)
				return cl
			}
			got := hex.EncodeToString(h.Sum(nil))
			if a.SHA256 != "" && got != a.SHA256 {
				os.Remove(tmpPath)
				return fmt.Errorf("artifact %s integrity mismatch", a.Name)
			}
			if err := artifact.Extract(tmpPath, dest); err != nil {
				os.Remove(tmpPath)
				return err
			}
			os.Remove(tmpPath)
		}
		if matches == 0 {
			return fmt.Errorf("required artifact %s from %s not found", in.Name, in.From)
		}
	}
	return nil
}

func (r *Runner) uploadArtifact(ctx context.Context, t server.Task, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if st, serr := f.Stat(); serr == nil {
		r.Metrics.Counter("kiwi_runner_artifact_bytes", float64(st.Size()))
	}
	url := r.Cfg.Server + "/api/v1/jobs/" + t.Job.ID + "/artifacts/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, f)
	if err != nil {
		return err
	}
	r.auth(req)
	req.Header.Set("Content-Type", "application/gzip")
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
		return fmt.Errorf("artifact upload %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func (r *Runner) complete(ctx context.Context, t server.Task, st model.Status, err error, outputs map[string]string) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	_ = r.post(ctx, "/api/v1/jobs/"+t.Job.ID+"/complete", server.Complete{RunnerID: r.ID, LeaseToken: t.LeaseToken, LeaseGeneration: t.LeaseGeneration, Status: st, Error: msg, Outputs: outputs}, nil)
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
		return fmt.Errorf("%s: %s", resp.Status, bb)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
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

// isHTTPStatus reports whether err was produced by r.post or a runner HTTP
// call failing with the given status (the error strings embed "STATUS
// TEXT").
func isHTTPStatus(err error, status int) bool {
	return err != nil && strings.HasPrefix(err.Error(), fmt.Sprintf("%d ", status))
}
func (r *Runner) auth(req *http.Request) {
	if r.Cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.Cfg.Token)
	}
}

// prepareClient builds the mTLS HTTP client when certificate material or an
// enrollment token is configured. Without any of them the client stays nil
// (plain HTTP dev mode). Certificate-bearing configurations require an https
// server URL.
func (r *Runner) prepareClient(ctx context.Context) error {
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
		// Ephemeral bootstrap: mint a fresh key, enroll it with the
		// enrollment token, and use the returned certificate for all
		// subsequent requests. The identity is per-process and stateless.
		newKey, csrPEM, err := runnerpki.GenerateKeyAndCSR(r.ID)
		if err != nil {
			return fmt.Errorf("generate enrollment key: %w", err)
		}
		keyPEM = newKey
		enc, err := r.enroll(ctx, caPEM, csrPEM)
		if err != nil {
			return err
		}
		certPEM = []byte(enc.Certificate)
		if len(caPEM) == 0 {
			caPEM = []byte(enc.CACertificate)
		}
	}
	tlsConf, err := runnerpki.TLSClientConfig(certPEM, keyPEM, caPEM, r.serverName())
	if err != nil {
		return err
	}
	r.Client = &http.Client{Timeout: 65 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConf}}
	return nil
}

// enroll requests a runner certificate for r.ID in exchange for the
// enrollment token, using a client that only trusts caPEM.
func (r *Runner) enroll(ctx context.Context, caPEM, csrPEM []byte) (*server.EnrollResponse, error) {
	if r.Cfg.EnrollToken == "" {
		return nil, fmt.Errorf("runner enrollment token is empty")
	}
	tlsConf, err := runnerpki.TLSClientConfig(nil, nil, caPEM, r.serverName())
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConf}}
	b, _ := json.Marshal(server.EnrollRequest{RunnerID: r.ID, CSR: base64.StdEncoding.EncodeToString(csrPEM)})
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
	if _, err := rand.Read(b); err != nil {
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
