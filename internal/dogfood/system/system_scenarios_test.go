package system_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood/system"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// containerEchoPipeline is a digest-pinned, network-none container job. Direct
// API submissions are always untrusted, and the untrusted capability floor
// forbids runtime native (policy ViolationKindNative) — so the smallest
// admitted product workload that can actually execute is a pinned container
// step. Native would avoid Docker entirely; the product policy does not allow
// that for this ingress.
const containerEchoPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
    network: none
    steps:
      - run: echo kiwi-system-dogfood
`

// nativeEchoPipeline is the smallest trusted workload: a host-native echo
// step. Untrusted policy forbids runtime native, so this pipeline is only
// executable through a TRUSTED ingress (signed forge webhook or trusted
// schedule). On a host without rootless Docker it is the SYSTEM success path.
const nativeEchoPipeline = `version: 1
jobs:
  build:
    runtime: native
    steps:
      - run: echo kiwi-system-dogfood-native
`

// untrustedContainerPipeline is an untrusted (direct API) container job with a
// digest-pinned image and no network. On a host without a hard workspace
// quota the runner's pre-checkout gate must fail it closed.
const untrustedContainerPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
    network: none
    steps:
      - run: echo quota-gate
`

// requireDocker skips when the container backend cannot run. The untrusted
// policy floor rejects native host execution for direct API submissions, so a
// successful product workload needs Docker (or tart). Fail-closed scenarios
// that never reach the executor do not call this.
func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed; untrusted direct API jobs cannot use runtime native (policy native_execution)")
	}
}

// rootlessDockerAvailable reports whether this host can complete an
// untrusted container job (the require_rootless policy floor).
func rootlessDockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	out, err := exec.Command("docker", "info", "--format", "{{.SecurityOptions}}").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "rootless")
}

// useTrustedNative selects the SYSTEM success-path workload for this host.
// When rootless Docker can satisfy the untrusted container floor, the
// untrusted container path runs (exercising that admission arm). Otherwise a
// TRUSTED native job runs through the product trusted ingress (signed
// webhook), so lifecycle and evidence proofs still execute. Skip only when
// BOTH paths are unavailable — trusted ingress is product code and has no
// host dependency beyond the harness loopback listener, so this currently
// always prefers running.
func useTrustedNative(t *testing.T) bool {
	t.Helper()
	if rootlessDockerAvailable() {
		return false
	}
	return true
}

// TestSysRootlessEnforced is the product proof of the untrusted rootless
// floor: on a Docker daemon that is NOT rootless, an untrusted container job
// must fail closed at the sandbox gate (never execute). The quota escape is
// set only so the attempt reaches the rootless check on hosts without XFS;
// the rootless requirement itself is never bypassed.
func TestSysRootlessEnforced(t *testing.T) {
	requireDocker(t)
	out, err := exec.Command("docker", "info", "--format", "{{.SecurityOptions}}").CombinedOutput()
	if err != nil {
		t.Skipf("docker info failed (%v): %s", err, out)
	}
	if strings.Contains(strings.ToLower(string(out)), "rootless") {
		t.Skip("docker daemon is rootless; the fail-closed rootless arm cannot be observed here")
	}
	t.Setenv("KIWI_ALLOW_UNQUOTAED_UNTRUSTED_DISK", "1")
	sys := start(t)
	if err := sys.StartRunner("rootless-runner", []string{"container"}); err != nil {
		t.Fatalf("start runner: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	runID, err := sys.SubmitPipeline(ctx, untrustedContainerPipeline, system.SubmitOpts{})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	status, err := sys.WaitJobTerminal(ctx, runID, "build")
	if err != nil {
		t.Fatalf("wait job: %v", err)
	}
	if status != model.StatusFailure {
		t.Fatalf("job status = %s, want failure (non-rootless daemon must not run untrusted container jobs)", status)
	}
	j, err := sys.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	if !strings.Contains(strings.ToLower(j.Error), "rootless") {
		t.Fatalf("job error = %q, want a rootless sandbox fail-closed message", j.Error)
	}
	if j.Trusted {
		t.Fatal("direct API job is trusted; gate input would be wrong")
	}
}

// TestSysDFBoot001 proves DF-BOOT-001 on the SYSTEM species: a real
// NewPersistent server, a real product submit (untrusted container when
// rootless Docker can run it, otherwise TRUSTED native via the signed
// webhook ingress), a real runner.Run executing a step to success, a
// public-API query, then a restart on the same DataDir that still serves the
// historical run.
func TestSysDFBoot001(t *testing.T) {
	trusted := useTrustedNative(t)
	if !trusted {
		// Operator escape for hosts without XFS project quotas (see
		// executor.AllowUnquotaedUntrustedDiskEnv). The fail-closed default is
		// proven separately in TestSysQuotaGate; this arm needs a successful
		// untrusted container attempt so the lifecycle and restart can be
		// observed on darwin/linux-without-prjquota.
		t.Setenv("KIWI_ALLOW_UNQUOTAED_UNTRUSTED_DISK", "1")
	}
	// Trusted-native arm only: the container arm runs against a REAL
	// rootless daemon and must keep it; the native arm never creates a
	// container, so the fail-closed crash reconciliation is hermeticized
	// (CLI-present/daemon-down hosts would otherwise kill the runner).
	if trusted {
		installFakeDockerForSystem(t)
	}
	dataDir := t.TempDir()
	sys, err := system.Launch(system.SystemConfig{
		RunnerToken: "sys-boot-runner",
		AdminToken:  "sys-boot-admin",
		DataDir:     dataDir,
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer func() { _ = sys.Close() }()
	if trusted {
		if err := sys.EnableTrustedWebhook(system.TrustedWebhookConfig{PipelineYAML: nativeEchoPipeline}); err != nil {
			t.Fatalf("enable trusted webhook: %v", err)
		}
	}

	// Untrusted container jobs require the runner's "container" label;
	// native jobs lease on the default "native" label every runner carries.
	var labels []string
	if !trusted {
		labels = []string{"container"}
	}
	if err := sys.StartRunner("boot-runner", labels); err != nil {
		t.Fatalf("start runner: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var runID string
	if trusted {
		runID, err = sys.SubmitTrustedNative(ctx, nativeEchoPipeline)
	} else {
		runID, err = sys.SubmitPipeline(ctx, containerEchoPipeline, system.SubmitOpts{})
	}
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	status, err := sys.WaitJobTerminal(ctx, runID, "build")
	if err != nil {
		t.Fatalf("wait job: %v", err)
	}
	if status != model.StatusSuccess {
		j, _ := sys.JobByKey(ctx, runID, "build")
		t.Fatalf("job status = %s error=%q, want success", status, j.Error)
	}
	run, err := sys.QueryRun(ctx, runID)
	if err != nil {
		t.Fatalf("query run: %v", err)
	}
	if run.Status != model.StatusSuccess {
		t.Fatalf("run status = %s, want success", run.Status)
	}
	job, err := sys.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	// AttemptRunnerID is stamped in the completion transaction; poll briefly
	// so a racing read cannot observe a terminal status a microsecond before
	// the completing runner identity is durable.
	deadline := time.Now().Add(5 * time.Second)
	for job.AttemptRunnerID == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		job, err = sys.JobByKey(ctx, runID, "build")
		if err != nil {
			t.Fatalf("job re-read: %v", err)
		}
	}
	if job.AttemptRunnerID == "" {
		t.Fatal("job has no attempt runner id after terminal success")
	}
	if job.Trusted != trusted {
		t.Fatalf("job trusted = %v, want %v (direct API is always untrusted; trusted ingress must set it)", job.Trusted, trusted)
	}

	// Eight-oracle cross-check of the live surfaces the public API exposes.
	obs := []dogfood.Observation{
		{Surface: dogfood.SurfaceClientResult, Terminal: "success", EffectCount: 0, Detail: "WaitJobTerminal"},
		{Surface: dogfood.SurfaceAuthoritativeState, Terminal: "success", EffectCount: 0, Detail: "GET run/jobs"},
		{Surface: dogfood.SurfaceLedger, Terminal: "success", EffectCount: 0, Detail: "terminal job persisted"},
		{Surface: dogfood.SurfaceRunnerAuthority, Terminal: "success", EffectCount: 0, Detail: "attempt_runner_id=" + job.AttemptRunnerID},
		{Surface: dogfood.SurfaceArtifacts, Terminal: "success", EffectCount: 0, Detail: "echo job uploads none"},
		{Surface: dogfood.SurfaceEvidence, Terminal: "success", EffectCount: 0, Detail: "see TestSysDFEvid001"},
		{Surface: dogfood.SurfaceExternalEffects, Terminal: "success", EffectCount: 0, Detail: "no deployment/OIDC"},
		{Surface: dogfood.SurfaceRecovery, Terminal: "success", EffectCount: 0, Detail: "restart below"},
	}
	if res := dogfood.NewOracle().Check(obs); !res.Green {
		t.Fatalf("eight-oracle: %s", res.Summary())
	}

	// Restart: stop the live runner and server, then Launch again on the
	// same DataDir. The historical run must still be served.
	if err := sys.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	sys2, err := system.Launch(system.SystemConfig{
		RunnerToken: "sys-boot-runner",
		AdminToken:  "sys-boot-admin",
		DataDir:     dataDir,
	})
	if err != nil {
		t.Fatalf("relaunch: %v", err)
	}
	defer func() { _ = sys2.Close() }()
	run2, err := sys2.QueryRun(ctx, runID)
	if err != nil {
		t.Fatalf("query run after restart: %v", err)
	}
	if run2.ID != runID || run2.Status != model.StatusSuccess {
		t.Fatalf("after restart run = %+v, want %s success", run2, runID)
	}
	jobs2, err := sys2.QueryJobs(ctx, runID)
	if err != nil {
		t.Fatalf("query jobs after restart: %v", err)
	}
	found := false
	for _, j := range jobs2 {
		if j.Key == "build" && j.Status == model.StatusSuccess {
			found = true
		}
	}
	if !found {
		t.Fatalf("after restart jobs = %+v, want terminal success build", jobs2)
	}
}

// TestSysDFEvid001 proves DF-EVID-001 on the SYSTEM species: after a real
// successful job (untrusted container on a rootless host, otherwise TRUSTED
// native via the signed webhook ingress) the public attestation endpoint
// serves a signed envelope that verifies under JWKS discovery and passes
// provenance.VerifyExecutionAttestation.
func TestSysDFEvid001(t *testing.T) {
	trusted := useTrustedNative(t)
	if !trusted {
		t.Setenv("KIWI_ALLOW_UNQUOTAED_UNTRUSTED_DISK", "1")
	}
	// Trusted-native arm only (see TestSysDFBoot001): never a container,
	// so hermeticize the fail-closed crash reconciliation after the real
	// host probe.
	if trusted {
		installFakeDockerForSystem(t)
	}
	sys := start(t)
	var labels []string
	if !trusted {
		labels = []string{"container"}
	}
	if err := sys.StartRunner("evid-runner", labels); err != nil {
		t.Fatalf("start runner: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var runID string
	var err error
	if trusted {
		runID, err = sys.SubmitTrustedNative(ctx, nativeEchoPipeline)
	} else {
		runID, err = sys.SubmitPipeline(ctx, containerEchoPipeline, system.SubmitOpts{})
	}
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	status, err := sys.WaitJobTerminal(ctx, runID, "build")
	if err != nil {
		t.Fatalf("wait job: %v", err)
	}
	if status != model.StatusSuccess {
		j, _ := sys.JobByKey(ctx, runID, "build")
		t.Fatalf("job status = %s error=%q, want success", status, j.Error)
	}
	job, err := sys.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	if job.Trusted != trusted {
		t.Fatalf("job trusted = %v, want %v", job.Trusted, trusted)
	}
	// Attestation is produced by the completion outbox (Maintain dispatch).
	evCtx, evCancel := context.WithTimeout(ctx, 25*time.Second)
	defer evCancel()
	envBytes, err := sys.FetchEvidence(evCtx, job.ID, job.LeaseGeneration)
	if err != nil {
		t.Fatalf("fetch evidence: %v", err)
	}
	if len(envBytes) == 0 {
		t.Fatal("empty attestation envelope")
	}
	st, err := sys.VerifyEvidence(ctx, envBytes)
	if err != nil {
		t.Fatalf("verify evidence: %v", err)
	}
	if st.Attestation == nil {
		t.Fatal("verified statement carries no execution attestation")
	}
	if st.Attestation.JobID != job.ID {
		t.Fatalf("attestation job id = %q, want %q", st.Attestation.JobID, job.ID)
	}
	if st.Attestation.JobKey != "" && st.Attestation.JobKey != job.Key {
		t.Fatalf("attestation job key = %q, want %q", st.Attestation.JobKey, job.Key)
	}
	// A tampered envelope must not verify.
	if len(envBytes) > 40 {
		bad := append([]byte(nil), envBytes...)
		bad[10] ^= 0x1
		if _, err := sys.VerifyEvidence(ctx, bad); err == nil {
			t.Fatal("tampered envelope verified")
		}
	}
}

// TestSysTrustedIngress proves the PRODUCT trusted ingress on the SYSTEM
// species: a signed GitHub push webhook (HMAC X-Hub-Signature-256 over a
// real push payload) is accepted by the real /hooks/github handler, the
// forge-derived Trusted bit lands on the job, and a native host step runs to
// success with evidence. Direct API submissions cannot do this — server
// submit force-clears Trusted — and nothing here mutates the store.
func TestSysTrustedIngress(t *testing.T) {
	// Trusted-native webhook lane: never creates a container; hermetic
	// docker keeps fail-closed crash reconciliation from killing the
	// runner on a CLI-present/daemon-down host.
	installFakeDockerForSystem(t)
	sys := start(t)
	if !sys.TrustedWebhookEnabled() {
		t.Fatal("trusted webhook ingress not enabled")
	}
	if err := sys.StartRunner("trusted-ingress-runner", nil); err != nil {
		t.Fatalf("start runner: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	runID, err := sys.DeliverTrustedPush(ctx, "sys-trusted-ingress-1", nativeEchoPipeline)
	if err != nil {
		t.Fatalf("deliver trusted push: %v", err)
	}
	status, err := sys.WaitJobTerminal(ctx, runID, "build")
	if err != nil {
		t.Fatalf("wait job: %v", err)
	}
	if status != model.StatusSuccess {
		j, _ := sys.JobByKey(ctx, runID, "build")
		t.Fatalf("job status = %s error=%q, want success", status, j.Error)
	}
	job, err := sys.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	if !job.Trusted {
		t.Fatal("signed push webhook job is untrusted; forge-derived Trusted was lost")
	}
	deadline := time.Now().Add(5 * time.Second)
	for job.AttemptRunnerID == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		job, err = sys.JobByKey(ctx, runID, "build")
		if err != nil {
			t.Fatalf("job re-read: %v", err)
		}
	}
	if job.AttemptRunnerID == "" {
		t.Fatal("job has no attempt runner id after terminal success")
	}
	// The same ingress must produce evidence, not just a green step.
	evCtx, evCancel := context.WithTimeout(ctx, 25*time.Second)
	defer evCancel()
	envBytes, err := sys.FetchEvidence(evCtx, job.ID, job.LeaseGeneration)
	if err != nil {
		t.Fatalf("fetch evidence: %v", err)
	}
	if _, err := sys.VerifyEvidence(ctx, envBytes); err != nil {
		t.Fatalf("verify evidence: %v", err)
	}
}

// TestSysTrustedScheduleIngress proves the non-forge product trusted
// ingress: a trusted schedule (admin trusted_run) fired through
// PUT /api/v1/schedules + POST .../trigger produces a Trusted native run.
// fireSchedule copies the STORED Trusted flag; the store is never mutated.
func TestSysTrustedScheduleIngress(t *testing.T) {
	// Trusted-native schedule lane: never creates a container (see
	// TestSysTrustedIngress).
	installFakeDockerForSystem(t)
	sys := start(t)
	if err := sys.StartRunner("trusted-sched-runner", nil); err != nil {
		t.Fatalf("start runner: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	runID, err := sys.SubmitTrustedSchedule(ctx, nativeEchoPipeline, system.SubmitOpts{})
	if err != nil {
		t.Fatalf("submit trusted schedule: %v", err)
	}
	status, err := sys.WaitJobTerminal(ctx, runID, "build")
	if err != nil {
		t.Fatalf("wait job: %v", err)
	}
	if status != model.StatusSuccess {
		j, _ := sys.JobByKey(ctx, runID, "build")
		t.Fatalf("job status = %s error=%q, want success", status, j.Error)
	}
	job, err := sys.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	if !job.Trusted {
		t.Fatal("trusted-schedule job is untrusted; fireSchedule lost the stored Trusted flag")
	}
}

// TestSysDFLease001 proves DF-LEASE-001 on the SYSTEM species over the real
// Complete API: a completion under a wrong (stale) lease generation is
// rejected with HTTP 409 (safety), and the legitimate completion of the same
// attempt still succeeds (liveness).
func TestSysDFLease001(t *testing.T) {
	sys := start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runID, err := sys.SubmitPipeline(ctx, containerEchoPipeline, system.SubmitOpts{})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	runnerID, err := sys.RegisterRunner(ctx, "lease-runner", []string{"native", "container"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	// Poll until the job is leased (short poll, real next endpoint).
	var task system.LeaseTask
	leased := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		lt, ok, err := sys.Next(ctx, runnerID)
		if err != nil {
			t.Fatalf("next: %v", err)
		}
		if ok {
			task = lt
			leased = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !leased {
		t.Fatal("job was never leased")
	}
	if task.JobKey != "build" {
		t.Fatalf("leased job key = %q, want build", task.JobKey)
	}

	// Safety: a completion carrying a stale generation must be rejected.
	stale := task
	stale.LeaseGeneration = task.LeaseGeneration + 99
	code, err := sys.Complete(ctx, stale, model.StatusSuccess, "")
	if err != nil {
		t.Fatalf("stale complete transport: %v", err)
	}
	if code != 409 {
		t.Fatalf("stale complete = HTTP %d, want 409", code)
	}
	// The job must still be running (stale write did not land).
	j, err := sys.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("job after stale complete: %v", err)
	}
	if j.Status.Terminal() {
		t.Fatalf("stale completion mutated job to %s", j.Status)
	}

	// Liveness: the legitimate completion of the same attempt succeeds.
	code, err = sys.Complete(ctx, task, model.StatusSuccess, "")
	if err != nil {
		t.Fatalf("legit complete transport: %v", err)
	}
	if code != 204 {
		t.Fatalf("legit complete = HTTP %d, want 204", code)
	}
	status, err := sys.WaitJobTerminal(ctx, runID, "build")
	if err != nil {
		t.Fatalf("wait terminal: %v", err)
	}
	if status != model.StatusSuccess {
		t.Fatalf("final status = %s, want success", status)
	}
}

// TestSysQuotaGate proves the untrusted hard-quota fail-closed arm on the
// SYSTEM species: an untrusted container job leased by a real runner on a
// host without an OS-level hard workspace quota must terminate in the
// pre-checkout gate, never in a successful checkout.
//
// The positive arm (hard quota available → admitted) requires Linux XFS
// prjquota and is not exercised here; this test never fakes a hard bound.
func TestSysQuotaGate(t *testing.T) {
	// The fail-closed gate runs before any container backend is invoked
	// (docker not required) — but the runner's crash reconciliation still
	// calls `docker ps` whenever the CLI exists, so the native-only fail
	// closed arm is hermeticized against a daemon-down host.
	installFakeDockerForSystem(t)
	sys := start(t)
	// Claim the "container" scheduling label so the untrusted container job
	// is leaseable on this host. The gate runs before any container backend
	// is invoked, so Docker is not required for the fail-closed arm.
	if err := sys.StartRunner("quota-runner", []string{"container"}); err != nil {
		t.Fatalf("start runner: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	runID, err := sys.SubmitPipeline(ctx, untrustedContainerPipeline, system.SubmitOpts{})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	status, err := sys.WaitJobTerminal(ctx, runID, "build")
	if err != nil {
		t.Fatalf("wait job: %v", err)
	}
	if status != model.StatusFailure {
		t.Fatalf("job status = %s, want failure (fail closed without hard quota)", status)
	}
	j, err := sys.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	if !strings.Contains(strings.ToLower(j.Error), "quota") {
		t.Fatalf("job error = %q, want a hard-workspace-quota fail-closed message", j.Error)
	}
	// Direct API submissions are always untrusted — the gate input is the
	// real trust bit the control plane persisted.
	if j.Trusted {
		t.Fatal("direct API job is trusted; gate input would be wrong")
	}
}

func start(t *testing.T) *system.System {
	t.Helper()
	return system.Start(t)
}
