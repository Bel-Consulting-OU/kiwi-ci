package system_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood/system"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
)

// DF-SCALE-002 live resource-leak / soak and the untrusted-container +
// hard-quota + signed-v6 evidence lane. These are SYSTEM-species production
// dogfood: real NewPersistent, real HTTP, real runner.Run.

const (
	// soakFixedJobs is the pinned DF-SCALE-002 main workload. Small enough
	// for a CI lane, large enough that a per-job goroutine/fd leak shows up
	// in the before/after delta.
	soakFixedJobs = 50
	// soakChurnJobs is the post-reconnect workload (runner stop → new
	// runner → more jobs). Proves leases survive a runner identity change
	// without accumulating resources across the churn.
	soakChurnJobs = 20
)

// resourceSnapshot is one before/after sample of process-wide resource use.
type resourceSnapshot struct {
	goroutines int
	heapAlloc  uint64
	openFDs    int
}

func snapResources() resourceSnapshot {
	// Two GCs so finalizers and idle spans settle before the heap sample.
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return resourceSnapshot{
		goroutines: runtime.NumGoroutine(),
		heapAlloc:  ms.HeapAlloc,
		openFDs:    openFDCount(),
	}
}

// openFDCount is a rough process-wide open-descriptor count. /proc/self/fd
// on Linux; /dev/fd on darwin. Returns -1 when neither is readable.
func openFDCount() int {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		entries, err := os.ReadDir(dir)
		if err == nil {
			return len(entries)
		}
	}
	return -1
}

func (r resourceSnapshot) String() string {
	return fmt.Sprintf("goroutines=%d heap_alloc=%d open_fds=%d", r.goroutines, r.heapAlloc, r.openFDs)
}

// TestSysDFScale002Soak is DF-SCALE-002 on the SYSTEM species: a fixed
// workload of short trusted-native jobs runs to terminal success on a real
// persistent server + HTTP + runner, a runner is stopped and replaced
// (churn) and more jobs complete, and process resources return near the
// pre-workload baseline. Resource facts are recorded in the test log.
func TestSysDFScale002Soak(t *testing.T) {
	sys := start(t)
	if err := sys.StartRunner("soak-runner-a", nil); err != nil {
		t.Fatalf("start runner: %v", err)
	}

	// Baseline after the server, Maintain loop and runner are live but
	// before any workload. The idle control plane is the floor we must
	// return to — not "before Launch", which would treat the server itself
	// as a leak.
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	before := snapResources()
	t.Logf("DF-SCALE-002 baseline: %s", before)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	// Phase 1: fixed trusted-native workload through the product trusted
	// ingress. Direct API submit is never used (it force-clears Trusted and
	// untrusted native is policy-forbidden).
	runIDs := make([]string, 0, soakFixedJobs)
	for i := 0; i < soakFixedJobs; i++ {
		id, err := sys.SubmitTrustedNative(ctx, nativeEchoPipeline)
		if err != nil {
			t.Fatalf("submit trusted-native job %d/%d: %v", i+1, soakFixedJobs, err)
		}
		runIDs = append(runIDs, id)
	}
	for i, runID := range runIDs {
		status, err := sys.WaitJobTerminal(ctx, runID, "build")
		if err != nil {
			t.Fatalf("wait job %d/%d (run %s): %v", i+1, soakFixedJobs, runID, err)
		}
		if status != model.StatusSuccess {
			j, _ := sys.JobByKey(ctx, runID, "build")
			t.Fatalf("job %d/%d status = %s error=%q, want success", i+1, soakFixedJobs, status, j.Error)
		}
	}
	t.Logf("DF-SCALE-002 phase1: %d trusted-native jobs terminal success", soakFixedJobs)

	// Phase 2: runner churn. Stop the live runner (join its goroutine), start
	// a fresh one under a new identity, and complete more jobs. A reconnect
	// must not leak the old runner's goroutines or strand the queue.
	sys.StopRunner()
	if err := sys.StartRunner("soak-runner-b", nil); err != nil {
		t.Fatalf("start churn runner: %v", err)
	}
	churnIDs := make([]string, 0, soakChurnJobs)
	for i := 0; i < soakChurnJobs; i++ {
		id, err := sys.SubmitTrustedNative(ctx, nativeEchoPipeline)
		if err != nil {
			t.Fatalf("submit churn job %d/%d: %v", i+1, soakChurnJobs, err)
		}
		churnIDs = append(churnIDs, id)
	}
	for i, runID := range churnIDs {
		status, err := sys.WaitJobTerminal(ctx, runID, "build")
		if err != nil {
			t.Fatalf("wait churn job %d/%d (run %s): %v", i+1, soakChurnJobs, runID, err)
		}
		if status != model.StatusSuccess {
			j, _ := sys.JobByKey(ctx, runID, "build")
			t.Fatalf("churn job %d/%d status = %s error=%q, want success", i+1, soakChurnJobs, status, j.Error)
		}
	}
	t.Logf("DF-SCALE-002 phase2: runner churn (soak-runner-a → soak-runner-b) + %d jobs terminal success", soakChurnJobs)

	// Drain: let completion-outbox / maintain work settle so the "after"
	// sample is not racing an in-flight attestation intent.
	time.Sleep(500 * time.Millisecond)
	after := snapResources()
	t.Logf("DF-SCALE-002 after: %s", after)
	t.Logf("DF-SCALE-002 delta: goroutines=%+d heap_alloc=%+d open_fds=%+d (baseline heap=%d after heap=%d)",
		after.goroutines-before.goroutines,
		int64(after.heapAlloc)-int64(before.heapAlloc),
		after.openFDs-before.openFDs,
		before.heapAlloc, after.heapAlloc)

	// All jobs already asserted success above. Resource recovery: goroutines
	// return near baseline (idle HTTP/runner/ticker goroutines are expected;
	// a leaked runner or per-job goroutine is not).
	const goroutineSlack = 50
	if after.goroutines > before.goroutines+goroutineSlack {
		t.Fatalf("goroutine leak: %d → %d (slack %d); %s → %s",
			before.goroutines, after.goroutines, goroutineSlack, before, after)
	}
	// Heap must not grow without bound. After GC the retained set is the
	// control plane plus run history; 3× baseline + 20MB absorbs history
	// growth while still catching a per-job retain.
	heapLimit := 3*before.heapAlloc + 20<<20
	if after.heapAlloc > heapLimit {
		t.Fatalf("heap grew unbounded: %d > limit %d (baseline %d); %s → %s",
			after.heapAlloc, heapLimit, before.heapAlloc, before, after)
	}
	// FD count is best-effort (procfs / devfs). When readable, require it
	// does not grow without bound either; a leaked listener/pipe per job
	// shows up here.
	if before.openFDs >= 0 && after.openFDs >= 0 {
		const fdSlack = 32
		if after.openFDs > before.openFDs+fdSlack {
			t.Fatalf("fd leak: %d → %d (slack %d); %s → %s",
				before.openFDs, after.openFDs, fdSlack, before, after)
		}
	} else {
		t.Logf("DF-SCALE-002 fd count unavailable on this host (before=%d after=%d); goroutine+heap checks only",
			before.openFDs, after.openFDs)
	}
	t.Logf("DF-SCALE-002 resource recovery OK: jobs=%d (fixed=%d churn=%d) goroutines %d→%d heap_alloc %d→%d (limit %d) open_fds %d→%d",
		soakFixedJobs+soakChurnJobs, soakFixedJobs, soakChurnJobs,
		before.goroutines, after.goroutines, before.heapAlloc, after.heapAlloc, heapLimit,
		before.openFDs, after.openFDs)
}

// dockerInstalled reports whether a docker CLI is on PATH (the daemon may
// still be unusable or non-rootless).
func dockerInstalled() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

// TestSysUntrustedContainerEvidenceLane is the production untrusted
// container + hard quota + signed v6 evidence lane.
//
// Arms (never a silent skip):
//
//  1. Rootless docker: digest-pinned untrusted container job, network none,
//     hard workspace quota when the host has XFS project quotas (else the
//     documented KIWI_ALLOW_UNQUOTAED_UNTRUSTED_DISK=1 operator escape).
//     Complete → fetch attestation → verify. Assert proven
//     NetworkAccessDenied or an honest observed receipt, and schema v6.
//  2. Docker present but NOT rootless: the untrusted rootless floor must
//     fail closed (the TestSysRootlessEnforced product proof — asserted
//     here so this lane cannot claim success while the floor is open) AND
//     trusted-native evidence runs as the documented substitute. The
//     high-assurance untrusted-container success lane requires rootless
//     docker.
//  3. Docker absent: no silent skip — log the host fact and still run the
//     trusted-native evidence substitute so the signed-v6 lane executes.
//
// FAIL is preferred only when docker IS rootless and the success path fails.
func TestSysUntrustedContainerEvidenceLane(t *testing.T) {
	switch {
	case dockerInstalled() && rootlessDockerAvailable():
		t.Log("untrusted-container evidence lane: rootless docker available — running the digest-pinned untrusted container success arm")
		runUntrustedContainerEvidence(t)
	case dockerInstalled():
		t.Log("untrusted-container evidence lane: docker is present but NOT rootless")
		t.Log("high-assurance untrusted-container success lane requires rootless docker; asserting the rootless fail-closed floor and running the trusted-native evidence substitute")
		assertUntrustedRootlessFloorFailsClosed(t)
		runTrustedNativeEvidence(t)
	default:
		t.Log("untrusted-container evidence lane: docker is not installed on this host")
		t.Log("high-assurance untrusted-container success lane requires rootless docker; running the trusted-native evidence substitute (not skipping)")
		runTrustedNativeEvidence(t)
	}
}

// assertUntrustedRootlessFloorFailsClosed re-asserts the product proof of
// TestSysRootlessEnforced on this host: a non-rootless daemon must not
// execute an untrusted container job. The quota escape is set only so the
// attempt reaches the rootless check; the rootless requirement itself is
// never bypassed.
func assertUntrustedRootlessFloorFailsClosed(t *testing.T) {
	t.Helper()
	t.Setenv("KIWI_ALLOW_UNQUOTAED_UNTRUSTED_DISK", "1")
	sys := start(t)
	if err := sys.StartRunner("evidence-lane-rootless-gate", []string{"container"}); err != nil {
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
	t.Logf("rootless floor FAIL-CLOSED confirmed: job error=%q", j.Error)
}

// runUntrustedContainerEvidence runs the success arm: a real untrusted
// container job (digest-pinned image, network none) completes under the
// hard-quota gate (real XFS project quota when the host has one, else the
// documented operator escape) and the signed execution attestation is
// fetched and verified as schema v6 with honest network-denial facts.
func runUntrustedContainerEvidence(t *testing.T) {
	t.Helper()
	// Prefer a real OS-level hard workspace quota. When the host cannot
	// install one (no XFS prjquota — typical darwin), the documented
	// operator escape admits the job with the step-boundary residual and we
	// say so in the log. The fail-closed default without the escape is
	// TestSysQuotaGate.
	hard, detail := probeHardWorkspaceQuota(t)
	if hard {
		t.Logf("untrusted evidence lane: real hard workspace quota available (%s)", detail)
	} else {
		t.Setenv(executor.AllowUnquotaedUntrustedDiskEnv, "1")
		t.Logf("untrusted evidence lane: no hard workspace quota on this host (%s); using %s=1 (operator escape; TestSysQuotaGate keeps the fail-closed default)", detail, executor.AllowUnquotaedUntrustedDiskEnv)
	}

	sys := start(t)
	if err := sys.StartRunner("evidence-lane-container", []string{"container"}); err != nil {
		t.Fatalf("start runner: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	runID, err := sys.SubmitPipeline(ctx, untrustedContainerPipeline, system.SubmitOpts{})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	status, err := sys.WaitJobTerminal(ctx, runID, "build")
	if err != nil {
		t.Fatalf("wait job: %v", err)
	}
	if status != model.StatusSuccess {
		j, _ := sys.JobByKey(ctx, runID, "build")
		t.Fatalf("untrusted container job status = %s error=%q, want success (rootless docker success lane must not fail)", status, j.Error)
	}
	job, err := sys.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	if job.Trusted {
		t.Fatal("direct API job is trusted; untrusted evidence lane would be measuring the wrong trust class")
	}
	assertSignedV6Evidence(t, sys, ctx, job, true)
}

// runTrustedNativeEvidence is the documented substitute when the
// high-assurance untrusted-container success lane is unavailable: a
// TRUSTED native job through the product trusted ingress produces the same
// signed v6 evidence lane (attestation fetch + JWKS verify).
func runTrustedNativeEvidence(t *testing.T) {
	t.Helper()
	sys := start(t)
	if err := sys.StartRunner("evidence-lane-native", nil); err != nil {
		t.Fatalf("start runner: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	runID, err := sys.SubmitTrustedNative(ctx, nativeEchoPipeline)
	if err != nil {
		t.Fatalf("submit trusted-native: %v", err)
	}
	status, err := sys.WaitJobTerminal(ctx, runID, "build")
	if err != nil {
		t.Fatalf("wait job: %v", err)
	}
	if status != model.StatusSuccess {
		j, _ := sys.JobByKey(ctx, runID, "build")
		t.Fatalf("trusted-native substitute job status = %s error=%q, want success", status, j.Error)
	}
	job, err := sys.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	if !job.Trusted {
		t.Fatal("trusted-native substitute job is untrusted; the signed evidence lane ran outside the trusted ingress")
	}
	assertSignedV6Evidence(t, sys, ctx, job, false)
}

// assertSignedV6Evidence fetches the execution attestation for job over the
// public API, verifies it under JWKS discovery, and asserts the signed v6
// contract: schema version 6, bound job identity, and — for the untrusted
// container arm — proven NetworkAccessDenied or an honest observed receipt
// (never a policy-only denial claim).
func assertSignedV6Evidence(t *testing.T, sys *system.System, ctx context.Context, job system.JobView, untrustedContainer bool) {
	t.Helper()
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
	if st.Attestation.SchemaVersion != provenance.ExecutionAttestationSchemaVersion() {
		t.Fatalf("attestation schemaVersion = %d, want %d (signed v6 evidence lane)",
			st.Attestation.SchemaVersion, provenance.ExecutionAttestationSchemaVersion())
	}
	if st.Attestation.JobID != job.ID {
		t.Fatalf("attestation job id = %q, want %q", st.Attestation.JobID, job.ID)
	}
	if st.Attestation.JobKey != "" && st.Attestation.JobKey != job.Key {
		t.Fatalf("attestation job key = %q, want %q", st.Attestation.JobKey, job.Key)
	}

	facts := st.Attestation.ExecutionAssurance.Facts
	if facts == nil {
		t.Fatal("signed v6 attestation carries no execution facts")
	}
	t.Logf("signed v6 evidence: schema=%d job=%s trusted=%v runtime=%s network_mode=%s network_access_denied=%v profile=%s observed=%+v",
		st.Attestation.SchemaVersion, st.Attestation.JobID, job.Trusted,
		facts.Runtime, facts.NetworkMode, facts.NetworkAccessDenied,
		st.Attestation.ExecutionAssurance.Name, facts.Observed)

	if !untrustedContainer {
		// Trusted native substitute: the lane proves the signed-v6 evidence
		// path, not container network denial (native host networking must
		// never claim network_access_denied).
		if facts.NetworkAccessDenied {
			t.Fatalf("trusted native facts = %+v, must not claim network_access_denied", facts)
		}
		return
	}

	// Untrusted digest-pinned container with network: none. Accept either
	// PROVEN denial (NetworkAccessDenied with an observed none receipt) or
	// an honest observed receipt that does not claim denial without proof.
	if facts.NetworkMode != model.NetworkModeFactNone {
		t.Fatalf("facts.NetworkMode = %q, want %q (pipeline network: none)", facts.NetworkMode, model.NetworkModeFactNone)
	}
	if facts.NetworkAccessDenied {
		if facts.Observed == nil || facts.Observed.NetworkEnforced != model.ObservedNetworkNone {
			t.Fatalf("NetworkAccessDenied claimed without a proven none receipt: observed=%+v", facts.Observed)
		}
		t.Logf("network denial PROVEN: observed network_enforced=%s", facts.Observed.NetworkEnforced)
		return
	}
	// Honest non-claim: either no receipt, or a receipt whose enforcement
	// is not "none" — the attestation must not upgrade policy into proof.
	if facts.Observed != nil && facts.Observed.NetworkEnforced == model.ObservedNetworkNone {
		t.Fatalf("observed network_enforced=none but NetworkAccessDenied=false — dishonest facts: %+v", facts)
	}
	t.Logf("network_access_denied not proven; observed receipt is honest (observed=%+v)", facts.Observed)
}

// probeHardWorkspaceQuota checks whether this host can install a real
// OS-level hard bound on a workspace tree (XFS project quota). The probe
// uses the same product entry point the runner uses and always cleans up.
func probeHardWorkspaceQuota(t *testing.T) (bool, string) {
	t.Helper()
	dir := t.TempDir()
	st, cleanup := executor.WorkspaceDiskQuotaSetup(dir, 4<<20)
	if cleanup != nil {
		defer func() { _ = cleanup() }()
	}
	return st.Hard, st.Detail
}
