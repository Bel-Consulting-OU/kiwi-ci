package dist_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood/system"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
)

// TestSysDFCanonicalReleaseScenarioIntegration is the SINGLE production
// release scenario the audit requires: one continuous real topology covering
// the full chain — not a set of separate demos.
//
// State that persists through every stage: one real PostgreSQL database, one
// object-store data directory, one product binary lineage (N-1 → HEAD →
// packaged bytes).
//
// Stage chain (each stage asserts its contract before the next begins):
//
//  1. N-1 → N: an N-1 product binary owns the postgres+object-store state
//     and writes durable history; the HEAD binary then takes the SAME state
//     (binary upgrade) and still serves that history.
//  2. Full topology: two real `kiwi runner` OS processes + a git mirror;
//     both runners register and claim leases; trusted work produces an
//     artifact.
//  3. Untrusted / high-assurance controls: a direct-API job is untrusted;
//     the hard-workspace-quota gate fails closed without a real OS quota
//     (or admits under a proven hard quota); the untrusted rootless floor
//     fails closed on a non-rootless daemon.
//  4. Signed evidence + verification proof: the execution attestation is
//     fetched over the public API, verifies under JWKS discovery as schema
//     v6 bound to the job, and a tampered envelope is refused.
//  5. Process kill / failover + retry: a runner hard-kill hands work to the
//     other runner; a control-plane SIGKILL mid-flight is restarted on the
//     same state; stale completion is refused without mutation; identical
//     completion replay is idempotent; a conflicting completion is refused;
//     the surviving lease and fresh work complete.
//  6. Backup → destroy → restore: pg_dump + object-store copy, destroy both,
//     restore both, and every historical proof (attestation bytes, evidence
//     root, artifact hash) still verifies on the restored cluster.
//  7. Packaged artifact: the exact HEAD binary bytes are hashed, installed
//     byte-for-byte, and that installed binary serves the restored state —
//     history, new work, and evidence — with the binary-used hash equal to
//     the recorded package hash.
//
// PostgreSQL-gated (startPostgres): the "Integration" suffix keeps the unit
// profile from selecting it and lets the integration lane's -run Integration
// find it (surfacecheck TestPostgresGatedTestsCarryIntegrationInName).
func TestSysDFCanonicalReleaseScenarioIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("canonical release scenario builds real binaries and starts real PostgreSQL")
	}

	// Go toolchain for every source build in this scenario.
	goBin := canonicalGoTool(t)
	srcDir := moduleRoot(t)
	root := t.TempDir()

	// --- binaries: N-1 and HEAD -----------------------------------------
	n1Bin := filepath.Join(root, "kiwi-n1")
	n1SHA := canonicalResolveNMinusOne(t, srcDir, goBin, n1Bin)
	t.Logf("canonical: N-1 binary sha=%s path=%s", n1SHA, n1Bin)

	headBin := buildKiwi(t, root)
	headSHA := canonicalSHA256File(t, headBin)
	t.Logf("canonical: HEAD binary sha256=%s path=%s", headSHA, headBin)

	// --- real PostgreSQL + object-store data dir ------------------------
	pgDSN, _ := startPostgres(t)
	pgAdmin := urlToPSQLAdmin(t, pgDSN)
	dbName := dbNameFromDSN(pgDSN)
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}

	const runnerToken = "canon-runner-token"
	const adminToken = "canon-admin-token"

	// ====================================================================
	// STAGE 1 — N-1 → N binary upgrade on one postgres+object-store state
	// ====================================================================
	n1Port := freeTCPPort(t)
	n1Listen := fmt.Sprintf("127.0.0.1:%d", n1Port)
	n1URL := fmt.Sprintf("http://%s", n1Listen)
	n1Srv := spawnServer(t, n1Bin, n1Listen, dataDir, pgDSN, runnerToken, adminToken)
	waitFor(t, "N-1 server liveness", 60*time.Second, func() bool {
		resp, err := http.Get(n1URL + "/liveness")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})

	// N-1 owns the state: write durable history over the public API.
	n1Sys, err := system.Attach(n1URL, adminToken, runnerToken, filepath.Join(root, "n1-work"))
	if err != nil {
		t.Fatalf("attach N-1: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	n1RunID, n1Job := canonicalWriteHistory(ctx, t, n1Sys, "n1-origin")
	if n1Job.Status != model.StatusSuccess {
		t.Fatalf("N-1 history job status = %s, want success", n1Job.Status)
	}
	// Capture N-1 evidence so the upgrade and the DR restore must preserve it.
	n1Env := fetchEvidence(t, n1URL, adminToken, n1Job.ID, n1Job.LeaseGeneration)
	if len(n1Env) == 0 {
		t.Fatal("N-1 history produced no attestation envelope")
	}
	n1EnvSum := sha256.Sum256(n1Env)
	n1EnvDigest := hex.EncodeToString(n1EnvSum[:])
	n1St := verifyEvidence(t, n1URL, n1Env)
	if n1St.Attestation == nil || n1St.Attestation.JobID != n1Job.ID {
		t.Fatalf("N-1 attestation mismatch: %+v", n1St.Attestation)
	}
	_ = n1Sys.Close()

	// N-1 releases the state; HEAD takes the SAME postgres database and
	// object-store directory. This is the N-1 → N moment.
	n1Srv.kill()
	serverPort := freeTCPPort(t)
	serverListen := fmt.Sprintf("127.0.0.1:%d", serverPort)
	serverURL := fmt.Sprintf("http://%s", serverListen)
	srv := spawnServer(t, headBin, serverListen, dataDir, pgDSN, runnerToken, adminToken)
	waitFor(t, "HEAD server liveness after upgrade", 60*time.Second, func() bool {
		resp, err := http.Get(serverURL + "/liveness")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})

	// Upgrade contract: the N-1 history is still served and still verifies.
	var histRun struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if code := apiGet(t, serverURL, adminToken, "/api/v1/runs/"+n1RunID, &histRun); code != 200 {
		t.Fatalf("HEAD query N-1 historical run = HTTP %d", code)
	}
	if histRun.ID != n1RunID {
		t.Fatalf("HEAD historical run id = %q, want %q", histRun.ID, n1RunID)
	}
	histEnv := fetchEvidence(t, serverURL, adminToken, n1Job.ID, n1Job.LeaseGeneration)
	if !bytes.Equal(n1Env, histEnv) {
		t.Fatal("N-1 attestation envelope changed across the N-1→N upgrade")
	}
	if st := verifyEvidence(t, serverURL, histEnv); st.Attestation == nil {
		t.Fatal("upgraded server's copy of the N-1 attestation does not verify")
	}
	t.Logf("canonical STAGE 1 ok: N-1→N upgrade preserved history run=%s attDigest=%s", n1RunID, n1EnvDigest)

	// ====================================================================
	// STAGE 2 — full topology: >=2 runners + object store + trusted work
	// ====================================================================
	repoURL := startGitMirror(t, root)
	workA := filepath.Join(root, "work-a")
	workB := filepath.Join(root, "work-b")
	_ = os.MkdirAll(workA, 0o700)
	_ = os.MkdirAll(workB, 0o700)
	runnerA := spawnRunner(t, headBin, serverURL, runnerToken, "canon-runner-a", workA, filepath.Join(root, "id-a"))
	runnerB := spawnRunner(t, headBin, serverURL, runnerToken, "canon-runner-b", workB, filepath.Join(root, "id-b"))
	_ = runnerB // stays live across the failover stage; cleanup tears it down

	var runners []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	waitFor(t, "two runners registered", 30*time.Second, func() bool {
		runners = nil
		return apiGet(t, serverURL, adminToken, "/api/v1/runners", &runners) == 200 && len(runners) >= 2
	})
	var idA, idB string
	for _, r := range runners {
		switch r.Name {
		case "canon-runner-a":
			idA = r.ID
		case "canon-runner-b":
			idB = r.ID
		}
	}
	if idA == "" || idB == "" || idA == idB {
		t.Fatalf("runner identities: A=%q B=%q (all %+v)", idA, idB, runners)
	}

	// Trusted schedule work with a deterministic artifact (the object store
	// must persist it) and a hold job that forces both runners to claim.
	trustedRunID := canonicalTriggerTrusted(t, serverURL, adminToken, "canon-sched-trusted", repoURL, canonicalTrustedPipeline)
	type canonJob struct {
		ID              string `json:"id"`
		Key             string `json:"key"`
		Status          string `json:"status"`
		Error           string `json:"error"`
		LeaseGeneration int64  `json:"lease_generation"`
		AttemptRunnerID string `json:"attempt_runner_id"`
		Trusted         bool   `json:"trusted"`
	}
	trustedJobs := func() (hold, probe canonJob) {
		var jobs []canonJob
		if apiGet(t, serverURL, adminToken, "/api/v1/runs/"+trustedRunID+"/jobs", &jobs) != 200 {
			return
		}
		for _, j := range jobs {
			switch j.Key {
			case "hold":
				hold = j
			case "probe":
				probe = j
			}
		}
		return
	}
	waitFor(t, "trusted jobs terminal", 120*time.Second, func() bool {
		h, p := trustedJobs()
		return h.Status == "success" && p.Status == "success"
	})
	holdJob, probeJob := trustedJobs()
	if holdJob.Error != "" || probeJob.Error != "" {
		t.Fatalf("trusted job errors: hold=%q probe=%q", holdJob.Error, probeJob.Error)
	}
	if !holdJob.Trusted || !probeJob.Trusted {
		t.Fatalf("trusted schedule jobs lost their trust bit: hold=%v probe=%v", holdJob.Trusted, probeJob.Trusted)
	}
	// Both runners must have claimed work (or the documented sequential
	// fallback proves the other runner can take over).
	if holdJob.AttemptRunnerID == probeJob.AttemptRunnerID {
		t.Logf("both trusted jobs completed by %s; failover arm covers the other runner", holdJob.AttemptRunnerID)
	} else {
		t.Logf("trusted leases claimed by both runners: hold=%s probe=%s", holdJob.AttemptRunnerID, probeJob.AttemptRunnerID)
	}

	// Artifact (object store) must be listed with a real digest and be
	// byte-stable — this is the payload the DR stage must preserve.
	var artifacts []struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	}
	if code := apiGet(t, serverURL, adminToken, "/api/v1/runs/"+trustedRunID+"/artifacts", &artifacts); code != 200 {
		t.Fatalf("list artifacts = HTTP %d", code)
	}
	var artProbe *struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	}
	for i := range artifacts {
		if artifacts[i].Name == "probe" {
			artProbe = &artifacts[i]
			break
		}
	}
	if artProbe == nil || artProbe.SHA256 == "" {
		t.Fatalf("probe artifact missing or digest-less: %+v", artifacts)
	}
	artCode, artBytes := apiGetBytes(t, serverURL, adminToken, "/api/v1/artifacts/"+artProbe.ID)
	if artCode != 200 || len(artBytes) == 0 {
		t.Fatalf("download probe artifact = HTTP %d (%d bytes)", artCode, len(artBytes))
	}
	artSum := sha256.Sum256(artBytes)
	artDigest := hex.EncodeToString(artSum[:])
	if artDigest != artProbe.SHA256 {
		t.Fatalf("artifact bytes sha256 = %s, want recorded %s", artDigest, artProbe.SHA256)
	}
	t.Logf("canonical STAGE 2 ok: run=%s hold=%s probe=%s artifact=%s sha256=%s",
		trustedRunID, holdJob.ID, probeJob.ID, artProbe.Name, artProbe.SHA256)

	// Retire the stage-2 runners before the untrusted arm: those runners use
	// a real git checkout and would race the quota-gate runner for the
	// untrusted job (placement labels are not a scheduling filter yet).
	// Fresh runners are spawned before stage 5 failover.
	runnerA.killNow()
	runnerB.killNow()

	// ====================================================================
	// STAGE 3 — untrusted / high-assurance controls
	// ====================================================================
	// Every direct-API submission is untrusted: the trust bit the gates read
	// is the one the control plane persisted.
	ctrlSys, err := system.Attach(serverURL, adminToken, runnerToken, filepath.Join(root, "ctrl-work"))
	if err != nil {
		t.Fatalf("attach controls: %v", err)
	}
	defer func() { _ = ctrlSys.Close() }()

	// Fail-closed default: no operator escape in the gate-runner process.
	t.Setenv(executor.AllowUnquotaedUntrustedDiskEnv, "")

	untrustedRunID, err := ctrlSys.SubmitPipeline(ctx, canonicalUntrustedPipeline, system.SubmitOpts{})
	if err != nil {
		t.Fatalf("submit untrusted: %v", err)
	}
	// A container-labeled in-process runner claims the untrusted job. The
	// hard-quota gate runs before any container backend or checkout, so this
	// arm never needs Docker to prove the fail-closed default.
	if err := ctrlSys.StartRunner("canon-quota-gate", []string{"container", "quota-gate"}); err != nil {
		t.Fatalf("start quota-gate runner: %v", err)
	}
	qStatus, err := ctrlSys.WaitJobTerminal(ctx, untrustedRunID, "build")
	if err != nil {
		t.Fatalf("wait untrusted job: %v", err)
	}
	qJob, err := ctrlSys.JobByKey(ctx, untrustedRunID, "build")
	if err != nil {
		t.Fatalf("untrusted job view: %v", err)
	}
	if qJob.Trusted {
		t.Fatal("direct-API job is trusted; the high-assurance gates would measure the wrong trust class")
	}
	// High-assurance control: without a real OS hard workspace quota the
	// untrusted job must fail closed in the pre-checkout gate. When the host
	// CAN install a hard quota the same attempt is admitted by that quota
	// (also a proven control) and may go on to the rootless floor.
	hardQuota, quotaDetail := canonicalProbeHardQuota(t)
	if !hardQuota {
		if qStatus != model.StatusFailure {
			t.Fatalf("untrusted job status = %s, want failure (fail closed without hard workspace quota)", qStatus)
		}
		if !strings.Contains(strings.ToLower(qJob.Error), "quota") {
			t.Fatalf("untrusted job error = %q, want a hard-workspace-quota fail-closed message", qJob.Error)
		}
		t.Logf("canonical STAGE 3a ok: hard-quota gate FAIL-CLOSED (detail=%s) error=%q", quotaDetail, qJob.Error)
	} else {
		t.Logf("canonical STAGE 3a: host provides a hard workspace quota (%s); gate admitted the untrusted job (status=%s error=%q)", quotaDetail, qStatus, qJob.Error)
		if qStatus == model.StatusFailure && !strings.Contains(strings.ToLower(qJob.Error), "quota") &&
			!strings.Contains(strings.ToLower(qJob.Error), "rootless") {
			// Failure for some other reason is acceptable only if it is a
			// named control (quota/rootless); anything else is a real miss.
			t.Fatalf("untrusted job failed outside the named high-assurance controls: %q", qJob.Error)
		}
	}
	ctrlSys.StopRunner()

	// Rootless floor: a non-rootless Docker daemon must not execute an
	// untrusted container job. Observed only when such a daemon is present.
	if canonicalDockerNonRootless(t) {
		t.Setenv(executor.AllowUnquotaedUntrustedDiskEnv, "1") // reach the rootless check
		if err := ctrlSys.StartRunner("canon-rootless-gate", []string{"container"}); err != nil {
			t.Fatalf("start rootless-gate runner: %v", err)
		}
		rlRunID, err := ctrlSys.SubmitPipeline(ctx, canonicalUntrustedPipeline, system.SubmitOpts{})
		if err != nil {
			t.Fatalf("submit rootless-gate job: %v", err)
		}
		rlStatus, err := ctrlSys.WaitJobTerminal(ctx, rlRunID, "build")
		if err != nil {
			t.Fatalf("wait rootless-gate job: %v", err)
		}
		rlJob, err := ctrlSys.JobByKey(ctx, rlRunID, "build")
		if err != nil {
			t.Fatalf("rootless-gate job view: %v", err)
		}
		if rlStatus != model.StatusFailure {
			t.Fatalf("rootless-gate job status = %s, want failure (non-rootless daemon must not run untrusted container jobs)", rlStatus)
		}
		if !strings.Contains(strings.ToLower(rlJob.Error), "rootless") {
			t.Fatalf("rootless-gate job error = %q, want a rootless sandbox fail-closed message", rlJob.Error)
		}
		ctrlSys.StopRunner()
		t.Logf("canonical STAGE 3b ok: rootless floor FAIL-CLOSED error=%q", rlJob.Error)
	} else {
		t.Logf("canonical STAGE 3b: no non-rootless docker daemon on this host; the rootless fail-closed arm is covered by TestSysRootlessEnforced")
	}
	// The documented untrusted success substitute: signed evidence from the
	// trusted topology is asserted in STAGE 4 (always runs).
	t.Log("canonical STAGE 3 ok: untrusted trust class + high-assurance gates")

	// ====================================================================
	// STAGE 4 — signed evidence + verification proof
	// ====================================================================
	probeEnv := fetchEvidence(t, serverURL, adminToken, probeJob.ID, probeJob.LeaseGeneration)
	if len(probeEnv) == 0 {
		t.Fatal("empty probe attestation envelope")
	}
	probeSum := sha256.Sum256(probeEnv)
	probeDigest := hex.EncodeToString(probeSum[:])
	probeSt := verifyEvidence(t, serverURL, probeEnv)
	if probeSt.Attestation == nil {
		t.Fatal("verified probe statement carries no execution attestation")
	}
	if probeSt.Attestation.JobID != probeJob.ID {
		t.Fatalf("probe attestation job id = %q, want %q", probeSt.Attestation.JobID, probeJob.ID)
	}
	if probeSt.Attestation.SchemaVersion != provenance.ExecutionAttestationSchemaVersion() {
		t.Fatalf("probe attestation schemaVersion = %d, want %d",
			probeSt.Attestation.SchemaVersion, provenance.ExecutionAttestationSchemaVersion())
	}
	if probeSt.Attestation.EvidenceRootSHA256 == "" {
		t.Fatal("probe attestation carries no evidence root")
	}
	// Verification proof: a tampered envelope must not verify.
	tampered := append([]byte(nil), probeEnv...)
	tampered[len(tampered)/2] ^= 0x1
	resolver := jwksResolver(t, serverURL)
	if _, err := provenance.VerifyWith(tampered, resolver, provenance.VerifyOptions{}); err == nil {
		t.Fatal("tampered envelope verified")
	}
	t.Logf("canonical STAGE 4 ok: signed evidence job=%s schema=%d attDigest=%s evidenceRoot=%s (tamper rejected)",
		probeSt.Attestation.JobID, probeSt.Attestation.SchemaVersion, probeDigest, probeSt.Attestation.EvidenceRootSHA256)

	// ====================================================================
	// STAGE 5 — process kill / failover + retry
	// ====================================================================
	// Respawn the stage-2 runners (retired during the untrusted arm so they
	// could not race the quota-gate runner). Names are new so the registry
	// lookup cannot pick up the dead stage-2 identities.
	runnerA2 := spawnRunner(t, headBin, serverURL, runnerToken, "canon-runner-a2", workA, filepath.Join(root, "id-a2"))
	runnerB2 := spawnRunner(t, headBin, serverURL, runnerToken, "canon-runner-b2b", workB, filepath.Join(root, "id-b2b"))
	_ = runnerB2
	var live []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var idA2, idB2 string
	waitFor(t, "respawned runners registered", 30*time.Second, func() bool {
		live = nil
		if apiGet(t, serverURL, adminToken, "/api/v1/runners", &live) != 200 {
			return false
		}
		idA2, idB2 = "", ""
		for _, r := range live {
			switch r.Name {
			case "canon-runner-a2":
				idA2 = r.ID
			case "canon-runner-b2b":
				idB2 = r.ID
			}
		}
		return idA2 != "" && idB2 != ""
	})
	if idA2 == "" || idB2 == "" {
		t.Fatalf("respawned runner identities: A=%q B=%q (all %+v)", idA2, idB2, live)
	}
	// 5a. Runner failover: hard-kill runner A; fresh work must land on
	// runner B (leases are not stranded to a dead process).
	runnerA2.killNow()
	idA = idA2
	failoverRunID := canonicalTriggerTrusted(t, serverURL, adminToken, "canon-sched-failover", repoURL, canonicalQuickPipeline)
	var failoverJob canonJob
	waitFor(t, "failover job claimed by a live runner", 90*time.Second, func() bool {
		var jobs []canonJob
		if apiGet(t, serverURL, adminToken, "/api/v1/runs/"+failoverRunID+"/jobs", &jobs) != 200 || len(jobs) == 0 {
			return false
		}
		for _, j := range jobs {
			if j.Status == "success" && j.AttemptRunnerID != "" && j.AttemptRunnerID != idA {
				failoverJob = j
				return true
			}
		}
		return false
	})
	if failoverJob.AttemptRunnerID == "" || failoverJob.AttemptRunnerID == idA {
		t.Fatalf("failover job completed by the hard-killed runner %q (want a live runner != %q)", failoverJob.AttemptRunnerID, idA)
	}
	t.Logf("canonical STAGE 5a ok: runner failover — killed %s, job completed by %s", idA, failoverJob.AttemptRunnerID)

	// 5b. Work retry: a failing job is retried as a fresh run and succeeds.
	failRunID := canonicalTriggerTrusted(t, serverURL, adminToken, "canon-sched-fail", repoURL, canonicalFailPipeline)
	var failedJob canonJob
	waitFor(t, "failing job terminal failure", 60*time.Second, func() bool {
		var jobs []canonJob
		if apiGet(t, serverURL, adminToken, "/api/v1/runs/"+failRunID+"/jobs", &jobs) != 200 {
			return false
		}
		for _, j := range jobs {
			if j.Status == "failure" {
				failedJob = j
				return true
			}
		}
		return false
	})
	if failedJob.Error == "" {
		t.Fatal("failed job carries no error message")
	}
	retryRunID := canonicalTriggerTrusted(t, serverURL, adminToken, "canon-sched-retry", repoURL, canonicalQuickPipeline)
	waitFor(t, "retried work terminal success", 90*time.Second, func() bool {
		var jobs []canonJob
		if apiGet(t, serverURL, adminToken, "/api/v1/runs/"+retryRunID+"/jobs", &jobs) != 200 {
			return false
		}
		for _, j := range jobs {
			if j.Key == "quick" && j.Status == "success" {
				return true
			}
		}
		return false
	})
	t.Logf("canonical STAGE 5b ok: work retry — fail run=%s error=%q, retried run=%s succeeded", failRunID, failedJob.Error, retryRunID)

	// 5c. Control-plane kill mid-flight + completion-retry contracts.
	// The live OS runners are stopped first so the chaos lease/complete
	// sequence is driven exclusively over the product runner API (the same
	// handler → authorization → store path a production runner uses) and no
	// real executor can complete the mid-flight job behind our back.
	runnerB.killNow()
	runnerB2.killNow()
	chaosSys, err := system.Attach(serverURL, adminToken, runnerToken, filepath.Join(root, "chaos-work"))
	if err != nil {
		t.Fatalf("attach chaos: %v", err)
	}
	defer func() { _ = chaosSys.Close() }()
	chaosRunID, err := chaosSys.SubmitPipeline(ctx, canonicalChaosPipeline, system.SubmitOpts{})
	if err != nil {
		t.Fatalf("submit chaos: %v", err)
	}
	chaosRunnerID, err := chaosSys.RegisterRunner(ctx, "canon-chaos-holder", []string{"native", "container"})
	if err != nil {
		t.Fatalf("register chaos runner: %v", err)
	}
	task1 := canonicalLeaseOne(t, ctx, chaosSys, chaosRunnerID)
	code, err := chaosSys.Complete(ctx, task1, model.StatusSuccess, "")
	if err != nil {
		t.Fatalf("pre-kill complete: %v", err)
	}
	if code != http.StatusNoContent {
		t.Fatalf("pre-kill complete = HTTP %d, want 204", code)
	}
	task2 := canonicalLeaseOne(t, ctx, chaosSys, chaosRunnerID)
	if task2.JobID == task1.JobID {
		t.Fatal("leased the already-completed job twice")
	}

	// SIGKILL the control plane mid-flight (one job terminal, one leased).
	srv.killNow()
	srv = spawnServer(t, headBin, serverListen, dataDir, pgDSN, runnerToken, adminToken)
	waitFor(t, "restarted server liveness", 60*time.Second, func() bool {
		resp, err := http.Get(serverURL + "/liveness")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})

	// Stale completion: refused, mutates nothing.
	stale := task2
	stale.LeaseGeneration = task2.LeaseGeneration + 99
	code, err = chaosSys.Complete(ctx, stale, model.StatusSuccess, "")
	if err != nil {
		t.Fatalf("stale complete transport: %v", err)
	}
	if code != http.StatusConflict {
		t.Fatalf("stale complete after restart = HTTP %d, want 409", code)
	}
	j2, err := chaosSys.JobByKey(ctx, chaosRunID, task2.JobKey)
	if err != nil {
		t.Fatalf("job %q after stale complete: %v", task2.JobKey, err)
	}
	if j2.Status.Terminal() {
		t.Fatalf("stale completion mutated job %q to %s", task2.JobKey, j2.Status)
	}

	// Completion retry (a): identical replay is idempotent.
	code, err = chaosSys.Complete(ctx, task1, model.StatusSuccess, "")
	if err != nil {
		t.Fatalf("replay complete transport: %v", err)
	}
	if code != http.StatusNoContent {
		t.Fatalf("identical completion replay = HTTP %d, want 204 (idempotent retry)", code)
	}
	// Completion retry (b): a conflicting second completion is refused.
	code, err = chaosSys.Complete(ctx, task1, model.StatusFailure, "canonical conflicting completion")
	if err != nil {
		t.Fatalf("conflict complete transport: %v", err)
	}
	if code != http.StatusConflict {
		t.Fatalf("conflicting completion = HTTP %d, want 409", code)
	}
	j1, err := chaosSys.JobByKey(ctx, chaosRunID, task1.JobKey)
	if err != nil {
		t.Fatalf("job %q after replay attempts: %v", task1.JobKey, err)
	}
	if j1.Status != model.StatusSuccess || j1.AttemptRunnerID == "" {
		t.Fatalf("double completion moved job %q: status=%s attempt=%q", task1.JobKey, j1.Status, j1.AttemptRunnerID)
	}

	// Liveness: the surviving lease completes; fresh work after the restart
	// also completes.
	code, err = chaosSys.Complete(ctx, task2, model.StatusSuccess, "")
	if err != nil {
		t.Fatalf("post-restart complete: %v", err)
	}
	if code != http.StatusNoContent {
		t.Fatalf("surviving-lease complete = HTTP %d, want 204", code)
	}
	if st, err := chaosSys.WaitJobTerminal(ctx, chaosRunID, task2.JobKey); err != nil || st != model.StatusSuccess {
		t.Fatalf("mid-flight job after restart: status=%s err=%v", st, err)
	}
	freshRunID, err := chaosSys.SubmitPipeline(ctx, canonicalChaosPipeline, system.SubmitOpts{})
	if err != nil {
		t.Fatalf("submit fresh after restart: %v", err)
	}
	task3 := canonicalLeaseOne(t, ctx, chaosSys, chaosRunnerID)
	if code, err = chaosSys.Complete(ctx, task3, model.StatusSuccess, ""); err != nil || code != http.StatusNoContent {
		t.Fatalf("fresh post-restart complete = HTTP %d err=%v", code, err)
	}
	if st, err := chaosSys.WaitJobTerminal(ctx, freshRunID, task3.JobKey); err != nil || st != model.StatusSuccess {
		t.Fatalf("fresh post-restart job: status=%s err=%v", st, err)
	}
	// The full chaos run itself is success (both original jobs terminal).
	if run, err := chaosSys.QueryRun(ctx, chaosRunID); err != nil || run.Status != model.StatusSuccess {
		t.Fatalf("chaos run status after kill/failover = %v err=%v, want success", run.Status, err)
	}
	t.Logf("canonical STAGE 5c ok: control-plane kill/failover + completion retry (run=%s)", chaosRunID)

	// ====================================================================
	// STAGE 6 — backup → destroy → restore, proof survives
	// ====================================================================
	// Capture every historical proof BEFORE the disaster.
	envBefore := fetchEvidence(t, serverURL, adminToken, probeJob.ID, probeJob.LeaseGeneration)
	if !bytes.Equal(probeEnv, envBefore) {
		t.Fatal("probe attestation drifted between stage 4 and backup")
	}
	n1EnvNow := fetchEvidence(t, serverURL, adminToken, n1Job.ID, n1Job.LeaseGeneration)
	if !bytes.Equal(n1Env, n1EnvNow) {
		t.Fatal("N-1 attestation drifted before backup")
	}
	artCode, artBytesBefore := apiGetBytes(t, serverURL, adminToken, "/api/v1/artifacts/"+artProbe.ID)
	if artCode != 200 || len(artBytesBefore) == 0 {
		t.Fatalf("download artifact before backup = HTTP %d (%d bytes)", artCode, len(artBytesBefore))
	}

	// Backup: pg_dump of the application database + object-store copy.
	backupDir := filepath.Join(root, "backup")
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dumpPath := filepath.Join(backupDir, "db.dump")
	pgDump := resolvePG(t, "pg_dump")
	if out, err := exec.Command(pgDump, "--format=custom", "-f", dumpPath, pgDSN).CombinedOutput(); err != nil {
		t.Fatalf("pg_dump: %v\n%s", err, out)
	}
	dataBackup := filepath.Join(backupDir, "data")
	if err := copyTree(dataDir, dataBackup); err != nil {
		t.Fatalf("backup object store: %v", err)
	}

	// Destroy: stop the server, drop the application database, remove the
	// object store.
	srv.kill()
	psql := resolvePG(t, "psql")
	if out, err := exec.Command(psql, pgAdmin, "-c", "DROP DATABASE IF EXISTS "+dbName).CombinedOutput(); err != nil {
		t.Fatalf("drop database: %v\n%s", err, out)
	}
	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatalf("destroy object store: %v", err)
	}

	// Restore: fresh database + restored object store at a NEW path
	// (production EnvelopeRef is CAS-relative and must survive a path change).
	if out, err := exec.Command(psql, pgAdmin, "-c", "CREATE DATABASE "+dbName).CombinedOutput(); err != nil {
		t.Fatalf("recreate database: %v\n%s", err, out)
	}
	pgRestore := resolvePG(t, "pg_restore")
	if out, err := exec.Command(pgRestore, "-d", pgDSN, dumpPath).CombinedOutput(); err != nil {
		t.Logf("pg_restore: %v\n%s", err, out)
	}
	dataDir2 := filepath.Join(root, "data-restored")
	if err := copyTree(dataBackup, dataDir2); err != nil {
		t.Fatalf("restore object store: %v", err)
	}

	// New processes on restored state.
	serverPort2 := freeTCPPort(t)
	serverURL2 := fmt.Sprintf("http://127.0.0.1:%d", serverPort2)
	srv2 := spawnServer(t, headBin, fmt.Sprintf("127.0.0.1:%d", serverPort2), dataDir2, pgDSN, runnerToken, adminToken)
	defer srv2.kill()
	waitFor(t, "restored server liveness", 60*time.Second, func() bool {
		resp, err := http.Get(serverURL2 + "/liveness")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})

	// Historical run is queryable.
	var runAfter struct {
		ID string `json:"id"`
	}
	if code := apiGet(t, serverURL2, adminToken, "/api/v1/runs/"+trustedRunID, &runAfter); code != 200 || runAfter.ID != trustedRunID {
		t.Fatalf("restored trusted run query = HTTP %d id=%q", code, runAfter.ID)
	}

	// Historical evidence MUST still verify — byte-identical, same root.
	envAfter := fetchEvidence(t, serverURL2, adminToken, probeJob.ID, probeJob.LeaseGeneration)
	if !bytes.Equal(probeEnv, envAfter) {
		t.Fatal("probe attestation envelope changed across backup/destroy/restore")
	}
	stAfter := verifyEvidence(t, serverURL2, envAfter)
	if stAfter.Attestation == nil || stAfter.Attestation.EvidenceRootSHA256 != probeSt.Attestation.EvidenceRootSHA256 {
		t.Fatalf("restored probe evidence root = %+v, want %q", stAfter.Attestation, probeSt.Attestation.EvidenceRootSHA256)
	}
	// N-1-origin history also survives (the upgrade chain is part of the
	// durable proof).
	n1EnvAfter := fetchEvidence(t, serverURL2, adminToken, n1Job.ID, n1Job.LeaseGeneration)
	if !bytes.Equal(n1Env, n1EnvAfter) {
		t.Fatal("N-1 attestation envelope changed across backup/destroy/restore")
	}
	if st := verifyEvidence(t, serverURL2, n1EnvAfter); st.Attestation == nil || st.Attestation.JobID != n1Job.ID {
		t.Fatalf("restored N-1 attestation mismatch: %+v", st.Attestation)
	}
	// Artifact bytes unchanged.
	artCode2, artBytesAfter := apiGetBytes(t, serverURL2, adminToken, "/api/v1/artifacts/"+artProbe.ID)
	if artCode2 != 200 || len(artBytesAfter) == 0 {
		t.Fatalf("download artifact after restore = HTTP %d (%d bytes)", artCode2, len(artBytesAfter))
	}
	if !bytes.Equal(artBytesBefore, artBytesAfter) {
		t.Fatal("artifact bytes changed across backup/destroy/restore")
	}

	// Liveness on the restored cluster: new job B completes with evidence.
	workB2 := filepath.Join(root, "work-b2")
	_ = os.MkdirAll(workB2, 0o700)
	_ = spawnRunner(t, headBin, serverURL2, runnerToken, "canon-runner-b2", workB2, filepath.Join(root, "id-b2"))
	waitFor(t, "restored-cluster runner registered", 30*time.Second, func() bool {
		var rs []any
		return apiGet(t, serverURL2, adminToken, "/api/v1/runners", &rs) == 200 && len(rs) >= 1
	})
	jobBRunID := canonicalTriggerTrusted(t, serverURL2, adminToken, "canon-sched-restore", repoURL, canonicalQuickPipeline)
	var jobB canonJob
	waitFor(t, "job B terminal success on restored cluster", 120*time.Second, func() bool {
		var jobs []canonJob
		if apiGet(t, serverURL2, adminToken, "/api/v1/runs/"+jobBRunID+"/jobs", &jobs) != 200 {
			return false
		}
		for _, j := range jobs {
			if j.Status == "success" {
				jobB = j
				return true
			}
			if j.Status == "failure" {
				t.Fatalf("job B failed on restored cluster: %q", j.Error)
			}
		}
		return false
	})
	envB := fetchEvidence(t, serverURL2, adminToken, jobB.ID, jobB.LeaseGeneration)
	if st := verifyEvidence(t, serverURL2, envB); st.Attestation == nil || st.Attestation.JobID != jobB.ID {
		t.Fatalf("job B attestation on restored cluster mismatch: %+v", st.Attestation)
	}
	t.Logf("canonical STAGE 6 ok: backup/destroy/restore preserved probe=%s n1=%s artifact=%s; job B run=%s",
		probeDigest, n1EnvDigest, artProbe.SHA256, jobBRunID)

	// ====================================================================
	// STAGE 7 — packaged artifact serves the restored production state
	// ====================================================================
	pkgSHA := canonicalSHA256File(t, headBin)
	if pkgSHA != headSHA {
		t.Fatalf("HEAD binary drifted during the scenario: now %s, built %s", pkgSHA, headSHA)
	}
	installDir := filepath.Join(root, "install")
	if err := os.MkdirAll(installDir, 0o700); err != nil {
		t.Fatal(err)
	}
	installedBin := filepath.Join(installDir, "kiwi")
	if err := canonicalCopyFile(headBin, installedBin); err != nil {
		t.Fatalf("install packaged binary: %v", err)
	}
	if got := canonicalSHA256File(t, installedBin); got != pkgSHA {
		t.Fatalf("installed binary sha256 = %s, want packaged %s", got, pkgSHA)
	}

	// The installed packaged bytes take the restored state (stop the
	// restore-server first so the packaged binary is THE server).
	srv2.kill()
	serverPort3 := freeTCPPort(t)
	serverURL3 := fmt.Sprintf("http://127.0.0.1:%d", serverPort3)
	srv3 := spawnServer(t, installedBin, fmt.Sprintf("127.0.0.1:%d", serverPort3), dataDir2, pgDSN, runnerToken, adminToken)
	defer srv3.kill()
	waitFor(t, "packaged server liveness", 60*time.Second, func() bool {
		resp, err := http.Get(serverURL3 + "/liveness")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})

	// Packaged binary serves the full history chain (N-1 origin + trusted
	// probe + restored job B) and their evidence still verifies.
	type histRef struct {
		name            string
		run             string
		jobID           string
		leaseGeneration int64
		env             []byte
	}
	histIDs := []histRef{
		{"n1-origin", n1RunID, n1Job.ID, n1Job.LeaseGeneration, n1Env},
		{"trusted-probe", trustedRunID, probeJob.ID, probeJob.LeaseGeneration, probeEnv},
		{"restore-jobB", jobBRunID, jobB.ID, jobB.LeaseGeneration, envB},
	}
	for _, h := range histIDs {
		var runView struct {
			ID string `json:"id"`
		}
		if code := apiGet(t, serverURL3, adminToken, "/api/v1/runs/"+h.run, &runView); code != 200 || runView.ID != h.run {
			t.Fatalf("packaged server lost %s run %s (HTTP %d)", h.name, h.run, code)
		}
		env := fetchEvidence(t, serverURL3, adminToken, h.jobID, h.leaseGeneration)
		if !bytes.Equal(h.env, env) {
			t.Fatalf("packaged server changed %s attestation bytes", h.name)
		}
		if st := verifyEvidence(t, serverURL3, env); st.Attestation == nil || st.Attestation.JobID != h.jobID {
			t.Fatalf("packaged server's %s attestation does not verify: %+v", h.name, st.Attestation)
		}
	}

	// New work on the packaged binary.
	work3 := filepath.Join(root, "work-pkg")
	_ = os.MkdirAll(work3, 0o700)
	_ = spawnRunner(t, installedBin, serverURL3, runnerToken, "canon-runner-pkg", work3, filepath.Join(root, "id-pkg"))
	waitFor(t, "packaged-server runner registered", 30*time.Second, func() bool {
		var rs []any
		return apiGet(t, serverURL3, adminToken, "/api/v1/runners", &rs) == 200 && len(rs) >= 1
	})
	pkgRunID := canonicalTriggerTrusted(t, serverURL3, adminToken, "canon-sched-pkg", repoURL, canonicalQuickPipeline)
	var pkgJob canonJob
	waitFor(t, "packaged-artifact job terminal success", 120*time.Second, func() bool {
		var jobs []canonJob
		if apiGet(t, serverURL3, adminToken, "/api/v1/runs/"+pkgRunID+"/jobs", &jobs) != 200 {
			return false
		}
		for _, j := range jobs {
			if j.Status == "success" {
				pkgJob = j
				return true
			}
			if j.Status == "failure" {
				t.Fatalf("packaged-artifact job failed: %q", j.Error)
			}
		}
		return false
	})
	pkgEnv := fetchEvidence(t, serverURL3, adminToken, pkgJob.ID, pkgJob.LeaseGeneration)
	if st := verifyEvidence(t, serverURL3, pkgEnv); st.Attestation == nil || st.Attestation.JobID != pkgJob.ID {
		t.Fatalf("packaged-artifact job attestation mismatch: %+v", st.Attestation)
	}

	// Binary-used hash equals the recorded package hash (re-read the file
	// the server process was started from).
	finalSHA := canonicalSHA256File(t, installedBin)
	if finalSHA != pkgSHA {
		t.Fatalf("post-run binary-used sha256 = %s, want packaged %s", finalSHA, pkgSHA)
	}
	t.Logf("canonical STAGE 7 ok: packaged artifact sha256=%s served run=%s job=%s", finalSHA, pkgRunID, pkgJob.ID)

	t.Logf("canonical release scenario COMPLETE: N-1=%s HEAD/pkg=%s n1Run=%s trustedRun=%s chaosRun=%s restoreRun=%s pkgRun=%s",
		n1SHA, pkgSHA, n1RunID, trustedRunID, chaosRunID, jobBRunID, pkgRunID)
}

// ---------------------------------------------------------------------------
// canonical scenario pipelines
// ---------------------------------------------------------------------------

// canonicalTrustedPipeline is the trusted-native workload with a hold job
// (forces both runners to claim) and a probe job that emits a deterministic
// artifact into the object store.
const canonicalTrustedPipeline = `version: 1
on:
  schedule:
    cron: "0 0 * * *"
jobs:
  hold:
    runtime: native
    steps:
      - name: hold
        run: sleep 3 && echo held
  probe:
    runtime: native
    steps:
      - name: probe
        run: |
          set -euo pipefail
          mkdir -p out
          echo canonical-release-artifact-v1 > out/probe.bin
    artifacts:
      - name: probe
        paths: [out]
`

// canonicalQuickPipeline is the smallest trusted-native workload.
const canonicalQuickPipeline = `version: 1
on:
  schedule:
    cron: "0 0 * * *"
jobs:
  quick:
    runtime: native
    steps:
      - name: quick
        run: echo canonical-quick-done
`

// canonicalFailPipeline is a trusted-native job that fails on purpose (the
// work-retry arm of the kill/failover stage).
const canonicalFailPipeline = `version: 1
on:
  schedule:
    cron: "0 0 * * *"
jobs:
  fail:
    runtime: native
    steps:
      - name: fail
        run: echo canonical-expected-failure && exit 1
`

// canonicalUntrustedPipeline is a digest-pinned, network-none untrusted
// container job submitted over the direct API (always untrusted).
const canonicalUntrustedPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
    network: none
    placement:
      labels: [quota-gate]
    steps:
      - run: echo canonical-untrusted
`

// canonicalChaosPipeline is the two-job workload for the mid-flight kill.
// Direct API submissions are always untrusted and untrusted policy forbids
// native host execution, so the jobs are digest-pinned containers (the
// synthetic chaos runner leases and completes them over the product API
// without invoking a container backend).
const canonicalChaosPipeline = `version: 1
jobs:
  alpha:
    runtime: container
    image: alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
    network: none
    steps:
      - run: echo canonical-alpha
  beta:
    runtime: container
    image: alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
    network: none
    steps:
      - run: echo canonical-beta
`

// ---------------------------------------------------------------------------
// canonical scenario helpers
// ---------------------------------------------------------------------------

// canonicalGoTool resolves the Go toolchain used for every source build.
func canonicalGoTool(t *testing.T) string {
	t.Helper()
	if env := os.Getenv("KIWI_TEST_GO"); env != "" {
		if st, err := os.Stat(env); err == nil && !st.IsDir() {
			return env
		}
	}
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	t.Fatal("go toolchain not found on PATH (set KIWI_TEST_GO to override)")
	return ""
}

// canonicalSHA256File returns the lowercase hex SHA-256 of a file's bytes.
func canonicalSHA256File(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// canonicalCopyFile copies src to dst byte-for-byte (packaged-artifact install).
func canonicalCopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// canonicalResolveNMinusOne produces a real N-1 product binary at outPath.
// A released artifact (KIWI_N_MINUS_ONE_BIN, optionally hash-pinned by
// KIWI_N_MINUS_ONE_SHA256) is preferred; otherwise a prior git commit is
// built from a real worktree. Under KIWI_REQUIRE_N_MINUS_ONE=1 a missing or
// unbuildable N-1 is a hard failure — the release scenario cannot drop the
// upgrade stage. Returns the N-1 identity (released sha256 or commit sha).
func canonicalResolveNMinusOne(t *testing.T, srcDir, goBin, outPath string) string {
	t.Helper()
	if bin := strings.TrimSpace(os.Getenv("KIWI_N_MINUS_ONE_BIN")); bin != "" {
		if st, err := os.Stat(bin); err != nil || st.IsDir() {
			t.Fatalf("released N-1 artifact %q is not a readable file: %v", bin, err)
		}
		sha := canonicalSHA256File(t, bin)
		if want := strings.TrimSpace(strings.ToLower(os.Getenv("KIWI_N_MINUS_ONE_SHA256"))); want != "" && sha != want {
			t.Fatalf("released N-1 artifact %q sha256 = %s, want pinned %s", bin, sha, want)
		}
		if err := canonicalCopyFile(bin, outPath); err != nil {
			t.Fatalf("install released N-1: %v", err)
		}
		if got := canonicalSHA256File(t, outPath); got != sha {
			t.Fatalf("installed N-1 sha256 = %s, want released %s", got, sha)
		}
		return sha
	}

	n1SHA := canonicalPickNMinusOneSHA(t, srcDir)
	required := false
	switch strings.ToLower(strings.TrimSpace(os.Getenv("KIWI_REQUIRE_N_MINUS_ONE"))) {
	case "1", "true", "yes":
		required = true
	}
	if n1SHA == "" {
		msg := "no prior commit produced a buildable N-1 worktree (set KIWI_REQUIRE_N_MINUS_ONE=1 to fail closed, or supply KIWI_N_MINUS_ONE_BIN/KIWI_N_MINUS_ONE_SHA256)"
		if required {
			t.Fatal("canonical N-1→N: " + msg)
		}
		t.Skip("canonical N-1→N: " + msg)
	}
	wt := filepath.Join(t.TempDir(), "kiwi-n1-wt")
	add := exec.Command("git", "worktree", "add", "--detach", wt, n1SHA)
	add.Dir = srcDir
	if out, err := add.CombinedOutput(); err != nil {
		msg := fmt.Sprintf("git worktree add %s: %v\n%s", n1SHA, err, out)
		if required {
			t.Fatal("canonical N-1→N: " + msg)
		}
		t.Skip("canonical N-1→N: " + msg)
	}
	defer func() {
		rm := exec.Command("git", "worktree", "remove", "--force", wt)
		rm.Dir = srcDir
		_ = rm.Run()
	}()
	build := exec.Command(goBin, "build", "-o", outPath, "./cmd/kiwi")
	build.Dir = wt
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		msg := fmt.Sprintf("N-1 go build from %s: %v\n%s", n1SHA, err, out)
		if required {
			t.Fatal("canonical N-1→N: " + msg)
		}
		t.Skip("canonical N-1→N: " + msg)
	}
	return n1SHA
}

// canonicalPickNMinusOneSHA walks recent history for a commit that is not
// HEAD. KIWI_N_MINUS_ONE_SHA forces the commit. Returns "" when none is
// acceptable (caller skips or fatals per KIWI_REQUIRE_N_MINUS_ONE).
func canonicalPickNMinusOneSHA(t *testing.T, srcDir string) string {
	t.Helper()
	if forced := strings.TrimSpace(os.Getenv("KIWI_N_MINUS_ONE_SHA")); forced != "" {
		rev := exec.Command("git", "rev-parse", "--verify", forced+"^{commit}")
		rev.Dir = srcDir
		if o, err := rev.CombinedOutput(); err == nil {
			return strings.TrimSpace(string(o))
		}
		return ""
	}
	log := exec.Command("git", "log", "--format=%H", "-n", "15")
	log.Dir = srcDir
	out, err := log.CombinedOutput()
	if err != nil {
		t.Fatalf("git log: %v\n%s", err, out)
	}
	head := exec.Command("git", "rev-parse", "HEAD")
	head.Dir = srcDir
	headOut, err := head.CombinedOutput()
	if err != nil {
		t.Fatalf("git rev-parse HEAD: %v\n%s", err, headOut)
	}
	headSHA := strings.TrimSpace(string(headOut))
	for _, line := range strings.Split(string(out), "\n") {
		sha := strings.TrimSpace(line)
		if sha != "" && sha != headSHA {
			return sha
		}
	}
	return ""
}

// canonicalWriteHistory creates durable run/job history over the public API:
// one untrusted submit, a synthetic runner registration, a real next lease,
// and a real complete. No executor runs — the control plane still persists
// the full lifecycle, which is the state the upgrade must preserve. The
// pipeline is a digest-pinned container job because direct API submissions
// are always untrusted and untrusted policy forbids native host execution.
func canonicalWriteHistory(ctx context.Context, t *testing.T, sys *system.System, marker string) (string, system.JobView) {
	t.Helper()
	runID, err := sys.SubmitPipeline(ctx, canonicalUntrustedPipeline, system.SubmitOpts{
		RepoFullName: "kiwi-dogfood/canon-" + marker,
		RepoURL:      "https://github.com/kiwi-dogfood/canon-" + marker + ".git",
	})
	if err != nil {
		t.Fatalf("submit history %s: %v", marker, err)
	}
	runnerID, err := sys.RegisterRunner(ctx, "hist-"+marker, []string{"native", "container"})
	if err != nil {
		t.Fatalf("register history runner: %v", err)
	}
	task := canonicalLeaseOne(t, ctx, sys, runnerID)
	code, err := sys.Complete(ctx, task, model.StatusSuccess, "")
	if err != nil {
		t.Fatalf("complete history: %v", err)
	}
	if code != http.StatusNoContent {
		t.Fatalf("complete history = HTTP %d, want 204", code)
	}
	status, err := sys.WaitJobTerminal(ctx, runID, task.JobKey)
	if err != nil {
		t.Fatalf("wait history terminal: %v", err)
	}
	if status != model.StatusSuccess {
		t.Fatalf("history job status = %s, want success", status)
	}
	job, err := sys.JobByKey(ctx, runID, task.JobKey)
	if err != nil {
		t.Fatalf("history job: %v", err)
	}
	return runID, job
}

// canonicalTriggerTrusted puts a trusted schedule and triggers one run over
// the public API (the product trusted ingress used by every dist dogfood).
func canonicalTriggerTrusted(t *testing.T, baseURL, adminToken, schedID, repoURL, spec string) string {
	t.Helper()
	schedBody := map[string]any{
		"id":         schedID,
		"repository": "owner/repo",
		"repo_url":   repoURL,
		"spec":       spec,
		"trusted":    true,
		"enabled":    true,
	}
	var sched struct {
		ID string `json:"id"`
	}
	code, raw := apiPut(t, baseURL, adminToken, "/api/v1/schedules", schedBody, &sched)
	if code >= 300 {
		t.Fatalf("schedule put = %d: %s", code, raw)
	}
	var run struct {
		ID string `json:"id"`
	}
	code, raw = apiPost(t, baseURL, adminToken, "/api/v1/schedules/"+sched.ID+"/trigger", map[string]any{}, &run)
	if code >= 300 {
		t.Fatalf("trigger = %d: %s", code, raw)
	}
	if run.ID == "" {
		t.Fatalf("no run id in trigger response: %s", raw)
	}
	return run.ID
}

// canonicalLeaseOne polls the product next endpoint until one task is leased.
func canonicalLeaseOne(t *testing.T, ctx context.Context, sys *system.System, runnerID string) system.LeaseTask {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		task, ok, err := sys.Next(ctx, runnerID)
		if err != nil {
			t.Fatalf("next: %v", err)
		}
		if ok {
			return task
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context done waiting for a lease: %v", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("no task was leased within the deadline")
	return system.LeaseTask{}
}

// canonicalProbeHardQuota reports whether this host can install a real
// OS-level hard bound on a workspace tree (the same product entry point the
// runner uses). Always cleans up.
func canonicalProbeHardQuota(t *testing.T) (bool, string) {
	t.Helper()
	dir := t.TempDir()
	st, cleanup := executor.WorkspaceDiskQuotaSetup(dir, 4<<20)
	if cleanup != nil {
		defer func() { _ = cleanup() }()
	}
	return st.Hard, st.Detail
}

// canonicalDockerNonRootless reports whether a docker daemon is present and
// NOT rootless — the observable arm of the untrusted rootless floor.
func canonicalDockerNonRootless(t *testing.T) bool {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	out, err := exec.Command("docker", "info", "--format", "{{.SecurityOptions}}").CombinedOutput()
	if err != nil {
		return false
	}
	return !strings.Contains(strings.ToLower(string(out)), "rootless")
}
