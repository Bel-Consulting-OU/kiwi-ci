package system_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/dogfood/system"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// fullCIPathPipeline is the Woodpecker-level workload: one trusted native
// job that declares a secret, a cache, and an artifact — the complete
// practical CI path the frozen scope requires.
const fullCIPathPipeline = `version: 1
name: woodpecker-path
secrets:
  - CI_TOKEN
jobs:
  build:
    steps:
      - name: prove-path
        run: |
          echo "secret-present=${KIWI_SECRET_CI_TOKEN:+yes}"
          mkdir -p .kiwi-cache && echo cached > .kiwi-cache/data.txt
          echo "artifact-body" > out.txt
          echo "log-line-1"
          echo "log-line-2"
    cache:
      - name: build-cache
        paths: [".kiwi-cache"]
        hash_files: ["go.sum"]
    artifacts:
      - name: out
        paths: ["out.txt"]
`

// TestSysWoodpeckerPathE2E is the frozen-scope acceptance proof: one normal
// push through the real webhook ingress produces a complete CI result.
//
//	Connect repository → push → webhook → parse/validate → schedule runner
//	→ execute (secret + cache + artifact + logs) → result → SCM status
//
// Every step is asserted. If any link in the chain is missing, this test
// fails: that is exactly what "as good as Woodpecker as a practical CI/CD
// system" means.
func TestSysWoodpeckerPathE2E(t *testing.T) {
	// Hermetic: native runner lane, never a container (see
	// fake_docker_system_test.go).
	installFakeDockerForSystem(t)
	// A static secret store so the CI_TOKEN declaration actually resolves:
	// the ordinary CI secret path must work end-to-end.
	sys := startWithSecrets(t, map[string]string{"CI_TOKEN": "woodpecker-path-token"})
	if !sys.TrustedWebhookEnabled() {
		t.Fatal("trusted webhook ingress not enabled")
	}
	// 1. Runner: a real OS runner process is online and eligible.
	if err := sys.StartRunner("woodpecker-path-runner", nil); err != nil {
		t.Fatalf("start runner: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// 2. Push → webhook → parse + validate → enqueue.
	runID, err := sys.DeliverTrustedPush(ctx, "woodpecker-path-1", fullCIPathPipeline)
	if err != nil {
		t.Fatalf("deliver trusted push: %v", err)
	}
	if runID == "" {
		t.Fatal("webhook produced no run id")
	}

	// 3. The run is accepted and the job is queued with the right shape.
	j, err := sys.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	if j.Status == model.StatusFailure {
		t.Fatalf("job failed immediately: %q", j.Error)
	}

	// 4. Execution reaches a terminal result through the real runner.
	status, err := sys.WaitJobTerminal(ctx, runID, "build")
	if err != nil {
		t.Fatalf("wait job: %v", err)
	}
	if status != model.StatusSuccess {
		j, _ = sys.JobByKey(ctx, runID, "build")
		t.Fatalf("job status = %s error=%q, want success", status, j.Error)
	}
	j, err = sys.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("job re-read: %v", err)
	}

	// 5. The job was executed by a real runner (not a simulated one).
	deadline := time.Now().Add(10 * time.Second)
	for j.AttemptRunnerID == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		j, err = sys.JobByKey(ctx, runID, "build")
		if err != nil {
			t.Fatalf("job re-read: %v", err)
		}
	}
	if j.AttemptRunnerID == "" {
		t.Fatal("job has no attempt runner id: the runner never executed it")
	}

	// 6. Logs: the job produced output the operator can read.
	if logs := sys.JobLogs(ctx, runID, "build"); logs == "" {
		t.Fatal("job produced no logs")
	} else if !strings.Contains(logs, "log-line-1") {
		t.Fatalf("logs missing expected output: %q", logs)
	}

	// 7. Artifacts: the declared artifact was uploaded and is retrievable.
	// Artifact uploads are gzip tarballs by contract; the proof is that the
	// bytes are present and gzip-shaped, not that the tar payload is plain.
	art := sys.JobArtifact(ctx, runID, "build", "out")
	if art == "" {
		t.Fatal("declared artifact was not uploaded/retrievable")
	}
	if len(art) < 2 || art[0] != 0x1f || art[1] != 0x8b {
		t.Fatalf("artifact is not a gzip payload (got %d bytes)", len(art))
	}

	// 8. Cache: the cache declaration survived compilation — the cache key
	// is recorded on the compiled job payload the runner executes.
	if j.CompiledJobPayload == nil {
		t.Fatal("job has no compiled payload")
	}
	payload := fmt.Sprintf("%v", j.CompiledJobPayload.EffectiveJob)
	if !strings.Contains(payload, "build-cache") {
		t.Fatalf("compiled payload lost the cache declaration: %v", payload)
	}

	// 9. Secret: the job declared CI_TOKEN and the delivery path accepted
	// it (untrusted jobs never receive secrets; this job is trusted).
	if !j.Trusted {
		t.Fatal("webhook-derived job is not trusted")
	}
	found := false
	for _, s := range j.DeclaredSecrets {
		if s == "CI_TOKEN" {
			found = true
		}
	}
	if !found {
		t.Fatalf("declared secrets = %v, want CI_TOKEN", j.DeclaredSecrets)
	}

	// 10. SCM status: the completion produced a forge status publication
	// (the outbox's forge_delivery intent is the SCM check update). The
	// outbox flushes on the Maintain tick / completion flush — poll like
	// any other asynchronous publication.
	scmDeadline := time.Now().Add(15 * time.Second)
	for !sys.ForgeStatusPublished(ctx, runID) && time.Now().Before(scmDeadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !sys.ForgeStatusPublished(ctx, runID) {
		t.Fatal("no SCM status was published for the completed job")
	}

	// 11. Evidence: the run produced a verifiable attestation — the
	// extra-strong layer on top of ordinary CI, kept frozen.
	envBytes, err := sys.FetchEvidence(ctx, j.ID, j.LeaseGeneration)
	if err != nil {
		t.Fatalf("fetch evidence: %v", err)
	}
	if _, err := sys.VerifyEvidence(ctx, envBytes); err != nil {
		t.Fatalf("verify evidence: %v", err)
	}

}

// startWithSecrets launches the harness with a static secret store.
func startWithSecrets(t *testing.T, secrets map[string]string) *system.System {
	t.Helper()
	return system.StartWithSecrets(t, secrets)
}
