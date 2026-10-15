package system

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// DF-LOCK-001: image-lock determinism authority is end-to-end. The repo's
// .kiwi/lock.json fetched at the SAME revision as the pipeline is applied by
// the canonical resolver — the enqueued job's canonical pipeline text must
// carry the LOCKED digests, never the mutable authoring tags. A bug that
// applies the lock only to a temporary webhook spec (or only at trigger
// eval) fails this test.
const lockAuthorityPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: example.invalid/app:1.0
    services:
      - name: db
        image: example.invalid/db:1.0
    steps:
      - run: echo locked
`

const lockAuthorityLock = `{
  "version": 1,
  "images": [
    {"ref": "example.invalid/app:1.0", "digest": "example.invalid/app:1.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    {"ref": "example.invalid/db:1.0", "digest": "example.invalid/db:1.0@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
  ]
}`

// TestSysDFLockAuthority001 proves the lock reaches the compiled graph that
// every runner recompiles. The workload is a trusted container job so the
// image identity is real execution input (not just a string in a document).
func TestSysDFLockAuthority001(t *testing.T) {
	t.Parallel()
	sys, err := Launch(SystemConfig{
		RunnerToken: "sys-lock-runner",
		AdminToken:  "sys-lock-admin",
		DataDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer func() { _ = sys.Close() }()

	if err := sys.EnableTrustedWebhook(TrustedWebhookConfig{
		PipelineYAML: lockAuthorityPipeline,
		LockYAML:     lockAuthorityLock,
	}); err != nil {
		t.Fatalf("enable trusted webhook: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	runID, err := sys.DeliverTrustedPush(ctx, "lock-authority-1", lockAuthorityPipeline)
	if err != nil {
		t.Fatalf("deliver trusted push: %v", err)
	}

	job, err := sys.JobByKey(ctx, runID, "build")
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	// The public DTO redacts the pipeline text. The observable execution
	// identity is the compiled job payload — it must carry the locked
	// digests. Trigger-eval-only locking (or locking a temporary spec that
	// is then discarded) leaves this on the mutable tag.
	if job.CompiledJobPayload == nil {
		t.Fatal("job has no compiled payload")
	}
	payload := fmt.Sprintf("%v", job.CompiledJobPayload.EffectiveJob)
	if !strings.Contains(payload, "example.invalid/app:1.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatalf("compiled payload lost the job image lock: %s", payload)
	}
	if !strings.Contains(payload, "example.invalid/db:1.0@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Fatalf("compiled payload lost the service image lock: %s", payload)
	}
	if strings.Contains(payload, `"example.invalid/app:1.0"`) && !strings.Contains(payload, "example.invalid/app:1.0@sha256:") {
		t.Fatalf("compiled payload still carries the mutable job tag: %s", payload)
	}
	// The enqueued job must be viable: the lock applied cleanly and the
	// workload is accepted (it may fail later at pull time for an invalid
	// registry — that is AFTER the determinism contract).
	if job.Status == model.StatusFailure && strings.Contains(job.Error, "image lock") {
		t.Fatalf("lock application failed at enqueue: %s", job.Error)
	}
}

// TestSysDFLockAuthorityFailClosed: a malformed lockfile at the trust
// boundary is FAIL-CLOSED — the webhook refuses the delivery rather than
// enqueueing a run on mutable tags.
func TestSysDFLockAuthorityFailClosed(t *testing.T) {
	t.Parallel()
	sys, err := Launch(SystemConfig{
		RunnerToken: "sys-lock2-runner",
		AdminToken:  "sys-lock2-admin",
		DataDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer func() { _ = sys.Close() }()

	if err := sys.EnableTrustedWebhook(TrustedWebhookConfig{
		PipelineYAML: lockAuthorityPipeline,
		LockYAML:     `{"version":1,"images":[{"ref":"example.invalid/app:1.0","digest":"example.invalid/app:1.0"}]}`,
	}); err != nil {
		t.Fatalf("enable trusted webhook: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// The digest is not @sha256:-pinned: the resolver must refuse.
	if _, err := sys.DeliverTrustedPush(ctx, "lock-fail-closed-1", lockAuthorityPipeline); err == nil {
		t.Fatal("malformed lockfile must refuse the delivery (fail closed)")
	}
}
