package server

// Real-PostgreSQL integration coverage for the generation-qualified
// artifact-sidecar contract: the pending row written by an SBOM upload is
// keyed by (job, lease generation, artifact, kind), the artifact payload
// gate resolves ONLY the current generation's row, the commit consumes ONLY
// that row, and a row for another generation survives (it is pruned by the
// 7-day maintenance window, never by another generation's commit).
//
// Gated on KIWI_TEST_POSTGRES_URL like every other *_it_test.go in this
// package; each test owns a throwaway schema.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// pgITSidecarPipeline declares one SBOM-gated artifact, so the real-PG
// sidecar upload/gate/consume path can be driven over the HTTP handlers.
const pgITSidecarPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    artifacts:
      - name: bin
        paths:
          - out/
        sbom: spdx-json
    steps:
      - run: echo hi
`

// TestIntegrationSidecarGenerationScoping proves the end-to-end
// generation-scoped sidecar flow on real PostgreSQL: a stale-generation
// pending row never satisfies the current generation's gate, the current
// generation's SBOM is stored durably and attached to its record, the
// commit consumes exactly its own row, and the other generation's row
// survives until the prune.
func TestIntegrationSidecarGenerationScoping(t *testing.T) {
	s, st := pgITServer(t, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	// DB-mode sidecar storage requires the shared CAS blob store.
	s.SetBlobStore(blob.NewFS(t.TempDir()))
	ctx := context.Background()

	runnerID := pgITRegisterRunner(t, s)
	run := pgITSubmit(t, s, pgITSidecarPipeline)
	task := pgITNext(t, s, runnerID)
	jobID := task.Job.ID
	if task.LeaseGeneration <= 0 {
		t.Fatalf("leased task generation = %d, want a positive generation", task.LeaseGeneration)
	}

	// A pending row for ANOTHER generation of the same artifact must never
	// satisfy this generation's gate.
	staleDigest := strings.Repeat("a", 64)
	if err := st.RememberPendingSidecar(ctx, jobID, task.LeaseGeneration+1, "bin", storage.ArtifactSidecarKindSBOM, staleDigest); err != nil {
		t.Fatalf("seed other-generation pending row: %v", err)
	}
	if w := pgITDo(t, s, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin", "token", "gated-payload", pgITLeaseHeaders(task, runnerID)); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("payload with only another generation's pending sbom = %d, want 422: %s", w.Code, w.Body.String())
	}
	records, err := st.ListArtifacts(ctx, run.ID)
	if err != nil {
		t.Fatalf("list artifacts after gated upload: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("gated upload recorded %d artifacts, want 0", len(records))
	}

	// The current generation's SBOM is accepted and stored durably.
	if w := pgITDo(t, s, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin.sbom", "token", validSPDX, pgITLeaseHeaders(task, runnerID)); w.Code != http.StatusCreated {
		t.Fatalf("sbom upload = %d: %s", w.Code, w.Body.String())
	}
	sbomDigest := sha256Hex([]byte(validSPDX))
	if d, ok, err := st.PendingSidecar(ctx, jobID, task.LeaseGeneration, "bin", storage.ArtifactSidecarKindSBOM); err != nil || !ok || d != sbomDigest {
		t.Fatalf("durable pending sbom = %q ok=%v err=%v, want %s", d, ok, err, sbomDigest)
	}

	// The payload commits, carries the digest reference, and consumes ONLY
	// its own generation's row.
	w := pgITDo(t, s, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin", "token", "attested-payload", pgITLeaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("payload upload = %d: %s", w.Code, w.Body.String())
	}
	var rec model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatalf("decode artifact record: %v", err)
	}
	if rec.SBOMSHA256 != sbomDigest || rec.SBOMPath != "cas:"+sbomDigest {
		t.Fatalf("record sbom references = %q/%q, want cas:%s", rec.SBOMPath, rec.SBOMSHA256, sbomDigest)
	}
	if rec.LeaseGeneration != task.LeaseGeneration {
		t.Fatalf("record generation = %d, want %d", rec.LeaseGeneration, task.LeaseGeneration)
	}
	if _, ok, err := st.PendingSidecar(ctx, jobID, task.LeaseGeneration, "bin", storage.ArtifactSidecarKindSBOM); err != nil || ok {
		t.Fatalf("own-generation pending row after commit = ok=%v err=%v, want consumed", ok, err)
	}
	if d, ok, err := st.PendingSidecar(ctx, jobID, task.LeaseGeneration+1, "bin", storage.ArtifactSidecarKindSBOM); err != nil || !ok || d != staleDigest {
		t.Fatalf("other-generation pending row after commit = %q ok=%v err=%v, want it to survive", d, ok, err)
	}

	// The prune keeps fresh rows and drops expired ones; the survivor is
	// reachable only through its own generation until then.
	if n, err := st.PrunePendingSidecars(ctx, time.Now().UTC().Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("prune keeping fresh rows = %d err=%v, want 0", n, err)
	}
	if _, ok, _ := st.PendingSidecar(ctx, jobID, task.LeaseGeneration+1, "bin", storage.ArtifactSidecarKindSBOM); !ok {
		t.Fatal("fresh other-generation row was pruned")
	}
}
