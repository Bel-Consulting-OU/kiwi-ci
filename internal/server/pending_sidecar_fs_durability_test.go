package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// fsSidecarFixture builds an fs-mode (non-DB) persistent server on dataDir
// with a leased SBOM-gated job, so sidecar durability across restarts can be
// exercised without the DB store.
func fsSidecarFixture(t *testing.T, dataDir string) (*Server, map[string]string) {
	t.Helper()
	s, err := NewPersistent("runner-tok", "admin-tok", dataDir)
	if err != nil {
		t.Fatal(err)
	}
	hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	fcSeedContract(s, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SBOM: "spdx-json"})
	return s, hdrs
}

// fsSidecarDir is the generation-qualified fs sidecar directory of the
// fixture's job.
func fsSidecarDir(s *Server, generation int64) string {
	dir := filepath.Join(s.store.Root, "artifacts", "run-c", "job-a")
	return artifactSidecarDir(dir, generation)
}

// TestFSPendingSidecarPointerSurvivesRestart is the D4-E restart contract:
// two sidecar uploads with different content in ONE generation leave two
// immutable files behind, and the LAST accepted digest survives the restart
// as a durable pointer. The payload upload after the restart must attach the
// second document; without the durable pointer the lexicographically first
// file would be attached instead, because the file names carry no "latest"
// relationship.
func TestFSPendingSidecarPointerSurvivesRestart(t *testing.T) {
	dataDir := t.TempDir()
	s1, hdrs := fsSidecarFixture(t, dataDir)
	const gen = 5

	docA := validSPDX
	docB := strings.Replace(validSPDX, `"name":"bin"`, `"name":"bin-2"`, 1)
	first, second := docA, docB
	if sha256Hex([]byte(docA)) > sha256Hex([]byte(docB)) {
		first, second = docB, docA
	}
	// Upload the lexicographically SMALLER digest first: the buggy
	// lexicographic candidate pick would choose it after the restart.
	for i, doc := range []string{first, second} {
		w := doJSONHeaders(t, s1, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", "runner-tok", doc, hdrs)
		if w.Code != http.StatusCreated {
			t.Fatalf("sidecar upload %d = %d: %s", i, w.Code, w.Body.String())
		}
	}
	want := sha256Hex([]byte(second))
	if sha256Hex([]byte(first)) >= want {
		t.Fatalf("test premise broken: first digest %s must sort before the last accepted %s", sha256Hex([]byte(first)), want)
	}
	files, err := os.ReadDir(fsSidecarDir(s1, gen))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("candidate files = %d, want 2", len(files))
	}
	// The durable state snapshot carries the pointer BEFORE the restart.
	raw, err := os.ReadFile(filepath.Join(dataDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), want) {
		t.Fatalf("state.json does not carry the accepted digest %s", want)
	}

	// Restart on the same data dir: a fresh server with no in-memory mirror.
	s2, hdrs2 := fsSidecarFixture(t, dataDir)
	s2.mu.Lock()
	restored, ok := s2.pendingSidecars[sidecarPendingKey("job-a", gen, "bin", storage.ArtifactSidecarKindSBOM)]
	s2.mu.Unlock()
	if !ok {
		t.Fatal("pending sidecar pointer was not restored after the restart")
	}
	if d, _, _ := decodePendingSidecar(restored); d != want {
		t.Fatalf("restored pointer digest = %q, want %q", d, want)
	}

	w := doJSONHeaders(t, s2, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", "runner-tok", "post-restart-payload", hdrs2)
	if w.Code != http.StatusCreated {
		t.Fatalf("artifact upload after restart = %d: %s", w.Code, w.Body.String())
	}
	var rec model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.SBOMSHA256 != want {
		t.Fatalf("attached sbom = %q, want the last accepted %q (lexicographically first was %q)", rec.SBOMSHA256, want, sha256Hex([]byte(first)))
	}
	// The fs record may reference the digest through an attached CAS
	// backend or the exact local file; both name the SAME accepted digest.
	if rec.SBOMPath != "cas:"+want && !strings.HasSuffix(rec.SBOMPath, want+".json") {
		t.Fatalf("attached sbom path = %q, want the accepted digest %q", rec.SBOMPath, want)
	}
}

// TestFSPendingSidecarMultipleCandidatesWithoutPointerFailClosed proves the
// fail-closed rule: when several immutable candidates exist for one identity
// and NO durable pointer names the accepted digest, resolution refuses
// instead of arbitrarily selecting one; the artifact upload is rejected and
// nothing is recorded.
func TestFSPendingSidecarMultipleCandidatesWithoutPointerFailClosed(t *testing.T) {
	dataDir := t.TempDir()
	s, hdrs := fsSidecarFixture(t, dataDir)
	const gen = 5

	docB := strings.Replace(validSPDX, `"name":"bin"`, `"name":"bin-2"`, 1)
	for i, doc := range []string{validSPDX, docB} {
		if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", "runner-tok", doc, hdrs); w.Code != http.StatusCreated {
			t.Fatalf("sidecar upload %d = %d: %s", i, w.Code, w.Body.String())
		}
	}
	// Simulate a legacy/unindexed restart: the files are on disk but no
	// durable pointer exists for the identity.
	s.mu.Lock()
	delete(s.pendingSidecars, sidecarPendingKey("job-a", gen, "bin", storage.ArtifactSidecarKindSBOM))
	s.mu.Unlock()

	dir := filepath.Join(s.store.Root, "artifacts", "run-c", "job-a")
	if _, err := findArtifactSidecar(dir, gen, "bin", "sbom", ""); !errors.Is(err, errAmbiguousArtifactSidecar) {
		t.Fatalf("findArtifactSidecar ambiguity = %v, want errAmbiguousArtifactSidecar", err)
	}
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", "runner-tok", "ambiguous-payload", hdrs)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("artifact upload with ambiguous sidecar = %d, want 422: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "ambiguous") {
		t.Fatalf("rejection does not name the ambiguity: %s", w.Body.String())
	}
	s.mu.Lock()
	recorded := len(s.artifacts)
	s.mu.Unlock()
	if recorded != 0 {
		t.Fatalf("ambiguous upload recorded %d artifacts, want 0", recorded)
	}
}

// TestFSPendingSidecarLegacySingleCandidateResolves proves the union with
// legacy on-disk state: exactly ONE candidate file per identity with no
// durable pointer is the unambiguous pre-upgrade layout and still resolves,
// while the pointer digest stays exact.
func TestFSPendingSidecarLegacySingleCandidateResolves(t *testing.T) {
	dataDir := t.TempDir()
	s, hdrs := fsSidecarFixture(t, dataDir)
	const gen = 5
	dir := filepath.Join(s.store.Root, "artifacts", "run-c", "job-a")
	if _, err := writeArtifactSidecar(dir, gen, "bin", "sbom", sha256Hex([]byte(validSPDX)), []byte(validSPDX)); err != nil {
		t.Fatal(err)
	}
	if _, err := findArtifactSidecar(dir, gen, "bin", "sbom", ""); err != nil {
		t.Fatalf("single legacy candidate must resolve, got %v", err)
	}
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", "runner-tok", "legacy-payload", hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("artifact upload with one legacy candidate = %d: %s", w.Code, w.Body.String())
	}
	var rec model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.SBOMSHA256 != sha256Hex([]byte(validSPDX)) {
		t.Fatalf("legacy sidecar digest = %q, want %q", rec.SBOMSHA256, sha256Hex([]byte(validSPDX)))
	}
	// Zero candidates stay a plain "missing", never ambiguous.
	empty := t.TempDir()
	if _, err := findArtifactSidecar(empty, gen, "bin", "sbom", ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("zero candidates = %v, want os.ErrNotExist", err)
	}
	if _, err := findArtifactSidecar(empty, gen, "bin", "sbom", strings.Repeat("a", 64)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing exact digest = %v, want os.ErrNotExist (no fallback scan)", err)
	}
}

// TestFSPendingSidecarConsumeAndPruneStayDurable proves the fs mirror's
// consume and prune still drop exactly their own entries AND persist the
// drop, so a restart cannot resurrect a consumed or expired pointer.
func TestFSPendingSidecarConsumeAndPruneStayDurable(t *testing.T) {
	dataDir := t.TempDir()
	s, hdrs := fsSidecarFixture(t, dataDir)
	const gen = 5
	digest := sha256Hex([]byte(validSPDX))
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", "runner-tok", validSPDX, hdrs); w.Code != http.StatusCreated {
		t.Fatalf("sidecar upload = %d: %s", w.Code, w.Body.String())
	}

	rec := model.ArtifactRecord{JobID: "job-a", Name: "bin", LeaseGeneration: gen, SBOMSHA256: digest}
	if err := s.consumeArtifactPendingSidecars(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	_, left := s.pendingSidecars[sidecarPendingKey("job-a", gen, "bin", storage.ArtifactSidecarKindSBOM)]
	s.mu.Unlock()
	if left {
		t.Fatal("consume left the fs pending pointer behind")
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), digest) {
		t.Fatalf("consumed pointer was not persisted away: %s", raw)
	}

	// Prune: a stale pointer is dropped AND the durable state follows.
	stale := encodePendingSidecar(strings.Repeat("f", 64), time.Now().UTC().Add(-2*pendingSidecarMaxAge))
	s.mu.Lock()
	s.pendingSidecars[sidecarPendingKey("job-a", gen, "bin", storage.ArtifactSidecarKindSigstore)] = stale
	s.mu.Unlock()
	if err := s.persistLocked(); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(dataDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), strings.Repeat("f", 64)) {
		t.Fatalf("stale pointer was not persisted before prune: %s", raw)
	}
	s.GC(context.Background(), time.Now().UTC())
	raw, err = os.ReadFile(filepath.Join(dataDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), strings.Repeat("f", 64)) {
		t.Fatalf("pruned pointer survived in the durable state: %s", raw)
	}
}
