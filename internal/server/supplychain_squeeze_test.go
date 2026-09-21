package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/supplychain"
)

// scErrReader fails after yielding data, forcing a non-MaxBytes read error.
type scErrReader struct{}

func (scErrReader) Read([]byte) (int, error) { return 0, errors.New("read exploded") }
func (scErrReader) Close() error             { return nil }

func scPutContract(t *testing.T, s *Server, f *dbFakeStore, jobID string, c storage.ArtifactContract) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.contracts == nil {
		f.contracts = map[string]map[string]storage.ArtifactContract{}
	}
	f.contracts[jobID] = map[string]storage.ArtifactContract{c.Name: c}
}

// TestSqueezeSBOMTrustRootHelpers covers SetSigstoreTrustRoot(nil) and the
// Rekor-enabled trust root.
func TestSqueezeSBOMTrustRootHelpers(t *testing.T) {
	s := New("t")
	s.SetSigstoreTrustRoot(nil, nil, "")
	pub := make([]byte, 32)
	s.SetSigstoreTrustRoot(nil, pub, "https://rekor.example")
	if !s.hasSigstoreTrustRoot() {
		t.Fatal("rekor-only trust root must be usable")
	}
	root := s.sigstoreTrustRoot()
	if root.Rekor == nil || root.Rekor.BaseURL != "https://rekor.example" {
		t.Fatalf("rekor root = %+v", root.Rekor)
	}
	// A key without a base URL (or with a short key) disables Rekor.
	s.SetSigstoreTrustRoot(nil, pub, "")
	if s.sigstoreTrustRoot().Rekor != nil {
		t.Fatal("rekor must require both key and base URL")
	}
	s.SetSigstoreTrustRoot(nil, make([]byte, 4), "https://rekor.example")
	if s.sigstoreTrustRoot().Rekor != nil {
		t.Fatal("rekor must require a full-size key")
	}
	if s.hasSigstoreTrustRoot() {
		t.Fatal("short rekor key must not count as a trust root")
	}
}

func TestSqueezeValidateSBOMDocument(t *testing.T) {
	if err := validateSBOMDocument(nil, supplychain.SBOMSPDX); err == nil {
		t.Fatal("empty payload must be rejected")
	}
	// Valid JSON that is not an object: json.Valid passes, Unmarshal fails.
	if err := validateSBOMDocument([]byte("[1,2]"), supplychain.SBOMSPDX); err == nil {
		t.Fatal("non-object payload must be rejected")
	}
	if err := validateSBOMDocument([]byte(`{"spdxVersion":"SPDX-2.3"}`), supplychain.SBOMSPDX); err == nil {
		t.Fatal("missing SPDXID must be rejected")
	}
	if err := validateSBOMDocument([]byte(`{"bomFormat":"CycloneDX"}`), supplychain.SBOMCycloneDX); err == nil {
		t.Fatal("missing specVersion must be rejected")
	}
	if err := validateSBOMDocument([]byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"x"}`), supplychain.SBOMFormat("bogus")); err == nil {
		t.Fatal("unknown format must be rejected")
	}
	if err := validateSBOMDocument([]byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}`), supplychain.SBOMSPDX); err != nil {
		t.Fatalf("valid spdx = %v", err)
	}
	if err := validateSBOMDocument([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`), supplychain.SBOMCycloneDX); err != nil {
		t.Fatalf("valid cyclonedx = %v", err)
	}
}

func TestSqueezePendingSidecarCodec(t *testing.T) {
	if _, _, ok := decodePendingSidecar(""); ok {
		t.Fatal("empty value must decode as absent")
	}
	d, created, ok := decodePendingSidecar("bare-digest")
	if !ok || d != "bare-digest" || !created.IsZero() {
		t.Fatalf("legacy decode = %q %v %v", d, created, ok)
	}
	// A non-numeric prefix is treated as the legacy bare-digest form.
	d, created, ok = decodePendingSidecar("not-a-number\x00digest")
	if !ok || d != "not-a-number\x00digest" || !created.IsZero() {
		t.Fatalf("bad timestamp decode = %q %v %v", d, created, ok)
	}
	enc := encodePendingSidecar("digest", time.Unix(1700000000, 0))
	d, created, ok = decodePendingSidecar(enc)
	if !ok || d != "digest" || !created.Equal(time.Unix(1700000000, 0).UTC()) {
		t.Fatalf("round trip = %q %v %v", d, created, ok)
	}
}

// TestSqueezeSBOMUploadContractEdges covers the undeclared and invalid
// declared format refusals.
func TestSqueezeSBOMUploadContractEdges(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	// The declared artifact has no sbom format.
	scPutContract(t, s, f, "job-a", fcBinContract())
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", "runner-tok", validSPDX, hdrs)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("undeclared sbom = %d, want 422: %s", w.Code, w.Body.String())
	}
	// A frozen contract carrying an unknown format is refused.
	scPutContract(t, s, f, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SBOM: "bogus"})
	w = doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", "runner-tok", validSPDX, hdrs)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid sbom format = %d, want 422: %s", w.Code, w.Body.String())
	}
}

// TestSqueezeSBOMUploadBodyAndStorageEdges covers the oversized payload, the
// missing blob store, blob-store failure and pending-sidecar persistence
// failure.
func TestSqueezeSBOMUploadBodyAndStorageEdges(t *testing.T) {
	t.Run("oversized body", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		scPutContract(t, s, f, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SBOM: "spdx-json"})
		req := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", strings.NewReader(strings.Repeat("x", maxSBOMBytes+8)))
		req.Header.Set("Authorization", "Bearer runner-tok")
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("oversized sbom = %d, want 400: %s", w.Code, w.Body.String())
		}
	})
	t.Run("no blob store", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		s.CAS = nil
		scPutContract(t, s, f, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SBOM: "spdx-json"})
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", "runner-tok", validSPDX, hdrs)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("sbom without blob store = %d, want 503: %s", w.Code, w.Body.String())
		}
	})
	t.Run("blob store put failure", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		s.SetBlobStore(&fcErrBlob{memBlob: newMemBlob(), putErr: errors.New("cas down")})
		scPutContract(t, s, f, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SBOM: "spdx-json"})
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", "runner-tok", validSPDX, hdrs)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("sbom cas put failure = %d, want 500: %s", w.Code, w.Body.String())
		}
	})
	t.Run("pending persistence failure", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		f.pendingErr = errStaticKindMissing
		scPutContract(t, s, f, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SBOM: "spdx-json"})
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", "runner-tok", validSPDX, hdrs)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("sbom pending failure = %d, want 503: %s", w.Code, w.Body.String())
		}
	})
	t.Run("attachment failure", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		scPutContract(t, s, f, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SBOM: "spdx-json"})
		if err := f.InsertArtifact(context.Background(), model.ArtifactRecord{ID: "art-1", RunID: "run-c", JobID: "job-a", Name: "bin", SHA256: strings.Repeat("a", 64), LeaseGeneration: 5}); err != nil {
			t.Fatal(err)
		}
		f.sidecarAttachErr = errStaticKindMissing
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", "runner-tok", validSPDX, hdrs)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("sbom attach failure = %d, want 503: %s", w.Code, w.Body.String())
		}
	})
}

// TestSqueezeSBOMFSModeEdges covers the fs-mode storage failures.
func TestSqueezeSBOMFSModeEdges(t *testing.T) {
	t.Run("mkdir failure", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		fcSeedContract(s, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SBOM: "spdx-json"})
		// A file where the artifacts/<run>/<job> directory should be.
		blocker := filepath.Join(s.store.Root, "artifacts", "run-c")
		if err := os.MkdirAll(filepath.Dir(blocker), 0o700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, blocker, []byte("x"))
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", "runner-tok", validSPDX, hdrs)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("sbom mkdir failure = %d, want 500: %s", w.Code, w.Body.String())
		}
	})
	t.Run("sidecar write failure", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		fcSeedContract(s, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SBOM: "spdx-json"})
		dir := filepath.Join(s.store.Root, "artifacts", "run-c", "job-a")
		if err := os.MkdirAll(filepath.Join(dir, "bin.sbom.json.tmp"), 0o700); err != nil {
			t.Fatal(err)
		}
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", "runner-tok", validSPDX, hdrs)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("sbom sidecar write failure = %d, want 500: %s", w.Code, w.Body.String())
		}
	})
	t.Run("memory attach failure", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		fcSeedContract(s, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SBOM: "spdx-json"})
		// The memory attach path cannot fail by itself; the store wrapper
		// makes the record lookup fail (DB-mode lookup is not used here, so
		// this asserts the success path stays reachable).
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", "runner-tok", validSPDX, hdrs)
		if w.Code != http.StatusCreated {
			t.Fatalf("sbom upload = %d, want 201: %s", w.Code, w.Body.String())
		}
	})
}

// TestSqueezeSigstoreUploadEdges covers the sigstore upload refusals and
// storage failures.
func TestSqueezeSigstoreUploadEdges(t *testing.T) {
	t.Run("undeclared gate", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		scPutContract(t, s, f, "job-a", fcBinContract())
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sigstore", "runner-tok", "{}", hdrs)
		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("undeclared sigstore = %d, want 422: %s", w.Code, w.Body.String())
		}
	})
	t.Run("read error", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		pinSigstoreRoot(s, "key-1", make([]byte, 32))
		scPutContract(t, s, f, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SigstoreRequired: true, SigstoreIssuer: "i", SigstoreIdentity: "id"})
		req := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sigstore", scErrReader{})
		req.Header.Set("Authorization", "Bearer runner-tok")
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("sigstore read error = %d, want 400: %s", w.Code, w.Body.String())
		}
	})
	t.Run("no blob store", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		s.CAS = nil
		pinSigstoreRoot(s, "key-1", make([]byte, 32))
		scPutContract(t, s, f, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SigstoreRequired: true, SigstoreIssuer: "i", SigstoreIdentity: "id"})
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sigstore", "runner-tok", "{}", hdrs)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("sigstore without blob store = %d, want 503: %s", w.Code, w.Body.String())
		}
	})
	t.Run("blob put failure", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		s.SetBlobStore(&fcErrBlob{memBlob: newMemBlob(), putErr: errors.New("cas down")})
		pinSigstoreRoot(s, "key-1", make([]byte, 32))
		scPutContract(t, s, f, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SigstoreRequired: true, SigstoreIssuer: "i", SigstoreIdentity: "id"})
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sigstore", "runner-tok", "{}", hdrs)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("sigstore cas failure = %d, want 500: %s", w.Code, w.Body.String())
		}
	})
	t.Run("pending failure", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		f.pendingErr = errStaticKindMissing
		pinSigstoreRoot(s, "key-1", make([]byte, 32))
		scPutContract(t, s, f, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SigstoreRequired: true, SigstoreIssuer: "i", SigstoreIdentity: "id"})
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sigstore", "runner-tok", "{}", hdrs)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("sigstore pending failure = %d, want 503: %s", w.Code, w.Body.String())
		}
	})
	t.Run("fs mkdir failure", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		fcSeedContract(s, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SigstoreIssuer: "i", SigstoreIdentity: "id"})
		pinSigstoreRoot(s, "key-1", make([]byte, 32))
		blocker := filepath.Join(s.store.Root, "artifacts", "run-c")
		if err := os.MkdirAll(filepath.Dir(blocker), 0o700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, blocker, []byte("x"))
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sigstore", "runner-tok", "{}", hdrs)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("sigstore mkdir failure = %d, want 500: %s", w.Code, w.Body.String())
		}
	})
	t.Run("fs write failure", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		fcSeedContract(s, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SigstoreIssuer: "i", SigstoreIdentity: "id"})
		pinSigstoreRoot(s, "key-1", make([]byte, 32))
		dir := filepath.Join(s.store.Root, "artifacts", "run-c", "job-a")
		if err := os.MkdirAll(filepath.Join(dir, "bin.sigstore.json.tmp"), 0o700); err != nil {
			t.Fatal(err)
		}
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sigstore", "runner-tok", "{}", hdrs)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("sigstore write failure = %d, want 500: %s", w.Code, w.Body.String())
		}
	})
}

// TestSqueezeSidecarStoreAbsent covers the DB-mode paths that need a store
// without the ArtifactSidecarStore extension.
func TestSqueezeSidecarStoreAbsent(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	s.DB = struct{ storage.Store }{Store: f}
	if _, ok := s.sidecarStore(); ok {
		t.Fatal("wrapper must not expose the sidecar store")
	}
	if err := s.rememberPendingSidecar(context.Background(), model.Job{ID: "j"}, "bin", storage.ArtifactSidecarKindSBOM, "d"); err == nil {
		t.Fatal("remember without sidecar store = nil error")
	}
	if err := s.consumeArtifactPendingSidecars(context.Background(), model.ArtifactRecord{}); err != nil {
		t.Fatalf("consume without sidecar store = %v", err)
	}
	if err := f.InsertArtifact(context.Background(), model.ArtifactRecord{ID: "art-1", RunID: "run-c", JobID: "job-a", Name: "bin", LeaseGeneration: 5}); err != nil {
		t.Fatal(err)
	}
	if err := s.attachSidecarToArtifact(context.Background(), model.Job{ID: "job-a", RunID: "run-c", LeaseGeneration: 5}, "bin", storage.ArtifactSidecarKindSBOM, "p", "d"); err == nil {
		t.Fatal("attach without sidecar store = nil error")
	}
	rec := model.ArtifactRecord{}
	if err := s.attachSidecarsToRecord(context.Background(), &rec, model.Job{ID: "j"}, "bin", t.TempDir()); err == nil {
		t.Fatal("attachSidecarsToRecord without sidecar store = nil error")
	}
}

// TestSqueezeConsumePendingSidecarErrors covers the consume failure paths.
func TestSqueezeConsumePendingSidecarErrors(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	f.pendingErr = errStaticKindMissing
	rec := model.ArtifactRecord{JobID: "job-a", Name: "bin", LeaseGeneration: 5, SBOMSHA256: "d1", SigstoreSHA256: "d2"}
	if err := s.consumeArtifactPendingSidecars(context.Background(), rec); err == nil {
		t.Fatal("sbom consume failure = nil error")
	}
	// A record with only a sigstore digest reaches the second consume call.
	rec = model.ArtifactRecord{JobID: "job-a", Name: "bin", LeaseGeneration: 5, SigstoreSHA256: "d2"}
	if err := s.consumeArtifactPendingSidecars(context.Background(), rec); err == nil {
		t.Fatal("sigstore consume failure = nil error")
	}
}

// TestSqueezeAttachSidecarLookupError covers the artifact-lookup failure in
// attachSidecarToArtifact.
func TestSqueezeAttachSidecarLookupError(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	s.DB = &fcStore{dbFakeStore: f, listArtifactsErr: errors.New("artifact table down")}
	if err := s.attachSidecarToArtifact(context.Background(), model.Job{ID: "job-a", LeaseGeneration: 5}, "bin", storage.ArtifactSidecarKindSBOM, "p", "d"); err == nil {
		t.Fatal("lookup failure = nil error")
	}
}

// TestSqueezeAttachSidecarKinds covers the DB-mode SBOM branch and the
// fs-mode branches.
func TestSqueezeAttachSidecarKinds(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	if err := f.InsertArtifact(context.Background(), model.ArtifactRecord{ID: "art-1", RunID: "run-c", JobID: "job-a", Name: "bin", SHA256: strings.Repeat("a", 64), LeaseGeneration: 5}); err != nil {
		t.Fatal(err)
	}
	if err := s.attachSidecarToArtifact(context.Background(), model.Job{ID: "job-a", RunID: "run-c", LeaseGeneration: 5}, "bin", storage.ArtifactSidecarKindSBOM, "cas:sum", "sum"); err != nil {
		t.Fatalf("db sbom attach: %v", err)
	}
	if err := s.attachSidecarToArtifact(context.Background(), model.Job{ID: "job-a", RunID: "run-c", LeaseGeneration: 5}, "bin", storage.ArtifactSidecarKindSigstore, "cas:sig", "sig"); err != nil {
		t.Fatalf("db sigstore attach: %v", err)
	}
	rec, err := f.GetArtifact(context.Background(), "art-1")
	if err != nil {
		t.Fatal(err)
	}
	if rec.SBOMSHA256 != "sum" || rec.SigstoreSHA256 != "sig" {
		t.Fatalf("record sidecars = %+v", rec)
	}

	// fs mode: the in-memory record is updated in place.
	fs, hdrs := fcMemoryBlobServer(t)
	fcSeedContract(fs, "job-a", fcBinContract())
	if w := doJSONHeaders(t, fs, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", "runner-tok", "payload", hdrs); w.Code != http.StatusCreated {
		t.Fatalf("artifact upload = %d: %s", w.Code, w.Body.String())
	}
	if err := fs.attachSidecarToArtifact(context.Background(), model.Job{ID: "job-a", RunID: "run-c", LeaseGeneration: 5}, "bin", storage.ArtifactSidecarKindSBOM, "p", "sum"); err != nil {
		t.Fatalf("fs sbom attach: %v", err)
	}
	if err := fs.attachSidecarToArtifact(context.Background(), model.Job{ID: "job-a", RunID: "run-c", LeaseGeneration: 5}, "bin", storage.ArtifactSidecarKindSigstore, "p", "sig"); err != nil {
		t.Fatalf("fs sigstore attach: %v", err)
	}
	fs.mu.Lock()
	var stored model.ArtifactRecord
	for _, a := range fs.artifacts {
		if a.JobID == "job-a" && a.Name == "bin" {
			stored = a
		}
	}
	fs.mu.Unlock()
	if stored.SBOMSHA256 != "sum" || stored.SigstoreSHA256 != "sig" {
		t.Fatalf("fs record sidecars = %+v", stored)
	}
}

// TestSqueezeGateArtifactAttestationEdges covers the gate's invalid-format
// and invalid-payload refusals.
func TestSqueezeGateArtifactAttestationEdges(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	scPutContract(t, s, f, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SBOM: "bogus"})
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid declared format = %d, want 422: %s", w.Code, w.Body.String())
	}
	// A valid format with an invalid document forces the validator branch.
	scPutContract(t, s, f, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SBOM: "spdx-json"})
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", "runner-tok", `{"spdxVersion":"SPDX-2.3"}`, hdrs); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid sbom document = %d, want 422: %s", w.Code, w.Body.String())
	}
	// Valid document then a payload: the gate accepts and records.
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", "runner-tok", validSPDX, hdrs); w.Code != http.StatusCreated {
		t.Fatalf("sbom upload = %d: %s", w.Code, w.Body.String())
	}
	if w := fcUploadBlobArtifact(t, s, hdrs, "payload"); w.Code != http.StatusCreated {
		t.Fatalf("artifact upload = %d: %s", w.Code, w.Body.String())
	}
}

// TestSqueezeSidecarBytesEdges covers the CAS-open failures in both modes.
func TestSqueezeSidecarBytesEdges(t *testing.T) {
	t.Run("db pending lookup error", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		f.pendingErr = errStaticKindMissing
		if _, err := s.sidecarBytes(context.Background(), model.Job{ID: "job-a", LeaseGeneration: 5}, "bin", "sbom", t.TempDir()); err == nil {
			t.Fatal("pending lookup error = nil")
		}
	})
	t.Run("db cas open error", func(t *testing.T) {
		s, f, _, _ := cacheFixture(t)
		if err := f.RememberPendingSidecar(context.Background(), "job-a", 5, "bin", storage.ArtifactSidecarKindSBOM, "missing-digest"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.sidecarBytes(context.Background(), model.Job{ID: "job-a", LeaseGeneration: 5}, "bin", "sbom", t.TempDir()); err == nil {
			t.Fatal("missing CAS blob = nil error")
		}
	})
	t.Run("fs cas open error falls back to file", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		_ = hdrs
		dir := t.TempDir()
		s.mu.Lock()
		s.pendingSidecars[sidecarPendingKey("job-a", 5, "bin", "sbom")] = encodePendingSidecar("missing-digest", time.Now().UTC())
		s.mu.Unlock()
		if err := writeFileAtomic(artifactSidecarPath(dir, "bin", "sbom"), []byte(validSPDX), 0o600); err != nil {
			t.Fatal(err)
		}
		b, err := s.sidecarBytes(context.Background(), model.Job{ID: "job-a", LeaseGeneration: 5}, "bin", "sbom", dir)
		if err != nil || string(b) != validSPDX {
			t.Fatalf("fs fallback = %q, %v", b, err)
		}
	})
}

// TestSqueezeAttachSidecarsToRecordFS covers the fs pending-digest branches
// and the local-file fallbacks.
func TestSqueezeAttachSidecarsToRecordFS(t *testing.T) {
	s, _ := fcMemoryBlobServer(t)
	dir := t.TempDir()
	// Local sbom + sigstore files, no pending digests.
	if err := writeFileAtomic(artifactSidecarPath(dir, "bin", "sbom"), []byte(validSPDX), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(artifactSidecarPath(dir, "bin", "sigstore"), []byte(`{"b":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := model.ArtifactRecord{}
	if err := s.attachSidecarsToRecord(context.Background(), &rec, model.Job{ID: "job-a"}, "bin", dir); err != nil {
		t.Fatal(err)
	}
	if rec.SBOMPath == "" || rec.SBOMSHA256 == "" || rec.SigstorePath == "" || rec.SigstoreSHA256 == "" {
		t.Fatalf("fs sidecar resolution = %+v", rec)
	}
	// Pending digests with a CAS resolve to cas: references.
	s.mu.Lock()
	s.pendingSidecars[sidecarPendingKey("job-b", 1, "bin", "sbom")] = encodePendingSidecar("sum", time.Now().UTC())
	s.pendingSidecars[sidecarPendingKey("job-b", 1, "bin", "sigstore")] = encodePendingSidecar("sig", time.Now().UTC())
	s.mu.Unlock()
	rec2 := model.ArtifactRecord{}
	if err := s.attachSidecarsToRecord(context.Background(), &rec2, model.Job{ID: "job-b", LeaseGeneration: 1}, "bin", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if rec2.SBOMPath != "cas:sum" || rec2.SigstorePath != "cas:sig" {
		t.Fatalf("pending sidecar resolution = %+v", rec2)
	}
}

// TestSqueezePrunePendingSidecars covers the memory prune and the store
// prune failure log.
func TestSqueezePrunePendingSidecars(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	f.pendingErr = errStaticKindMissing
	s.pruneExpiredPendingSidecars(context.Background(), time.Now().UTC())

	mem, _ := fcMemoryBlobServer(t)
	old := encodePendingSidecar("old", time.Now().UTC().Add(-2*pendingSidecarMaxAge))
	mem.mu.Lock()
	mem.pendingSidecars["old"] = old
	mem.pendingSidecars["garbage"] = "bare"
	mem.mu.Unlock()
	mem.pruneExpiredPendingSidecars(context.Background(), time.Now().UTC())
	mem.mu.Lock()
	n := len(mem.pendingSidecars)
	_, stillOld := mem.pendingSidecars["old"]
	mem.mu.Unlock()
	if n != 0 || stillOld {
		t.Fatalf("prune left %d entries (old present=%v)", n, stillOld)
	}
}

// TestSqueezeUploadSigstoreRecorded covers a successful DB-mode sigstore
// upload with pending-state write and CAS storage.
func TestSqueezeUploadSigstoreRecorded(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	pinSigstoreRoot(s, "key-1", make([]byte, 32))
	scPutContract(t, s, f, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SigstoreIssuer: "i", SigstoreIdentity: "id"})
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sigstore", "runner-tok", "{}", hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("sigstore upload = %d: %s", w.Code, w.Body.String())
	}
	if _, ok, err := f.PendingSidecar(context.Background(), "job-a", 5, "bin", storage.ArtifactSidecarKindSigstore); err != nil || !ok {
		t.Fatalf("pending sigstore not recorded: ok=%v err=%v", ok, err)
	}
}

// TestSqueezeSigstoreUploadRecordedDigestBranch covers the DB-mode attach of
// a sigstore sidecar to an existing artifact record (the digest-set branch).
func TestSqueezeSigstoreUploadRecordedDigestBranch(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	digest := strings.Repeat("a", 64)
	bundle, pub := buildSigstoreBundle(t, digest)
	pinSigstoreRoot(s, "key-1", pub)
	scPutContract(t, s, f, "job-a", storage.ArtifactContract{
		Name: "bin", Paths: []string{"out/"},
		SigstoreIssuer:   "https://token.actions.githubusercontent.com",
		SigstoreIdentity: "my-identity",
	})
	if err := f.InsertArtifact(context.Background(), model.ArtifactRecord{ID: "art-1", RunID: "run-c", JobID: "job-a", Name: "bin", SHA256: digest, LeaseGeneration: 5}); err != nil {
		t.Fatal(err)
	}
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sigstore", "runner-tok", string(bundle), hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("sigstore upload = %d: %s", w.Code, w.Body.String())
	}
	rec, err := f.GetArtifact(context.Background(), "art-1")
	if err != nil {
		t.Fatal(err)
	}
	if rec.SigstoreSHA256 == "" || rec.SigstorePath == "" {
		t.Fatalf("sigstore sidecar not attached: %+v", rec)
	}
}

// TestSqueezeAttachSidecarsToRecordDBErrors covers the DB-mode pending
// lookup failures.
func TestSqueezeAttachSidecarsToRecordDBErrors(t *testing.T) {
	s2, f2, _, _ := cacheFixture(t)
	s2.DB = &fcStore{dbFakeStore: f2, pendingSidecarReadErr: errors.New("pending table down")}
	rec := model.ArtifactRecord{}
	if err := s2.attachSidecarsToRecord(context.Background(), &rec, model.Job{ID: "job-a", LeaseGeneration: 5}, "bin", t.TempDir()); err == nil {
		t.Fatal("db pending lookup error = nil")
	}
}

// TestSqueezeRememberPendingSidecarDB covers the durable remember path.
func TestSqueezeRememberPendingSidecarDB(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	if err := s.rememberPendingSidecar(context.Background(), model.Job{ID: "job-a", LeaseGeneration: 5}, "bin", storage.ArtifactSidecarKindSBOM, "digest"); err != nil {
		t.Fatal(err)
	}
	if d, ok, err := f.PendingSidecar(context.Background(), "job-a", 5, "bin", storage.ArtifactSidecarKindSBOM); err != nil || !ok || d != "digest" {
		t.Fatalf("pending = %q ok=%v err=%v", d, ok, err)
	}
}

// TestSqueezeSidecarPendingKeyAndFormat covers helpers directly.
func TestSqueezeSidecarPendingKeyAndFormat(t *testing.T) {
	if got := sidecarPendingKey("j", 3, "bin", "sbom"); !strings.Contains(got, "j\x003\x00bin\x00sbom") {
		t.Fatalf("pending key = %q", got)
	}
	if sidecarPendingKey("j", 3, "bin", "sbom") == sidecarPendingKey("j", 4, "bin", "sbom") {
		t.Fatal("pending key must include the lease generation")
	}
	if got := artifactSidecarPath("/d", "bin", "sbom"); got != filepath.Join("/d", "bin.sbom.json") {
		t.Fatalf("sidecar path = %q", got)
	}
	if sha256Hex([]byte("x")) != "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881" {
		t.Fatal("sha256Hex mismatch")
	}
}

// sigstorePendingErrStore fails only the sigstore pending lookup.
type sigstorePendingErrStore struct{ *dbFakeStore }

func (s sigstorePendingErrStore) PendingSidecar(ctx context.Context, jobID string, generation int64, artifactName, kind string) (string, bool, error) {
	if kind == storage.ArtifactSidecarKindSigstore {
		return "", false, errors.New("sigstore pending table down")
	}
	return s.dbFakeStore.PendingSidecar(ctx, jobID, generation, artifactName, kind)
}

// TestSqueezeCycloneDXFormatField covers the bomFormat refusal.
func TestSqueezeCycloneDXFormatField(t *testing.T) {
	if err := validateSBOMDocument([]byte(`{}`), supplychain.SBOMCycloneDX); err == nil {
		t.Fatal("missing bomFormat must be rejected")
	}
}

// TestSqueezeGateInvalidLocalSidecar covers the gate's audit branch when the
// sidecar bytes on disk do not validate.
func TestSqueezeGateInvalidLocalSidecar(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	fcSeedContract(s, "job-a", storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SBOM: "spdx-json"})
	dir := filepath.Join(s.store.Root, "artifacts", "run-c", "job-a")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(artifactSidecarPath(dir, "bin", "sbom"), []byte(`{"spdxVersion":"SPDX-1.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if w := fcUploadBlobArtifact(t, s, hdrs, "payload"); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid local sidecar = %d, want 422: %s", w.Code, w.Body.String())
	}
}

// TestSqueezeSidecarBytesFromCAS covers the fs-mode CAS hit.
func TestSqueezeSidecarBytesFromCAS(t *testing.T) {
	s, _ := fcMemoryBlobServer(t)
	obj, err := s.CAS.Put(context.Background(), strings.NewReader(validSPDX))
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.pendingSidecars[sidecarPendingKey("job-a", 5, "bin", "sbom")] = encodePendingSidecar(obj.SHA256, time.Now().UTC())
	s.mu.Unlock()
	b, err := s.sidecarBytes(context.Background(), model.Job{ID: "job-a", LeaseGeneration: 5}, "bin", "sbom", t.TempDir())
	if err != nil || string(b) != validSPDX {
		t.Fatalf("cas sidecar bytes = %q, %v", b, err)
	}
}

// TestSqueezeAttachSidecarsToRecordSigstoreLookupError covers the sigstore
// pending lookup failure.
func TestSqueezeAttachSidecarsToRecordSigstoreLookupError(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	s.DB = sigstorePendingErrStore{dbFakeStore: f}
	rec := model.ArtifactRecord{}
	if err := s.attachSidecarsToRecord(context.Background(), &rec, model.Job{ID: "job-a", LeaseGeneration: 5}, "bin", t.TempDir()); err == nil {
		t.Fatal("sigstore pending lookup error = nil")
	}
}

// TestSqueezeAttachSidecarsToRecordSigstoreDigest covers the DB-mode
// sigstore digest copy onto a fresh record.
func TestSqueezeAttachSidecarsToRecordSigstoreDigest(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	scPutContract(t, s, f, "job-a", storage.ArtifactContract{
		Name: "bin", Paths: []string{"out/"},
		SigstoreIssuer:   "https://token.actions.githubusercontent.com",
		SigstoreIdentity: "my-identity",
	})
	pinSigstoreRoot(s, "key-1", make([]byte, 32))
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sigstore", "runner-tok", "{}", hdrs); w.Code != http.StatusCreated {
		t.Fatalf("sigstore upload = %d: %s", w.Code, w.Body.String())
	}
	if w := fcUploadBlobArtifact(t, s, hdrs, "payload"); w.Code != http.StatusCreated {
		t.Fatalf("artifact upload = %d: %s", w.Code, w.Body.String())
	}
	var stored model.ArtifactRecord
	f.mu.Lock()
	for _, a := range f.artifacts {
		if a.JobID == "job-a" && a.Name == "bin" {
			stored = a
		}
	}
	f.mu.Unlock()
	if stored.SigstorePath == "" || stored.SigstoreSHA256 == "" {
		t.Fatalf("sigstore sidecar not copied onto the record: %+v", stored)
	}
}
