package runner

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/supplychain"
)

const (
	testArtifactSHA  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testArtifactName = "app"
)

// writeTestArtifact writes an artifact archive plus its manifest sibling.
func writeTestArtifact(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.tar.gz")
	if err := os.WriteFile(path, []byte("archive-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	man := map[string]any{
		"version": 1, "name": testArtifactName, "run_id": "run-1", "job_id": "job-1",
		"sha256": testArtifactSHA, "size": 13,
		"entries": []map[string]any{{"path": "out/app.txt", "sha256": testArtifactSHA, "size": 13}},
	}
	b, err := json.Marshal(man)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".manifest.json", b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// attestServer records artifact PUTs and can fail chosen name suffixes.
type attestServer struct {
	mu     sync.Mutex
	fail   map[string]int
	puts   []string
	failed map[string]string
}

func (s *attestServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		s.mu.Lock()
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/artifacts/") {
			s.puts = append(s.puts, name)
			if s.fail == nil {
				s.fail = map[string]int{}
			}
			if status, ok := s.fail[name]; ok {
				if s.failed == nil {
					s.failed = map[string]string{}
				}
				s.failed[name] = fmt.Sprintf("%d", status)
				s.mu.Unlock()
				w.WriteHeader(status)
				return
			}
		}
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
}

func (s *attestServer) putNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.puts...)
}

func compiledWithArtifact(decl pipeline.Artifact) pipeline.CompiledJob {
	return pipeline.CompiledJob{ID: "build", BaseID: "build", Job: pipeline.Job{Artifacts: []pipeline.Artifact{decl}}}
}

func TestFinalDeclaredArtifactForPaths(t *testing.T) {
	strict := compiledWithArtifact(pipeline.Artifact{Name: testArtifactName, SBOM: "spdx-json"})
	if a, ok := declaredArtifactFor(model.Job{}, strict, testArtifactName); !ok || a.SBOM != "spdx-json" {
		t.Fatalf("strict declaration = %+v %v", a, ok)
	}
	// A matrix variant key falls back to the lenient raw-YAML lookup.
	job := model.Job{Key: "build[dir=x]", BaseKey: "build",
		Pipeline: "version: 1\njobs:\n  build:\n    artifacts:\n      - name: app\n        sbom: cyclonedx-json\n        sigstore:\n          required: true\n"}
	a, ok := declaredArtifactFor(job, pipeline.CompiledJob{}, testArtifactName)
	if !ok || a.SBOM != "cyclonedx-json" || a.Sigstore == nil || !a.Sigstore.Required {
		t.Fatalf("lenient declaration = %+v %v", a, ok)
	}
	// Malformed raw YAML is not a declaration.
	bad := model.Job{Key: "build", Pipeline: "{{{"}
	if _, ok := declaredArtifactFor(bad, pipeline.CompiledJob{}, testArtifactName); ok {
		t.Fatal("malformed pipeline produced a declaration")
	}
	// An undeclared name is not found.
	if _, ok := declaredArtifactFor(job, pipeline.CompiledJob{}, "other"); ok {
		t.Fatal("undeclared artifact found")
	}
}

func TestFinalUploadArtifactWithAttestationsSuccessAndSBOMFailures(t *testing.T) {
	task := basicTask(payloadPipeline)
	ctx := context.Background()
	path := writeTestArtifact(t)

	// A malformed sbom declaration is refused before any upload.
	asrv := &attestServer{}
	ts := httptest.NewServer(asrv.handler())
	defer ts.Close()
	r := &Runner{ID: "r", Cfg: Config{Server: ts.URL}, Client: ts.Client(), Metrics: NewMetrics()}
	err := r.uploadArtifactWithAttestations(ctx, task, compiledWithArtifact(pipeline.Artifact{Name: testArtifactName, SBOM: "bogus"}), testArtifactName, path)
	if err == nil || !strings.Contains(err.Error(), "sbom") {
		t.Fatalf("malformed sbom = %v", err)
	}
	if puts := asrv.putNames(); len(puts) != 0 {
		t.Fatalf("uploads before the sbom refusal: %v", puts)
	}

	// A missing manifest fails the SBOM build.
	noManifest := filepath.Join(t.TempDir(), "app.tar.gz")
	if err := os.WriteFile(noManifest, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = r.uploadArtifactWithAttestations(ctx, task, compiledWithArtifact(pipeline.Artifact{Name: testArtifactName, SBOM: "spdx-json"}), testArtifactName, noManifest)
	if err == nil || !strings.Contains(err.Error(), "sbom") {
		t.Fatalf("missing manifest = %v", err)
	}

	// A failing sbom PUT stops the sequence.
	asrv.fail = map[string]int{testArtifactName + ".sbom": http.StatusInternalServerError}
	err = r.uploadArtifactWithAttestations(ctx, task, compiledWithArtifact(pipeline.Artifact{Name: testArtifactName, SBOM: "spdx-json"}), testArtifactName, path)
	if err == nil {
		t.Fatal("failing sbom upload accepted")
	}

	// SPDX and CycloneDX SBOM uploads precede the payload.
	for _, format := range []string{"spdx-json", "cyclonedx-json"} {
		asrv = &attestServer{}
		ts2 := httptest.NewServer(asrv.handler())
		r2 := &Runner{ID: "r", Cfg: Config{Server: ts2.URL}, Client: ts2.Client(), Metrics: NewMetrics()}
		if err := r2.uploadArtifactWithAttestations(ctx, task, compiledWithArtifact(pipeline.Artifact{Name: testArtifactName, SBOM: format}), testArtifactName, path); err != nil {
			t.Fatalf("%s upload: %v", format, err)
		}
		got := asrv.putNames()
		want := []string{testArtifactName + ".sbom", testArtifactName}
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("%s uploads = %v, want %v", format, got, want)
		}
		ts2.Close()
	}
}

func TestFinalUploadArtifactWithAttestationsSigstorePaths(t *testing.T) {
	task := basicTask(payloadPipeline)
	ctx := context.Background()
	path := writeTestArtifact(t)
	decl := pipeline.Artifact{Name: testArtifactName, Sigstore: &pipeline.SigstoreConfig{Required: true, Issuer: "https://issuer.example", Identity: "id@example"}}

	asrv := &attestServer{}
	ts := httptest.NewServer(asrv.handler())
	defer ts.Close()

	// A required gate without a signing key refuses the job.
	r := &Runner{ID: "r", Cfg: Config{Server: ts.URL}, Client: ts.Client(), Metrics: NewMetrics()}
	err := r.uploadArtifactWithAttestations(ctx, task, compiledWithArtifact(decl), testArtifactName, path)
	if err == nil || !strings.Contains(err.Error(), "sigstore gate required") {
		t.Fatalf("missing key = %v", err)
	}

	// An optional gate without a key warns and uploads the payload.
	optional := pipeline.Artifact{Name: testArtifactName, Sigstore: &pipeline.SigstoreConfig{}}
	if err := r.uploadArtifactWithAttestations(ctx, task, compiledWithArtifact(optional), testArtifactName, path); err != nil {
		t.Fatalf("optional gate: %v", err)
	}
	if puts := asrv.putNames(); len(puts) != 1 || puts[0] != testArtifactName {
		t.Fatalf("optional gate uploads = %v", puts)
	}

	// A missing key file fails the signing step.
	r = &Runner{ID: "r", Cfg: Config{Server: ts.URL, SigstoreKeyPath: filepath.Join(t.TempDir(), "missing.pem")}, Client: ts.Client(), Metrics: NewMetrics()}
	if err := r.uploadArtifactWithAttestations(ctx, task, compiledWithArtifact(decl), testArtifactName, path); err == nil {
		t.Fatal("missing signing key file accepted")
	}

	// A key file with the wrong PEM type is refused.
	wrongType := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(wrongType, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}), 0o600); err != nil {
		t.Fatal(err)
	}
	r = &Runner{ID: "r", Cfg: Config{Server: ts.URL, SigstoreKeyPath: wrongType}, Client: ts.Client(), Metrics: NewMetrics()}
	if err := r.uploadArtifactWithAttestations(ctx, task, compiledWithArtifact(decl), testArtifactName, path); err == nil {
		t.Fatal("non-PKCS8 PEM accepted")
	}

	// A PKCS8 block with undecodable DER is refused.
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-der")}), 0o600); err != nil {
		t.Fatal(err)
	}
	r = &Runner{ID: "r", Cfg: Config{Server: ts.URL, SigstoreKeyPath: garbage}, Client: ts.Client(), Metrics: NewMetrics()}
	if err := r.uploadArtifactWithAttestations(ctx, task, compiledWithArtifact(decl), testArtifactName, path); err == nil {
		t.Fatal("undecodable PKCS8 block accepted")
	}

	// A non-Ed25519 PKCS8 key is refused.
	ecdsaKey := filepath.Join(t.TempDir(), "ecdsa.pem")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ecdsaKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	r = &Runner{ID: "r", Cfg: Config{Server: ts.URL, SigstoreKeyPath: ecdsaKey}, Client: ts.Client(), Metrics: NewMetrics()}
	if err := r.uploadArtifactWithAttestations(ctx, task, compiledWithArtifact(decl), testArtifactName, path); err == nil {
		t.Fatal("ECDSA signing key accepted")
	}

	// A missing artifact file fails the digest step of signing.
	key := writeTestSigstoreKey(t)
	r = &Runner{ID: "r", Cfg: Config{Server: ts.URL, SigstoreKeyPath: key}, Client: ts.Client(), Metrics: NewMetrics()}
	if err := r.uploadArtifactWithAttestations(ctx, task, compiledWithArtifact(decl), testArtifactName, filepath.Join(t.TempDir(), "missing.tar.gz")); err == nil {
		t.Fatal("missing artifact accepted for signing")
	}

	// A failing sigstore PUT stops the sequence.
	asrv.fail = map[string]int{testArtifactName + ".sigstore": http.StatusBadGateway}
	if err := r.uploadArtifactWithAttestations(ctx, task, compiledWithArtifact(decl), testArtifactName, path); err == nil {
		t.Fatal("failing sigstore upload accepted")
	}

	// The full sbom+sigstore+payload sequence succeeds with a real key.
	asrv.mu.Lock()
	asrv.fail = nil
	asrv.puts = nil
	asrv.mu.Unlock()
	full := pipeline.Artifact{Name: testArtifactName, SBOM: "spdx-json", Sigstore: &pipeline.SigstoreConfig{Required: true, Issuer: "i", Identity: "n"}}
	if err := r.uploadArtifactWithAttestations(ctx, task, compiledWithArtifact(full), testArtifactName, path); err != nil {
		t.Fatalf("full attestation sequence: %v", err)
	}
	got := asrv.putNames()
	want := []string{testArtifactName + ".sbom", testArtifactName + ".sigstore", testArtifactName}
	if len(got) != len(want) {
		t.Fatalf("uploads = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("uploads = %v, want %v", got, want)
		}
	}
}

func TestFinalBuildSBOMUnsupportedFormatAndManifestErrors(t *testing.T) {
	r := &Runner{}
	if _, err := r.buildSBOM("app", model.Job{}, supplychain.SBOMFormat("bogus"), filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing manifest accepted")
	}
	// A readable manifest with an unknown format reaches the format default.
	if _, err := r.buildSBOM("app", model.Job{}, supplychain.SBOMFormat("bogus"), writeTestArtifact(t)); err == nil || !strings.Contains(err.Error(), "unsupported sbom format") {
		t.Fatalf("unsupported sbom format = %v", err)
	}
	path := writeTestArtifact(t)
	out, err := r.buildSBOM("app", model.Job{SHA: "abc"}, supplychain.SBOMSPDX, path)
	if err != nil || len(out) == 0 {
		t.Fatalf("spdx sbom = %d bytes, %v", len(out), err)
	}
}

func TestFinalSha256FileErrors(t *testing.T) {
	if _, err := sha256File(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file hashed")
	}
	// Reading a directory surfaces the read error.
	if _, err := sha256File(t.TempDir()); err == nil {
		t.Fatal("directory hashed")
	}
}

func TestFinalPutArtifactBytesErrors(t *testing.T) {
	task := basicTask(payloadPipeline)
	bad := &Runner{Cfg: Config{Server: "http://[::1"}, Client: &http.Client{}}
	if err := bad.putArtifactBytes(context.Background(), task, "a", []byte("x"), "application/json"); err == nil {
		t.Fatal("malformed put URL accepted")
	}
	closed := &Runner{Cfg: Config{Server: "http://127.0.0.1:1"}, Client: &http.Client{}}
	if err := closed.putArtifactBytes(context.Background(), task, "a", []byte("x"), "application/json"); err == nil {
		t.Fatal("put transport failure accepted")
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "refused", http.StatusConflict)
	}))
	defer ts.Close()
	r := &Runner{Cfg: Config{Server: ts.URL}, Client: ts.Client()}
	if err := r.putArtifactBytes(context.Background(), task, "a", []byte("x"), "application/json"); err == nil {
		t.Fatal("non-2xx put accepted")
	}
}

// TestFinalSignArtifactBundleKeyKinds pins the key-material error taxonomy
// directly on the signing helper.
func TestFinalSignArtifactBundleKeyKinds(t *testing.T) {
	path := writeTestArtifact(t)
	cfg := &pipeline.SigstoreConfig{Issuer: "i", Identity: "n"}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &Runner{Cfg: Config{SigstoreKeyPath: keyPath}}
	bundle, err := r.signArtifactBundle("app", model.Job{RepoURL: "https://github.com/acme/app.git", Ref: "main"}, path, cfg)
	if err != nil || len(bundle) == 0 {
		t.Fatalf("signArtifactBundle = %d bytes, %v", len(bundle), err)
	}
	var out map[string]any
	if err := json.Unmarshal(bundle, &out); err != nil {
		t.Fatalf("bundle is not JSON: %v", err)
	}
	if out["mediaType"] != supplychain.SigstoreBundleMediaType {
		t.Fatalf("mediaType = %v", out["mediaType"])
	}
}

// TestFinalUploadArtifactWithAttestationsNoDeclaration checks the plain
// upload path when the artifact has no attestation contract.
func TestFinalUploadArtifactWithAttestationsNoDeclaration(t *testing.T) {
	asrv := &attestServer{}
	ts := httptest.NewServer(asrv.handler())
	defer ts.Close()
	r := &Runner{ID: "r", Cfg: Config{Server: ts.URL}, Client: ts.Client(), Metrics: NewMetrics()}
	path := writeTestArtifact(t)
	cj := compiledWithArtifact(pipeline.Artifact{Name: testArtifactName})
	if err := r.uploadArtifactWithAttestations(context.Background(), basicTask(payloadPipeline), cj, testArtifactName, path); err != nil {
		t.Fatalf("plain upload: %v", err)
	}
	if puts := asrv.putNames(); len(puts) != 1 || puts[0] != testArtifactName {
		t.Fatalf("plain uploads = %v", puts)
	}
}
