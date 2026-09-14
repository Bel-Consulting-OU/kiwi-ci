package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
)

func TestProvenanceSignedWithProvenanceKeyNotOIDC(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.provenance == nil || s.oidc == nil {
		t.Fatal("signing roots not initialized")
	}
	if s.provenance.KID == s.oidc.KID {
		t.Fatalf("provenance and OIDC keys share kid %q", s.provenance.KID)
	}
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	hdrs := leaseHeaders(task, runnerID)
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/bin", "token", "payload", hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	var rec model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.ProvenancePath == "" {
		t.Fatal("no provenance attached")
	}
	envBytes, err := os.ReadFile(rec.ProvenancePath)
	if err != nil {
		t.Fatal(err)
	}
	var env provenance.Envelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Signatures) == 0 {
		t.Fatal("unsigned provenance envelope")
	}
	if env.Signatures[0].KeyID != s.provenance.KID {
		t.Fatalf("provenance signed with kid %q, want provenance key %q", env.Signatures[0].KeyID, s.provenance.KID)
	}
	if env.Signatures[0].KeyID == s.oidc.KID {
		t.Fatal("provenance signed with the OIDC key")
	}
	// The envelope must verify against the provenance public key and fail
	// against the OIDC key.
	if err := provenance.Verify(env, s.provenance.Public); err != nil {
		t.Fatalf("provenance verify with provenance key: %v", err)
	}
	if err := provenance.Verify(env, s.oidc.Public); err == nil {
		t.Fatal("provenance verifies with the OIDC key (key confusion)")
	}
	// The provenance key pair is persisted under dataDir for restarts.
	if _, err := os.Stat(filepath.Join(dir, "provenance.key")); err != nil {
		t.Fatalf("provenance.key not persisted: %v", err)
	}
}

func TestSeparateSigningRootsPersisted(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	provenanceKID := s.provenance.KID
	cacheKID := s.cacheSigner.KID
	webSecret := s.WebSessionSecret
	if len(webSecret) != 32 {
		t.Fatal("web session secret not initialized")
	}
	// Restart: all three roots reload from disk.
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.provenance.KID != provenanceKID {
		t.Fatalf("provenance key rotated across restart: %q -> %q", provenanceKID, s2.provenance.KID)
	}
	if s2.cacheSigner.KID != cacheKID {
		t.Fatalf("cache key rotated across restart: %q -> %q", cacheKID, s2.cacheSigner.KID)
	}
	if string(s2.WebSessionSecret) != string(webSecret) {
		t.Fatal("web session secret rotated across restart")
	}
	// Each root is a distinct key.
	if provenanceKID == cacheKID {
		t.Fatal("provenance and cache keys are identical")
	}
}
