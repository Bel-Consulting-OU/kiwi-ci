package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// sidecarNoFenceStore keeps every capability a sidecar upload needs up to the
// digest fence (Store, pending-sidecar store, transactional lease commits)
// but deliberately not the distributed fence, so the fence failure branch is
// reachable through the real handler.
type sidecarNoFenceStore struct {
	storage.Store
	storage.ArtifactContractStore
	storage.ArtifactSidecarStore
	storage.LeaseCommitStore
}

// pinTestSigstoreRoot installs a throwaway verification key so the sigstore
// upload's trust-root precondition is satisfied.
func pinTestSigstoreRoot(t *testing.T, s *Server) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pinSigstoreRoot(s, "key-1", pub)
}

// TestSidecarUploadFailsClosedWithoutDigestFence pins the DB-mode sidecar
// contract: both the SBOM and the Sigstore upload acquire the digest fence
// before publishing, and a store without the distributed fence is refused
// (500) instead of falling back to a process-local serialization.
func TestSidecarUploadFailsClosedWithoutDigestFence(t *testing.T) {
	body := validSPDX
	t.Run("sbom", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		f.mu.Lock()
		f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": {Name: "bin", Paths: []string{"out/"}, SBOM: "spdx-json"}}
		f.mu.Unlock()
		s.DB = sidecarNoFenceStore{Store: f, ArtifactContractStore: f, ArtifactSidecarStore: f, LeaseCommitStore: f}
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", "runner-tok", body, hdrs)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("sbom upload without a digest fence = %d, want 503: %s", w.Code, w.Body.String())
		}
	})
	t.Run("sigstore", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		f.mu.Lock()
		f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": {Name: "bin", Paths: []string{"out/"}, SigstoreRequired: true}}
		f.mu.Unlock()
		s.DB = sidecarNoFenceStore{Store: f, ArtifactContractStore: f, ArtifactSidecarStore: f, LeaseCommitStore: f}
		pinTestSigstoreRoot(t, s)
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sigstore", "runner-tok", `{"bundle":true}`, hdrs)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("sigstore upload without a digest fence = %d, want 503: %s", w.Code, w.Body.String())
		}
	})
}

// TestSidecarUploadCASIntegrityFailures pins the publication-verification
// contract: a CAS backend that rejects the sidecar with a typed integrity
// failure answers 503 and stores nothing, for both sidecar kinds, instead of
// recording a digest the shared store disagrees with.
func TestSidecarUploadCASIntegrityFailures(t *testing.T) {
	newBroken := func(t *testing.T, contract storage.ArtifactContract) (*Server, map[string]string, *memBlob) {
		t.Helper()
		s, f, _, hdrs := cacheFixture(t)
		f.mu.Lock()
		f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": contract}
		f.mu.Unlock()
		mb := newMemBlob()
		s.SetBlobStore(&fcErrBlob{memBlob: mb, putErr: cas.ErrBackendIntegrity})
		pinTestSigstoreRoot(t, s)
		return s, hdrs, mb
	}

	t.Run("sbom", func(t *testing.T) {
		s, hdrs, mb := newBroken(t, storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SBOM: "spdx-json"})
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sbom", "runner-tok", validSPDX, hdrs)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("sbom integrity failure = %d, want 503: %s", w.Code, w.Body.String())
		}
		mb.mu.Lock()
		objects := len(mb.objects)
		mb.mu.Unlock()
		if objects != 0 {
			t.Fatalf("integrity-failed sbom left %d CAS objects", objects)
		}
	})
	t.Run("sigstore", func(t *testing.T) {
		s, hdrs, _ := newBroken(t, storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, SigstoreRequired: true})
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin.sigstore", "runner-tok", `{"bundle":true}`, hdrs)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("sigstore integrity failure = %d, want 503: %s", w.Code, w.Body.String())
		}
	})
}

// TestSigstoreFSPendingPersistFailureFailsClosed proves the fs-mode sidecar
// upload never acknowledges a bundle whose pending pointer did not become
// durable: a failed state snapshot answers 503.
func TestSigstoreFSPendingPersistFailureFailsClosed(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pinSigstoreRoot(s, "key-1", pub)
	_, jobID, hdrs := seedLeasedArtifactJob(t, s, sigstoreOptionalPipeline)
	s.persistFailForTest = errors.New("synthetic state persist failure")
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/bin.sigstore", "token", `{"bundle":true}`, hdrs)
	s.persistFailForTest = nil
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("sigstore upload with a failed pending persist = %d, want 503: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	pending := len(s.pendingSidecars)
	s.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending sidecar pointers survived a failed persist: %d", pending)
	}
}
