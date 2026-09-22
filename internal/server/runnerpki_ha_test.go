package server

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// writeRunnerCAPEMFilesForTest writes a CA as --runner-ca-cert/-key PEM files.
func writeRunnerCAPEMFilesForTest(t *testing.T, ca *runnerpki.CA) (certPath, keyPath string) {
	t.Helper()
	certPEM, keyPEM, err := caPEMsForTest(ca)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "runner-ca.crt")
	keyPath = filepath.Join(dir, "runner-ca.key")
	writeTestFile(t, certPath, certPEM)
	writeTestFile(t, keyPath, keyPEM)
	return certPath, keyPath
}

// TestSetRunnerCASharedStoreInstallsAndCompares is the HA contract for an
// explicit runner CA: it is atomically installed into the shared cluster key
// store, a replica configured with the SAME files adopts the stored CA (one
// trust root: a certificate issued by A verifies on B), and a replica
// configured with DIFFERENT files fails startup with the disagreement error
// without replacing the stored CA.
func TestSetRunnerCASharedStoreInstallsAndCompares(t *testing.T) {
	shared := &StaticClusterKeyStore{Keys: map[string][]byte{}}
	caA, err := runnerpki.NewCA("shared explicit A", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := writeRunnerCAPEMFilesForTest(t, caA)

	s1 := &Server{ClusterKeys: shared}
	if err := s1.SetRunnerCA(certPath, keyPath); err != nil {
		t.Fatalf("SetRunnerCA with a shared store: %v", err)
	}
	if s1.RunnerCA == nil {
		t.Fatal("explicit CA not loaded")
	}
	stored, found, err := shared.Lookup(clusterKindRunnerCA)
	if err != nil || !found {
		t.Fatalf("explicit CA not installed into the shared cluster key store: found=%v err=%v", found, err)
	}
	certPEM, _ := os.ReadFile(certPath)
	keyPEM, _ := os.ReadFile(keyPath)
	if want := runnerCAObject(certPEM, keyPEM); !bytes.Equal(stored, want) {
		t.Fatal("stored runner CA is not the canonical explicit object")
	}

	// Same files on a second replica: one trust root.
	s2 := &Server{ClusterKeys: shared}
	if err := s2.SetRunnerCA(certPath, keyPath); err != nil {
		t.Fatalf("second replica with the same CA files: %v", err)
	}
	if s2.RunnerCA == nil || !bytes.Equal(s1.RunnerCA.Cert.Raw, s2.RunnerCA.Cert.Raw) {
		t.Fatal("replicas did not converge on one runner CA")
	}
	_, leaf := pkiSignRunner(t, s1.RunnerCA, "runner-shared")
	roots := runnerpki.Pool(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s2.RunnerCA.Cert.Raw}))
	if id, err := s2.RunnerCA.VerifyPeer(leaf, roots); err != nil || id != "runner-shared" {
		t.Fatalf("a certificate issued by replica A does not verify on replica B: id=%q err=%v", id, err)
	}

	// Different files on a third replica: fail startup, keep the shared CA.
	caB, err := runnerpki.NewCA("divergent B", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPathB, keyPathB := writeRunnerCAPEMFilesForTest(t, caB)
	s3 := &Server{ClusterKeys: shared}
	err = s3.SetRunnerCA(certPathB, keyPathB)
	if err == nil || !strings.Contains(err.Error(), "configured runner CA disagrees with cluster runner CA") {
		t.Fatalf("divergent explicit CA = %v", err)
	}
	after, _, err := shared.Lookup(clusterKindRunnerCA)
	if err != nil || !bytes.Equal(after, stored) {
		t.Fatalf("divergent attempt replaced the shared runner CA: err=%v", err)
	}
}

// TestSetRunnerCALocalModeUnchanged proves an in-memory server without a
// cluster store keeps the legacy explicit-file behavior (and its errors).
func TestSetRunnerCALocalModeUnchanged(t *testing.T) {
	ca, err := runnerpki.NewCA("local-only", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := writeRunnerCAPEMFilesForTest(t, ca)
	s := New("t")
	if err := s.SetRunnerCA(certPath, keyPath); err != nil || s.RunnerCA == nil {
		t.Fatalf("local SetRunnerCA = %v (ca=%v)", err, s.RunnerCA)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(certPath), "runner-ca.pem")); err == nil {
		t.Fatal("local mode must not materialize a cluster object")
	}
	if err := New("t").SetRunnerCA(filepath.Join(t.TempDir(), "missing.crt"), keyPath); err == nil || !strings.Contains(err.Error(), "read runner CA certificate") {
		t.Fatalf("missing certificate error = %v", err)
	}
	if err := New("t").SetRunnerCA(certPath, filepath.Join(t.TempDir(), "missing.key")); err == nil || !strings.Contains(err.Error(), "read runner CA key") {
		t.Fatalf("missing key error = %v", err)
	}
}

// TestSetRunnerCAStoreWithoutInstallerFailsClosed proves a configured cluster
// store that cannot install-or-compare refuses the explicit CA instead of
// falling back to node-local files.
func TestSetRunnerCAStoreWithoutInstallerFailsClosed(t *testing.T) {
	ca, err := runnerpki.NewCA("no installer", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := writeRunnerCAPEMFilesForTest(t, ca)
	s := New("t")
	s.ClusterKeys = fixedClusterStore{b: runnerCAObjectForTest(t, ca)}
	if err := s.SetRunnerCA(certPath, keyPath); err == nil || !strings.Contains(err.Error(), "install-or-load") {
		t.Fatalf("store without install-or-load accepted an explicit CA: %v", err)
	}
	if s.RunnerCA != nil {
		t.Fatal("refused CA still installed")
	}
}

// TestEnsureRunnerCAUsesInstallOrLoad proves the auto-CA path installs the
// generated material through the same create-if-absent primitive: a second
// replica's EnsureRunnerCA reuses the stored CA instead of minting its own.
func TestEnsureRunnerCAUsesInstallOrLoad(t *testing.T) {
	shared := &StaticClusterKeyStore{Keys: map[string][]byte{}}
	s1 := &Server{ClusterKeys: shared}
	if err := s1.EnsureRunnerCA(); err != nil || s1.RunnerCA == nil {
		t.Fatalf("first EnsureRunnerCA = %v", err)
	}
	stored, found, err := shared.Lookup(clusterKindRunnerCA)
	if err != nil || !found || len(stored) == 0 {
		t.Fatalf("auto CA not installed into the shared store: found=%v err=%v", found, err)
	}
	s2 := &Server{ClusterKeys: shared}
	if err := s2.EnsureRunnerCA(); err != nil || s2.RunnerCA == nil {
		t.Fatalf("second EnsureRunnerCA = %v", err)
	}
	if !bytes.Equal(s1.RunnerCA.Cert.Raw, s2.RunnerCA.Cert.Raw) {
		t.Fatal("auto-CA replicas diverged instead of sharing the installed CA")
	}
	after, _, err := shared.Lookup(clusterKindRunnerCA)
	if err != nil || !bytes.Equal(after, stored) {
		t.Fatalf("second EnsureRunnerCA replaced the shared CA: err=%v", err)
	}
	// Stores without the primitive keep the legacy LoadOrCreate fallback.
	fallbackCA, err := runnerpki.NewCA("fallback", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	legacy := &Server{ClusterKeys: fixedLookupStore{b: runnerCAObjectForTest(t, fallbackCA), found: true}}
	if err := legacy.EnsureRunnerCA(); err != nil || legacy.RunnerCA == nil {
		t.Fatalf("fallback EnsureRunnerCA = %v", err)
	}
	if !bytes.Equal(legacy.RunnerCA.Cert.Raw, fallbackCA.Cert.Raw) {
		t.Fatal("fallback EnsureRunnerCA did not load the stored CA")
	}
}

// TestRunnerCAObjectsAgreeFormats pins the disagreement comparison: identical
// material agrees across PEM-formatting and legacy separator differences,
// while a genuinely different CA never does.
func TestRunnerCAObjectsAgreeFormats(t *testing.T) {
	ca, err := runnerpki.NewCA("agree", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := caPEMsForTest(ca)
	if err != nil {
		t.Fatal(err)
	}
	canonical := runnerCAObject(certPEM, keyPEM)
	if !runnerCAObjectsAgree(canonical, canonical) {
		t.Fatal("identical objects must agree")
	}
	// Legacy separator-less layout of the SAME CA.
	legacy := append(append([]byte{}, certPEM...), keyPEM...)
	if !runnerCAObjectsAgree(canonical, legacy) {
		t.Fatal("the same CA in the legacy object layout must agree")
	}
	// A different CA always disagrees.
	other, err := runnerpki.NewCA("disagree", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	otherCert, otherKey, err := caPEMsForTest(other)
	if err != nil {
		t.Fatal(err)
	}
	if runnerCAObjectsAgree(canonical, runnerCAObject(otherCert, otherKey)) {
		t.Fatal("different CAs must disagree")
	}
	// Corrupt material cannot masquerade as agreement with a real CA.
	if runnerCAObjectsAgree(canonical, []byte("garbage")) {
		t.Fatal("garbage compared equal to a real CA")
	}
}
