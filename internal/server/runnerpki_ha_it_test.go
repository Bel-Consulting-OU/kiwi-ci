package server

// Real-PostgreSQL integration tests for the HA runner-PKI contract: an
// explicit runner CA is installed-or-compared through the DB-backed cluster
// key store so two replicas over one database trust ONE CA, a divergent
// explicit CA fails startup instead of splitting the trust root, and the
// first-boot auto CA is created through the same shared store without any
// node-local data directory. Gated on KIWI_TEST_POSTGRES_URL like the other
// *_it_test.go files in this package.

import (
	"bytes"
	"context"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// TestIntegrationRunnerCAPKISharedAcrossDBReplicas proves the explicit-CA
// install-or-compare contract over real PostgreSQL: replica A installs its
// CA, replica B with the same files adopts it (a certificate issued by A
// verifies on B), and a replica with different files fails startup with the
// disagreement error without replacing the shared CA.
func TestIntegrationRunnerCAPKISharedAcrossDBReplicas(t *testing.T) {
	env := pgITServerSetup(t)
	caA, err := runnerpki.NewCA("ha pki A", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPathA, keyPathA := writeRunnerCAPEMFilesForTest(t, caA)

	s1, blobs := pgITClusterKeyServer(t, env, t.TempDir())
	if err := s1.SetRunnerCA(certPathA, keyPathA); err != nil {
		t.Fatalf("replica A SetRunnerCA: %v", err)
	}
	if s1.RunnerCA == nil {
		t.Fatal("replica A has no runner CA")
	}

	s2, _ := pgITClusterKeyServer(t, env, t.TempDir())
	if err := s2.SetRunnerCA(certPathA, keyPathA); err != nil {
		t.Fatalf("replica B with the same CA files: %v", err)
	}
	if s2.RunnerCA == nil || !bytes.Equal(s1.RunnerCA.Cert.Raw, s2.RunnerCA.Cert.Raw) {
		t.Fatal("replicas did not converge on one shared runner CA")
	}
	_, leaf := pkiSignRunner(t, s1.RunnerCA, "runner-ha")
	roots := runnerpki.Pool(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s2.RunnerCA.Cert.Raw}))
	if id, err := s2.RunnerCA.VerifyPeer(leaf, roots); err != nil || id != "runner-ha" {
		t.Fatalf("a certificate issued by replica A does not verify on replica B: id=%q err=%v", id, err)
	}

	// The shared row holds exactly the explicit object: no silent local-only
	// trust root, no re-encoding drift.
	stored, found, err := blobs.GetClusterKey(context.Background(), clusterKindRunnerCA)
	if err != nil || !found {
		t.Fatalf("shared runner CA row: found=%v err=%v", found, err)
	}
	want, err := os.ReadFile(certPathA)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPathA)
	if err != nil {
		t.Fatal(err)
	}
	want = runnerCAObject(want, keyPEM)
	if !bytes.Equal(stored, want) {
		t.Fatal("shared runner CA row does not hold the explicit cert+key object")
	}

	// A third replica with DIFFERENT explicit files must fail startup ...
	caB, err := runnerpki.NewCA("divergent B", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPathB, keyPathB := writeRunnerCAPEMFilesForTest(t, caB)
	s3, _ := pgITClusterKeyServer(t, env, t.TempDir())
	err = s3.SetRunnerCA(certPathB, keyPathB)
	if err == nil || !strings.Contains(err.Error(), "configured runner CA disagrees with cluster runner CA") {
		t.Fatalf("divergent explicit CA = %v", err)
	}
	// ... and must not have replaced the shared CA.
	after, found, err := blobs.GetClusterKey(context.Background(), clusterKindRunnerCA)
	if err != nil || !found || !bytes.Equal(after, want) {
		t.Fatalf("divergent replica replaced the shared runner CA: found=%v err=%v", found, err)
	}
}

// TestIntegrationRunnerCAPKIEnrollmentWithoutDataDir proves the first-boot
// auto-CA path against the DB-backed store with NO node-local data
// directory: EnsureRunnerCA installs the shared CA through the same
// install-or-load primitive, and a second replica adopts it instead of
// minting its own.
func TestIntegrationRunnerCAPKIEnrollmentWithoutDataDir(t *testing.T) {
	env := pgITServerSetup(t)
	blobs := pgITClusterKeyBlobs(t, env)

	s1 := New("token")
	s1.AdminToken = "admin-token"
	if err := s1.UseClusterKeyStore(&DBClusterKeyStore{Blobs: blobs}); err != nil {
		t.Fatalf("UseClusterKeyStore: %v", err)
	}
	if err := s1.EnsureRunnerCA(); err != nil {
		t.Fatalf("auto runner CA without a data dir: %v", err)
	}
	if s1.RunnerCA == nil {
		t.Fatal("auto runner CA not materialized")
	}
	stored, found, err := blobs.GetClusterKey(context.Background(), clusterKindRunnerCA)
	if err != nil || !found || len(stored) == 0 {
		t.Fatalf("auto CA not stored in the shared table: found=%v err=%v", found, err)
	}

	s2 := New("token")
	s2.AdminToken = "admin-token"
	if err := s2.UseClusterKeyStore(&DBClusterKeyStore{Blobs: blobs}); err != nil {
		t.Fatalf("second UseClusterKeyStore: %v", err)
	}
	if err := s2.EnsureRunnerCA(); err != nil {
		t.Fatalf("second replica EnsureRunnerCA: %v", err)
	}
	if !bytes.Equal(s1.RunnerCA.Cert.Raw, s2.RunnerCA.Cert.Raw) {
		t.Fatal("replicas that raced to enroll did not share one CA")
	}
	after, found, err := blobs.GetClusterKey(context.Background(), clusterKindRunnerCA)
	if err != nil || !found || !bytes.Equal(after, stored) {
		t.Fatalf("second replica replaced the shared auto CA: found=%v err=%v", found, err)
	}
}
