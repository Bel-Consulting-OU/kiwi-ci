package app

// Real-PostgreSQL integration tests for the HA runner-PKI startup ordering.
// They prove the defects fixed in this round: runner PKI is initialized
// BEFORE HA/production validation, an explicit CA is installed-or-compared
// against the shared DB cluster key store (divergent files fail startup
// instead of splitting the trust root), and DB-backed enrollment no longer
// requires a node-local --data-dir. Gated on KIWI_TEST_POSTGRES_URL through
// scratchPostgresDSN like the other app integration tests.

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// productionPKIServerArgs returns production-mode server args on dsn/addr
// plus the caller's runner-PKI flags.
func productionPKIServerArgs(t *testing.T, dsn, addr string, extra ...string) []string {
	t.Helper()
	certFile, keyFile := writeSelfSignedTLS(t)
	args := []string{
		"--listen", addr, "--database-url", dsn,
		"--mode", "production", "--external-url", "https://ci.example.com",
		"--tls-cert", certFile, "--tls-key", keyFile,
		"--admin-token", "admin",
	}
	return append(args, extra...)
}

// pkiSharedCAObject reads explicit runner-CA files and renders the canonical
// shared cluster object (cert PEM + NUL + key PEM).
func pkiSharedCAObject(t *testing.T, certPath, keyPath string) []byte {
	t.Helper()
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return append(append(append([]byte{}, certPEM...), 0), keyPEM...)
}

// pkiSharedRunnerCA reads the runner-ca row from the database.
func pkiSharedRunnerCA(t *testing.T, dsn string) ([]byte, bool) {
	t.Helper()
	db, err := openDBForTest(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	blobs, ok := any(db).(storage.ClusterKeyBlobStore)
	if !ok {
		t.Fatal("SQL store does not implement ClusterKeyBlobStore")
	}
	stored, found, err := blobs.GetClusterKey(context.Background(), "runner-ca")
	if err != nil {
		t.Fatalf("read shared runner CA: %v", err)
	}
	return stored, found
}

// TestIntegrationRunnerPKIExplicitCASharedAcrossReplicas: two production
// replicas over one database with the SAME explicit CA files both start and
// the shared key table holds exactly that CA object; a replica configured
// with DIFFERENT files fails startup with the disagreement error instead of
// trusting a divergent node-local CA.
func TestIntegrationRunnerPKIExplicitCASharedAcrossReplicas(t *testing.T) {
	dsn := scratchPostgresDSN(t)
	caA, err := runnerpki.NewCA("ha replica A", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certA, keyA := writeRunnerCAFiles(t, caA)

	ctxA, cancelA := context.WithCancel(context.Background())
	addrA := freeTCPAddr(t)
	errChA := startServer(t, ctxA, productionPKIServerArgs(t, dsn, addrA,
		"--runner-ca-cert", certA, "--runner-ca-key", keyA)...)
	waitTCPUp(t, addrA, errChA, 20*time.Second)

	ctxB, cancelB := context.WithCancel(context.Background())
	addrB := freeTCPAddr(t)
	errChB := startServer(t, ctxB, productionPKIServerArgs(t, dsn, addrB,
		"--runner-ca-cert", certA, "--runner-ca-key", keyA)...)
	waitTCPUp(t, addrB, errChB, 20*time.Second)

	want := pkiSharedCAObject(t, certA, keyA)
	stored, found := pkiSharedRunnerCA(t, dsn)
	if !found || !bytes.Equal(stored, want) {
		t.Fatalf("shared runner CA row: found=%v equal=%v", found, bytes.Equal(stored, want))
	}

	// A third replica with DIFFERENT explicit files must fail startup with
	// the disagreement error, before any listener serves.
	caC, err := runnerpki.NewCA("divergent C", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certC, keyC := writeRunnerCAFiles(t, caC)
	errChC := startServer(t, context.Background(), productionPKIServerArgs(t, dsn, freeTCPAddr(t),
		"--runner-ca-cert", certC, "--runner-ca-key", keyC)...)
	select {
	case err := <-errChC:
		if err == nil || !strings.Contains(err.Error(), "configured runner CA disagrees with cluster runner CA") {
			t.Fatalf("divergent replica startup = %v, want the disagreement error", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("divergent replica did not fail startup")
	}
	after, found := pkiSharedRunnerCA(t, dsn)
	if !found || !bytes.Equal(after, want) {
		t.Fatalf("shared runner CA was replaced by the divergent replica: found=%v", found)
	}

	if err := stopServer(t, cancelB, errChB); err != nil {
		t.Fatalf("replica B returned %v", err)
	}
	if err := stopServer(t, cancelA, errChA); err != nil {
		t.Fatalf("replica A returned %v", err)
	}
}

// TestIntegrationRunnerPKIEnrollmentStartsWithoutDataDir: first boot in
// production with an enrollment token, the DB cluster key store and NO
// node-local data dir (and no bearer tokens) must start. EnsureRunnerCA
// initializes the shared CA BEFORE the production credential decision, so
// the actual state is enforced mTLS; the old order rejected this deployment.
func TestIntegrationRunnerPKIEnrollmentStartsWithoutDataDir(t *testing.T) {
	dsn := scratchPostgresDSN(t)
	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := startServer(t, ctx, productionPKIServerArgs(t, dsn, addr,
		"--runner-enroll-token", "enroll-token")...)
	waitTCPUp(t, addr, errCh, 20*time.Second)
	if err := stopServer(t, cancel, errCh); err != nil {
		t.Fatalf("enrollment server returned %v", err)
	}

	stored, found := pkiSharedRunnerCA(t, dsn)
	if !found || len(stored) == 0 {
		t.Fatalf("auto runner CA not persisted in the shared DB store: found=%v", found)
	}
	if !bytes.Contains(stored, []byte("CERTIFICATE")) || !bytes.Contains(stored, []byte("PRIVATE KEY")) {
		t.Fatal("auto runner CA object is not a certificate+key PEM pair")
	}

	// A second replica with the same enrollment token adopts the SAME CA.
	ctx2, cancel2 := context.WithCancel(context.Background())
	addr2 := freeTCPAddr(t)
	errCh2 := startServer(t, ctx2, productionPKIServerArgs(t, dsn, addr2,
		"--runner-enroll-token", "enroll-token")...)
	waitTCPUp(t, addr2, errCh2, 20*time.Second)
	if err := stopServer(t, cancel2, errCh2); err != nil {
		t.Fatalf("second enrollment server returned %v", err)
	}
	after, found := pkiSharedRunnerCA(t, dsn)
	if !found || !bytes.Equal(after, stored) {
		t.Fatal("second replica replaced the shared auto CA instead of adopting it")
	}
}

// TestIntegrationRunnerPKIActualStateDecidesCredentials: the production
// runner-auth decision uses the ACTUAL initialized state. An explicit CA
// with client certificates NOT required is not enforced mTLS, so with no
// per-runner bearer credentials startup fails the post-DB check.
func TestIntegrationRunnerPKIActualStateDecidesCredentials(t *testing.T) {
	dsn := scratchPostgresDSN(t)
	ca, err := runnerpki.NewCA("actual state", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := writeRunnerCAFiles(t, ca)
	errCh := startServer(t, context.Background(), productionPKIServerArgs(t, dsn, freeTCPAddr(t),
		"--runner-ca-cert", certPath, "--runner-ca-key", keyPath,
		"--runner-require-client-certs=false")...)
	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "production requires runner mTLS or per-runner credentials") {
			t.Fatalf("CA without enforced client certs = %v, want the per-runner credential refusal", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("server without an enforced runner credential did not fail startup")
	}
}
