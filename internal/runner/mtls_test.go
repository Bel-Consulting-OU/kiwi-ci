package runner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

func selfSignedServerCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// TestMTLSEnrollAndRegister drives the full enrollment flow against an mTLS
// control plane: the runner mints a key, enrolls it with the enrollment
// token, and its subsequent register/next requests carry the issued
// certificate.
func TestMTLSEnrollAndRegister(t *testing.T) {
	ca, err := runnerpki.NewCA("test runner ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New("runner-token")
	srv.RunnerCA = ca
	srv.RunnerEnrollToken = "enroll-secret"
	serverCertPEM, serverKeyPEM := selfSignedServerCert(t)

	ts := httptest.NewUnstartedServer(srv.Handler())
	// VerifyClientCertIfGiven: enrollment must be reachable before the
	// runner holds a certificate; handler-level binding enforces identity
	// on every other endpoint.
	serverTLS, err := runnerpki.TLSServerConfig(serverCertPEM, serverKeyPEM, ca, false)
	if err != nil {
		t.Fatal(err)
	}
	ts.TLS = serverTLS
	ts.StartTLS()
	defer ts.Close()

	ctx := context.Background()
	r := &Runner{Cfg: Config{
		Server:      ts.URL,
		Token:       "runner-token",
		EnrollToken: "enroll-secret",
		CACert:      string(serverCertPEM),
	}, ID: "runner-test-1"}
	if err := r.prepareClient(ctx); err != nil {
		t.Fatalf("prepareClient: %v", err)
	}
	if r.Client == nil {
		t.Fatal("mTLS client not built")
	}
	r.Client = server.NoRedirectClient(r.Client)
	if err := r.register(ctx); err != nil {
		t.Fatalf("register over mTLS: %v", err)
	}
	if r.ID != "runner-test-1" {
		t.Fatalf("runner id changed: %q", r.ID)
	}
	if _, _, err := r.next(ctx); err != nil {
		t.Fatalf("next over mTLS: %v", err)
	}
}

func TestPrepareClientRequiresHTTPS(t *testing.T) {
	r := &Runner{Cfg: Config{Server: "http://127.0.0.1:8080", CACert: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"}, ID: "r1"}
	if err := r.prepareClient(context.Background()); err == nil {
		t.Fatal("certificate configuration over plaintext http must be rejected")
	}
}

func TestPrepareClientDevModeLeavesClientNil(t *testing.T) {
	r := &Runner{Cfg: Config{Server: "http://127.0.0.1:8080"}, ID: "r1"}
	if err := r.prepareClient(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Client != nil {
		t.Fatal("no TLS client expected in dev mode")
	}
}

func TestPrepareClientRequiresCertAndKeyTogether(t *testing.T) {
	r := &Runner{Cfg: Config{Server: "https://ci.example.com", Cert: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"}, ID: "r1"}
	if err := r.prepareClient(context.Background()); err == nil {
		t.Fatal("certificate without key must be rejected")
	}
}

func TestValidateServerURLNonLoopbackHTTPRejected(t *testing.T) {
	t.Setenv("KIWI_RUNNER_ALLOW_INSECURE", "")
	if err := validateServerURL("http://ci.example.com"); err == nil {
		t.Fatal("non-loopback plaintext http must be rejected")
	}
}
