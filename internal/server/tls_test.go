package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// selfSignedServerCert writes a TLS server certificate/key pair to dir and
// returns their paths.
func selfSignedServerCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kiwi-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"127.0.0.1", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// issueRunnerClientCert issues a runner client certificate for runnerID
// signed by ca, returning the tls.Certificate.
func issueRunnerClientCert(t *testing.T, ca *runnerpki.CA, runnerID string) tls.Certificate {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := &x509.CertificateRequest{Subject: pkix.Name{CommonName: runnerID}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csr, priv)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	certPEM, err := ca.SignRunnerCSR(csrPEM, runnerID, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestTLSConfigVerifiesRunnerClientCerts(t *testing.T) {
	ca, err := runnerpki.NewCA("test runner CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("runner-tok")
	s.AdminToken = "admin-tok"
	s.RunnerCA = ca
	s.RunnerClientCAPool = runnerpki.Pool(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}))
	s.RequireRunnerClientCerts = true

	certFile, keyFile := selfSignedServerCert(t, t.TempDir())
	tlsCfg, err := s.TLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %d, want TLS 1.2 floor", tlsCfg.MinVersion)
	}
	// The listener is SHARED with admin/forge/dashboard traffic: the
	// handshake verifies client certificates when presented but never
	// requires them. The mandatory-certificate rule lives in the
	// runner-tier HTTP authorization.
	if tlsCfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("ClientAuth = %v, want VerifyClientCertIfGiven on the shared listener", tlsCfg.ClientAuth)
	}
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.TLS = tlsCfg
	ts.StartTLS()
	defer ts.Close()

	// A runnerpki-issued client certificate succeeds at the handshake and
	// the identity binds to a runner-tier route (the runner bearer is still
	// presented; the certificate pins the transport identity). The runner
	// registers through the mTLS client first: registration adopts the
	// certificate identity.
	clientCert := issueRunnerClientCert(t, ca, "runner-1")
	client := ts.Client()
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{clientCert}, InsecureSkipVerify: true}}
	regReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/runners/register", stringsReader(`{"name":"runner-1","protocol_min":3,"protocol_max":3}`))
	regReq.Header.Set("Authorization", "Bearer runner-tok")
	regReq.Header.Set("Content-Type", "application/json")
	regResp, err := client.Do(regReq)
	if err != nil {
		t.Fatal(err)
	}
	regResp.Body.Close()
	if regResp.StatusCode != http.StatusOK {
		t.Fatalf("register with client cert: got %d, want 200", regResp.StatusCode)
	}
	req0, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/runners/runner-1/next", stringsReader("{}"))
	req0.Header.Set("Authorization", "Bearer runner-tok")
	req0.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req0)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("next with valid client cert: got %d, want 200/204", resp.StatusCode)
	}

	// Without a client certificate the handshake still succeeds (shared
	// listener), but runner-tier routes are refused at the HTTP layer even
	// with a valid runner bearer: 401.
	noCert := ts.Client()
	noCert.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}
	publicResp, err := noCert.Get(ts.URL + "/readiness")
	if err != nil {
		t.Fatal(err)
	}
	publicResp.Body.Close()
	if publicResp.StatusCode != http.StatusOK {
		t.Fatalf("cert-less /readiness on shared listener: got %d, want 200", publicResp.StatusCode)
	}
	noCertReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/runners/runner-1/next", stringsReader("{}"))
	noCertReq.Header.Set("Authorization", "Bearer runner-tok")
	noCertReq.Header.Set("Content-Type", "application/json")
	noCertResp, err := noCert.Do(noCertReq)
	if err != nil {
		t.Fatal(err)
	}
	noCertResp.Body.Close()
	if noCertResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("runner-tier route without client cert: got %d, want 401", noCertResp.StatusCode)
	}

	// A valid certificate acting for a different runner ID fails the
	// identity binding (403) even though the handshake succeeded.
	otherCert := issueRunnerClientCert(t, ca, "runner-2")
	client2 := ts.Client()
	client2.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{otherCert}, InsecureSkipVerify: true}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/runners/runner-1/next", stringsReader("{}"))
	req.Header.Set("Authorization", "Bearer runner-tok")
	req.Header.Set("Content-Type", "application/json")
	resp2, err := client2.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("cert identity mismatch on runner route: got %d, want 403", resp2.StatusCode)
	}
}

func TestTLSConfigVerifyIfGivenWithoutRequirement(t *testing.T) {
	ca, err := runnerpki.NewCA("test runner CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("runner-tok")
	s.RunnerCA = ca
	s.RunnerClientCAPool = runnerpki.Pool(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}))

	certFile, keyFile := selfSignedServerCert(t, t.TempDir())
	tlsCfg, err := s.TLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("ClientAuth = %v, want VerifyClientCertIfGiven", tlsCfg.ClientAuth)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	ts.TLS = tlsCfg
	ts.StartTLS()
	defer ts.Close()
	plain := ts.Client()
	plain.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}
	resp, err := plain.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cert-less request with VerifyClientCertIfGiven: got %d, want 200", resp.StatusCode)
	}
}

func TestTLSConfigRequiresPoolWhenRequired(t *testing.T) {
	s := New("t")
	s.RequireRunnerClientCerts = true
	certFile, keyFile := selfSignedServerCert(t, t.TempDir())
	if _, err := s.TLSConfig(certFile, keyFile); err == nil {
		t.Fatal("expected error for RequireRunnerClientCerts without a CA pool")
	}
}

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }
