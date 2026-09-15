package runnerpki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

func caCertPEM(t *testing.T, ca *CA) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

func parseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no certificate PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func signRunner(t *testing.T, ca *CA, runnerID string) (keyPEM, certPEM []byte, cert *x509.Certificate) {
	t.Helper()
	keyPEM, csrPEM, err := GenerateKeyAndCSR(runnerID)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err = ca.SignRunnerCSR(csrPEM, runnerID, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	return keyPEM, certPEM, parseCert(t, certPEM)
}

func TestCASelfSigned(t *testing.T) {
	ca, err := NewCA("test runner ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Cert.IsCA || !ca.Cert.BasicConstraintsValid {
		t.Fatal("CA certificate must have CA basic constraints")
	}
	if ca.Cert.Subject.CommonName != "test runner ca" {
		t.Fatalf("unexpected CN %q", ca.Cert.Subject.CommonName)
	}
	if err := ca.Cert.CheckSignatureFrom(ca.Cert); err != nil {
		t.Fatalf("CA certificate is not self-signed: %v", err)
	}
	if !time.Now().Before(ca.Cert.NotAfter) || time.Now().Before(ca.Cert.NotBefore) {
		t.Fatal("CA validity window is wrong")
	}
}

func TestSignRunnerCSR(t *testing.T) {
	ca, err := NewCA("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, certPEM, cert := signRunner(t, ca, "runner-1")
	if cert.Subject.CommonName != "runner-1" {
		t.Fatalf("CN = %q, want runner-1", cert.Subject.CommonName)
	}
	found := false
	for _, u := range cert.URIs {
		if u.String() == RunnerURIPrefix+"runner-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("spiffe URI missing: %v", cert.URIs)
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("KeyUsage = %v", cert.KeyUsage)
	}
	// Runner leaf certificates are ClientAuth-only: they can never
	// authenticate a TLS server.
	if !hasEKU(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) || hasEKU(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatalf("EKU = %v, want client auth only", cert.ExtKeyUsage)
	}
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 {
		t.Fatalf("leaf carries requester-derived SANs: %v %v %v", cert.DNSNames, cert.IPAddresses, cert.EmailAddresses)
	}
	roots := Pool(caCertPEM(t, ca))
	chains, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatalf("issued cert does not verify: %v", err)
	}
	if len(chains) == 0 {
		t.Fatal("no verification chain returned")
	}
	if cert.SerialNumber.Cmp(big.NewInt(0)) <= 0 {
		t.Fatal("serial must be positive")
	}
	_ = certPEM
}

func TestSignRunnerCSRRejectsTamperedSignature(t *testing.T) {
	ca, err := NewCA("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, csrPEM, err := GenerateKeyAndCSR("runner-1")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("no CSR PEM block")
	}
	raw := append([]byte(nil), block.Bytes...)
	raw[len(raw)-1] ^= 0xff
	tampered := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})
	if _, err := ca.SignRunnerCSR(tampered, "runner-1", time.Hour, nil); err == nil {
		t.Fatal("tampered CSR must be rejected")
	}
}

func TestSignRunnerCSRSynthesizesIdentity(t *testing.T) {
	ca, err := NewCA("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// A hostile CSR: the requester claims CN=victim and a raft of SANs.
	// The server ignores all of it and signs ONLY the synthesized
	// identity from the authenticated runner ID.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostileURI, err := url.Parse("spiffe://evil.example/admin")
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "victim", Organization: []string{"evil"}},
		URIs:     []*url.URL{hostileURI},
		DNSNames: []string{"evil.example"},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	certPEM, err := ca.SignRunnerCSR(csrPEM, "runner-a", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert := parseCert(t, certPEM)
	if cert.Subject.CommonName != "runner-a" {
		t.Fatalf("CN = %q, want runner-a", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) != 0 {
		t.Fatalf("CSR subject leaked into certificate: %+v", cert.Subject)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != RunnerURIPrefix+"runner-a" {
		t.Fatalf("URIs = %v, want only the synthesized spiffe identity", cert.URIs)
	}
	if len(cert.DNSNames) != 0 {
		t.Fatalf("CSR DNS SANs leaked: %v", cert.DNSNames)
	}
	_ = pub
}

func TestSignRunnerCSRFillsEmptyCN(t *testing.T) {
	ca, err := NewCA("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	certPEM, err := ca.SignRunnerCSR(csrPEM, "runner-9", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert := parseCert(t, certPEM)
	if cert.Subject.CommonName != "runner-9" {
		t.Fatalf("CN = %q, want runner-9", cert.Subject.CommonName)
	}
	_ = pub
}

func TestVerifyPeer(t *testing.T) {
	ca, err := NewCA("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, _, cert := signRunner(t, ca, "runner-7")
	roots := Pool(caCertPEM(t, ca))
	id, err := ca.VerifyPeer(cert, roots)
	if err != nil {
		t.Fatalf("VerifyPeer: %v", err)
	}
	if id != "runner-7" {
		t.Fatalf("runner id = %q, want runner-7", id)
	}
	// Unknown roots must fail.
	if _, err := ca.VerifyPeer(cert, Pool(nil)); err == nil {
		t.Fatal("verify against empty pool must fail")
	}
	// A nil peer must fail.
	if _, err := ca.VerifyPeer(nil, roots); err == nil {
		t.Fatal("nil peer must fail")
	}
}

func TestGenerateKeyAndCSR(t *testing.T) {
	privPEM, csrPEM, err := GenerateKeyAndCSR("runner-3")
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(privPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatal("key PEM malformed")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(ed25519.PrivateKey); !ok {
		t.Fatal("key is not Ed25519")
	}
	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil {
		t.Fatal("CSR PEM malformed")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR self-signature invalid: %v", err)
	}
	if csr.Subject.CommonName != "runner-3" {
		t.Fatalf("CN = %q", csr.Subject.CommonName)
	}
	if len(csr.URIs) != 1 || csr.URIs[0].String() != RunnerURIPrefix+"runner-3" {
		t.Fatalf("URIs = %v", csr.URIs)
	}
	if _, _, err := GenerateKeyAndCSR(""); err == nil {
		t.Fatal("empty runner id must be rejected")
	}
}

func TestLoadOrCreateCA(t *testing.T) {
	dir := t.TempDir()
	ca1, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca1.Cert.Raw) != string(ca2.Cert.Raw) {
		t.Fatal("reloaded CA certificate differs")
	}
	if _, err := LoadOrCreateCA(filepath.Join(dir, "nested")); err != nil {
		t.Fatalf("fresh nested dir: %v", err)
	}
}

func TestLoadCARejectsMismatchedKey(t *testing.T) {
	ca1, err := NewCA("first", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := NewCA("second", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := caCertPEM(t, ca1)
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca2.Key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if _, err := LoadCA(certPEM, keyPEM); err == nil {
		t.Fatal("cert/key from different CAs must fail to load")
	}
}

func TestLeafSerialsUniqueAcrossGenerations(t *testing.T) {
	// Serial numbers come from crypto/rand, not process-local counters:
	// two fresh CAs (e.g. two control-plane generations) must not issue
	// colliding leaf serials, and one CA must issue distinct serials.
	ca1, err := NewCA("generation one", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := NewCA("generation two", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, certPEM1, cert1 := signRunner(t, ca1, "runner-1")
	_, certPEM2, cert2 := signRunner(t, ca1, "runner-2")
	_, certPEM3, cert3 := signRunner(t, ca2, "runner-3")
	if cert1.SerialNumber.Cmp(cert2.SerialNumber) == 0 {
		t.Fatal("leaf serials within one CA collided")
	}
	if cert1.SerialNumber.Cmp(cert3.SerialNumber) == 0 || cert2.SerialNumber.Cmp(cert3.SerialNumber) == 0 {
		t.Fatal("leaf serials across CA generations collided")
	}
	for i, cert := range []*x509.Certificate{cert1, cert2, cert3} {
		if cert.SerialNumber.BitLen() > 128 || cert.SerialNumber.Sign() <= 0 {
			t.Fatalf("leaf %d serial %v is not a positive 128-bit number", i, cert.SerialNumber)
		}
	}
	_ = certPEM1
	_ = certPEM2
	_ = certPEM3
}

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

func TestTLSHandshakeMTLS(t *testing.T) {
	ca, err := NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	runnerKey, runnerCert, _ := signRunner(t, ca, "runner-1")
	otherKey, otherCert, _ := signRunner(t, ca, "runner-2")
	serverCertPEM, serverKeyPEM := selfSignedServerCert(t)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerID := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			peerID = RunnerIDFromCert(r.TLS.PeerCertificates[0])
		}
		_, _ = io.WriteString(w, peerID)
	}))
	serverTLS, err := TLSServerConfig(serverCertPEM, serverKeyPEM, ca, true)
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = serverTLS
	srv.StartTLS()
	defer srv.Close()

	clientTLS, err := TLSClientConfig(runnerCert, runnerKey, serverCertPEM, "")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("mTLS handshake failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "runner-1" {
		t.Fatalf("server saw peer %q, want runner-1", body)
	}

	// A different client certificate authenticates a different identity.
	otherTLS, err := TLSClientConfig(otherCert, otherKey, serverCertPEM, "")
	if err != nil {
		t.Fatal(err)
	}
	otherClient := &http.Client{Transport: &http.Transport{TLSClientConfig: otherTLS}}
	resp, err = otherClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("second client handshake failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "runner-2" {
		t.Fatalf("server saw peer %q, want runner-2", body)
	}

	// A client without a certificate must fail the handshake.
	noCertTLS, err := TLSClientConfig(nil, nil, serverCertPEM, "")
	if err != nil {
		t.Fatal(err)
	}
	noCertClient := &http.Client{Transport: &http.Transport{TLSClientConfig: noCertTLS}}
	if resp, err := noCertClient.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("client without certificate must fail the mTLS handshake")
	}
}

func TestTLSClientConfigLoadsServerName(t *testing.T) {
	cfg, err := TLSClientConfig(nil, nil, nil, "ci.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "ci.example.com" {
		t.Fatalf("ServerName = %q", cfg.ServerName)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatal("minimum TLS version must be 1.3")
	}
	if _, err := TLSClientConfig([]byte("not a cert"), []byte("not a key"), nil, ""); err == nil {
		t.Fatal("garbage key pair must be rejected")
	}
	if _, err := TLSServerConfig(nil, nil, nil, true); err == nil {
		t.Fatal("missing CA must be rejected when client certs are required")
	}
}
