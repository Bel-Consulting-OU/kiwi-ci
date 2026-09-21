package app

// Socket-level tests for the control-plane listener: they drive the REAL
// serving path (Server -> net.Listen -> Serve/ServeTLS) instead of asserting
// on a constructed tls.Config, which is exactly why the plaintext-serving P0
// and the global-timeout P2 shipped. TLS material is generated in-test with
// crypto/x509 for 127.0.0.1.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// observeControlPlane installs fn as the controlPlaneBuilt hook for one test.
func observeControlPlane(t *testing.T, fn func(h *http.Server, addr string)) {
	t.Helper()
	prev := controlPlaneBuilt
	controlPlaneBuilt = fn
	t.Cleanup(func() { controlPlaneBuilt = prev })
}

// controlPlaneSnapshot copies the assembled server's timeout/TLS values at
// hook time. net/http mutates http.Server.TLSConfig (NextProtos) once Serve
// starts, so reading the live *http.Server from the test goroutine would
// race with the serving goroutine.
type controlPlaneSnapshot struct {
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	TLSConfigured     bool
	TLSMinVersion     uint16
	TLSCertificates   int
}

func snapshotControlPlane(h *http.Server) controlPlaneSnapshot {
	s := controlPlaneSnapshot{
		ReadTimeout:       h.ReadTimeout,
		WriteTimeout:      h.WriteTimeout,
		ReadHeaderTimeout: h.ReadHeaderTimeout,
		IdleTimeout:       h.IdleTimeout,
		TLSConfigured:     h.TLSConfig != nil,
	}
	if h.TLSConfig != nil {
		s.TLSMinVersion = h.TLSConfig.MinVersion
		s.TLSCertificates = len(h.TLSConfig.Certificates)
	}
	return s
}

// startServerEphemeral starts Server with --listen 127.0.0.1:0 through the
// listenControlPlane seam and returns the real bound address plus the error
// channel from startServer. The seam removes the reserve-close-reopen race of
// freeTCPAddr and exposes the address actually served.
func startServerEphemeral(t *testing.T, ctx context.Context, args ...string) (string, chan error) {
	t.Helper()
	prev := listenControlPlane
	addrCh := make(chan string, 1)
	listenControlPlane = func(network, _ string) (net.Listener, error) {
		ln, err := net.Listen(network, "127.0.0.1:0")
		if err == nil {
			select {
			case addrCh <- ln.Addr().String():
			default:
			}
		}
		return ln, err
	}
	t.Cleanup(func() { listenControlPlane = prev })
	errCh := make(chan error, 1)
	go func() { errCh <- Server(ctx, append([]string{"--listen", "127.0.0.1:0"}, args...)) }()
	select {
	case addr := <-addrCh:
		return addr, errCh
	case err := <-errCh:
		t.Fatalf("Server returned before listening: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("server did not bind a listener")
	}
	return "", nil
}

// testServerTLS is an in-test CA plus a 127.0.0.1 server certificate signed
// by it, materialized where --tls-cert/--tls-key can load them.
type testServerTLS struct {
	roots    *x509.CertPool
	certFile string
	keyFile  string
}

func newTestServerTLS(t *testing.T) testServerTLS {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kiwi socket test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(srvKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return testServerTLS{roots: roots, certFile: certFile, keyFile: keyFile}
}

// writeRunnerCAFiles writes a runnerpki CA as --runner-ca-cert/--runner-ca-key
// PEM files.
func writeRunnerCAFiles(t *testing.T, ca *runnerpki.CA) (string, string) {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "runner-ca.crt")
	keyPath := filepath.Join(dir, "runner-ca.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// newRunnerClientCert issues an Ed25519 client certificate for id signed by
// the runner CA (CN identity, ClientAuth EKU, exactly like enrolled certs).
func newRunnerClientCert(t *testing.T, ca *runnerpki.CA, id string) tls.Certificate {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: id},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, priv.Public(), ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// tlsHTTPClient builds a client that trusts roots and presents cert when
// non-nil.
func tlsHTTPClient(roots *x509.CertPool, cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 15 * time.Second}
}

// doSocketJSON performs one request against the real listener and returns the
// response (body already read) and the body bytes.
func doSocketJSON(t *testing.T, client *http.Client, method, url, bearer, body string) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return resp, data
}

// TestTLSSocketPlaintextRejectedAndHTTPSVerified drives the real serving path
// with --tls-cert/--tls-key: the port must refuse plaintext and complete a
// verified TLS handshake. Before the T1-A fix this listener served PLAINTEXT
// (ListenAndServe), so the first probe returned 200.
func TestTLSSocketPlaintextRejectedAndHTTPSVerified(t *testing.T) {
	pki := newTestServerTLS(t)
	ctx, cancel := context.WithCancel(context.Background())
	addr, errCh := startServerEphemeral(t, ctx, "--tls-cert", pki.certFile, "--tls-key", pki.keyFile)
	defer func() {
		if err := stopServer(t, cancel, errCh); err != nil {
			t.Fatalf("Server returned %v", err)
		}
	}()

	// Plaintext against the TLS port must fail or answer non-200. Go's TLS
	// server special-cases HTTP-looking records with a plaintext 400, so both
	// outcomes are accepted; a 200 means the listener is serving plaintext.
	plain := &http.Client{Timeout: 5 * time.Second}
	resp, err := plain.Get("http://" + addr + "/readiness")
	if err == nil {
		if resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			t.Fatal("plaintext HTTP request to the TLS listener returned 200: listener is serving plaintext")
		}
		t.Logf("plaintext probe rejected: status %d", resp.StatusCode)
		resp.Body.Close()
	} else {
		t.Logf("plaintext probe rejected: transport error %v", err)
	}

	// The same port completes a verified TLS handshake trusting the in-test CA.
	client := tlsHTTPClient(pki.roots, nil)
	resp, body := doSocketJSON(t, client, http.MethodGet, "https://"+addr+"/readiness", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS /readiness = %d %s, want 200", resp.StatusCode, body)
	}
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Fatalf("HTTPS negotiated %+v, want TLS >= 1.2", resp.TLS)
	}
}

// TestTLSSocketRunnerMTLSIdentity proves the verified peer certificate reaches
// the HTTP authorization layer: with a runner CA (and no shared bearer token)
// the certificate alone registers and identifies a runner, a mismatched
// certificate is refused, and a certificate-less request is rejected.
func TestTLSSocketRunnerMTLSIdentity(t *testing.T) {
	pki := newTestServerTLS(t)
	runnerCA, err := runnerpki.NewCA("socket runner CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caCert, caKey := writeRunnerCAFiles(t, runnerCA)

	ctx, cancel := context.WithCancel(context.Background())
	// No --runner-token: enforced runner mTLS is the only runner credential
	// (--runner-require-client-certs defaults to true).
	addr, errCh := startServerEphemeral(t, ctx,
		"--tls-cert", pki.certFile, "--tls-key", pki.keyFile,
		"--runner-ca-cert", caCert, "--runner-ca-key", caKey)
	defer func() {
		if err := stopServer(t, cancel, errCh); err != nil {
			t.Fatalf("Server returned %v", err)
		}
	}()

	base := "https://" + addr
	cert1 := newRunnerClientCert(t, runnerCA, "runner-1")
	client1 := tlsHTTPClient(pki.roots, &cert1)

	// Certificate-only registration adopts the certificate identity.
	resp, body := doSocketJSON(t, client1, http.MethodPost, base+"/api/v1/runners/register", "",
		`{"name":"runner-1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cert-only register = %d %s, want 200", resp.StatusCode, body)
	}
	var registered model.Runner
	if err := json.Unmarshal(body, &registered); err != nil {
		t.Fatal(err)
	}
	if registered.ID != "runner-1" {
		t.Fatalf("cert-only register adopted id %q, want the certificate CN runner-1", registered.ID)
	}

	// runner-1's certificate is authorized on runner-1's routes.
	resp, body = doSocketJSON(t, client1, http.MethodPost, base+"/api/v1/runners/runner-1/next", "", "")
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("runner-1 next with runner-1 cert = %d %s, want 200/204", resp.StatusCode, body)
	}

	// A different valid certificate cannot act for runner-1: the handshake
	// succeeds (both chain to the runner CA) but the HTTP identity binding
	// rejects the mismatch.
	cert2 := newRunnerClientCert(t, runnerCA, "runner-2")
	client2 := tlsHTTPClient(pki.roots, &cert2)
	resp, body = doSocketJSON(t, client2, http.MethodPost, base+"/api/v1/runners/runner-1/next", "", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("runner-2 cert on runner-1 route = %d %s, want 403 identity mismatch", resp.StatusCode, body)
	}

	// Certificate-less clients still reach the shared listener (readiness),
	// but the runner tier requires the certificate: 401.
	clientNone := tlsHTTPClient(pki.roots, nil)
	resp, body = doSocketJSON(t, clientNone, http.MethodGet, base+"/readiness", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readiness without client cert = %d %s, want 200 (shared listener VerifyClientCertIfGiven)", resp.StatusCode, body)
	}
	resp, body = doSocketJSON(t, clientNone, http.MethodPost, base+"/api/v1/runners/register", "",
		`{"name":"runner-x","protocol_min":3,"protocol_max":3}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cert-less register with enforced runner mTLS = %d %s, want 401", resp.StatusCode, body)
	}
}

// TestTLSSocketNoTLSControlServesPlaintext is the control case: without
// --tls-cert/--tls-key the same serving path stays plaintext and builds no
// TLS configuration.
func TestTLSSocketNoTLSControlServesPlaintext(t *testing.T) {
	snapCh := make(chan controlPlaneSnapshot, 1)
	observeControlPlane(t, func(h *http.Server, _ string) { snapCh <- snapshotControlPlane(h) })

	ctx, cancel := context.WithCancel(context.Background())
	addr, errCh := startServerEphemeral(t, ctx)
	defer func() {
		if err := stopServer(t, cancel, errCh); err != nil {
			t.Fatalf("Server returned %v", err)
		}
	}()

	resp, body := doSocketJSON(t, &http.Client{Timeout: 5 * time.Second}, http.MethodGet, "http://"+addr+"/readiness", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("plaintext /readiness = %d %s, want 200", resp.StatusCode, body)
	}
	select {
	case snap := <-snapCh:
		if snap.TLSConfigured {
			t.Fatal("no-TLS control built a TLS configuration, want none")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("control-plane hook was not invoked")
	}
}

// TestTLSListenerTimeoutConfiguration asserts the timeout policy actually
// assembled: header bound kept, idle bound kept, global body read/write
// deadlines disabled (the P2 fix), and the TLS configuration from
// Server.TLSConfig carried for the TLS case only.
func TestTLSListenerTimeoutConfiguration(t *testing.T) {
	pki := newTestServerTLS(t)

	newCapturedServer := func(t *testing.T, args ...string) controlPlaneSnapshot {
		t.Helper()
		snapCh := make(chan controlPlaneSnapshot, 1)
		observeControlPlane(t, func(h *http.Server, _ string) { snapCh <- snapshotControlPlane(h) })
		ctx, cancel := context.WithCancel(context.Background())
		_, errCh := startServerEphemeral(t, ctx, args...)
		t.Cleanup(func() {
			if err := stopServer(t, cancel, errCh); err != nil {
				t.Fatalf("Server returned %v", err)
			}
		})
		select {
		case snap := <-snapCh:
			return snap
		case <-time.After(5 * time.Second):
			t.Fatal("control-plane hook was not invoked")
			return controlPlaneSnapshot{}
		}
	}

	t.Run("TLS listener", func(t *testing.T) {
		h := newCapturedServer(t, "--tls-cert", pki.certFile, "--tls-key", pki.keyFile)
		if h.ReadTimeout != 0 || h.WriteTimeout != 0 {
			t.Fatalf("global ReadTimeout/WriteTimeout = %v/%v, want 0/0 (streaming routes must not carry body/write deadlines)", h.ReadTimeout, h.WriteTimeout)
		}
		if h.ReadHeaderTimeout != 5*time.Second {
			t.Fatalf("ReadHeaderTimeout = %v, want 5s", h.ReadHeaderTimeout)
		}
		if h.IdleTimeout != 90*time.Second {
			t.Fatalf("IdleTimeout = %v, want 90s", h.IdleTimeout)
		}
		if !h.TLSConfigured {
			t.Fatal("TLS listener built without a TLS configuration")
		}
		if h.TLSMinVersion != tls.VersionTLS12 {
			t.Fatalf("TLS MinVersion = %x, want TLS 1.2", h.TLSMinVersion)
		}
		if h.TLSCertificates != 1 {
			t.Fatalf("TLS certificates = %d, want the loaded server pair", h.TLSCertificates)
		}
	})

	t.Run("plaintext listener", func(t *testing.T) {
		h := newCapturedServer(t)
		if h.ReadTimeout != 0 || h.WriteTimeout != 0 {
			t.Fatalf("plaintext ReadTimeout/WriteTimeout = %v/%v, want 0/0", h.ReadTimeout, h.WriteTimeout)
		}
		if h.TLSConfigured {
			t.Fatal("plaintext listener carries a TLS configuration, want none")
		}
	})
}

// socketArtifactPipeline declares one "bin" artifact so the upload endpoint
// accepts the streamed body (internal/server/contracts_test.go shape).
const socketArtifactPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    artifacts:
      - name: bin
        paths:
          - out/
        retention: 1h
    steps:
      - run: echo hi
`

// trickleReader emits small chunks separated by gaps, forcing chunked transfer
// encoding and a body whose arrival spans (len(chunks)-1)*gap.
type trickleReader struct {
	chunks [][]byte
	gap    time.Duration
	i      int
	off    int
}

func newTrickleReader(chunkSize, chunks int, gap time.Duration) *trickleReader {
	list := make([][]byte, chunks)
	for i := range list {
		list[i] = bytes.Repeat([]byte{'x'}, chunkSize)
	}
	return &trickleReader{chunks: list, gap: gap}
}

func (r *trickleReader) Read(p []byte) (int, error) {
	if r.i >= len(r.chunks) {
		return 0, io.EOF
	}
	if r.i > 0 && r.off == 0 {
		time.Sleep(r.gap)
	}
	n := copy(p, r.chunks[r.i][r.off:])
	r.off += n
	if r.off == len(r.chunks[r.i]) {
		r.i++
		r.off = 0
	}
	return n, nil
}

// leaseArtifactJob registers a runner, submits a run whose pipeline declares
// the "bin" artifact, leases the job, and returns the runner plus the lease
// contract required for artifact uploads on the real listener.
func leaseArtifactJob(t *testing.T, client *http.Client, base, token string) (model.Runner, string, string, int64) {
	t.Helper()
	resp, body := doSocketJSON(t, client, http.MethodPost, base+"/api/v1/runners/register", token,
		`{"name":"slow-runner","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register = %d %s, want 200", resp.StatusCode, body)
	}
	var runner model.Runner
	if err := json.Unmarshal(body, &runner); err != nil {
		t.Fatal(err)
	}
	submit := `{"repo_url":"https://example.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","sha":"abc","event":"push","pipeline":` +
		jsonString(t, socketArtifactPipeline) + `}`
	resp, body = doSocketJSON(t, client, http.MethodPost, base+"/api/v1/runs", token, submit)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("submit = %d %s, want 202", resp.StatusCode, body)
	}
	resp, body = doSocketJSON(t, client, http.MethodPost, base+"/api/v1/runners/"+runner.ID+"/next", token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lease = %d %s, want 200", resp.StatusCode, body)
	}
	var task struct {
		Job             model.Job `json:"job"`
		LeaseToken      string    `json:"lease_token"`
		LeaseGeneration int64     `json:"lease_generation"`
	}
	if err := json.Unmarshal(body, &task); err != nil {
		t.Fatal(err)
	}
	if task.Job.ID == "" {
		t.Fatalf("lease returned no job: %s", body)
	}
	return runner, task.Job.ID, task.LeaseToken, task.LeaseGeneration
}

// TestSlowUploadStreamingDeadlinePolicy proves the P2 fix on the real server:
// a multi-second chunked artifact upload (the up-to-8-GiB streaming class,
// internal/server/blobs.go maxBlobBytes) succeeds while a JSON API body
// stalled past the same bound is cut.
//
// The 30s semantics are proven WITHOUT a 31s wall-clock test by (a) asserting
// the assembled server has ReadTimeout/WriteTimeout 0
// (TestTLSListenerTimeoutConfiguration) and (b) shrinking only the
// middleware's duration seams here so the same code path that enforces the
// production 30s/60s in withAPIDeadlines makes the exempt route outlive the
// bound and cuts the non-exempt route.
func TestSlowUploadStreamingDeadlinePolicy(t *testing.T) {
	prevRead, prevWrite := apiReadDeadline, apiWriteDeadline
	apiReadDeadline, apiWriteDeadline = 500*time.Millisecond, 10*time.Second
	t.Cleanup(func() { apiReadDeadline, apiWriteDeadline = prevRead, prevWrite })

	ctx, cancel := context.WithCancel(context.Background())
	addr, errCh := startServerEphemeral(t, ctx, "--runner-token", "tok", "--data-dir", t.TempDir())
	defer func() {
		if err := stopServer(t, cancel, errCh); err != nil {
			t.Fatalf("Server returned %v", err)
		}
	}()

	base := "http://" + addr
	client := &http.Client{Timeout: 30 * time.Second}
	runner, jobID, leaseToken, leaseGeneration := leaseArtifactJob(t, client, base, "tok")

	// The streaming-exempt artifact upload: ~1s of trickled chunks, twice the
	// shrunk 500ms bound.
	uploadStart := time.Now()
	upReq, err := http.NewRequest(http.MethodPut, base+"/api/v1/jobs/"+jobID+"/artifacts/bin",
		newTrickleReader(8, 6, 200*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	upReq.Header.Set("Authorization", "Bearer tok")
	upReq.Header.Set("X-Kiwi-Runner-ID", runner.ID)
	upReq.Header.Set("X-Kiwi-Lease-Token", leaseToken)
	upReq.Header.Set("X-Kiwi-Lease-Generation", strconv.FormatInt(leaseGeneration, 10))
	upResp, err := client.Do(upReq)
	if err != nil {
		t.Fatalf("slow artifact upload failed at the transport: %v", err)
	}
	upBody, _ := io.ReadAll(io.LimitReader(upResp.Body, 1<<20))
	upResp.Body.Close()
	if upResp.StatusCode != http.StatusCreated {
		t.Fatalf("slow artifact upload = %d %s, want 201", upResp.StatusCode, upBody)
	}
	if elapsed := time.Since(uploadStart); elapsed < 500*time.Millisecond {
		t.Fatalf("slow upload finished in %v; the test did not exercise the body deadline", elapsed)
	}

	// The same trickle against an ordinary JSON route is cut by the bound:
	// the request must not be accepted (the client may observe the 400 or a
	// transport error from the server closing the body early).
	downReq, err := http.NewRequest(http.MethodPost, base+"/api/v1/runs", newTrickleReader(8, 6, 200*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	downReq.Header.Set("Authorization", "Bearer tok")
	downReq.Header.Set("Content-Type", "application/json")
	downResp, downErr := client.Do(downReq)
	if downErr == nil {
		defer downResp.Body.Close()
		if downResp.StatusCode < 400 {
			t.Fatalf("stalled JSON body = %d, want the body deadline to refuse it", downResp.StatusCode)
		}
	}
}

// TestStreamingDeadlineStalledHeaderDropped proves ReadHeaderTimeout still
// applies to the real listener: a connection that stalls mid-headers is
// dropped (or answered with a non-200), never served.
func TestStreamingDeadlineStalledHeaderDropped(t *testing.T) {
	observeControlPlane(t, func(h *http.Server, _ string) {
		h.ReadHeaderTimeout = 200 * time.Millisecond
	})
	ctx, cancel := context.WithCancel(context.Background())
	addr, errCh := startServerEphemeral(t, ctx)
	defer func() {
		if err := stopServer(t, cancel, errCh); err != nil {
			t.Fatalf("Server returned %v", err)
		}
	}()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /readiness HTTP/1.1\r\nHost: kiwi\r\n"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond) // 3x the shrunken header bound
	_, werr := io.WriteString(conn, "\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, rerr := http.ReadResponse(bufio.NewReader(conn), nil)
	if rerr != nil {
		var ne net.Error
		if errors.As(rerr, &ne) && ne.Timeout() {
			t.Fatal("stalled header connection was neither dropped nor answered past ReadHeaderTimeout")
		}
		if werr == nil {
			t.Logf("connection dropped after the header stall: %v", rerr)
		}
		return
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("stalled header connection was served: %d", resp.StatusCode)
	}
	t.Logf("header stall answered with %d, not served", resp.StatusCode)
}

// TestKeepAliveStreamClearsInheritedDeadlines is the HTTP/1.1 keep-alive
// regression for the connection-deadline leak: the first (ordinary) request
// on a connection leaves absolute read/write deadlines on it, and the SAME
// connection then runs a deliberately slow streaming upload that outlives
// those deadlines. It must complete 201 because the streaming branch clears
// both deadlines before dispatch. No client pooling is involved: raw net.Dial
// plus manual chunked framing.
func TestKeepAliveStreamClearsInheritedDeadlines(t *testing.T) {
	prevRead, prevWrite := apiReadDeadline, apiWriteDeadline
	apiReadDeadline, apiWriteDeadline = 400*time.Millisecond, 400*time.Millisecond
	t.Cleanup(func() { apiReadDeadline, apiWriteDeadline = prevRead, prevWrite })

	ctx, cancel := context.WithCancel(context.Background())
	addr, errCh := startServerEphemeral(t, ctx, "--runner-token", "tok", "--data-dir", t.TempDir())
	defer func() {
		if err := stopServer(t, cancel, errCh); err != nil {
			t.Fatalf("Server returned %v", err)
		}
	}()

	base := "http://" + addr
	client := &http.Client{Timeout: 15 * time.Second}
	runner, jobID, leaseToken, leaseGeneration := leaseArtifactJob(t, client, base, "tok")

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)

	// Request 1: an ordinary API route. Its response completes, but the
	// middleware's absolute deadlines stay on the connection.
	if _, err := fmt.Fprintf(conn, "GET /readiness HTTP/1.1\r\nHost: kiwi\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("readiness on raw connection: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readiness = %d, want 200", resp.StatusCode)
	}

	// Let the first request's absolute deadlines expire before the stream.
	time.Sleep(700 * time.Millisecond)

	// Request 2: a slow streaming PUT on the SAME connection, ~1.5s > the
	// 400ms ordinary deadlines.
	head := fmt.Sprintf("PUT /api/v1/jobs/%s/artifacts/bin HTTP/1.1\r\nHost: kiwi\r\n"+
		"Authorization: Bearer tok\r\n"+
		"X-Kiwi-Runner-ID: %s\r\n"+
		"X-Kiwi-Lease-Token: %s\r\n"+
		"X-Kiwi-Lease-Generation: %d\r\n"+
		"Content-Type: application/gzip\r\n"+
		"Transfer-Encoding: chunked\r\n\r\n",
		jobID, runner.ID, leaseToken, leaseGeneration)
	if _, err := io.WriteString(conn, head); err != nil {
		t.Fatal(err)
	}
	streamUntil := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(streamUntil) {
		if _, err := io.WriteString(conn, "4\r\nkiwi\r\n"); err != nil {
			t.Fatalf("slow stream on the reused keep-alive connection was cut (inherited deadlines leaked?): %v", err)
		}
		time.Sleep(150 * time.Millisecond)
	}
	if _, err := io.WriteString(conn, "0\r\n\r\n"); err != nil {
		t.Fatalf("final chunk on the reused connection: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	streamResp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("streaming response on the reused connection failed (inherited deadlines leaked?): %v", err)
	}
	streamBody, _ := io.ReadAll(io.LimitReader(streamResp.Body, 1<<20))
	streamResp.Body.Close()
	if streamResp.StatusCode != http.StatusCreated {
		t.Fatalf("slow stream on the reused connection = %d %s, want 201", streamResp.StatusCode, streamBody)
	}
}

// stallAfterFirstRead sends one small chunk and then stalls long past any
// (test-shrunk) idle bound before completing, forcing the server-side sliding
// read deadline to fire.
type stallAfterFirstRead struct {
	sent bool
}

func (b *stallAfterFirstRead) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, "kiwi"), nil
	}
	time.Sleep(2 * time.Second)
	return 0, io.EOF
}

// TestStreamingStalledUploadDroppedByIdleBound proves the sliding bound is a
// real bound: an upload that sends some bytes and then stops is terminated
// (never accepted with 201) well before its stall ends.
func TestStreamingStalledUploadDroppedByIdleBound(t *testing.T) {
	prevIdle := streamIdleTimeout
	streamIdleTimeout = 250 * time.Millisecond
	t.Cleanup(func() { streamIdleTimeout = prevIdle })

	ctx, cancel := context.WithCancel(context.Background())
	addr, errCh := startServerEphemeral(t, ctx, "--runner-token", "tok", "--data-dir", t.TempDir())
	defer func() {
		if err := stopServer(t, cancel, errCh); err != nil {
			t.Fatalf("Server returned %v", err)
		}
	}()

	base := "http://" + addr
	client := &http.Client{Timeout: 15 * time.Second}
	runner, jobID, leaseToken, leaseGeneration := leaseArtifactJob(t, client, base, "tok")

	req, err := http.NewRequest(http.MethodPut, base+"/api/v1/jobs/"+jobID+"/artifacts/bin", io.NopCloser(&stallAfterFirstRead{}))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("X-Kiwi-Runner-ID", runner.ID)
	req.Header.Set("X-Kiwi-Lease-Token", leaseToken)
	req.Header.Set("X-Kiwi-Lease-Generation", strconv.FormatInt(leaseGeneration, 10))
	req.Header.Set("Content-Type", "application/gzip")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err == nil {
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode == http.StatusCreated {
			t.Fatalf("stalled upload was accepted: %d", resp.StatusCode)
		}
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("stalled upload survived the idle bound: %v elapsed", elapsed)
	}
}

// TestStreamingContinuousUploadOutlivesIdleWindows proves the bound is
// sliding, not absolute: a trickle whose every gap is below the idle bound
// keeps resetting it, so the transfer completes even though its total
// duration exceeds both the ordinary API deadlines and several idle windows.
func TestStreamingContinuousUploadOutlivesIdleWindows(t *testing.T) {
	prevRead, prevWrite, prevIdle := apiReadDeadline, apiWriteDeadline, streamIdleTimeout
	apiReadDeadline, apiWriteDeadline, streamIdleTimeout = 300*time.Millisecond, 300*time.Millisecond, 400*time.Millisecond
	t.Cleanup(func() { apiReadDeadline, apiWriteDeadline, streamIdleTimeout = prevRead, prevWrite, prevIdle })

	ctx, cancel := context.WithCancel(context.Background())
	addr, errCh := startServerEphemeral(t, ctx, "--runner-token", "tok", "--data-dir", t.TempDir())
	defer func() {
		if err := stopServer(t, cancel, errCh); err != nil {
			t.Fatalf("Server returned %v", err)
		}
	}()

	base := "http://" + addr
	client := &http.Client{Timeout: 15 * time.Second}
	runner, jobID, leaseToken, leaseGeneration := leaseArtifactJob(t, client, base, "tok")

	// 12 chunks, one every 120ms: ~1.44s total, three-plus idle windows,
	// with every individual gap well inside one window.
	req, err := http.NewRequest(http.MethodPut, base+"/api/v1/jobs/"+jobID+"/artifacts/bin",
		newTrickleReader(8, 12, 120*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("X-Kiwi-Runner-ID", runner.ID)
	req.Header.Set("X-Kiwi-Lease-Token", leaseToken)
	req.Header.Set("X-Kiwi-Lease-Generation", strconv.FormatInt(leaseGeneration, 10))
	req.Header.Set("Content-Type", "application/gzip")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("continuous slow upload failed at the transport: %v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if elapsed := time.Since(start); elapsed < 800*time.Millisecond {
		t.Fatalf("upload finished in %v; it never streamed past the idle window", elapsed)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("continuous slow upload = %d %s, want 201", resp.StatusCode, body)
	}
}

// deadlineRecordingWriter observes the deadline operations the middleware
// performs on its ResponseWriter. ResponseController discovers the
// Set{Read,Write}Deadline methods directly, so this is the exact seam the
// production net.Conn exposes.
type deadlineRecordingWriter struct {
	http.ResponseWriter
	readClears  int
	writeClears int
	readArms    int
	writeArms   int
	lastRead    time.Time
	lastWrite   time.Time
}

func (d *deadlineRecordingWriter) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		d.readClears++
	} else {
		d.readArms++
		d.lastRead = t
	}
	return nil
}

func (d *deadlineRecordingWriter) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		d.writeClears++
	} else {
		d.writeArms++
		d.lastWrite = t
	}
	return nil
}

func (d *deadlineRecordingWriter) Flush() {}

// TestStreamingBranchClearsInheritedDeadlines pins the exact S1-B fix at the
// middleware seam: on a streaming route both connection deadlines must be
// cleared before dispatch (a reused connection must never run the stream
// under the previous request's deadlines), and the sliding idle bound must
// re-arm the write deadline after a Write and the read deadline after a body
// Read. This fails against the pre-fix middleware, which dispatched the
// stream without touching either deadline.
func TestStreamingBranchClearsInheritedDeadlines(t *testing.T) {
	prevRead, prevWrite, prevIdle := apiReadDeadline, apiWriteDeadline, streamIdleTimeout
	apiReadDeadline, apiWriteDeadline = 5*time.Minute, 5*time.Minute
	streamIdleTimeout = 3 * time.Second
	t.Cleanup(func() { apiReadDeadline, apiWriteDeadline, streamIdleTimeout = prevRead, prevWrite, prevIdle })

	h := withAPIDeadlines(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("answer")); err != nil {
			t.Errorf("stream write: %v", err)
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("stream body read: %v", err)
		}
	}))
	rec := &deadlineRecordingWriter{ResponseWriter: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-1/artifacts/bin", strings.NewReader("chunk"))
	h.ServeHTTP(rec, req)

	if rec.readClears == 0 {
		t.Fatal("streaming branch did not clear the inherited read deadline")
	}
	if rec.writeClears == 0 {
		t.Fatal("streaming branch did not clear the inherited write deadline")
	}
	if rec.readArms == 0 || rec.writeArms == 0 {
		t.Fatalf("streaming branch did not arm the sliding deadlines: read arms=%d write arms=%d", rec.readArms, rec.writeArms)
	}
	if until := time.Until(rec.lastWrite); until <= time.Second || until > 4*time.Second {
		t.Fatalf("write deadline re-armed at %v from now, want ~%v", until, streamIdleTimeout)
	}
	if until := time.Until(rec.lastRead); until <= time.Second || until > 4*time.Second {
		t.Fatalf("read deadline re-armed at %v from now, want ~%v", until, streamIdleTimeout)
	}
}

// jsonString marshals a string as a JSON literal for embedding in a request
// body.
func jsonString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
