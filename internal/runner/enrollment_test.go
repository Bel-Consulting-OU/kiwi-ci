package runner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// caCertPEM encodes a CA certificate as PEM.
func caCertPEM(t *testing.T, ca *runnerpki.CA) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

// caSignedServerCert mints a TLS server certificate (localhost/127.0.0.1,
// ServerAuth) signed by the runner CA so a runner that trusts only the
// runner CA can verify the test listener.
func caSignedServerCert(t *testing.T, ca *runnerpki.CA) (certPEM, keyPEM []byte) {
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// signIdentity mints a client certificate for id signed by ca, with the
// validity window shifted by offset (negative offsets yield expired
// certificates).
func signIdentity(t *testing.T, ca *runnerpki.CA, id string, validity, offset time.Duration) (keyPEM, certPEM []byte) {
	t.Helper()
	keyPEM, csrPEM, err := runnerpki.GenerateKeyAndCSR(id)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(offset)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: id},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return keyPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// enrollCountingServer serves a real control plane with runner mTLS
// enabled, counting enroll requests and capturing the last enroll body.
func enrollCountingServer(t *testing.T) (ca *runnerpki.CA, ts *httptest.Server, enrollCalls *atomic.Int32, lastEnrollBody func() []byte) {
	t.Helper()
	ca, err := runnerpki.NewCA("test runner ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New("runner-token")
	srv.RunnerCA = ca
	srv.RunnerEnrollToken = "enroll-secret"
	var mu sync.Mutex
	var body []byte
	calls := &atomic.Int32{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/runners/enroll" {
			calls.Add(1)
			b, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(b))
			mu.Lock()
			body = append(body[:0], b...)
			mu.Unlock()
		}
		srv.Handler().ServeHTTP(w, r)
	})
	serverCertPEM, serverKeyPEM := caSignedServerCert(t, ca)
	ts = httptest.NewUnstartedServer(h)
	serverTLS, err := runnerpki.TLSServerConfig(serverCertPEM, serverKeyPEM, ca, false)
	if err != nil {
		t.Fatal(err)
	}
	ts.TLS = serverTLS
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ca, ts, calls, func() []byte {
		mu.Lock()
		defer mu.Unlock()
		return append([]byte(nil), body...)
	}
}

// TestEnrollmentReusesPersistedIdentity persists a valid identity and
// verifies the runner reuses it without calling the enroll endpoint, and
// that the reused certificate authenticates register/next.
func TestEnrollmentReusesPersistedIdentity(t *testing.T) {
	ca, ts, enrollCalls, _ := enrollCountingServer(t)
	dir := t.TempDir()
	keyPEM, certPEM := signIdentity(t, ca, "runner-stable", 365*24*time.Hour, 0)
	store := IdentityStore{Dir: dir}
	if err := store.Save(Identity{ID: "runner-stable", KeyPEM: keyPEM, CertPEM: certPEM, CACertPEM: caCertPEM(t, ca)}); err != nil {
		t.Fatal(err)
	}

	r := &Runner{Cfg: Config{Server: ts.URL, Token: "runner-token", EnrollToken: "enroll-secret", IdentityDir: dir}}
	if err := r.prepareClient(context.Background()); err != nil {
		t.Fatalf("prepareClient: %v", err)
	}
	if got := enrollCalls.Load(); got != 0 {
		t.Fatalf("enroll endpoint called %d times despite a valid persisted certificate", got)
	}
	if r.ID != "runner-stable" {
		t.Fatalf("runner ID = %q, want persisted runner-stable", r.ID)
	}
	if r.Client == nil {
		t.Fatal("mTLS client not built")
	}
	r.Client = server.NoRedirectClient(r.Client)
	if err := r.register(context.Background()); err != nil {
		t.Fatalf("register with persisted identity: %v", err)
	}
	if _, _, err := r.next(context.Background()); err != nil {
		t.Fatalf("next with persisted identity: %v", err)
	}
	id, ok := store.Load()
	if !ok || string(id.CertPEM) != string(certPEM) {
		t.Fatal("persisted identity must be untouched when reused")
	}
}

// TestEnrollmentRenewKeepsStableID persists an identity with an expired
// certificate and verifies the runner re-enrolls exactly once, sends the
// persisted runner ID in the CSR/enroll request, and replaces the persisted
// material with the fresh certificate under the SAME runner ID.
func TestEnrollmentRenewKeepsStableID(t *testing.T) {
	ca, ts, enrollCalls, lastEnrollBody := enrollCountingServer(t)
	dir := t.TempDir()
	oldKey, expiredCert := signIdentity(t, ca, "runner-stable", time.Hour, -30*24*time.Hour)
	store := IdentityStore{Dir: dir}
	if err := store.Save(Identity{ID: "runner-stable", KeyPEM: oldKey, CertPEM: expiredCert, CACertPEM: caCertPEM(t, ca)}); err != nil {
		t.Fatal(err)
	}

	r := &Runner{Cfg: Config{Server: ts.URL, Token: "runner-token", EnrollToken: "enroll-secret", CACert: string(caCertPEM(t, ca)), IdentityDir: dir}}
	if err := r.prepareClient(context.Background()); err != nil {
		t.Fatalf("prepareClient: %v", err)
	}
	if got := enrollCalls.Load(); got != 1 {
		t.Fatalf("enroll calls = %d, want exactly 1", got)
	}
	if r.ID != "runner-stable" {
		t.Fatalf("runner ID = %q, want the persisted stable ID", r.ID)
	}
	var req server.EnrollRequest
	if err := json.Unmarshal(lastEnrollBody(), &req); err != nil {
		t.Fatalf("enroll body: %v", err)
	}
	if req.RunnerID != "runner-stable" {
		t.Fatalf("enroll request runner_id = %q, want persisted runner-stable", req.RunnerID)
	}

	id, ok := store.Load()
	if !ok {
		t.Fatal("re-enrolled identity not persisted")
	}
	if id.ID != "runner-stable" {
		t.Fatalf("persisted ID changed to %q", id.ID)
	}
	if !id.CertUsable() {
		t.Fatal("persisted certificate must be fresh after re-enrollment")
	}
	if string(id.KeyPEM) == string(oldKey) {
		t.Fatal("persisted key must be regenerated on re-enrollment")
	}
	if string(id.CertPEM) == string(expiredCert) {
		t.Fatal("persisted certificate must be replaced on re-enrollment")
	}

	r.Client = server.NoRedirectClient(r.Client)
	if err := r.register(context.Background()); err != nil {
		t.Fatalf("register after re-enrollment: %v", err)
	}
	if _, _, err := r.next(context.Background()); err != nil {
		t.Fatalf("next after re-enrollment: %v", err)
	}
}

// TestEnrollmentPersistsAuthoritativeRunnerID drives enrollment against a
// control plane that issues a certificate under a DIFFERENT runner ID than
// the client proposed: the server-synthesized runner_id from the enroll
// response must be persisted and used for registration. It also pins the
// enroll wire format: Authorization Bearer grant value and the configured
// labels.
func TestEnrollmentPersistsAuthoritativeRunnerID(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	const authoritativeID = "authoritative-runner-7"
	var mu sync.Mutex
	var enrollAuth, enrollRunnerID string
	var enrollLabels []string
	var registerID string
	var registerPeerOK bool

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/runners/enroll":
			mu.Lock()
			enrollAuth = r.Header.Get("Authorization")
			var in server.EnrollRequest
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				mu.Unlock()
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			enrollRunnerID = in.RunnerID
			enrollLabels = append([]string(nil), in.Labels...)
			mu.Unlock()
			csrPEM, err := base64.StdEncoding.DecodeString(in.CSR)
			if err != nil {
				http.Error(w, "bad csr", http.StatusBadRequest)
				return
			}
			certPEM, err := ca.SignRunnerCSR(csrPEM, authoritativeID, 365*24*time.Hour, nil)
			if err != nil {
				http.Error(w, "csr rejected", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(server.EnrollResponse{
				RunnerID:      authoritativeID,
				Certificate:   string(certPEM),
				CACertificate: string(caCertPEM(t, ca)),
				TTLSeconds:    365 * 24 * 3600,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/runners/register":
			var in map[string]any
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			mu.Lock()
			registerID, _ = in["id"].(string)
			mu.Unlock()
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "certificate required", http.StatusForbidden)
				return
			}
			pid, err := ca.VerifyPeer(r.TLS.PeerCertificates[0], runnerpki.Pool(caCertPEM(t, ca)))
			mu.Lock()
			registerPeerOK = err == nil && pid == authoritativeID
			mu.Unlock()
			if !registerPeerOK {
				http.Error(w, "identity mismatch", http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"` + authoritativeID + `","name":"r","capacity":1}`))
		default:
			http.NotFound(w, r)
		}
	})
	serverCertPEM, serverKeyPEM := caSignedServerCert(t, ca)
	ts := httptest.NewUnstartedServer(h)
	serverTLS, err := runnerpki.TLSServerConfig(serverCertPEM, serverKeyPEM, ca, false)
	if err != nil {
		t.Fatal(err)
	}
	ts.TLS = serverTLS
	ts.StartTLS()
	defer ts.Close()

	dir := t.TempDir()
	r := &Runner{Cfg: Config{
		Server:       ts.URL,
		Token:        "runner-token",
		EnrollToken:  "grant-value",
		EnrollLabels: []string{"dc:east", "pool:default"},
		CACert:       string(caCertPEM(t, ca)),
		IdentityDir:  dir,
	}, ID: "proposed-id"}
	if err := r.prepareClient(context.Background()); err != nil {
		t.Fatalf("prepareClient: %v", err)
	}
	if r.ID != authoritativeID {
		t.Fatalf("runner ID = %q, want server-authoritative %q", r.ID, authoritativeID)
	}
	store := IdentityStore{Dir: dir}
	id, ok := store.Load()
	if !ok {
		t.Fatal("enrolled identity not persisted")
	}
	if id.ID != authoritativeID {
		t.Fatalf("persisted ID = %q, want %q", id.ID, authoritativeID)
	}
	if !id.CertUsable() {
		t.Fatal("persisted certificate must be usable")
	}
	wantCA, err := runnerpki.ParseCertPEM(caCertPEM(t, ca))
	if err != nil {
		t.Fatal(err)
	}
	gotCA, err := runnerpki.ParseCertPEM(id.CACertPEM)
	if err != nil || !bytes.Equal(gotCA.Raw, wantCA.Raw) {
		t.Fatal("persisted CA must be the enroll-response CA certificate")
	}

	mu.Lock()
	if enrollAuth != "Bearer grant-value" {
		t.Errorf("enroll Authorization = %q, want Bearer grant-value", enrollAuth)
	}
	if enrollRunnerID != "proposed-id" {
		t.Errorf("enroll request runner_id = %q, want the client proposal proposed-id", enrollRunnerID)
	}
	if len(enrollLabels) != 2 || enrollLabels[0] != "dc:east" || enrollLabels[1] != "pool:default" {
		t.Errorf("enroll labels = %v, want [dc:east pool:default]", enrollLabels)
	}
	mu.Unlock()

	r.Client = server.NoRedirectClient(r.Client)
	if err := r.register(context.Background()); err != nil {
		t.Fatalf("register: %v", err)
	}
	mu.Lock()
	if registerID != authoritativeID {
		t.Errorf("register payload id = %q, want %q", registerID, authoritativeID)
	}
	if !registerPeerOK {
		t.Error("register peer certificate not bound to the authoritative ID")
	}
	mu.Unlock()
}
