package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// idcovCARunnerFixture builds a server with a runner CA and one signed
// runner certificate for runner-a.
func idcovCARunnerFixture(t *testing.T) (*Server, *runnerpki.CA, *x509.Certificate) {
	t.Helper()
	ca, err := runnerpki.NewCA("idcov ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("secret")
	s.RunnerCA = ca
	_, cert := pkiSignRunner(t, ca, "runner-a")
	return s, ca, cert
}

// TestIDCovLoadRunnerCA covers every branch of the data-dir CA loader.
func TestIDCovLoadRunnerCA(t *testing.T) {
	if err := New("t").loadRunnerCA(""); err != nil {
		t.Fatalf("loadRunnerCA(\"\") = %v", err)
	}
	// No files at all: mTLS stays disabled.
	empty := t.TempDir()
	s := New("t")
	if err := s.loadRunnerCA(empty); err != nil || s.RunnerCA != nil {
		t.Fatalf("loadRunnerCA(empty) = %v (ca=%v)", err, s.RunnerCA)
	}
	// Only the certificate: still disabled.
	half := t.TempDir()
	writeTestFile(t, filepath.Join(half, "ca.crt"), []byte("cert"))
	s2 := New("t")
	if err := s2.loadRunnerCA(half); err != nil || s2.RunnerCA != nil {
		t.Fatalf("loadRunnerCA(half) = %v (ca=%v)", err, s2.RunnerCA)
	}
	// Only the key: still disabled.
	half2 := t.TempDir()
	writeTestFile(t, filepath.Join(half2, "ca.key"), []byte("key"))
	s3 := New("t")
	if err := s3.loadRunnerCA(half2); err != nil || s3.RunnerCA != nil {
		t.Fatalf("loadRunnerCA(key-only) = %v (ca=%v)", err, s3.RunnerCA)
	}
	// Unreadable certificate (a directory) is a hard error.
	dirCert := t.TempDir()
	if err := os.Mkdir(filepath.Join(dirCert, "ca.crt"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := New("t").loadRunnerCA(dirCert); err == nil {
		t.Fatal("loadRunnerCA(dir cert) = nil error")
	}
	// Unreadable key (a directory) is a hard error.
	dirKey := t.TempDir()
	writeTestFile(t, filepath.Join(dirKey, "ca.crt"), []byte("cert"))
	if err := os.Mkdir(filepath.Join(dirKey, "ca.key"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := New("t").loadRunnerCA(dirKey); err == nil {
		t.Fatal("loadRunnerCA(dir key) = nil error")
	}
	// Invalid material is a hard error.
	bad := t.TempDir()
	writeTestFile(t, filepath.Join(bad, "ca.crt"), []byte("junk"))
	writeTestFile(t, filepath.Join(bad, "ca.key"), []byte("junk"))
	if err := New("t").loadRunnerCA(bad); err == nil || !strings.Contains(err.Error(), "load runner CA") {
		t.Fatalf("loadRunnerCA(invalid) = %v", err)
	}
	// A valid persisted pair installs the CA.
	ca, err := runnerpki.NewCA("persisted", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	good := t.TempDir()
	certPEM, keyPEM, err := caPEMsForTest(ca)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(good, "ca.crt"), certPEM)
	writeTestFile(t, filepath.Join(good, "ca.key"), keyPEM)
	s4 := New("t")
	if err := s4.loadRunnerCA(good); err != nil || s4.RunnerCA == nil {
		t.Fatalf("loadRunnerCA(valid) = %v (ca=%v)", err, s4.RunnerCA)
	}
}

// TestIDCovEnsureRunnerCA covers the already-installed fast path, the
// missing-store refusal, store failures and bad stored objects.
func TestIDCovEnsureRunnerCA(t *testing.T) {
	s, _, _ := idcovCARunnerFixture(t)
	if err := s.EnsureRunnerCA(); err != nil {
		t.Fatalf("EnsureRunnerCA with CA installed = %v", err)
	}
	bare := New("t")
	if err := bare.EnsureRunnerCA(); err == nil {
		t.Fatal("EnsureRunnerCA without a cluster store = nil error")
	}
	// The cluster store is created when absent, then loaded.
	dir := t.TempDir()
	create := New("t")
	create.ClusterKeys = &FSClusterKeyStore{Dir: dir}
	if err := create.EnsureRunnerCA(); err != nil || create.RunnerCA == nil {
		t.Fatalf("EnsureRunnerCA create = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, runnerCAObjectFile)); err != nil {
		t.Fatalf("runner CA object not persisted: %v", err)
	}
	// LoadOrCreate errors and unparsable stored objects propagate.
	fail := New("t")
	fail.ClusterKeys = failingClusterStore{err: errIDCovBoom}
	if err := fail.EnsureRunnerCA(); err == nil {
		t.Fatal("EnsureRunnerCA store failure = nil error")
	}
	bad := New("t")
	bad.ClusterKeys = fixedClusterStore{b: []byte("garbage")}
	if err := bad.EnsureRunnerCA(); err == nil {
		t.Fatal("EnsureRunnerCA garbage blob = nil error")
	}
}

// TestIDCovSetRunnerCA covers explicit PEM path loading.
func TestIDCovSetRunnerCA(t *testing.T) {
	ca, err := runnerpki.NewCA("explicit", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := caPEMsForTest(ca)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	writeTestFile(t, certPath, certPEM)
	writeTestFile(t, keyPath, keyPEM)

	s := New("t")
	if err := s.SetRunnerCA(certPath, keyPath); err != nil || s.RunnerCA == nil {
		t.Fatalf("SetRunnerCA(valid) = %v", err)
	}
	if err := New("t").SetRunnerCA(filepath.Join(dir, "missing.crt"), keyPath); err == nil || !strings.Contains(err.Error(), "read runner CA certificate") {
		t.Fatalf("missing certificate error = %v", err)
	}
	if err := New("t").SetRunnerCA(certPath, filepath.Join(dir, "missing.key")); err == nil || !strings.Contains(err.Error(), "read runner CA key") {
		t.Fatalf("missing key error = %v", err)
	}
	badCert := filepath.Join(dir, "bad.crt")
	writeTestFile(t, badCert, []byte("junk"))
	if err := New("t").SetRunnerCA(badCert, keyPath); err == nil {
		t.Fatal("invalid pair = nil error")
	}
}

// TestIDCovEnrollHandlerBranches drives enroll() directly for its
// pre-signature failures.
func TestIDCovEnrollHandlerBranches(t *testing.T) {
	// No CA configured.
	s := New("t")
	s.RunnerEnrollToken = "enroll"
	w := httptest.NewRecorder()
	s.enroll(w, httptest.NewRequest(http.MethodPost, "/api/v1/runners/enroll", strings.NewReader("{}")))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("enroll without CA = %d, want 503", w.Code)
	}

	// With a CA: malformed JSON, missing runner id and out-of-range id.
	ca, err := runnerpki.NewCA("enroll ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s2 := New("t")
	s2.RunnerCA = ca
	s2.RunnerEnrollToken = "enroll"
	cases := []struct {
		name string
		body string
		want int
	}{
		{"bad json", `{`, http.StatusBadRequest},
		{"missing id", `{"csr":"x"}`, http.StatusBadRequest},
		{"oversized id", `{"runner_id":"` + strings.Repeat("r", maxRunnerIDLen+1) + `","csr":"x"}`, http.StatusBadRequest},
		{"control-char id", `{"runner_id":"bad\nid","csr":"x"}`, http.StatusBadRequest},
		{"bad csr base64", `{"runner_id":"r1","csr":"!!!"}`, http.StatusBadRequest},
		{"empty csr", `{"runner_id":"r1","csr":""}`, http.StatusBadRequest},
		{"oversized csr", `{"runner_id":"r1","csr":"` + strings.Repeat("A", 90<<10) + `"}`, http.StatusBadRequest},
		{"non-csr pem", `{"runner_id":"r1","csr":"` + base64Std("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n") + `"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/v1/runners/enroll", strings.NewReader(tc.body))
			r.Header.Set("Authorization", "Bearer enroll")
			s2.enroll(w, r)
			if w.Code != tc.want {
				t.Fatalf("enroll = %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}

	// A valid enroll request succeeds and returns the signed certificate.
	_, csrPEM, err := runnerpki.GenerateKeyAndCSR("r1")
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/runners/enroll", strings.NewReader(`{"runner_id":"r1","csr":"`+base64Std(string(csrPEM))+`"}`))
	r.Header.Set("Authorization", "Bearer enroll")
	s2.enroll(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("valid enroll = %d: %s", w.Code, w.Body.String())
	}
}

// TestIDCovValidRunnerID pins the identity-safety predicate.
func TestIDCovValidRunnerID(t *testing.T) {
	valid := []string{"runner-1", "rÜnner", "名前", "a b"}
	for _, id := range valid {
		if !validRunnerID(id) {
			t.Errorf("validRunnerID(%q) = false", id)
		}
	}
	invalid := []string{"null\x00byte", "line\nbreak", "tab\there", "\x7f", "\x01", string([]byte{0xff, 0xfe})}
	for _, id := range invalid {
		if validRunnerID(id) {
			t.Errorf("validRunnerID(%q) = true", id)
		}
	}
	// Direct sanity: invalid UTF-8 is rejected even without control runes.
	if validRunnerID(string([]byte{0xc3, 0x28})) {
		t.Fatal("invalid UTF-8 accepted")
	}
	if utf8.ValidString(string([]byte{0xc3, 0x28})) {
		t.Fatal("test fixture is unexpectedly valid UTF-8")
	}
}

// TestIDCovPeerRunnerID covers the CA/TLS preconditions.
func TestIDCovPeerRunnerID(t *testing.T) {
	if _, err := New("t").peerRunnerID(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Fatal("peerRunnerID without CA = nil error")
	}
	s, _, cert := idcovCARunnerFixture(t)
	if _, err := s.peerRunnerID(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Fatal("peerRunnerID without peer cert = nil error")
	}
	id, err := s.peerRunnerID(crlRequestWithCert(t, cert))
	if err != nil || id != "runner-a" {
		t.Fatalf("peerRunnerID = %q, %v", id, err)
	}
}

// TestIDCovResolveRunnerIdentityBranches walks the identity-resolution
// matrix that registration and every runner route share.
func TestIDCovResolveRunnerIdentityBranches(t *testing.T) {
	s, _, certA := idcovCARunnerFixture(t)
	_, certB := pkiSignRunner(t, s.RunnerCA, "runner-b")

	// mTLS-required mode: a bearer that disagrees with the certificate is
	// refused before any claimed-id comparison.
	s.RequireRunnerClientCerts = true
	s.LoadRunnerTokens(map[string]string{"runner-b": auth.TokenDigest("tok-b")})
	bearerB := httptest.NewRequest(http.MethodPost, "/", nil)
	bearerB.Header.Set("Authorization", "Bearer tok-b")
	bearerB.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certA}}
	if _, _, err := s.resolveRunnerIdentity(bearerB, ""); err == nil {
		t.Fatal("bearer/certificate mismatch accepted in mTLS mode")
	}
	// Certificate identity disagreeing with the claimed id.
	if _, _, err := s.resolveRunnerIdentity(crlRequestWithCert(t, certA), "runner-b"); err == nil {
		t.Fatal("claimed id mismatch accepted in mTLS mode")
	}
	// Matching certificate and claimed id resolve.
	id, constrained, err := s.resolveRunnerIdentity(crlRequestWithCert(t, certA), "runner-a")
	if err != nil || !constrained || id != "runner-a" {
		t.Fatalf("mTLS resolve = %q %v %v", id, constrained, err)
	}
	// Missing peer certificate in mTLS mode.
	if _, _, err := s.resolveRunnerIdentity(httptest.NewRequest(http.MethodPost, "/", nil), ""); err == nil {
		t.Fatal("missing peer cert accepted in mTLS mode")
	}

	// Optional-certificate mode: bearer + peer present.
	s.RequireRunnerClientCerts = false
	// An unknown bearer is not a per-runner credential: the peer
	// certificate is the identity.
	bearerA := httptest.NewRequest(http.MethodPost, "/", nil)
	bearerA.Header.Set("Authorization", "Bearer tok-a")
	bearerA.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certA}}
	if id, _, err := s.resolveRunnerIdentity(bearerA, ""); err != nil || id != "runner-a" {
		t.Fatalf("unknown bearer + peer = %q, %v", id, err)
	}
	// Known bearer agreeing with the certificate.
	s.LoadRunnerTokens(map[string]string{"runner-a": auth.TokenDigest("tok-a")})
	id, constrained, err = s.resolveRunnerIdentity(bearerA, "runner-a")
	if err != nil || !constrained || id != "runner-a" {
		t.Fatalf("bearer+cert resolve = %q %v %v", id, constrained, err)
	}
	// Known bearer disagreeing with the certificate.
	bearerB.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certA}}
	if _, _, err := s.resolveRunnerIdentity(bearerB, ""); err == nil {
		t.Fatal("bearer/certificate mismatch accepted")
	}
	// Known bearer agreeing with the certificate but not the claimed id.
	bearerA.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certA}}
	if _, _, err := s.resolveRunnerIdentity(bearerA, "runner-b"); err == nil {
		t.Fatal("claimed id mismatch accepted (bearer+peer)")
	}
	// Bare bearer without a peer certificate: the identity is the bearer.
	plainBearer := httptest.NewRequest(http.MethodPost, "/", nil)
	plainBearer.Header.Set("Authorization", "Bearer tok-a")
	id, constrained, err = s.resolveRunnerIdentity(plainBearer, "runner-a")
	if err != nil || !constrained || id != "runner-a" {
		t.Fatalf("bearer-only resolve = %q %v %v", id, constrained, err)
	}
	if _, _, err := s.resolveRunnerIdentity(plainBearer, "runner-b"); err == nil {
		t.Fatal("bearer/claimed mismatch accepted")
	}
	// Peer certificate only (no bearer): the certificate is the identity.
	id, constrained, err = s.resolveRunnerIdentity(crlRequestWithCert(t, certB), "runner-b")
	if err != nil || !constrained || id != "runner-b" {
		t.Fatalf("peer-only resolve = %q %v %v", id, constrained, err)
	}
	if _, _, err := s.resolveRunnerIdentity(crlRequestWithCert(t, certB), "runner-a"); err == nil {
		t.Fatal("peer/claimed mismatch accepted")
	}
	// Neither credential in optional mode: refused.
	if _, _, err := s.resolveRunnerIdentity(httptest.NewRequest(http.MethodPost, "/", nil), ""); err == nil {
		t.Fatal("no credential accepted with a runner CA configured")
	}

	// No CA at all: the legacy shared bearer identity is unconstrained.
	legacy := New("t")
	id, constrained, err = legacy.resolveRunnerIdentity(httptest.NewRequest(http.MethodPost, "/", nil), "")
	if err != nil || constrained || id != "" {
		t.Fatalf("legacy resolve = %q %v %v", id, constrained, err)
	}
	legacyBearer := httptest.NewRequest(http.MethodPost, "/", nil)
	legacy.LoadRunnerTokens(map[string]string{"runner-a": auth.TokenDigest("tok-a")})
	legacyBearer.Header.Set("Authorization", "Bearer tok-a")
	if _, _, err := legacy.resolveRunnerIdentity(legacyBearer, "runner-b"); err == nil {
		t.Fatal("legacy bearer/claimed mismatch accepted")
	}
	// verifyRunnerIdentity propagates the resolution error as false.
	if legacy.verifyRunnerIdentity(legacyBearer, "runner-b") {
		t.Fatal("verifyRunnerIdentity accepted a mismatched bearer")
	}
}

// TestIDCovResolveRegistrationProfileBinding covers the mTLS, per-runner
// bearer and legacy branches of the ONLY registration profile-key chooser.
// The security-critical properties: only a peer certificate that VERIFIED
// against the runner CA contributes a serial, and a per-runner bearer
// identity never contributes a client-asserted serial.
func TestIDCovResolveRegistrationProfileBinding(t *testing.T) {
	s, _, certA := idcovCARunnerFixture(t)
	if got := s.resolveRegistrationProfileBinding(crlRequestWithCert(t, certA), "runner-a", "payload-serial"); got.Serial != certA.SerialNumber.Text(16) || got.RunnerID != "" {
		t.Fatalf("verified peer binding = %+v", got)
	}
	if got := s.resolveRegistrationProfileBinding(httptest.NewRequest(http.MethodPost, "/", nil), "runner-a", "payload-serial"); got.Serial != "" || got.RunnerID != "" {
		t.Fatalf("no peer cert binding = %+v, want empty", got)
	}
	// A certificate that does NOT chain to the runner CA must not select a
	// serial binding, even though it is presented.
	otherCA, err := runnerpki.NewCA("unrelated ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, foreign := pkiSignRunner(t, otherCA, "runner-a")
	if got := s.resolveRegistrationProfileBinding(crlRequestWithCert(t, foreign), "runner-a", "payload-serial"); got.Serial != "" || got.RunnerID != "" {
		t.Fatalf("unverified peer certificate selected a binding: %+v", got)
	}

	// Per-runner bearer: the authenticated runner ID is the key and the
	// client-asserted payload serial is NEVER consulted.
	bare := New("t")
	bare.LoadRunnerTokens(map[string]string{"runner-a": auth.TokenDigest("tok-a")})
	bearer := httptest.NewRequest(http.MethodPost, "/", nil)
	bearer.Header.Set("Authorization", "Bearer tok-a")
	for _, payload := range []string{"  ", "serial-1", "serial-owned", "serial-mine"} {
		got := bare.resolveRegistrationProfileBinding(bearer, "runner-a", payload)
		if got.RunnerID != "runner-a" || got.Serial != "" {
			t.Fatalf("bearer payload %q binding = %+v, want runner-id only", payload, got)
		}
	}

	// Legacy shared-token mode (no CA, no per-runner token): the payload
	// serial stays the dev binding key, and another runner's recorded
	// serial is refused.
	plain := New("t")
	if got := plain.resolveRegistrationProfileBinding(httptest.NewRequest(http.MethodPost, "/", nil), "runner-a", "  "); got.Serial != "" {
		t.Fatalf("blank payload serial = %+v", got)
	}
	if got := plain.resolveRegistrationProfileBinding(httptest.NewRequest(http.MethodPost, "/", nil), "runner-a", "serial-1"); got.Serial != "serial-1" || got.RunnerID != "" {
		t.Fatalf("unowned legacy payload serial = %+v", got)
	}
	plain.mu.Lock()
	plain.runners["runner-b"] = model.Runner{ID: "runner-b", CertSerial: "serial-owned"}
	plain.runners["runner-a"] = model.Runner{ID: "runner-a", CertSerial: "serial-mine"}
	plain.mu.Unlock()
	if got := plain.resolveRegistrationProfileBinding(httptest.NewRequest(http.MethodPost, "/", nil), "runner-a", "serial-owned"); got.Serial != "" {
		t.Fatalf("serial owned by another runner accepted: %+v", got)
	}
	if got := plain.resolveRegistrationProfileBinding(httptest.NewRequest(http.MethodPost, "/", nil), "runner-a", "serial-mine"); got.Serial != "serial-mine" {
		t.Fatalf("own legacy serial refused: %+v", got)
	}
}

// TestIDCovSerialClaimedByOther covers the empty-serial fast path, the
// memory scan and the DB scan.
func TestIDCovSerialClaimedByOther(t *testing.T) {
	s := New("t")
	if claimed, err := s.serialClaimedByOther(context.Background(), "", "runner-a"); claimed || err != nil {
		t.Fatalf("empty serial = %v %v", claimed, err)
	}
	s.mu.Lock()
	s.runners["runner-b"] = model.Runner{ID: "runner-b", CertSerial: " serial-b "}
	s.mu.Unlock()
	if claimed, err := s.serialClaimedByOther(context.Background(), "serial-b", "runner-a"); err != nil || !claimed {
		t.Fatalf("other-owned serial = %v %v", claimed, err)
	}
	if claimed, err := s.serialClaimedByOther(context.Background(), "serial-b", "runner-b"); err != nil || claimed {
		t.Fatalf("self-owned serial = %v %v", claimed, err)
	}

	// DB mode scans the store and fails closed on a store error.
	f := newDBFakeStore()
	f.runners["runner-b"] = model.Runner{ID: "runner-b", CertSerial: "serial-db"}
	s2 := New("t")
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if claimed, err := s2.serialClaimedByOther(context.Background(), "serial-db", "runner-a"); err != nil || !claimed {
		t.Fatalf("db other-owned serial = %v %v", claimed, err)
	}
	if claimed, err := s2.serialClaimedByOther(context.Background(), "serial-db", "runner-b"); err != nil || claimed {
		t.Fatalf("db self-owned serial = %v %v", claimed, err)
	}
	fault := &idcovListErrStore{dbFakeStore: f}
	s3 := New("t")
	if err := s3.SwitchToDB(fault); err != nil {
		t.Fatal(err)
	}
	if claimed, err := s3.serialClaimedByOther(context.Background(), "serial-db", "runner-a"); !claimed || err == nil {
		t.Fatalf("db error must fail closed: %v %v", claimed, err)
	}
}

// idcovListErrStore fails every runner listing.
type idcovListErrStore struct {
	*dbFakeStore
}

func (idcovListErrStore) ListRunners(ctx context.Context) ([]model.Runner, error) {
	return nil, errIDCovBoom
}

// TestIDCovCheckPeerCertRevoked covers the no-peer fast path and the
// revocation rejection.
func TestIDCovCheckPeerCertRevoked(t *testing.T) {
	s := New("t")
	if err := s.checkPeerCertRevoked(httptest.NewRequest(http.MethodPost, "/", nil)); err != nil {
		t.Fatalf("no peer cert = %v", err)
	}
	_, _, certA := idcovCARunnerFixture(t)
	s.mu.Lock()
	s.crl[certA.SerialNumber.Text(16)] = "runner-a"
	s.mu.Unlock()
	if err := s.checkPeerCertRevoked(crlRequestWithCert(t, certA)); err == nil {
		t.Fatal("revoked peer cert accepted")
	}
	// A nil first peer certificate is tolerated.
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{nil}}
	if err := s.checkPeerCertRevoked(req); err != nil {
		t.Fatalf("nil peer cert = %v", err)
	}
}

// TestIDCovRunnerIdentityThroughHandler drives registration with per-runner
// bearer credentials so the mTLS binding path runs end to end.
func TestIDCovRunnerIdentityThroughHandler(t *testing.T) {
	s, _, _ := idcovCARunnerFixture(t)
	_, certB := pkiSignRunner(t, s.RunnerCA, "runner-b")
	s.RequireRunnerClientCerts = false
	s.LoadRunnerTokens(map[string]string{"runner-a": auth.TokenDigest("tok-a")})
	h := s.Handler()

	body := map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "protocol_min": 3, "protocol_max": 3}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register", body, "tok-a", nil); w.Code != http.StatusOK {
		t.Fatalf("per-runner bearer register = %d: %s", w.Code, w.Body.String())
	}
	// A mismatched certificate on the same bearer is refused.
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register", body, "tok-a", certB); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("mismatched cert register = %d", w.Code)
	}
}

// errIDCovBoom is a sentinel store failure.
var errIDCovBoom = errors.New("idcov boom")

// base64Std encodes a string with standard base64 padding.
func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
