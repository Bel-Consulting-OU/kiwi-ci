package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// pkiRequest serves one request against the handler, optionally carrying a
// TLS peer certificate so handlers that bind runner identity can be tested
// without a live TLS listener.
func pkiRequest(t *testing.T, h http.Handler, method, path string, body any, token string, peer *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	if peer != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func pkiParseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no certificate PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func pkiSignRunner(t *testing.T, ca *runnerpki.CA, runnerID string) (certPEM []byte, cert *x509.Certificate) {
	t.Helper()
	_, csrPEM, err := runnerpki.GenerateKeyAndCSR(runnerID)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err = ca.SignRunnerCSR(csrPEM, runnerID, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, pkiParseCert(t, certPEM)
}

func TestEnrollEndpoint(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("runner-token")
	s.RunnerCA = ca
	s.RunnerEnrollToken = "enroll-secret"
	h := s.Handler()

	keyPEM, csrPEM, err := runnerpki.GenerateKeyAndCSR("runner-42")
	if err != nil {
		t.Fatal(err)
	}
	body := EnrollRequest{RunnerID: "runner-42", CSR: base64.StdEncoding.EncodeToString(csrPEM)}

	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", body, "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("enroll without token: %d", w.Code)
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", body, "wrong-token", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("enroll with wrong token: %d", w.Code)
	}
	w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", body, "enroll-secret", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", w.Code, w.Body.String())
	}
	var out EnrollResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.TTLSeconds <= 0 {
		t.Fatalf("TTLSeconds = %d", out.TTLSeconds)
	}
	cert := pkiParseCert(t, []byte(out.Certificate))
	if cert.Subject.CommonName != "runner-42" {
		t.Fatalf("cert CN = %q, want runner-42", cert.Subject.CommonName)
	}
	if _, err := tls.X509KeyPair([]byte(out.Certificate), keyPEM); err != nil {
		t.Fatalf("issued cert does not match enrollment key: %v", err)
	}
	id, err := ca.VerifyPeer(cert, runnerpki.Pool([]byte(out.CACertificate)))
	if err != nil {
		t.Fatalf("issued cert rejected by CA: %v", err)
	}
	if id != "runner-42" {
		t.Fatalf("VerifyPeer runner id = %q", id)
	}
}

func TestEnrollRejectsIdentityMismatch(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("runner-token")
	s.RunnerCA = ca
	s.RunnerEnrollToken = "enroll-secret"
	_, csrPEM, err := runnerpki.GenerateKeyAndCSR("runner-43")
	if err != nil {
		t.Fatal(err)
	}
	body := EnrollRequest{RunnerID: "runner-42", CSR: base64.StdEncoding.EncodeToString(csrPEM)}
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/enroll", body, "enroll-secret", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("CN mismatch: %d %s", w.Code, w.Body.String())
	}
}

func TestEnrollDisabledWithoutCA(t *testing.T) {
	s := New("runner-token")
	s.RunnerEnrollToken = "enroll-secret"
	_, csrPEM, err := runnerpki.GenerateKeyAndCSR("runner-1")
	if err != nil {
		t.Fatal(err)
	}
	body := EnrollRequest{RunnerID: "runner-1", CSR: base64.StdEncoding.EncodeToString(csrPEM)}
	if w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/enroll", body, "enroll-secret", nil); w.Code != http.StatusNotFound {
		t.Fatalf("enroll without CA: %d", w.Code)
	}
}

func TestRegisterProtocolNegotiation(t *testing.T) {
	s := New("secret")
	h := s.Handler()
	register := func(body map[string]any) *httptest.ResponseRecorder {
		return pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register", body, "secret", nil)
	}
	if w := register(map[string]any{"name": "r1"}); w.Code != http.StatusBadRequest {
		t.Fatalf("missing protocol: %d", w.Code)
	}
	if w := register(map[string]any{"name": "r1", "protocol_min": 1, "protocol_max": 2}); w.Code != http.StatusBadRequest {
		t.Fatalf("non-overlapping range: %d", w.Code)
	}
	if w := register(map[string]any{"name": "r1", "protocol_min": 4, "protocol_max": 4}); w.Code != http.StatusBadRequest {
		t.Fatalf("future protocol: %d", w.Code)
	}
	w := register(map[string]any{"name": "r1", "protocol_min": 2, "protocol_max": 5})
	if w.Code != http.StatusOK {
		t.Fatalf("overlapping range: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		ProtocolMin int `json:"protocol_min"`
		ProtocolMax int `json:"protocol_max"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.ProtocolMin != ProtocolMin || out.ProtocolMax != ProtocolMax {
		t.Fatalf("negotiated protocol = [%d,%d], want [%d,%d]", out.ProtocolMin, out.ProtocolMax, ProtocolMin, ProtocolMax)
	}
}

func TestRegisterMTLSBindsIdentity(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("secret")
	s.RunnerCA = ca
	h := s.Handler()
	certAPEM, certA := pkiSignRunner(t, ca, "runner-a")

	base := map[string]any{"name": "ra", "capacity": 1, "protocol_min": 3, "protocol_max": 3}

	withID := map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "protocol_min": 3, "protocol_max": 3}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register", withID, "secret", certA); w.Code != http.StatusOK {
		t.Fatalf("matching cert: %d %s", w.Code, w.Body.String())
	}
	mismatch := map[string]any{"id": "runner-b", "name": "rb", "capacity": 1, "protocol_min": 3, "protocol_max": 3}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register", mismatch, "secret", certA); w.Code != http.StatusForbidden {
		t.Fatalf("mismatched id: %d", w.Code)
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register", base, "secret", nil); w.Code != http.StatusForbidden {
		t.Fatalf("missing peer cert: %d", w.Code)
	}
	// An empty ID adopts the certificate identity.
	w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register", base, "secret", certA)
	if w.Code != http.StatusOK {
		t.Fatalf("empty id adoption: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.ID != "runner-a" {
		t.Fatalf("adopted id = %q, want runner-a", out.ID)
	}
	_ = certAPEM
}

func TestVerifyRunnerIdentityHelper(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("secret")
	_, certA := pkiSignRunner(t, ca, "runner-a")
	_, certB := pkiSignRunner(t, ca, "runner-b")

	plain := httptest.NewRequest(http.MethodPost, "/", nil)
	if !s.verifyRunnerIdentity(plain, "anything") {
		t.Fatal("dev mode must accept any claimed identity")
	}
	s.RunnerCA = ca
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certA}}
	if !s.verifyRunnerIdentity(req, "runner-a") {
		t.Fatal("matching cert identity must pass")
	}
	if s.verifyRunnerIdentity(req, "runner-b") {
		t.Fatal("mismatched cert identity must fail")
	}
	req2 := httptest.NewRequest(http.MethodPost, "/", nil)
	req2.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certB}}
	if !s.verifyRunnerIdentity(req2, "runner-b") {
		t.Fatal("second runner identity must pass")
	}
	if s.verifyRunnerIdentity(plain, "runner-a") {
		t.Fatal("missing peer cert must fail when mTLS enabled")
	}
}

func TestNextHeartbeatMTLSBinding(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("secret")
	s.RunnerCA = ca
	h := s.Handler()
	_, certA := pkiSignRunner(t, ca, "runner-a")
	_, certB := pkiSignRunner(t, ca, "runner-b")

	reg := map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "labels": []string{"container"}, "protocol_min": 3, "protocol_max": 3}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register", reg, "secret", certA); w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	run := SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: testPipeline}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runs", run, "secret", nil); w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/runner-a/next", map[string]any{}, "secret", certB); w.Code != http.StatusForbidden {
		t.Fatalf("next with wrong cert: %d", w.Code)
	}
	w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/runner-a/next", map[string]any{}, "secret", certA)
	if w.Code != http.StatusOK {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	hb := Heartbeat{RunnerID: "runner-a", LeaseToken: task.LeaseToken, LeaseGeneration: task.LeaseGeneration}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/heartbeat", hb, "secret", certB); w.Code != http.StatusForbidden {
		t.Fatalf("heartbeat with wrong cert: %d", w.Code)
	}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/heartbeat", hb, "secret", certA); w.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d %s", w.Code, w.Body.String())
	}
}
