package server

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// TestRunnerTierFailsClosedWithoutCredential: a server with an admin token
// but neither a runner token nor enforced runner mTLS refuses runner-tier
// routes with 503 instead of silently serving them.
func TestRunnerTierFailsClosedWithoutCredential(t *testing.T) {
	s := New("")
	s.AdminToken = "admin-tok"
	h := s.Handler()
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/runners/register"},
		{http.MethodPost, "/api/v1/runners/r1/next"},
		{http.MethodPost, "/api/v1/jobs/j1/heartbeat"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}"))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s without runner credential: got %d, want 503", tc.method, tc.path, w.Code)
		}
		if !strings.Contains(w.Body.String(), "runner authentication is not configured") {
			t.Errorf("%s %s: body = %q", tc.method, tc.path, w.Body.String())
		}
	}
	// Admin routes keep working.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	req.Header.Set("Authorization", "Bearer admin-tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("admin route with only admin token: got %d, want 200", w.Code)
	}
}

// TestRunnerTierMTLSEnforcedPassesToHandler: with enforced runner mTLS the
// tier gate requires a valid peer certificate (401 without one, even with
// a valid bearer) and passes certificate-carrying requests to the handler
// where per-route identity checks still apply.
func TestRunnerTierMTLSEnforcedPassesToHandler(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("runner-tok")
	s.RunnerCA = ca
	s.RequireRunnerClientCerts = true
	h := s.Handler()
	_, certA := pkiSignRunner(t, ca, "runner-a")

	reg := map[string]any{"id": "runner-a", "name": "ra", "capacity": 1, "protocol_min": 3, "protocol_max": 3}
	// Valid bearer without a peer certificate: 401 at the tier gate.
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register", reg, "runner-tok", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("runner route without peer cert: got %d, want 401", w.Code)
	}
	// With the certificate the tier passes to the handler (identity still
	// checked per route: a mismatched claimed ID is 403 inside register).
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register", reg, "runner-tok", certA); w.Code != http.StatusOK {
		t.Fatalf("register with cert: %d %s", w.Code, w.Body.String())
	}
	_, certB := pkiSignRunner(t, ca, "runner-b")
	bad := map[string]any{"id": "runner-b", "name": "rb", "capacity": 1, "protocol_min": 3, "protocol_max": 3}
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register", bad, "runner-tok", certB); w.Code != http.StatusOK {
		t.Fatalf("register runner-b: %d", w.Code)
	}
	// Per-route identity: cert B acting for runner-a is 403 inside next().
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/runner-a/next", map[string]any{}, "runner-tok", certB); w.Code != http.StatusForbidden {
		t.Fatalf("next with wrong cert: got %d, want 403", w.Code)
	}
}

// TestSharedListenerEnrollWithoutClientCert: enrollment works over the
// shared TLS listener without a client certificate (it authenticates with
// the enrollment token), while runner-tier routes demand the certificate.
func TestSharedListenerEnrollWithoutClientCert(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New("runner-tok")
	s.RunnerCA = ca
	s.RunnerEnrollToken = "enroll-secret"
	s.RunnerClientCAPool = runnerpki.Pool(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}))
	s.RequireRunnerClientCerts = true
	certFile, keyFile := selfSignedServerCert(t, t.TempDir())
	tlsCfg, err := s.TLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.TLS = tlsCfg
	ts.StartTLS()
	defer ts.Close()

	client := ts.Client()
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}}

	_, csrPEM, err := runnerpki.GenerateKeyAndCSR("runner-7")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(EnrollRequest{RunnerID: "runner-7", CSR: base64.StdEncoding.EncodeToString(csrPEM)})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/runners/enroll", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer enroll-secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b := make([]byte, 512)
		n, _ := resp.Body.Read(b)
		t.Fatalf("enroll without client cert: got %d: %s", resp.StatusCode, b[:n])
	}
	var out EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.RunnerID != "runner-7" {
		t.Fatalf("enrolled identity = %q, want runner-7", out.RunnerID)
	}

	// The same cert-less client cannot reach runner-tier routes.
	regReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/runners/register", stringsReader(`{"name":"r","protocol_min":3,"protocol_max":3}`))
	regReq.Header.Set("Authorization", "Bearer runner-tok")
	regReq.Header.Set("Content-Type", "application/json")
	regResp, err := client.Do(regReq)
	if err != nil {
		t.Fatal(err)
	}
	regResp.Body.Close()
	if regResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("runner register without cert: got %d, want 401", regResp.StatusCode)
	}
}

// TestPublicClassifierSharedByTiers: with a populated token store the
// shared classifier keeps health endpoints, enrollment and webhooks
// reachable while non-public paths still demand a token.
func TestPublicClassifierSharedByTiers(t *testing.T) {
	s := storeServer(t, "admin-tok", map[string]auth.Principal{
		"ci-token": {Subject: "ci-bot", Roles: []auth.Role{auth.RoleRun}},
	})
	h := s.Handler()

	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/readiness", http.StatusOK},
		{http.MethodGet, "/liveness", http.StatusOK},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}")))
		if w.Code != tc.want {
			t.Errorf("%s %s: got %d, want %d", tc.method, tc.path, w.Code, tc.want)
		}
	}
	// The webhook path reaches its handler (any non-401/403 response; the
	// handler rejects the unsigned payload itself). The point is that the
	// strict token-store middleware did not gate it.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/hooks/github", strings.NewReader("{}")))
	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Fatalf("/hooks/github blocked by token middleware: got %d", w.Code)
	}
	// Non-public path without a token: 401.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("non-public path without token: got %d, want 401", w.Code)
	}
}

// TestEnrollGrants: single-use grants with expiry, label binding and
// hash-only persistence.
func TestEnrollGrants(t *testing.T) {
	ca, err := runnerpki.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.RunnerCA = ca

	raw, err := s.CreateEnrollGrant(time.Hour, []string{"os:macos", "arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 64 {
		t.Fatalf("raw grant length = %d, want 64 hex chars", len(raw))
	}
	// The raw grant is never stored: only its digest is.
	s.mu.Lock()
	_, stored := s.EnrollGrants[auth.TokenDigest(raw)]
	_, rawStored := s.EnrollGrants[raw]
	s.mu.Unlock()
	if !stored {
		t.Fatal("grant digest not stored")
	}
	if rawStored {
		t.Fatal("raw grant value must never be stored")
	}
	// The persisted file contains hashes only.
	onDisk, err := os.ReadFile(filepath.Join(dir, enrollGrantsFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(onDisk), raw) {
		t.Fatal("enroll-grants.json contains the raw grant value")
	}

	h := s.Handler()
	enrollBody := func(runnerID string, labels []string) EnrollRequest {
		_, csrPEM, err := runnerpki.GenerateKeyAndCSR(runnerID)
		if err != nil {
			t.Fatal(err)
		}
		return EnrollRequest{RunnerID: runnerID, CSR: base64.StdEncoding.EncodeToString(csrPEM), Labels: labels}
	}

	// Label binding: missing a bound label is rejected (and the grant is
	// not consumed by a rejected attempt).
	req := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBody("runner-1", []string{"os:macos"}), raw, nil)
	if req.Code != http.StatusUnauthorized {
		t.Fatalf("enroll without bound labels: got %d, want 401", req.Code)
	}
	// With all bound labels the grant works exactly once.
	ok := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBody("runner-1", []string{"os:macos", "arm64", "extra"}), raw, nil)
	if ok.Code != http.StatusOK {
		t.Fatalf("enroll with bound labels: got %d: %s", ok.Code, ok.Body.String())
	}
	var out EnrollResponse
	if err := json.Unmarshal(ok.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.RunnerID != "runner-1" {
		t.Fatalf("enrolled identity = %q, want runner-1", out.RunnerID)
	}
	// Reuse is rejected.
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBody("runner-2", []string{"os:macos", "arm64"}), raw, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("grant reuse: got %d, want 401", w.Code)
	}

	// Expired grants are rejected by the tier gate.
	if _, err := s.CreateEnrollGrant(-0, nil); err == nil {
		t.Fatal("zero ttl must be rejected")
	}
	expired, err := s.CreateEnrollGrant(time.Nanosecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/enroll", enrollBody("runner-3", nil), expired, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired grant: got %d, want 401", w.Code)
	}

	// Used state survives a restart (hash-only persistence).
	s2, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.RunnerCA = ca
	s2.mu.Lock()
	g, ok2 := s2.EnrollGrants[auth.TokenDigest(raw)]
	s2.mu.Unlock()
	if !ok2 || !g.Used {
		t.Fatalf("grant used state not persisted: ok=%v grant=%+v", ok2, g)
	}
}

// TestCreateEnrollGrantLabelBindingDirectly checks the grant map contents
// (expiry and bound labels).
func TestCreateEnrollGrantState(t *testing.T) {
	s := New("t")
	raw, err := s.CreateEnrollGrant(time.Minute, []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	g := s.EnrollGrants[auth.TokenDigest(raw)]
	s.mu.Unlock()
	if g.Used {
		t.Fatal("fresh grant must be unused")
	}
	if len(g.BoundLabels) != 2 || g.BoundLabels[0] != "a" || g.BoundLabels[1] != "b" {
		t.Fatalf("bound labels = %v", g.BoundLabels)
	}
	if time.Until(g.ExpiresAt) > time.Minute || time.Until(g.ExpiresAt) < 55*time.Second {
		t.Fatalf("expiry = %v, want ~1m", g.ExpiresAt)
	}
}

// TestValidateRunnerRegistration enforces capacity, label grammar, region
// grammar, protocol clamping and finite non-negative usage rates.
func TestValidateRunnerRegistration(t *testing.T) {
	valid := RunnerInfo{Capacity: 2, Labels: []string{"container", "os:macos"}, Region: "us-east-1", ProtocolMin: 2, ProtocolMax: 5, CostPerHour: 1.5, PowerWatts: 120}
	if err := validateRunnerRegistration(&valid); err != nil {
		t.Fatalf("valid registration rejected: %v", err)
	}
	if valid.ProtocolMin != ProtocolMin || valid.ProtocolMax != ProtocolMax {
		t.Fatalf("protocol not clamped: [%d,%d]", valid.ProtocolMin, valid.ProtocolMax)
	}

	cases := []struct {
		name   string
		mutate func(*RunnerInfo)
	}{
		{"negative capacity", func(in *RunnerInfo) { in.Capacity = -1 }},
		{"huge capacity", func(in *RunnerInfo) { in.Capacity = maxRunnerCapacity + 1 }},
		{"bad label", func(in *RunnerInfo) { in.Labels = []string{"-leading-dash"} }},
		{"bad label chars", func(in *RunnerInfo) { in.Labels = []string{"space label"} }},
		{"region too long", func(in *RunnerInfo) { in.Region = strings.Repeat("r", 65) }},
		{"bad region", func(in *RunnerInfo) { in.Region = "bad region!" }},
		{"missing protocol", func(in *RunnerInfo) { in.ProtocolMin, in.ProtocolMax = 0, 0 }},
		{"non-overlapping protocol", func(in *RunnerInfo) { in.ProtocolMin, in.ProtocolMax = 1, 2 }},
		{"NaN cost", func(in *RunnerInfo) { in.CostPerHour = math.NaN() }},
		{"Inf cost", func(in *RunnerInfo) { in.CostPerHour = math.Inf(1) }},
		{"negative cost", func(in *RunnerInfo) { in.CostPerHour = -0.5 }},
		{"NaN watts", func(in *RunnerInfo) { in.PowerWatts = math.NaN() }},
		{"negative watts", func(in *RunnerInfo) { in.PowerWatts = -1 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := valid
			c.mutate(&in)
			if err := validateRunnerRegistration(&in); err == nil {
				t.Fatalf("registration accepted, want error")
			}
		})
	}
}

// TestRegisterRejectsNaNCost: Go's JSON decoder accepts NaN/Infinity
// float64 literals; the registration gate must reject them so usage
// accounting never silently skips a job.
func TestRegisterRejectsNaNCost(t *testing.T) {
	s := New("secret")
	h := s.Handler()
	w := pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		[]byte(`{"name":"r","protocol_min":3,"protocol_max":3,"cost_per_hour":NaN}`), "secret", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("NaN cost_per_hour: got %d, want 400: %s", w.Code, w.Body.String())
	}
	w = pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		[]byte(`{"name":"r","protocol_min":3,"protocol_max":3,"power_watts":Infinity}`), "secret", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("Inf power_watts: got %d, want 400", w.Code)
	}
	// A sane registration still works.
	w = pkiRequest(t, h, http.MethodPost, "/api/v1/runners/register",
		[]byte(`{"name":"r","protocol_min":3,"protocol_max":3,"cost_per_hour":1.5,"power_watts":120,"capacity":2}`), "secret", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("sane registration: got %d: %s", w.Code, w.Body.String())
	}
}

// TestWebLoginIssuesUniqueSessionNonces: every login mints a fresh random
// nonce, so two logins produce different cookies and CSRF tokens, and each
// token validates only for its own session.
func TestWebLoginIssuesUniqueSessionNonces(t *testing.T) {
	s := testWebServer(t, "admin-token")
	cookie1, csrf1, code1 := login(t, s, "admin-token")
	if code1 != http.StatusOK {
		t.Fatalf("first login = %d", code1)
	}
	cookie2, csrf2, code2 := login(t, s, "admin-token")
	if code2 != http.StatusOK {
		t.Fatalf("second login = %d", code2)
	}
	if cookie1 == cookie2 {
		t.Fatal("two logins produced identical session cookies")
	}
	if csrf1 == csrf2 {
		t.Fatal("two logins produced identical CSRF tokens")
	}
	// Each cookie verifies.
	for i, cookie := range []string{cookie1, cookie2} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
		r.Header.Set("Cookie", webSessionCookie+"="+cookie)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("login %d cookie rejected: %d", i+1, w.Code)
		}
	}
	// A CSRF token from login 2 is not accepted for login 1's session.
	r := httptest.NewRequest(http.MethodPost, "/api/v1/runs/nope/cancel", strings.NewReader("{}"))
	r.Header.Set("Cookie", webSessionCookie+"="+cookie1)
	r.Header.Set(webCSRFHeader, csrf2)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-session CSRF: got %d, want 403", w.Code)
	}
	// The right pair passes the CSRF gate.
	r = httptest.NewRequest(http.MethodPost, "/api/v1/runs/nope/cancel", strings.NewReader("{}"))
	r.Header.Set("Cookie", webSessionCookie+"="+cookie1)
	r.Header.Set(webCSRFHeader, csrf1)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("matching CSRF: got %d, want 404 (passes the gate)", w.Code)
	}
}

// TestWebSessionTamperedMACRejected: flipping a MAC character in a
// well-formed cookie must fail constant-time validation.
func TestWebSessionTamperedMACRejected(t *testing.T) {
	s := testWebServer(t, "admin-token")
	cookie, _, _ := login(t, s, "admin-token")
	parts := strings.Split(cookie, "|")
	if len(parts) != 3 {
		t.Fatalf("cookie format = %q", cookie)
	}
	mac := []byte(parts[1])
	mac[0] ^= 0xff
	parts[1] = string(mac)
	tampered := strings.Join(parts, "|")
	r := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	r.Header.Set("Cookie", webSessionCookie+"="+tampered)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("tampered MAC: got %d, want 401", w.Code)
	}
}
