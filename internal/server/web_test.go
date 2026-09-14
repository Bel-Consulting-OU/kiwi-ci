package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testWebServer builds a server with a deterministic web session secret so
// tests can mint cookies directly.
func testWebServer(t *testing.T, adminToken string) *Server {
	t.Helper()
	s := New(adminToken)
	s.WebSessionSecret = bytes.Repeat([]byte{0x2a}, 32)
	return s
}

func TestDashboardServesStrictCSP(t *testing.T) {
	s := testWebServer(t, "admin")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET / = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "<!doctype html>") {
		t.Fatalf("GET / did not serve the dashboard html")
	}
	csp := w.Header().Get("Content-Security-Policy")
	want := "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
	if csp != want {
		t.Fatalf("CSP = %q, want %q", csp, want)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing nosniff header")
	}
	// The dashboard must not ship inline scripts or styles.
	if strings.Contains(w.Body.String(), "<script>") || strings.Contains(w.Body.String(), "<style>") {
		t.Fatalf("dashboard contains inline script/style")
	}
}

func TestStaticAssetsServed(t *testing.T) {
	s := testWebServer(t, "admin")
	for _, path := range []string{"/static/app.js", "/static/app.css"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, w.Code)
		}
		ct := w.Header().Get("Content-Type")
		if !strings.Contains(ct, "javascript") && !strings.Contains(ct, "text/css") {
			t.Fatalf("GET %s content-type = %q", path, ct)
		}
	}
	// Unknown static paths must 404 rather than fall through to the dashboard.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/static/missing.js", nil)
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET /static/missing.js = %d, want 404", w.Code)
	}
}

// login performs the login flow and returns the session cookie and CSRF
// token.
func login(t *testing.T, s *Server, token string) (string, string, int) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(`{"token":"`+token+`"}`))
	r.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(w, r)
	cookie := ""
	for _, c := range w.Result().Cookies() {
		if c.Name == webSessionCookie {
			cookie = c.Value
		}
	}
	return cookie, w.Header().Get(webCSRFHeader), w.Code
}

func TestWebLoginIssuesHttpOnlyCookie(t *testing.T) {
	s := testWebServer(t, "admin-token")
	cookie, csrf, code := login(t, s, "admin-token")
	if code != http.StatusOK {
		t.Fatalf("login = %d", code)
	}
	if cookie == "" || csrf == "" {
		t.Fatalf("login did not issue cookie/csrf: %q %q", cookie, csrf)
	}
	// Re-issue the request to inspect the Set-Cookie attributes.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(`{"token":"admin-token"}`))
	s.Handler().ServeHTTP(w, r)
	setCookie := w.Header().Get("Set-Cookie")
	for _, want := range []string{"HttpOnly", "Secure", "SameSite=Strict", webSessionCookie + "="} {
		if !strings.Contains(setCookie, want) {
			t.Fatalf("Set-Cookie %q missing %q", setCookie, want)
		}
	}
}

func TestWebLoginRejectsWrongToken(t *testing.T) {
	s := testWebServer(t, "admin-token")
	if _, _, code := login(t, s, "wrong"); code != http.StatusUnauthorized {
		t.Fatalf("login with wrong token = %d, want 401", code)
	}
}

func TestWebSessionMutatingRequiresCSRF(t *testing.T) {
	s := testWebServer(t, "admin-token")
	cookie, csrf, _ := login(t, s, "admin-token")

	post := func(withCSRF string) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/runs/nope/cancel", strings.NewReader("{}"))
		r.Header.Set("Cookie", webSessionCookie+"="+cookie)
		if withCSRF != "" {
			r.Header.Set(webCSRFHeader, withCSRF)
		}
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}

	// A mutating request with the session cookie but no CSRF token is
	// rejected with 403 before reaching the handler (the run is fake, but
	// the CSRF gate sits in front of routing authorization).
	if code := post(""); code != http.StatusForbidden {
		t.Fatalf("mutating request without CSRF = %d, want 403", code)
	}
	if code := post("bogus|0"); code != http.StatusForbidden {
		t.Fatalf("mutating request with bogus CSRF = %d, want 403", code)
	}
	// With the correct CSRF token the request passes the CSRF gate (404:
	// the run does not exist — but it is not 401/403).
	if code := post(csrf); code != http.StatusNotFound {
		t.Fatalf("mutating request with CSRF = %d, want 404 (passes auth)", code)
	}
}

func TestWebSessionAuthorizesReadEndpoints(t *testing.T) {
	s := testWebServer(t, "admin-token")
	cookie, _, _ := login(t, s, "admin-token")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	r.Header.Set("Cookie", webSessionCookie+"="+cookie)
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/runs with session = %d", w.Code)
	}
}

func TestWebSessionExpiry(t *testing.T) {
	s := testWebServer(t, "admin-token")
	// Mint a session whose expiry is one hour in the past.
	expStr := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
	stale := webMAC(s.WebSessionSecret, "web", expStr) + "|" + expStr
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	r.Header.Set("Cookie", webSessionCookie+"="+stale)
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expired session = %d, want 401", w.Code)
	}
	// A tampered MAC must also fail.
	tampered := strings.TrimPrefix(stale, "a") + "|" + expStr
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	r.Header.Set("Cookie", webSessionCookie+"="+tampered)
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("tampered session = %d, want 401", w.Code)
	}
}

func TestWebLogoutClearsCookie(t *testing.T) {
	s := testWebServer(t, "admin-token")
	cookie, _, _ := login(t, s, "admin-token")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/logout", nil)
	r.Header.Set("Cookie", webSessionCookie+"="+cookie)
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("logout = %d", w.Code)
	}
	if set := w.Header().Get("Set-Cookie"); !strings.Contains(set, "Max-Age=0") {
		t.Fatalf("logout did not clear the cookie: %q", set)
	}
}

func TestWebSessionCannotAccessRunnerOnlyRoutes(t *testing.T) {
	s := testWebServer(t, "admin-token")
	s.RunnerToken = "runner-token"
	cookie, _, _ := login(t, s, "admin-token")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/runners/register", strings.NewReader("{}"))
	r.Header.Set("Cookie", webSessionCookie+"="+cookie)
	s.Handler().ServeHTTP(w, r)
	// Runner registration is runner-only; a web session must not authorize it.
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("session cookie reached runner-only endpoint: %d", w.Code)
	}
}

// TestWebSessionEndToEndCancel exercises a full admin flow: bearer submit,
// session login, cookie+CSRF cancel.
func TestWebSessionEndToEndCancel(t *testing.T) {
	s := testWebServer(t, "admin-token")
	pipelineYAML := "version: 1\njobs:\n  a:\n    runtime: container\n    image: alpine:latest\n    steps:\n      - run: \"true\"\n"

	submit := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runs", strings.NewReader(`{"repo_url":"https://example.com/x.git","pipeline":`+strconv.Quote(pipelineYAML)+`}`))
	req.Header.Set("Authorization", "Bearer admin-token")
	s.Handler().ServeHTTP(submit, req)
	if submit.Code != http.StatusAccepted {
		t.Fatalf("submit = %d: %s", submit.Code, submit.Body.String())
	}
	var run struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(submit.Body.Bytes(), &run); err != nil {
		t.Fatalf("submit response: %v", err)
	}

	cookie, csrf, _ := login(t, s, "admin-token")
	cancel := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", strings.NewReader("{}"))
	req.Header.Set("Cookie", webSessionCookie+"="+cookie)
	req.Header.Set(webCSRFHeader, csrf)
	s.Handler().ServeHTTP(cancel, req)
	if cancel.Code != http.StatusOK {
		t.Fatalf("session cancel = %d: %s", cancel.Code, cancel.Body.String())
	}
}
