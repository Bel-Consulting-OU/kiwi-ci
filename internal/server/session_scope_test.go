package server

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// serveWithSession issues a request carrying the session cookie (and
// optionally the CSRF header).
func serveWithSession(s *Server, method, path, cookie, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader("{}"))
	if cookie != "" {
		r.Header.Set("Cookie", webSessionCookie+"="+cookie)
	}
	if csrf != "" {
		r.Header.Set(webCSRFHeader, csrf)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// TestWebSessionNonceUniqueness1000 mints 1000 sessions and proves every
// nonce, session cookie and CSRF token is distinct, and that no CSRF token
// is accepted for another session.
func TestWebSessionNonceUniqueness1000(t *testing.T) {
	s := testWebServer(t, "admin-token")
	cookies := make(map[string]bool, 1000)
	csrfs := make(map[string]bool, 1000)
	nonces := make(map[string]bool, 1000)
	var sampleCookie, sampleCSRF string
	var foreignCookie string
	for i := 0; i < 1000; i++ {
		cookie, csrf, code := login(t, s, "admin-token")
		if code != http.StatusOK {
			t.Fatalf("login %d = %d", i, code)
		}
		nonce, _, _, ok := parseWebToken(cookie)
		if !ok {
			t.Fatalf("login %d produced a malformed cookie %q", i, cookie)
		}
		if cookies[cookie] {
			t.Fatalf("duplicate session cookie at login %d", i)
		}
		if csrfs[csrf] {
			t.Fatalf("duplicate CSRF token at login %d", i)
		}
		if nonces[nonce] {
			t.Fatalf("duplicate session nonce at login %d", i)
		}
		cookies[cookie] = true
		csrfs[csrf] = true
		nonces[nonce] = true
		if i == 1 {
			sampleCookie, sampleCSRF = cookie, csrf
		}
		if i == 2 {
			foreignCookie = cookie
		}
	}
	// The sample session authenticates.
	if w := serveWithSession(s, http.MethodGet, "/api/v1/runs", sampleCookie, ""); w.Code != http.StatusOK {
		t.Fatalf("sample session rejected: %d", w.Code)
	}
	// Its CSRF token works for its own session...
	if w := serveWithSession(s, http.MethodPost, "/api/v1/runs", sampleCookie, sampleCSRF); w.Code == http.StatusForbidden {
		t.Fatalf("own CSRF token rejected: %d", w.Code)
	}
	// ...but the first session's CSRF token never validates against a
	// different session's cookie.
	if w := serveWithSession(s, http.MethodPost, "/api/v1/runs", foreignCookie, sampleCSRF); w.Code != http.StatusForbidden {
		t.Fatalf("foreign CSRF token accepted: %d", w.Code)
	}
}

// TestWebSessionTokenEdges feeds hand-crafted token shapes: forged MACs,
// expired expiries, cross-tag reuse, malformed framing and unbounded input.
func TestWebSessionTokenEdges(t *testing.T) {
	s := testWebServer(t, "admin-token")
	cookie, csrf, _ := login(t, s, "admin-token")
	nonce, _, expStr, ok := parseWebToken(cookie)
	if !ok {
		t.Fatalf("cookie framing: %q", cookie)
	}
	secret := s.WebSessionSecret

	// Valid MAC over an already-expired nonce/expiry pair.
	pastExp := time.Now().Add(-time.Hour).Unix()
	pastStr := strconv.FormatInt(pastExp, 10)
	expired := nonce + "|" + webMAC(secret, "web", nonce+":"+pastStr) + "|" + pastStr
	// Valid MAC but the wrong tag: a CSRF token must never authenticate a
	// session cookie.
	crossTag := nonce + "|" + webMAC(secret, "csrf", nonce+":"+expStr) + "|" + expStr
	// The session MAC replayed as a CSRF header (with the cookie present).
	cases := []struct {
		name   string
		cookie string
		csrf   string
		method string
		want   int
	}{
		{"expired session", expired, "", http.MethodGet, http.StatusUnauthorized},
		{"cross-tag session", crossTag, "", http.MethodGet, http.StatusUnauthorized},
		{"flipped MAC", tamperMAC(cookie), "", http.MethodGet, http.StatusUnauthorized},
		{"extra part", cookie + "|extra", "", http.MethodGet, http.StatusUnauthorized},
		{"empty mac", nonce + "||" + expStr, "", http.MethodGet, http.StatusUnauthorized},
		{"empty nonce", "|" + webMAC(secret, "web", ":"+expStr) + "|" + expStr, "", http.MethodGet, http.StatusUnauthorized},
		{"empty expiry", nonce + "|" + webMAC(secret, "web", nonce+":") + "|", "", http.MethodGet, http.StatusUnauthorized},
		{"non-numeric expiry", nonce + "|" + webMAC(secret, "web", nonce+":soon") + "|soon", "", http.MethodGet, http.StatusUnauthorized},
		{"nul in cookie", nonce + "\x00|" + webMAC(secret, "web", nonce+":"+expStr) + "|" + expStr, "", http.MethodGet, http.StatusUnauthorized},
		{"oversized cookie", strings.Repeat("a", 1<<20), "", http.MethodGet, http.StatusUnauthorized},
		{"missing CSRF on POST", cookie, "", http.MethodPost, http.StatusForbidden},
		{"session MAC as CSRF", cookie, cookie, http.MethodPost, http.StatusForbidden},
		{"csrf with foreign expiry", cookie, nonce + "|" + webMAC(secret, "csrf", nonce+":99999999999") + "|99999999999", http.MethodPost, http.StatusForbidden},
		{"csrf with foreign nonce", cookie, "deadbeef|" + webMAC(secret, "csrf", "deadbeef:"+expStr) + "|" + expStr, http.MethodPost, http.StatusForbidden},
		{"correct pair", cookie, csrf, http.MethodPost, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := serveWithSession(s, tc.method, "/api/v1/runs", tc.cookie, tc.csrf)
			if tc.want == 0 {
				if w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
					t.Fatalf("%s = %d, want the gate to pass: %s", tc.name, w.Code, w.Body.String())
				}
				return
			}
			if w.Code != tc.want {
				t.Fatalf("%s = %d, want %d: %s", tc.name, w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// tamperMAC flips one hex nibble of the MAC part.
func tamperMAC(cookie string) string {
	parts := strings.Split(cookie, "|")
	if len(parts) != 3 {
		return cookie
	}
	mac := []byte(parts[1])
	if len(mac) == 0 {
		return cookie
	}
	if mac[0] == 'a' {
		mac[0] = 'b'
	} else {
		mac[0] = 'a'
	}
	parts[1] = string(mac)
	return strings.Join(parts, "|")
}

// TestWebCSRFRequiredForEveryMutatingMethod proves the double-submit gate
// covers POST/PUT/PATCH/DELETE for cookie-authenticated requests on both
// the RBAC and admin tiers, while safe methods stay CSRF-free.
func TestWebCSRFRequiredForEveryMutatingMethod(t *testing.T) {
	s := testWebServer(t, "admin-token")
	cookie, csrf, _ := login(t, s, "admin-token")

	mutating := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/runs"},
		{http.MethodPost, "/api/v1/runner-profiles"},
		{http.MethodPut, "/api/v1/schedules"},
		{http.MethodPut, "/api/v1/runner-profiles/p"},
		{http.MethodPatch, "/api/v1/runs"},
		{http.MethodDelete, "/api/v1/runs"},
	}
	for _, tc := range mutating {
		// Without the CSRF header: always 403, never the handler.
		if w := serveWithSession(s, tc.method, tc.path, cookie, ""); w.Code != http.StatusForbidden {
			t.Errorf("%s %s without CSRF = %d, want 403", tc.method, tc.path, w.Code)
		}
		// With the matching CSRF header the gate passes (the handler may
		// then reject the payload/method itself).
		if w := serveWithSession(s, tc.method, tc.path, cookie, csrf); w.Code == http.StatusForbidden {
			t.Errorf("%s %s with valid CSRF = %d, want the gate to pass", tc.method, tc.path, w.Code)
		}
	}
	// Safe methods need no CSRF.
	for _, path := range []string{"/api/v1/runs", "/api/v1/runners"} {
		if w := serveWithSession(s, http.MethodGet, path, cookie, ""); w.Code != http.StatusOK {
			t.Errorf("GET %s with a valid session = %d, want 200", path, w.Code)
		}
	}
	// A request with a bad bearer AND no cookie is not cookie-authenticated:
	// it must be 401, not a CSRF 403 (the gate only applies to sessions).
	r := httptest.NewRequest(http.MethodPost, "/api/v1/runs", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad bearer on mutating route = %d, want 401", w.Code)
	}
}

// TestWebSessionSecretConfiguration pins the KIWI_WEB_SESSION_SECRET
// contract: a valid 64-hex value is used verbatim (so replicas with the
// same secret validate each other's cookies), an invalid value falls back
// to a fresh random secret (never a weak/empty key).
func TestWebSessionSecretConfiguration(t *testing.T) {
	valid := strings.Repeat("ab", 32)
	t.Setenv("KIWI_WEB_SESSION_SECRET", valid)
	s1 := New("admin-token")
	s2 := New("admin-token")
	// The secret is initialized lazily (ensureWebSessionSecret) in memory
	// mode; exercise the same entry point a login would.
	s1.ensureWebSessionSecret()
	s2.ensureWebSessionSecret()
	if len(s1.WebSessionSecret) != 32 || len(s2.WebSessionSecret) != 32 {
		t.Fatal("valid secret not loaded")
	}
	if string(s1.WebSessionSecret) != string(s2.WebSessionSecret) {
		t.Fatal("replicas with the same configured secret must share it")
	}
	// A session minted on s1 validates on s2 (same key).
	cookie, _, code := login(t, s1, "admin-token")
	if code != http.StatusOK {
		t.Fatalf("login = %d", code)
	}
	if w := serveWithSession(s2, http.MethodGet, "/api/v1/runs", cookie, ""); w.Code != http.StatusOK {
		t.Fatalf("shared-secret session rejected by replica: %d", w.Code)
	}
	// A different secret must not validate another replica's session.
	s3 := New("admin-token")
	s3.WebSessionSecret = []byte(strings.Repeat("cd", 32))
	if w := serveWithSession(s3, http.MethodGet, "/api/v1/runs", cookie, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("foreign-secret session accepted: %d", w.Code)
	}
	// Invalid configured values fall back to a fresh random 32-byte key.
	for _, bad := range []string{"", "   ", "zz", strings.Repeat("a", 63), strings.Repeat("a", 65), "not-hex!"} {
		t.Setenv("KIWI_WEB_SESSION_SECRET", bad)
		s := New("admin-token")
		s.ensureWebSessionSecret()
		if len(s.WebSessionSecret) != 32 {
			t.Fatalf("invalid secret %q produced a %d-byte key", bad, len(s.WebSessionSecret))
		}
		if strings.Contains(string(s.WebSessionSecret), bad) && bad != "" {
			t.Fatalf("invalid secret %q leaked into the key", bad)
		}
	}
}

// TestWebLogoutRequiresNoAuthButClearsTheCookie pins the logout contract:
// it is public (no token), returns no session material, and clears the
// cookie with MaxAge<0.
func TestWebLogoutRequiresNoAuthButClearsTheCookie(t *testing.T) {
	s := testWebServer(t, "admin-token")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/logout", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("logout = %d", w.Code)
	}
	setCookie := w.Header().Get("Set-Cookie")
	for _, want := range []string{webSessionCookie + "=;", "Max-Age=0", "HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(setCookie, want) {
			t.Fatalf("logout Set-Cookie %q missing %q", setCookie, want)
		}
	}
	if strings.Contains(w.Body.String(), "|") {
		t.Fatalf("logout body leaked token material: %s", w.Body.String())
	}
}
