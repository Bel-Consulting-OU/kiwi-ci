package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Web session support for the dashboard.
//
// Sessions are opaque, short-lived cookies issued by POST /api/v1/login
// against the admin token. The cookie value is
//
//	hex(nonce) + "|" + mac + "|" + expiry
//
// where the nonce is 16 fresh random bytes per session (crypto/rand, never
// expiry-derived), the expiry is a Unix timestamp, and the mac is
// hex(hmac-sha256(secret, tag+":"+nonce+":"+expiry)) — the HMAC proves the
// cookie was issued by this control plane and the integrity of both the
// nonce and the expiry. The server needs no session store: the MAC
// authenticates the value and the expiry bounds its lifetime. The CSRF
// token is the same construction with the "csrf" tag over the SAME nonce
// and expiry as the session cookie, so it is a true double-submit token:
// an attacker who can read the cookie cannot forge the header and vice
// versa, and a CSRF token from another session never validates.
//
// Validation compares MACs in constant time.

const (
	webSessionCookie  = "kiwi_session"
	webCSRFHeader     = "X-Kiwi-CSRF"
	webSessionTTL     = 8 * time.Hour
	webSessionNonceSz = 16
)

// webSessionSecretFromEnv resolves the KIWI_WEB_SESSION_SECRET override. It
// reports (nil, false, nil) when the variable is unset, the decoded key when
// it is set validly, and a startup error when it is set but malformed:
// silently falling back to a random per-process key on a typo would split
// dashboard sessions across replicas (or invalidate every session on a
// restart) with no signal to the operator.
func webSessionSecretFromEnv() ([]byte, bool, error) {
	raw := strings.TrimSpace(os.Getenv("KIWI_WEB_SESSION_SECRET"))
	if raw == "" {
		return nil, false, nil
	}
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != 32 {
		return nil, false, fmt.Errorf("KIWI_WEB_SESSION_SECRET must be 64 hex characters (a 32-byte shared key)")
	}
	return b, true, nil
}

// webSessionSecret returns the web session HMAC key: the
// KIWI_WEB_SESSION_SECRET env var (64 hex characters) when set, otherwise a
// fresh random 32-byte key. A malformed configured value is an error, never a
// silent random fallback. The random key is the documented dev/fs behavior
// for a server with no shared cluster key store; when a store is configured
// the key is derived from it instead (see loadWebSessionCluster).
func webSessionSecret() ([]byte, error) {
	if b, ok, err := webSessionSecretFromEnv(); err != nil {
		return nil, err
	} else if ok {
		return b, nil
	}
	b := make([]byte, 32)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return nil, fmt.Errorf("generate web session secret: %w", err)
	}
	return b, nil
}

// ensureWebSessionSecret initializes the session key on first use.
func (s *Server) ensureWebSessionSecret() error {
	if len(s.WebSessionSecret) == 32 {
		return nil
	}
	b, err := webSessionSecret()
	if err != nil {
		return err
	}
	s.WebSessionSecret = b
	return nil
}

// webMAC returns hex(hmac-sha256(secret, tag+":"+payload)).
func webMAC(secret []byte, tag, payload string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(tag))
	mac.Write([]byte(":"))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// newWebToken mints a fresh random nonce and returns the signed token
// value (nonce|mac|expiry) plus its expiry, or an error when the entropy
// source fails.
func newWebToken(secret []byte, tag, fingerprint string) (value string, expiry int64, err error) {
	nonce := make([]byte, webSessionNonceSz)
	if _, err = io.ReadFull(randReader, nonce); err != nil {
		return "", 0, err
	}
	nonceHex := hex.EncodeToString(nonce)
	expiry = time.Now().UTC().Add(webSessionTTL).Unix()
	expStr := strconv.FormatInt(expiry, 10)
	return nonceHex + "|" + webMAC(secret, tag, nonceHex+":"+expStr+":"+fingerprint) + "|" + expStr, expiry, nil
}

// adminTokenFingerprint binds a dashboard session to the admin credential it
// was minted against: rotating the admin token invalidates every existing
// session immediately instead of leaving stolen cookies valid for the full
// TTL.
func adminTokenFingerprint(adminToken string) string {
	sum := sha256.Sum256([]byte("kiwi-admin-token:" + adminToken))
	return hex.EncodeToString(sum[:8])
}

// parseWebToken splits a token value into its nonce, MAC and expiry parts.
func parseWebToken(v string) (nonce, mac, expStr string, ok bool) {
	parts := strings.Split(v, "|")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// webTokenOK validates a signed token: a valid MAC (constant time) over a
// non-expired nonce+expiry pair. Structurally empty parts are rejected
// outright — a well-formed token always carries all three components.
func webTokenOK(secret []byte, tag, v, fingerprint string) bool {
	nonce, mac, expStr, ok := parseWebToken(v)
	if !ok || nonce == "" || mac == "" || expStr == "" {
		return false
	}
	expiry, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return false
	}
	want := webMAC(secret, tag, nonce+":"+expStr+":"+fingerprint)
	return subtle.ConstantTimeCompare([]byte(mac), []byte(want)) == 1
}

// webLogin implements POST /api/v1/login: it verifies the submitted token
// against the admin token (constant time) and issues the session cookie
// plus the CSRF token, both bound to the same fresh random nonce.
func (s *Server) webLogin(w http.ResponseWriter, r *http.Request) {
	if err := s.ensureWebSessionSecret(); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &in) {
		return
	}
	fingerprint := adminTokenFingerprint(s.AdminToken)
	if s.AdminToken == "" || !constantTimeString(in.Token, s.AdminToken) {
		// Failed logins are audited (source address only; the attempted
		// token is never recorded) so brute force is visible even though the
		// token comparison itself is constant time.
		s.auditLocked("web.login.failed", "anonymous", "", "", "invalid admin token", map[string]string{"source": clientSource(r)})
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	// The admin token authenticated the request: only now does the schema
	// gate run, so a failed login attempt performs no compatibility DB reads.
	if !s.requireSchemaCompatible(w, r) {
		return
	}
	s.auditLocked("web.login", "web", "", "", "dashboard session created", map[string]string{"source": clientSource(r)})
	sessionValue, expiry, err := newWebToken(s.WebSessionSecret, "web", fingerprint)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	nonce, _, expStr, _ := parseWebToken(sessionValue)
	csrfValue := nonce + "|" + webMAC(s.WebSessionSecret, "csrf", nonce+":"+expStr+":"+fingerprint) + "|" + expStr
	http.SetCookie(w, &http.Cookie{
		Name:     webSessionCookie,
		Value:    sessionValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(expiry, 0),
	})
	w.Header().Set(webCSRFHeader, csrfValue)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// webLogout implements POST /api/v1/logout by clearing the session cookie.
//
// Logout changes session state, so it is a POST that demands the same
// double-submit CSRF proof as every other cookie-authenticated mutation: a
// valid session cookie plus the matching X-Kiwi-CSRF header (the exact checks
// auth() applies to mutating tierAdmin/tierRBAC requests). The route is
// public — no bearer is required — so auth() never sees it and the check must
// live here, before the cookie is touched: a cross-site request can never log
// the user out.
func (s *Server) webLogout(w http.ResponseWriter, r *http.Request) {
	if !s.webSessionOK(r) || !s.webCSRFOK(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	// The session cookie + CSRF proof authenticated the request: only now
	// does the schema gate run, so a request without a valid session performs
	// no compatibility DB reads.
	if !s.requireSchemaCompatible(w, r) {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     webSessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// webLogoutMethodNotAllowed implements GET /api/v1/logout: logout is a
// state-changing POST, so the read method is refused with 405 and an explicit
// Allow header rather than being served by the dashboard's "GET /"
// catch-all.
func (s *Server) webLogoutMethodNotAllowed(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Allow", http.MethodPost)
	http.Error(w, "method not allowed: logout is POST /api/v1/logout", http.StatusMethodNotAllowed)
}

// webSessionOK validates the session cookie: a valid HMAC (constant time)
// over a non-expired nonce+expiry pair.
func (s *Server) webSessionOK(r *http.Request) bool {
	if len(s.WebSessionSecret) != 32 {
		return false
	}
	c, err := r.Cookie(webSessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	return webTokenOK(s.WebSessionSecret, "web", c.Value, adminTokenFingerprint(s.AdminToken))
}

// webCSRFOK validates the double-submit CSRF token for a cookie-authenticated
// request: the X-Kiwi-CSRF header must carry a valid "csrf" MAC over the
// SAME nonce and expiry as the session cookie, binding the two submissions
// to one session. All comparisons are constant time.
func (s *Server) webCSRFOK(r *http.Request) bool {
	c, err := r.Cookie(webSessionCookie)
	if err != nil {
		return false
	}
	cNonce, _, cExp, ok := parseWebToken(c.Value)
	if !ok {
		return false
	}
	hNonce, hMAC, hExp, ok := parseWebToken(r.Header.Get(webCSRFHeader))
	if !ok {
		return false
	}
	// The header must submit the exact nonce/expiry of the session cookie
	// (double-submit binding).
	if !constantTimeString(cNonce, hNonce) || !constantTimeString(cExp, hExp) {
		return false
	}
	want := webMAC(s.WebSessionSecret, "csrf", hNonce+":"+hExp+":"+adminTokenFingerprint(s.AdminToken))
	return subtle.ConstantTimeCompare([]byte(hMAC), []byte(want)) == 1
}

// clientSource is the audited login source: the immediate peer address only
// (no forwarded headers are trusted), bounded so attacker-controlled text
// cannot flood the audit record.
func clientSource(r *http.Request) string {
	addr := r.RemoteAddr
	if len(addr) > 64 {
		addr = addr[:64]
	}
	return addr
}

// webMutatingMethod reports whether the method mutates server state and so
// requires a CSRF token when authenticated via the session cookie.
func webMutatingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// constantTimeString compares two strings in constant time.
func constantTimeString(got, want string) bool {
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
