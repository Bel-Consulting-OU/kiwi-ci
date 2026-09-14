package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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
//	hex(hmac-sha256(secret, "web:"+expiry)) + "|" + expiry
//
// with the expiry as a Unix timestamp, so the server needs no session
// store: the HMAC proves the cookie was issued by this control plane and
// the expiry bounds its lifetime. The CSRF token is the same construction
// with the "csrf:" tag: it is a true double-submit token because it is
// HMACed over the same expiry as the session cookie, so an attacker who
// can read the cookie cannot forge the header and vice versa.

const (
	webSessionCookie = "kiwi_session"
	webCSRFHeader    = "X-Kiwi-CSRF"
	webSessionTTL    = 8 * time.Hour
)

// webSessionSecret returns the web session HMAC key: the
// KIWI_WEB_SESSION_SECRET env var (64 hex characters) when set, otherwise
// a fresh random 32-byte key.
func webSessionSecret() []byte {
	if raw := strings.TrimSpace(os.Getenv("KIWI_WEB_SESSION_SECRET")); raw != "" {
		if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
			return b
		}
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("kiwi server: failed to generate web session secret: " + err.Error())
	}
	return b
}

// ensureWebSessionSecret initializes the session key on first use.
func (s *Server) ensureWebSessionSecret() {
	if len(s.WebSessionSecret) == 32 {
		return
	}
	s.WebSessionSecret = webSessionSecret()
}

// webMAC returns hex(hmac-sha256(secret, tag+":"+expiry)).
func webMAC(secret []byte, tag, expiry string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(tag))
	mac.Write([]byte(":"))
	mac.Write([]byte(expiry))
	return hex.EncodeToString(mac.Sum(nil))
}

// webLogin implements POST /api/v1/login: it verifies the submitted token
// against the admin token (constant time) and issues the session cookie
// plus the CSRF token.
func (s *Server) webLogin(w http.ResponseWriter, r *http.Request) {
	s.ensureWebSessionSecret()
	var in struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &in) {
		return
	}
	if s.AdminToken == "" || !constantTimeString(in.Token, s.AdminToken) {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	expiry := time.Now().UTC().Add(webSessionTTL).Unix()
	expStr := strconv.FormatInt(expiry, 10)
	http.SetCookie(w, &http.Cookie{
		Name:     webSessionCookie,
		Value:    webMAC(s.WebSessionSecret, "web", expStr) + "|" + expStr,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(expiry, 0),
	})
	w.Header().Set(webCSRFHeader, webMAC(s.WebSessionSecret, "csrf", expStr)+"|"+expStr)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// webLogout implements GET /api/v1/logout by clearing the session cookie.
func (s *Server) webLogout(w http.ResponseWriter, r *http.Request) {
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

// webSessionOK validates the session cookie: a valid HMAC over a
// non-expired timestamp.
func (s *Server) webSessionOK(r *http.Request) bool {
	if len(s.WebSessionSecret) != 32 {
		return false
	}
	c, err := r.Cookie(webSessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	mac, expStr, ok := strings.Cut(c.Value, "|")
	if !ok {
		return false
	}
	expiry, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(mac), []byte(webMAC(s.WebSessionSecret, "web", expStr))) == 1
}

// webSessionExpiry returns the expiry carried by a valid session cookie,
// or 0.
func (s *Server) webSessionExpiry(r *http.Request) int64 {
	c, err := r.Cookie(webSessionCookie)
	if err != nil {
		return 0
	}
	_, expStr, ok := strings.Cut(c.Value, "|")
	if !ok {
		return 0
	}
	expiry, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return 0
	}
	return expiry
}

// webCSRFOK validates the double-submit CSRF token for a cookie-authenticated
// request: the X-Kiwi-CSRF header must carry the HMAC over the same expiry
// as the session cookie, binding the two submissions to one session.
func (s *Server) webCSRFOK(r *http.Request) bool {
	if !s.webSessionOK(r) {
		return false
	}
	expiry := s.webSessionExpiry(r)
	if expiry == 0 {
		return false
	}
	mac, expStr, ok := strings.Cut(r.Header.Get(webCSRFHeader), "|")
	if !ok || expStr != strconv.FormatInt(expiry, 10) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(mac), []byte(webMAC(s.WebSessionSecret, "csrf", expStr))) == 1
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
