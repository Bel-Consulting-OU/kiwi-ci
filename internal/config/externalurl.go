package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateExternalURL parses raw as the control plane's public base URL (the
// OIDC issuer identifier and the base for forge status links) and returns it
// normalized: trailing slashes are trimmed because they are not part of an
// issuer identity, and nothing else about the value is rewritten.
//
// It is the ONE parsed-URL policy shared by config validation
// (server.external_url, --external-url, KIWI_EXTERNAL_URL) and the OIDC
// startup path (Server.oidcIssuer), so a value that survives startup can
// never later make the OIDC endpoints answer 503: config validation and OIDC
// accept exactly the same set. The inverse is deliberately not true — mode
// "production" is stricter than the OIDC path, which has no mode of its own —
// so a production config can never carry a plaintext issuer OIDC would
// reject.
//
// Policy:
//   - non-empty and absolute: a scheme plus a host, never an opaque URL;
//   - scheme https://, or http:// only for a genuine loopback host
//     ("localhost", 127.0.0.0/8, ::1 — never a prefix lookalike such as
//     "localhost.evil.example"), because an issuer identifier must never
//     travel in plaintext;
//   - mode "production" forbids even the loopback http exception;
//   - no userinfo (credentials belong in headers, never in a public URL),
//     no query and no fragment (an issuer identifier is a bare origin+path).
func ValidateExternalURL(raw, mode string) (string, error) {
	v := strings.TrimRight(raw, "/")
	if v == "" {
		return "", fmt.Errorf("external URL is required")
	}
	u, err := url.Parse(v)
	if err != nil {
		return "", fmt.Errorf("external URL is not a valid URL: %w", err)
	}
	if u.Host == "" || u.Hostname() == "" || u.Opaque != "" {
		return "", fmt.Errorf("external URL must be an absolute URL with a host")
	}
	if u.User != nil {
		return "", fmt.Errorf("external URL must not carry userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("external URL must not carry a query or fragment")
	}
	if u.Scheme == "https" {
		return v, nil
	}
	if u.Scheme == "http" {
		if mode == "production" {
			return "", fmt.Errorf("external URL must use https:// in production mode, got plaintext http for %q", u.Host)
		}
		if isLoopbackHost(u.Hostname()) {
			return v, nil
		}
	}
	return "", fmt.Errorf("external URL must use https://, or plaintext http only for a genuine loopback development host, got %q", raw)
}

// isLoopbackHost reports whether host is a genuine loopback name or address
// ("localhost", 127.0.0.0/8, ::1) — never a prefix lookalike.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
