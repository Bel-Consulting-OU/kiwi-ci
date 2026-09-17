package secretbroker

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Hardened provider HTTP transport.
//
// Every secret provider talks to a credential-bearing endpoint: the request
// carries a Vault token, an AWS SigV4 Authorization header, an OAuth bearer
// token, a 1Password session token, or a sealed delivery. An indefinite
// client (http.DefaultClient has no timeout at all, and a bare &http.Client{}
// only bounds the request) lets a stalled or malicious endpoint pin a
// resolver goroutine forever, and a redirect-following client can be lured
// into replaying those credentials against an attacker-controlled origin.
// hardenedClient therefore bounds every phase of the exchange and refuses
// redirects outright.
const (
	// hardenedTotalTimeout bounds one full request/response exchange.
	hardenedTotalTimeout = 30 * time.Second
	// hardenedDialTimeout bounds TCP connection establishment.
	hardenedDialTimeout = 10 * time.Second
	// hardenedTLSHandshakeTimeout bounds the TLS handshake.
	hardenedTLSHandshakeTimeout = 10 * time.Second
	// hardenedResponseHeaderTimeout bounds the wait for response headers.
	hardenedResponseHeaderTimeout = 30 * time.Second
	// hardenedIdleConnTimeout bounds idle keep-alive connections.
	hardenedIdleConnTimeout = 90 * time.Second
)

// hardenedDialer is the provider dialer: bounded TCP establishment with
// keep-alive. It is a package variable so tests can pin its bounds.
var hardenedDialer = &net.Dialer{
	Timeout:   hardenedDialTimeout,
	KeepAlive: 30 * time.Second,
}

// hardenedTransport returns the provider transport with explicit dial, TLS,
// response-header and idle timeouts. It mirrors the S3 store transport so
// every credential-bearing HTTP path in the control plane is bounded the
// same way.
func hardenedTransport() *http.Transport {
	return &http.Transport{
		DialContext:           hardenedDialer.DialContext,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       hardenedIdleConnTimeout,
		TLSHandshakeTimeout:   hardenedTLSHandshakeTimeout,
		ResponseHeaderTimeout: hardenedResponseHeaderTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
}

// hardenedClient returns the default provider client: a finite total
// timeout, the hardened transport, and redirect refusal (the redirect
// response is surfaced as-is; the caller's Authorization header is never
// replayed to a Location target).
func hardenedClient() *http.Client {
	return &http.Client{
		Timeout:       hardenedTotalTimeout,
		Transport:     hardenedTransport(),
		CheckRedirect: refuseRedirects,
	}
}

// refuseRedirects is the redirect policy shared by every provider client.
func refuseRedirects(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// providerClient resolves the client a provider must use: the hardened
// default, or a hardened copy of the configured client (an injected client's
// transport is preserved for tests, but a zero total timeout becomes the
// hardened bound and redirect refusal is always enforced on the copy).
func providerClient(configured *http.Client) *http.Client {
	if configured == nil {
		return hardenedClient()
	}
	c := *configured
	if c.Timeout <= 0 {
		c.Timeout = hardenedTotalTimeout
	}
	if c.Transport == nil {
		c.Transport = hardenedTransport()
	}
	c.CheckRedirect = refuseRedirects
	return &c
}

// devAllowLoopbackHTTPEnv is the explicit, process-wide escape hatch for
// cleartext loopback endpoints. Without it, http:// is rejected even for a
// loopback host: production deployments must never silently downgrade a
// credential-bearing transport.
const devAllowLoopbackHTTPEnv = "KIWI_DEV_ALLOW_LOOPBACK_HTTP"

// isLoopbackHost reports whether host is one of the exact loopback names the
// cleartext escape hatch admits. Wildcard and alternate loopback addresses
// (for example 127.0.0.2) are deliberately excluded so the exception stays
// minimal and auditable.
func isLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

// credentialQueryKey reports whether a query parameter name suggests a
// credential riding the URL. URLs are logged, indexed and cached, so a
// secret in a query string leaks through paths the process does not control.
func credentialQueryKey(key string) bool {
	k := strings.ToLower(key)
	for _, marker := range []string{"token", "key", "secret", "password", "passwd", "credential", "sig", "auth", "session", "apikey", "api_key"} {
		if strings.Contains(k, marker) {
			return true
		}
	}
	return false
}

// validateProviderEndpoint validates a configured secret-provider base URL:
//
//   - only http and https schemes are accepted;
//   - the URL must have a host, no userinfo and no fragment (userinfo would
//     smuggle credentials into every request line and log it);
//   - query parameters that look credential-bearing are rejected;
//   - https is always accepted; cleartext http is accepted only when the
//     caller opted in (allowLoopbackHTTP), the host is an exact loopback
//     name, and the process set KIWI_DEV_ALLOW_LOOPBACK_HTTP=1.
//
// Providers call it before every request so a misconfigured endpoint fails
// closed instead of leaking credentials over an unvalidated origin.
func validateProviderEndpoint(rawURL string, allowLoopbackHTTP bool) error {
	if strings.TrimSpace(rawURL) == "" {
		return fmt.Errorf("provider endpoint: empty address")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("provider endpoint %q: %w", rawURL, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("provider endpoint %q: unsupported scheme %q", rawURL, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("provider endpoint %q: address has no host", rawURL)
	}
	if u.User != nil {
		return fmt.Errorf("provider endpoint %q: userinfo is not allowed", rawURL)
	}
	if u.Fragment != "" {
		return fmt.Errorf("provider endpoint %q: fragments are not allowed", rawURL)
	}
	for key := range u.Query() {
		if credentialQueryKey(key) {
			return fmt.Errorf("provider endpoint %q: query parameter %q must not carry credentials", rawURL, key)
		}
	}
	if strings.ToLower(u.Scheme) == "http" {
		if !allowLoopbackHTTP || !isLoopbackHost(u.Hostname()) || os.Getenv(devAllowLoopbackHTTPEnv) != "1" {
			return fmt.Errorf("provider endpoint %q: insecure http address rejected (https required; loopback http requires %s=1)", rawURL, devAllowLoopbackHTTPEnv)
		}
	}
	return nil
}
