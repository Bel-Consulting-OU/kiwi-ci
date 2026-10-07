package config

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func mustParseIP(t *testing.T, raw string) net.IP {
	t.Helper()
	ip := net.ParseIP(raw)
	if ip == nil {
		t.Fatalf("ParseIP(%q) failed", raw)
	}
	return ip
}

// TestTrustedProxiesTOML pins the server.trusted_proxies schema: an inline
// array of CIDR strings is decoded into the config and parsed into nets.
func TestTrustedProxiesTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kiwi.toml")
	body := "[server]\ntrusted_proxies = [\"10.0.0.0/8\", \"192.168.1.0/24\"]\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Server.TrustedProxies) != 2 {
		t.Fatalf("trusted proxies = %v, want 2 entries", cfg.Server.TrustedProxies)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	nets := cfg.TrustedProxyNets()
	if len(nets) != 2 {
		t.Fatalf("TrustedProxyNets = %d nets, want 2", len(nets))
	}
	if !nets[0].Contains(mustParseIP(t, "10.1.2.3")) || !nets[1].Contains(mustParseIP(t, "192.168.1.9")) {
		t.Fatalf("parsed nets do not cover the configured ranges: %v", nets)
	}
}

// TestTrustedProxiesValidationRejectsInvalid: a typo in a trust range must
// fail startup instead of silently trusting nothing (or a wrong prefix).
func TestTrustedProxiesValidationRejectsInvalid(t *testing.T) {
	c := Default()
	c.Server.TrustedProxies = []string{"10.0.0.0/8", "not-a-cidr"}
	if err := c.Validate(); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
	c = Default()
	c.Server.TrustedProxies = []string{""}
	if err := c.Validate(); err == nil {
		t.Fatal("empty entry accepted")
	}
	c = Default()
	c.Server.TrustedProxies = []string{"10.0.0.0/8"}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid CIDR rejected: %v", err)
	}
	if got := len(c.TrustedProxyNets()); got != 1 {
		t.Fatalf("TrustedProxyNets = %d, want 1", got)
	}
}

// TestTrustedProxiesEnvOverride: the comma-separated environment override is
// applied, and an empty value never clears a configured list.
func TestTrustedProxiesEnvOverride(t *testing.T) {
	t.Setenv("KIWI_SERVER_TRUSTED_PROXIES", "10.0.0.0/8, 192.168.0.0/16")
	c := Default()
	if err := c.ApplyEnv(); err != nil {
		t.Fatal(err)
	}
	if len(c.Server.TrustedProxies) != 2 {
		t.Fatalf("env trusted proxies = %v, want 2", c.Server.TrustedProxies)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	t.Setenv("KIWI_SERVER_TRUSTED_PROXIES", "")
	c = Default()
	c.Server.TrustedProxies = []string{"10.0.0.0/8"}
	if err := c.ApplyEnv(); err != nil {
		t.Fatal(err)
	}
	if len(c.Server.TrustedProxies) != 1 {
		t.Fatalf("empty env cleared the configured trusted proxies: %v", c.Server.TrustedProxies)
	}
}

// TestRateLimitMiddlewareCarriesTrustedProxies: the existing app wiring
// (srv.RateLimiter = cfg.RateLimitMiddleware()) must carry the trusted-proxy
// ranges to the canonical-IP resolver.
func TestRateLimitMiddlewareCarriesTrustedProxies(t *testing.T) {
	c := Default()
	c.Server.TrustedProxies = []string{"10.0.0.0/8"}
	m := c.RateLimitMiddleware()
	if m == nil {
		t.Fatal("RateLimitMiddleware returned nil for default rates")
	}
	if len(m.TrustedProxies) != 1 {
		t.Fatalf("middleware trusted proxies = %d, want 1", len(m.TrustedProxies))
	}
	// No configured proxies -> no trust.
	c = Default()
	m = c.RateLimitMiddleware()
	if m == nil || len(m.TrustedProxies) != 0 {
		t.Fatalf("unexpected trusted proxies without configuration: %+v", m)
	}
}
