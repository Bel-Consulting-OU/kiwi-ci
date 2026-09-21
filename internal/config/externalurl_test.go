package config

import (
	"strings"
	"testing"
)

// TestExternalURLValidationMatchesOIDC pins the shared policy behind B5-B:
// every value malformed for the OIDC startup path is rejected by
// config.Validate at startup, so a value that passes validation can never
// later make the OIDC endpoints answer 503. The OIDC profile (no mode, the
// permissive superset) and the dev-mode config profile accept exactly the
// same values; production is the strict subset that also forbids plaintext
// loopback.
func TestExternalURLValidationMatchesOIDC(t *testing.T) {
	cases := []struct {
		name string
		url  string
		mode string
		want bool
	}{
		{"https production", "https://ci.example.com", "production", true},
		{"https trailing slashes normalized", "https://ci.example.com///", "production", true},
		{"https with path", "https://ci.example.com/kiwi", "production", true},
		{"https with port", "https://ci.example.com:8443", "production", true},
		{"https localhost production", "https://localhost", "production", true},
		{"http production rejected", "http://ci.example.com", "production", false},
		{"http loopback production rejected", "http://localhost:8080", "production", false},
		{"http loopback dev allowed", "http://localhost:8080", "dev", true},
		{"http 127 dev allowed", "http://127.0.0.1:9000", "dev", true},
		{"http ipv6 loopback dev allowed", "http://[::1]:9000", "dev", true},
		{"http remote dev rejected", "http://ci.internal", "dev", false},
		{"loopback lookalike rejected", "http://localhost.evil.example", "dev", false},
		{"loopback prefix lookalike rejected", "http://localhostfoo", "dev", false},
		{"ip lookalike rejected", "http://127.0.0.1.attacker.test", "dev", false},
		{"https without host rejected", "https://", "production", false},
		{"host-less https path rejected", "https:///ci.example.com", "production", false},
		{"scheme-relative rejected", "//ci.example.com", "production", false},
		{"non-http scheme rejected", "ftp://ci.example.com", "production", false},
		{"userinfo rejected", "https://user:pw@ci.example.com", "production", false},
		{"query rejected", "https://ci.example.com?x=1", "production", false},
		{"fragment rejected", "https://ci.example.com#frag", "production", false},
		{"relative rejected", "not a url", "production", false},
		{"empty production rejected", "", "production", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateExternalURL(tc.url, tc.mode)
			if tc.want != (err == nil) {
				t.Fatalf("ValidateExternalURL(%q, %q) err=%v, want ok=%v", tc.url, tc.mode, err, tc.want)
			}
			if tc.want {
				want := strings.TrimRight(tc.url, "/")
				if got != want {
					t.Fatalf("normalized URL = %q, want %q", got, want)
				}
				if strings.HasSuffix(got, "/") {
					t.Fatalf("normalized URL kept a trailing slash: %q", got)
				}
			}

			// The OIDC startup profile is the permissive superset: whatever
			// config validation accepts, the OIDC path accepts too. The
			// reverse may differ only because production is stricter.
			_, oidcErr := ValidateExternalURL(tc.url, "")

			cfg := Default()
			cfg.Server.Mode = tc.mode
			cfg.Server.ExternalURL = tc.url
			cfgErr := cfg.Validate()
			if tc.url == "" && tc.mode != "production" {
				// An empty external_url is legitimately optional outside
				// production (OIDC answers 503 until it is configured).
				if cfgErr != nil {
					t.Fatalf("empty dev external_url rejected: %v", cfgErr)
				}
				return
			}
			if (cfgErr == nil) != tc.want {
				t.Fatalf("config.Validate(%q, mode %q) err=%v, want ok=%v", tc.url, tc.mode, cfgErr, tc.want)
			}
			if cfgErr == nil && oidcErr != nil {
				t.Fatalf("config accepted %q but OIDC startup rejects it: %v", tc.url, oidcErr)
			}
			if tc.want && tc.mode == "dev" && oidcErr != nil {
				t.Fatalf("valid dev value %q rejected by the OIDC profile: %v", tc.url, oidcErr)
			}
		})
	}
}
