package server

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/config"
)

// TestOIDCIssuerUsesSharedExternalURLValidator proves the OIDC startup path
// and config validation share ONE parsed-URL validator: oidcIssuer accepts
// exactly the values config.ValidateExternalURL accepts in the OIDC profile
// and returns the same normalized issuer, so a value that passes config
// validation can never later turn every OIDC request into a 503.
func TestOIDCIssuerUsesSharedExternalURLValidator(t *testing.T) {
	values := []string{
		"https://ci.example.com",
		"https://ci.example.com/",
		"https://ci.example.com/base/",
		"https://ci.example.com:8443",
		"http://localhost",
		"http://localhost:8080",
		"http://127.0.0.1:9000",
		"http://[::1]:9000",
		"https://LOCALHOST",
		"http://localhost.evil.example",
		"http://localhostfoo",
		"http://127.0.0.1.attacker.test",
		"https://",
		"https:///ci.example.com",
		"//ci.example.com",
		"ftp://ci.example.com",
		"https://user:pw@ci.example.com",
		"https://ci.example.com?x=1",
		"https://ci.example.com#frag",
		"not a url",
	}
	for _, raw := range values {
		want, wantErr := config.ValidateExternalURL(raw, "")
		s := New("secret")
		s.ExternalURL = raw
		got, err := s.oidcIssuer()
		if (err == nil) != (wantErr == nil) {
			t.Errorf("oidcIssuer(%q) err=%v, shared validator err=%v", raw, err, wantErr)
			continue
		}
		if err == nil && got != want {
			t.Errorf("oidcIssuer(%q) = %q, shared validator = %q", raw, got, want)
		}
	}
}
