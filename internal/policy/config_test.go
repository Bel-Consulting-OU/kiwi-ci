package policy

import "testing"

func TestOIDCPolicyAllows(t *testing.T) {
	unrestricted := OIDCPolicy{AllowedAudiences: nil}
	if !unrestricted.Allows("anything") {
		t.Fatal("nil AllowedAudiences must allow any audience")
	}
	deny := OIDCPolicy{AllowedAudiences: []string{}}
	if deny.Allows("anything") {
		t.Fatal("empty AllowedAudiences must deny every audience")
	}
	restricted := OIDCPolicy{AllowedAudiences: []string{"ci.example.com"}}
	if !restricted.Allows("ci.example.com") {
		t.Fatal("allowlisted audience must be allowed")
	}
	if restricted.Allows("evil.example.com") {
		t.Fatal("non-allowlisted audience must be denied")
	}
}

func TestOIDCFromCapabilities(t *testing.T) {
	if p := OIDCFromCapabilities(DefaultTrustedCapabilities()); !p.Allows("any") {
		t.Fatal("trusted capabilities must map to an unrestricted OIDCPolicy")
	}
	if p := OIDCFromCapabilities(DefaultUntrustedCapabilities()); p.Allows("any") {
		t.Fatal("untrusted capabilities must map to a deny-all OIDCPolicy")
	}
	p := OIDCFromCapabilities(Capabilities{OIDC: []string{"aud1"}})
	if !p.Allows("aud1") || p.Allows("aud2") {
		t.Fatal("OIDCPolicy must mirror the capability audiences")
	}
}
