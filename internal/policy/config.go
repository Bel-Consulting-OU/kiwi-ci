package policy

// OIDCPolicy declares which audiences a job may request OIDC id_tokens for.
type OIDCPolicy struct {
	AllowedAudiences []string
}

// Allows reports whether audience is permitted. A nil AllowedAudiences means
// no restriction (trusted default); an empty non-nil slice denies everything.
func (p OIDCPolicy) Allows(audience string) bool {
	if p.AllowedAudiences == nil {
		return true
	}
	return containsString(p.AllowedAudiences, audience)
}

// OIDCFromCapabilities converts a capability set's OIDC audiences into an
// OIDCPolicy for id_token issuance checks.
func OIDCFromCapabilities(c Capabilities) OIDCPolicy {
	return OIDCPolicy{AllowedAudiences: c.OIDC}
}
