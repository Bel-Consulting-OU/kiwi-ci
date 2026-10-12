package server

import (
	"net/http"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/verifyapi"
)

// verificationPrefix is the additive verification substrate subtree.
const verificationPrefix = "/api/v1/verifications/"

// verificationPrincipal adapts the server's request authentication onto the
// verifyapi.Service principal. Fail closed: without a store principal or a
// valid admin bearer the facade answers 401 before any store work. The
// authority scope is looked up in VerificationScopes by principal subject;
// every configured scope must be a strict SubjectRef hierarchy
// (ValidateHierarchy / ValidateScopes) and an unlisted or malformed entry
// yields no capabilities. Authority is capability-shaped: the principal
// receives CapabilitiesIn(scope), and admin break-glass is ONLY the explicit
// GlobalVerificationAdmin capability — never a zero SubjectRef.
func (s *Server) verificationPrincipal(r *http.Request) (verifyapi.Principal, bool) {
	if p, ok := auth.PrincipalFrom(r); ok {
		return verifyapi.Principal{
			Subject:      p.Subject,
			Capabilities: s.verificationCapabilities(p.Subject, p.Has(auth.RoleAdmin)),
		}, true
	}
	// Admin-token callers are not store principals; map them to an explicit
	// GlobalVerificationAdmin principal so the break-glass path still
	// reaches the Service's Authorizer (and is audited there).
	if s.AdminToken != "" && bearerOK(r.Header.Get("Authorization"), s.AdminToken) {
		return verifyapi.Principal{
			Subject:      "admin",
			Capabilities: []verifyapi.Capability{verifyapi.GlobalVerificationAdmin},
		}, true
	}
	return verifyapi.Principal{}, false
}

// verificationCapabilities builds the capability set for a subject. The
// configured scope must pass ValidateHierarchy (defense in depth on top of
// config load: a malformed partial hierarchy grants nothing); the admin
// role maps to the explicit GlobalVerificationAdmin capability and never to
// a zero-ref wildcard.
func (s *Server) verificationCapabilities(subject string, adminRole bool) []verifyapi.Capability {
	var caps []verifyapi.Capability
	if scope, ok := s.VerificationScopes[subject]; ok && scope.ValidateHierarchy() == nil {
		caps = append(caps, verifyapi.CapabilitiesIn(scope)...)
	}
	if adminRole {
		caps = append(caps, verifyapi.GlobalVerificationAdmin)
	}
	return caps
}

// SetVerificationScopes loads the authority scope map used by the
// verification facade (typically from server configuration). Every scope
// must be a strict SubjectRef hierarchy (namespace[/tenant[/project[/repository]]])
// — validate via verifyapi.ValidateScopes, which refuses malformed partial
// shapes such as tenant-only or namespace/project. A refusal leaves the
// previous map in place; scopes are never partially installed.
func (s *Server) SetVerificationScopes(scopes map[string]verifyapi.SubjectRef) error {
	if err := verifyapi.ValidateScopes(scopes); err != nil {
		return err
	}
	s.VerificationScopes = scopes
	return nil
}

// mountVerifications registers the additive /api/v1/verifications/* facade
// when a Service is configured. Method-prefixed subtree patterns are
// required so the registration does not conflict with the "GET /" catch-all;
// the ServiceHandler owns fine-grained method routing inside the subtree.
// The surface is opt-in: without a Service the routes are not registered and
// the subtree is absent (404).
func (s *Server) mountVerifications(mux *http.ServeMux) {
	if s.Verification == nil {
		return
	}
	h := verifyapi.ServiceHandler(s.Verification, s.verificationPrincipal)
	mux.Handle("GET "+verificationPrefix, h)
	mux.Handle("POST "+verificationPrefix, h)
}
