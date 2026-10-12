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
// SubjectRef scope is looked up in VerificationScopes by principal subject;
// an unlisted subject gets a zero scope (denied for named subjects by
// ScopeAuthorizer) unless the principal holds the admin role.
func (s *Server) verificationPrincipal(r *http.Request) (verifyapi.Principal, bool) {
	if p, ok := auth.PrincipalFrom(r); ok {
		return verifyapi.Principal{
			Subject: p.Subject,
			Scope:   s.VerificationScopes[p.Subject],
			Admin:   p.Has(auth.RoleAdmin),
		}, true
	}
	// Admin-token callers are not store principals; map them to an admin
	// verification principal so the break-glass path still reaches the
	// Service's Authorizer.
	if s.AdminToken != "" && bearerOK(r.Header.Get("Authorization"), s.AdminToken) {
		return verifyapi.Principal{Subject: "admin", Admin: true}, true
	}
	return verifyapi.Principal{}, false
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
