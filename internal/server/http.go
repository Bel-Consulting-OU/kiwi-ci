package server

import "net/http"

// NoRedirectClient returns a copy of base that never follows redirects.
// Credential-bearing clients must not transparently forward Authorization
// headers or tokens to a different origin; a redirect response is surfaced
// to the caller as-is (http.ErrUseLastResponse). The caller's client is not
// mutated.
func NoRedirectClient(base *http.Client) *http.Client {
	if base == nil {
		base = &http.Client{}
	}
	c := *base
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}
