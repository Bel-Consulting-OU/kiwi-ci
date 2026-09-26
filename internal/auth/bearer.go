package auth

import (
	"strings"
	"unicode"
)

// bearerPrefix is the ONE accepted authorization scheme spelling. The scheme
// is case-sensitive on purpose: every caller in this codebase emits exactly
// "Bearer ", and accepting deviant spellings would fragment the credential
// grammar across endpoints.
const bearerPrefix = "Bearer "

// ParseBearer extracts the credential from an HTTP Authorization header.
//
// The grammar is strict and shared by every bearer-parsing site (the auth
// middleware, the server's tier gates, runner token resolution, enrollment
// and the OIDC issuance endpoint):
//
//   - the header must carry the exact "Bearer " scheme prefix. A header that
//     IS the raw credential (no scheme) is NOT a bearer presentation and is
//     rejected; the previous strings.TrimPrefix pattern silently accepted it;
//   - the token is trimmed of surrounding whitespace and must be non-empty;
//   - whitespace or a comma inside the token is rejected, so a header can
//     never smuggle a credential list or a padded variant through.
//
// ok=false means the header is not a well-formed bearer presentation; callers
// must treat it exactly like a missing header (401/absent credential), never
// as "the raw header is the token".
func ParseBearer(h string) (string, bool) {
	if !strings.HasPrefix(h, bearerPrefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(bearerPrefix):])
	if tok == "" {
		return "", false
	}
	for _, r := range tok {
		if r == ',' || unicode.IsSpace(r) {
			return "", false
		}
	}
	return tok, true
}
