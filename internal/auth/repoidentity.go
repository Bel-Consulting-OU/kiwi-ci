package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// This file defines the typed repository identity used by every authorization,
// lease, test-intelligence and canonicalization decision in the control
// plane. Repository identity used to be inferred from strings by "does the
// first path segment contain a dot" (splitHostLike/splitCanonicalRepo/
// splitForgeRepoKey). A dotless host ID such as "gitlab/acme/widget" (single
// label internal DNS) is indistinguishable from a bare nested group name by
// that heuristic: a grant for the canonical repository gitlab/acme/widget
// matched the bare alias portion of the unrelated canonical repository
// forge.example/gitlab/acme/widget. No string heuristic fixes this because
// the string itself is ambiguous; identity must be typed and explicit.
//
// The types below make the distinction part of the value:
//
//   - RepoIdentity is a canonical, forge-scoped identity whose Host is
//     REQUIRED and explicit. An identity is compared to another identity by
//     (canonical host, full name) equality only.
//   - RepoAlias is a bare, host-less name. It is NOT an identity: it
//     addresses every forge that presents the name, so it is only ever
//     matched against an EXPLICIT bare grant (never inferred from a
//     canonical grant, and never treated as the host portion of a canonical
//     string).
//   - RepoGrant is the parsed form of a repository ACL grant: exactly one of
//     an identity or an alias.
//
// # Serialized forms
//
// Canonical identities and bare aliases each have an unambiguous serialized
// spelling used by ACL configuration (see TokenStore.Load):
//
//   - identity: "r1:<base64url(host)>:<base64url(full_name)>"
//   - alias:    "a1:<base64url(full_name)>" (or the plain "owner/name"
//     spelling, which is unambiguous for exactly two path segments because a
//     canonical identity always carries a host plus at least owner/name, i.e.
//     three path segments)
//
// The base64url parts are RawURLEncoding (no "=" padding). The parser is
// strict: malformed, padded, empty or whitespace-bearing parts are rejected,
// and a bare string is rejected wherever a canonical identity is required
// (ParseRepoIdentity).
//
// # Legacy migration rule
//
// Persisted repository IDs (run/job/schedule records) and in-process ACL maps
// written before typed identity carry the legacy "host/owner/name" spelling
// produced by CanonicalRepoID. That spelling is read with the documented
// positional rule: a string with three or more path segments is the canonical
// identity whose host is the FIRST segment and whose full name is the
// remainder; a string with fewer segments is a bare alias. The rule never
// consults dots, so a dotless host parses exactly like a dotted one.
//
// ACL CONFIGURATION is stricter and fails closed (ParseRepoGrantConfig,
// TokenStore.Load): a legacy string with three or more path segments is
// AMBIGUOUS (it could read as a bare nested name), so loading it is refused
// with an error naming the string and both accepted spellings. Operators must
// spell such a grant as "r1:<base64url(host)>:<base64url(full_name)>" or, for
// a bare alias, as "a1:<base64url(full_name)>" (or plain "owner/name" when the
// name has exactly two segments).
const (
	// RepoIdentityPrefix tags the unambiguous serialized form of a canonical
	// repository identity.
	RepoIdentityPrefix = "r1:"
	// RepoAliasPrefix tags the unambiguous serialized form of a bare alias
	// whose full name is not the plain two-segment "owner/name" spelling.
	RepoAliasPrefix = "a1:"
)

// ErrRepoGrantAmbiguous reports that a repository ACL grant string is a
// legacy ambiguous spelling: a string with three or more path segments and no
// explicit r1:/a1: tag. It could name host "first-segment" plus a full name, or
// a bare nested group path; guessing either way is the defect this package
// eliminates, so loading or validating such a grant fails closed. The error
// names the string and the two accepted spellings.
var ErrRepoGrantAmbiguous = errors.New("auth: ambiguous legacy repository grant")

// RepoGrantError is the parse/validation error of one repository grant
// string. It carries the offending string so operators can fix the exact
// entry; ambiguous legacy spellings match ErrRepoGrantAmbiguous through
// errors.Is.
type RepoGrantError struct {
	// Grant is the offending grant string, quoted in Error.
	Grant string
	// Ambiguous reports whether the string is a legacy ambiguous spelling
	// (as opposed to malformed or empty input).
	Ambiguous bool
	// Detail explains the rejection.
	Detail string
}

func (e *RepoGrantError) Error() string {
	if e.Ambiguous {
		return fmt.Sprintf("%v %q: %s; spell a canonical identity as %s<base64url(host)>:<base64url(full_name)> (for example %q) or a bare alias as %s<base64url(full_name)> / owner/name (for example %q)",
			ErrRepoGrantAmbiguous, e.Grant, e.Detail, RepoIdentityPrefix, exampleIdentitySerialized, RepoAliasPrefix, exampleAliasSerialized)
	}
	return fmt.Sprintf("auth: invalid repository grant %q: %s", e.Grant, e.Detail)
}

// Is makes errors.Is(err, ErrRepoGrantAmbiguous) succeed for ambiguous
// legacy grants.
func (e *RepoGrantError) Is(target error) bool {
	return e.Ambiguous && target == ErrRepoGrantAmbiguous
}

// Example spellings embedded in the ambiguity error. They are constants so
// the operator-facing message is stable and the error text can be asserted.
const (
	exampleIdentitySerialized = "r1:Z2l0bGFi:YWNtZS93aWRnZXQ"
	exampleAliasSerialized    = "a1:Z3JvdXAvc3ViL3Byb2plY3Q"
)

// RepoIdentity is a canonical, forge-scoped repository identity. Host is the
// canonical forge host (see CanonicalHost) and is required; FullName is the
// forge-native repository path (owner/name, nested group paths allowed). Two
// identities are the same repository exactly when both fields are equal.
//
// The FullName is case-folded to ONE canonical form (see FoldRepoFullName):
// repository path case is NOT identity-bearing. The forges Kiwi supports treat
// owner/name case-insensitively, and an unfolded path let
// repo_url=https://github.com/Acme/Backend.git persist
// "github.com/Acme/Backend" and bypass an explicit
// "github.com/acme/backend" deny plus every repository policy. Every
// constructor, parser and comparator folds the path, so all spellings of one
// repository resolve to the same identity.
type RepoIdentity struct {
	Host     string
	FullName string
}

// RepoAlias is a bare, host-less repository name ("owner/name", possibly a
// nested group path). An alias is not an identity: it addresses every forge
// presenting the name and therefore only ever matches an explicit bare grant.
// Its FullName is folded like an identity's.
type RepoAlias struct {
	FullName string
}

// FoldRepoFullName canonicalizes the case of a repository full name (path)
// onto the ONE folded form every identity uses: ASCII A-Z are lowercased.
// Repository paths are case-insensitive on the forges Kiwi supports, and path
// case used to be identity-bearing (a mixed-case clone URL stored an unfolded
// canonical ID and bypassed an explicit lowercase deny and its policies).
//
// Only ASCII is folded, deliberately: PostgreSQL's LOWER() folds ASCII
// identically, so the Go identity and the SQL kiwi_canonical_repo_id /
// kiwi_normalize_* functions agree byte-for-byte on every path that can name a
// repository (the forges restrict repository paths to ASCII). The forge HOST
// is folded separately by CanonicalHost.
func FoldRepoFullName(s string) string {
	upper := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			upper = true
			break
		}
	}
	if !upper {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// RepoGrantKind classifies a parsed repository ACL grant.
type RepoGrantKind int

const (
	// RepoGrantInvalid is the zero kind: not a usable grant.
	RepoGrantInvalid RepoGrantKind = iota
	// RepoGrantIdentity is a canonical, forge-scoped grant.
	RepoGrantIdentity
	// RepoGrantAlias is a bare, host-less grant.
	RepoGrantAlias
)

// RepoGrant is a parsed repository ACL grant: exactly one of a canonical
// identity or a bare alias. The zero value is invalid and matches nothing.
type RepoGrant struct {
	kind  RepoGrantKind
	ident RepoIdentity
	alias RepoAlias
}

// IdentityGrant wraps an explicit canonical identity as a grant.
func IdentityGrant(id RepoIdentity) RepoGrant {
	return RepoGrant{kind: RepoGrantIdentity, ident: id}
}

// AliasGrant wraps an explicit bare alias as a grant.
func AliasGrant(a RepoAlias) RepoGrant {
	return RepoGrant{kind: RepoGrantAlias, alias: a}
}

// Kind reports the grant kind.
func (g RepoGrant) Kind() RepoGrantKind { return g.kind }

// IsIdentity reports whether the grant is a canonical, host-scoped identity.
func (g RepoGrant) IsIdentity() bool { return g.kind == RepoGrantIdentity }

// IsAlias reports whether the grant is a bare, host-less alias.
func (g RepoGrant) IsAlias() bool { return g.kind == RepoGrantAlias }

// Identity returns the canonical identity and true for identity grants. The
// returned value is normalized (path case folded), so a directly constructed
// grant can never compare unfolded.
func (g RepoGrant) Identity() (RepoIdentity, bool) {
	if g.kind != RepoGrantIdentity {
		return RepoIdentity{}, false
	}
	return g.ident.normalized(), true
}

// Alias returns the bare alias and true for alias grants. The returned value
// is normalized (path case folded).
func (g RepoGrant) Alias() (RepoAlias, bool) {
	if g.kind != RepoGrantAlias {
		return RepoAlias{}, false
	}
	return g.alias.normalized(), true
}

// normalized returns the identity with its full name folded onto the one
// canonical path form. The host is left as-is (constructors canonicalize it;
// a directly constructed value is not silently reinterpreted).
func (id RepoIdentity) normalized() RepoIdentity {
	return RepoIdentity{Host: id.Host, FullName: FoldRepoFullName(id.FullName)}
}

// normalized returns the alias with its full name folded.
func (a RepoAlias) normalized() RepoAlias {
	return RepoAlias{FullName: FoldRepoFullName(a.FullName)}
}

// AuthorizationID is the value a canonical lookup compares against the
// persisted canonical repository ID: the identity's "host/fullName" string,
// or the alias' bare full name. It never mixes the two: an alias only ever
// matches bare grants (see Principal.repoEntryGrant).
func (g RepoGrant) AuthorizationID() string {
	switch g.kind {
	case RepoGrantIdentity:
		return g.ident.ID()
	case RepoGrantAlias:
		return g.alias.normalized().FullName
	}
	return ""
}

// Serialized renders the grant in its explicit ACL spelling. Identity grants
// always render as the r1: form; alias grants render as the plain owner/name
// spelling when that spelling is unambiguous (exactly one slash), and as the
// a1: form otherwise.
func (g RepoGrant) Serialized() string {
	switch g.kind {
	case RepoGrantIdentity:
		return g.ident.Serialized()
	case RepoGrantAlias:
		return g.alias.Serialized()
	}
	return ""
}

// ID renders the canonical identity as the legacy "host/fullName" string used
// by storage, SQL comparisons and persisted records. The value always carries
// the explicit canonical host and the FOLDED full name (see FoldRepoFullName);
// an empty FullName yields "".
func (id RepoIdentity) ID() string {
	if id.Host == "" || id.FullName == "" {
		return ""
	}
	return id.Host + "/" + FoldRepoFullName(id.FullName)
}

// Serialized renders the identity in the unambiguous ACL form
// "r1:<base64url(host)>:<base64url(full_name)>". The full name part is folded.
func (id RepoIdentity) Serialized() string {
	if id.Host == "" || id.FullName == "" {
		return ""
	}
	return RepoIdentityPrefix + base64.RawURLEncoding.EncodeToString([]byte(id.Host)) +
		":" + base64.RawURLEncoding.EncodeToString([]byte(FoldRepoFullName(id.FullName)))
}

// String renders the identity in its canonical storage form, identical to ID.
func (id RepoIdentity) String() string { return id.ID() }

// Serialized renders the alias in its explicit ACL spelling: the plain
// "owner/name" form when the name has exactly one slash (unambiguous: a
// canonical identity always needs a host in front of owner/name), the
// "a1:<base64url(full_name)>" form otherwise. The full name is folded.
func (a RepoAlias) Serialized() string {
	if a.FullName == "" {
		return ""
	}
	full := FoldRepoFullName(a.FullName)
	if strings.Count(full, "/") == 1 {
		return full
	}
	return RepoAliasPrefix + base64.RawURLEncoding.EncodeToString([]byte(full))
}

// String renders the alias as its bare folded full name.
func (a RepoAlias) String() string { return FoldRepoFullName(a.FullName) }

// CanonicalHostIdentity canonicalizes host and fullName into a RepoIdentity:
// the host is normalized with CanonicalHost, the full name is trimmed, and a
// full name that already starts with a canonically equivalent spelling of the
// KNOWN host is reduced to its remainder (so re-canonicalizing a persisted
// identity is idempotent). The host is never inferred from the full name: a
// name that embeds a different host stays part of the full name, keeping the
// identity host-scoped. host must canonicalize to a non-empty value.
func CanonicalHostIdentity(host, fullName string) (RepoIdentity, error) {
	h, full := canonicalRepoParts(host, fullName)
	if h == "" {
		return RepoIdentity{}, fmt.Errorf("auth: canonical repository identity requires a host")
	}
	if !validCanonicalHost(h) {
		return RepoIdentity{}, fmt.Errorf("auth: invalid forge host %q", host)
	}
	if err := validateFullName(full, true); err != nil {
		return RepoIdentity{}, err
	}
	return RepoIdentity{Host: h, FullName: full}, nil
}

// CanonicalHostAlias canonicalizes a bare full name into a RepoAlias. The
// full name is folded onto the one canonical path form.
func CanonicalHostAlias(fullName string) (RepoAlias, error) {
	a := RepoAlias{FullName: FoldRepoFullName(strings.TrimSpace(fullName))}
	if err := validateFullName(a.FullName, false); err != nil {
		return RepoAlias{}, err
	}
	return a, nil
}

// canonicalRepoParts implements the legacy CanonicalRepoID derivation without
// any shape heuristic: it canonicalizes a KNOWN host, trims the full name,
// and strips one leading segment from the full name only when that segment
// canonicalizes to exactly the known host and an owner/name remainder follows.
//
// A host of "" (the caller knows no host) keeps the trimmed full name
// unchanged; the host is never guessed from the name.
func canonicalRepoParts(host, fullName string) (canonHost, canonFull string) {
	canonFull = FoldRepoFullName(strings.TrimSpace(fullName))
	if canonFull == "" {
		return CanonicalHost(host), ""
	}
	canonHost = CanonicalHost(host)
	if canonHost != "" {
		if first, rest, ok := splitFirstPathSegment(canonFull); ok &&
			CanonicalHost(first) == canonHost && strings.Contains(rest, "/") {
			canonFull = rest
		}
	}
	return canonHost, canonFull
}

// validCanonicalHost reports whether a canonical host is a usable host value:
// non-empty, no whitespace, no path separator, no userinfo. Bracketed IPv6
// literals pass (their colons are internal).
func validCanonicalHost(host string) bool {
	if host == "" || strings.ContainsAny(host, " \t\r\n/?#@") {
		return false
	}
	if strings.HasPrefix(host, "[") {
		end := strings.Index(host, "]")
		return end > 1 && !strings.ContainsAny(host[end+1:], " \t\r\n")
	}
	return true
}

// splitFirstPathSegment splits "first/rest" on the first slash.
func splitFirstPathSegment(s string) (first, rest string, ok bool) {
	i := strings.Index(s, "/")
	if i <= 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// validateFullName rejects malformed repository full names: empty, surrounding
// or interior whitespace, empty path segments, a trailing slash, and control
// characters. requireSlash additionally demands at least owner/name (used for
// canonical identities, whose full name always has an owner segment).
func validateFullName(full string, requireSlash bool) error {
	if full == "" {
		return fmt.Errorf("empty repository full name")
	}
	if strings.TrimSpace(full) != full {
		return fmt.Errorf("repository full name %q has surrounding whitespace", full)
	}
	if strings.ContainsAny(full, " \t\r\n\x00") {
		return fmt.Errorf("repository full name %q contains whitespace or control characters", full)
	}
	if strings.HasPrefix(full, "/") || strings.HasSuffix(full, "/") || strings.Contains(full, "//") {
		return fmt.Errorf("repository full name %q has an empty path segment", full)
	}
	if requireSlash && !strings.Contains(full, "/") {
		return fmt.Errorf("repository full name %q has no owner/name path", full)
	}
	return nil
}

// ParseRepoIdentity parses the strict, unambiguous canonical identity spelling
// "r1:<base64url(host)>:<base64url(full_name)>". Malformed, padded, empty or
// whitespace-bearing parts are rejected, and a bare (untagged) string is
// rejected in this canonical position. The host is canonicalized.
func ParseRepoIdentity(s string) (RepoIdentity, error) {
	if !strings.HasPrefix(s, RepoIdentityPrefix) {
		return RepoIdentity{}, &RepoGrantError{Grant: s, Detail: "a canonical repository identity must use the " + RepoIdentityPrefix + " form"}
	}
	body := strings.TrimPrefix(s, RepoIdentityPrefix)
	parts := strings.Split(body, ":")
	if len(parts) != 2 {
		return RepoIdentity{}, &RepoGrantError{Grant: s, Detail: "expected exactly two base64url parts after " + RepoIdentityPrefix}
	}
	for _, enc := range parts {
		if enc == "" || strings.Contains(enc, "=") {
			return RepoIdentity{}, &RepoGrantError{Grant: s, Detail: "base64url parts must be non-empty and unpadded"}
		}
	}
	hostBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return RepoIdentity{}, &RepoGrantError{Grant: s, Detail: "host part is not valid base64url"}
	}
	fullBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return RepoIdentity{}, &RepoGrantError{Grant: s, Detail: "full-name part is not valid base64url"}
	}
	host := string(hostBytes)
	full := FoldRepoFullName(string(fullBytes))
	canonHost := CanonicalHost(host)
	if !validCanonicalHost(canonHost) {
		return RepoIdentity{}, &RepoGrantError{Grant: s, Detail: fmt.Sprintf("host %q is empty or malformed", host)}
	}
	if err := validateFullName(full, true); err != nil {
		return RepoIdentity{}, &RepoGrantError{Grant: s, Detail: err.Error()}
	}
	return RepoIdentity{Host: canonHost, FullName: full}, nil
}

// ParseRepoAlias parses the strict bare-alias spelling
// "a1:<base64url(full_name)>". Malformed, padded, empty or whitespace-bearing
// parts are rejected; a canonical identity string is rejected.
func ParseRepoAlias(s string) (RepoAlias, error) {
	if !strings.HasPrefix(s, RepoAliasPrefix) {
		return RepoAlias{}, &RepoGrantError{Grant: s, Detail: "an explicit bare alias must use the " + RepoAliasPrefix + " form or the plain owner/name spelling"}
	}
	enc := strings.TrimPrefix(s, RepoAliasPrefix)
	if enc == "" || strings.Contains(enc, "=") {
		return RepoAlias{}, &RepoGrantError{Grant: s, Detail: "the base64url part must be non-empty and unpadded"}
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return RepoAlias{}, &RepoGrantError{Grant: s, Detail: "the part after " + RepoAliasPrefix + " is not valid base64url"}
	}
	full := FoldRepoFullName(string(raw))
	if err := validateFullName(full, false); err != nil {
		return RepoAlias{}, &RepoGrantError{Grant: s, Detail: err.Error()}
	}
	return RepoAlias{FullName: full}, nil
}

// ParseRepoGrant parses one repository grant with the documented rule used for
// in-process values and persisted repository IDs:
//
//  1. "r1:..." is a canonical identity (strict ParseRepoIdentity);
//  2. "a1:..." is a bare alias (strict ParseRepoAlias);
//  3. a legacy string with exactly one path segment is a bare alias;
//  4. a legacy string with two path segments is a bare alias ("owner/name");
//  5. a legacy string with three or more path segments is the canonical
//     identity whose host is the FIRST segment and whose full name is the
//     remainder. This is the shape CanonicalRepoID produces for every known
//     host, dotted or dotless, and it is never inferred from dots.
//
// Malformed strings (whitespace, empty segments, invalid hosts) are rejected.
// ACL CONFIGURATION must use ParseRepoGrantConfig instead, which refuses the
// legacy spellings of rule 5 as ambiguous.
func ParseRepoGrant(s string) (RepoGrant, error) {
	return parseRepoGrant(s, true)
}

// ParseRepoGrantConfig parses one repository grant under the strict ACL
// CONFIGURATION schema: the explicit r1:/a1: forms, plus the unambiguous
// legacy bare spellings (zero or one slash). A legacy string with three or
// more path segments is ambiguous (rule 5 above would have to guess whether
// the first segment is a dotless host or part of a bare nested name), so it is
// rejected with ErrRepoGrantAmbiguous naming the string and both accepted
// spellings. This is the parser behind TokenStore.Load and the repository
// grant validation exported by internal/config.
func ParseRepoGrantConfig(s string) (RepoGrant, error) {
	return parseRepoGrant(s, false)
}

// parseRepoGrant is the shared implementation; allowLegacyCanonical selects
// rule 5 (in-process migration) versus the strict configuration schema.
func parseRepoGrant(s string, allowLegacyCanonical bool) (RepoGrant, error) {
	if s == "" {
		return RepoGrant{}, &RepoGrantError{Grant: s, Detail: "grant is empty"}
	}
	if strings.HasPrefix(s, RepoIdentityPrefix) {
		id, err := ParseRepoIdentity(s)
		if err != nil {
			return RepoGrant{}, err
		}
		return IdentityGrant(id), nil
	}
	if strings.HasPrefix(s, RepoAliasPrefix) {
		a, err := ParseRepoAlias(s)
		if err != nil {
			return RepoGrant{}, err
		}
		return AliasGrant(a), nil
	}
	if strings.TrimSpace(s) != s {
		return RepoGrant{}, &RepoGrantError{Grant: s, Detail: "grant has surrounding whitespace"}
	}
	if err := validateFullName(s, false); err != nil {
		return RepoGrant{}, &RepoGrantError{Grant: s, Detail: err.Error()}
	}
	first, rest, ok := splitFirstPathSegment(s)
	if !ok {
		return AliasGrant(RepoAlias{FullName: FoldRepoFullName(s)}), nil
	}
	if !strings.Contains(rest, "/") {
		return AliasGrant(RepoAlias{FullName: FoldRepoFullName(s)}), nil
	}
	if !allowLegacyCanonical {
		return RepoGrant{}, &RepoGrantError{
			Grant:     s,
			Ambiguous: true,
			Detail:    "a legacy string with three or more path segments could be the dotless host " + fmt.Sprintf("%q", first) + " with full name " + fmt.Sprintf("%q", rest) + " or a bare nested name",
		}
	}
	host := CanonicalHost(first)
	if !validCanonicalHost(host) {
		return RepoGrant{}, &RepoGrantError{Grant: s, Detail: fmt.Sprintf("host %q is empty or malformed", first)}
	}
	if err := validateFullName(rest, true); err != nil {
		return RepoGrant{}, &RepoGrantError{Grant: s, Detail: err.Error()}
	}
	return IdentityGrant(RepoIdentity{Host: host, FullName: FoldRepoFullName(rest)}), nil
}

// ParseStoredRepoID parses a persisted repository ID (run/job/schedule
// records, runner allowlist entries, test-intelligence queries) with the
// documented legacy positional rule; it is ParseRepoGrant's migration rule and
// never consults dots. Persisted canonical IDs written by CanonicalRepoID are
// therefore parsed into the same typed identity they were derived from, with a
// dotless host parsed exactly like a dotted one.
func ParseStoredRepoID(s string) (RepoGrant, error) {
	return parseRepoGrant(s, true)
}
