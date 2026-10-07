package secretbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Typed secret-provider error classes.
//
// Every provider failure is classified into exactly one of these classes so a
// broker chain can decide whether advancing to the next broker is permitted.
// The classes are sentinels: errors.Is works through every wrapper and through
// ChainBroker's aggregate error.
//
// Semantics:
//
//   - ErrSecretNotFound: the secret is absent from the authoritative store.
//     This is the ONLY class that advances a chain by default.
//   - ErrUnauthorized: 401, expired/invalid credentials, invalid signatures.
//   - ErrForbidden: 403, access denied, policy denied.
//   - ErrUnavailable: 5xx, network/TLS failure, timeout, provider outage,
//     invalid endpoint, malformed request rejection, and cancellation.
//     Cancellation is classified Unavailable but the chain never falls back
//     on it: a canceled resolution must not consult any further broker.
//   - ErrMalformedResponse: an undecodable or structurally unusable provider
//     response (including a successful response missing the expected value).
//
// Authorization, policy, and malformed-response failures must NEVER be
// masked by falling through to a later broker, and the configuration layer
// refuses a chain policy that names them (see ParseFallbackOn).
//
// Declared class precedence lattice (highest wins):
//
//	rank 4  forbidden, unauthorized   authorization/policy: terminal, never fallback-able
//	rank 3  malformed                 unusable response: terminal, never fallback-able
//	rank 2  unavailable               outage/timeout/cancellation: terminal unless opted in
//	rank 1  not_found                 absence: terminal unless opted in
//	rank 0  unknown                   unclassified: never fallback-able, stops the chain
//
// ClassPrecedence exposes these ranks. When a chain exhausts every broker the
// returned aggregate error takes the highest-ranked class among the
// encountered failures (see ChainBroker.Resolve), so an outage is never
// reported as an absence. An unclassified error never participates in
// fallback and stops the chain as-is.
var (
	ErrSecretNotFound    = errors.New("secretbroker: secret not found")
	ErrUnauthorized      = errors.New("secretbroker: provider unauthorized")
	ErrForbidden         = errors.New("secretbroker: provider access denied")
	ErrUnavailable       = errors.New("secretbroker: provider unavailable")
	ErrMalformedResponse = errors.New("secretbroker: malformed provider response")
)

// ProviderError is a classified provider failure. It preserves both the
// class sentinel and the underlying cause, so errors.Is(err, ErrForbidden)
// and errors.Is(err, io.ErrUnexpectedEOF) can both succeed.
type ProviderError struct {
	// Provider names the broker/provider that produced the failure.
	Provider string
	// Class is one of the Err* class sentinels above.
	Class error
	// Detail is a safe, human-readable summary. It must never contain a
	// secret value or a raw provider response body.
	Detail string
	// Err is the underlying cause, when there is one.
	Err error
}

func (e *ProviderError) Error() string {
	var b strings.Builder
	if e.Provider != "" {
		b.WriteString(e.Provider)
		b.WriteString(": ")
	}
	if e.Detail != "" {
		b.WriteString(e.Detail)
	}
	if e.Err != nil {
		if b.Len() > 0 {
			b.WriteString(": ")
		}
		b.WriteString(e.Err.Error())
	}
	if b.Len() == 0 {
		return "secretbroker: provider error"
	}
	return b.String()
}

// Unwrap exposes the class sentinel and the cause to errors.Is/errors.As.
func (e *ProviderError) Unwrap() []error {
	errs := make([]error, 0, 2)
	if e.Class != nil {
		errs = append(errs, e.Class)
	}
	if e.Err != nil {
		errs = append(errs, e.Err)
	}
	return errs
}

// classError builds a classified provider error. detail must be safe to
// surface (no secret values, no raw provider bodies).
func classError(provider string, class error, detail string, cause error) error {
	return &ProviderError{Provider: provider, Class: class, Detail: detail, Err: cause}
}

// ErrorClass returns the declared class name of err ("not_found",
// "unauthorized", "forbidden", "unavailable", "malformed") or "unknown" for
// an unclassified error; nil yields "". It is used to annotate chain
// decisions, to evaluate a FallbackOn policy, and for telemetry. When an
// error aggregates several classes, the highest-precedence class wins (see
// the lattice above), so ErrorClass agrees with terminalClass and telemetry
// never mistakes an outage for an absence.
func ErrorClass(err error) string {
	if err == nil {
		return ""
	}
	for _, entry := range classPrecedenceTable {
		if errors.Is(err, entry.sentinel) {
			return entry.name
		}
	}
	return ClassUnknown
}

// FallbackClassNotFound and FallbackClassUnavailable are the only error
// classes a chain may be configured to fall through on. Authorization,
// policy and malformed-response classes are deliberately not configurable:
// falling through on them would mask an authoritative security decision.
//
// ClassUnauthorized, ClassForbidden, ClassMalformed and ClassUnknown complete
// the class-name vocabulary returned by ErrorClass.
const (
	FallbackClassNotFound    = "not_found"
	FallbackClassUnavailable = "unavailable"
	ClassUnauthorized        = "unauthorized"
	ClassForbidden           = "forbidden"
	ClassMalformed           = "malformed"
	ClassUnknown             = "unknown"
)

// classPrecedenceTable is the declared precedence lattice as data, ordered
// from the highest rank to the lowest so the first match wins. It is the
// single source of truth for ClassPrecedence, classSentinel, terminalClass
// and ErrorClass. Forbidden and unauthorized share the top rank; forbidden is
// listed first so an error matching both resolves deterministically (a chain
// itself never accumulates both: it stops at the first non-fallback class).
var classPrecedenceTable = []struct {
	name     string
	rank     int
	sentinel error
}{
	{ClassForbidden, 4, ErrForbidden},
	{ClassUnauthorized, 4, ErrUnauthorized},
	{ClassMalformed, 3, ErrMalformedResponse},
	{FallbackClassUnavailable, 2, ErrUnavailable},
	{FallbackClassNotFound, 1, ErrSecretNotFound},
}

// ClassPrecedence returns the declared precedence rank of a class name:
// higher wins. Unknown, empty and unrecognized names rank 0 and never
// participate in fallback.
func ClassPrecedence(class string) int {
	for _, entry := range classPrecedenceTable {
		if entry.name == class {
			return entry.rank
		}
	}
	return 0
}

// classSentinel maps a class name to its sentinel error, or nil when the name
// is not a declared class.
func classSentinel(class string) error {
	for _, entry := range classPrecedenceTable {
		if entry.name == class {
			return entry.sentinel
		}
	}
	return nil
}

// terminalClass is a pure function returning the sentinel of the
// highest-precedence class among errs, or nil when none of them is
// classified. It is order-independent: the lattice decides, and the tied top
// rank (forbidden/unauthorized) resolves to forbidden. An unclassified error
// contributes nothing; callers must treat it as chain-stopping and return it
// unmasked.
func terminalClass(errs []error) error {
	for _, entry := range classPrecedenceTable {
		for _, err := range errs {
			if errors.Is(err, entry.sentinel) {
				return entry.sentinel
			}
		}
	}
	return nil
}

// DefaultFallbackOn is the built-in chain policy: a chain advances only when
// the authoritative store reports the secret absent.
var DefaultFallbackOn = []string{FallbackClassNotFound}

// ParseFallbackOn validates and normalizes a configured fallback policy.
// A nil policy keeps the default ([not_found]); a non-nil empty policy means
// "never fall back". Only "not_found" and "unavailable" are accepted;
// anything else (including "unauthorized", "forbidden", "malformed" and
// unknown values) is a configuration error, because a chain must never be
// configured to mask an authorization or security failure.
func ParseFallbackOn(entries []string) ([]string, error) {
	if entries == nil {
		return nil, nil
	}
	out := make([]string, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, raw := range entries {
		v := strings.TrimSpace(raw)
		switch v {
		case FallbackClassNotFound, FallbackClassUnavailable:
		default:
			return nil, fmt.Errorf("fallback_on contains %q: only %q and %q are accepted (a chain must never fall through on an authorization, policy, or malformed-response failure)",
				raw, FallbackClassNotFound, FallbackClassUnavailable)
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out, nil
}

// httpStatusClass maps an HTTP rejection status onto its class. Unknown 4xx
// statuses and redirects are Unavailable (fail closed; never fallback-able
// unless the operator explicitly opts into the unavailable class).
func httpStatusClass(status int) error {
	switch {
	case status == http.StatusNotFound || status == http.StatusGone:
		return ErrSecretNotFound
	case status == http.StatusUnauthorized || status == http.StatusProxyAuthRequired:
		return ErrUnauthorized
	case status == http.StatusForbidden:
		return ErrForbidden
	default:
		return ErrUnavailable
	}
}

// statusDetail renders a safe "status N (Code)" detail. The provider code is
// a fixed identifier, never a message or body.
func statusDetail(status int, code string) string {
	if code == "" {
		return fmt.Sprintf("status %d", status)
	}
	return fmt.Sprintf("status %d (%s)", status, code)
}

// transportError classifies a request/response transport failure (network,
// DNS, TLS, timeout, cancellation) as Unavailable while preserving the
// underlying cause, including context.Canceled/context.DeadlineExceeded.
func transportError(provider, detail string, cause error) error {
	return classError(provider, ErrUnavailable, detail, cause)
}

// decodeError classifies an undecodable or structurally unusable response as
// MalformedResponse while preserving the parse cause.
func decodeError(provider, detail string, cause error) error {
	return classError(provider, ErrMalformedResponse, detail, cause)
}

// oauthErrorCode extracts the OAuth2 error code from a token-endpoint body
// (GCP and Azure both use {"error":"..."}). An unparsable body yields "".
func oauthErrorCode(body []byte) string {
	var eb struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &eb); err != nil {
		return ""
	}
	return strings.TrimSpace(eb.Error)
}

// oauthErrorClass classifies an OAuth error code, falling back to the HTTP
// status class. Expired/revoked credentials arrive as HTTP 400 invalid_grant
// from both Google and Azure, so the code must take precedence over 400.
func oauthErrorClass(code string, status int) error {
	switch code {
	case "invalid_grant", "invalid_client", "unauthorized_client", "unauthorized":
		return ErrUnauthorized
	case "access_denied":
		return ErrForbidden
	default:
		return httpStatusClass(status)
	}
}

// vaultErrorTextClass scans a Vault error body for an authorization marker.
// Vault normally uses 403 for policy denial, but older/edge paths answer 400
// with "permission denied"; treating that as Unavailable would let an
// explicit unavailable fallback mask a denial. It returns nil when no marker
// is found; the body is never included in an error message.
func vaultErrorTextClass(body []byte) error {
	text := strings.ToLower(string(body))
	switch {
	case strings.Contains(text, "permission denied"), strings.Contains(text, "forbidden"):
		return ErrForbidden
	case strings.Contains(text, "invalid token"), strings.Contains(text, "missing client token"),
		strings.Contains(text, "bad token"), strings.Contains(text, "token is expired"):
		return ErrUnauthorized
	default:
		return nil
	}
}

// awsErrorCode extracts a sanitized AWS JSON-protocol error code from the
// x-amzn-errortype header or the body's __type field. Only the code (after
// any namespace prefix) is returned, never the message.
func awsErrorCode(resp *http.Response, body []byte) string {
	code := ""
	if h := resp.Header.Get("x-amzn-errortype"); h != "" {
		code = h
		if i := strings.IndexAny(code, ":;,"); i >= 0 {
			code = code[:i]
		}
	}
	if strings.TrimSpace(code) == "" {
		var eb struct {
			Type string `json:"__type"`
		}
		if err := json.Unmarshal(body, &eb); err == nil {
			code = eb.Type
		}
	}
	if i := strings.LastIndex(code, "#"); i >= 0 {
		code = code[i+1:]
	}
	return strings.TrimSpace(code)
}

// awsErrorClass maps an AWS Secrets Manager error code onto its class,
// falling back to the HTTP status class. AWS uses HTTP 400 for several
// distinct failures, so the code is authoritative.
func awsErrorClass(code string, status int) error {
	switch code {
	case "ResourceNotFoundException":
		return ErrSecretNotFound
	case "AccessDeniedException", "KMSAccessDeniedException":
		return ErrForbidden
	case "UnrecognizedClientException", "InvalidClientTokenId", "InvalidSignatureException",
		"SignatureDoesNotMatch", "ExpiredTokenException", "InvalidAccessKeyId",
		"MissingAuthenticationToken", "AccessDenied":
		return ErrUnauthorized
	case "ThrottlingException", "Throttling", "RequestLimitExceeded", "LimitExceededException",
		"InternalServiceError", "InternalFailure", "ServiceUnavailable", "RequestTimeout":
		return ErrUnavailable
	default:
		return httpStatusClass(status)
	}
}

// cancellationErr converts a context error into a classified Unavailable
// error. context.Canceled/DeadlineExceeded remain errors.Is-matchable.
func cancellationErr(provider, detail string, ctxErr error) error {
	return classError(provider, ErrUnavailable, detail, ctxErr)
}

// isContextDone reports whether ctx has fired, so a chain can stop
// immediately instead of consulting another broker.
func isContextDone(ctx context.Context) bool {
	return ctx.Err() != nil
}
