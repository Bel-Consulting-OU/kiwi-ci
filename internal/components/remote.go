package components

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RemoteRegistry resolves digest-pinned component refs from a remote
// component registry HTTP API. Transport security is strict: the base URL
// must be a canonical https:// URL with no userinfo, query or fragment, and
// the client never follows redirects, so bearer credentials cannot leak to
// another origin. Each registry response is read to at most 1 MiB and must
// be a single complete JSON value: oversize responses and trailing material
// after that value are rejected before the spec is decoded.
type RemoteRegistry struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

// maxRegistryResponseBytes bounds one registry spec response: the total
// bytes read from the response body, not just the prefix a decoder happens
// to consume.
const maxRegistryResponseBytes = 1 << 20

// defaultRegistryTimeout bounds every registry request when the caller did
// not configure a timeout on their own client.
const defaultRegistryTimeout = 20 * time.Second

// NewRemoteRegistry validates the base URL and returns a registry client.
// http:// base URLs are rejected outright (strict HTTPS), and so are
// userinfo, query and fragment components: credentials belong in the
// Authorization header (never in a URL that gets logged), and a query or
// fragment would silently survive into every derived request URL. The
// scheme must be spelled in canonical lowercase.
//
// Case and percent-encoding cannot bypass these rules. net/url lowercases
// the scheme before it is compared, so an upper-case "HTTPS://" still
// requires TLS; the explicit prefix check additionally rejects the
// non-canonical spelling because BaseURL is concatenated and logged
// verbatim. Percent-encoded delimiters cannot fabricate components either:
// only literal '?', '#', '@' and ':' delimit a URL's query, fragment,
// userinfo and scheme, so encoded forms (for example "%3F" inside a path)
// remain path data that is sent verbatim, while a malformed escape makes
// url.Parse fail closed.
func NewRemoteRegistry(baseURL, token string) (*RemoteRegistry, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("components: parse remote registry URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("components: remote registry must use https:// (got %q)", baseURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("components: remote registry URL has no host: %q", baseURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("components: remote registry URL must not carry userinfo: %q", baseURL)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return nil, fmt.Errorf("components: remote registry URL must not carry a query: %q", baseURL)
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("components: remote registry URL must not carry a fragment: %q", baseURL)
	}
	if !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("components: remote registry URL must be spelled with a lowercase https:// scheme: %q", baseURL)
	}
	return &RemoteRegistry{BaseURL: strings.TrimRight(baseURL, "/"), Token: token}, nil
}

// client returns the HTTP client used for registry requests. It always
// returns a hardened copy of the configured client (which may be nil):
// caller-supplied transport, TLS configuration, proxy, cookie jar and
// headers are preserved because they carry no transport *policy*, but the
// policy fields are enforced unconditionally. A Timeout that is unset
// (zero or negative, i.e. no deadline) becomes defaultRegistryTimeout, and
// CheckRedirect always refuses redirects with http.ErrUseLastResponse so a
// 3xx cannot carry the bearer token to another origin. The caller's
// *http.Client is copied, never mutated.
func (r *RemoteRegistry) client() *http.Client {
	var c http.Client
	if r.Client != nil {
		c = *r.Client
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultRegistryTimeout
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &c
}

// Resolve fetches the component named by a validated digest-pinned ref and
// verifies the returned spec's digest against the pin. Unpinned (local
// path) refs are rejected: the remote registry only serves pinned refs.
func (r *RemoteRegistry) Resolve(ctx context.Context, ref string) (Spec, string, error) {
	if err := ResolveComponentRef(ref); err != nil {
		return Spec{}, "", err
	}
	name, pinned := splitRemoteRef(ref)
	if pinned == "" {
		return Spec{}, "", fmt.Errorf("component %q: remote registry requires a digest-pinned name@sha256:<hex> ref", ref)
	}
	u := r.BaseURL + "/components/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Spec{}, "", err
	}
	req.Header.Set("Accept", "application/json")
	if r.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.Token)
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return Spec{}, "", fmt.Errorf("components: fetch %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Spec{}, "", fmt.Errorf("components: registry %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	// Read one byte past the bound so an exactly-at-limit body is accepted
	// while anything larger is rejected: a streaming decoder would instead
	// stop at the limit and silently ignore trailing material, so the limit
	// would bound only the consumed prefix, not the response.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistryResponseBytes+1))
	if err != nil {
		return Spec{}, "", fmt.Errorf("components: read %s: %w", name, err)
	}
	if len(raw) > maxRegistryResponseBytes {
		return Spec{}, "", fmt.Errorf("components: decode %s: response exceeds the %d-byte limit", name, maxRegistryResponseBytes)
	}
	// json.Unmarshal, unlike a streaming Decoder, rejects any non-whitespace
	// material after the top-level JSON value.
	var spec Spec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return Spec{}, "", fmt.Errorf("components: decode %s: %w", name, err)
	}
	digest, err := Digest(spec)
	if err != nil {
		return Spec{}, "", err
	}
	if pinned != digest {
		return Spec{}, "", fmt.Errorf("component %q digest mismatch: registry serves %s, pipeline pins %s", spec.Name, digest, pinned)
	}
	return spec, digest, nil
}

// ChainRegistry tries each registry in order and returns the first
// successful resolution.
type ChainRegistry []Registry

func (c ChainRegistry) Resolve(ctx context.Context, ref string) (Spec, string, error) {
	var errs []error
	for _, r := range c {
		if r == nil {
			continue
		}
		spec, digest, err := r.Resolve(ctx, ref)
		if err == nil {
			return spec, digest, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return Spec{}, "", fmt.Errorf("component %q not found: empty registry chain", ref)
	}
	return Spec{}, "", fmt.Errorf("component %q not found: %w", ref, errors.Join(errs...))
}
