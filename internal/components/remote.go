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
// must be https:// and the client never follows redirects, so bearer
// credentials cannot leak to another origin. Registry responses are
// bounded at 1 MiB.
type RemoteRegistry struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

// maxRegistryResponseBytes bounds one registry spec response.
const maxRegistryResponseBytes = 1 << 20

// NewRemoteRegistry validates the base URL and returns a registry client.
// http:// base URLs are rejected outright (strict HTTPS).
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
	return &RemoteRegistry{BaseURL: strings.TrimRight(baseURL, "/"), Token: token}, nil
}

func (r *RemoteRegistry) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
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
	var spec Spec
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRegistryResponseBytes)).Decode(&spec); err != nil {
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
