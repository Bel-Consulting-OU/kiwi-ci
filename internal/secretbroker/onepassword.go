package secretbroker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// OnePasswordClient resolves secrets from a 1Password Connect server.
type OnePasswordClient struct {
	Host    string
	Token   string
	VaultID string

	HTTPClient *http.Client
}

func (c *OnePasswordClient) client() *http.Client {
	return providerClient(c.HTTPClient)
}

type onePasswordItemResponse struct {
	Fields []struct {
		Label string `json:"label"`
		Value string `json:"value"`
	} `json:"fields"`
	Value string `json:"value"`
}

// Resolve fetches the item named "name" from the configured vault, filtered to
// the password field, and returns its value.
func (c *OnePasswordClient) Resolve(ctx context.Context, name string, _ SecretScope) (string, error) {
	if err := validateProviderEndpoint(c.Host, true); err != nil {
		return "", classError("onepassword", ErrUnavailable, "invalid endpoint", err)
	}
	u := strings.TrimRight(c.Host, "/") + "/v1/vaults/" + url.PathEscape(c.VaultID) +
		"/items/" + url.PathEscape(name) + "?fields=password"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", classError("onepassword", ErrUnavailable, "build request", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.client().Do(req)
	if err != nil {
		return "", transportError("onepassword", "request failed", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", transportError("onepassword", "read response", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", classError("onepassword", httpStatusClass(resp.StatusCode), fmt.Sprintf("status %d", resp.StatusCode), nil)
	}
	var out onePasswordItemResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", decodeError("onepassword", "decode response", err)
	}
	for _, f := range out.Fields {
		if f.Value != "" {
			return f.Value, nil
		}
	}
	if out.Value != "" {
		return out.Value, nil
	}
	return "", classError("onepassword", ErrMalformedResponse, fmt.Sprintf("item %q has no password field", name), nil)
}
