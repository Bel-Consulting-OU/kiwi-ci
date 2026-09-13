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
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
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
	u := strings.TrimRight(c.Host, "/") + "/v1/vaults/" + url.PathEscape(c.VaultID) +
		"/items/" + url.PathEscape(name) + "?fields=password"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", fmt.Errorf("onepassword: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("onepassword: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("onepassword: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("onepassword: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out onePasswordItemResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("onepassword: decode response: %w", err)
	}
	for _, f := range out.Fields {
		if f.Value != "" {
			return f.Value, nil
		}
	}
	if out.Value != "" {
		return out.Value, nil
	}
	return "", fmt.Errorf("onepassword: item %q has no password field", name)
}
