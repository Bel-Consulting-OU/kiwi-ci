package secretbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// VaultClient resolves secrets from a HashiCorp Vault KV v2 secrets engine.
type VaultClient struct {
	Address string
	Token   string

	HTTPClient *http.Client
}

func (c *VaultClient) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c *VaultClient) baseURL() (*url.URL, error) {
	u, err := url.Parse(c.Address)
	if err != nil {
		return nil, fmt.Errorf("vault: parse address: %w", err)
	}
	if u.Scheme != "https" {
		if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("vault: insecure http address %q rejected (non-loopback)", c.Address)
		}
		if u.Scheme != "http" {
			return nil, fmt.Errorf("vault: unsupported scheme %q", u.Scheme)
		}
	}
	if u.Host == "" {
		return nil, fmt.Errorf("vault: address has no host")
	}
	return u, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type vaultKV2Response struct {
	Data struct {
		Data json.RawMessage `json:"data"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

// firstVaultValue returns data.data["value"], or the first key in document
// order when "value" is absent.
func firstVaultValue(data json.RawMessage) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return "", fmt.Errorf("vault: decode data: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return "", fmt.Errorf("vault: data is not an object")
	}
	var first string
	var haveFirst bool
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return "", fmt.Errorf("vault: decode data: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return "", fmt.Errorf("vault: non-string data key")
		}
		var val string
		if err := dec.Decode(&val); err != nil {
			return "", fmt.Errorf("vault: decode value for %q: %w", key, err)
		}
		if key == "value" {
			return val, nil
		}
		if !haveFirst {
			first, haveFirst = val, true
		}
	}
	if !haveFirst {
		return "", fmt.Errorf("vault: secret has no data")
	}
	return first, nil
}

// Resolve performs a KV v2 GET on /v1/secret/data/{path}. The resolved value
// is data.data["value"], or the first entry when "value" is absent. Redirects
// are not followed.
func (c *VaultClient) Resolve(ctx context.Context, name string, _ SecretScope) (string, error) {
	base, err := c.baseURL()
	if err != nil {
		return "", err
	}
	u := *base
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/secret/data/" + strings.TrimLeft(name, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("vault: build request: %w", err)
	}
	if c.Token != "" {
		req.Header.Set("X-Vault-Token", c.Token)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("vault: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("vault: read response: %w", err)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return "", fmt.Errorf("vault: unexpected redirect status %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out vaultKV2Response
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("vault: decode response: %w", err)
	}
	if len(out.Errors) > 0 {
		return "", fmt.Errorf("vault: %s", strings.Join(out.Errors, "; "))
	}
	return firstVaultValue(out.Data.Data)
}
