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

// AzureClient resolves secrets from Azure Key Vault using the OAuth2
// client-credentials flow against the tenant's v2.0 token endpoint.
type AzureClient struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	VaultURL     string

	TokenURL   string
	HTTPClient *http.Client
}

func (c *AzureClient) client() *http.Client {
	return providerClient(c.HTTPClient)
}

func (c *AzureClient) tokenURL() string {
	if c.TokenURL != "" {
		return c.TokenURL
	}
	return "https://login.microsoftonline.com/" + c.TenantID + "/oauth2/v2.0/token"
}

type azureTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func (c *AzureClient) accessToken(ctx context.Context) (string, error) {
	tokenURL := c.tokenURL()
	if err := validateProviderEndpoint(tokenURL, true); err != nil {
		return "", classError("azure", ErrUnavailable, "invalid token endpoint", err)
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
		"scope":         {"https://vault.azure.net/.default"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", classError("azure", ErrUnavailable, "token request", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client().Do(req)
	if err != nil {
		return "", transportError("azure", "token request failed", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", transportError("azure", "token response read failed", err)
	}
	if resp.StatusCode != http.StatusOK {
		code := oauthErrorCode(body)
		class := oauthErrorClass(code, resp.StatusCode)
		return "", classError("azure", class, statusDetailToken(resp.StatusCode, code), nil)
	}
	var out azureTokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", decodeError("azure", "decode token response", err)
	}
	if out.AccessToken == "" {
		return "", classError("azure", ErrMalformedResponse, "empty access token", nil)
	}
	return out.AccessToken, nil
}

type azureSecretResponse struct {
	Value string `json:"value"`
}

// Resolve fetches {vaultURL}/secrets/{name}?api-version=7.4 and returns the
// "value" field.
func (c *AzureClient) Resolve(ctx context.Context, name string, _ SecretScope) (string, error) {
	token, err := c.accessToken(ctx)
	if err != nil {
		return "", err
	}
	if err := validateProviderEndpoint(c.VaultURL, true); err != nil {
		return "", classError("azure", ErrUnavailable, "invalid vault endpoint", err)
	}
	u := strings.TrimRight(c.VaultURL, "/") + "/secrets/" + url.PathEscape(name) + "?api-version=7.4"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", classError("azure", ErrUnavailable, "build request", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.client().Do(req)
	if err != nil {
		return "", transportError("azure", "request failed", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", transportError("azure", "read response", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", classError("azure", httpStatusClass(resp.StatusCode), fmt.Sprintf("status %d", resp.StatusCode), nil)
	}
	var out azureSecretResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", decodeError("azure", "decode response", err)
	}
	if out.Value == "" {
		return "", classError("azure", ErrMalformedResponse, fmt.Sprintf("secret %q has no value", name), nil)
	}
	return out.Value, nil
}
