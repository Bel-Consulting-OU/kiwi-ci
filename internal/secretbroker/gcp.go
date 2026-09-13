package secretbroker

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GCPClient resolves secrets from Google Cloud Secret Manager using a
// service-account RS256 JWT to obtain an OAuth access token.
type GCPClient struct {
	Project       string
	ClientEmail   string
	PrivateKeyPEM []byte

	TokenURL         string
	SecretManagerURL string
	Scope            string
	HTTPClient       *http.Client
	Now              func() time.Time
}

func (c *GCPClient) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *GCPClient) tokenURL() string {
	if c.TokenURL != "" {
		return c.TokenURL
	}
	return "https://oauth2.googleapis.com/token"
}

func (c *GCPClient) secretManagerURL() string {
	if c.SecretManagerURL != "" {
		return c.SecretManagerURL
	}
	return "https://secretmanager.googleapis.com"
}

func (c *GCPClient) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *GCPClient) scope() string {
	if c.Scope != "" {
		return c.Scope
	}
	return "https://www.googleapis.com/auth/cloud-platform"
}

func (c *GCPClient) privateKey() (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(c.PrivateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("gcp: private key is not PEM encoded")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("gcp: parse private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("gcp: private key is %T, want *rsa.PrivateKey", key)
	}
	return rsaKey, nil
}

// serviceAccountJWT builds a structurally valid RS256 service-account JWT for
// the token endpoint.
func (c *GCPClient) serviceAccountJWT() (string, error) {
	key, err := c.privateKey()
	if err != nil {
		return "", err
	}
	now := c.now().UTC()
	header := base64.RawURLEncoding.EncodeToString(mustJSON(map[string]string{"alg": "RS256", "typ": "JWT"}))
	claims := base64.RawURLEncoding.EncodeToString(mustJSON(map[string]interface{}{
		"iss":   c.ClientEmail,
		"scope": c.scope(),
		"aud":   c.tokenURL(),
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}))
	signingInput := header + "." + claims
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("gcp: sign jwt: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func mustJSON(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

type gcpTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func (c *GCPClient) accessToken(ctx context.Context) (string, error) {
	jwt, err := c.serviceAccountJWT()
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {jwt},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("gcp: token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("gcp: token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("gcp: token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gcp: token status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out gcpTokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("gcp: decode token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("gcp: empty access token")
	}
	return out.AccessToken, nil
}

// Resolve fetches the latest version of the secret and base64-decodes
// payload.data.
func (c *GCPClient) Resolve(ctx context.Context, name string, _ SecretScope) (string, error) {
	token, err := c.accessToken(ctx)
	if err != nil {
		return "", err
	}
	u := c.secretManagerURL() + "/v1/projects/" + url.PathEscape(c.Project) +
		"/secrets/" + url.PathEscape(name) + "/versions/latest:access"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", fmt.Errorf("gcp: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("gcp: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("gcp: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gcp: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("gcp: decode response: %w", err)
	}
	if out.Payload.Data == "" {
		return "", fmt.Errorf("gcp: secret %q has no payload data", name)
	}
	decoded, err := base64.StdEncoding.DecodeString(out.Payload.Data)
	if err != nil {
		return "", fmt.Errorf("gcp: decode payload data: %w", err)
	}
	return string(decoded), nil
}
