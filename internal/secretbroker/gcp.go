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
	return providerClient(c.HTTPClient)
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
		return "", classError("gcp", ErrUnavailable, "service account credentials unusable", err)
	}
	tokenURL := c.tokenURL()
	if err := validateProviderEndpoint(tokenURL, true); err != nil {
		return "", classError("gcp", ErrUnavailable, "invalid token endpoint", err)
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {jwt},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", classError("gcp", ErrUnavailable, "token request", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client().Do(req)
	if err != nil {
		return "", transportError("gcp", "token request failed", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", transportError("gcp", "token response read failed", err)
	}
	if resp.StatusCode != http.StatusOK {
		code := oauthErrorCode(body)
		class := oauthErrorClass(code, resp.StatusCode)
		return "", classError("gcp", class, statusDetailToken(resp.StatusCode, code), nil)
	}
	var out gcpTokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", decodeError("gcp", "decode token response", err)
	}
	if out.AccessToken == "" {
		return "", classError("gcp", ErrMalformedResponse, "empty access token", nil)
	}
	return out.AccessToken, nil
}

// statusDetailToken renders a safe "token status N (code)" detail; the OAuth
// error code is a fixed identifier, never a description or body.
func statusDetailToken(status int, code string) string {
	if code == "" {
		return fmt.Sprintf("token status %d", status)
	}
	return fmt.Sprintf("token status %d (%s)", status, code)
}

// Resolve fetches the latest version of the secret and base64-decodes
// payload.data.
func (c *GCPClient) Resolve(ctx context.Context, name string, _ SecretScope) (string, error) {
	token, err := c.accessToken(ctx)
	if err != nil {
		return "", err
	}
	secretManagerURL := c.secretManagerURL()
	if err := validateProviderEndpoint(secretManagerURL, true); err != nil {
		return "", classError("gcp", ErrUnavailable, "invalid secret manager endpoint", err)
	}
	u := secretManagerURL + "/v1/projects/" + url.PathEscape(c.Project) +
		"/secrets/" + url.PathEscape(name) + "/versions/latest:access"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", classError("gcp", ErrUnavailable, "build request", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.client().Do(req)
	if err != nil {
		return "", transportError("gcp", "request failed", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", transportError("gcp", "read response", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", classError("gcp", httpStatusClass(resp.StatusCode), fmt.Sprintf("status %d", resp.StatusCode), nil)
	}
	var out struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", decodeError("gcp", "decode response", err)
	}
	if out.Payload.Data == "" {
		return "", classError("gcp", ErrMalformedResponse, fmt.Sprintf("secret %q has no payload data", name), nil)
	}
	decoded, err := base64.StdEncoding.DecodeString(out.Payload.Data)
	if err != nil {
		return "", decodeError("gcp", "decode payload data", err)
	}
	return string(decoded), nil
}
