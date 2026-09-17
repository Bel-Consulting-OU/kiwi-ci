package secretbroker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// SecretsManagerClient resolves secrets from AWS Secrets Manager using AWS
// Signature Version 4 (service: secretsmanager).
type SecretsManagerClient struct {
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string

	Endpoint   string
	HTTPClient *http.Client
}

func (c *SecretsManagerClient) client() *http.Client {
	return providerClient(c.HTTPClient)
}

func (c *SecretsManagerClient) endpoint() string {
	if c.Endpoint != "" {
		return c.Endpoint
	}
	return "https://secretsmanager." + c.Region + ".amazonaws.com"
}

type secretsManagerResponse struct {
	SecretString string `json:"SecretString"`
	SecretBinary []byte `json:"SecretBinary"`
}

// Resolve calls GetSecretValue with SecretId=name and parses SecretString.
func (c *SecretsManagerClient) Resolve(ctx context.Context, name string, _ SecretScope) (string, error) {
	payload, err := json.Marshal(map[string]string{"SecretId": name})
	if err != nil {
		return "", fmt.Errorf("secretsmanager: marshal request: %w", err)
	}
	endpoint := c.endpoint()
	if err := validateProviderEndpoint(endpoint, true); err != nil {
		return "", fmt.Errorf("secretsmanager: %w", err)
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("secretsmanager: parse endpoint: %w", err)
	}
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	headers := map[string]string{
		"content-type": "application/x-amz-json-1.1",
		"host":         u.Host,
		"x-amz-date":   amzDate,
		"x-amz-target": "secretsmanager.GetSecretValue",
	}
	signed := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if c.SessionToken != "" {
		headers["x-amz-security-token"] = c.SessionToken
		signed = append(signed, "x-amz-security-token")
		sort.Strings(signed)
	}

	canonical, signedHeaders, _ := awsV4CanonicalRequest(http.MethodPost, u.EscapedPath(), u.RawQuery, headers, signed, payload)
	credentialScope := date + "/" + c.Region + "/secretsmanager/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + credentialScope + "\n" + sha256Hex([]byte(canonical))
	signingKey := awsV4SigningKey(c.SecretAccessKey, date, c.Region, "secretsmanager")
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))
	auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.AccessKeyID, credentialScope, signedHeaders, signature)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return "", fmt.Errorf("secretsmanager: build request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", auth)

	resp, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("secretsmanager: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("secretsmanager: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("secretsmanager: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out secretsManagerResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("secretsmanager: decode response: %w", err)
	}
	if out.SecretString != "" {
		return out.SecretString, nil
	}
	return "", fmt.Errorf("secretsmanager: secret %q has no SecretString", name)
}

// awsV4CanonicalRequest builds the SigV4 canonical request and returns it
// together with the sorted signed-headers list and the payload hash.
func awsV4CanonicalRequest(method, uri, query string, headers map[string]string, signed []string, payload []byte) (canonical, signedHeaders, payloadHash string) {
	if uri == "" {
		uri = "/"
	}
	var b strings.Builder
	b.WriteString(method)
	b.WriteByte('\n')
	b.WriteString(uri)
	b.WriteByte('\n')
	b.WriteString(query)
	b.WriteByte('\n')
	for _, name := range signed {
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(trimCanonicalHeaderValue(headers[name]))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	signedHeaders = strings.Join(signed, ";")
	b.WriteString(signedHeaders)
	b.WriteByte('\n')
	payloadHash = sha256Hex(payload)
	b.WriteString(payloadHash)
	return b.String(), signedHeaders, payloadHash
}

func trimCanonicalHeaderValue(v string) string {
	v = strings.TrimSpace(v)
	fields := strings.Fields(v)
	return strings.Join(fields, " ")
}

func awsV4SigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
