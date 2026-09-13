package secretbroker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAWSCanonicalRequest(t *testing.T) {
	payload := []byte(`{"SecretId":"ci/token"}`)
	headers := map[string]string{
		"content-type": "application/x-amz-json-1.1",
		"host":         "secretsmanager.us-east-1.amazonaws.com",
		"x-amz-date":   "20240901T000000Z",
		"x-amz-target": "secretsmanager.GetSecretValue",
	}
	signed := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	canonical, signedHeaders, payloadHash := awsV4CanonicalRequest("POST", "/", "", headers, signed, payload)

	wantCanonical := "POST\n" +
		"/\n" +
		"\n" +
		"content-type:application/x-amz-json-1.1\n" +
		"host:secretsmanager.us-east-1.amazonaws.com\n" +
		"x-amz-date:20240901T000000Z\n" +
		"x-amz-target:secretsmanager.GetSecretValue\n" +
		"\n" +
		"content-type;host;x-amz-date;x-amz-target\n" +
		sha256Hex(payload)
	if canonical != wantCanonical {
		t.Fatalf("canonical request mismatch:\ngot:\n%s\nwant:\n%s", canonical, wantCanonical)
	}
	if signedHeaders != "content-type;host;x-amz-date;x-amz-target" {
		t.Fatalf("signed headers %q", signedHeaders)
	}
	if payloadHash != sha256Hex(payload) {
		t.Fatalf("payload hash %q", payloadHash)
	}
}

func TestAWSCanonicalRequestDefaultURIAndTrimsHeader(t *testing.T) {
	headers := map[string]string{"host": "  example.com  "}
	canonical, _, _ := awsV4CanonicalRequest("GET", "", "", headers, []string{"host"}, nil)
	if !strings.HasPrefix(canonical, "GET\n/\n\nhost:example.com\n") {
		t.Fatalf("unexpected canonical request: %q", canonical)
	}
}

func TestAWSV4SigningKeyDeterministic(t *testing.T) {
	k1 := awsV4SigningKey("secret", "20240901", "us-east-1", "secretsmanager")
	k2 := awsV4SigningKey("secret", "20240901", "us-east-1", "secretsmanager")
	if string(k1) != string(k2) {
		t.Fatal("signing key must be deterministic")
	}
	k3 := awsV4SigningKey("secret", "20240902", "us-east-1", "secretsmanager")
	if string(k1) == string(k3) {
		t.Fatal("signing key must depend on the date")
	}
}

func TestSecretsManagerResolve(t *testing.T) {
	var gotAuth, gotTarget, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotTarget = r.Header.Get("X-Amz-Target")
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.Write([]byte(`{"SecretString":"aws-secret"}`))
	}))
	defer srv.Close()

	c := &SecretsManagerClient{
		Region:          "us-east-1",
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "sekrit",
		Endpoint:        srv.URL,
	}
	v, err := c.Resolve(context.Background(), "ci/token", SecretScope{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "aws-secret" {
		t.Fatalf("got %q", v)
	}
	if gotTarget != "secretsmanager.GetSecretValue" {
		t.Fatalf("x-amz-target %q", gotTarget)
	}
	if !strings.Contains(gotBody, `"ci/token"`) {
		t.Fatalf("body %q", gotBody)
	}
	if !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") ||
		!strings.Contains(gotAuth, "/us-east-1/secretsmanager/aws4_request, SignedHeaders=") ||
		!strings.Contains(gotAuth, ", Signature=") {
		t.Fatalf("authorization %q", gotAuth)
	}
}

func TestSecretsManagerResolveErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"__type":"ResourceNotFoundException"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	c := &SecretsManagerClient{
		Region:          "us-east-1",
		AccessKeyID:     "AKID",
		SecretAccessKey: "sekrit",
		Endpoint:        srv.URL,
	}
	if _, err := c.Resolve(context.Background(), "nope", SecretScope{}); err == nil {
		t.Fatal("expected error for 400")
	}
}

func TestSecretsManagerResolveEmptySecretString(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := &SecretsManagerClient{
		Region:          "us-east-1",
		AccessKeyID:     "AKID",
		SecretAccessKey: "sekrit",
		Endpoint:        srv.URL,
	}
	if _, err := c.Resolve(context.Background(), "empty", SecretScope{}); err == nil {
		t.Fatal("expected error when SecretString is empty")
	}
}
