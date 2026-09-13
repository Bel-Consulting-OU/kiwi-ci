package secretbroker

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func rsaPEM(key *rsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestGCPResolve(t *testing.T) {
	key := testRSAKey(t)
	fixedNow := time.Date(2024, 9, 1, 12, 0, 0, 0, time.UTC)

	var oauthAssertion string
	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("oauth parse form: %v", err)
		}
		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("grant_type %q", r.PostForm.Get("grant_type"))
		}
		oauthAssertion = r.PostForm.Get("assertion")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"ya29.fake","token_type":"Bearer","expires_in":3600}`))
	}))
	defer oauth.Close()

	var gotAuth string
	secretData := base64.StdEncoding.EncodeToString([]byte("gcp-secret"))
	sm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/v1/projects/my-project/secrets/ci/token/versions/latest:access" {
			t.Errorf("path %q (escaped %q)", r.URL.Path, r.URL.EscapedPath())
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name":"x","payload":{"data":"` + secretData + `"}}`))
	}))
	defer sm.Close()

	c := &GCPClient{
		Project:          "my-project",
		ClientEmail:      "svc@project.iam.gserviceaccount.com",
		PrivateKeyPEM:    rsaPEM(key),
		TokenURL:         oauth.URL,
		SecretManagerURL: sm.URL,
		Now:              func() time.Time { return fixedNow },
	}
	v, err := c.Resolve(context.Background(), "ci/token", SecretScope{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "gcp-secret" {
		t.Fatalf("got %q", v)
	}
	if gotAuth != "Bearer ya29.fake" {
		t.Fatalf("secret manager auth %q", gotAuth)
	}

	parts := strings.Split(oauthAssertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion %q not a JWT", oauthAssertion)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}
	if header.Alg != "RS256" || header.Typ != "JWT" {
		t.Fatalf("jwt header %+v", header)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Iss   string `json:"iss"`
		Scope string `json:"scope"`
		Aud   string `json:"aud"`
		Iat   int64  `json:"iat"`
		Exp   int64  `json:"exp"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Iss != "svc@project.iam.gserviceaccount.com" {
		t.Fatalf("iss %q", claims.Iss)
	}
	if claims.Scope != "https://www.googleapis.com/auth/cloud-platform" {
		t.Fatalf("scope %q", claims.Scope)
	}
	if claims.Aud != oauth.URL {
		t.Fatalf("aud %q, want token URL %q", claims.Aud, oauth.URL)
	}
	if claims.Iat != fixedNow.Unix() || claims.Exp != fixedNow.Add(time.Hour).Unix() {
		t.Fatalf("iat/exp %d/%d", claims.Iat, claims.Exp)
	}
}

func TestGCPServiceAccountJWTSignatureValid(t *testing.T) {
	key := testRSAKey(t)
	c := &GCPClient{
		Project:       "p",
		ClientEmail:   "svc@example.com",
		PrivateKeyPEM: rsaPEM(key),
		TokenURL:      "https://oauth2.googleapis.com/token",
	}
	jwt, err := c.serviceAccountJWT()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("JWT signature does not verify: %v", err)
	}
}

func TestGCPResolveErrorStatus(t *testing.T) {
	key := testRSAKey(t)
	oauth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"t"}`))
	}))
	defer oauth.Close()
	sm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"code":404}}`, http.StatusNotFound)
	}))
	defer sm.Close()

	c := &GCPClient{
		Project:          "p",
		ClientEmail:      "svc@example.com",
		PrivateKeyPEM:    rsaPEM(key),
		TokenURL:         oauth.URL,
		SecretManagerURL: sm.URL,
	}
	if _, err := c.Resolve(context.Background(), "nope", SecretScope{}); err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestGCPRejectsNonPEMKey(t *testing.T) {
	c := &GCPClient{PrivateKeyPEM: []byte("not a pem")}
	if _, err := c.serviceAccountJWT(); err == nil {
		t.Fatal("expected PEM error")
	}
}

func TestGCPRejectsNonRSAKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	c := &GCPClient{PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})}
	if _, err := c.serviceAccountJWT(); err == nil {
		t.Fatal("expected RSA-only error")
	}
}
