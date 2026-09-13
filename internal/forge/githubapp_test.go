package forge

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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testAppKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return key, pemBytes
}

func TestAppJWT(t *testing.T) {
	key, pemBytes := testAppKey(t)
	app := NewApp(12345, pemBytes)
	now := time.Now()
	token, err := app.jwt(now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt has %d parts", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}
	if header["alg"] != "RS256" || header["typ"] != "JWT" {
		t.Fatalf("bad header: %s", headerJSON)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != "12345" {
		t.Fatalf("bad iss: %v", claims["iss"])
	}
	iat := int64(claims["iat"].(float64))
	exp := int64(claims["exp"].(float64))
	if exp-iat != 660 {
		t.Fatalf("bad lifetime: iat=%d exp=%d", iat, exp)
	}
	if iat > now.Add(-60*time.Second).Unix() || iat < now.Add(-120*time.Second).Unix() {
		t.Fatalf("iat not ~now-60s: %d vs %d", iat, now.Unix())
	}
	// Verify the RS256 signature with the public key.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	// PKCS#8 keys are also accepted.
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	app8 := NewApp(12345, pkcs8PEM)
	if _, err := app8.jwt(now); err != nil {
		t.Fatalf("pkcs8 key rejected: %v", err)
	}
}

func TestAppTokenFor(t *testing.T) {
	_, pemBytes := testAppKey(t)
	var installationCalls, tokenCalls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			installationCalls.Add(1)
			if r.Header.Get("Authorization") == "" {
				http.Error(w, "missing auth", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": 7})
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			tokenCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "install-token", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	app := NewApp(99, pemBytes)
	app.BaseURL = ts.URL

	tok, err := app.TokenFor(context.Background(), "octocat/hello-world")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "install-token" {
		t.Fatalf("unexpected token %q", tok)
	}
	if installationCalls.Load() != 1 || tokenCalls.Load() != 1 {
		t.Fatalf("expected one lookup + one mint, got %d/%d", installationCalls.Load(), tokenCalls.Load())
	}
	// Cached: no further API calls.
	for i := 0; i < 3; i++ {
		if tok, err = app.TokenFor(context.Background(), "octocat/hello-world"); err != nil || tok != "install-token" {
			t.Fatalf("cached token failed: %v %q", err, tok)
		}
	}
	if installationCalls.Load() != 1 || tokenCalls.Load() != 1 {
		t.Fatalf("cache bypassed: %d/%d", installationCalls.Load(), tokenCalls.Load())
	}

	// A different repository mints its own token.
	if _, err := app.TokenFor(context.Background(), "other/repo"); err != nil {
		t.Fatal(err)
	}
	if installationCalls.Load() != 2 || tokenCalls.Load() != 2 {
		t.Fatalf("per-repo cache broken: %d/%d", installationCalls.Load(), tokenCalls.Load())
	}
}

func TestAppSingleFlight(t *testing.T) {
	_, pemBytes := testAppKey(t)
	var inFlight atomic.Int64
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/installation"):
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": 7})
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			inFlight.Add(1)
			<-release
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "install-token", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	app := NewApp(99, pemBytes)
	app.BaseURL = ts.URL

	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() {
			_, err := app.TokenFor(context.Background(), "octocat/hello-world")
			errs <- err
		}()
	}
	// Give the first goroutine time to enter the token API.
	time.Sleep(100 * time.Millisecond)
	close(release)
	for i := 0; i < 4; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if inFlight.Load() != 1 {
		t.Fatalf("single-flight violated: %d concurrent token mints", inFlight.Load())
	}
}

func TestAppErrors(t *testing.T) {
	app := NewApp(1, []byte("not pem"))
	if _, err := app.jwt(time.Now()); err == nil {
		t.Fatal("non-PEM key must fail")
	}
	if _, err := app.TokenFor(context.Background(), ""); err == nil {
		t.Fatal("empty repo must fail")
	}
}

func TestAppInstallationTokenError(t *testing.T) {
	_, pemBytes := testAppKey(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer ts.Close()
	app := NewApp(99, pemBytes)
	app.BaseURL = ts.URL
	if _, err := app.TokenFor(context.Background(), "missing/repo"); err == nil {
		t.Fatal("expected error for unknown repo")
	}
}
