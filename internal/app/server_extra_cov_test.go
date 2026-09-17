package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServerRejectsAddressInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	err = Server(context.Background(), []string{"--listen", ln.Addr().String()})
	if err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("Server on a bound address = %v", err)
	}
}

func TestServerMetricsListenerBindFailure(t *testing.T) {
	err := Server(context.Background(), []string{"--listen", freeTCPAddr(t), "--metrics-listen", "127.0.0.1:99999999"})
	if err == nil || !strings.Contains(err.Error(), "metrics listener") {
		t.Fatalf("Server with an invalid metrics address = %v", err)
	}
}

func TestServerTLSConfigurationError(t *testing.T) {
	certFile, _ := writeSelfSignedTLS(t)
	badKey := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(badKey, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Server(context.Background(), []string{"--listen", freeTCPAddr(t), "--tls-cert", certFile, "--tls-key", badKey})
	if err == nil || !strings.Contains(err.Error(), "TLS configuration") {
		t.Fatalf("Server with a bad TLS key = %v", err)
	}
}

func TestServerRunnerCAPartialPair(t *testing.T) {
	// config.Validate already rejects a half-configured CA pair, so the
	// app-level belt-and-braces check (server_runner.go:485-487) is
	// defensive and unreachable through Server.
	certFile, _ := writeSelfSignedTLS(t)
	err := Server(context.Background(), []string{"--runner-ca-cert", certFile})
	if err == nil || !strings.Contains(err.Error(), "runner_pki.ca_cert requires runner_pki.ca_key") {
		t.Fatalf("Server with only a runner CA cert = %v", err)
	}
}

func TestServerRateLimiterWiring(t *testing.T) {
	addr := freeTCPAddr(t)
	cfgPath := filepath.Join(t.TempDir(), "kiwi.toml")
	body := fmt.Sprintf("[server]\nlisten = %q\n\n[rate_limit]\nper_second = 5.0\nburst = 10\n", addr)
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := startServer(t, ctx, "--config", cfgPath)
	waitTCPUp(t, addr, errCh, 10*time.Second)
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	_ = resp.Body.Close()
	if err := stopServer(t, cancel, errCh); err != nil {
		t.Fatalf("Server returned %v", err)
	}
}

func TestServerDefaultListenAndModeFromEmptyEnvironment(t *testing.T) {
	// Empty env values fall through to the built-in defaults (:8080, dev).
	probe, err := net.Listen("tcp", ":8080")
	if err != nil {
		t.Skipf("port 8080 unavailable: %v", err)
	}
	_ = probe.Close()
	t.Setenv("KIWI_SERVER_LISTEN", "")
	t.Setenv("KIWI_SERVER_MODE", "")
	ctx, cancel := context.WithCancel(context.Background())
	errCh := startServer(t, ctx)
	waitTCPUp(t, "127.0.0.1:8080", errCh, 10*time.Second)
	if err := stopServer(t, cancel, errCh); err != nil {
		t.Fatalf("Server returned %v", err)
	}
}

func TestLoadEd25519PublicKeyPEMBranches(t *testing.T) {
	if _, err := loadEd25519PublicKey("-----BEGIN PUBLIC KEY-----\n@@@not-base64@@@\n-----END PUBLIC KEY-----"); err == nil {
		t.Fatal("malformed PEM accepted")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadEd25519PublicKey(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))); err == nil {
		t.Fatal("RSA public key accepted as Ed25519")
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := loadEd25519PublicKey(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edDER})))
	if err != nil || !got.Equal(pub) {
		t.Fatalf("Ed25519 PEM load: %v", err)
	}
	raw := filepath.Join(t.TempDir(), "raw.key")
	if err := os.WriteFile(raw, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := loadEd25519PublicKey(raw); err != nil || !got.Equal(pub) {
		t.Fatalf("raw key load: %v", err)
	}
}

func TestTUIWrapperDegradesOnNonTerminal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"seq":1,"run_id":"run1","job_id":"j1","job_key":"build","step":"s","line":"wrapped","created_at":"2026-09-14T00:00:00Z"}]`))
	}))
	defer ts.Close()
	if err := TUI(context.Background(), []string{"--server", ts.URL, "run1"}); err != nil {
		t.Fatalf("TUI: %v", err)
	}
	if err := TUI(context.Background(), []string{"--bogus"}); err == nil {
		t.Fatal("unknown TUI flag accepted")
	}
}
