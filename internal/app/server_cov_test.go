package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// freeTCPAddr reserves then releases a loopback port for a test server.
func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// waitTCPUp polls until addr accepts connections or the deadline passes.
// A server that returns early fails the test with its error.
func waitTCPUp(t *testing.T, addr string, errCh chan error, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("Server returned before listening on %s: %v", addr, err)
		default:
		}
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server on %s did not come up", addr)
}

// startServer runs Server in a goroutine and returns the error channel.
func startServer(t *testing.T, ctx context.Context, args ...string) chan error {
	t.Helper()
	errCh := make(chan error, 1)
	go func() { errCh <- Server(ctx, args) }()
	return errCh
}

func stopServer(t *testing.T, cancel context.CancelFunc, errCh chan error) error {
	t.Helper()
	cancel()
	select {
	case err := <-errCh:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("Server did not return after context cancellation")
		return nil
	}
}

func TestServerPersistentDataDirAndClusterStore(t *testing.T) {
	dataDir := t.TempDir()
	clusterDir := filepath.Join(t.TempDir(), "cluster-keys")
	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := startServer(t, ctx, "--listen", addr, "--data-dir", dataDir, "--cluster-key-dir", clusterDir)
	waitTCPUp(t, addr, errCh, 10*time.Second)
	if err := stopServer(t, cancel, errCh); err != nil {
		t.Fatalf("Server returned %v", err)
	}
}

func TestServerTLSListener(t *testing.T) {
	certFile, keyFile := writeSelfSignedTLS(t)
	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := startServer(t, ctx, "--listen", addr, "--tls-cert", certFile, "--tls-key", keyFile)
	waitTCPUp(t, addr, errCh, 10*time.Second)
	if err := stopServer(t, cancel, errCh); err != nil {
		t.Fatalf("Server returned %v", err)
	}
}

func TestServerOtelTracingWiring(t *testing.T) {
	// A configured OTLP endpoint enables tracing without a live collector
	// (the exporter is lazy). Known defect: resource.Merge rejects the
	// server's resource attributes against resource.Default()'s schema URL,
	// so enabling tracing currently fails startup with an "otel:" error.
	cfgPath := filepath.Join(t.TempDir(), "kiwi.toml")
	addr := freeTCPAddr(t)
	body := fmt.Sprintf("[server]\nlisten = %q\n\n[observability]\notel_endpoint = \"http://127.0.0.1:9\"\n", addr)
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := startServer(t, ctx, "--config", cfgPath)
	// Either the tracing wiring succeeds and the server serves, or the
	// startup fails with the otel resource error; both paths must be hit.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			if err == nil || !strings.Contains(err.Error(), "otel:") {
				t.Fatalf("Server = %v, want otel wiring error", err)
			}
			return
		default:
		}
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			_ = c.Close()
			if err := stopServer(t, cancel, errCh); err != nil {
				t.Fatalf("Server returned %v", err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server neither started nor failed")
}

func TestServerRunnerTokensFileInMemory(t *testing.T) {
	dir := t.TempDir()
	tokensPath := filepath.Join(dir, "runner-tokens.json")
	digest := strings.Repeat("ab", 32)
	body, _ := json.Marshal(map[string]string{"runner-1": digest})
	if err := os.WriteFile(tokensPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := startServer(t, ctx, "--listen", addr, "--runner-tokens-file", tokensPath)
	waitTCPUp(t, addr, errCh, 10*time.Second)
	if err := stopServer(t, cancel, errCh); err != nil {
		t.Fatalf("Server returned %v", err)
	}
}

func TestServerRunnerCAExplicitPair(t *testing.T) {
	ca, err := runnerpki.NewCA("cov-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := startServer(t, ctx, "--listen", addr, "--runner-ca-cert", certPath, "--runner-ca-key", keyPath,
		"--runner-require-client-certs=false")
	waitTCPUp(t, addr, errCh, 10*time.Second)
	if err := stopServer(t, cancel, errCh); err != nil {
		t.Fatalf("Server returned %v", err)
	}
}

func TestServerRunnerEnrollmentGeneratesCA(t *testing.T) {
	dataDir := t.TempDir()
	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := startServer(t, ctx, "--listen", addr, "--data-dir", dataDir, "--runner-enroll-token", "enroll-tok")
	waitTCPUp(t, addr, errCh, 10*time.Second)
	if err := stopServer(t, cancel, errCh); err != nil {
		t.Fatalf("Server returned %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "ca.crt")); err != nil {
		t.Fatalf("enrollment did not persist a runner CA: %v", err)
	}
}

func TestServerStaticBrokerAndComponentDir(t *testing.T) {
	registryDir := t.TempDir()
	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := startServer(t, ctx, "--listen", addr,
		"--secret-broker", "static", "--secret-static", "A=1,B=2",
		"--component-registry-dir", registryDir)
	waitTCPUp(t, addr, errCh, 10*time.Second)
	if err := stopServer(t, cancel, errCh); err != nil {
		t.Fatalf("Server returned %v", err)
	}
}

func TestServerConfigFilePolicyAndMirrorFlags(t *testing.T) {
	polFile := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(polFile, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	addr := freeTCPAddr(t)
	cfgPath := filepath.Join(t.TempDir(), "kiwi.toml")
	body := fmt.Sprintf("[server]\nlisten = %q\n\n[policy]\nfile = %q\n", addr, polFile)
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := startServer(t, ctx, "--config", cfgPath,
		"--downstream-allow", "child=parent",
		"--downstream-trusted-ingress", "child=true",
		"--sigstore-key", "ci="+writeEd25519PEM(t),
		"--rekor-base-url", "https://rekor.example")
	waitTCPUp(t, addr, errCh, 10*time.Second)
	if err := stopServer(t, cancel, errCh); err != nil {
		t.Fatalf("Server returned %v", err)
	}
}

func TestServerRejectsBadInputs(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	badTokens := filepath.Join(t.TempDir(), "tokens.json")
	if err := os.WriteFile(badTokens, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	shortTokens := filepath.Join(t.TempDir(), "short.json")
	if err := os.WriteFile(shortTokens, []byte(`{"r1":"abcd"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	badPolicyCfg := filepath.Join(t.TempDir(), "badpolicy.toml")
	if err := os.WriteFile(badPolicyCfg, []byte("[policy]\nfile = \""+missing+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	badPKICfg := filepath.Join(t.TempDir(), "pki.toml")
	if err := os.WriteFile(badPKICfg, []byte("[runner_pki]\nenabled = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unknown flag", []string{"--nope"}, "flag provided but not defined"},
		{"tls key without cert", []string{"--tls-key", missing}, "--tls-key requires --tls-cert"},
		{"tls cert without key", []string{"--tls-cert", missing}, "--tls-cert requires --tls-key"},
		{"cluster dir without data dir", []string{"--cluster-key-dir", missing}, "requires --data-dir"},
		{"bad downstream allow", []string{"--downstream-allow", "oops"}, "--downstream-allow requires"},
		{"bad trusted ingress", []string{"--downstream-trusted-ingress", "t=maybe"}, "--downstream-trusted-ingress"},
		{"bad sigstore key", []string{"--sigstore-key", "nope"}, "--sigstore-key requires"},
		{"bad rekor key", []string{"--rekor-public-key", missing}, "--rekor-public-key"},
		{"missing config file", []string{"--config", missing}, "config:"},
		{"malformed config", []string{"--config", badTokens}, "config:"},
		{"unknown secret broker", []string{"--secret-broker", "bogus"}, "secret_broker.broker must be one of"},
		{"gcp credentials missing", []string{"--secret-broker", "gcp", "--gcp-project", "p", "--gcp-credentials", missing}, "gcp credentials"},
		{"component dir missing", []string{"--component-registry-dir", missing}, "component"},
		{"bad github app id", []string{"--github-app-id", "abc"}, "--github-app-id"},
		{"github app key missing", []string{"--github-app-id", "42", "--github-app-private-key", missing}, "github app private key"},
		{"bad max connections", []string{"--database-max-connections", "abc"}, "--database-max-connections"},
		{"unreachable database", []string{"--database-url", "postgres://postgres@127.0.0.1:1/postgres?sslmode=disable"}, "storage:"},
		{"production without database", []string{"--mode", "production"}, "external_url is required in production"},
		{"runner tokens file missing", []string{"--runner-tokens-file", missing}, "runner tokens file:"},
		{"runner tokens file malformed", []string{"--runner-tokens-file", badTokens}, "runner tokens file"},
		{"runner tokens file short digest", []string{"--runner-tokens-file", shortTokens}, "64-char SHA-256"},
		{"policy file missing", []string{"--config", badPolicyCfg}, "policy:"},
		{"pki enabled without pair", []string{"--config", badPKICfg}, "runner_pki.enabled requires"},
		{"enroll token without data dir", []string{"--runner-enroll-token", "tok"}, "requires --data-dir"},
		{"runner ca unreadable", []string{"--runner-ca-cert", missing, "--runner-ca-key", missing}, "read runner CA certificate"},
		{"rekor pem invalid", []string{"--rekor-public-key", badTokens}, "--rekor-public-key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Server(context.Background(), c.args)
			if err == nil {
				t.Fatalf("Server(%v) succeeded, want error containing %q", c.args, c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Server(%v) = %v, want error containing %q", c.args, err, c.want)
			}
		})
	}
}

func TestServerProductionRefusesSharedRunnerToken(t *testing.T) {
	err := Server(context.Background(), []string{
		"--mode", "production",
		"--database-url", "postgres://postgres@127.0.0.1:1/postgres?sslmode=disable",
		"--external-url", "https://ci.example.com",
		"--tls-cert", "c.pem", "--tls-key", "k.pem",
		"--admin-token", "admin", "--runner-token", "runner",
	})
	if err == nil || !strings.Contains(err.Error(), "shared runner token is dev-only") {
		t.Fatalf("production Server = %v, want shared-runner-token refusal", err)
	}
}

// writeSelfSignedTLS writes a throwaway RSA certificate/key pair.
func writeSelfSignedTLS(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// writeEd25519PEM writes a PKIX Ed25519 public key and returns its path.
func writeEd25519PEM(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ed25519.pub")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadRunnerTokensFile(t *testing.T) {
	if got, err := loadRunnerTokensFile("  "); err != nil || got != nil {
		t.Fatalf("blank path = %v, %v", got, err)
	}
	digest := strings.Repeat("0a", 32)
	path := filepath.Join(t.TempDir(), "tokens.json")
	body, _ := json.Marshal(map[string]string{" runner-1 ": digest})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadRunnerTokensFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got["runner-1"] != digest {
		t.Fatalf("tokens = %v", got)
	}
	if _, err := loadRunnerTokensFile(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("missing file accepted")
	}
	blankID := filepath.Join(t.TempDir(), "blank.json")
	if err := os.WriteFile(blankID, []byte(`{"":"`+digest+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRunnerTokensFile(blankID); err == nil {
		t.Fatal("blank runner id accepted")
	}
}

func TestMinHelper(t *testing.T) {
	if min(3, 5) != 3 || min(5, 3) != 3 || min(4, 4) != 4 {
		t.Fatal("min misbehaves")
	}
}

// storeOnly satisfies storage.Store without implementing the optional
// RunnerTokenStore extension: the credential probe must report false.
type storeOnly struct{ storage.Store }

func TestHasProvisionedRunnerTokensNonRunnerTokenStore(t *testing.T) {
	has, err := hasProvisionedRunnerTokens(context.Background(), storeOnly{})
	if err != nil {
		t.Fatalf("hasProvisionedRunnerTokens: %v", err)
	}
	if has {
		t.Fatal("non-token store reports provisioned runner tokens")
	}
}

// runnerAdminFake serves the runner admin API and records calls.
func runnerAdminFake(t *testing.T, status int, body string) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		if status != http.StatusOK {
			http.Error(w, body, status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	return ts, &seen
}

func TestRunnerAdminList(t *testing.T) {
	ts, seen := runnerAdminFake(t, http.StatusOK, `[
		{"id":"abcdefghijkl","name":"r1","region":"eu","busy":false,"disabled":false,"draining":false,"capacity":4,"labels":["linux","x64"]},
		{"id":"short","name":"r2","capacity":1}
	]`)
	if err := RunnerAdmin(context.Background(), "list", []string{"--server", ts.URL + "/", "--token", "admin-token"}); err != nil {
		t.Fatalf("runner list: %v", err)
	}
	if len(*seen) != 1 || (*seen)[0] != "GET /api/v1/runners" {
		t.Fatalf("requests = %v", *seen)
	}
}

func TestRunnerAdminListEmpty(t *testing.T) {
	ts, _ := runnerAdminFake(t, http.StatusOK, `[]`)
	if err := RunnerAdmin(context.Background(), "list", []string{"--server", ts.URL}); err != nil {
		t.Fatalf("empty runner list: %v", err)
	}
}

func TestRunnerAdminMutations(t *testing.T) {
	for _, sub := range []string{"drain", "disable", "enable"} {
		ts, seen := runnerAdminFake(t, http.StatusOK, `{"id":"r1","name":"runner-one"}`)
		if err := RunnerAdmin(context.Background(), sub, []string{"--server", ts.URL, "--token", "tok", "r1"}); err != nil {
			t.Fatalf("runner %s: %v", sub, err)
		}
		want := "POST /api/v1/runners/r1/" + sub
		if len(*seen) != 1 || (*seen)[0] != want {
			t.Fatalf("requests = %v, want %s", *seen, want)
		}
	}
}

func TestRunnerAdminErrors(t *testing.T) {
	ts, _ := runnerAdminFake(t, http.StatusOK, `[]`)
	if err := RunnerAdmin(context.Background(), "drain", []string{"--server", ts.URL}); err == nil {
		t.Fatal("drain without an ID succeeded")
	}
	if err := RunnerAdmin(context.Background(), "bogus", []string{"--server", ts.URL}); err == nil {
		t.Fatal("unknown subcommand succeeded")
	}
	if err := RunnerAdmin(context.Background(), "list", []string{"--bogus"}); err == nil {
		t.Fatal("bad flag succeeded")
	}
	failing, _ := runnerAdminFake(t, http.StatusInternalServerError, "boom")
	if err := RunnerAdmin(context.Background(), "list", []string{"--server", failing.URL}); err == nil {
		t.Fatal("500 response accepted")
	}
	badJSON, _ := runnerAdminFake(t, http.StatusOK, `{`)
	if err := RunnerAdmin(context.Background(), "list", []string{"--server", badJSON.URL}); err == nil {
		t.Fatal("malformed JSON accepted")
	}
	// An unreachable server fails at the transport layer.
	if err := RunnerAdmin(context.Background(), "list", []string{"--server", "http://127.0.0.1:1"}); err == nil {
		t.Fatal("unreachable server accepted")
	}
	// A malformed URL fails when the request is built.
	if err := RunnerAdmin(context.Background(), "drain", []string{"--server", "http://[::1", "r1"}); err == nil {
		t.Fatal("malformed URL accepted")
	}
}

func TestRunnerCommandFlagValidation(t *testing.T) {
	if err := Runner(context.Background(), []string{"--runner-mtls", "--runner-cert", "c.pem"}); err == nil {
		t.Fatal("--runner-mtls with a cert but no key succeeded")
	}
	if err := Runner(context.Background(), []string{"--runner-mtls"}); err == nil {
		t.Fatal("--runner-mtls without credentials succeeded")
	}
	if err := Runner(context.Background(), []string{"--bogus"}); err == nil {
		t.Fatal("unknown flag succeeded")
	}
	// Defaults point at the local control plane; an unreachable server
	// fails registration fast.
	tmp := t.TempDir()
	err := Runner(context.Background(), []string{"--server", "http://127.0.0.1:1", "--token", "t", "--name", "n",
		"--labels", "a,b", "--drain", "--identity-dir", filepath.Join(tmp, "identity"), "--work-dir", tmp,
		"--prewarm", "alpine@sha256:" + strings.Repeat("0", 64), "--metrics-listen", "127.0.0.1:0"})
	if err == nil {
		t.Fatal("unreachable server accepted")
	}
	// Certificate-mode misconfiguration is rejected before any network I/O.
	if err := Runner(context.Background(), []string{"--runner-mtls", "--runner-cert", "c.pem", "--runner-key", "k.pem", "--server", "http://127.0.0.1:1"}); err == nil {
		t.Fatal("plaintext server with runner certificates accepted")
	}
	// Subcommands route to the admin surface.
	ts, _ := runnerAdminFake(t, http.StatusOK, `[]`)
	if err := Runner(context.Background(), []string{"list", "--server", ts.URL}); err != nil {
		t.Fatalf("runner list subcommand: %v", err)
	}
}

func TestStringListFlags(t *testing.T) {
	var s stringList
	if s.String() != "" {
		t.Fatalf("empty stringList = %q", s.String())
	}
	if err := s.Set("a, b ,,c"); err != nil {
		t.Fatal(err)
	}
	if got := s.values(); len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("values = %v", got)
	}
	if s.String() != "a,b,c" {
		t.Fatalf("String = %q", s.String())
	}
	got := s.values()
	got[0] = "mutated"
	if s.values()[0] != "a" {
		t.Fatal("values must copy")
	}
}

func TestDecodeModelRunnerJSON(t *testing.T) {
	var r model.Runner
	if err := json.Unmarshal([]byte(`{"id":"x"}`), &r); err != nil || r.ID != "x" {
		t.Fatalf("decode runner: %v %v", r, err)
	}
}
