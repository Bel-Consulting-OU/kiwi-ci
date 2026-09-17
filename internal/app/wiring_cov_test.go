package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/config"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

func TestBuildSecretBrokerUnknownProvider(t *testing.T) {
	if _, err := buildSecretBroker(config.SecretBrokerConfig{Broker: "mystery"}); err == nil {
		t.Fatal("unknown broker provider accepted")
	}
}

func TestBuildSecretBrokerChainsStaticFallback(t *testing.T) {
	broker, err := buildSecretBroker(config.SecretBrokerConfig{
		Broker: "aws", AWSRegion: "eu-west-1",
		Static: "TOKEN=secret, ,=novalue,BAD",
	})
	if err != nil {
		t.Fatalf("chain broker: %v", err)
	}
	if broker == nil {
		t.Fatal("chain broker is nil")
	}
	// Static-only configuration returns the static broker directly.
	static, err := buildSecretBroker(config.SecretBrokerConfig{Broker: "static", Static: "A=1"})
	if err != nil || static == nil {
		t.Fatalf("static broker: %v %v", static, err)
	}
	// Static pairs without a primary broker form a single-entry chain.
	staticOnly, err := buildSecretBroker(config.SecretBrokerConfig{Static: "A=1"})
	if err != nil || staticOnly == nil {
		t.Fatalf("static-only broker: %v %v", staticOnly, err)
	}
	// No broker and no static pairs stays disabled.
	none, err := buildSecretBroker(config.SecretBrokerConfig{})
	if err != nil || none != nil {
		t.Fatalf("empty broker = %v, %v", none, err)
	}
	// Every named provider constructs without error.
	for _, name := range []string{"vault", "aws", "azure", "onepassword"} {
		if _, err := buildSecretBroker(config.SecretBrokerConfig{Broker: name}); err != nil {
			t.Fatalf("broker %s: %v", name, err)
		}
	}
}

func TestParseStaticPairsSkipsMalformedEntries(t *testing.T) {
	got := parseStaticPairs(" , =value,BAD,KEY=ok")
	if len(got) != 1 || got["KEY"] != "ok" {
		t.Fatalf("parseStaticPairs = %v", got)
	}
}

func TestParseGCPServiceAccountErrors(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := parseGCPServiceAccount(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing credentials file accepted")
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseGCPServiceAccount(bad); err == nil {
		t.Fatal("malformed credentials accepted")
	}
	incomplete := filepath.Join(dir, "incomplete.json")
	if err := os.WriteFile(incomplete, []byte(`{"client_email":"a@b.c"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseGCPServiceAccount(incomplete); err == nil {
		t.Fatal("credentials without a private key accepted")
	}
	valid := filepath.Join(dir, "valid.json")
	body, _ := json.Marshal(map[string]string{"client_email": "a@b.c", "private_key": "-----BEGIN PRIVATE KEY-----\nxx\n-----END PRIVATE KEY-----\n"})
	if err := os.WriteFile(valid, body, 0o600); err != nil {
		t.Fatal(err)
	}
	email, key, err := parseGCPServiceAccount(valid)
	if err != nil || email != "a@b.c" || len(key) == 0 {
		t.Fatalf("valid credentials = %q %q %v", email, key, err)
	}
	// The GCP broker wires the parsed credentials.
	if _, err := buildSecretBroker(config.SecretBrokerConfig{Broker: "gcp", GCPCredentials: valid, GCPProject: "p"}); err != nil {
		t.Fatalf("gcp broker: %v", err)
	}
}

func TestBuildComponentRegistryErrorsAndChain(t *testing.T) {
	if _, err := buildComponentRegistry(config.ComponentsConfig{RegistryDir: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("missing registry dir accepted")
	}
	badRemote := config.ComponentsConfig{RemoteURL: "not-a-url"}
	if _, err := buildComponentRegistry(badRemote); err == nil {
		t.Fatal("invalid remote registry URL accepted")
	}
	// A local directory plus a remote URL yields a two-entry chain.
	dir := t.TempDir()
	reg, err := buildComponentRegistry(config.ComponentsConfig{RegistryDir: dir, RemoteURL: "https://registry.example"})
	if err != nil {
		t.Fatalf("registry chain: %v", err)
	}
	if reg == nil {
		t.Fatal("registry chain is nil")
	}
	// Neither configured: disabled.
	if reg, err := buildComponentRegistry(config.ComponentsConfig{}); err != nil || reg != nil {
		t.Fatalf("empty registry = %v, %v", reg, err)
	}
	// Local only.
	if reg, err := buildComponentRegistry(config.ComponentsConfig{RegistryDir: dir}); err != nil || reg == nil {
		t.Fatalf("local registry = %v, %v", reg, err)
	}
	// Remote only.
	if reg, err := buildComponentRegistry(config.ComponentsConfig{RemoteURL: "https://registry.example"}); err != nil || reg == nil {
		t.Fatalf("remote registry = %v, %v", reg, err)
	}
}

func TestStartMetricsListenerRejectsBadAddress(t *testing.T) {
	srv := server.New("tok")
	if _, _, err := startMetricsListener(srv, "256.256.256.256:999999"); err == nil {
		t.Fatal("invalid metrics address accepted")
	}
}

func TestApplyAuthConfigError(t *testing.T) {
	srv := server.New("tok")
	err := applyAuthConfig(srv, &config.Config{Auth: config.AuthConfig{TokensFile: filepath.Join(t.TempDir(), "missing.json")}})
	if err == nil {
		t.Fatal("missing tokens file accepted")
	}
	// The unset path is a no-op.
	if err := applyAuthConfig(srv, &config.Config{}); err != nil {
		t.Fatalf("unset tokens file: %v", err)
	}
}
