package app

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/components"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/config"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secretbroker"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

func TestApplyForgeConfig(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(keyPath, []byte("-----BEGIN RSA PRIVATE KEY-----\nstub\n-----END RSA PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.GitHub.WebhookSecret = "gh-wh"
	cfg.GitHub.Token = "gh-token"
	cfg.GitHub.AppID = 4242
	cfg.GitHub.PrivateKeyPath = keyPath
	cfg.GitLab.WebhookSecret = "gl-wh"
	cfg.GitLab.Token = "gl-token"
	cfg.GitLab.BaseURL = "https://gitlab.internal.example"
	cfg.Forgejo.WebhookSecret = "fj-wh"
	cfg.Forgejo.Token = "fj-token"
	cfg.Forgejo.BaseURL = "https://forgejo.internal.example"
	srv := server.New("runner")
	if err := applyForgeConfig(srv, cfg); err != nil {
		t.Fatal(err)
	}
	if srv.GitHubWebhookSecret != "gh-wh" || srv.GitHubToken != "gh-token" {
		t.Errorf("github fields = %q %q", srv.GitHubWebhookSecret, srv.GitHubToken)
	}
	if srv.GitHubAppID != 4242 || srv.GitHubAppPrivateKey == "" || !strings.Contains(srv.GitHubAppPrivateKey, "RSA PRIVATE KEY") {
		t.Errorf("github app fields = %d key=%q", srv.GitHubAppID, srv.GitHubAppPrivateKey)
	}
	if srv.GitLabWebhookSecret != "gl-wh" || srv.GitLabToken != "gl-token" || srv.ForgejoWebhookSecret != "fj-wh" || srv.ForgejoToken != "fj-token" {
		t.Errorf("gitlab/forgejo fields not wired")
	}
	// Base URL overrides reach the forge adapters via SetForgeBaseURL (the
	// end-to-end effect is asserted in TestGitLabWebhookBaseURL).
	// Missing key file is a startup error.
	bad := config.Default()
	bad.GitHub.AppID = 1
	bad.GitHub.PrivateKeyPath = filepath.Join(t.TempDir(), "missing.pem")
	if err := applyForgeConfig(server.New("r"), bad); err == nil {
		t.Fatal("missing app private key accepted")
	}
}

func TestApplyAuthConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tokens.json")
	digest := auth.TokenDigest("secret-token")
	content, err := json.Marshal(map[string]auth.Principal{
		digest: {Subject: "ci-bot", Roles: []auth.Role{auth.RoleAdmin}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Auth.TokensFile = p
	srv := server.New("runner")
	if err := applyAuthConfig(srv, cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.AuthStore.Authenticate("secret-token"); !ok {
		t.Fatal("loaded token does not authenticate")
	}
	if _, ok := srv.AuthStore.Authenticate("other"); ok {
		t.Fatal("unknown token authenticates")
	}
	// An unreadable file fails startup.
	cfg.Auth.TokensFile = filepath.Join(t.TempDir(), "nope.json")
	if err := applyAuthConfig(server.New("r"), cfg); err == nil {
		t.Fatal("missing tokens file accepted")
	}
}

func TestApplyQuotaConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Quota = config.QuotaConfig{
		RepoConcurrency:  4,
		TeamConcurrency:  12,
		RepoQueueDepth:   8,
		TeamQueueDepth:   24,
		DailyCostLimit:   1.5,
		DailyEnergyLimit: 2500,
		FailOpen:         true,
	}
	srv := server.New("r")
	applyQuotaConfig(srv, cfg)
	if srv.QuotaLimits.RepoConcurrency != 4 || srv.QuotaLimits.TeamConcurrency != 12 || srv.QuotaLimits.RepoQueueDepth != 8 || srv.QuotaLimits.TeamQueueDepth != 24 {
		t.Errorf("limits = %+v", srv.QuotaLimits)
	}
	if srv.DailyCostLimit != 1.5 || srv.DailyEnergyLimit != 2500 || !srv.QuotaFailOpen {
		t.Errorf("budgets = %g %g failOpen=%t", srv.DailyCostLimit, srv.DailyEnergyLimit, srv.QuotaFailOpen)
	}
}

func TestBuildSecretBroker(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		b, err := buildSecretBroker(config.SecretBrokerConfig{})
		if err != nil || b != nil {
			t.Fatalf("empty config: %v %v", b, err)
		}
	})
	t.Run("vault", func(t *testing.T) {
		b, err := buildSecretBroker(config.SecretBrokerConfig{Broker: "vault", VaultAddr: "https://vault.example", VaultToken: "t"})
		if err != nil {
			t.Fatal(err)
		}
		v, ok := b.(*secretbroker.VaultClient)
		if !ok || v.Address != "https://vault.example" || v.Token != "t" {
			t.Fatalf("vault broker = %#v", b)
		}
	})
	t.Run("aws", func(t *testing.T) {
		b, err := buildSecretBroker(config.SecretBrokerConfig{Broker: "aws", AWSRegion: "eu-west-1", AWSAccessKey: "ak", AWSSecretKey: "sk", AWSToken: "st"})
		if err != nil {
			t.Fatal(err)
		}
		a, ok := b.(*secretbroker.SecretsManagerClient)
		if !ok || a.Region != "eu-west-1" || a.AccessKeyID != "ak" || a.SecretAccessKey != "sk" || a.SessionToken != "st" {
			t.Fatalf("aws broker = %#v", b)
		}
	})
	t.Run("gcp", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "sa.json")
		if err := os.WriteFile(p, []byte(`{"client_email":"sa@proj.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		b, err := buildSecretBroker(config.SecretBrokerConfig{Broker: "gcp", GCPProject: "proj", GCPCredentials: p})
		if err != nil {
			t.Fatal(err)
		}
		g, ok := b.(*secretbroker.GCPClient)
		if !ok || g.Project != "proj" || g.ClientEmail != "sa@proj.iam.gserviceaccount.com" || len(g.PrivateKeyPEM) == 0 {
			t.Fatalf("gcp broker = %#v", b)
		}
		// Missing credentials file is a startup error.
		if _, err := buildSecretBroker(config.SecretBrokerConfig{Broker: "gcp", GCPProject: "p", GCPCredentials: filepath.Join(t.TempDir(), "nope.json")}); err == nil {
			t.Fatal("missing gcp credentials accepted")
		}
	})
	t.Run("azure", func(t *testing.T) {
		b, err := buildSecretBroker(config.SecretBrokerConfig{Broker: "azure", AzureTenant: "t", AzureClientID: "c", AzureSecret: "s", AzureVaultURL: "https://kv.example"})
		if err != nil {
			t.Fatal(err)
		}
		a, ok := b.(*secretbroker.AzureClient)
		if !ok || a.TenantID != "t" || a.ClientID != "c" || a.ClientSecret != "s" || a.VaultURL != "https://kv.example" {
			t.Fatalf("azure broker = %#v", b)
		}
	})
	t.Run("onepassword", func(t *testing.T) {
		b, err := buildSecretBroker(config.SecretBrokerConfig{Broker: "onepassword", OnePasswordHost: "https://op.example", OnePasswordToken: "t", OnePasswordVault: "v"})
		if err != nil {
			t.Fatal(err)
		}
		o, ok := b.(*secretbroker.OnePasswordClient)
		if !ok || o.Host != "https://op.example" || o.Token != "t" || o.VaultID != "v" {
			t.Fatalf("onepassword broker = %#v", b)
		}
	})
	t.Run("static", func(t *testing.T) {
		b, err := buildSecretBroker(config.SecretBrokerConfig{Broker: "static", Static: "a=1,b=two"})
		if err != nil {
			t.Fatal(err)
		}
		s, ok := b.(secretbroker.StaticBroker)
		if !ok || s["a"] != "1" || s["b"] != "two" {
			t.Fatalf("static broker = %#v", b)
		}
	})
	t.Run("chain provider plus static", func(t *testing.T) {
		b, err := buildSecretBroker(config.SecretBrokerConfig{Broker: "vault", VaultAddr: "https://vault.example", Static: "a=1"})
		if err != nil {
			t.Fatal(err)
		}
		ch, ok := b.(secretbroker.ChainBroker)
		if !ok || len(ch) != 2 {
			t.Fatalf("chain = %#v", b)
		}
		if _, ok := ch[0].(*secretbroker.VaultClient); !ok {
			t.Fatalf("chain[0] = %T", ch[0])
		}
		if _, ok := ch[1].(secretbroker.StaticBroker); !ok {
			t.Fatalf("chain[1] = %T", ch[1])
		}
	})
}

func TestBuildComponentRegistry(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "components"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "components", "build.yaml"),
		[]byte("name: build\nsteps:\n  - run: echo hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := buildComponentRegistry(config.ComponentsConfig{RegistryDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.(*components.LocalRegistry); !ok {
		t.Fatalf("registry = %T", reg)
	}
	if _, _, err := reg.Resolve(context.Background(), "components/build.yaml"); err != nil {
		t.Fatalf("resolve through wired registry: %v", err)
	}
	// No components section: no registry.
	if reg, err := buildComponentRegistry(config.ComponentsConfig{}); err != nil || reg != nil {
		t.Fatalf("empty components: %v %v", reg, err)
	}
	// A bad remote URL surfaces at startup.
	if _, err := buildComponentRegistry(config.ComponentsConfig{RemoteURL: "http://reg.example"}); err == nil {
		t.Fatal("http remote accepted")
	}
}

// TestGitLabWebhookBaseURL drives the full webhook path: the token verifies
// and the pipeline fetch hits the configured base URL's /api/v4 namespace.
func TestGitLabWebhookBaseURL(t *testing.T) {
	var fetchCalls atomic.Int64
	var sawToken atomic.Value
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/raw") {
			fetchCalls.Add(1)
			sawToken.Store(r.Header.Get("PRIVATE-TOKEN"))
			io.WriteString(w, "version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    steps:\n      - run: echo hi\n")
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	srv := server.New("runner-token")
	srv.GitLabWebhookSecret = "gl-secret"
	srv.GitLabToken = "gl-token"
	srv.SetForgeBaseURL("gitlab", ts.URL)

	body := `{"object_kind":"push","ref":"refs/heads/main","before":"","after":"abc123","checkout_sha":"abc123","project":{"id":1,"path_with_namespace":"team/repo","default_branch":"main"},"repository":{"git_http_url":"https://gitlab.internal.example/team/repo.git"}}`
	req := httptest.NewRequest(http.MethodPost, "/hooks/gitlab", strings.NewReader(body))
	req.Header.Set("X-GitLab-Token", "gl-secret")
	req.Header.Set("X-Gitlab-Event", "Push Hook")
	req.Header.Set("X-GitLab-Event-UUID", "uuid-1")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("webhook = %d: %s", w.Code, w.Body.String())
	}
	var run struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil || run.ID == "" {
		t.Fatalf("run = %s", w.Body.String())
	}
	if fetchCalls.Load() != 1 {
		t.Fatalf("pipeline fetch calls = %d, want 1 (base URL not used)", fetchCalls.Load())
	}
	if tok, _ := sawToken.Load().(string); tok != "gl-token" {
		t.Fatalf("fetch PRIVATE-TOKEN = %q, want gl-token", tok)
	}

	// A wrong token is rejected before any fetch.
	req2 := httptest.NewRequest(http.MethodPost, "/hooks/gitlab", strings.NewReader(body))
	req2.Header.Set("X-GitLab-Token", "wrong")
	req2.Header.Set("X-Gitlab-Event", "Push Hook")
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("bad token webhook = %d, want 401", w2.Code)
	}
}

func TestStartMetricsListener(t *testing.T) {
	srv := server.New("runner-token")
	addr, stop, err := startMetricsListener(srv, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics = %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if !strings.Contains(string(b), "kiwi_runs") {
		t.Fatalf("metrics body missing state gauges: %.100s", b)
	}

	// An unbindable address is a startup error, not a background failure.
	if _, _, err := startMetricsListener(srv, "127.0.0.1:99999"); err == nil {
		t.Fatal("invalid metrics address accepted")
	}
	// A conflicting bind is a startup error.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, _, err := startMetricsListener(srv, ln.Addr().String()); err == nil {
		t.Fatal("conflicting metrics bind accepted")
	}
}

func TestConfigCheckNewSections(t *testing.T) {
	valid := `[server]
mode = "dev"
[quota]
repo_concurrency = 4
[secret_broker]
broker = "vault"
vault_addr = "https://vault.example"
[components]
registry_dir = "/tmp/components"
[gitlab]
base_url = "https://gitlab.internal.example"
`
	p := filepath.Join(t.TempDir(), "kiwi.toml")
	if err := os.WriteFile(p, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ConfigCheck(context.Background(), []string{"-config", p}); err != nil {
		t.Fatalf("valid new sections rejected: %v", err)
	}

	invalid := valid + "\n[github]\napp_id = 123\n"
	p2 := filepath.Join(t.TempDir(), "kiwi2.toml")
	if err := os.WriteFile(p2, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ConfigCheck(context.Background(), []string{"-config", p2}); err == nil {
		t.Fatal("app id without private key accepted by config check")
	}
}
