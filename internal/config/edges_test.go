package config

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func loadToml(t *testing.T, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kiwi.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestLoadTOMLSyntaxErrors(t *testing.T) {
	cases := map[string]string{
		"unterminated section": "[server\nlisten = \":1\"\n",
		"invalid section name": "[ser ver]\n",
		"dotted section name":  "[server.tls]\n",
		"key outside section":  "listen = \":1\"\n",
		"missing equals":       "[server]\nlisten\n",
		"empty value":          "[server]\nlisten =\n",
		"empty key":            "[server]\n= \":1\"\n",
		"unknown key":          "[server]\nnot_a_key = 1\n",
		"duplicate key":        "[server]\nlisten = \":1\"\nlisten = \":2\"\n",
		"unknown section":      "[nope]\nkey = 1\n",
		"string for int":       "[server]\nshutdown_grace_seconds = \"soon\"\n",
		"bad int":              "[server]\nshutdown_grace_seconds = 12abc\n",
		"bad float":            "[server]\nshutdown_grace_seconds = 1.2.3\n",
		"bad bool":             "[server]\nshutdown_grace_seconds = yes\n",
	}
	for name, body := range cases {
		if _, err := loadToml(t, body); err == nil {
			t.Errorf("%s: expected an error for:\n%s", name, body)
		}
	}
}

func TestParseScalarKindsAndErrors(t *testing.T) {
	cases := []struct {
		in   string
		want any
		ok   bool
	}{
		{"true", true, true},
		{"false", false, true},
		{`"hello"`, "hello", true},
		{`'literal'`, "literal", true},
		{"7", int64(7), true},
		{"-3", int64(-3), true},
		{"2.5", 2.5, true},
		{"1e3", 1000.0, true},
		{"", nil, false},
		{"1.2.3", nil, false},
		{"unquoted", nil, false},
		{`"unterminated`, nil, false},
	}
	for _, tc := range cases {
		got, err := parseScalar(tc.in)
		if tc.ok {
			if err != nil {
				t.Errorf("parseScalar(%q) = %v", tc.in, err)
				continue
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseScalar(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("parseScalar(%q) = %#v, want an error", tc.in, got)
		}
	}
}

func TestUnquoteEscapes(t *testing.T) {
	got, err := unquote(`a\n\t\r\f\b\/\\\"z`)
	if err != nil {
		t.Fatalf("unquote: %v", err)
	}
	if got != "a\n\t\r\f\b/\\\"z" {
		t.Fatalf("unquote = %q", got)
	}
	got, err = unquote(`\u0041\u00e9`)
	if err != nil {
		t.Fatalf("unicode escapes: %v", err)
	}
	if got != "Aé" {
		t.Fatalf("unicode escapes = %q", got)
	}
	for _, bad := range []string{`trailing\`, `\q`, `\u12`, `\uZZZZ`} {
		if _, err := unquote(bad); err == nil {
			t.Errorf("unquote(%q) = nil error, want a failure", bad)
		}
	}
	if got, err := unquote(""); err != nil || got != "" {
		t.Fatalf("unquote(empty) = %q (err %v)", got, err)
	}
}

func TestAssignTypeMismatches(t *testing.T) {
	var s struct {
		Str   string
		Int   int
		Float float64
		Bool  bool
		Map   map[string]string
	}
	v := reflect.ValueOf(&s).Elem()

	if err := assign(v.Field(0), int64(1)); err == nil || !strings.Contains(err.Error(), "expected a string") {
		t.Fatalf("string mismatch = %v", err)
	}
	if err := assign(v.Field(1), "x"); err == nil || !strings.Contains(err.Error(), "expected an integer") {
		t.Fatalf("int mismatch = %v", err)
	}
	if err := assign(v.Field(1), int64(5)); err != nil || s.Int != 5 {
		t.Fatalf("int assign = %v (%d)", err, s.Int)
	}
	if err := assign(v.Field(2), int64(4)); err != nil || s.Float != 4 {
		t.Fatalf("float from int = %v (%v)", err, s.Float)
	}
	if err := assign(v.Field(2), 1.5); err != nil || s.Float != 1.5 {
		t.Fatalf("float assign = %v (%v)", err, s.Float)
	}
	if err := assign(v.Field(2), "x"); err == nil || !strings.Contains(err.Error(), "expected a number") {
		t.Fatalf("float mismatch = %v", err)
	}
	if err := assign(v.Field(3), "x"); err == nil || !strings.Contains(err.Error(), "expected a bool") {
		t.Fatalf("bool mismatch = %v", err)
	}
	if err := assign(v.Field(3), true); err != nil || !s.Bool {
		t.Fatalf("bool assign = %v", err)
	}
	if err := assign(v.Field(4), "x"); err == nil || !strings.Contains(err.Error(), "unsupported field type") {
		t.Fatalf("unsupported kind = %v", err)
	}
	if err := assign(reflect.ValueOf("not settable"), "x"); err == nil || !strings.Contains(err.Error(), "not settable") {
		t.Fatalf("unsettable = %v", err)
	}
}

func TestValidateRemainingBranches(t *testing.T) {
	cfg := Default()
	cfg.Server.Mode = "staging"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "server.mode") {
		t.Fatalf("bad mode = %v", err)
	}

	cfg = Default()
	cfg.Server.Mode = "production"
	cfg.Server.ExternalURL = "http://ci.example.com"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("http external_url = %v", err)
	}
	cfg.Server.ExternalURL = "https://ci.example.com"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid production config = %v", err)
	}

	cfg = Default()
	cfg.Blob.Backend = "gcs"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "blob.backend") {
		t.Fatalf("bad backend = %v", err)
	}

	cfg = Default()
	cfg.Components.RemoteURL = "https://exa mple.com/x"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unparseable remote_url must fail")
	}
	cfg.Components.RemoteURL = "https://"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "no host") {
		t.Fatalf("host-less remote_url = %v", err)
	}

	cfg = Default()
	cfg.GitLab.BaseURL = "not a url"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "gitlab.base_url") {
		t.Fatalf("bad gitlab base_url = %v", err)
	}
	cfg = Default()
	cfg.Forgejo.BaseURL = "ftp://forgejo.example"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "forgejo.base_url") {
		t.Fatalf("bad forgejo base_url = %v", err)
	}

	cfg = Default()
	cfg.Database.MaxConnections = -1
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "max_connections") {
		t.Fatalf("negative max_connections = %v", err)
	}

	cfg = Default()
	cfg.Server.Mode = "production"
	cfg.Server.ExternalURL = "https://ci.example.com"
	cfg.Database.URL = "mysql://db"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "postgres") {
		t.Fatalf("bad database url = %v", err)
	}
	cfg.Database.URL = "postgresql://db"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("postgresql url = %v", err)
	}

	cfg = Default()
	cfg.Blob.Backend = "s3"
	cfg.Blob.S3Endpoint, cfg.Blob.S3Bucket, cfg.Blob.S3Region = "https://s3", "", ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "s3_endpoint") {
		t.Fatalf("incomplete s3 = %v", err)
	}

	cfg = Default()
	cfg.GitHub.AppID = 42
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "private_key_path") {
		t.Fatalf("app id without key = %v", err)
	}
	cfg = Default()
	cfg.GitHub.PrivateKeyPath = "/k.pem"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "app_id") {
		t.Fatalf("key without app id = %v", err)
	}
}

func TestRateLimitBurstDefault(t *testing.T) {
	cfg := Default()
	cfg.RateLimit.Burst = 0
	if got := cfg.RateLimitBurst(); got != 100 {
		t.Fatalf("unset burst = %d, want the 100 fallback", got)
	}
	cfg.RateLimit.Burst = 7
	if got := cfg.RateLimitBurst(); got != 7 {
		t.Fatalf("explicit burst = %d", got)
	}
}

func TestValidateEmptyModeAndBackendDefaults(t *testing.T) {
	cfg := &Config{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty config must validate with defaults: %v", err)
	}
}

func TestOverrideFromFlagsAllArms(t *testing.T) {
	fs := flag.NewFlagSet("all", flag.ContinueOnError)
	for _, name := range []string{
		"listen", "mode", "external-url", "tls-cert", "tls-key", "database-url",
		"runner-token", "admin-token", "runner-enroll-token", "runner-ca-cert", "runner-ca-key",
		"github-webhook-secret", "github-token", "github-app-id", "github-app-private-key",
		"gitlab-token", "gitlab-webhook-secret", "gitlab-base-url",
		"forgejo-token", "forgejo-webhook-secret", "forgejo-base-url",
		"tokens-file", "runner-tokens-file", "database-max-connections", "metrics-listen",
		"secret-broker", "vault-addr", "vault-token", "aws-region", "aws-access-key",
		"aws-secret-key", "aws-token", "gcp-credentials", "gcp-project", "azure-tenant",
		"azure-client-id", "azure-client-secret", "azure-vault-url",
		"onepassword-host", "onepassword-token", "onepassword-vault", "secret-static",
		"component-registry-dir", "component-remote", "component-remote-token",
		"repo-concurrency", "team-concurrency", "repo-queue-depth", "team-queue-depth",
		"daily-cost-limit", "daily-energy-limit", "quota-fail-open",
		"untrusted-cpu-ceiling", "untrusted-memory-ceiling", "untrusted-disk-ceiling", "untrusted-pids-ceiling",
		"otel-endpoint", "rate-limit-per-second", "rate-limit-burst",
	} {
		fs.String(name, "", "")
	}
	args := []string{
		"-listen", ":9999", "-mode", "production", "-external-url", "https://ci.example",
		"-tls-cert", "/c.pem", "-tls-key", "/k.pem", "-database-url", "postgres://db",
		"-runner-token", "rt", "-admin-token", "at", "-runner-enroll-token", "et",
		"-runner-ca-cert", "/ca.pem", "-runner-ca-key", "/ca.key",
		"-github-webhook-secret", "ghs", "-github-token", "ght", "-github-app-id", "77",
		"-github-app-private-key", "/app.pem",
		"-gitlab-token", "glt", "-gitlab-webhook-secret", "gls", "-gitlab-base-url", "https://gl.example",
		"-forgejo-token", "fjt", "-forgejo-webhook-secret", "fjs", "-forgejo-base-url", "https://fj.example",
		"-tokens-file", "/t.json", "-runner-tokens-file", "/rt.json",
		"-database-max-connections", "23", "-metrics-listen", ":8888",
		"-secret-broker", "aws", "-vault-addr", "https://v", "-vault-token", "vt",
		"-aws-region", "eu-west-1", "-aws-access-key", "ak", "-aws-secret-key", "sk", "-aws-token", "st",
		"-gcp-credentials", "/gcp.json", "-gcp-project", "proj",
		"-azure-tenant", "tenant", "-azure-client-id", "cid", "-azure-client-secret", "csec",
		"-azure-vault-url", "https://kv", "-onepassword-host", "https://op",
		"-onepassword-token", "opt", "-onepassword-vault", "opv", "-secret-static", "k=v",
		"-component-registry-dir", "/direg", "-component-remote", "https://reg", "-component-remote-token", "regtok",
		"-repo-concurrency", "1", "-team-concurrency", "2", "-repo-queue-depth", "3", "-team-queue-depth", "4",
		"-daily-cost-limit", "5", "-daily-energy-limit", "6", "-quota-fail-open", "true",
		"-untrusted-cpu-ceiling", "7", "-untrusted-memory-ceiling", "8589934592",
		"-untrusted-disk-ceiling", "17179869184", "-untrusted-pids-ceiling", "2048",
		"-otel-endpoint", "otel:4318", "-rate-limit-per-second", "12.5", "-rate-limit-burst", "9",
	}
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	if err := cfg.OverrideFromFlags(fs); err != nil {
		t.Fatalf("OverrideFromFlags: %v", err)
	}
	if cfg.Server.Listen != ":9999" || cfg.Server.Mode != "production" ||
		cfg.Server.ExternalURL != "https://ci.example" || cfg.Server.TLSCert != "/c.pem" || cfg.Server.TLSKey != "/k.pem" {
		t.Fatalf("server = %+v", cfg.Server)
	}
	if cfg.Database.URL != "postgres://db" || cfg.Database.MaxConnections != 23 {
		t.Fatalf("database = %+v", cfg.Database)
	}
	if cfg.Auth.RunnerToken != "rt" || cfg.Auth.AdminToken != "at" || cfg.Auth.TokensFile != "/t.json" || cfg.Auth.RunnerTokensFile != "/rt.json" {
		t.Fatalf("auth = %+v", cfg.Auth)
	}
	if cfg.RunnerPKI.Enabled || cfg.RunnerPKI.EnrollToken != "et" || cfg.RunnerPKI.CACert != "/ca.pem" || cfg.RunnerPKI.CAKey != "/ca.key" {
		t.Fatalf("runner pki = %+v", cfg.RunnerPKI)
	}
	if cfg.GitHub.WebhookSecret != "ghs" || cfg.GitHub.Token != "ght" || cfg.GitHub.AppID != 77 || cfg.GitHub.PrivateKeyPath != "/app.pem" {
		t.Fatalf("github = %+v", cfg.GitHub)
	}
	if cfg.GitLab.Token != "glt" || cfg.GitLab.WebhookSecret != "gls" || cfg.GitLab.BaseURL != "https://gl.example" {
		t.Fatalf("gitlab = %+v", cfg.GitLab)
	}
	if cfg.Forgejo.Token != "fjt" || cfg.Forgejo.WebhookSecret != "fjs" || cfg.Forgejo.BaseURL != "https://fj.example" {
		t.Fatalf("forgejo = %+v", cfg.Forgejo)
	}
	if cfg.Observability.MetricsListen != ":8888" || cfg.Observability.OTelEndpoint != "otel:4318" {
		t.Fatalf("observability = %+v", cfg.Observability)
	}
	sb := cfg.SecretBroker
	if sb.Broker != "aws" || sb.VaultAddr != "https://v" || sb.VaultToken != "vt" || sb.AWSRegion != "eu-west-1" ||
		sb.AWSAccessKey != "ak" || sb.AWSSecretKey != "sk" || sb.AWSToken != "st" ||
		sb.GCPCredentials != "/gcp.json" || sb.GCPProject != "proj" || sb.AzureTenant != "tenant" ||
		sb.AzureClientID != "cid" || sb.AzureSecret != "csec" || sb.AzureVaultURL != "https://kv" ||
		sb.OnePasswordHost != "https://op" || sb.OnePasswordToken != "opt" || sb.OnePasswordVault != "opv" || sb.Static != "k=v" {
		t.Fatalf("secret broker = %+v", sb)
	}
	if cfg.Components.RegistryDir != "/direg" || cfg.Components.RemoteURL != "https://reg" || cfg.Components.RemoteToken != "regtok" {
		t.Fatalf("components = %+v", cfg.Components)
	}
	q := cfg.Quota
	if q.RepoConcurrency != 1 || q.TeamConcurrency != 2 || q.RepoQueueDepth != 3 || q.TeamQueueDepth != 4 ||
		q.DailyCostLimit != 5 || q.DailyEnergyLimit != 6 || !q.FailOpen {
		t.Fatalf("quota = %+v", q)
	}
	if q.UntrustedCPUCeiling != 7 || q.UntrustedMemoryCeiling != 8<<30 ||
		q.UntrustedDiskCeiling != 16<<30 || q.UntrustedPIDsCeiling != 2048 {
		t.Fatalf("untrusted ceilings = %+v", q)
	}
	if cfg.RateLimit.PerSecond != 12.5 || cfg.RateLimit.Burst != 9 {
		t.Fatalf("rate limit = %+v", cfg.RateLimit)
	}
}

func TestOverrideFromFlagsParseErrors(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		flags []string
	}{
		{"github-app-id", []string{"-github-app-id", "not-a-number"}, []string{"github-app-id"}},
		{"database-max-connections", []string{"-database-max-connections", "many"}, []string{"database-max-connections"}},
		{"quota-fail-open", []string{"-quota-fail-open", "perhaps"}, []string{"quota-fail-open"}},
		{"repo-concurrency", []string{"-repo-concurrency", "lots"}, []string{"repo-concurrency"}},
		{"daily-cost-limit-second", []string{"-daily-cost-limit", "lots", "-repo-concurrency", "lots"}, []string{"daily-cost-limit", "repo-concurrency"}},
		{"team-concurrency", []string{"-team-concurrency", "lots"}, []string{"team-concurrency"}},
		{"repo-queue-depth", []string{"-repo-queue-depth", "lots"}, []string{"repo-queue-depth"}},
		{"team-queue-depth", []string{"-team-queue-depth", "lots"}, []string{"team-queue-depth"}},
		{"daily-cost-limit", []string{"-daily-cost-limit", "lots"}, []string{"daily-cost-limit"}},
		{"daily-energy-limit", []string{"-daily-energy-limit", "lots"}, []string{"daily-energy-limit"}},
		{"rate-limit-per-second", []string{"-rate-limit-per-second", "fast"}, []string{"rate-limit-per-second"}},
		{"rate-limit-burst", []string{"-rate-limit-burst", "many"}, []string{"rate-limit-burst"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("bad", flag.ContinueOnError)
			for _, name := range tc.flags {
				fs.String(name, "", "")
			}
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			err := Default().OverrideFromFlags(fs)
			if err == nil {
				t.Fatalf("OverrideFromFlags(%v) = nil, want a parse error", tc.args)
			}
			if !strings.Contains(err.Error(), "invalid syntax") {
				t.Fatalf("error = %v, want a parse failure", err)
			}
		})
	}
}

func TestOverrideFromFlagsIgnoresUnknownAndUnset(t *testing.T) {
	fs := flag.NewFlagSet("mixed", flag.ContinueOnError)
	fs.String("listen", ":1111", "")
	fs.String("unknown-future-flag", "", "")
	if err := fs.Parse([]string{"-unknown-future-flag=1"}); err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	if err := cfg.OverrideFromFlags(fs); err != nil {
		t.Fatalf("OverrideFromFlags: %v", err)
	}
	if cfg.Server.Listen != ":8080" {
		t.Fatalf("unset flag overrode the default: %q", cfg.Server.Listen)
	}
}

func TestOverrideFromFlagsSkipsEmptyValues(t *testing.T) {
	fs := flag.NewFlagSet("empty", flag.ContinueOnError)
	for _, name := range []string{"github-app-id", "database-max-connections", "quota-fail-open", "rate-limit-per-second", "rate-limit-burst"} {
		fs.String(name, "", "")
	}
	if err := fs.Parse([]string{
		"-github-app-id", "", "-database-max-connections", "", "-quota-fail-open", "",
		"-rate-limit-per-second", "", "-rate-limit-burst", "",
	}); err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	if err := cfg.OverrideFromFlags(fs); err != nil {
		t.Fatalf("empty values must be ignored, got %v", err)
	}
	if cfg.GitHub.AppID != 0 || cfg.Database.MaxConnections != 0 || cfg.Quota.FailOpen {
		t.Fatalf("empty values changed config: %+v %+v %+v", cfg.GitHub, cfg.Database, cfg.Quota)
	}
}

func TestFlagFloatEmptyIsNoop(t *testing.T) {
	fs := flag.NewFlagSet("f", flag.ContinueOnError)
	fs.String("x", "", "")
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	var dst float64 = 3
	f := fs.Lookup("x")
	if err := flagFloat(f, &dst); err != nil || dst != 3 {
		t.Fatalf("flagFloat(empty) = %v (dst %v)", err, dst)
	}
}
